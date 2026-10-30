// Bounded recursive host discovery. DNS and HTTP observations are ledger records; host records are derived.
import dns from 'node:dns/promises';
import tls from 'node:tls';
import {randomBytes} from 'node:crypto';
import {publicIP, safeRequest} from '../network.mjs';
import {hash, need} from '../util.mjs';
import {mineOrigin, extractFromHtml} from './assets.mjs';
import {parseOpenApi, sensitivePathEntries, sensitivePathMatches} from './recon.mjs';
import {selectSensitivePathEntries} from './sensitive-path-catalog.mjs';
import {credentialQueryKey} from './private-query.mjs';
import {responseSizeLimited} from './response-size.mjs';

const ROOT_WORDS = Object.freeze(['www','api','app','admin','auth','login','accounts','account','portal','dashboard','console',
  'dev','staging','stage','test','qa','prod','production','old','new','legacy','beta','preview','internal','status','docs',
  'help','support','cdn','static','assets','images','files','uploads','download','blog','shop','store','mail','m','mobile',
  'v1','v2','graphql','gateway','edge','eu','us','west','east','sandbox','demo','jobs','web','backend','frontend']);
const CHILD_WORDS = Object.freeze(['api','app','admin','auth','dev','staging','test','qa','old','new','v1','v2','internal',
  'portal','console','static','assets','eu','us']);
const BASE_PATHS = ['/', '/robots.txt', '/sitemap.xml', '/openapi.json', '/swagger.json', '/api-docs', '/.well-known/security.txt'];
const MODEL_HOSTS_PER_PAGE = 40;
const MODEL_NAMING_PAGES = 4;
const MODEL_CONTEXT_BYTES = 24000;
const MAX_CERT_NAMES = 256;
const MAX_EXPLICIT_HOST_URLS = 256;
const unique = values => [...new Set(values.filter(Boolean))];
const within = (host, domains) => domains.some(domain => host === domain || host.endsWith(`.${domain}`));

function hostname(value) {
  const lower = String(value ?? '').trim().toLowerCase().replace(/^\*\./, '').replace(/\.$/, '');
  return lower.length <= 253 && lower.split('.').every(label =>
    /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(label)) ? lower : null;
}

function namesFromCt(body, domain) {
  let rows;
  try {rows = JSON.parse(body);} catch {return [];}
  if (!Array.isArray(rows)) return [];
  return unique(rows.flatMap(row => String(row.name_value ?? '').split(/\s+/)).map(hostname).filter(host => host && within(host, [domain])));
}

async function defaultConnectTls(host, addresses) {
  const address = addresses[0];
  return new Promise((resolve, reject) => {
    const socket = tls.connect({host: address, port: 443, servername: host, rejectUnauthorized: true});
    socket.setTimeout(3000);
    socket.once('secureConnect', () => {
      const authorized = socket.authorized;
      const certificate = socket.getPeerCertificate();
      socket.destroy();
      if (!authorized || !certificate || !Object.keys(certificate).length)
        reject(Error('The HTTPS peer returned no verified certificate.'));
      else resolve(certificate);
    });
    socket.once('timeout', () => socket.destroy(Error('TLS certificate lookup timed out.')));
    socket.once('error', reject);
  });
}

function certificateNames(certificate) {
  const values = Array.isArray(certificate?.sans) ? certificate.sans :
    String(certificate?.subjectaltname ?? '').split(/,\s*/).filter(item => /^DNS:/i.test(item))
      .map(item => item.slice(4));
  const exact = [], wildcards = [];
  for (const value of values) {
    const raw = String(value ?? '').trim();
    const host = hostname(raw);
    if (!host) continue;
    const list = raw.startsWith('*.') ? wildcards : exact;
    if (!list.includes(host)) list.push(host);
  }
  const expiresAt = Date.parse(certificate?.valid_to ?? certificate?.expires ?? '');
  const issuer = certificate?.issuer;
  const sans = exact.slice(0, MAX_CERT_NAMES);
  const wildcardSans = wildcards.slice(0, MAX_CERT_NAMES - sans.length);
  return {issuer: String(typeof issuer === 'string' ? issuer : issuer?.O ?? issuer?.CN ?? '').slice(0, 120) || null,
    sans, wildcardSans,
    expires: Number.isFinite(expiresAt) ? new Date(expiresAt).toISOString() : null,
    cut: Math.max(0, exact.length + wildcards.length - MAX_CERT_NAMES)};
}

async function defaultResolve(name) {
  const bounded = async promise => {
    let timer;
    try {return await Promise.race([promise, new Promise(resolve => {timer = setTimeout(() => resolve([]), 3000);})]);}
    finally {clearTimeout(timer);}
  };
  const answers = await Promise.allSettled([bounded(dns.resolve4(name)), bounded(dns.resolve6(name))]);
  return unique(answers.flatMap(result => result.status === 'fulfilled' ? result.value : []));
}

function stackOf(response) {
  const markers = [];
  const header = response.headers ?? {};
  const server = header.server ?? '';
  const powered = header['x-powered-by'] ?? '';
  if (server) markers.push({product: String(server).split('/')[0], version: String(server).split('/')[1] ?? null, by: 'server-header'});
  if (powered) markers.push({product: String(powered).split('/')[0], version: String(powered).split('/')[1] ?? null, by: 'x-powered-by'});
  const body = response.body ?? '';
  for (const [marker, product] of [['/_next/', 'Next.js'], ['__NUXT__', 'Nuxt'], ['wp-content', 'WordPress'],
    ['ng-version', 'Angular'], ['data-reactroot', 'React']]) if (body.includes(marker)) markers.push({product, version: null, by: 'html'});
  return markers;
}

function namingContext(domains, records) {
  const brief = (value, limit) => String(value ?? '').slice(0, limit);
  return {domains, hosts: records.map(record => ({host: record.host, title: brief(record.title, 160),
    stack: record.stack.slice(0, 6).map(item => ({product: brief(item.product, 100),
      version: brief(item.version, 60), by: brief(item.by, 60)})),
    paths: record.operations.slice(0, 8).map(item => brief(item.path, 300)),
    assetHosts: (record.assets?.hosts ?? []).slice(0, 8).map(item => brief(item.host, 253))}))};
}

/** Only explicit HTTP(S) URLs in a page or selected response headers become hostname leads. */
function observedHostReferences(response, origin) {
  const references = [];
  const addUrls = (values, source) => {
    for (const value of values) references.push({value, source});
  };
  if ((/html/i.test(response.type ?? response.headers?.['content-type'] ?? '') ||
      /^\s*<(?:!doctype|html)\b/i.test(response.body ?? '')) &&
      typeof response.body === 'string') {
    const html = extractFromHtml(response.body, {url: `${origin}/`});
    addUrls([...html.scripts, ...html.links, ...html.modulepreload], 'html');
  }
  for (const name of ['link', 'location', 'content-security-policy', 'access-control-allow-origin']) {
    const value = response.headers?.[name];
    if (value == null) continue;
    const text = Array.isArray(value) ? value.join(' ') : String(value);
    addUrls(text.match(/(?:https?:)?\/\/(?:[a-z0-9-]+\.)+[a-z][a-z0-9-]{1,62}(?::\d{1,5})?/gi) ?? [],
      `header:${name}`);
  }
  const hosts = [];
  for (const reference of references.slice(0, MAX_EXPLICIT_HOST_URLS)) {
    try {
      const url = new URL(reference.value, origin);
      if (!['http:', 'https:'].includes(url.protocol) || url.username || url.password) continue;
      hosts.push({host: url.hostname, source: reference.source});
    } catch { /* malformed link or header is not a hostname lead */ }
  }
  return {hosts, cut: Math.max(0, references.length - MAX_EXPLICIT_HOST_URLS)};
}

/** Discovery uses only in-scope names, bounded queries and the injected guarded requester. */
export async function discover(scope, {requester, ledger, resolve = defaultResolve, ct = null, offline = false,
  connectTls = null, infer = null, model = null,
  log = () => {}, nowMs = () => Date.now()} = {}) {
  need(typeof requester === 'function' && ledger, 'Discovery needs a guarded requester and ledger.');
  const domains = scope.domains.map(hostname).filter(Boolean);
  const records = new Map(), queue = [], queued = new Set(), sources = new Map(),
    external = new Set(), wildcards = new Map(), dnsCache = new Map();
  const pendingWordlists = [];
  let nextWordlist = 0;
  const stats = {dnsQueries: 0, hostsFound: 0, hostsProbed: 0, hostsLive: 0, ctQueries: 0,
    tlsHandshakes: 0, tlsFailures: 0, tlsNamesCut: 0, cut: 0};
  const deadline = nowMs() + scope.limits.minutes * 60000;
  const maxHosts = scope.limits.hosts, maxDns = scope.limits.dnsQueries;
  const depthLimit = scope.discovery.depth;
  const dnsWords = scope.seeds.dnsWords === 'default' ? null : scope.seeds.dnsWords;
  const wordsFor = depth => dnsWords ?? (depth === 0 ? ROOT_WORDS : CHILD_WORDS);
  const origins = new Set([new URL(scope.target.origin).hostname]);
  for (const domain of domains) origins.add(domain);
  for (const host of scope.discovery.knownHosts ?? []) origins.add(host);
  const seedHosts = new Set([...origins].map(hostname).filter(Boolean));

  function add(raw, source, depth = 0) {
    const host = hostname(raw);
    if (!host) return;
    if (!within(host, domains)) {external.add(host); return;}
    const relative = Math.min(...domains.filter(domain => host === domain || host.endsWith(`.${domain}`))
      .map(domain => host === domain ? 0 : host.slice(0, -domain.length - 1).split('.').length));
    if (relative > depthLimit) {stats.cut++; return;}
    if (!scope.discovery.recurse && !seedHosts.has(host)) return;
    const foundBy = sources.get(host) ?? new Set();
    foundBy.add(source);
    sources.set(host, foundBy);
    if (records.has(host)) records.get(host).foundBy = [...foundBy];
    if (!queued.has(host)) {
      queued.add(host);
      queue.push({host, source, depth: relative});
    }
  }

  async function resolveName(host, source) {
    if (dnsCache.has(host)) return dnsCache.get(host);
    if (!within(host, domains) || stats.dnsQueries >= maxDns || nowMs() >= deadline) {stats.cut++; return [];}
    stats.dnsQueries++;
    let addresses = [], error = null;
    const start = nowMs();
    try {addresses = unique(await resolve(host));} catch (cause) {error = cause.code ?? 'resolve-failed';}
    const evidence = ledger.append({step: 'discovery', kind: 'dns', name: host, type: 'A/AAAA', answer: addresses,
      source, error, ms: nowMs() - start});
    const answer = {addresses, evidence};
    if (!error) dnsCache.set(host, answer);
    return answer;
  }

  async function crt(domain) {
    if (offline || !scope.discovery.recurse || !scope.discovery.external.certificateTransparency) return [];
    stats.ctQueries++;
    const url = `https://crt.sh/?q=%25.${encodeURIComponent(domain)}&output=json`;
    let response;
    try {response = ct ? await ct(domain) : await safeRequest(url, {maxBytes: 2 * 1024 * 1024, timeout: 5000});}
    catch (error) {ledger.append({step: 'discovery', kind: 'lookup', source: 'ct', domain, blocked: {reason: error.message}});return [];}
    const body = typeof response === 'string' ? response : response.body;
    const names = namesFromCt(body, domain);
    ledger.append({step: 'discovery', kind: 'lookup', source: 'ct', domain, status: response.status ?? 200,
      bytes: Buffer.byteLength(body ?? ''), hash: `sha256:${hash(body ?? '')}`, names: names.length});
    return names;
  }

  for (const host of origins) add(host, host === new URL(scope.target.origin).hostname ? 'target' : 'seed');

  // Process one breadth-first batch at a time. Each host owns its request
  // budget and evidence record; the guarded requester owns the shared RPS.
  async function inspectHost({host, source, depth}, dnsResult) {
    stats.hostsFound++;
    const record = {host, depth, foundBy: [...sources.get(host)], addresses: dnsResult.addresses, live: null,
      stack: [], title: null, assets: null, operations: [], operationCut: 0,
      exposures: [], evidence: [dnsResult.evidence], requests: 0};
    records.set(host, record);
    let origin = `https://${host}`;
    let root = await requester({url: `${origin}/`, identity: 'anonymous', method: 'GET', step: 'discovery', purpose: 'discover',
      headers: {accept: 'text/html, application/json;q=0.9, */*;q=0.8'}});
    record.requests++;
    if (root.evidenceId) record.evidence.push(root.evidenceId);
    if (root.status == null && record.requests < scope.limits.requestsPerHost && nowMs() < deadline) {
      origin = `http://${host}`;
      root = await requester({url: `${origin}/`, identity: 'anonymous', method: 'GET', step: 'discovery', purpose: 'discover',
        headers: {accept: 'text/html, application/json;q=0.9, */*;q=0.8'}});
      record.requests++;
      if (root.evidenceId) record.evidence.push(root.evidenceId);
    }
    stats.hostsProbed++;
    if (root.status == null) return;
    stats.hostsLive++;
    record.origin = origin;
    record.live = {[new URL(origin).protocol.slice(0, -1)]: root.status};
    if (origin.startsWith('https:') && nowMs() < deadline) {
      if (!connectTls && !record.addresses.every(publicIP)) {
        const evidenceId = ledger.append({step: 'discovery', kind: 'tls', host,
          blocked: {reason: 'non-public resolved address'}});
        record.evidence.push(evidenceId);
      } else {
        stats.tlsHandshakes++;
        try {
          const certificate = certificateNames(await (connectTls ?? defaultConnectTls)(host, record.addresses));
          stats.tlsNamesCut += certificate.cut;
          stats.cut += certificate.cut;
          const evidenceId = ledger.append({step: 'discovery', kind: 'tls', host,
            certificate: {issuer: certificate.issuer, sans: certificate.sans,
              wildcardSans: certificate.wildcardSans, expires: certificate.expires,
              namesCut: certificate.cut}});
          record.evidence.push(evidenceId);
          record.certificate = {issuer: certificate.issuer, sans: certificate.sans,
            wildcardSans: certificate.wildcardSans, expires: certificate.expires, evidenceId};
          for (const name of certificate.sans) add(name, `tls:${host}`);
        } catch (error) {
          stats.tlsFailures++;
          stats.cut++;
          const evidenceId = ledger.append({step: 'discovery', kind: 'tls', host,
            blocked: {reason: String(error?.code ?? error?.message ?? 'certificate lookup failed').slice(0, 160)}});
          record.evidence.push(evidenceId);
        }
      }
    }
    record.stack = stackOf(root);
    record.title = /<title[^>]*>([^<]{1,160})<\/title>/i.exec(root.body ?? '')?.[1]?.trim() ?? null;
    record.fingerprint = {status: root.status, hash: root.hash, bytes: root.bytes, type: root.type};
    const references = observedHostReferences(root, origin);
    stats.cut += references.cut;
    for (const reference of references.hosts) add(reference.host, `${reference.source}:${host}`);
    if (source === 'wildcard-candidate' && wildcards.get(host.slice(host.indexOf('.') + 1))?.hash === root.hash) {
      record.alias = 'wildcard';
      return;
    }
    const maxRequests = scope.limits.requestsPerHost;
    // Analyze client code before lower-priority path guesses so a tight per-host cap still reaches scripts.
    if (record.requests < maxRequests && nowMs() < deadline) {
      const assetRequester = async options => {
        if (record.requests >= maxRequests || nowMs() >= deadline) {
          stats.cut++;
          return {refused: true, reason: 'per-host discovery budget'};
        }
        record.requests++;
        return requester(options);
      };
      const assets = await mineOrigin(origin, {requester: assetRequester, pages: ['/'], assetHosts: scope.discovery.assetHosts,
        workers: scope.limits.agents,
        crawlPaths: ['/'], maxPages: Math.min(8, Math.max(1, maxRequests - record.requests)),
        maxFiles: Math.min(20, maxRequests - record.requests),
        maxTotal: 8 * 1024 * 1024, log});
      record.assets = assets;
      stats.cut += assets.stats.pagesCut + assets.stats.sourceMapSourcesCut +
        assets.stats.sourceMapBudgetCut;
      for (const endpoint of assets.endpoints ?? []) addOperation(record, endpoint, 'client-asset');
      for (const named of assets.hosts) add(named.host, `asset:${host}`);
    }
    for (const pathname of BASE_PATHS.slice(1)) {
      if (record.requests >= maxRequests || nowMs() >= deadline) {stats.cut++; break;}
      const response = await requester({url: `${origin}${pathname}`, identity: 'anonymous', method: 'GET',
        step: 'discovery', purpose: 'discover'});
      record.requests++;
      if (response.evidenceId) record.evidence.push(response.evidenceId);
      if (response.status === 200 && /(?:openapi|swagger|api-docs)/i.test(pathname)) {
        let doc;
        try {doc = JSON.parse(response.body);} catch {doc = null;}
        if (doc) {
          const parsed = parseOpenApi(doc, origin);
          for (const operation of parsed.operations) addOperation(record, operation, `document:${pathname}`);
          for (const server of parsed.servers) if (URL.canParse(server, origin)) {
            add(new URL(server, origin).hostname, `document:${host}`);
          }
        }
      }
    }
    if (scope.discovery.sensitivePaths) {
      const selection = selectSensitivePathEntries({entries: sensitivePathEntries, mined: record.assets,
        routes: record.operations, maxCandidates: Math.min(30, Math.max(0, maxRequests - record.requests))});
      record.sensitivePathSelection = {available: selection.available, selected: selection.selected,
        skipped: selection.skipped, fingerprints: selection.fingerprints,
        heuristicFingerprints: selection.heuristicFingerprints,
        modelFingerprints: selection.modelFingerprints};
      stats.cut += selection.skipped.length;
      for (const [index, entry] of selection.entries.entries()) {
        if (record.requests >= maxRequests || nowMs() >= deadline) {
          const cut = selection.entries.slice(index).map(item => ({path: item.path, reason: 'host-budget'}));
          record.sensitivePathSelection.skipped.push(...cut);
          stats.cut += cut.length;
          break;
        }
        const response = await requester({url: `${origin}${entry.path}`, identity: 'anonymous', method: 'GET',
          step: 'discovery', purpose: 'sensitive', omitExcerpt: true, noCache: true,
          maxBytes: entry.ranged ? 128 : 65536,
          ...(entry.ranged ? {headers: {range: 'bytes=0-63'}} : {})});
        record.requests++;
        if (response.evidenceId) record.evidence.push(response.evidenceId);
        if (responseSizeLimited(response)) {
          record.sensitivePathSelection.skipped.push({path: entry.path, reason: 'response-size-cut'});
          stats.cut++;
          continue;
        }
        if (sensitivePathMatches(entry.path, response)) record.exposures.push({...entry, evidenceId: response.evidenceId});
      }
    }
    if (scope.discovery.recurse && depth < depthLimit) pendingWordlists.push({host, depth, origin});
  }

  // Resolve and inspect independent hosts concurrently without reserving more
  // hosts than the configured cap. Children discovered by a batch enter the
  // next breadth-first batch after all its peers finish.
  async function drainQueue() {
    const workers = Math.max(1, scope.limits.agents ?? 1);
    while (queue.length && records.size < maxHosts && nowMs() < deadline) {
      const batch = [];
      const slots = Math.min(workers, maxHosts - records.size);
      while (queue.length && batch.length < slots) {
        const item = queue.shift();
        if (!records.has(item.host)) batch.push(item);
      }
      if (!batch.length) continue;
      const dnsSettled = await Promise.allSettled(batch.map(item =>
        resolveName(item.host, item.source)));
      const dnsFailure = dnsSettled.find(item => item.status === 'rejected');
      if (dnsFailure) throw dnsFailure.reason;
      const dnsResults = dnsSettled.map(item => item.value);
      const jobs = [];
      for (const [index, item] of batch.entries()) {
        const dnsResult = dnsResults[index];
        if (!dnsResult?.addresses?.length) continue;
        jobs.push(inspectHost(item, dnsResult));
      }
      const inspected = await Promise.allSettled(jobs);
      const hostFailure = inspected.find(item => item.status === 'rejected');
      if (hostFailure) throw hostFailure.reason;
    }
  }
  await drainQueue();
  if (records.size < maxHosts && nowMs() < deadline) {
    for (const domain of domains) for (const host of await crt(domain)) add(host, 'ct');
    await drainQueue();
  } else if (scope.discovery.recurse && scope.discovery.external.certificateTransparency && !offline) {
    stats.cut += domains.length;
  }

  const modelNaming = {modelCalls: 0, pagesSent: 0, hostsSent: 0, hostsAvailable: 0,
    hostsCut: 0, candidates: 0, accepted: 0, rejected: 0, newHosts: 0, modelError: null};
  if (infer && model && scope.discovery.recurse && records.size < maxHosts && nowMs() < deadline) {
    for (let page = 0; page < MODEL_NAMING_PAGES; page++) {
      const live = [...records.values()].filter(record => record.live);
      let batch = live.slice(modelNaming.hostsSent, modelNaming.hostsSent + MODEL_HOSTS_PER_PAGE);
      if (!batch.length) break;
      let context = namingContext(domains, batch);
      while (batch.length > 1 && Buffer.byteLength(JSON.stringify(context)) > MODEL_CONTEXT_BYTES) {
        batch = batch.slice(0, -1);
        context = namingContext(domains, batch);
      }
      if (Buffer.byteLength(JSON.stringify(context)) > MODEL_CONTEXT_BYTES) {
        modelNaming.modelError = `A host naming summary exceeds the ${MODEL_CONTEXT_BYTES}-byte model input limit.`;
        log({stage: 'discovery-model', message: modelNaming.modelError});
        break;
      }
      let answer;
      try {
        modelNaming.modelCalls++;
        answer = await infer(model, [{role: 'system', content: 'From the observed hostnames and stack hints, propose additional exact DNS hostnames likely to exist under the verified apex domains. Combine observed naming patterns across levels, such as api-staging, api-dev, or region.stage.api. Return only names; do not claim a host exists. No wildcard, off-domain, URL, path, credential or finding. Code validates and resolves each name under the run budget.'},
          {role: 'user', content: JSON.stringify(context)}], {schema: {type: 'object', properties: {
          names: {type: 'array', maxItems: 30, items: {type: 'string', maxLength: 253}}},
          required: ['names'], additionalProperties: false}});
      } catch (error) {
        modelNaming.modelError = error.message;
        log({stage: 'discovery-model', message: `Muse naming failed: ${error.message}`});
        break;
      }
      const names = Array.isArray(answer?.names) ? answer.names.slice(0, 30) : [];
      modelNaming.pagesSent++;
      modelNaming.hostsSent += batch.length;
      modelNaming.candidates += names.length;
      const accepted = [];
      for (const raw of names) {
        const host = typeof raw === 'string' && raw.length <= 253 && !raw.includes('*') ? hostname(raw) : null;
        if (!host || !within(host, domains) || queued.has(host)) {modelNaming.rejected++; continue;}
        const before = queued.size;
        add(host, 'model:naming');
        if (queued.size > before) accepted.push(host);
        else modelNaming.rejected++;
      }
      modelNaming.accepted += accepted.length;
      ledger.append({step: 'discovery', kind: 'model-host-proposals', page: page + 1,
        observed: batch.map(record => record.host), accepted, rejected: names.length - accepted.length});
      const before = stats.hostsFound;
      await drainQueue();
      modelNaming.newHosts += stats.hostsFound - before;
      log({stage: 'discovery-model', message: `Muse naming page ${page + 1}: ${accepted.length} scoped names queued, ${stats.hostsFound - before} resolved hosts`});
      if (records.size >= maxHosts || nowMs() >= deadline) break;
    }
  }
  // Observed seeds, certificate names, asset hosts and model proposals get the first host slots.
  // Only then do speculative wordlist names consume DNS and host budget.
  while (nextWordlist < pendingWordlists.length && records.size < maxHosts && nowMs() < deadline) {
    const {host, depth, origin} = pendingWordlists[nextWordlist++];
    const words = wordsFor(depth);
    const wildcardName = `${randomBytes(10).toString('hex')}.${host}`;
    const wildcard = await resolveName(wildcardName, 'wildcard-check');
    if (wildcard?.addresses?.length) {
      const response = await requester({url: `${new URL(origin).protocol}//${wildcardName}/`, identity: 'anonymous', method: 'GET',
        step: 'discovery', purpose: 'discover'});
      if (response.hash) wildcards.set(host, {hash: response.hash});
    }
    const candidates = words.map(word => `${word}.${host}`);
    for (let at = 0; at < candidates.length; at += 20) {
      if (stats.dnsQueries >= maxDns || nowMs() >= deadline) {stats.cut += candidates.length - at; break;}
      const batch = candidates.slice(at, at + 20);
      const settled = await Promise.allSettled(batch.map(child => resolveName(child, 'wordlist')));
      const failure = settled.find(item => item.status === 'rejected');
      if (failure) throw failure.reason;
      const answers = settled.map(item => item.value);
      for (const [index, child] of batch.entries()) {
        const answer = answers[index];
        if (!answer?.addresses?.length) continue;
        if (wildcard?.addresses?.length && answer.addresses.join(',') === wildcard.addresses.join(','))
          add(child, 'wildcard-candidate');
        else add(child, 'wordlist');
      }
    }
    await drainQueue();
  }
  for (const pending of pendingWordlists.slice(nextWordlist))
    stats.cut += wordsFor(pending.depth).length;
  if (queue.length) stats.cut += queue.length;
  modelNaming.hostsAvailable = [...records.values()].filter(record => record.live).length;
  modelNaming.hostsCut = Math.max(0, modelNaming.hostsAvailable - modelNaming.hostsSent);
  const hosts = [...records.values()];
  log({stage: 'discovery', message: `${hosts.length} resolved hosts, ${stats.hostsLive} live; ${stats.dnsQueries} DNS queries; ${stats.cut} hosts, queries or pages cut by budget`});
  return {domains, hosts, external: [...external], stats, modelNaming, incomplete: stats.cut > 0};
}

function addOperation(record, operation, source) {
  const path = operation?.path;
  const method = String(operation?.method ?? 'UNKNOWN').toUpperCase();
  if (typeof path !== 'string' || !path.startsWith('/') || path.length > 300 ||
      !/^(GET|HEAD|POST|PUT|PATCH|DELETE|OPTIONS|UNKNOWN)$/.test(method)) return;
  const params = (operation.params ?? []).slice(0, 16).map(param => {
    const name = typeof param === 'string' ? param : param?.name;
    const example = typeof param === 'string' ? operation.examples?.[name]?.[0] :
      param?.example ?? operation.examples?.[name]?.[0];
    const safeExample = (typeof example === 'string' || typeof example === 'number') &&
      /^[A-Za-z0-9_.-]{1,64}$/.test(String(example)) &&
      !credentialQueryKey(name ?? '');
    return {name, in: typeof param === 'string' ? null : param?.in ?? null,
      ...(safeExample ? {example: String(example)} : {})};
  }).filter(param => typeof param.name === 'string' && param.name.length <= 80);
  const key = `${method} ${path}`;
  const existing = record.operations.find(item => `${item.method} ${item.path}` === key);
  if (existing) {
    const merged = new Map(existing.params.map(param => [`${param.in} ${param.name}`, param]));
    for (const param of params) {
      const name = `${param.in} ${param.name}`;
      merged.set(name, {...merged.get(name), ...param,
        ...(param.example == null && merged.get(name)?.example != null ?
          {example: merged.get(name).example} : {})});
    }
    existing.params = [...merged.values()];
    existing.source = [...new Set([...existing.source, source])];
    return;
  }
  if (record.operations.length >= 100) {record.operationCut++; return;}
  record.operations.push({method, path, params, source: [source], tag: operation.tag ?? null});
}
