// Read-only route discovery from robots, sitemaps and linked directory indexes.
// Every request uses the guarded requester; robots directives are leads, never findings.
import {extractFromHtml, maskSecrets} from './assets.mjs';
import {mutatingActionPath, validateUrl} from './scope.mjs';
import {randomBytes} from 'node:crypto';

const MAX_ROUTES = 160;
const MAX_REQUESTS = 64;
const MAX_DEPTH = 4;
const MAX_LINKS = 48;
const MAX_ASSET_PAGES = 16;
const TEXT_BYTES = 131072;
const FILE_BYTES = 128;
const FILE_CANDIDATE = /(?:\.(?:kdbx|sqlite|sqlite3|db|sql|zip|tar|gz|tgz|pem|key|p12|pfx|env|bak|old|backup|ini|conf|ya?ml|log)|\/(?:\.env|\.gitignore))$/i;
const PAGE_CANDIDATE = /(?:\/|\/[^/.]+|\/[^/]+\.(?:html?|php|aspx?|jsp|cfm))$/i;
const API_DOCUMENT = /(?:openapi|swagger|api-docs)(?:\/[\w.-]+)?\.(?:json|ya?ml)$/i;

function pathOf(value, base, scope) {
  if (typeof value !== 'string' || !value || value.length > 500 || /[\x00-\x1f\x7f\\]/.test(value) ||
      maskSecrets(value) !== value || !URL.canParse(value, base)) return null;
  const url = new URL(value, base);
  if (url.origin !== scope.target.origin || url.username || url.password || url.hash ||
      !/^\/[A-Za-z0-9_./~!$&'()+,;=:@-]*$/.test(url.pathname)) return null;
  // Query values in links can contain live tokens. Retain only the route path.
  url.search = '';
  const checked = validateUrl(scope, url.href, {identity: 'anonymous', method: 'GET', purpose: 'task'});
  return checked.ok ? url.pathname : null;
}

/** Extract literal same-origin route leads; wildcard directives yield only their literal prefix. */
export function parseRobots(text, base, scope) {
  const leads = [];
  for (const [index, raw] of String(text ?? '').split(/\r?\n/).entries()) {
    const line = raw.replace(/\s+#.*$/, '').trim();
    const match = /^(Allow|Disallow|Sitemap)\s*:\s*(\S+)/i.exec(line);
    if (!match) continue;
    const directive = match[1].toLowerCase();
    let value = match[2];
    if (directive !== 'sitemap') value = value.split(/[?*$]/, 1)[0];
    if (!value || value === '/') continue;
    const path = pathOf(value, base, scope);
    if (path) leads.push({path, source: `robots:${directive}`, line: index + 1});
  }
  return leads;
}

function sitemapPaths(body, base, scope) {
  return [...String(body ?? '').matchAll(/<loc\b[^>]*>([^<]{1,500})<\/loc>/gi)]
    .map(match => pathOf(match[1].trim().replace(/&amp;/g, '&'), base, scope)).filter(Boolean);
}

function listingLinks(path, response, scope) {
  const url = new URL(path.endsWith('/') ? path : `${path}/`, scope.target.origin).href;
  if (response?.status !== 200) return [];
  if (/json/i.test(response.type ?? '')) {
    let names;
    try {names = JSON.parse(response.body);} catch {return [];}
    if (!Array.isArray(names) || names.length < 3 || names.length > 200 ||
        !names.every(name => typeof name === 'string' && /^[A-Za-z0-9_.-]{1,120}$/.test(name)) ||
        names.filter(name => /\.[A-Za-z0-9]{1,10}$/.test(name)).length < 2) return [];
    return names.map(name => pathOf(name, url, scope)).filter(Boolean);
  }
  if (!/html/i.test(response.type ?? '') ||
      !/<title>\s*(?:index of|listing directory)\b/i.test(response.body ?? '')) return [];
  const title = /<title>([^<]{1,300})<\/title>/i.exec(response.body ?? '')?.[1] ?? '';
  if (!title.includes(path) && !title.includes(path.replace(/\/$/, ''))) return [];
  const links = extractFromHtml(response.body, {url}).links
    .map(value => pathOf(value, url, scope))
    .filter(value => value && value !== path && value !== path.replace(/\/$/, '') &&
      value.startsWith(path.endsWith('/') ? path : `${path}/`));
  return [...new Set(links)];
}

export function directoryListingMatches(path, response, scope) {
  return listingLinks(path, response, scope).length > 0;
}

const signatureDefinitions = [
  {signature: 'KeePass KDBX header', severity: 'medium', match: response =>
    /^03d9a29a67fb4bb5/i.test(response.prefixHex ?? '')},
  {signature: 'SQLite database header', severity: 'medium', match: response =>
    /^53514c69746520666f726d6174203300/i.test(response.prefixHex ?? '')},
  {signature: 'ZIP archive header', severity: 'low', match: response =>
    /^504b0304/i.test(response.prefixHex ?? '')},
  {signature: 'PEM private key', severity: 'high', match: response =>
    /^-----BEGIN (?:[A-Z]+ )*PRIVATE KEY-----/m.test(response.body ?? '')},
  {signature: 'SQL dump statements', severity: 'medium', match: response =>
    /(?:^|\n)\s*(?:CREATE TABLE|INSERT INTO)\s+/i.test(response.body ?? '')},
  {signature: 'environment key-value lines', severity: 'medium', match: response =>
    !/html/i.test(response.type ?? '') && /(?:^|\n)\s*[A-Za-z_][A-Za-z0-9_]*\s*=\s*\S+/m.test(response.body ?? '')},
];

export function observedExposureMatches(exposure, response, scope) {
  if (exposure.signature === 'directory index')
    return response?.status === 200 && directoryListingMatches(exposure.path, response, scope);
  if (!fileRangeValid(response)) return false;
  return !!signatureDefinitions.find(item => item.signature === exposure.signature)?.match(response);
}

function fileSignature(response) {
  if (!fileRangeValid(response) || /html/i.test(response.type ?? '')) return null;
  return signatureDefinitions.find(item => item.match(response)) ?? null;
}

function fileRangeValid(response) {
  return response?.status === 200 || response?.status === 206 &&
    /^bytes 0-\d{1,2}\/\d+$/i.test(response.headers?.['content-range'] ?? '');
}

function missingSibling(path) {
  const parent = path.endsWith('/') ? path : path.slice(0, path.lastIndexOf('/') + 1);
  const extension = path.endsWith('/') ? '' : /\.[A-Za-z0-9]{1,10}$/.exec(path)?.[0] ?? '';
  return `${parent}__bypass_absent_${randomBytes(6).toString('hex')}${extension}`;
}

/** Return observed route records, independently rechecked exposures, and bounded coverage. */
export async function reconObservedRoutes(scope, requester, {deadline = Infinity, log = () => {}} = {}) {
  const origin = scope.target.origin;
  const queue = [], queued = new Set(), records = new Map(), exposures = [];
  const cuts = {scope: 0, routes: 0, requests: 0, depth: 0, links: 0, time: 0, fileSize: 0};
  let requests = 0, listings = 0, filesChecked = 0, filesUnfetched = 0;
  const recordOnly = (path, source, from) => {
    if (records.size >= MAX_ROUTES && !records.has(path)) {cuts.routes++; return;}
    const item = records.get(path) ?? {path, method: 'GET', sources: [],
      status: null, evidenceId: null, links: 0, listing: false};
    item.sources.push({source, from});
    records.set(path, item);
    filesUnfetched++;
  };
  const enqueue = (value, source, depth = 0, from = null, line = null) => {
    const path = pathOf(value, origin, scope);
    if (!path) {cuts.scope++; return;}
    if (depth > MAX_DEPTH) {cuts.depth++; return;}
    if (records.size >= MAX_ROUTES && !records.has(path)) {cuts.routes++; return;}
    const record = records.get(path) ?? {path, method: 'GET', sources: [], status: null,
      evidenceId: null, links: 0, listing: false};
    if (!record.sources.some(item => item.source === source && item.from === from))
      record.sources.push({source, ...(from ? {from} : {}), ...(line ? {line} : {})});
    records.set(path, record);
    if (!queued.has(path)) {queued.add(path); queue.push({path, depth});}
  };

  // Fetch robots with its explicit discover allowance even when the operator's include is narrow.
  const robotsAllowed = validateUrl(scope, '/robots.txt', {identity: 'anonymous', purpose: 'discover'}).ok;
  if (robotsAllowed && Date.now() < deadline) {
    const response = await requester({url: '/robots.txt', identity: 'anonymous', method: 'GET',
      step: 'recon', purpose: 'discover', maxBytes: TEXT_BYTES});
    requests++;
    if (response?.status === 200 && !/html/i.test(response.type ?? ''))
      for (const lead of parseRobots(response.body, origin, scope))
        enqueue(lead.path, lead.source, 0, '/robots.txt', lead.line);
  }
  if (validateUrl(scope, '/sitemap.xml', {identity: 'anonymous', purpose: 'discover'}).ok)
    enqueue('/sitemap.xml', 'standard-sitemap');
  enqueue('/', 'entry-page');
  for (const value of scope.discover ?? []) if (value !== '/robots.txt' && value !== '/')
    enqueue(value, 'scope-discover');

  const workers = Math.max(1, scope.limits?.agents ?? 1);
  while (queue.length && requests < MAX_REQUESTS && Date.now() < deadline) {
    const batch = [];
    while (queue.length && batch.length < workers && requests < MAX_REQUESTS &&
        Date.now() < deadline) {
      const item = queue.shift();
      if (mutatingActionPath(item.path) && batch.length) {
        queue.unshift(item);
        break;
      }
      const isCandidate = FILE_CANDIDATE.test(item.path);
      // Reserve the fixed request budget before any await. Responses are
      // interpreted in queue order, so newly observed links join the next batch.
      requests++;
      batch.push({...item, isCandidate, response: requester({url: item.path,
        identity: 'anonymous', method: 'GET', step: 'recon', purpose: 'task',
        maxBytes: isCandidate ? FILE_BYTES : TEXT_BYTES,
        ...(isCandidate ? {headers: {range: 'bytes=0-63'}} : {}),
        omitExcerpt: isCandidate})});
      if (mutatingActionPath(item.path)) break;
    }
    const settled = await Promise.allSettled(batch.map(item => item.response));
    const failure = settled.find(item => item.status === 'rejected');
    if (failure) throw failure.reason;
    const responses = settled.map(item => item.value);
    for (const [index, {path, depth, isCandidate}] of batch.entries()) {
    const record = records.get(path);
    const response = responses[index];
    const negotiatedHtml = false;
    record.status = Number.isInteger(response?.status) ? response.status : null;
    record.type = response?.type ?? null;
    record.evidenceId = response?.evidenceId ?? null;
    if (isCandidate) filesChecked++;
    if (isCandidate && response?.blocked && /size limit/i.test(response.reason ?? '')) cuts.fileSize++;
    if (response?.status >= 300 && response.status < 400 && response.headers?.location) {
      const redirected = pathOf(response.headers.location, new URL(path, origin).href, scope);
      if (redirected && redirected !== path) enqueue(redirected, 'same-origin-redirect', depth, path);
    }
    if (![200, 206].includes(response?.status)) continue;
    if (/xml/i.test(response.type ?? '') || /<\?(?:xml|sitemap)/i.test(response.body ?? '')) {
      const paths = sitemapPaths(response.body, new URL(path, origin).href, scope);
      cuts.links += Math.max(0, paths.length - MAX_LINKS);
      for (const linked of paths.slice(0, MAX_LINKS)) enqueue(linked, 'sitemap-loc', depth + 1, path);
    }
    const links = listingLinks(path, response, scope);
    if (links.length) {
      const fresh = requests < MAX_REQUESTS && Date.now() < deadline ?
        await requester({url: path, identity: 'anonymous', method: 'GET', step: 'reverify',
          purpose: 'task', maxBytes: TEXT_BYTES, noCache: true,
          headers: {'cache-control': 'no-cache',
            ...(negotiatedHtml ? {accept: 'text/html'} : {})}}) : null;
      if (fresh) requests++;
      const confirmedLinks = listingLinks(path, fresh, scope);
      const controlPath = missingSibling(path.endsWith('/') ? path : `${path}/`);
      const control = requests < MAX_REQUESTS && Date.now() < deadline ?
        await requester({url: controlPath, identity: 'anonymous', method: 'GET', step: 'control',
          purpose: 'task', maxBytes: TEXT_BYTES, noCache: true, omitExcerpt: true,
          ...(negotiatedHtml ? {headers: {accept: 'text/html'}} : {})}) : null;
      if (control) requests++;
      const distinctControl = Number.isInteger(control?.status) && control.status < 500 &&
        control.hash !== response.hash && !directoryListingMatches(controlPath, control, scope);
      if (distinctControl && links.some(link => confirmedLinks.includes(link))) {
        record.listing = true;
        record.links = links.length;
        listings++;
        exposures.push({path, signature: 'directory index', severity: 'low',
          source: 'observed-directory', evidenceId: response.evidenceId,
          confirmationEvidence: fresh.evidenceId, controlEvidence: control.evidenceId,
          acceptHtml: negotiatedHtml, hash: fresh.hash});
      }
      cuts.links += Math.max(0, links.length - MAX_LINKS);
      for (const linked of links.slice(0, MAX_LINKS)) {
        // A .url file can name an external download. Record it, but do not request its body.
        if (/\.(?:url|desktop|webloc)$/i.test(linked)) {
          recordOnly(linked, 'directory-link-unfetched', path);
          continue;
        }
        if (FILE_CANDIDATE.test(linked) || PAGE_CANDIDATE.test(linked))
          enqueue(linked, 'directory-link', depth + 1, path);
        else recordOnly(linked, 'directory-file-unfetched', path);
      }
    } else if (/html/i.test(response.type ?? '') && !isCandidate) {
      const links = extractFromHtml(response.body, {url: new URL(path, origin).href}).links;
      cuts.links += Math.max(0, links.length - MAX_LINKS);
      for (const linked of links.slice(0, MAX_LINKS)) {
        const next = pathOf(linked, new URL(path, origin).href, scope);
        if (next && (PAGE_CANDIDATE.test(next) || API_DOCUMENT.test(next)))
          enqueue(next, 'html-link', depth + 1, path);
      }
    }
    if (isCandidate) {
      const matched = fileSignature(response);
      if (matched && requests < MAX_REQUESTS && Date.now() < deadline) {
        const fresh = await requester({url: path, identity: 'anonymous', method: 'GET',
          step: 'reverify', purpose: 'task', maxBytes: FILE_BYTES,
          noCache: true, omitExcerpt: true,
          headers: {'cache-control': 'no-cache', range: 'bytes=0-63'}});
        requests++;
        const controlPath = missingSibling(path);
        const control = requests < MAX_REQUESTS && Date.now() < deadline ?
          await requester({url: controlPath, identity: 'anonymous', method: 'GET',
            step: 'control', purpose: 'task', maxBytes: FILE_BYTES,
            noCache: true, omitExcerpt: true, headers: {range: 'bytes=0-63'}}) : null;
        if (control) requests++;
        if (observedExposureMatches({path, signature: matched.signature}, fresh, scope) &&
            Number.isInteger(control?.status) && control.status < 500 &&
            !observedExposureMatches({path: controlPath, signature: matched.signature}, control, scope))
          exposures.push({path, signature: matched.signature, severity: matched.severity,
            source: 'observed-file', evidenceId: response.evidenceId,
            confirmationEvidence: fresh.evidenceId, controlEvidence: control.evidenceId,
            hash: fresh.hash});
      }
    }
    }
  }
  if (queue.length) cuts.requests += queue.length;
  if (Date.now() >= deadline) cuts.time += queue.length;
  const routes = [...records.values()];
  const eligibleAssetPages = routes.filter(item => item.status === 200 &&
    /html/i.test(item.type ?? '') && PAGE_CANDIDATE.test(item.path))
    .map(item => item.path);
  cuts.assetPages = Math.max(0, eligibleAssetPages.length - MAX_ASSET_PAGES);
  const assetPages = eligibleAssetPages.slice(0, MAX_ASSET_PAGES);
  const stats = {routes: routes.length, requested: requests, listings, filesChecked,
    filesUnfetched,
    exposures: exposures.length, queued: queue.length, cuts};
  log({stage: 'recon', message: `Observed routes: ${routes.length} paths from robots, sitemaps and links; ${listings} directory indexes; ${filesChecked} file checks; ${Object.values(cuts).reduce((a, b) => a + b, 0)} cut`});
  return {routes, exposures, assetPages, stats};
}
