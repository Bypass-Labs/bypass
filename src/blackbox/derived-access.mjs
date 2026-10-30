// Check newly mapped session routes as an anonymous caller. A route name,
// authenticated link, or self-declared private field is only a lead: none
// independently establishes the application's access policy.
import {createHash} from 'node:crypto';
import {PRIVATE_JSON_BYTES, privateDeclarationSignal} from './content-boundary.mjs';
import {responseCached} from './poc-runtime.mjs';
import {responseSizeLimited} from './response-size.mjs';
import {validateUrl} from './scope.mjs';

const jsonType = type => /(?:json|\+json)/i.test(type ?? '');
const staticAsset = pathname => /\.(?:m?js|css|map|png|jpe?g|gif|webp|svg|ico|woff2?|ttf|eot|pdf|zip|gz)$/i.test(pathname);
const possiblePrivateJson = (route, pathname) => jsonType(route.type) ||
  !route.type && !staticAsset(pathname);
const digest = body => `sha256:${createHash('sha256').update(body).digest('hex')}`;
const stable = response => response && !response.blocked && !response.refused &&
  response.status === 200 && !responseCached(response) &&
  jsonType(response.type) && typeof response.body === 'string' &&
  Buffer.byteLength(response.body) <= PRIVATE_JSON_BYTES;
const hashOf = response => typeof response?.hash === 'string' ? response.hash :
  typeof response?.body === 'string' ? digest(response.body) : null;
const signalMatches = (response, signal) => {
  const current = stable(response) ? privateDeclarationSignal(response.body, response.type) : null;
  return !!current && current.markerKey === signal.markerKey &&
    current.materialField === signal.materialField;
};

export async function checkDerivedAnonymousAccess(mapped, surface, scope, {
  requester, requestAuthenticated, budget = 0, deadline = Infinity,
  seen = new Set(), log = () => {},
} = {}) {
  const rows = new Map();
  const byPath = new Map((surface?.patterns ?? []).map(record => [record.pattern, record]));
  const alreadyMeasured = new Set();
  let nonJsonSkipped = 0;
  for (const route of mapped?.routes ?? []) {
    if (route.method !== 'GET' || route.status < 200 || route.status >= 500) continue;
    let url;
    try { url = new URL(route.path, scope.target.origin); } catch { continue; }
    if (url.origin !== scope.target.origin || !byPath.has(url.pathname) || seen.has(url.pathname) ||
        // Public recon already measured the anonymous denial. Keep this route
        // in Muse's authenticated planning surface without spending another
        // anonymous exposure check on the same boundary.
        [401, 403, 404].includes(byPath.get(url.pathname)?.responseFacts?.anonymousStatus) ||
        !validateUrl(scope, route.path, {identity: 'anonymous', method: 'GET'}).ok) continue;
    // This automatic checker only has an oracle for a private JSON document.
    // Static assets stay in the authenticated route inventory for Muse, but
    // should not become anonymous private-read tasks or size-limit blocks.
    if (!possiblePrivateJson(route, url.pathname)) {
      nonJsonSkipped++;
      continue;
    }
    const known = byPath.get(url.pathname)?.responseFacts;
    // Public recon already made the anonymous request. When the authenticated
    // response has the same status, type and shape and no private declaration,
    // a second anonymous exposure check adds no independent boundary evidence.
    // Keep this route in `surface` for Muse; only deduplicate this automatic
    // check so the later protected planner retains its task budget.
    if (!route.privateSignal && Number.isInteger(known?.anonymousStatus) &&
        known.anonymousStatus === route.status &&
        (known.anonymousType ?? null) === (route.type ?? null) &&
        JSON.stringify(known.anonymousShape ?? null) === JSON.stringify(route.shape ?? null)) {
      alreadyMeasured.add(url.pathname);
      continue;
    }
    const prior = rows.get(url.pathname);
    if (!prior || route.privateSignal && !prior.privateSignal)
      rows.set(url.pathname, route);
  }
  for (const pathname of rows.keys()) alreadyMeasured.delete(pathname);
  const candidates = [...rows.values()].sort((a, b) =>
    Number(!!b.privateSignal) - Number(!!a.privateSignal));
  const findings = [], results = [], selected = [], max = Math.max(0, Math.floor(budget));
  let tested = 0;
  for (const route of candidates) {
    if (tested >= max || Date.now() >= deadline) break;
    const pathname = new URL(route.path, scope.target.origin).pathname;
    seen.add(pathname);
    tested++;
    const record = byPath.get(pathname);
    const call = (step, auth = false) => (auth ? requestAuthenticated : requester)({
      url: route.path, identity: 'anonymous', method: 'GET', purpose: 'task', step,
      noCache: true, omitExcerpt: true, maxBytes: PRIVATE_JSON_BYTES,
      headers: {'cache-control': 'no-cache'},
    });
    const lead = {path: route.path, parameter: null, basis: 'derived-session-route'};
    selected.push({kind: 'derived-private-read', path: route.path, parameter: null,
      priority: route.privateSignal ? 8 : 3, by: 'observed-derived-route',
      basis: 'derived-session-route'});
    let first;
    try { first = await call('task'); } catch { first = {blocked: true, reason: 'request-failed'}; }
    const evidence = [first.evidenceId].filter(Boolean);
    if (record) record.fingerprint = {...record.fingerprint,
      anonymous: {status: first.status ?? null, type: first.type ?? null,
        hash: hashOf(first), evidenceId: first.evidenceId ?? null}};
    let verdict = 'inconclusive', reason = 'anonymous read completed; private account impact was not established';
    if (first.blocked || first.refused) {
      if (responseSizeLimited(first)) {
        verdict = 'inconclusive';
        reason = 'private JSON response exceeded the 16 MiB requester limit';
      } else {
        verdict = 'blocked'; reason = first.reason ?? 'guarded request refused';
      }
    } else if (!Number.isInteger(first.status) || first.status === 429 || first.status >= 500 ||
        responseCached(first)) {
      verdict = 'inconclusive'; reason = 'anonymous response unavailable, throttled or cached';
    } else if (route.privateSignal && [401, 403, 404].includes(first.status)) {
      verdict = 'not_reproduced'; reason = 'anonymous caller was denied the self-declared private resource';
    } else if (route.privateSignal && route.privateHash && stable(first) &&
        signalMatches(first, route.privateSignal) && hashOf(first) === route.privateHash) {
      let owner, second;
      try {
        owner = await call('control', true);
        second = await call('reverify');
      } catch { owner = {blocked: true}; second = {blocked: true}; }
      evidence.push(...[owner.evidenceId, second.evidenceId].filter(Boolean));
      const matched = stable(owner) && stable(second) &&
        signalMatches(owner, route.privateSignal) &&
        signalMatches(second, route.privateSignal) &&
        hashOf(owner) === route.privateHash && hashOf(second) === route.privateHash;
      verdict = 'inconclusive';
      reason = matched ? 'fresh authenticated and anonymous reads matched self-declared private JSON; independent access policy or denial control is missing' :
        'private response or fresh controls changed';
    }
    results.push({lead, kind: 'derived-private-read', verdict, reason, evidence,
      origin: scope.target.origin});
  }
  const cut = Math.max(0, candidates.length - tested);
  log({stage: 'derived-recon', message: `${tested} protected routes checked anonymously; ` +
    `${alreadyMeasured.size} reused from public recon; ${nonJsonSkipped} non-JSON routes left to Muse; ` +
    `${cut} untested within remaining task/time budget`});
  return {findings, results, tested, cut, alreadyMeasured: alreadyMeasured.size, nonJsonSkipped,
    plan: selected, strategyDecisions: [],
    investigations: [], modelCoverage: {pagesAvailable: 0, pagesSent: 0,
      candidatesAvailable: 0, candidatesSent: 0}, modelCalls: 0, modelError: null};
}
