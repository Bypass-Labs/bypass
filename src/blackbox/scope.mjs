// Scope of a black-box audit: the authoritative defaults, scope-file loading, never/include matching,
// URL validation, the token bucket, credential placement and the guarded requester that every stage
// sends its HTTP through (GET/HEAD plus exact reviewed method/body contracts, credentials only to
// credentialOrigins, everything recorded).
// Implements design sections 4.1, 4.2, 7.4 (steps 1, 3, 4, 5) and 17 of docs/BLACKBOX_AUDIT.md.
import fs from 'node:fs';
import { safeRequest, pathAllowed, loopback, scopeReady } from '../network.mjs';
import { hash, need, Fault, envName, delay } from '../util.mjs';
import { scrub } from './ledger.mjs';
import {jwtUnsignedCanaries, validModelHeaders} from './poc-runtime.mjs';
import {credentialQueryKey, maskCredentialParams} from './private-query.mjs';
export {credentialQueryKey};

const READ_METHODS = ['GET', 'HEAD'];
const WRITE_METHODS = ['POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'];
const WRITE_PLACEMENTS = ['json', 'form', 'xml', 'query', 'header'];
const PURPOSES = new Set(['task', 'discover', 'asset', 'sensitive', 'xml-body', 'json-body', 'form-body', 'auth-body', 'reviewed-method']);
const MAX_QUERY_PARAMS = 8;
const MAX_AGENTS = 100;
const AUTH_FORMAT = /^(bearer|cookie|header:[A-Za-z0-9!#$%&'*+.^_`|~-]+)$/;
const WORDLIST_FIELDS = new Set(['seeds.words', 'seeds.children', 'seeds.dnsWords']);
const STEPS = new Set(['discovery', 'recon', 'identity', 'control', 'task', 'anonymous', 'followup', 'reverify', 'mirror', 'chain', 'poc']);
const JWT_CANARY_IDENTITIES = new Map([['jwt-invalid-signature', 'invalidSignature'],
  ['jwt-unsigned-one', 'first'], ['jwt-unsigned-two', 'second']]);
const STORED_HEADERS = ['content-type', 'cache-control', 'age', 'x-cache', 'etag', 'vary', 'www-authenticate', 'location', 'link',
  'content-range',
  'access-control-allow-origin', 'access-control-allow-credentials', 'content-security-policy',
  'server', 'x-powered-by', 'retry-after', 'x-ratelimit-remaining'];
const MAX_BODY_BYTES = 16 * 1024 * 1024;
const SHAPE_BYTES = 2048;
const EXCERPT_SOURCE_CHARS = 8192;
const STORED_URL_CHARS = 2048;
const RETRY_DELAY_MS = 200;
const RETRYABLE_FAULT = /^Request failed: (ECONNRESET|ECONNREFUSED|ECONNABORTED|EPIPE|ETIMEDOUT|EHOSTUNREACH|ENETUNREACH|EAI_AGAIN)\b|^Response interrupted/;
const MIN_RPS = 0.5;
const HALVE_COOLDOWN_MS = 1000;
const ID_KEY = /^(id|_id|uid|uuid|slug)$|(Id|ID|_id|_uid)$/;
const OWNERSHIP_KEY = /^(userId|ownerId|owner_uid|uid|createdBy|email|accountId|tenantId)$|(UserId|_uid|OwnerId|Id|_id)$/;
const INVALID_HEADER_CHAR = /[^\t\x20-\x7e\x80-\xff]/;
// Some applications mutate state through GET. Keep this deliberately narrow: an
// action segment or an explicit action query, not a substring anywhere in a route.
// An operator may review and opt in an exact path through scope.discover.
const MUTATING_READ_ACTION = /^(?:delete|remove|destroy|logout|signout|signoff|unsubscribe|revoke|purge|checkout|charge)(?:$|[-_])/i;
const MUTATING_READ_SEGMENT = /^(?:delete|remove|destroy|logout|signout|signoff|unsubscribe|revoke|purge|checkout|charge)$/i;

function externalDestination(value, origin, {allowEmail = false, allowedEmails = null} = {}) {
  const text = String(value);
  for (const match of text.matchAll(/\b[a-z][a-z0-9+.-]*:\/\/[^\s"'<>)]*/gi)) {
    let url;
    try {url = new URL(match[0]);} catch {return true;}
    if (!['http:', 'https:'].includes(url.protocol) ||
        url.origin !== origin && !url.hostname.endsWith('.invalid')) return true;
  }
  if (allowEmail || allowedEmails?.has(text)) return false;
  // A synthetic mailbox at a reserved example domain is a canary value, not
  // an external recipient. Keep rejecting real mailbox domains and URLs.
  for (const match of text.matchAll(/\b[A-Za-z0-9._%+-]+@([A-Za-z0-9.-]+\.[A-Za-z]{2,})\b/g))
    if (!/^(?:[A-Za-z0-9-]+\.)*(?:invalid|test|localhost|example\.(?:com|net|org))$/i.test(match[1]))
      return true;
  return false;
}

/** Built-in scope: route words are not implicit exclusions. Methods and reviewed bodies control writes. Deep-frozen. */
export const DEFAULT_SCOPE = deepFreeze({
  schemaVersion: 1,
  target: {origin: 'http://127.0.0.1:4329', environment: 'local', acknowledged: null},
  domains: [],
  discovery: {recurse: true, depth: 127, knownHosts: [], sensitivePaths: true, assetHosts: [], auditDomains: [],
    external: {certificateTransparency: false, osv: false, wayback: false}},
  credentialOrigins: ['http://127.0.0.1:4329'],
  include: ['/'],
  discover: ['/', '/openapi.json', '/swagger.json', '/swagger/v1/swagger.json', '/api-docs', '/docs', '/robots.txt', '/sitemap.xml'],
  never: [],
  methods: ['GET', 'HEAD', 'POST', 'PATCH', 'DELETE'],
  identities: {owner: {env: 'OWNER_TOKEN', role: 'member', login: null},
    outsider: {env: 'OTHER_TOKEN', role: 'member', login: null}, auth: 'bearer', identityPath: null,
    identityCookieName: null, login: null},
  harvest: {useOutsiderIds: true, sequentialNeighbors: 3, thirdParty: 'read', redactFields: ['email', 'phone']},
  probes: {
    crlfResponseHeader: true,
    hostHeaderRedirect: true,
    jwtUnsigned: true,
    commandExecution: true,
    pathTraversal: true,
    xmlExternalEntity: true,
    xmlPostPaths: [],
    jsonPostPaths: [],
    formPostPaths: [],
    writeOperations: [],
    massExposure: ['all=1', 'all=true', 'scope=all', 'mine=false', 'limit=1000', 'include=all'],
    expandKeys: ['include', 'expand', 'fields'],
    expandValues: ['email', 'user', 'owner', 'private', 'all', '*'],
    identityFilters: ['userId', 'user_id', 'uid', 'owner', 'ownerId', 'owner_uid', 'account', 'accountId', 'tenant', 'tenantId', 'email'],
  },
  limits: {rps: 50, hosts: 200, dnsQueries: 5000, requestsPerHost: 50, maxUrls: 400,
    domScriptBytes: 2 * 1024 * 1024, tasks: 0, agents: 40, waves: 1,
    modelCalls: 120, modelConcurrency: 4, researchCallsPerHypothesis: 100, minutes: 10},
  seeds: {openapi: null, lists: [], paths: [], words: 'default', children: 'default', dnsWords: 'default'},
  expiresAt: null,
  notes: '',
});

/** Zero in a reviewed scope means the task count is governed by time, rate and model budgets. */
export function taskAllowance(scope) {
  return scope.limits.tasks === 0 ? Number.MAX_SAFE_INTEGER : scope.limits.tasks;
}

/**
 * Loads the effective scope: DEFAULT_SCOPE <- scope file (optional JSON path) <- overrides
 * {ownerEnv, otherEnv, auth, identityPath, modelAgents, httpWorkers, waves, rps,
 * modelCalls, maxUrls, maxTasks, domScriptBytes, acceptLocal, includes, domains}.
 * Network and HTTP worker flags may lower a limit the file sets, never raise it (Fault 2 'exceeds scope').
 * modelAgents and modelCalls are inference execution settings, so explicit run flags may
 * raise or lower their saved values. A loopback
 * origin needs a reviewed local scope file or acceptLocal (Fault 3); deployed origins need a verified, authorized target and
 * separate current DNS ownership proof for every apex domain in the scope.
 * @returns {{scope: object, hash: string}} the deep-frozen scope and hash(JSON.stringify(scope))
 */
export function loadScope({file, origin, overrides = {}, targets = []} = {}) {
  const fromFile = file ? readScopeFile(file) : {};
  const scope = mergeScope(structuredClone(DEFAULT_SCOPE), fromFile, '');
  const target = originOf(origin ?? fromFile.target?.origin ?? DEFAULT_SCOPE.target.origin);
  if (fromFile.target?.origin != null) {
    const written = originOf(fromFile.target.origin);
    need(written === target, `The scope file ${file} is written for ${written}, not ${target}.`);
  }
  const local = loopback(new URL(target).hostname);
  if (local) need(overrides.acceptLocal === true || !!file,
    `${target} is a loopback target: run blackbox setup to create a scope, or pass --accept-local.`, 3);
  else need(file, 'A deployed target needs a reviewed blackbox.scope.json, target verify, and target authorize.', 3);
  const registered = targets.find(item => item.url === target);
  if (!local) {
    need(registered, `Add ${target} with target add, then run target verify and target authorize.`, 3);
    scopeReady(registered);
  }
  scope.target = {origin: target, environment: local ? 'local' : registered.environment, acknowledged: local ? 'local-owner' : 'verified-authorized'};
  scope.credentialOrigins = (fromFile.credentialOrigins ?? [target]).map(originOf);
  // A reviewed `never` array is authoritative. Older saved scopes retain their written exclusions.
  // Redaction fields always retain their defaults independently of request scope.
  scope.never = [...new Set(scope.never)];
  scope.harvest.redactFields = [...new Set([...DEFAULT_SCOPE.harvest.redactFields, ...scope.harvest.redactFields])];
  applyOverrides(scope, fromFile, overrides);
  if (!local && fromFile.harvest?.thirdParty == null) scope.harvest.thirdParty = 'count-only';
  if (!local && scope.harvest.thirdParty !== 'read') scope.harvest.sequentialNeighbors = 0;
  if (local && scope.domains.length) need(overrides.testResolver === true &&
    scope.domains.every(domain => domain.endsWith('.test')),
    'A loopback run can enumerate only injected .test fixture domains; deployed domains need DNS TXT proof.', 3);
  if (!local) {
    for (const entry of scope.include) need(pathAllowed(entry, registered.authorization.paths),
      `Include ${entry} exceeds target authorization.`, 2);
    if (scope.probes.jsonPostPaths.length || scope.probes.formPostPaths.length)
      need(registered.authorization.methods.includes('POST'),
        'Reviewed JSON/form POST paths need POST in the target authorization.', 2);
    need(scope.limits.rps <= registered.authorization.maxRequestsPerSecond,
      `Scope rate ${scope.limits.rps} exceeds target authorization rate ${registered.authorization.maxRequestsPerSecond}.`, 2);
    for (const domain of scope.domains) {
      const apex = targets.find(item => item.url === `https://${domain}`);
      need(apex?.ownership?.method === 'dns' && apex.ownership.status === 'verified' &&
        Date.parse(apex.ownership.expiresAt) > Date.now(),
        `Apex ${domain} needs its own current DNS TXT ownership proof (target add/verify).`, 3);
    }
    for (const domain of scope.discovery.auditDomains) {
      const apex = targets.find(item => item.url === `https://${domain}`);
      need(apex, `Active descendant audit for ${domain} needs a registered apex target.`, 3);
      scopeReady(apex);
      for (const entry of scope.include) need(pathAllowed(entry, apex.authorization.paths),
        `Include ${entry} exceeds ${domain} descendant audit authorization.`, 2);
      need(scope.limits.rps <= apex.authorization.maxRequestsPerSecond,
        `Scope rate ${scope.limits.rps} exceeds ${domain} descendant audit authorization.`, 2);
    }
    for (const origin of scope.credentialOrigins) {
      const authorized = targets.find(item => item.url === origin);
      need(authorized, `Credential origin ${origin} needs its own registered target authorization.`, 3);
      scopeReady(authorized);
      for (const entry of scope.include) need(pathAllowed(entry, authorized.authorization.paths),
        `Include ${entry} exceeds credential origin ${origin} authorization.`, 2);
      need(scope.limits.rps <= authorized.authorization.maxRequestsPerSecond,
        `Scope rate ${scope.limits.rps} exceeds credential origin ${origin} authorization.`, 2);
    }
    const expiry = Math.min(Date.parse(scope.expiresAt ?? registered.authorization.expiresAt),
      Date.parse(registered.authorization.expiresAt), Date.parse(registered.ownership.expiresAt),
      ...scope.domains.map(domain => Date.parse(targets.find(item => item.url === `https://${domain}`).ownership.expiresAt)),
      ...scope.credentialOrigins.map(origin => Date.parse(targets.find(item => item.url === origin).authorization.expiresAt)),
      ...scope.credentialOrigins.map(origin => Date.parse(targets.find(item => item.url === origin).ownership.expiresAt)),
      ...scope.discovery.auditDomains.map(domain => Date.parse(targets.find(item => item.url === `https://${domain}`).authorization.expiresAt)));
    scope.expiresAt = new Date(expiry).toISOString();
    scope.authorizedOrigins = Object.fromEntries([target, ...scope.credentialOrigins]
      .filter((origin, index, all) => all.indexOf(origin) === index).map(origin => {
      const record = targets.find(item => item.url === origin);
      return [origin, {url: record.url, environment: record.environment,
        ownership: record.ownership, authorization: record.authorization}];
    }));
    scope.authorizedDomains = Object.fromEntries(scope.discovery.auditDomains.map(domain => {
      const record = targets.find(item => item.url === `https://${domain}`);
      return [domain, {url: record.url, ownership: record.ownership, authorization: record.authorization}];
    }));
  }
  checkScope(scope);
  deepFreeze(scope);
  return {scope, hash: hash(JSON.stringify(scope))};
}

/**
 * Checks a path and query against scope.never (design 4.2). Entries starting with '/' are globs
 * over the lowercased path ('*' spans anything, '/' included). Other entries are verbs: a path
 * segment, decoded query key or value matches when, lowercased, it starts with the verb and the
 * character after it is not a lowercase letter (delete, delete-all, deleteUser; not sender).
 * @returns {{refused: false} | {refused: true, rule: 'never', match: string}}
 */
export function matchNever(scope, pathname, query = '') {
  const path = String(pathname ?? '');
  const params = [...new URLSearchParams(query ?? '')].flat();
  const words = [...path.split('/'), ...params].filter(Boolean);
  for (const entry of scope.never) {
    const rule = entry.trim().toLowerCase();
    const hit = rule.startsWith('/') ? globPattern(rule).test(path.toLowerCase()) : words.some(word => verbMatches(rule, word));
    if (hit) return {refused: true, rule: 'never', match: entry};
  }
  return {refused: false};
}

export function mutatingActionPath(pathname) {
  const segments = String(pathname).split('/').filter(Boolean);
  return MUTATING_READ_ACTION.test(segments.at(-1) ?? '') ||
    segments.slice(0, -1).some(segment => MUTATING_READ_SEGMENT.test(segment));
}

function mutatingReadAction(parsed) {
  if (mutatingActionPath(parsed.pathname)) return true;
  return [...parsed.searchParams].some(([key, value]) =>
    /^(?:action|op|do)$/i.test(key) && MUTATING_READ_ACTION.test(value));
}

function observedMethodAuthorized(scope, method) {
  return scope.methods.includes(method) && WRITE_METHODS.includes(method) &&
    (scope.target.environment === 'local' ||
    scope.target.acknowledged === 'verified-authorized' &&
    scope.authorizedOrigins?.[scope.target.origin]?.authorization?.methods?.includes(method) === true);
}

/** True when the path sits under an include prefix, matched exactly as pathAllowed does. */
export function inInclude(scope, pathname) {
  return pathAllowed(pathname, scope.include);
}

/**
 * Validates one request URL (design 7.4 steps 1, 3, 4, 5; steps 2 and 6 live in the planner).
 * purpose 'task' (default) confines the path to include and refuses dot segments; 'discover' also
 * allows the exact `discover` documents and dot-files such as /.env; 'asset' also allows same-origin
 * .js, .mjs and .map files. Outside include only anonymous requests pass. `method` defaults to GET.
 * @returns {{ok: true, url: string} | {ok: false, reason: string, match?: string}}
 */
export function validateUrl(scope, url, {purpose = 'task', identity = null, method = 'GET'} = {}) {
  need(PURPOSES.has(purpose), `Unknown request purpose '${purpose}'.`);
  if (scope.expiresAt && Date.parse(scope.expiresAt) <= Date.now()) return refusal('scope-expired');
  const input = String(url ?? '');
  if (!input.trim() || !URL.canParse(input, scope.target.origin)) return refusal('origin');
  const parsed = new URL(input, scope.target.origin);
  const credentialed = identity != null && identity !== 'anonymous';
  if (!onScopeOrigin(scope, parsed, purpose, credentialed) || input.includes('#')) return refusal('origin');
  const exactOrigin = parsed.origin === scope.target.origin;
  const bodyMethod = WRITE_METHODS.includes(method) && exactOrigin && !parsed.search;
  const authPost = purpose === 'auth-body' && method === 'POST' &&
    bodyMethod &&
    scope.localAuthPostContracts?.[parsed.pathname] && !parsed.search;
  if (!scope.methods.includes(method) ||
      ['xml-body', 'json-body', 'form-body'].includes(purpose) && !bodyMethod ||
      purpose === 'auth-body' && !authPost ||
      purpose === 'reviewed-method' && (!WRITE_METHODS.includes(method) || !exactOrigin))
    return refusal('method');
  const authorization = scope.authorizedOrigins?.[parsed.origin]?.authorization;
  if (scope.target.environment !== 'local' && parsed.origin === scope.target.origin &&
      !authorization) return refusal('target-authorization');
  const exactAuthorizedXmlPost = method === 'POST' &&
    authorization?.xmlPostPaths?.includes(parsed.pathname);
  if (authorization && !authorization.methods.includes(method) &&
      !exactAuthorizedXmlPost)
    return refusal('target-authorization');
  if (credentialed && !scope.credentialOrigins.includes(parsed.origin)) return refusal('credential-origin');
  // The URL parser resolves '..', '%2e%2e' and '\' silently, so the raw input is checked as well.
  const rawPath = rawPathOf(input);
  if (rawPath.includes('%') || parsed.pathname.includes('%')) return refusal('percent');
  if (/[\x00-\x1f\x7f]/.test(input) || unsafeSegments(rawPath, purpose) || unsafeSegments(parsed.pathname, purpose)) return refusal('segment');
  if (!reachable(scope, parsed, purpose, credentialed)) return refusal('include');
  // Operator exclusions apply to every method, including observed JSON/form POST.
  const never = matchNever(scope, parsed.pathname, parsed.search);
  if (never.refused) return refusal('never', never.match);
  // No blanket route-word exclusions: read-only reset, verification, OAuth and
  // callback routes remain available. A clearly mutating GET/HEAD action needs
  // an exact operator-reviewed entry in discover before any stage can send it.
  if (READ_METHODS.includes(method) && mutatingReadAction(parsed) &&
      !scope.discover.includes(`${parsed.pathname}${parsed.search}`)) return refusal('read-action-review');
  const keys = [...parsed.searchParams.keys()];
  if (keys.length > MAX_QUERY_PARAMS) return refusal('query-count');
  return {ok: true, url: parsed.href};
}

/**
 * Token bucket without burst: take() resolves no earlier than 1000/rate ms after the previous
 * slot. halve() halves the rate (once per second at most, never below 0.5 rps or the start rate).
 * @returns {{take: () => Promise<void>, halve: () => void, rate: () => number}}
 */
export function createLimiter(rps) {
  need(Number.isFinite(rps) && rps > 0, 'The request rate must be a positive number.');
  const floor = Math.min(rps, MIN_RPS);
  let rate = rps;
  let nextSlot = 0;
  let lastHalved = -Infinity;

  async function take() {
    const slot = Math.max(performance.now(), nextSlot);
    nextSlot = slot + 1000 / rate;
    while (performance.now() < slot) await delay(Math.ceil(slot - performance.now()));
  }

  function halve() {
    const at = performance.now();
    if (at - lastHalved < HALVE_COOLDOWN_MS) return;
    lastHalved = at;
    rate = Math.max(rate / 2, floor);
  }

  return {take, halve, rate: () => rate};
}

/**
 * Credential header for 'owner' or 'outsider', read from `env` when called: {authorization:
 * 'Bearer <v>'}, {cookie: '<v>'} or {'<Name>': '<v>'}; 'anonymous' gets {}. A missing value throws
 * Fault code 3 with details {reason: 'credential_missing', env: NAME}; only the name is reported.
 */
export function credentialHeaders(scope, identity, env = {}, requestUrl = null) {
  if (identity == null || identity === 'anonymous') return {};
  if (JWT_CANARY_IDENTITIES.has(identity)) {
    need(scope.probes?.jwtUnsigned === true && scope.identities.auth === 'bearer',
      'Unsigned-JWT probes need an enabled bearer-token scope.');
    const canaries = jwtUnsignedCanaries(env[scope.identities.owner.env]);
    need(canaries, 'Unsigned-JWT probes need a signed owner JWT.');
    return {authorization: `Bearer ${canaries[JWT_CANARY_IDENTITIES.get(identity)]}`};
  }
  need(identity === 'owner' || identity === 'outsider', `Unknown identity '${identity}'.`);
  const name = scope.identities[identity].env;
  const value = env[name];
  need(typeof value === 'string' && value.length > 0, `Set ${name} to the ${identity} account's credential.`, 3, {reason: 'credential_missing', env: name});
  need(!INVALID_HEADER_CHAR.test(value), `${name} contains characters an HTTP header cannot carry.`, 3, {reason: 'credential_invalid', env: name});
  const auth = scope.identities.auth;
  if (scope.identities.identityCookieName && requestUrl) {
    const target = new URL(requestUrl, scope.target.origin);
    if (target.origin === scope.target.origin && target.pathname === scope.identities.identityPath && !target.search) {
      need(auth === 'bearer' && /^[A-Za-z0-9._~-]{1,4096}$/.test(value),
        `${name} cannot be used as the configured identity cookie.`, 3,
        {reason: 'credential_invalid', env: name});
      return {cookie: `${scope.identities.identityCookieName}=${value}`};
    }
  }
  if (auth === 'bearer') return {authorization: `Bearer ${value}`};
  if (auth === 'cookie') return {cookie: value};
  return {[auth.slice('header:'.length)]: value};
}

/**
 * The guarded request function (design 4.2, 6.10, 8.2, 14, 17). Returns
 * async request({url, identity, method = 'GET', headers = {}, body, step, task, agent,
 *   maxBytes, noCache, purpose = 'task', timeout})
 *   -> {status, type, bytes, hash, body, headers, shape, ids, ownership, ms, evidenceId}
 *   -> {refused: true, reason, evidenceId} when validateUrl or credential routing refuses (step 'refused')
 *   -> {blocked: true, reason, evidenceId} when safeRequest throws; network errors and 5xx are retried once
 * Every exchange is appended to the ledger first. Results are cached per (identity, method, URL)
 * unless noCache; request.stats = {sent, cached, refused, blocked, rate}. Credential values are
 * scrubbed from the body, the stored headers and the ledger record; set-cookie is never kept.
 */
export function createRequester(scope, {ledger, limiter = createLimiter(scope.limits.rps), env = {}, allowLocal = false,
  log = () => {}, run = null, signal, deadline = Infinity} = {}) {
  need(ledger, 'The guarded requester needs an evidence ledger.');
  const cache = new Map();
  const stats = {sent: 0, cached: 0, refused: 0, blocked: 0, get rate() { return limiter.rate(); }};

  async function request({url, identity = 'anonymous', method = 'GET', headers = {}, body, step, task = null, agent = null, maxBytes,
    noCache = false, purpose = 'task', timeout, derivedBearer = null,
    derivedCookie = null, omitExcerpt = false, rawModelRequest = false,
    rawForSessionChain = false, rawForAuthProof = false, redactValues = [],
    auditCallback = null} = {}) {
    need(STEPS.has(step), `Unknown evidence step '${step}'.`);
    need(maxBytes == null || (Number.isInteger(maxBytes) && maxBytes > 0 && maxBytes <= MAX_BODY_BYTES), `maxBytes must be a whole number up to ${MAX_BODY_BYTES}.`);
    const callerHeaders = rawModelRequest ? {...headers} : allowedCallerHeaders(headers);
    need(!rawModelRequest || noCache && purpose === 'task' &&
      headers && typeof headers === 'object' && !Array.isArray(headers) &&
      Object.entries(headers).every(([name, value]) =>
        /^[!#$%&'*+.^_`|~0-9A-Za-z-]+$/.test(name) &&
        typeof value === 'string' && !/[\r\n\x00]/.test(value)),
    'A model request must be an uncached scoped HTTP request with valid header syntax.');
    const derivedRead = ['GET', 'HEAD'].includes(method) && purpose === 'task';
    const derivedReviewedWrite = WRITE_METHODS.includes(method) &&
      (['json-body', 'form-body', 'xml-body', 'reviewed-method'].includes(purpose) ||
        rawModelRequest) && observedMethodAuthorized(scope, method);
    need(derivedBearer == null || (identity === 'anonymous' &&
      (derivedRead || derivedReviewedWrite && observedMethodAuthorized(scope, method)) && noCache &&
      typeof derivedBearer === 'string' && /^[\x21-\x7e]{16,4096}$/.test(derivedBearer)),
    'A derived bearer requires an uncached scoped request on the audited application.');
    need(derivedCookie == null || (derivedBearer == null && identity === 'anonymous' &&
      (derivedRead || derivedReviewedWrite && observedMethodAuthorized(scope, method)) && noCache &&
      typeof derivedCookie === 'string' &&
      /^[A-Za-z0-9._~-]{1,128}=[^\x00-\x20;,\x7f]{1,4096}$/.test(derivedCookie)),
    'A derived cookie requires an uncached scoped request on the audited application.');
    need(!rawForSessionChain || (scope.target.environment === 'local' &&
      identity === 'anonymous' && method === 'GET' && purpose === 'task' && noCache && omitExcerpt),
    'Raw session-chain extraction requires an uncached, unlogged local anonymous GET.');
    need(!rawForAuthProof || (observedMethodAuthorized(scope, 'POST') &&
      identity === 'anonymous' && method === 'POST' && purpose === 'auth-body' && noCache && omitExcerpt),
    'Raw authentication proof extraction requires an uncached, unlogged scoped anonymous POST.');
    const additionalSecrets = Array.isArray(redactValues) ? redactValues.filter(value =>
      typeof value === 'string' && value.length >= 4 && value.length <= 4096) : [];
    const contentTypes = Object.entries(callerHeaders).filter(([name]) => name.toLowerCase() === 'content-type');
    const methodPath = URL.canParse(url, scope.target.origin) ?
      new URL(url, scope.target.origin).pathname : '';
    const methodPlacement = purpose === 'json-body' ? 'json' :
      purpose === 'form-body' ? 'form' : purpose === 'xml-body' ? 'xml' : null;
    const typedContract = methodPlacement ? scope.localAutoMethodContracts?.[
      `${method} ${methodPlacement} ${methodPath}`] : null;
    const expectedType = typedContract?.contentType ??
      ({json: 'application/json', form: 'application/x-www-form-urlencoded',
        xml: 'application/xml'})[methodPlacement];
    const xmlBody = WRITE_METHODS.includes(method) && purpose === 'xml-body' && noCache &&
      typeof body === 'string' && Buffer.byteLength(body) > 0 && Buffer.byteLength(body) <= 4096 &&
      contentTypes.length === 1 && contentTypes[0][1] === expectedType;
    let jsonDocument = null, jsonParsed = false;
    if (['json-body', 'auth-body'].includes(purpose) && typeof body === 'string')
      try {jsonDocument = JSON.parse(body); jsonParsed = true;} catch { /* refused below */ }
    const jsonBody = WRITE_METHODS.includes(method) && purpose === 'json-body' && noCache &&
      typeof body === 'string' && Buffer.byteLength(body) > 0 && Buffer.byteLength(body) <= 4096 &&
      contentTypes.length === 1 && contentTypes[0][1] === expectedType &&
      /^application\/(?:json|[a-z0-9.-]+\+json)(?:\s*;|$)/i.test(expectedType) &&
      jsonParsed;
    const formParams = purpose === 'form-body' && typeof body === 'string' ? new URLSearchParams(body) : null;
    const formEntries = formParams ? [...formParams.entries()] : [];
    const formBody = WRITE_METHODS.includes(method) && purpose === 'form-body' && noCache &&
      typeof body === 'string' && Buffer.byteLength(body) > 0 && Buffer.byteLength(body) <= 4096 &&
      contentTypes.length === 1 && contentTypes[0][1] === expectedType &&
      formParams != null;
    const authPath = URL.canParse(url, scope.target.origin) ? new URL(url, scope.target.origin).pathname : '';
    const authContract = scope.localAuthPostContracts?.[authPath];
    const authValues = isPlainObject(jsonDocument) ? Object.entries(jsonDocument) : [];
    const authBody = method === 'POST' && purpose === 'auth-body' && noCache && omitExcerpt &&
      rawForAuthProof && observedMethodAuthorized(scope, 'POST') &&
      contentTypes.length === 1 && contentTypes[0][1] === 'application/json' &&
      typeof body === 'string' && Buffer.byteLength(body) <= 4096 &&
      authContract && authValues.length === 2 &&
      authValues.every(([key, value]) => authContract.fields.includes(key) &&
        typeof value === 'string' && value.length >= 3 && value.length <= 128 &&
        !/[\x00-\x1f\x7f]/.test(value) &&
        !externalDestination(value, scope.target.origin, {allowEmail: true})) &&
      authValues.some(([key]) => key === authContract.usernameField) &&
      authValues.some(([key]) => key === authContract.passwordField);
    const rawBody = rawModelRequest && (body === undefined ||
      typeof body === 'string' && Buffer.byteLength(body) <= MAX_BODY_BYTES);
    need(rawBody || (body === undefined && !['xml-body', 'json-body', 'form-body', 'auth-body'].includes(purpose)) ||
      xmlBody || jsonBody || formBody || authBody,
      'Request bodies require an uncached, bounded, reviewed XML, JSON or form POST path.');
    if (JWT_CANARY_IDENTITIES.has(identity)) need(method === 'GET' && purpose === 'task' && noCache,
      'Unsigned-JWT probes require uncached GET requests in task scope.');
    const inputSecrets = URL.canParse(url, scope.target.origin) ?
      [...new URL(url, scope.target.origin).searchParams].filter(([name]) =>
        credentialQueryKey(name)).map(([, value]) => value).filter(Boolean) : [];
    if (isPlainObject(jsonDocument)) for (const [name, value] of Object.entries(jsonDocument))
      if (credentialQueryKey(name) && typeof value === 'string' && value)
        inputSecrets.push(value);
    for (const [name, value] of formEntries)
      if (credentialQueryKey(name) && value) inputSecrets.push(value);
    const rawSecrets = rawModelRequest ? [
      ...Object.values(callerHeaders).filter(value => typeof value === 'string' && value.length >= 4),
      ...Object.entries(callerHeaders).filter(([name]) =>
        name.toLowerCase() === 'cookie').flatMap(([, value]) =>
        String(value).split(';').map(pair => pair.slice(pair.indexOf('=') + 1).trim())
          .filter(part => part.length >= 4)),
      ...Object.entries(callerHeaders).filter(([name]) =>
        name.toLowerCase() === 'authorization').map(([, value]) =>
        String(value).replace(/^\S+\s+/, '')).filter(part => part.length >= 4),
      ...(typeof body === 'string' && body.length >= 4 ? [body] : []),
      ...(jsonDocument && typeof jsonDocument === 'object' ?
        Object.values(jsonDocument).filter(value => typeof value === 'string' && value.length >= 4) : []),
    ] : [];
    const context = {url, identity, method, step, task, agent, purpose, maxBytes, timeout, body,
      omitExcerpt, rawModelRequest, rawForSessionChain, rawForAuthProof,
      secrets: [...credentialSecrets(scope, env), ...(derivedBearer ? [derivedBearer] : []),
        ...(derivedCookie ? [derivedCookie, derivedCookie.slice(derivedCookie.indexOf('=') + 1)] : []),
        ...additionalSecrets, ...inputSecrets, ...rawSecrets]};
    if (Date.now() >= deadline) return refuse(context, 'time-budget');
    const check = validateUrl(scope, url, {purpose, identity, method});
    if (!check.ok) return refuse(context, check.reason, check.match);
    if (JWT_CANARY_IDENTITIES.has(identity) && new URL(check.url).origin !== scope.target.origin)
      return refuse(context, 'jwt-canary-origin');
    if (scope.authorizedOrigins?.[new URL(check.url).origin]) {
      try { scopeReady(scope.authorizedOrigins[new URL(check.url).origin], new URL(check.url).pathname, method); }
      catch (error) { return refuse(context, 'target-authorization', error.message); }
    }
    const requestUrl = new URL(check.url);
    if (derivedBearer && requestUrl.origin !== scope.target.origin)
      return refuse(context, 'derived-bearer-origin');
    if (derivedCookie && requestUrl.origin !== scope.target.origin)
      return refuse(context, 'derived-cookie-origin');
    const auditDomain = scope.discovery.auditDomains.find(domain =>
      requestUrl.hostname === domain || requestUrl.hostname.endsWith(`.${domain}`));
    if (context.purpose === 'task' && auditDomain && scope.authorizedDomains?.[auditDomain]) {
      try {scopeReady(scope.authorizedDomains[auditDomain], requestUrl.pathname, method);}
      catch (error) {return refuse(context, 'domain-authorization', error.message);}
    }
    let credentials;
    try {
      credentials = credentialHeaders(scope, identity, env, requestUrl);
    } catch (error) {
      if (!String(error.details?.reason).startsWith('credential_')) throw error;
      return refuse(context, error.details.reason, error.details.env);
    }
    if (JWT_CANARY_IDENTITIES.has(identity)) context.secrets.push(credentials.authorization.slice('Bearer '.length));
    const prepared = {...context, target: check.url,
      headers: {...callerHeaders, ...credentials,
        ...(derivedBearer ? {authorization: `Bearer ${derivedBearer}`} : {}),
        ...(derivedCookie ? {cookie: derivedCookie} : {})}};
    const key = `${identity} ${method} ${check.url}`;
    if (noCache) return exchange(prepared);
    if (cache.has(key)) {
      stats.cached += 1;
      return cache.get(key);
    }
    // The pending promise is cached, so concurrent agents asking for the same control share one request.
    // Keep only small bodies in the run cache. Larger scoped responses are still
    // inspected, but retaining many of them can exhaust memory on broad audits.
    const pending = exchange(prepared);
    cache.set(key, pending);
    const result = await pending;
    if (!reusable(result) || result.bytes > 512 * 1024) cache.delete(key);
    return result;
  }

  async function exchange(context) {
    const targetUrl = new URL(context.target);
    const allowRemoteHttp = context.identity === 'anonymous' &&
      targetUrl.protocol === 'http:' && scope.domains.some(domain =>
        (context.purpose !== 'task' || scope.discovery.auditDomains.includes(domain)) &&
        (targetUrl.hostname === domain || targetUrl.hostname.endsWith(`.${domain}`)));
    const options = {allowLocal, allowRemoteHttp, method: context.method, headers: context.headers,
      body: context.body,
      maxBytes: context.maxBytes ?? MAX_BODY_BYTES, timeout: context.timeout, signal};
    let outcome = await send(context.target, options);
    if (READ_METHODS.includes(context.method) && retryable(outcome)) {
      record(context, outcome);
      await delay(RETRY_DELAY_MS);
      outcome = await send(context.target, options);
    }
    const result = record(context, outcome);
    if (result.blocked) stats.blocked += 1;
    return result;
  }

  async function send(target, options) {
    await limiter.take();
    stats.sent += 1;
    const started = performance.now();
    try {
      const response = await safeRequest(target, options);
      return {response, ms: Math.round(performance.now() - started)};
    } catch (error) {
      if (!(error instanceof Fault)) throw error;
      return {error};
    }
  }

  function record(context, outcome) {
    return outcome.error ? recordBlocked(context, outcome.error) : recordResponse(context, outcome);
  }

  function recordResponse(context, {response, ms}) {
    const body = scrub(response.body, context.secrets);
    const json = parseJson(body);
    const headers = context.rawForAuthProof ? {} : storedHeaders(response.headers, context.secrets);
    const submittedMarkers = new Set([...new URL(context.target).searchParams.values()]
      .flatMap(value => value.match(/\b[0-9a-f]{24}\b/g) ?? []));
    const auditHeader = response.headers['x-bypass-audit'];
    if (typeof auditHeader === 'string' && submittedMarkers.has(auditHeader))
      headers['x-bypass-audit'] = auditHeader;
    const facts = {
      status: response.status,
      type: mediaType(response.headers['content-type']),
      bytes: Buffer.byteLength(response.body),
      hash: `sha256:${hash(response.body)}`,
      shape: json === undefined ? null : boundedShape(json),
      ownership: ownershipOf(json),
    };
    const documentPath = new URL(context.target).pathname;
    const apiDocument = context.purpose === 'discover' &&
      /\/(?:openapi(?:\.json)?|swagger(?:\.json)?|api-docs)(?:\/|$)/i.test(documentPath);
    const evidenceId = append({
      ...exchangeEntry(context),
      response: {status: facts.status, headers, bytes: facts.bytes, hash: facts.hash, shape: facts.shape, ownership: facts.ownership, ms},
      // Scripts and API documents can contain credential examples under otherwise innocuous field names.
      // Derived route facts and a response hash are retained; raw document excerpts are not.
      excerpt: context.omitExcerpt || context.purpose === 'asset' || apiDocument || !body ?
        undefined : body.slice(0, EXCERPT_SOURCE_CHARS),
    }, context.secrets);
    if (facts.status === 429) {
      limiter.halve();
      log({stage: 'request', message: `HTTP 429: request rate is now ${limiter.rate()} per second`, evidenceId});
    }
    return {...facts, body: context.rawForAuthProof ? '' : body,
      prefixHex: response.prefixHex,
      ...(context.rawForSessionChain || context.rawForAuthProof ? {rawBody: response.body} : {}),
      // This value is returned only to the in-process caller. The ledger's
      // storedHeaders above still omits Set-Cookie and credential values.
      ...(context.rawForAuthProof || context.rawModelRequest ?
        {rawSetCookie: response.headers['set-cookie'] ?? []} : {}),
      headers, ids: idsOf(json), ms, evidenceId};
  }

  function recordBlocked(context, error) {
    const reason = scrub(error.message, context.secrets);
    const evidenceId = append({...exchangeEntry(context), blocked: {reason}}, context.secrets);
    log({stage: 'request', message: `Request blocked: ${reason}`, evidenceId});
    return {blocked: true, reason, evidenceId};
  }

  function refuse(context, reason, match) {
    stats.refused += 1;
    const evidenceId = append({
      task: context.task, step: 'refused', agent: context.agent, identity: context.identity,
      request: {method: context.method, url: storedUrl(context.url)}, refused: {rule: reason, match},
    }, context.secrets);
    log({stage: 'request', message: `Request refused (${reason})`, evidenceId});
    return {refused: true, reason,
      ...(reason === 'local-auto-post-contract' && match !== undefined ? {detail: match} : {}),
      evidenceId};
  }

  function exchangeEntry(context) {
    const headerNames = [...new Set(['accept', ...Object.keys(context.headers).map(name => name.toLowerCase())])];
    return {
      task: context.task, step: context.step, agent: context.agent, identity: context.identity,
      request: {method: context.method, url: storedUrl(context.target), headers: headerNames,
        ...(context.body === undefined ? {} : {bodyBytes: Buffer.byteLength(context.body),
          bodyHash: `sha256:${hash(context.body)}`})},
    };
  }

  function append(entry, secrets) {
    return ledger.append(scrub({run, ...entry}, secrets));
  }

  request.stats = stats;
  return request;
}

/** {key: 'string'|'number'|'boolean'|'null'|'array'|'object'}, recursing into objects to `depth`. */
export function jsonShape(value, depth = 2) {
  if (value === null) return 'null';
  if (Array.isArray(value)) return 'array';
  if (typeof value !== 'object') return typeof value;
  if (depth <= 0) return 'object';
  return Object.fromEntries(Object.entries(value).map(([key, field]) => [key, jsonShape(field, depth - 1)]));
}

/** Names of the ownership-looking fields of an object (userId, ownerId, owner_uid, email, *Id, *_uid, …). */
export function ownershipFields(obj) {
  if (!isPlainObject(obj)) return [];
  return Object.keys(obj).filter(key => OWNERSHIP_KEY.test(key));
}

function deepFreeze(value) {
  if (value && typeof value === 'object') {
    for (const child of Object.values(value)) deepFreeze(child);
    Object.freeze(value);
  }
  return value;
}

function isPlainObject(value) {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

function readScopeFile(file) {
  let text;
  try {
    text = fs.readFileSync(file, 'utf8');
  } catch (error) {
    throw new Fault(`Cannot read scope file ${file}: ${error.code ?? error.message}.`);
  }
  let data;
  try {
    data = JSON.parse(text);
  } catch (error) {
    throw new Fault(`Scope file ${file} is not valid JSON: ${error.message}`);
  }
  need(isPlainObject(data), `Scope file ${file} must contain a JSON object.`);
  return data;
}

/** Copies `patch` onto `base`, refusing unknown fields and values whose type differs from the default. */
function mergeScope(base, patch, prefix) {
  need(isPlainObject(patch), `Scope field '${prefix.slice(0, -1) || 'root'}' must be a JSON object.`);
  for (const [key, value] of Object.entries(patch)) {
    const field = prefix + key;
    need(Object.hasOwn(base, key), `Unknown scope field '${field}'.`);
    base[key] = mergedValue(base[key], value, field);
  }
  return base;
}

function mergedValue(current, value, field) {
  if (field === 'probes.writeOperations') {
    need(Array.isArray(value) && value.every(item => isPlainObject(item) &&
      Object.keys(item).length === 3 &&
      ['method', 'path', 'placement'].every(key => typeof item[key] === 'string')),
    "Scope field 'probes.writeOperations' must be a list of exact method, path, and placement objects.");
    return value.map(item => ({method: item.method, path: item.path,
      placement: item.placement}));
  }
  if (field === 'identities.login' && value !== null) {
    need(isPlainObject(value), "Scope field 'identities.login' must be a login object or null.");
    const allowed = new Set(['path', 'usernameField', 'passwordField', 'encoding']);
    need(Object.entries(value).every(([name, entry]) => allowed.has(name) && typeof entry === 'string'),
      'identities.login contains an unknown field or a non-string value.');
    return {...value};
  }
  if (/^identities\.(?:owner|outsider)\.login$/.test(field) && value !== null) {
    need(isPlainObject(value) && Object.entries(value).every(([name, entry]) =>
      ['usernameEnv', 'passwordEnv'].includes(name) && typeof entry === 'string'),
    `Scope field '${field}' must contain usernameEnv and passwordEnv names only.`);
    return {...value};
  }
  if (isPlainObject(current)) return mergeScope(current, value, `${field}.`);
  if (Array.isArray(current) || (WORDLIST_FIELDS.has(field) && Array.isArray(value))) {
    need(Array.isArray(value) && value.every(item => typeof item === 'string'), `Scope field '${field}' must be a list of strings.`);
    return [...value];
  }
  if (current === null) {
    need(value === null || typeof value === 'string', `Scope field '${field}' must be a string or null.`);
    return value;
  }
  need(typeof value === typeof current, `Scope field '${field}' must be a ${typeof current}.`);
  return value;
}

function applyOverrides(scope, fromFile, overrides) {
  const {ownerEnv, otherEnv, auth, identityPath, includes, domains, auditDomains} = overrides;
  if (ownerEnv != null) scope.identities.owner.env = String(ownerEnv);
  if (otherEnv != null) scope.identities.outsider.env = String(otherEnv);
  if (auth != null) scope.identities.auth = String(auth);
  if (identityPath != null) scope.identities.identityPath = String(identityPath);
  for (const name of ['rps', 'waves']) {
    if (overrides[name] != null) scope.limits[name] = loweredLimit(name, overrides[name], fromFile.limits?.[name]);
  }
  // `agents` remains an internal compatibility alias for HTTP task workers;
  // the public --agents flag sets Muse investigator concurrency instead.
  const httpWorkers = overrides.httpWorkers ?? overrides.agents;
  if (httpWorkers != null) scope.limits.agents = loweredLimit(
    overrides.httpWorkers != null ? 'http-workers' : 'agents',
    httpWorkers, fromFile.limits?.agents);
  if (overrides.modelAgents != null) {
    const modelAgents = Number(overrides.modelAgents);
    need(Number.isSafeInteger(modelAgents) && modelAgents > 0 && modelAgents <= MAX_AGENTS,
      `--agents must be a whole number from 1 through ${MAX_AGENTS}.`);
    scope.limits.modelConcurrency = modelAgents;
  }
  if (overrides.modelCalls != null) {
    const modelCalls = Number(overrides.modelCalls);
    need(Number.isSafeInteger(modelCalls) && modelCalls > 0,
      '--model-calls must be a positive whole number.');
    scope.limits.modelCalls = modelCalls;
  }
  if (overrides.minutes != null) {
    const minutes = Number(overrides.minutes);
    need(Number.isFinite(minutes) && minutes > 0,
      '--minutes must be a positive number.');
    scope.limits.minutes = minutes;
  }
  if (overrides.maxUrls != null) {
    const maxUrls = Number(overrides.maxUrls);
    need(Number.isSafeInteger(maxUrls) && maxUrls >= 0,
      '--max-urls must be a nonnegative whole number (0 disables the URL-count cap).');
    scope.limits.maxUrls = maxUrls;
  }
  if (overrides.maxTasks != null) {
    const maxTasks = Number(overrides.maxTasks);
    need(Number.isSafeInteger(maxTasks) && maxTasks >= 0,
      '--max-tasks must be a nonnegative whole number (0 disables the task-count cap).');
    scope.limits.tasks = maxTasks;
  }
  if (overrides.domScriptBytes != null) {
    const domScriptBytes = Number(overrides.domScriptBytes);
    need(Number.isSafeInteger(domScriptBytes) && domScriptBytes > 0 &&
      domScriptBytes <= 16 * 1024 * 1024,
      '--dom-script-bytes must be a whole number from 1 through 16777216.');
    scope.limits.domScriptBytes = domScriptBytes;
  }
  if (includes != null) {
    const entries = listOf(includes);
    if (fromFile.include) {
      for (const entry of entries) need(pathAllowed(entry, fromFile.include), `Include ${entry} exceeds scope include ${fromFile.include.join(', ')}.`);
    }
    scope.include = entries;
  }
  if (domains != null) {
    const entries = listOf(domains);
    if (fromFile.domains) {
      for (const entry of entries) need(fromFile.domains.includes(entry), `Domain ${entry} exceeds scope domains ${fromFile.domains.join(', ')}.`);
    }
    scope.domains = entries;
  }
  if (auditDomains != null) {
    const entries = listOf(auditDomains);
    if (fromFile.discovery?.auditDomains) for (const entry of entries)
      need(fromFile.discovery.auditDomains.includes(entry),
        `Active audit domain ${entry} exceeds scope discovery.auditDomains.`);
    scope.discovery.auditDomains = entries;
  }
}

function loweredLimit(name, value, ceiling) {
  const number = Number(value);
  need(Number.isFinite(number) && number > 0, `--${name} must be a positive number.`);
  need(ceiling == null || number <= ceiling, `--${name} ${number} exceeds scope limit ${ceiling}.`);
  return number;
}

function checkScope(scope) {
  const {identities, limits} = scope;
  need(scope.schemaVersion === 1, 'Scope schemaVersion must be 1.');
  envName(identities.owner.env);
  envName(identities.outsider.env);
  need(identities.owner.env !== identities.outsider.env, 'The owner and outsider accounts need different environment variables.');
  need(AUTH_FORMAT.test(identities.auth), `Credential placement '${identities.auth}' must be bearer, cookie or header:<Name>.`);
  need(Array.isArray(scope.methods) && scope.methods.length > 0 &&
    scope.methods.every(method => typeof method === 'string' &&
      /^[A-Z][A-Z0-9!#$%&'+.^_`|~-]{0,31}$/.test(method) &&
      !['CONNECT', 'PRI'].includes(method)),
  'Scope methods must be HTTP method names supported by the request runner.');
  need(scope.include.length > 0 && scope.include.every(isPathPrefix), 'Each include entry must be a path prefix such as /api.');
  need(scope.domains.every(domain => typeof domain === 'string' && domain.length <= 253 &&
    /^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z][a-z0-9-]{1,62}$/.test(domain)),
  'Discovery domains must be lowercase apex names without wildcards, ports or paths.');
  need(scope.discover.every(entry => entry.startsWith('/')), 'Each discover entry must be a path such as /openapi.json.');
  need(scope.never.every(entry => entry.trim().length > 0), 'Never entries cannot be empty.');
  need(Number.isInteger(scope.discovery.depth) && scope.discovery.depth >= 0 && scope.discovery.depth <= 127,
    'discovery.depth must be a whole number from 0 to 127.');
  need(scope.discovery.auditDomains.every(domain => scope.domains.includes(domain)),
    'discovery.auditDomains must be a subset of verified discovery domains.');
  need(['certificateTransparency', 'osv', 'wayback'].every(name =>
    typeof scope.discovery.external[name] === 'boolean'),
  'discovery.external switches must be true or false.');
  need(['read', 'count-only'].includes(scope.harvest.thirdParty), 'harvest.thirdParty must be read or count-only.');
  need(typeof scope.probes.crlfResponseHeader === 'boolean' &&
    typeof scope.probes.hostHeaderRedirect === 'boolean' &&
    typeof scope.probes.jwtUnsigned === 'boolean' &&
    typeof scope.probes.commandExecution === 'boolean' &&
    typeof scope.probes.pathTraversal === 'boolean' &&
    typeof scope.probes.xmlExternalEntity === 'boolean', 'Active probe switches must be true or false.');
  need(Array.isArray(scope.probes.xmlPostPaths) && scope.probes.xmlPostPaths.length <= 20 &&
    scope.probes.xmlPostPaths.every(path => typeof path === 'string' &&
      /^\/[A-Za-z0-9/_.-]{1,200}$/.test(path) && !path.endsWith('/') &&
      !unsafeSegments(path, 'task') &&
      inInclude(scope, path) && !matchNever(scope, path).refused),
  'probes.xmlPostPaths must contain at most 20 exact included paths outside the never list.');
  need(Array.isArray(scope.probes.jsonPostPaths) && scope.probes.jsonPostPaths.length <= 20 &&
    scope.probes.jsonPostPaths.every(path => typeof path === 'string' &&
      /^\/[A-Za-z0-9/_.-]{1,200}$/.test(path) && !path.endsWith('/') &&
      !unsafeSegments(path, 'task') &&
      inInclude(scope, path) && !matchNever(scope, path).refused),
  'probes.jsonPostPaths must contain at most 20 exact included paths outside the never list.');
  need(Array.isArray(scope.probes.formPostPaths) && scope.probes.formPostPaths.length <= 20 &&
    scope.probes.formPostPaths.every(path => typeof path === 'string' &&
      /^\/[A-Za-z0-9/_.-]{1,200}$/.test(path) && !path.endsWith('/') &&
      !unsafeSegments(path, 'task') &&
      inInclude(scope, path) && !matchNever(scope, path).refused),
  'probes.formPostPaths must contain at most 20 exact included paths outside the never list.');
  need(Array.isArray(scope.probes.writeOperations) &&
    scope.probes.writeOperations.length <= 100 &&
    scope.probes.writeOperations.every(item => item && typeof item === 'object' &&
      WRITE_METHODS.includes(item.method) && WRITE_PLACEMENTS.includes(item.placement) &&
      (item.method !== 'OPTIONS' || ['query', 'header'].includes(item.placement)) &&
      typeof item.path === 'string' && /^\/[A-Za-z0-9/_.-]{1,200}$/.test(item.path) &&
      !item.path.endsWith('/') && !unsafeSegments(item.path, 'task') &&
      inInclude(scope, item.path) && !matchNever(scope, item.path).refused),
  'probes.writeOperations must contain at most 100 exact included method, path, and placement contracts outside the never list.');
  need(Number.isInteger(scope.harvest.sequentialNeighbors) && scope.harvest.sequentialNeighbors >= 0 &&
    scope.harvest.sequentialNeighbors <= 20, 'harvest.sequentialNeighbors must be a whole number from 0 to 20.');
  for (const origin of scope.credentialOrigins) {
    need(new URL(origin).protocol === 'https:' || loopback(new URL(origin).hostname),
      `Credential origin ${origin} must use HTTPS unless it is loopback.`, 3);
    if (scope.target.environment === 'local') need(loopback(new URL(origin).hostname),
      `Credential origin ${origin} is not a loopback origin; a local scope cannot send it credentials.`, 3);
    else need(!loopback(new URL(origin).hostname),
      `Credential origin ${origin} cannot be loopback for a deployed scope.`, 3);
  }
  const included = path => path.startsWith('/') && inInclude(scope, path);
  if (identities.identityPath != null) {
    need(included(identities.identityPath), `identityPath ${identities.identityPath} must sit inside include (${scope.include.join(', ')}).`);
  }
  if (identities.identityCookieName != null) {
    need(identities.auth === 'bearer' && typeof identities.identityPath === 'string' &&
      isPathPrefix(identities.identityPath) && /^[A-Za-z][A-Za-z0-9_-]{0,63}$/.test(identities.identityCookieName),
    'identities.identityCookieName needs a bearer scope, an exact identityPath and a safe cookie name.');
  }
  if (identities.login) {
    const login = identities.login;
    need(typeof login.path === 'string' && isPathPrefix(login.path) && !login.path.endsWith('/'),
      'identities.login.path must be an exact path without a query or trailing slash.');
    for (const field of ['usernameField', 'passwordField']) if (login[field] != null)
      need(/^[A-Za-z_][A-Za-z0-9_]{0,63}$/.test(login[field]), `identities.login.${field} is invalid.`);
    if (login.encoding != null) need(['json', 'form'].includes(login.encoding), 'identities.login.encoding must be json or form.');
  }
  for (const name of ['owner', 'outsider']) {
    const login = identities[name].login;
    if (!login) continue;
    need(typeof login.usernameEnv === 'string' && typeof login.passwordEnv === 'string',
      `identities.${name}.login needs usernameEnv and passwordEnv.`);
    envName(login.usernameEnv);
    envName(login.passwordEnv);
    need(login.usernameEnv !== login.passwordEnv, `identities.${name}.login needs distinct variable names.`);
  }
  for (const list of scope.seeds.lists) need(included(list), `seeds.lists entry ${list} must sit inside include (${scope.include.join(', ')}).`);
  need(scope.seeds.dnsWords === 'default' || Array.isArray(scope.seeds.dnsWords) &&
    scope.seeds.dnsWords.length <= 2000 && scope.seeds.dnsWords.every(word =>
      typeof word === 'string' && /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(word)),
  'seeds.dnsWords must be "default" or at most 2000 lowercase DNS labels.');
  for (const [name, value] of Object.entries(limits))
    need(Number.isFinite(value) && (['maxUrls', 'tasks'].includes(name) ? value >= 0 : value > 0),
      `Scope limit ${name} must be ${['maxUrls', 'tasks'].includes(name) ? 'a nonnegative' : 'a positive'} number.`);
  need(Number.isSafeInteger(limits.maxUrls), 'Scope limit maxUrls must be a whole number.');
  need(Number.isSafeInteger(limits.tasks), 'Scope limit tasks must be a whole number.');
  need(Number.isSafeInteger(limits.domScriptBytes) && limits.domScriptBytes <= 16 * 1024 * 1024,
    'Scope limit domScriptBytes must be a whole number through 16777216.');
  need(Number.isSafeInteger(limits.modelCalls), 'Model calls must be a positive whole number.');
  need(Number.isInteger(limits.agents) && limits.agents <= MAX_AGENTS, `Agents must be a whole number up to ${MAX_AGENTS}.`);
  need(Number.isSafeInteger(limits.modelConcurrency) && limits.modelConcurrency <= MAX_AGENTS,
    `Muse agents must be a whole number up to ${MAX_AGENTS}.`);
  need(Number.isInteger(limits.researchCallsPerHypothesis) && limits.researchCallsPerHypothesis <= 1000,
    'Research calls per hypothesis must be a whole number up to 1000.');
  need(limits.waves === 1 || limits.waves === 2, 'Waves must be 1 or 2.');
  if (scope.expiresAt != null) {
    const expires = Date.parse(scope.expiresAt);
    need(Number.isFinite(expires), `Scope expiresAt '${scope.expiresAt}' is not a date.`);
    need(expires > Date.now(), `The scope expired at ${scope.expiresAt}.`, 3);
  }
}

/** Validate a reviewable full or partial scope template before setup writes or reuses it. */
export function validateScopeTemplate(template) {
  const scope = mergeScope(structuredClone(DEFAULT_SCOPE), template, '');
  checkScope(scope);
  return scope;
}

function isPathPrefix(entry) {
  return entry.startsWith('/') && !/[?#*%\\;]/.test(entry) && pathAllowed(entry, [entry])
    && entry.split('/').every(segment => segment !== '.' && segment !== '..');
}

function listOf(value) {
  if (Array.isArray(value)) return value.map(String);
  return String(value).split(',').map(entry => entry.trim()).filter(Boolean);
}

function originOf(value) {
  const text = String(value ?? '');
  need(URL.canParse(text), 'Enter the target as an origin such as http://127.0.0.1:4329.');
  const url = new URL(text);
  const plain = ['http:', 'https:'].includes(url.protocol) && !url.username && !url.password && !url.search && !url.hash && url.pathname === '/';
  need(plain, 'Use an origin such as http://127.0.0.1:4329, without a path, query or credentials.');
  return url.origin;
}

function refusal(reason, match) {
  return match === undefined ? {ok: false, reason} : {ok: false, reason, match};
}

function onScopeOrigin(scope, url, purpose, credentialed) {
  if (url.username || url.password) return false;
  if (url.origin === scope.target.origin || scope.credentialOrigins.includes(url.origin)) return true;
  if (!credentialed && purpose === 'task' && !url.port && scope.discovery.auditDomains.some(domain =>
    url.hostname === domain || url.hostname.endsWith(`.${domain}`))) return true;
  if (credentialed || purpose === 'task' || !['discover', 'asset', 'sensitive'].includes(purpose)) return false;
  if (purpose === 'asset' && scope.discovery.assetHosts.includes(url.hostname) && /\.(js|mjs|map)$/.test(url.pathname)) return true;
  return scope.domains.some(domain => url.hostname === domain || url.hostname.endsWith(`.${domain}`));
}

/** The path as written, before the URL parser normalizes it: scheme and authority removed, query and fragment cut. */
function rawPathOf(input) {
  return input.trim().replace(/^[a-z][a-z0-9+.-]*:[\\/]*[^\\/?#]*/i, '').split(/[?#]/, 1)[0];
}

function unsafeSegments(path, purpose) {
  if (/[;\\]/.test(path)) return true;
  return path.split('/').some(segment => segment === '.' || segment === '..' ||
    (purpose === 'task' || purpose === 'xml-body') && segment.startsWith('.'));
}

/** Inside include anything goes; outside it only anonymous discover documents and same-origin scripts. */
function reachable(scope, url, purpose, credentialed) {
  const pathname = url.pathname;
  if (url.origin !== scope.target.origin && !scope.credentialOrigins.includes(url.origin))
    return !credentialed && (purpose === 'task' ?
      !url.port && scope.discovery.auditDomains.some(domain => url.hostname === domain || url.hostname.endsWith(`.${domain}`)) &&
        inInclude(scope, pathname) : true);
  if (inInclude(scope, pathname)) return true;
  if (credentialed) return false;
  if (purpose === 'discover') return scope.discover.includes(pathname) ||
    scope.discover.includes(`${pathname}${url.search}`);
  if (purpose === 'asset') return scope.discover.includes(pathname) || /\.(js|mjs|map)$/.test(pathname);
  if (purpose === 'sensitive') return scope.discovery.sensitivePaths;
  return false;
}

function verbMatches(verb, word) {
  return word.toLowerCase().startsWith(verb) && !/[a-z]/.test(word.charAt(verb.length));
}

function globPattern(glob) {
  const source = glob.split('*').map(part => part.replace(/[.+?^${}()|[\]\\]/g, '\\$&')).join('.*');
  return new RegExp(`^${source}$`);
}

/** Both credential values, plus the value parts of cookie credentials, for exact-value scrubbing. */
function credentialSecrets(scope, env) {
  const values = [scope.identities.owner.env, scope.identities.outsider.env,
    scope.identities.owner.login?.usernameEnv, scope.identities.owner.login?.passwordEnv,
    scope.identities.outsider.login?.usernameEnv, scope.identities.outsider.login?.passwordEnv]
    .map(name => env[name])
    .filter(value => typeof value === 'string' && value.length > 0);
  if (scope.identities.auth !== 'cookie') return values;
  const cookieValues = values.flatMap(value => value.split(';').map(pair => pair.slice(pair.indexOf('=') + 1).trim()));
  return [...values, ...cookieValues.filter(value => value.length >= 8)];
}

function allowedCallerHeaders(headers) {
  for (const name of Object.keys(headers)) {
    need(validModelHeaders([{name, value: headers[name]}]),
      `Header '${name}' cannot be represented as an HTTP header.`);
  }
  return headers;
}

function reusable(result) {
  return !result.blocked && result.status !== 429 && result.status < 500;
}

function retryable(outcome) {
  return outcome.error ? RETRYABLE_FAULT.test(outcome.error.message) : outcome.response.status >= 500;
}

function storedHeaders(headers, secrets) {
  const kept = {};
  for (const name of STORED_HEADERS) {
    const value = headers[name];
    if (value === undefined) continue;
    const text = scrub(Array.isArray(value) ? value.join(', ') : String(value), secrets);
    // Only the scheme of www-authenticate is kept: its parameters may echo a token (design 14).
    kept[name] = name === 'www-authenticate' ? text.trim().split(/[\s,]/, 1)[0] : maskCredentialParams(text);
  }
  return kept;
}

function storedUrl(url) {
  return maskCredentialParams(String(url ?? '')).slice(0, STORED_URL_CHARS);
}

function mediaType(value) {
  return String(value ?? '').split(';')[0].trim().toLowerCase();
}

/** A body that is not JSON is a fact about the response, not a failure: shape stays null. */
function parseJson(text) {
  if (!/^\s*[[{]/.test(text)) return undefined;
  try {
    return JSON.parse(text);
  } catch {
    return undefined;
  }
}

function boundedShape(json) {
  const full = jsonShape(json, 2);
  if (byteSize(full) <= SHAPE_BYTES) return full;
  const shallow = jsonShape(json, 1);
  if (byteSize(shallow) <= SHAPE_BYTES) return shallow;
  const kept = {};
  for (const [key, type] of Object.entries(shallow)) {
    kept[key] = type;
    if (byteSize(kept) > SHAPE_BYTES) {
      delete kept[key];
      break;
    }
  }
  return kept;
}

function byteSize(value) {
  return Buffer.byteLength(JSON.stringify(value));
}

/** ID-like scalars (id, _id, uid, uuid, slug, *Id, *_id, *_uid) at object depth 2 or less, list items included. */
function idsOf(json) {
  const found = new Set();
  collectIds(json, 2, found);
  return [...found];
}

function collectIds(value, depth, found) {
  if (Array.isArray(value)) {
    for (const item of value) if (isPlainObject(item)) collectIds(item, depth, found);
    return;
  }
  if (!isPlainObject(value) || depth <= 0) return;
  for (const [key, field] of Object.entries(value)) {
    if (ID_KEY.test(key) && isIdValue(field)) found.add(String(field));
    else if (field && typeof field === 'object') collectIds(field, depth - 1, found);
  }
}

function isIdValue(value) {
  return (typeof value === 'string' && value.length > 0 && value.length <= 200) || Number.isFinite(value);
}

/** {field: hash(value)} for the ownership fields of an item, or of the first wrapped item ({run: {...}}). */
function ownershipOf(json) {
  if (!isPlainObject(json)) return {};
  const own = hashedOwnership(json);
  if (Object.keys(own).length) return own;
  const inner = Object.values(json).find(value => isPlainObject(value) && Object.keys(hashedOwnership(value)).length);
  return inner ? hashedOwnership(inner) : {};
}

function hashedOwnership(item) {
  const scalar = value => ['string', 'number', 'boolean'].includes(typeof value);
  return Object.fromEntries(ownershipFields(item).filter(field => scalar(item[field])).map(field => [field, hash(item[field])]));
}
