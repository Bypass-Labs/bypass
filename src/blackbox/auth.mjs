import {ownershipReady} from '../ownership-store.mjs';
// Authentication of the two test accounts: finds the login call (pinned in the scope, mined from bundles or
// documented in OpenAPI), sends exactly one POST of the operator's credentials per account, takes the token from
// the answer and hands the guarded requester a private env. No credential or token reaches the ledger or a log.
// Implements design section 4.4 (with the evidence rules of section 14) of docs/BLACKBOX_AUDIT.md.
import { safeRequest, pathAllowed } from '../network.mjs';
import { need, Fault } from '../util.mjs';
import { matchNever } from './scope.mjs';
import { scrub } from './ledger.mjs';
import {parseOpenApi} from './recon.mjs';

/** Paths that look like a login call (design 4.4). */
export const LOGIN_PATH_RE = /(^|\/)(login|signin|sign-in|session|sessions|auth\/token|oauth\/token|token)(\/|$)/i;

const IDENTITIES = ['owner', 'outsider'];
const USERNAME_FIELDS = ['email', 'username', 'login', 'user', 'identifier'];
const PASSWORD_FIELDS = ['password', 'pass', 'pwd'];
const TOKEN_FIELDS = [['token'], ['accessToken'], ['access_token'], ['id_token'], ['jwt'], ['authentication', 'token'], ['data', 'token']];
const JWT_DEPTH = 3;
const JWT_SHAPE = /^eyJ[\w-]*\.eyJ[\w-]*\.[\w-]*$/;
// Visible ASCII only: a value with spaces or control characters cannot travel in a header as it was received.
const TOKEN_TEXT = /^[\x21-\x7e]{1,8192}$/;
const SESSION_COOKIE = /(session|sid|token|auth|jwt)/i;
const CSRF_COOKIE = /csrf|xsrf/i;
const CONTENT_TYPES = {json: 'application/json', form: 'application/x-www-form-urlencoded'};
// No location or link header: a login redirect may carry the token in its query.
const LOGIN_HEADERS = ['content-type', 'cache-control', 'retry-after', 'server', 'www-authenticate'];
const STORED_URL_CHARS = 2048;
const REFRESH_WINDOW_MS = 60_000;
const SESSION_ENV = {owner: 'BX_SESSION_OWNER', outsider: 'BX_SESSION_OUTSIDER'};
const CREDENTIAL_ENV = {
  owner: {usernameEnv: 'OWNER_USER', passwordEnv: 'OWNER_PASS'},
  outsider: {usernameEnv: 'OTHER_USER', passwordEnv: 'OTHER_PASS'},
};

/**
 * Login calls to try, in order (design 4.4). A pinned entry {path, usernameField, passwordField, encoding?} from
 * scope.identities.login is the only candidate when given. Otherwise POST endpoints whose path matches
 * LOGIN_PATH_RE and has no template slot: mined call sites (sent as JSON), then OpenAPI operations as parseOpenApi
 * returns them (Swagger 2 formData parameters, or an inline OpenAPI 3 `requestBody` when the operation carries
 * one), deduplicated by path. Username field: the first of email, username, login, user, identifier the call
 * names, else 'email'; password field: the first of password, pass, pwd, else 'password'.
 * @returns {{path: string, usernameField: string, passwordField: string, encoding: 'json'|'form', source: 'pinned'|'mined'|'openapi'}[]}
 */
export function findLoginCandidates({mined = null, openapi = [], pinned = null} = {}) {
  if (pinned) {
    return [{path: pinned.path, usernameField: pinned.usernameField ?? 'email', passwordField: pinned.passwordField ?? 'password',
      encoding: pinned.encoding === 'form' ? 'form' : 'json', source: 'pinned'}];
  }
  const found = [
    ...(mined?.endpoints ?? []).filter(isLoginCall).map(endpoint => loginCandidate(endpoint.path, endpoint.params ?? [], 'json', 'mined')),
    ...(openapi ?? []).filter(isLoginCall).map(openapiCandidate),
  ];
  const byPath = new Map();
  for (const candidate of found) if (!byPath.has(candidate.path)) byPath.set(candidate.path, candidate);
  return [...byPath.values()];
}

/**
 * The session credential in a login answer {status, headers, body}: a JSON field (token, accessToken,
 * access_token, id_token, jwt, authentication.token, data.token, in that order), else the first JWT-shaped
 * string at depth 3 or less, else the first live Set-Cookie named like a session (session, sid, token, auth,
 * jwt; CSRF cookies excluded). The status is not looked at: login() reads 2xx answers only.
 * @returns {{placement: 'bearer', value: string} | {placement: 'cookie', name: string, value: string} | null}
 */
export function extractToken(response) {
  const body = response?.body;
  const json = typeof body === 'string' ? parseJson(body) : body;
  const value = tokenField(json) ?? jwtWithin(json, JWT_DEPTH);
  if (value) return {placement: 'bearer', value};
  return sessionCookie(response?.headers?.['set-cookie']);
}

/** The `exp` claim of a JWT in milliseconds, decoded without verifying the signature; null for anything else. */
export function jwtExpiry(token) {
  const parts = typeof token === 'string' ? token.split('.') : [];
  if (parts.length !== 3) return null;
  const claims = parseJson(Buffer.from(parts[1], 'base64url').toString('utf8'));
  return Number.isFinite(claims?.exp) ? claims.exp * 1000 : null;
}

/**
 * Sends ONE login POST for `identity` ('owner'|'outsider') with `credentials` {username, password} to `origin`
 * (default the target) + candidate.path, JSON or form-encoded as the candidate says; never retried. It is refused
 * unsent, and recorded with step 'refused', when the origin is not a credential origin, the path is not exactly
 * the path that would be requested (dot segments, encoded separators, a query, another host) or `never` matches
 * it. The ledger record (step 'identity') holds the request line, the status, a few headers and the size: never
 * a request or response body, a credential or the token.
 * @returns {Promise<{ok: true, placement: 'bearer'|'cookie', cookieName?: string, value: string, expiresAt: number|null}
 *   | {ok: false, reason: 'not-found'|'refused'|'request-failed'|'no-token'|string}>} reason 'http-<status>' for a non-2xx answer
 */
export async function login(scope, {identity, credentials, candidate, origin = scope.target.origin, ledger, allowLocal = false, log = () => {}} = {}) {
  need(IDENTITIES.includes(identity), `Unknown identity '${identity}'.`);
  need(ledger, 'login needs the evidence ledger.');
  need(credentials?.username && credentials?.password, `The ${identity} login needs a username and a password.`);
  if (!candidate) return {ok: false, reason: 'not-found'};
  const url = `${origin}${candidate.path}`;
  const refusal = loginRefusal(scope, origin, candidate.path);
  if (refusal) {
    const evidenceId = ledger.append({step: 'refused', identity, request: {method: 'POST', url: url.slice(0, STORED_URL_CHARS)}, refused: refusal});
    log({stage: 'identity', message: `${identity}: login at ${candidate.path} refused (${refusal.rule})`, evidenceId});
    return {ok: false, reason: 'refused'};
  }
  const secrets = [credentials.username, credentials.password];
  const request = {method: 'POST', url, headers: ['content-type']};
  const encoding = candidate.encoding === 'form' ? 'form' : 'json';
  let response;
  try {
    response = await safeRequest(url, {allowLocal, method: 'POST', headers: {'content-type': CONTENT_TYPES[encoding]},
      body: loginBody(candidate, credentials, encoding)});
  } catch (error) {
    if (!(error instanceof Fault)) throw error;
    const evidenceId = ledger.append({step: 'identity', identity, request, blocked: {reason: scrub(error.message, secrets)}});
    log({stage: 'identity', message: `${identity}: login request to ${candidate.path} failed`, evidenceId});
    return {ok: false, reason: 'request-failed'};
  }
  const accepted = response.status >= 200 && response.status < 300;
  const token = accepted ? extractToken(response) : null;
  const evidenceId = ledger.append({step: 'identity', identity, request, response: {
    status: response.status, headers: loginHeaders(response.headers, [...secrets, token?.value]), bytes: Buffer.byteLength(response.body),
  }});
  const reason = !accepted ? `http-${response.status}` : token ? null : 'no-token';
  if (reason) {
    log({stage: 'identity', message: `${identity}: login at ${candidate.path} failed (${reason})`, evidenceId});
    return {ok: false, reason};
  }
  log({stage: 'identity', message: `${identity}: logged in at ${candidate.path} (${token.placement} session)`, evidenceId});
  const session = {ok: true, placement: token.placement, value: token.value, expiresAt: jwtExpiry(token.value)};
  return token.placement === 'cookie' ? {...session, cookieName: token.name} : session;
}

/**
 * Establishes the owner and outsider sessions (design 4.4). A token already set in scope.identities.<id>.env is
 * used as is. Otherwise the account's credentials (env names in identities.<id>.login.usernameEnv/passwordEnv,
 * default OWNER_USER/OWNER_PASS and OTHER_USER/OTHER_PASS) get ONE login: the first candidate that is not
 * refused; a failed attempt is final for the run. A session goes into the returned private env under
 * BX_SESSION_OWNER or BX_SESSION_OUTSIDER, and the returned frozen scope copy points identities.<id>.env at it
 * with identities.auth set to the placement received: 'bearer', or 'cookie' with the env value '<name>=<value>'.
 * One scope carries one placement, so a session that differs from the configured placement of a ready token, or
 * from the other account's session, is dropped with reason 'placement-mismatch'.
 * refresh() logs in again, once per call, each login session whose JWT expires within 60 s; a failed re-login
 * marks it not ok and removes its session value. It resolves to `identities`, which it updates in place.
 * anonymousOnly is true when neither account was supplied at all.
 * @returns {Promise<{scope: object, env: object, loginSpecs: object, identities: {owner: object, outsider: object}, anonymousOnly: boolean,
 *   refresh: () => Promise<object>}>} each identity is {mode: 'token'|'login'|'none', ok, reason, expiresAt}
 */
export async function establishIdentities(scope, {mined = null, openapi = [], requester = null,
  env = {}, ledger, allowLocal = false, log = () => {}} = {}) {
  // Deployed login is an exact, separately authorized POST. A discovered POST call is not permission.
  let candidates = scope.target.environment === 'local' || scope.identities.login ?
    findLoginCandidates({mined, openapi, pinned: scope.identities.login ?? null}) : [];
  if (!candidates.length && scope.target.environment === 'local' && requester &&
      IDENTITIES.some(identity => {
        const names = credentialNames(scope, identity);
        return !present(env[scope.identities[identity].env]) &&
          present(env[names.usernameEnv]) && present(env[names.passwordEnv]);
      })) {
    const documents = [...new Set([...scope.discover.filter(path => /openapi|swagger|api-docs/i.test(path)),
      scope.seeds.openapi].filter(Boolean))].slice(0, 6);
    const operations = [];
    for (const document of documents) {
      const response = await requester({url: document, identity: 'anonymous', method: 'GET',
        step: 'identity', purpose: 'discover'});
      if (response.status !== 200 || typeof response.body !== 'string' || response.body.length > 500000) continue;
      let json;
      try {json = JSON.parse(response.body);} catch {continue;}
      if (json?.openapi || json?.swagger) operations.push(...parseOpenApi(json, scope.target.origin).operations);
    }
    candidates = findLoginCandidates({mined, openapi: operations});
  }
  const tokenNames = IDENTITIES.map(identity => scope.identities[identity].env).filter(name => present(env[name]));
  const state = {
    env: Object.fromEntries(tokenNames.map(name => [name, env[name]])),
    // A ready token keeps the placement the operator configured; otherwise the first login decides it.
    auth: tokenNames.length || scope.identities.identityCookieName ? scope.identities.auth : null,
    logins: {},
  };
  const context = {scope, env, candidates, ledger, allowLocal, log, state};
  const identities = {};
  for (const identity of IDENTITIES) identities[identity] = await establish(context, identity);
  const anonymousOnly = IDENTITIES.every(identity => identities[identity].mode === 'none');
  if (anonymousOnly) log({stage: 'identity', message: 'No test accounts: cross-account tests are skipped'});

  async function refresh() {
    for (const [identity, candidate] of Object.entries(state.logins)) {
      const status = identities[identity];
      if (!status.ok || status.expiresAt === null || status.expiresAt - Date.now() > REFRESH_WINDOW_MS) continue;
      const result = await login(scope, {identity, credentials: credentialsOf(scope, identity, env), candidate, ledger, allowLocal, log});
      if (result.ok && result.placement === state.auth) {
        state.env[SESSION_ENV[identity]] = sessionValue(result);
        status.expiresAt = result.expiresAt;
        continue;
      }
      delete state.env[SESSION_ENV[identity]];
      Object.assign(status, {ok: false, reason: result.ok ? 'placement-mismatch' : result.reason, expiresAt: null});
    }
    return identities;
  }

  const loginSpecs = Object.fromEntries(Object.entries(state.logins).map(([identity, candidate]) =>
    [identity, {origin: scope.target.origin, path: candidate.path, usernameField: candidate.usernameField,
      passwordField: candidate.passwordField, encoding: candidate.encoding, ...credentialNames(scope, identity)}]));
  return {scope: sessionScope(scope, state), env: state.env, loginSpecs, identities, anonymousOnly, refresh};
}

/** One account: its ready token, else its single login attempt, else nothing. */
async function establish({scope, env, candidates, ledger, allowLocal, log, state}, identity) {
  const tokenName = scope.identities[identity].env;
  if (present(env[tokenName])) {
    log({stage: 'identity', message: `${identity}: using the token in ${tokenName}`});
    return {mode: 'token', ok: true, reason: null, expiresAt: jwtExpiry(env[tokenName])};
  }
  const names = credentialNames(scope, identity);
  const missing = [names.usernameEnv, names.passwordEnv].filter(name => !present(env[name]));
  if (missing.length === 2) {
    log({stage: 'identity', message: `${identity}: none of ${tokenName}, ${names.usernameEnv}, ${names.passwordEnv} is set; the account is not used`});
    return failed('none', 'no-credentials');
  }
  if (missing.length) {
    log({stage: 'identity', message: `${identity}: ${missing[0]} is not set, so there is no login attempt`});
    return failed('login', 'credentials-incomplete');
  }
  const credentials = credentialsOf(scope, identity, env);
  for (const candidate of candidates) {
    const result = await login(scope, {identity, credentials, candidate, ledger, allowLocal, log});
    if (result.reason !== 'refused') return adopt(state, identity, result, candidate, log);
  }
  const where = candidates.length ? 'every login endpoint found is refused by the scope' : 'no login endpoint found';
  log({stage: 'identity', message: `${identity}: ${where}; set ${tokenName} or pin identities.login`});
  return failed('login', candidates.length ? 'refused' : 'not-found');
}

/** Keeps a successful login whose placement fits the scope's single placement; a failed attempt is final. */
function adopt(state, identity, result, candidate, log) {
  if (!result.ok) return failed('login', result.reason);
  if (state.auth && state.auth !== result.placement) {
    const message = `${identity}: the login gave a ${result.placement} session but this run sends ${state.auth} credentials; it is not used`;
    log({stage: 'identity', message});
    return failed('login', 'placement-mismatch');
  }
  state.auth = result.placement;
  state.logins[identity] = candidate;
  state.env[SESSION_ENV[identity]] = sessionValue(result);
  return {mode: 'login', ok: true, reason: null, expiresAt: result.expiresAt};
}

function failed(mode, reason) {
  return {mode, ok: false, reason, expiresAt: null};
}

/** A frozen copy of the scope whose identities point at the session env names and carry the placement in use. */
function sessionScope(scope, state) {
  const copy = structuredClone(scope);
  copy.identities.auth = state.auth ?? scope.identities.auth;
  for (const identity of Object.keys(state.logins)) copy.identities[identity].env = SESSION_ENV[identity];
  return deepFreeze(copy);
}

function sessionValue(result) {
  return result.placement === 'cookie' ? `${result.cookieName}=${result.value}` : result.value;
}

function credentialNames(scope, identity) {
  const names = scope.identities[identity].login ?? {};
  return {
    usernameEnv: names.usernameEnv ?? CREDENTIAL_ENV[identity].usernameEnv,
    passwordEnv: names.passwordEnv ?? CREDENTIAL_ENV[identity].passwordEnv,
  };
}

/** The credential values, read from the environment when they are needed and never kept. */
function credentialsOf(scope, identity, env) {
  const names = credentialNames(scope, identity);
  return {username: env[names.usernameEnv], password: env[names.passwordEnv]};
}

/** Why a login may not be sent, or null: credential origin, the exact path, the never list (design 4.2, 4.4). */
function loginRefusal(scope, origin, path) {
  if (!scope.credentialOrigins.includes(origin)) return {rule: 'credential-origin'};
  const url = typeof path === 'string' && URL.canParse(path, origin) ? new URL(path, origin) : null;
  if (!url || url.origin !== origin || url.pathname !== path || !pathAllowed(path, ['/'])) return {rule: 'path'};
  if (scope.expiresAt && Date.parse(scope.expiresAt) <= Date.now()) return {rule: 'scope-expired'};
  if (scope.target.environment !== 'local') {
    const registered = scope.authorizedOrigins?.[origin];
    if (!registered || !ownershipReady(registered) ||
      registered.authorization?.origin !== origin || Date.parse(registered.authorization.expiresAt) <= Date.now() ||
      !registered.authorization.loginPaths?.includes(path) || scope.identities.login?.path !== path)
      return {rule: 'login-post-authorization'};
  }
  const never = matchNever(scope, path);
  return never.refused ? {rule: 'never', match: never.match} : null;
}

function loginBody(candidate, {username, password}, encoding) {
  const fields = {[candidate.usernameField]: username, [candidate.passwordField]: password};
  return encoding === 'form' ? new URLSearchParams(fields).toString() : JSON.stringify(fields);
}

/** The response headers worth keeping from a login answer, scrubbed; www-authenticate keeps only its scheme. */
function loginHeaders(headers, secrets) {
  const kept = {};
  for (const name of LOGIN_HEADERS) {
    if (headers[name] === undefined) continue;
    const text = scrub(String(headers[name]), secrets);
    kept[name] = name === 'www-authenticate' ? text.trim().split(/[\s,]/, 1)[0] : text;
  }
  return kept;
}

function isLoginCall(entry) {
  return entry?.method === 'POST' && typeof entry.path === 'string' && !entry.path.includes('{') && LOGIN_PATH_RE.test(entry.path);
}

function loginCandidate(path, fields, encoding, source) {
  const names = fields.filter(name => typeof name === 'string');
  return {
    path, usernameField: firstNamed(names, USERNAME_FIELDS, 'email'), passwordField: firstNamed(names, PASSWORD_FIELDS, 'password'), encoding, source,
  };
}

/** The first of `choices` among `names` (case-insensitive, spelled as the call spells it), else `fallback`. */
function firstNamed(names, choices, fallback) {
  for (const choice of choices) {
    const name = names.find(entry => entry.toLowerCase() === choice);
    if (name) return name;
  }
  return fallback;
}

/** Body fields and encoding of an OpenAPI operation: Swagger 2 formData parameters, else the inline requestBody schema. */
function openapiCandidate(operation) {
  const formData = (operation.params ?? []).filter(param => param?.in === 'formData').map(param => param.name);
  const content = operation.requestBody?.content ?? {};
  const json = content['application/json'];
  const form = content['application/x-www-form-urlencoded'];
  const fields = formData.length ? formData : operation.bodyFields ?? Object.keys((json ?? form)?.schema?.properties ?? {});
  const encoding = formData.length ? 'form' : operation.bodyEncoding ?? (form && !json ? 'form' : 'json');
  return loginCandidate(operation.path, fields, encoding, 'openapi');
}

function tokenField(json) {
  for (const path of TOKEN_FIELDS) {
    const value = path.reduce((node, key) => (isObject(node) ? node[key] : undefined), json);
    if (isToken(value)) return value;
  }
  return null;
}

/** The first JWT-shaped string within `depth` levels of objects and arrays. */
function jwtWithin(value, depth) {
  if (typeof value === 'string') return JWT_SHAPE.test(value) && isToken(value) ? value : null;
  if (!value || typeof value !== 'object' || depth === 0) return null;
  for (const child of Object.values(value)) {
    const found = jwtWithin(child, depth - 1);
    if (found) return found;
  }
  return null;
}

/** Prefer a named session cookie; a sole live HttpOnly cookie can also be a session. */
function sessionCookie(setCookie) {
  const fallback = [];
  for (const line of [setCookie ?? []].flat()) {
    const [pair, ...attributes] = String(line).split(';');
    const at = pair.indexOf('=');
    if (at < 1) continue;
    const name = pair.slice(0, at).trim();
    const value = pair.slice(at + 1).trim();
    if (CSRF_COOKIE.test(name) || !isToken(name) || !isToken(value) ||
        deletes(attributes)) continue;
    if (SESSION_COOKIE.test(name)) return {placement: 'cookie', name, value};
    if (value.length >= 16 && attributes.some(attribute =>
      attribute.trim().toLowerCase() === 'httponly'))
      fallback.push({placement: 'cookie', name, value});
  }
  return fallback.length === 1 ? fallback[0] : null;
}

/** A Set-Cookie deletes its cookie with Max-Age zero or less, or with an Expires date in the past. */
function deletes(attributes) {
  return attributes.some(attribute => {
    const at = attribute.indexOf('=');
    if (at === -1) return false;
    const key = attribute.slice(0, at).trim().toLowerCase();
    const value = attribute.slice(at + 1).trim();
    return (key === 'max-age' && Number(value) <= 0) || (key === 'expires' && Date.parse(value) <= Date.now());
  });
}

/** A body that is not a JSON object or array is data, not a failure: it yields undefined. */
function parseJson(text) {
  if (!/^\s*[[{]/.test(text)) return undefined;
  try {
    return JSON.parse(text);
  } catch {
    return undefined;
  }
}

function isObject(value) {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

function isToken(value) {
  return typeof value === 'string' && TOKEN_TEXT.test(value);
}

function present(value) {
  return typeof value === 'string' && value.length > 0;
}

function deepFreeze(value) {
  if (value && typeof value === 'object') {
    for (const child of Object.values(value)) deepFreeze(child);
    Object.freeze(value);
  }
  return value;
}
