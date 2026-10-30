// Tests for black-box authentication (src/blackbox/auth.mjs): login discovery from a mined summary, OpenAPI
// operations and a pinned entry, token extraction, JWT expiry, single login POSTs against a loopback API, and the
// session scope and env handed to the guarded requester, with no credential in the ledger or the log (design 4.4, 14).
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import http from 'node:http';
import { temp, port } from './helpers.mjs';
import { loadScope, credentialHeaders, createRequester, createLimiter } from '../src/blackbox/scope.mjs';
import { createLedger } from '../src/blackbox/ledger.mjs';
import { LOGIN_PATH_RE, findLoginCandidates, extractToken, jwtExpiry, login, establishIdentities } from '../src/blackbox/auth.mjs';

// Synthetic accounts of the loopback fixture: their values must never reach the ledger, a log event or a message.
const ALICE = Object.freeze({id: 'u-1', username: 'alice.owner@example.test', password: 'pw-alice-7Qv2m9', token: 'tok-alice-5d1e8c4b'});
const BOB = Object.freeze({id: 'u-2', username: 'bob.other@example.test', password: 'pw-bob-3Kx8n1', token: 'tok-bob-9a7f2e6d'});
const ACCOUNTS = [ALICE, BOB];
const SECRETS = ACCOUNTS.flatMap(account => [account.username, account.password, account.token]);
const CREDENTIAL_ENV = Object.freeze({OWNER_USER: ALICE.username, OWNER_PASS: ALICE.password, OTHER_USER: BOB.username, OTHER_PASS: BOB.password});
const ALICE_LOGIN = Object.freeze({username: ALICE.username, password: ALICE.password});
const BOB_LOGIN = Object.freeze({username: BOB.username, password: BOB.password});
const LOGIN_CALL = Object.freeze({path: '/api/auth/login', method: 'POST', params: ['email', 'password'], headers: [], files: ['http://127.0.0.1/static/app.js']});
const MINED = Object.freeze({endpoints: [
  {path: '/api/me', method: 'GET', params: [], headers: [], files: []},
  {path: '/api/login', method: 'GET', params: [], headers: [], files: []},
  {path: '/api/invoices', method: 'POST', params: ['total'], headers: [], files: []},
  {path: '/api/tenants/{id}/login', method: 'POST', params: ['email', 'password'], headers: [], files: []},
  LOGIN_CALL,
]});
const JSON_LOGIN = Object.freeze({path: '/api/auth/login', usernameField: 'email', passwordField: 'password', encoding: 'json', source: 'mined'});

/** An unsigned JWT-shaped token carrying `claims`. */
function jwt(claims) {
  const part = value => Buffer.from(JSON.stringify(value)).toString('base64url');
  return `${part({alg: 'HS256', typ: 'JWT'})}.${part(claims)}.c2lnbmF0dXJl`;
}

const seconds = () => Math.floor(Date.now() / 1000);

function tempDir(t) {
  const dir = temp();
  t.after(() => fs.rmSync(dir, {recursive: true, force: true}));
  return dir;
}

/** A mutable loopback scope; `edit` adds what scope files cannot carry yet (identities.login, identities.<id>.login). */
function scopeFor(origin, edit = () => {}) {
  const scope = structuredClone(loadScope({origin, overrides: {acceptLocal: true}}).scope);
  edit(scope);
  return scope;
}

/** A ledger given no secrets, so the tests prove auth.mjs never hands it a credential. */
function ledgerFor(t) {
  return createLedger(tempDir(t), {run: 'bx-test'});
}

function ledgerText(ledger) {
  return fs.existsSync(ledger.file) ? fs.readFileSync(ledger.file, 'utf8') : '';
}

function records(ledger) {
  return ledgerText(ledger).split('\n').filter(Boolean).map(line => JSON.parse(line));
}

/** Fails naming only the position of the secret, never its value. */
function assertNoSecrets(text, where, secrets = SECRETS) {
  secrets.forEach((secret, index) => assert.ok(!text.includes(secret), `${where} contains secret #${index}`));
}

/** Loopback API: `routes` maps 'METHOD /path' to (req, rawBody) => {status, headers?, body}; hits are counted per route. */
async function startApi(t, routes) {
  const listenPort = await port();
  const hits = {};
  const server = http.createServer((req, res) => {
    let raw = '';
    req.setEncoding('utf8');
    req.on('data', chunk => { raw += chunk; });
    req.on('end', () => {
      const key = `${req.method} ${new URL(req.url, 'http://127.0.0.1').pathname}`;
      hits[key] = (hits[key] ?? 0) + 1;
      const reply = routes[key]?.(req, raw) ?? {status: 404, body: {error: 'not found'}};
      res.writeHead(reply.status, {'content-type': 'application/json', ...reply.headers});
      res.end(JSON.stringify(reply.body ?? {}));
    });
  });
  await new Promise(resolve => server.listen(listenPort, '127.0.0.1', resolve));
  t.after(() => new Promise(resolve => {
    server.closeAllConnections();
    server.close(resolve);
  }));
  return {origin: `http://127.0.0.1:${listenPort}`, hits};
}

/** Counts a login attempt under the account id (never the username) the request named. */
function countAttempt(attempts, username) {
  const id = ACCOUNTS.find(account => account.username === username)?.id ?? 'unknown';
  attempts[id] = (attempts[id] ?? 0) + 1;
}

/** JSON login {email, password}: 200 with issue(account) for a known account, 401 otherwise. */
function jsonLogin(attempts, issue = account => ({token: account.token})) {
  return (req, raw) => {
    const body = /^\s*\{/.test(raw) ? JSON.parse(raw) : {};
    countAttempt(attempts, body.email);
    const account = ACCOUNTS.find(entry => entry.username === body.email && entry.password === body.password);
    const json = req.headers['content-type'] === 'application/json';
    return account && json ? {status: 200, body: issue(account)} : {status: 401, body: {error: 'invalid credentials'}};
  };
}

/** Form login username/password: a CSRF cookie, then the session cookie `sid`. */
function formLogin(attempts) {
  return (req, raw) => {
    const form = new URLSearchParams(raw);
    countAttempt(attempts, form.get('username'));
    const account = ACCOUNTS.find(entry => entry.username === form.get('username') && entry.password === form.get('password'));
    if (!account || req.headers['content-type'] !== 'application/x-www-form-urlencoded') return {status: 401, body: {error: 'invalid credentials'}};
    return {status: 200, headers: {'set-cookie': ['csrftoken=csrf-0f1e2d3c4b; Path=/', `sid=${account.token}; HttpOnly; Path=/`]}, body: {ok: true}};
  };
}

/** GET /api/me for a bearer token or a `sid` cookie. */
function me(req) {
  const bearer = (req.headers.authorization ?? '').replace(/^Bearer /, '');
  const sid = /(?:^|;\s*)sid=([^;]+)/.exec(req.headers.cookie ?? '')?.[1];
  const account = ACCOUNTS.find(entry => entry.token === bearer || entry.token === sid);
  return account ? {status: 200, body: {id: account.id, role: 'member'}} : {status: 401, body: {error: 'login required'}};
}

// ---- Pure functions ---------------------------------------------------------------------------------------------

test('LOGIN_PATH_RE matches login, session and token paths, not look-alikes', () => {
  for (const path of ['/login', '/api/auth/login', '/api/signin', '/sign-in', '/api/session', '/api/v1/sessions', '/auth/token',
    '/oauth/token', '/api/token', '/API/Login', '/api/login/']) {
    assert.ok(LOGIN_PATH_RE.test(path), path);
  }
  for (const path of ['/api/login-history', '/api/tokens', '/api/loginfo', '/api/sessionsx', '/api/users', '/blogin', '/api/tokenize']) {
    assert.ok(!LOGIN_PATH_RE.test(path), path);
  }
});

test('findLoginCandidates takes POST login call sites from a mined summary and ignores GET routes', () => {
  assert.deepEqual(findLoginCandidates({mined: MINED}), [JSON_LOGIN]);
  const fields = params => findLoginCandidates({mined: {endpoints: [{path: '/signin', method: 'POST', params}]}})
    .map(candidate => [candidate.usernameField, candidate.passwordField]);
  assert.deepEqual(fields([]), [['email', 'password']]);
  assert.deepEqual(fields(['remember', 'user', 'userName', 'pwd']), [['userName', 'pwd']]);
  assert.deepEqual(fields(['identifier', 'login', 'pass', 'password']), [['login', 'password']]);
  assert.deepEqual(findLoginCandidates({}), []);
  assert.deepEqual(findLoginCandidates({mined: null, openapi: []}), []);
});

test('findLoginCandidates adds OpenAPI login operations with their body fields and encoding, deduplicated by path', () => {
  const jsonBody = properties => ({content: {'application/json': {schema: {type: 'object', properties}}}});
  const openapi = [
    {path: '/api/auth/login', method: 'POST', params: [], tag: 'auth', requestBody: jsonBody({username: {}, password: {}})},
    {path: '/v1/session', method: 'POST', params: [], tag: null, requestBody: jsonBody({username: {}, password: {}})},
    {path: '/v1/auth/token', method: 'POST', params: [{name: 'login', in: 'formData'}, {name: 'pass', in: 'formData'}], tag: null},
    {path: '/v1/signin', method: 'POST', params: [], tag: null,
      requestBody: {content: {'application/x-www-form-urlencoded': {schema: {properties: {identifier: {}, password: {}}}}}}},
    {path: '/v1/login', method: 'GET', params: [], tag: null},
    {path: '/v1/users', method: 'POST', params: [], tag: null},
  ];
  assert.deepEqual(findLoginCandidates({mined: MINED, openapi}), [
    JSON_LOGIN,
    {path: '/v1/session', usernameField: 'username', passwordField: 'password', encoding: 'json', source: 'openapi'},
    {path: '/v1/auth/token', usernameField: 'login', passwordField: 'pass', encoding: 'form', source: 'openapi'},
    {path: '/v1/signin', usernameField: 'identifier', passwordField: 'password', encoding: 'form', source: 'openapi'},
  ]);
});

test('findLoginCandidates: a pinned login overrides everything discovered', () => {
  const openapi = [{path: '/v1/session', method: 'POST', params: [], tag: null}];
  assert.deepEqual(findLoginCandidates({mined: MINED, openapi, pinned: {path: '/members/enter', usernameField: 'handle', passwordField: 'secret'}}), [
    {path: '/members/enter', usernameField: 'handle', passwordField: 'secret', encoding: 'json', source: 'pinned'},
  ]);
  assert.deepEqual(findLoginCandidates({mined: MINED, pinned: {path: '/api/auth/login', encoding: 'form'}}), [
    {path: '/api/auth/login', usernameField: 'email', passwordField: 'password', encoding: 'form', source: 'pinned'},
  ]);
});

test('extractToken reads each JSON token shape in the documented order, then any JWT up to depth 3', () => {
  const token = body => extractToken({status: 200, headers: {}, body: JSON.stringify(body)});
  const shapes = [{token: 'opaque-1'}, {accessToken: 'opaque-1'}, {access_token: 'opaque-1'}, {id_token: 'opaque-1'}, {jwt: 'opaque-1'},
    {authentication: {token: 'opaque-1'}}, {data: {token: 'opaque-1'}}];
  for (const body of shapes) assert.deepEqual(token(body), {placement: 'bearer', value: 'opaque-1'}, JSON.stringify(Object.keys(body)));
  assert.deepEqual(token({jwt: 'later', data: {token: 'last'}, token: 'first'}), {placement: 'bearer', value: 'first'});
  const nested = jwt({sub: 'u-1'});
  assert.deepEqual(token({result: {session: {credential: nested}}}), {placement: 'bearer', value: nested});
  assert.deepEqual(token({sessions: [{credential: nested}]}), {placement: 'bearer', value: nested});
  assert.equal(token({a: {b: {c: {d: nested}}}}), null);
  assert.equal(token({token: '', accessToken: {value: 'x'}, access_token: 'has space', ok: true}), null);
  assert.equal(extractToken({status: 200, headers: {}, body: '<html>signed in</html>'}), null);
});

test('extractToken falls back to a live session cookie, skipping CSRF, unrelated and cleared cookies', () => {
  const headers = {'set-cookie': ['theme=dark; Path=/', 'XSRF-TOKEN=csrf-1234; Path=/', 'session=; Max-Age=0',
    'auth=deleted; Expires=Thu, 01 Jan 1970 00:00:00 GMT', 'connect.sid=s%3Aabc.def; HttpOnly; Path=/']};
  assert.deepEqual(extractToken({status: 200, headers, body: '{"ok":true}'}), {placement: 'cookie', name: 'connect.sid', value: 's%3Aabc.def'});
  assert.deepEqual(extractToken({status: 200, headers, body: '{"token":"opaque-2"}'}), {placement: 'bearer', value: 'opaque-2'});
  assert.deepEqual(extractToken({status: 200, headers: {'set-cookie': 'sid=abc123; Path=/'}, body: ''}), {placement: 'cookie', name: 'sid', value: 'abc123'});
  assert.equal(extractToken({status: 200, headers: {'set-cookie': ['theme=dark']}, body: '{"ok":true}'}), null);
  assert.equal(extractToken({status: 200, headers: {}, body: ''}), null);
});

test('extractToken accepts one live nonstandard HttpOnly session candidate', () => {
  const value = 'opaque-private-cookie-123456';
  const response = lines => extractToken({status: 200, body: '',
    headers: {'set-cookie': lines}});
  assert.deepEqual(response(['theme=dark; Path=/',
    'csrfToken=not-a-session; HttpOnly', `workspace=${value}; HttpOnly; Secure`]),
  {placement: 'cookie', name: 'workspace', value});
  assert.equal(response([`workspace=${value}; HttpOnly`,
    'tracking=another-long-cookie-value; HttpOnly']), null);
  assert.equal(response([`workspace=${value}; HttpOnly; Max-Age=0`]), null);
});

test('jwtExpiry decodes exp without verifying it, in milliseconds', () => {
  assert.equal(jwtExpiry(jwt({sub: 'u-1', exp: 1893456000})), 1893456000000);
  assert.equal(jwtExpiry(jwt({sub: 'u-1'})), null);
  assert.equal(jwtExpiry(jwt({exp: '1893456000'})), null);
  assert.equal(jwtExpiry('opaque-token'), null);
  assert.equal(jwtExpiry('eyJhbGciOiJub25lIn0.not-json.'), null);
  assert.equal(jwtExpiry(undefined), null);
});

// ---- login() against a loopback API ------------------------------------------------------------------------------

test('login sends one JSON POST with the call-site fields and returns the bearer token and its expiry', async t => {
  const exp = seconds() + 3600;
  const issued = jwt({sub: ALICE.id, exp});
  const attempts = {};
  const seen = [];
  const handler = jsonLogin(attempts, account => ({accessToken: issued, user: {id: account.id}}));
  const api = await startApi(t, {'POST /api/auth/login': (req, raw) => {
    seen.push({type: req.headers['content-type'], raw});
    return handler(req, raw);
  }});
  const ledger = ledgerFor(t);
  const events = [];
  const result = await login(scopeFor(api.origin), {identity: 'owner', credentials: ALICE_LOGIN, candidate: JSON_LOGIN, ledger,
    allowLocal: true, log: event => events.push(event)});
  const {value, ...rest} = result;
  assert.ok(value === issued, 'login returns the issued token');
  assert.deepEqual(rest, {ok: true, placement: 'bearer', expiresAt: exp * 1000});
  assert.deepEqual(api.hits, {'POST /api/auth/login': 1});
  assert.deepEqual(attempts, {'u-1': 1});
  assert.equal(seen[0].type, 'application/json');
  assert.ok(seen[0].raw === JSON.stringify({email: ALICE.username, password: ALICE.password}), 'the body carries the call-site field names');
  const [record, ...others] = records(ledger);
  assert.equal(others.length, 0);
  assert.deepEqual([record.step, record.identity, record.run], ['identity', 'owner', 'bx-test']);
  assert.deepEqual(record.request, {method: 'POST', url: `${api.origin}/api/auth/login`, headers: ['content-type']});
  assert.deepEqual(Object.keys(record.response).sort(), ['bytes', 'headers', 'status']);
  assert.equal(record.response.status, 200);
  assert.deepEqual(Object.keys(record.response.headers), ['content-type']);
  assert.equal(record.excerpt, undefined);
  assertNoSecrets(ledgerText(ledger), 'the ledger', [...SECRETS, issued]);
  assertNoSecrets(JSON.stringify(events), 'the log', [...SECRETS, issued]);
});

test('login reports http-<status> or no-token after its single request and never retries', async t => {
  const api = await startApi(t, {
    // A hostile answer echoes the submitted body into a header the ledger keeps.
    'POST /api/auth/login': (req, raw) => ({status: 401, headers: {'www-authenticate': 'Bearer realm="api", error="invalid_token"', server: `echo ${raw}`},
      body: {error: 'invalid credentials'}}),
    'POST /api/session': () => ({status: 200, headers: {'set-cookie': ['theme=dark; Path=/']}, body: {ok: true}}),
    'POST /api/token': () => ({status: 503, body: {error: 'busy'}}),
  });
  const ledger = ledgerFor(t);
  const attempt = path => login(scopeFor(api.origin), {identity: 'outsider', credentials: BOB_LOGIN, candidate: {...JSON_LOGIN, path},
    ledger, allowLocal: true});
  assert.deepEqual(await attempt('/api/auth/login'), {ok: false, reason: 'http-401'});
  assert.deepEqual(await attempt('/api/session'), {ok: false, reason: 'no-token'});
  assert.deepEqual(await attempt('/api/token'), {ok: false, reason: 'http-503'});
  assert.deepEqual(api.hits, {'POST /api/auth/login': 1, 'POST /api/session': 1, 'POST /api/token': 1});
  const kept = records(ledger).map(record => [record.step, record.identity, record.response.status, record.response.headers['www-authenticate'] ?? null]);
  assert.deepEqual(kept, [['identity', 'outsider', 401, 'Bearer'], ['identity', 'outsider', 200, null], ['identity', 'outsider', 503, null]]);
  assertNoSecrets(ledgerText(ledger), 'the ledger');
  assert.equal(records(ledger)[0].response.headers.server, 'echo {"email":"[REDACTED]","password":"[REDACTED]"}');
});

test('login posts form-encoded credentials and takes the session cookie, not the CSRF cookie', async t => {
  const attempts = {};
  const api = await startApi(t, {'POST /api/session': formLogin(attempts)});
  const candidate = {path: '/api/session', usernameField: 'username', passwordField: 'password', encoding: 'form', source: 'openapi'};
  const ledger = ledgerFor(t);
  const {value, ...rest} = await login(scopeFor(api.origin), {identity: 'outsider', credentials: BOB_LOGIN, candidate, ledger, allowLocal: true});
  assert.ok(value === BOB.token, 'login returns the session cookie value');
  assert.deepEqual(rest, {ok: true, placement: 'cookie', cookieName: 'sid', expiresAt: null});
  assert.deepEqual(attempts, {'u-2': 1});
  assertNoSecrets(ledgerText(ledger), 'the ledger');
});

test('login refuses never-listed paths, rewritten paths and non-credential origins without sending anything', async t => {
  const api = await startApi(t, {});
  const ledger = ledgerFor(t);
  const scope = scopeFor(api.origin, scope => {scope.never = ['oauth', 'logout'];});
  const options = {identity: 'owner', credentials: ALICE_LOGIN, ledger, allowLocal: true};
  const rewritten = ['/api/../login', '/api/./login', '/api/%2e%2e/login', '/login?next=/', '//elsewhere.test/login', 'login'];
  for (const path of ['/oauth/token', '/api/auth/logout', ...rewritten]) {
    assert.deepEqual(await login(scope, {...options, candidate: {...JSON_LOGIN, path}}), {ok: false, reason: 'refused'}, path);
  }
  assert.deepEqual(await login(scope, {...options, candidate: JSON_LOGIN, origin: 'http://127.0.0.1:9'}), {ok: false, reason: 'refused'});
  assert.deepEqual(await login(scope, {...options, candidate: null}), {ok: false, reason: 'not-found'});
  assert.deepEqual(api.hits, {});
  const refused = records(ledger).map(record => [record.step, record.request.method, record.refused.rule, record.refused.match ?? null]);
  assert.deepEqual(refused, [
    ['refused', 'POST', 'never', 'oauth'], ['refused', 'POST', 'never', 'logout'],
    ...rewritten.map(() => ['refused', 'POST', 'path', null]), ['refused', 'POST', 'credential-origin', null],
  ]);
});

test('deployed login is refused before the network unless the exact POST path is authorized', async t => {
  const ledger = ledgerFor(t);
  const origin = 'https://app.example.com';
  const expiry = new Date(Date.now() + 86400000).toISOString();
  const scope = scopeFor('http://127.0.0.1:4329');
  scope.target.origin = origin;
  scope.target.environment = 'staging';
  scope.credentialOrigins = [origin];
  scope.expiresAt = expiry;
  scope.identities.login = {path: '/api/auth/login'};
  scope.authorizedOrigins = {[origin]: {url: origin, ownership: {status: 'verified', expiresAt: expiry},
    authorization: {origin, expiresAt: expiry, loginPaths: []}}};
  const result = await login(scope, {identity: 'owner', credentials: ALICE_LOGIN, candidate: JSON_LOGIN, ledger});
  assert.deepEqual(result, {ok: false, reason: 'refused'});
  assert.equal(records(ledger).at(-1).refused.rule, 'login-post-authorization');
});

test('login records a blocked exchange and reports request-failed when nothing answers', async t => {
  const origin = `http://127.0.0.1:${await port()}`;
  const ledger = ledgerFor(t);
  const result = await login(scopeFor(origin), {identity: 'owner', credentials: ALICE_LOGIN, candidate: JSON_LOGIN, ledger, allowLocal: true});
  assert.deepEqual(result, {ok: false, reason: 'request-failed'});
  const [record] = records(ledger);
  assert.deepEqual([record.step, record.identity, record.request.method, record.response], ['identity', 'owner', 'POST', undefined]);
  assert.match(record.blocked.reason, /ECONNREFUSED/);
});

// ---- establishIdentities() ---------------------------------------------------------------------------------------

test('establishIdentities uses ready tokens and sends no login request', async t => {
  const attempts = {};
  const api = await startApi(t, {'POST /api/auth/login': jsonLogin(attempts)});
  const scope = scopeFor(api.origin);
  const ledger = ledgerFor(t);
  const env = {OWNER_TOKEN: ALICE.token, OTHER_TOKEN: BOB.token, ...CREDENTIAL_ENV, UNRELATED_SETTING: 'x'};
  const result = await establishIdentities(scope, {mined: MINED, env, ledger, allowLocal: true});
  const ready = {mode: 'token', ok: true, reason: null, expiresAt: null};
  assert.deepEqual(result.identities, {owner: ready, outsider: ready});
  assert.equal(result.anonymousOnly, false);
  assert.deepEqual(api.hits, {});
  assert.equal(ledger.count(), 0);
  assert.deepEqual(result.scope.identities, scope.identities);
  assert.deepEqual(Object.keys(result.env).sort(), ['OTHER_TOKEN', 'OWNER_TOKEN']);
  assert.ok(result.env.OWNER_TOKEN === ALICE.token && result.env.OTHER_TOKEN === BOB.token, 'the ready tokens are handed through');
});

test('establishIdentities logs each account in exactly once and hands the requester a session scope and env', async t => {
  const attempts = {};
  const api = await startApi(t, {'POST /api/auth/login': jsonLogin(attempts), 'GET /api/me': me});
  const scope = scopeFor(api.origin);
  const ledger = ledgerFor(t);
  const events = [];
  const result = await establishIdentities(scope, {mined: MINED, env: CREDENTIAL_ENV, ledger, allowLocal: true, log: event => events.push(event)});
  assert.deepEqual(attempts, {'u-1': 1, 'u-2': 1});
  assert.deepEqual(api.hits, {'POST /api/auth/login': 2});
  const session = {mode: 'login', ok: true, reason: null, expiresAt: null};
  assert.deepEqual(result.identities, {owner: session, outsider: session});
  assert.equal(result.anonymousOnly, false);
  const {identities} = result.scope;
  assert.deepEqual([identities.owner.env, identities.outsider.env, identities.auth], ['BX_SESSION_OWNER', 'BX_SESSION_OUTSIDER', 'bearer']);
  assert.ok(Object.isFrozen(result.scope) && Object.isFrozen(identities.owner), 'the session scope is frozen like a loaded scope');
  assert.equal(scope.identities.owner.env, 'OWNER_TOKEN', 'the input scope is left as it was');
  assert.deepEqual(Object.keys(result.env).sort(), ['BX_SESSION_OUTSIDER', 'BX_SESSION_OWNER']);
  const request = createRequester(result.scope, {ledger, env: result.env, limiter: createLimiter(500), allowLocal: true, run: 'bx-test'});
  for (const [identity, account] of [['owner', ALICE], ['outsider', BOB]]) {
    const answer = await request({url: '/api/me', identity, step: 'identity'});
    assert.equal(answer.status, 200, identity);
    assert.equal(JSON.parse(answer.body).id, account.id);
  }
  assert.deepEqual(records(ledger).map(record => [record.step, record.identity, record.request.method, record.request.url.slice(api.origin.length)]), [
    ['identity', 'owner', 'POST', '/api/auth/login'], ['identity', 'outsider', 'POST', '/api/auth/login'],
    ['identity', 'owner', 'GET', '/api/me'], ['identity', 'outsider', 'GET', '/api/me'],
  ]);
  assertNoSecrets(ledgerText(ledger), 'the ledger');
  assertNoSecrets(JSON.stringify(events), 'the log');
  assert.ok(events.some(event => event.stage === 'identity' && /logged in/.test(event.message)));
});

test('a failed login is final: refused candidates are skipped unsent and no other candidate is tried', async t => {
  const attempts = {};
  const api = await startApi(t, {'POST /api/auth/login': jsonLogin(attempts), 'POST /api/session': jsonLogin(attempts)});
  const mined = {endpoints: [{path: '/oauth/token', method: 'POST', params: ['username', 'password'], headers: [], files: []}, LOGIN_CALL,
    {path: '/api/session', method: 'POST', params: ['email', 'password'], headers: [], files: []}]};
  const ledger = ledgerFor(t);
  const wrong = 'pw-wrong-0000';
  const result = await establishIdentities(scopeFor(api.origin, scope => {scope.never = ['oauth'];}),
    {mined, env: {...CREDENTIAL_ENV, OTHER_PASS: wrong}, ledger, allowLocal: true});
  assert.deepEqual(result.identities.owner, {mode: 'login', ok: true, reason: null, expiresAt: null});
  assert.deepEqual(result.identities.outsider, {mode: 'login', ok: false, reason: 'http-401', expiresAt: null});
  assert.deepEqual(attempts, {'u-1': 1, 'u-2': 1});
  assert.deepEqual(api.hits, {'POST /api/auth/login': 2});
  assert.equal(result.scope.identities.outsider.env, 'OTHER_TOKEN');
  assert.deepEqual(Object.keys(result.env), ['BX_SESSION_OWNER']);
  assert.deepEqual(records(ledger).map(record => [record.step, record.identity, record.refused?.match ?? record.response?.status]), [
    ['refused', 'owner', 'oauth'], ['identity', 'owner', 200], ['refused', 'outsider', 'oauth'], ['identity', 'outsider', 401],
  ]);
  assertNoSecrets(ledgerText(ledger), 'the ledger', [...SECRETS, wrong]);
});

test('establishIdentities without tokens or credentials is anonymous-only; half a credential is a failed login', async t => {
  const api = await startApi(t, {'POST /api/auth/login': jsonLogin({})});
  const scope = scopeFor(api.origin);
  const ledger = ledgerFor(t);
  const none = await establishIdentities(scope, {mined: MINED, env: {}, ledger, allowLocal: true});
  const unused = {mode: 'none', ok: false, reason: 'no-credentials', expiresAt: null};
  assert.deepEqual(none.identities, {owner: unused, outsider: unused});
  assert.equal(none.anonymousOnly, true);
  assert.deepEqual(none.env, {});
  assert.deepEqual(await none.refresh(), none.identities);
  const half = await establishIdentities(scope, {mined: MINED, env: {OWNER_USER: ALICE.username}, ledger, allowLocal: true});
  assert.deepEqual(half.identities, {owner: {mode: 'login', ok: false, reason: 'credentials-incomplete', expiresAt: null}, outsider: unused});
  assert.equal(half.anonymousOnly, false);
  const nowhere = await establishIdentities(scope, {mined: {endpoints: []}, env: CREDENTIAL_ENV, ledger, allowLocal: true});
  assert.equal(nowhere.identities.owner.reason, 'not-found');
  assert.deepEqual(api.hits, {});
  assert.equal(ledger.count(), 0);
});

test('a pinned form login yields cookie placement; a login that cannot share the configured placement is not used', async t => {
  const attempts = {};
  const api = await startApi(t, {'POST /members/enter': formLogin(attempts), 'POST /api/auth/login': jsonLogin(attempts), 'GET /api/me': me});
  const scope = scopeFor(api.origin, draft => {
    draft.identities.login = {path: '/members/enter', usernameField: 'username', passwordField: 'password', encoding: 'form'};
    draft.identities.owner.login = {usernameEnv: 'ALICE_LOGIN', passwordEnv: 'ALICE_SECRET'};
  });
  const ledger = ledgerFor(t);
  const env = {ALICE_LOGIN: ALICE.username, ALICE_SECRET: ALICE.password, OTHER_USER: BOB.username, OTHER_PASS: BOB.password};
  const cookies = await establishIdentities(scope, {mined: MINED, env, ledger, allowLocal: true});
  assert.deepEqual(attempts, {'u-1': 1, 'u-2': 1});
  assert.deepEqual(api.hits, {'POST /members/enter': 2});
  assert.equal(cookies.scope.identities.auth, 'cookie');
  assert.ok(credentialHeaders(cookies.scope, 'owner', cookies.env).cookie === `sid=${ALICE.token}`, 'the owner session travels as its cookie');
  const request = createRequester(cookies.scope, {ledger, env: cookies.env, limiter: createLimiter(500), allowLocal: true});
  assert.equal(JSON.parse((await request({url: '/api/me', identity: 'outsider', step: 'identity'})).body).id, BOB.id);

  const mixed = await establishIdentities(scope, {mined: MINED, env: {OWNER_TOKEN: ALICE.token, OTHER_USER: BOB.username, OTHER_PASS: BOB.password},
    ledger, allowLocal: true});
  assert.deepEqual(mixed.identities.owner, {mode: 'token', ok: true, reason: null, expiresAt: null});
  assert.deepEqual(mixed.identities.outsider, {mode: 'login', ok: false, reason: 'placement-mismatch', expiresAt: null});
  assert.equal(mixed.scope.identities.auth, 'bearer');
  assert.equal(mixed.scope.identities.outsider.env, 'OTHER_TOKEN');
  assert.deepEqual(Object.keys(mixed.env), ['OWNER_TOKEN']);
  assert.deepEqual(attempts, {'u-1': 1, 'u-2': 2});
  assertNoSecrets(ledgerText(ledger), 'the ledger');
});

test('refresh logs in again once for sessions whose JWT expires within a minute; a failed re-login is final', async t => {
  const attempts = {};
  const server = {lifetime: 30, reject: false, issued: []};
  const issue = account => {
    const token = jwt({sub: account.id, exp: seconds() + server.lifetime, n: server.issued.length});
    server.issued.push(token);
    return {token};
  };
  const handler = jsonLogin(attempts, issue);
  const api = await startApi(t, {'POST /api/auth/login': (req, raw) => (server.reject ? {status: 401, body: {error: 'locked'}} : handler(req, raw))});
  const ledger = ledgerFor(t);
  const options = {mined: MINED, env: CREDENTIAL_ENV, ledger, allowLocal: true};

  const result = await establishIdentities(scopeFor(api.origin), options);
  assert.deepEqual(attempts, {'u-1': 1, 'u-2': 1});
  assert.ok(result.identities.owner.expiresAt <= Date.now() + 30_000, 'the first session expires within a minute');
  const first = {...result.env};
  server.lifetime = 3600;
  assert.equal(await result.refresh(), result.identities);
  assert.deepEqual(attempts, {'u-1': 2, 'u-2': 2});
  assert.ok(result.env.BX_SESSION_OWNER !== first.BX_SESSION_OWNER && result.env.BX_SESSION_OUTSIDER !== first.BX_SESSION_OUTSIDER, 'fresh tokens replace the old ones');
  assert.ok(result.identities.owner.ok && result.identities.outsider.ok);
  assert.ok(result.identities.owner.expiresAt > Date.now() + 3_000_000, 'the refreshed session carries its new expiry');
  await result.refresh();
  assert.deepEqual(attempts, {'u-1': 2, 'u-2': 2}, 'a session far from expiry is not refreshed');

  server.lifetime = 30;
  const failing = await establishIdentities(scopeFor(api.origin), options);
  server.reject = true;
  await failing.refresh();
  await failing.refresh();
  const failed = {mode: 'login', ok: false, reason: 'http-401', expiresAt: null};
  assert.deepEqual(failing.identities, {owner: failed, outsider: failed});
  assert.deepEqual(failing.env, {});
  assert.equal(api.hits['POST /api/auth/login'], 8);
  assertNoSecrets(ledgerText(ledger), 'the ledger', [...SECRETS, ...server.issued]);
});
