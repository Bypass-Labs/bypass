// Tests for the black-box scope (src/blackbox/scope.mjs) and evidence ledger (src/blackbox/ledger.mjs):
// never/include matching, URL validation, the token bucket, credential placement, the guarded requester
// against a loopback API, and the ledger hash chain with scrubbing and masking (design 4.2, 7.4, 14, 17).
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import http from 'node:http';
import path from 'node:path';
import { hash } from '../src/util.mjs';
import {authorization, scopeReady} from '../src/network.mjs';
import { temp, port } from './helpers.mjs';
import {
  DEFAULT_SCOPE, loadScope, taskAllowance, matchNever, inInclude, validateUrl, createLimiter,
  credentialHeaders, createRequester, jsonShape, ownershipFields,
} from '../src/blackbox/scope.mjs';
import { createLedger, verifyLedger, maskExcerpt, scrub } from '../src/blackbox/ledger.mjs';
import {check as checkProof} from '../src/blackbox/poc-runtime.mjs';

const ORIGIN = 'http://127.0.0.1:4329';
const LOCAL = {acceptLocal: true};
const CREDENTIALS = Object.freeze({OWNER_CRED: 'owner-cred-9f8e7d6c5b4a', OTHER_CRED: 'other-cred-1a2b3c4d5e6f'});
const ITEM_BODY = JSON.stringify({id: 'inv-101', ownerId: 'u-1', email: 'alice@example.com', total: 120});

/** A mutable copy of the defaults with some fields replaced, for the pure functions. */
function scopeWith(changes = {}) {
  return {...structuredClone(DEFAULT_SCOPE), ...changes};
}

function tempDir(t) {
  const dir = temp();
  t.after(() => fs.rmSync(dir, {recursive: true, force: true}));
  return dir;
}

function writeScopeFile(dir, content, name = 'blackbox.scope.json') {
  const file = path.join(dir, name);
  fs.writeFileSync(file, JSON.stringify(content));
  return file;
}

function ledgerLines(ledger) {
  return fs.readFileSync(ledger.file, 'utf8').trim().split('\n');
}

/** Loopback API for the requester tests; counts hits per path. */
async function startApi(t) {
  const listenPort = await port();
  const hits = {};
  const timers = new Set();
  const server = http.createServer((req, res) => {
    const {pathname} = new URL(req.url, 'http://127.0.0.1');
    hits[pathname] = (hits[pathname] ?? 0) + 1;
    const reply = (status, body, headers = {}) => {
      res.writeHead(status, {'content-type': 'application/json; charset=utf-8', ...headers});
      res.end(body);
    };
    const token = (req.headers.authorization ?? '').replace(/^Bearer /, '');
    if (pathname === '/api/items/inv-101') {
      return reply(200, ITEM_BODY, {
        'set-cookie': ['session=cookie-secret-123456; HttpOnly'], 'cache-control': 'no-store', etag: '"v1"', 'x-internal-token': 'header-secret-777',
      });
    }
    if (pathname === '/openapi.json') return reply(200, JSON.stringify({openapi: '3.0.0', paths: {
      '/api/preview': {get: {parameters: [
        {name: 'source.file', in: 'query', example: 'guide.txt'},
        {name: 'auth.token', in: 'query', example: 'shortsecret'}]}}}}));
    if (pathname === '/api/echo') {
      return reply(token ? 200 : 401, JSON.stringify({seen: token, note: `token=${token}`}), {
        location: `/login?token=${token}&next=/home`, 'www-authenticate': `Bearer realm="api", error_description="${token} expired"`,
      });
    }
    if (pathname === '/api/slow') {
      const timer = setTimeout(() => reply(200, '{"late":true}'), 400);
      timers.add(timer);
      res.on('close', () => clearTimeout(timer));
      return undefined;
    }
    if (pathname === '/api/cookie-echo') {
      const cookies = Object.fromEntries((req.headers.cookie ?? '').split('; ').filter(Boolean).map(pair => pair.split('=')));
      return reply(200, JSON.stringify(cookies));
    }
    if (pathname === '/api/auth-login' && req.method === 'POST')
      return reply(200, '{}', {'set-cookie': ['session=bx-cookie-secret-123456; HttpOnly']});
    if (pathname === '/api/flaky') return hits[pathname] === 1 ? reply(503, '{"error":"busy"}') : reply(200, '{"ok":true}');
    if (pathname === '/api/body-echo') {
      const chunks = [];
      req.on('data', chunk => chunks.push(chunk));
      req.on('end', () => reply(200, JSON.stringify({seen: Buffer.concat(chunks).toString()})));
      return undefined;
    }
    if (pathname === '/api/large') return reply(200, JSON.stringify({payload: 'x'.repeat(700 * 1024)}));
    if (pathname === '/api/limited') return reply(429, '{"error":"slow down"}', {'retry-after': '1'});
    return reply(404, '{"error":"not found"}');
  });
  await new Promise(resolve => server.listen(listenPort, '127.0.0.1', resolve));
  t.after(() => new Promise(resolve => {
    for (const timer of timers) clearTimeout(timer);
    server.closeAllConnections();
    server.close(resolve);
  }));
  return {origin: `http://127.0.0.1:${listenPort}`, hits};
}

async function requesterFixture(t, {env = CREDENTIALS, scopeOverrides = {}, log} = {}) {
  const api = await startApi(t);
  const dir = tempDir(t);
  const overrides = {...LOCAL, ownerEnv: 'OWNER_CRED', otherEnv: 'OTHER_CRED', rps: 500, ...scopeOverrides};
  const {scope} = loadScope({origin: api.origin, overrides});
  // The ledger gets no secrets here, so these tests prove the requester scrubs credentials by itself.
  const ledger = createLedger(dir, {run: 'bx-test', redactFields: scope.harvest.redactFields});
  const limiter = createLimiter(500);
  const request = createRequester(scope, {ledger, limiter, env, allowLocal: true, run: 'bx-test', log});
  return {api, scope, ledger, limiter, request};
}

test('DEFAULT_SCOPE is deep-frozen and has no hidden path-word exclusions', () => {
  assert.ok(Object.isFrozen(DEFAULT_SCOPE) && Object.isFrozen(DEFAULT_SCOPE.limits));
  assert.ok(Object.isFrozen(DEFAULT_SCOPE.never) && Object.isFrozen(DEFAULT_SCOPE.identities.owner));
  assert.deepEqual(DEFAULT_SCOPE.never, []);
  assert.deepEqual(DEFAULT_SCOPE.probes, {
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
    expandKeys: ['include', 'expand', 'fields'], expandValues: ['email', 'user', 'owner', 'private', 'all', '*'],
    identityFilters: ['userId', 'user_id', 'uid', 'owner', 'ownerId', 'owner_uid', 'account', 'accountId', 'tenant', 'tenantId', 'email'],
  });
  assert.deepEqual(DEFAULT_SCOPE.methods, ['GET', 'HEAD', 'POST', 'PATCH', 'DELETE']);
  assert.deepEqual(DEFAULT_SCOPE.include, ['/']);
  assert.equal(DEFAULT_SCOPE.limits.modelCalls, 120);
  assert.equal(DEFAULT_SCOPE.limits.maxUrls, 400);
  assert.equal(DEFAULT_SCOPE.limits.domScriptBytes, 2097152);
  assert.equal(DEFAULT_SCOPE.limits.tasks, 0);
});

test('task count is unlimited by default and can be capped or reopened per run', t => {
  const file = writeScopeFile(tempDir(t), {limits: {tasks: 400}});
  assert.equal(loadScope({file, origin: ORIGIN}).scope.limits.tasks, 400);
  assert.equal(loadScope({file, origin: ORIGIN,
    overrides: {maxTasks: 0}}).scope.limits.tasks, 0);
  assert.equal(loadScope({file, origin: ORIGIN,
    overrides: {maxTasks: 900}}).scope.limits.tasks, 900);
  assert.equal(taskAllowance(loadScope({file, origin: ORIGIN,
    overrides: {maxTasks: 0}}).scope), Number.MAX_SAFE_INTEGER);
  assert.throws(() => loadScope({file, origin: ORIGIN,
    overrides: {maxTasks: -1}}), /max-tasks/);
});

test('loadScope requires a reviewed file or --accept-local on loopback and builds the local scope with its hash', () => {
  assert.throws(() => loadScope({origin: ORIGIN}), {code: 3, message: /accept-local/});
  const {scope, hash: scopeHash} = loadScope({origin: 'http://127.0.0.1:5001/', overrides: LOCAL});
  assert.deepEqual(scope.target, {origin: 'http://127.0.0.1:5001', environment: 'local', acknowledged: 'local-owner'});
  assert.deepEqual(scope.credentialOrigins, ['http://127.0.0.1:5001']);
  assert.deepEqual(scope.include, ['/']);
  assert.equal(scopeHash, hash(JSON.stringify(scope)));
  assert.ok(Object.isFrozen(scope) && Object.isFrozen(scope.limits) && Object.isFrozen(scope.never));
});

test('an explicit model-call run budget can change without widening the reviewed network scope', t => {
  const file = writeScopeFile(tempDir(t), {limits: {rps: 5, modelCalls: 60}});
  const {scope: saved} = loadScope({file, origin: ORIGIN});
  const {scope: raised, hash: raisedHash} = loadScope({file, origin: ORIGIN,
    overrides: {modelCalls: 120}});
  assert.equal(saved.limits.modelCalls, 60);
  assert.equal(raised.limits.modelCalls, 120);
  assert.equal(raised.limits.rps, 5);
  assert.notEqual(raisedHash, hash(JSON.stringify(saved)));
  assert.throws(() => loadScope({file, origin: ORIGIN, overrides: {rps: 6}}),
    /exceeds scope limit/);
  for (const modelCalls of [0, -1, 1.5, 'NaN'])
    assert.throws(() => loadScope({file, origin: ORIGIN, overrides: {modelCalls}}),
      /--model-calls must be a positive whole number/);
});

test('the audit time window can be changed per run without widening network scope', t => {
  const file = writeScopeFile(tempDir(t), {limits: {rps: 5, minutes: 30}});
  const saved = loadScope({file, origin: ORIGIN}).scope;
  const raised = loadScope({file, origin: ORIGIN,
    overrides: {minutes: '60'}}).scope;
  assert.equal(saved.limits.minutes, 30);
  assert.equal(raised.limits.minutes, 60);
  assert.equal(raised.limits.rps, 5);
  assert.deepEqual(raised.include, saved.include);
  for (const minutes of [0, -1, 'NaN'])
    assert.throws(() => loadScope({file, origin: ORIGIN, overrides: {minutes}}),
      /--minutes must be a positive number/);
});

test('authenticated recon URL cap can be raised or removed per run without changing scope', t => {
  const file = writeScopeFile(tempDir(t), {limits: {rps: 5, maxUrls: 200}});
  const saved = loadScope({file, origin: ORIGIN}).scope;
  const raised = loadScope({file, origin: ORIGIN,
    overrides: {maxUrls: '400'}}).scope;
  const uncapped = loadScope({file, origin: ORIGIN,
    overrides: {maxUrls: '0'}}).scope;
  assert.equal(saved.limits.maxUrls, 200);
  assert.equal(raised.limits.maxUrls, 400);
  assert.equal(uncapped.limits.maxUrls, 0);
  assert.equal(uncapped.limits.rps, 5);
  assert.deepEqual(uncapped.include, saved.include);
  for (const maxUrls of [-1, 1.5, 'NaN'])
    assert.throws(() => loadScope({file, origin: ORIGIN, overrides: {maxUrls}}),
      /--max-urls must be a nonnegative whole number/);
});

test('DOM script byte cap can rise to 16 MiB without changing network authorization', t => {
  const file = writeScopeFile(tempDir(t), {limits: {rps: 5, domScriptBytes: 2097152}});
  const raised = loadScope({file, origin: ORIGIN,
    overrides: {domScriptBytes: '16777216'}}).scope;
  assert.equal(raised.limits.domScriptBytes, 16777216);
  assert.equal(raised.limits.rps, 5);
  for (const domScriptBytes of [0, 16777217, 1.5, 'NaN'])
    assert.throws(() => loadScope({file, origin: ORIGIN,
      overrides: {domScriptBytes}}), /--dom-script-bytes/);
});

test('loadScope requires deployed registration and refuses origins with a path', t => {
  assert.throws(() => loadScope({origin: 'https://app.example.com', overrides: LOCAL}), {code: 3});
  const loopbackCredentials = writeScopeFile(tempDir(t), {credentialOrigins: [ORIGIN]});
  assert.throws(() => loadScope({file: loopbackCredentials, origin: 'https://app.example.com', overrides: LOCAL}), {code: 3, message: /target add/});
  assert.throws(() => loadScope({origin: 'http://127.0.0.1:5001/api', overrides: LOCAL}), {code: 2});
  assert.throws(() => loadScope({origin: 'not a url', overrides: LOCAL}), {code: 2});
});

test('deployed scope needs app authorization and separate DNS proof of each apex', t => {
  const origin = 'https://app.example.com';
  const expiry = new Date(Date.now() + 86400000).toISOString();
  const target = {url: origin, environment: 'staging', ownership: {status: 'verified', method: 'dns', expiresAt: expiry},
    authorization: {origin, paths: ['/'], methods: ['GET', 'HEAD'], maxRequestsPerSecond: 2, expiresAt: expiry}};
  const apex = {url: 'https://example.com', ownership: {status: 'verified', method: 'dns', expiresAt: expiry}};
  const file = writeScopeFile(tempDir(t), {target: {origin}, include: ['/api'], domains: ['example.com'],
    credentialOrigins: [origin], limits: {rps: 2}});
  assert.throws(() => loadScope({file, origin, targets: [target]}), {code: 3, message: /Apex example.com/});
  const {scope} = loadScope({file, origin, targets: [target, apex]});
  assert.equal(scope.target.environment, 'staging');
  assert.equal(scope.probes.crlfResponseHeader, true);
  assert.equal(scope.probes.hostHeaderRedirect, true);
  assert.equal(scope.probes.jwtUnsigned, true);
  assert.equal(scope.probes.commandExecution, true);
  assert.equal(scope.probes.pathTraversal, true);
  assert.equal(scope.probes.xmlExternalEntity, true);
  const excludedFile = writeScopeFile(tempDir(t), {target: {origin}, include: ['/api'], limits: {rps: 2},
    probes: {crlfResponseHeader: false, hostHeaderRedirect: false, jwtUnsigned: false,
      commandExecution: false, pathTraversal: false, xmlExternalEntity: false}});
  assert.equal(loadScope({file: excludedFile, origin, targets: [target]}).scope.probes.crlfResponseHeader, false);
  assert.equal(loadScope({file: excludedFile, origin, targets: [target]}).scope.probes.hostHeaderRedirect, false);
  assert.equal(loadScope({file: excludedFile, origin, targets: [target]}).scope.probes.jwtUnsigned, false);
  assert.equal(loadScope({file: excludedFile, origin, targets: [target]}).scope.probes.commandExecution, false);
  assert.equal(loadScope({file: excludedFile, origin, targets: [target]}).scope.probes.pathTraversal, false);
  assert.equal(loadScope({file: excludedFile, origin, targets: [target]}).scope.probes.xmlExternalEntity, false);
  assert.equal(validateUrl(scope, 'https://deep.api.example.com/', {purpose: 'discover'}).ok, true);
  assert.equal(validateUrl(scope, 'https://deep.api.example.com/api/users', {purpose: 'task'}).reason, 'origin');
  assert.equal(validateUrl(scope, 'https://other-example.com/', {purpose: 'discover'}).reason, 'origin');
  assert.equal(validateUrl(scope, 'https://deep.api.example.com/', {purpose: 'discover', identity: 'owner'}).reason, 'origin');
});

test('deployed POST follows the selected methods and authorized path prefix', t => {
  const origin = 'https://app.example.test';
  const expiresAt = new Date(Date.now() + 86400000).toISOString();
  const target = {url: origin, environment: 'staging',
    ownership: {status: 'verified', method: 'dns', expiresAt},
    authorization: {origin, paths: ['/api'], methods: ['GET', 'HEAD', 'POST'],
      maxRequestsPerSecond: 2, expiresAt}};
  const file = writeScopeFile(tempDir(t), {target: {origin}, include: ['/api'],
    probes: {jsonPostPaths: ['/api/evaluate'], formPostPaths: ['/api/form']},
    limits: {rps: 2}});
  assert.throws(() => loadScope({file, origin}), {code: 3, message: /target add/});
  target.authorization.methods = ['GET', 'HEAD'];
  assert.throws(() => loadScope({file, origin, targets: [target]}),
    {code: 2, message: /POST in the target authorization/});
  target.authorization.methods.push('POST');
  const {scope} = loadScope({file, origin, targets: [target]});
  assert.equal(validateUrl(scope, '/api/evaluate',
    {method: 'POST', purpose: 'json-body'}).ok, true);
  assert.equal(validateUrl(scope, '/api/form',
    {method: 'POST', purpose: 'form-body'}).ok, true);
  assert.equal(validateUrl(scope, '/api/evaluate?x=1',
    {method: 'POST', purpose: 'json-body'}).reason, 'method');
  assert.equal(validateUrl(scope, '/api/missing',
    {method: 'POST', purpose: 'json-body'}).ok, true);
  assert.equal(validateUrl(scope, '/api/evaluate',
    {method: 'POST', purpose: 'task'}).ok, true);
  assert.equal(validateUrl(scope, '/outside',
    {method: 'POST', purpose: 'json-body'}).reason, 'include');
  assert.equal(scopeReady(target, '/api/evaluate', 'POST'), true);
  assert.throws(() => scopeReady(target, '/api/evaluate', 'PATCH'), /Method PATCH/);
});

test('active descendant probes need apex authorization and stay inside its path scope', t => {
  const origin = 'https://app.example.com';
  const expiresAt = new Date(Date.now() + 86400000).toISOString();
  const target = {url: origin, environment: 'staging',
    ownership: {status: 'verified', method: 'dns', expiresAt},
    authorization: {origin, paths: ['/api'], methods: ['GET', 'HEAD'], maxRequestsPerSecond: 2, expiresAt}};
  const apex = {url: 'https://example.com', environment: 'staging',
    ownership: {status: 'verified', method: 'dns', expiresAt}};
  const file = writeScopeFile(tempDir(t), {target: {origin}, domains: ['example.com'],
    discovery: {auditDomains: ['example.com']}, include: ['/api'], limits: {rps: 2}});
  assert.throws(() => loadScope({file, origin, targets: [target, apex]}),
    {code: 3, message: /authorization/});
  apex.authorization = {origin: apex.url, paths: ['/api'], methods: ['GET', 'HEAD'],
    maxRequestsPerSecond: 2, expiresAt};
  const {scope} = loadScope({file, origin, targets: [target, apex]});
  assert.equal(validateUrl(scope, 'https://deep.api.example.com/api/search',
    {purpose: 'task', identity: 'anonymous'}).ok, true);
  assert.equal(validateUrl(scope, 'http://deep.api.example.com/api/search',
    {purpose: 'task', identity: 'anonymous'}).ok, true);
  assert.equal(validateUrl(scope, 'https://deep.api.example.com/admin',
    {purpose: 'task', identity: 'anonymous'}).reason, 'include');
  assert.equal(validateUrl(scope, 'https://deep.api.example.com:8443/api/search',
    {purpose: 'task', identity: 'anonymous'}).reason, 'origin');
  assert.equal(validateUrl(scope, 'https://deep.api.example.com/api/search',
    {purpose: 'task', identity: 'owner'}).reason, 'origin');
  assert.equal(validateUrl(scope, 'https://outside.example.net/api/search',
    {purpose: 'task', identity: 'anonymous'}).reason, 'origin');
});

test('every deployed credential origin needs compatible paths and rate before the run', t => {
  const origin = 'https://app.example.com', second = 'https://api.example.com';
  const expiresAt = new Date(Date.now() + 86400000).toISOString();
  const makeTarget = url => ({url, environment: 'staging',
    ownership: {status: 'verified', method: 'dns', expiresAt},
    authorization: {origin: url, paths: ['/api'], methods: ['GET', 'HEAD'],
      maxRequestsPerSecond: 2, expiresAt}});
  const primary = makeTarget(origin), child = makeTarget(second);
  const file = writeScopeFile(tempDir(t), {target: {origin}, credentialOrigins: [origin, second],
    include: ['/api'], limits: {rps: 2}});
  child.authorization.paths = ['/public'];
  assert.throws(() => loadScope({file, origin, targets: [primary, child]}),
    {code: 2, message: /credential origin.*authorization/});
  child.authorization.paths = ['/api'];
  child.authorization.maxRequestsPerSecond = 1;
  assert.throws(() => loadScope({file, origin, targets: [primary, child]}),
    {code: 2, message: /rate.*credential origin/});
  child.authorization.maxRequestsPerSecond = 2;
  const {scope} = loadScope({file, origin, targets: [primary, child]});
  assert.equal(scope.authorizedOrigins[second].authorization.origin, second);
});

test('a deployed login POST needs an exact pinned path in both scope and target authorization', t => {
  const origin = 'https://app.example.com';
  const expiry = new Date(Date.now() + 86400000).toISOString();
  const target = {url: origin, environment: 'staging', ownership: {status: 'verified', method: 'dns', expiresAt: expiry}};
  const auth = authorization(target, {paths: ['/api'], methods: ['GET', 'HEAD'], loginPaths: ['/api/login'],
    maxRequestsPerSecond: 2, expiresAt: expiry});
  assert.deepEqual(auth.loginPaths, ['/api/login']);
  assert.throws(() => authorization(target, {paths: ['/api'], loginPaths: ['/outside/login']}), /loginPaths/);
  target.authorization = auth;
  const file = writeScopeFile(tempDir(t), {target: {origin}, include: ['/api'], limits: {rps: 2},
    identities: {owner: {login: {usernameEnv: 'ALICE_USER', passwordEnv: 'ALICE_PASS'}},
      outsider: {login: {usernameEnv: 'BOB_USER', passwordEnv: 'BOB_PASS'}},
      login: {path: '/api/login'}}});
  const {scope} = loadScope({file, origin, targets: [target]});
  assert.equal(scope.identities.login.path, '/api/login');
  assert.equal(scope.identities.outsider.login.usernameEnv, 'BOB_USER');
  assert.deepEqual(scope.authorizedOrigins[origin].authorization.loginPaths, ['/api/login']);
  assert.equal(validateUrl({...scope, expiresAt: '2020-01-01T00:00:00Z'}, '/api/items').reason, 'scope-expired');
});

test('XML POST uses selected methods and deployed authorization', t => {
  const origin = 'https://app.example.com';
  const expiry = new Date(Date.now() + 86400000).toISOString();
  const target = {url: origin, environment: 'staging',
    ownership: {status: 'verified', method: 'dns', expiresAt: expiry}};
  const route = '/api/xml/import';
  const file = writeScopeFile(tempDir(t), {target: {origin}, include: ['/api'], limits: {rps: 2},
    probes: {xmlExternalEntity: true, xmlPostPaths: [route]}});
  target.authorization = authorization(target, {paths: ['/api'], methods: ['GET', 'HEAD'],
    maxRequestsPerSecond: 2, expiresAt: expiry});
  assert.equal(loadScope({file, origin, targets: [target]}).scope.methods.includes('POST'), true);
  assert.throws(() => scopeReady(target, route, 'POST'), /Method POST/);
  target.authorization = authorization(target, {paths: ['/api'], methods: ['GET', 'HEAD'],
    xmlPostPaths: [route], maxRequestsPerSecond: 2, expiresAt: expiry});
  const {scope} = loadScope({file, origin, targets: [target]});
  assert.equal(validateUrl(scope, route, {purpose: 'xml-body', method: 'POST'}).ok, true);
  assert.equal(validateUrl(scope, route, {purpose: 'task', method: 'POST'}).ok, true);
  assert.equal(validateUrl(scope, '/api/xml/other', {purpose: 'xml-body', method: 'POST'}).reason,
    'target-authorization');
  assert.equal(validateUrl(scope, `${route}?x=1`, {purpose: 'xml-body', method: 'POST'}).reason, 'method');
  assert.equal(validateUrl(scope, '/api/delete', {purpose: 'xml-body', method: 'POST'}).reason,
    'target-authorization');
  assert.equal(scopeReady(target, route, 'POST'), true);
  assert.throws(() => scopeReady(target, '/api/xml/other', 'POST'), /Method POST/);
  assert.throws(() => authorization(target, {paths: ['/api'], xmlPostPaths: ['/outside']}), /xmlPostPaths/);
});

test('JSON POST follows local method scope and path exclusions', t => {
  const file = writeScopeFile(tempDir(t), {target: {origin: ORIGIN},
    probes: {jsonPostPaths: ['/api/evaluate']}});
  const {scope} = loadScope({file, origin: ORIGIN});
  assert.equal(validateUrl(scope, '/api/evaluate', {purpose: 'json-body', method: 'POST'}).ok, true);
  assert.equal(validateUrl(scope, '/api/evaluate?x=1', {purpose: 'json-body', method: 'POST'}).reason, 'method');
  assert.equal(validateUrl(scope, '/api/other', {purpose: 'json-body', method: 'POST'}).ok, true);
  assert.equal(validateUrl(scope, '/api/evaluate', {purpose: 'task', method: 'POST'}).ok, true);
  const verbFile = writeScopeFile(tempDir(t), {target: {origin: ORIGIN},
    probes: {jsonPostPaths: ['/api/execute']}});
  const verbScope = loadScope({file: verbFile, origin: ORIGIN}).scope;
  assert.equal(validateUrl(verbScope, '/api/execute', {purpose: 'json-body', method: 'POST'}).ok, true);
  assert.equal(validateUrl(verbScope, '/api/execute', {purpose: 'task', method: 'GET'}).ok, true);
  const verbExcluded = structuredClone(verbScope);
  verbExcluded.never = ['execute'];
  assert.equal(validateUrl(verbExcluded, '/api/execute',
    {purpose: 'json-body', method: 'POST'}).reason, 'never');
  assert.throws(() => loadScope({file: writeScopeFile(tempDir(t),
    {target: {origin: ORIGIN}, probes: {jsonPostPaths: ['/api/execute']},
      never: ['execute']}), origin: ORIGIN}), /jsonPostPaths/);
  assert.throws(() => loadScope({file: writeScopeFile(tempDir(t),
    {target: {origin: ORIGIN}, probes: {jsonPostPaths: ['/api/execute']},
      never: ['/api/execute']}), origin: ORIGIN}),
  /jsonPostPaths/);
});

test('form POST follows local method scope and path exclusions', t => {
  const file = writeScopeFile(tempDir(t), {target: {origin: ORIGIN},
    probes: {formPostPaths: ['/api/evaluate']}});
  const {scope} = loadScope({file, origin: ORIGIN});
  assert.equal(validateUrl(scope, '/api/evaluate', {purpose: 'form-body', method: 'POST'}).ok, true);
  assert.equal(validateUrl(scope, '/api/evaluate?x=1', {purpose: 'form-body', method: 'POST'}).reason, 'method');
  assert.equal(validateUrl(scope, '/api/other', {purpose: 'form-body', method: 'POST'}).ok, true);
  assert.equal(validateUrl(scope, '/api/evaluate', {purpose: 'task', method: 'POST'}).ok, true);
  const verbExcluded = structuredClone(scope);
  verbExcluded.never = ['evaluate'];
  assert.equal(validateUrl(verbExcluded, '/api/evaluate',
    {purpose: 'form-body', method: 'POST'}).reason, 'never');
  assert.throws(() => loadScope({file: writeScopeFile(tempDir(t),
    {target: {origin: ORIGIN}, probes: {formPostPaths: ['/api/evaluate']},
      never: ['/api/evaluate']}), origin: ORIGIN}), /formPostPaths/);
});

test('guarded requester preserves distinct form encodings on the reviewed POST route', async t => {
  const api = await startApi(t);
  const dir = tempDir(t);
  const file = writeScopeFile(dir, {target: {origin: api.origin},
    probes: {formPostPaths: ['/api/form']}});
  const {scope} = loadScope({file, origin: api.origin});
  const ledger = createLedger(dir, {run: 'bx-form-test', redactFields: scope.harvest.redactFields});
  const request = createRequester(scope, {ledger, limiter: createLimiter(500), env: {}, allowLocal: true});
  const base = {url: '/api/form', method: 'POST', purpose: 'form-body', step: 'task', noCache: true,
    headers: {'content-type': 'application/x-www-form-urlencoded'}};
  const response = await request({...base, body: new URLSearchParams({name: 'hello world'}).toString()});
  assert.equal(response.status, 404);
  assert.equal(api.hits['/api/form'], 1);
  const named = await request({...base, body: 'token=secret'});
  assert.equal(named.status, 404);
  for (const body of ['name=a&name=b', 'name=%61', 'name=']) {
    const varied = await request({...base, body});
    assert.equal(varied.status, 404);
  }
  assert.equal(api.hits['/api/form'], 5);
  assert.ok(!fs.readFileSync(ledger.file, 'utf8').includes('secret'));
});

test('an authorized POST can test new fields and values without an exact contract veto', async t => {
  const api = await startApi(t);
  const dir = tempDir(t);
  const file = writeScopeFile(dir, {target: {origin: api.origin},
    probes: {jsonPostPaths: ['/api/auto']}});
  const scope = structuredClone(loadScope({file, origin: api.origin}).scope);
  scope.localAutoPostContracts = {'json /api/auto': {
    contentType: 'application/json', fields: ['q']}};
  const ledger = createLedger(dir, {run: 'bx-auto-post-refusal'});
  const request = createRequester(scope, {ledger, allowLocal: true});
  const base = {url: '/api/auto', method: 'POST', purpose: 'json-body',
    step: 'task', noCache: true, headers: {'content-type': 'application/json'}};
  const extended = await request({...base, body: JSON.stringify({q: 'plain', unseen: 'safe'})});
  assert.equal(extended.status, 404);
  const external = await request({...base, body: JSON.stringify({q: 'https://other.example.com/'})});
  assert.equal(external.status, 404);
  const canaryEmail = await request({...base, body: JSON.stringify({q: 'probe@example.com'})});
  assert.equal(canaryEmail.status, 404);
  const realEmail = await request({...base, body: JSON.stringify({q: 'probe@external.example'})});
  assert.equal(realEmail.status, 404);
  const lookalikeEmail = await request({...base, body: JSON.stringify({q: 'probe@example.com.evil'})});
  assert.equal(lookalikeEmail.status, 404);
  const allowed = await request({...base, body: JSON.stringify({q: 'plain'})});
  assert.equal(allowed.status, 404);
  assert.equal(api.hits['/api/auto'], 6);
  assert.deepEqual(ledgerLines(ledger).map(line => {
    const entry = JSON.parse(line);
    return entry.refused?.rule ?? entry.response?.status;
  }), [404, 404, 404, 404, 404, 404]);
  const records = ledgerLines(ledger).map(JSON.parse);
  assert.ok(!JSON.stringify(records).includes('other.example.com'));
});

test('authorized POST can carry operator supplied destination values', async t => {
  const api = await startApi(t);
  const dir = tempDir(t);
  const file = writeScopeFile(dir, {target: {origin: api.origin},
    probes: {jsonPostPaths: ['/api/auto']}});
  const scope = structuredClone(loadScope({file, origin: api.origin}).scope);
  scope.localAutoPostContracts = {'json /api/auto': {
    contentType: 'application/json', fields: ['q']}};
  const ledger = createLedger(dir, {run: 'bx-owned-callback'});
  const request = createRequester(scope, {ledger, allowLocal: true});
  const base = {url: '/api/auto', method: 'POST', purpose: 'json-body',
    step: 'task', noCache: true, headers: {'content-type': 'application/json'}};
  const callback = `http://127.0.0.1:34567/bx-ssrf/${'a'.repeat(24)}`;
  const allowed = await request({...base, body: JSON.stringify({q: callback}),
    auditCallback: callback});
  assert.equal(allowed.status, 404);
  const unrelated = await request({...base,
    body: JSON.stringify({q: 'https://unrelated.example/'}),
    auditCallback: callback});
  assert.equal(unrelated.status, 404);
  const forged = await request({...base,
    body: JSON.stringify({q: 'http://127.0.0.1:34567/other'}),
    auditCallback: 'http://127.0.0.1:34567/other'});
  assert.equal(forged.status, 404);
  assert.equal(api.hits['/api/auto'], 3);
});

test('an observed login accepts an email username without treating it as an outbound destination', async t => {
  const api = await startApi(t);
  const dir = tempDir(t);
  const file = writeScopeFile(dir, {target: {origin: api.origin},
    probes: {jsonPostPaths: ['/api/login']}});
  const scope = structuredClone(loadScope({file, origin: api.origin}).scope);
  scope.localAuthPostContracts = {'/api/login': {
    fields: ['email', 'password'], usernameField: 'email', passwordField: 'password'}};
  const ledger = createLedger(dir, {run: 'bx-auth-email'});
  const request = createRequester(scope, {ledger, allowLocal: true});
  const result = await request({url: '/api/login', method: 'POST', purpose: 'auth-body',
    step: 'task', noCache: true, omitExcerpt: true, rawForAuthProof: true,
    headers: {'content-type': 'application/json'},
    body: JSON.stringify({email: 'owner@actual.example', password: 'wrong-pass-123'})});
  assert.equal(result.status, 404);
  assert.equal(api.hits['/api/login'], 1);
});

test('authorized local JSON retains credential redaction while accepting new values', async t => {
  const api = await startApi(t);
  const dir = tempDir(t);
  const file = writeScopeFile(dir, {target: {origin: api.origin},
    probes: {jsonPostPaths: ['/api/body-echo']},
    identities: {owner: {login: {usernameEnv: 'OWNER_USER', passwordEnv: 'OWNER_PASS'}}}});
  const scope = structuredClone(loadScope({file, origin: api.origin}).scope);
  scope.localAutoPostContracts = {'json /api/body-echo': {
    contentType: 'application/json', fields: ['email']}};
  const ledger = createLedger(dir, {run: 'bx-configured-email'});
  const request = createRequester(scope, {ledger, allowLocal: true,
    env: {OWNER_USER: 'owner@real.example', OWNER_PASS: 'test-password'}});
  const base = {url: '/api/body-echo', method: 'POST', purpose: 'json-body',
    step: 'task', noCache: true, headers: {'content-type': 'application/json'}};
  const allowed = await request({...base, body: JSON.stringify({email: 'owner@real.example'})});
  assert.equal(allowed.status, 200);
  assert.equal(api.hits['/api/body-echo'], 1);
  assert.ok(!JSON.stringify(allowed).includes('owner@real.example'));
  assert.ok(!fs.readFileSync(ledger.file, 'utf8').includes('owner@real.example'));
  const other = await request({...base, body: JSON.stringify({email: 'other@real.example'})});
  assert.equal(other.status, 200);
  assert.equal(api.hits['/api/body-echo'], 2);
});

test('derived bearer reaches authorized POST paths and is absent from evidence', async t => {
  const api = await startApi(t);
  const dir = tempDir(t);
  const file = writeScopeFile(dir, {target: {origin: api.origin},
    probes: {jsonPostPaths: ['/api/json'], formPostPaths: ['/api/form'],
      xmlExternalEntity: true, xmlPostPaths: ['/api/xml']}});
  const {scope} = loadScope({file, origin: api.origin});
  const ledger = createLedger(dir, {run: 'bx-derived-post-test', redactFields: scope.harvest.redactFields});
  const request = createRequester(scope, {ledger, limiter: createLimiter(500), allowLocal: true});
  const bearer = 'bx-derived-session-token-123456';
  for (const [url, purpose, contentType, body] of [
    ['/api/json', 'json-body', 'application/json', '{"name":"sample"}'],
    ['/api/form', 'form-body', 'application/x-www-form-urlencoded', 'name=sample'],
    ['/api/xml', 'xml-body', 'application/xml', '<root>sample</root>'],
  ]) {
    const result = await request({url, identity: 'anonymous', method: 'POST', purpose,
      step: 'task', noCache: true, omitExcerpt: true,
      headers: {'content-type': contentType}, body, derivedBearer: bearer});
    assert.equal(result.status, 404);
    assert.equal(api.hits[url], 1);
  }
  const other = await request({url: '/api/other', identity: 'anonymous', method: 'POST',
    purpose: 'json-body', step: 'task', noCache: true, omitExcerpt: true,
    headers: {'content-type': 'application/json'}, body: '{"name":"sample"}',
    derivedBearer: bearer});
  assert.equal(other.status, 404);
  assert.equal(api.hits['/api/other'], 1);
  assert.equal(fs.readFileSync(ledger.file, 'utf8').includes(bearer), false);
});

test('guarded cookie handoff keeps Set-Cookie transient and redacts derived reads', async t => {
  const api = await startApi(t);
  const dir = tempDir(t);
  const {scope: loaded} = loadScope({origin: api.origin,
    overrides: {acceptLocal: true, rps: 500}});
  const scope = structuredClone(loaded);
  scope.localAuthPostContracts = {'/api/auth-login': {fields: ['user', 'password'],
    usernameField: 'user', passwordField: 'password'}};
  const ledger = createLedger(dir, {run: 'bx-derived-cookie-test',
    redactFields: scope.harvest.redactFields});
  const request = createRequester(scope, {ledger, limiter: createLimiter(500),
    allowLocal: true});
  const login = await request({url: '/api/auth-login', identity: 'anonymous',
    method: 'POST', purpose: 'auth-body', step: 'control', noCache: true,
    omitExcerpt: true, rawForAuthProof: true,
    headers: {'content-type': 'application/json'},
    body: JSON.stringify({user: 'bx-test', password: 'bx-invalid-123456'})});
  assert.equal(login.status, 200);
  assert.deepEqual(login.headers, {});
  assert.deepEqual(login.rawSetCookie, ['session=bx-cookie-secret-123456; HttpOnly']);
  const cookie = 'session=bx-cookie-secret-123456';
  const read = await request({url: '/api/cookie-echo', identity: 'anonymous',
    method: 'GET', purpose: 'task', step: 'task', noCache: true,
    derivedCookie: cookie});
  assert.equal(read.status, 200);
  assert.equal(read.hash, `sha256:${hash(JSON.stringify({session: 'bx-cookie-secret-123456'}))}`);
  assert.ok(!JSON.stringify(read).includes('bx-cookie-secret-123456'));
  assert.ok(!fs.readFileSync(ledger.file, 'utf8').includes('bx-cookie-secret-123456'));
  assert.equal(api.hits['/api/auth-login'], 1);
});

test('loadScope: a flag may lower a limit the scope file sets, never raise it', t => {
  const dir = tempDir(t);
  const file = writeScopeFile(dir, {schemaVersion: 1, limits: {rps: 20, agents: 10}});
  const lowered = loadScope({file, origin: ORIGIN, overrides: {...LOCAL, rps: '5', agents: 4, waves: 1}}).scope;
  assert.deepEqual([lowered.limits.rps, lowered.limits.agents, lowered.limits.waves], [5, 4, 1]);
  assert.throws(() => loadScope({file, origin: ORIGIN, overrides: {...LOCAL, rps: 50}}), {code: 2, message: /exceeds scope/});
  assert.throws(() => loadScope({file, origin: ORIGIN, overrides: {...LOCAL, agents: 11}}), {code: 2, message: /exceeds scope/});
  // The built-in defaults are not a ceiling the operator wrote: the end-to-end run passes --rps 200.
  assert.equal(loadScope({origin: ORIGIN, overrides: {...LOCAL, rps: 200}}).scope.limits.rps, 200);
  assert.throws(() => loadScope({origin: ORIGIN, overrides: {...LOCAL, agents: 101}}), {code: 2});
  assert.throws(() => loadScope({origin: ORIGIN, overrides: {...LOCAL, waves: 3}}), {code: 2});
  assert.throws(() => loadScope({origin: ORIGIN, overrides: {...LOCAL, rps: 0}}), {code: 2});
});

test('loadScope: Muse agents and HTTP workers are separate execution limits', t => {
  const dir = tempDir(t);
  const file = writeScopeFile(dir, {schemaVersion: 1,
    limits: {agents: 10, modelConcurrency: 2}});
  const {scope} = loadScope({file, origin: ORIGIN, overrides: {...LOCAL,
    modelAgents: 12, httpWorkers: 4}});
  assert.equal(scope.limits.modelConcurrency, 12);
  assert.equal(scope.limits.agents, 4);
  assert.throws(() => loadScope({file, origin: ORIGIN,
    overrides: {...LOCAL, httpWorkers: 11}}), {code: 2, message: /exceeds scope/});
  assert.throws(() => loadScope({file, origin: ORIGIN,
    overrides: {...LOCAL, modelAgents: 101}}), {code: 2});
});

test('loadScope: identityPath and seeds.lists sit inside include; identities are distinct env var names', t => {
  const dir = tempDir(t);
  const file = writeScopeFile(dir, {include: ['/api'], seeds: {lists: ['/api/invoices']}});
  const overrides = {...LOCAL, identityPath: '/api/me', ownerEnv: 'ALICE_TOKEN', otherEnv: 'BOB_TOKEN', auth: 'header:X-Api-Key'};
  const {scope} = loadScope({file, origin: ORIGIN, overrides});
  assert.deepEqual(scope.identities, {owner: {env: 'ALICE_TOKEN', role: 'member', login: null},
    outsider: {env: 'BOB_TOKEN', role: 'member', login: null},
    auth: 'header:X-Api-Key', identityPath: '/api/me', identityCookieName: null, login: null});
  assert.throws(() => loadScope({file, origin: ORIGIN, overrides: {...LOCAL, identityPath: '/me'}}), {code: 2});
  const outside = writeScopeFile(dir, {include: ['/api'], seeds: {lists: ['/v1/invoices']}}, 'outside.json');
  assert.throws(() => loadScope({file: outside, origin: ORIGIN, overrides: LOCAL}), {code: 2});
  assert.throws(() => loadScope({origin: ORIGIN, overrides: {...LOCAL, ownerEnv: 'owner-token'}}), {code: 2});
  assert.throws(() => loadScope({origin: ORIGIN, overrides: {...LOCAL, otherEnv: 'OWNER_TOKEN'}}), {code: 2});
  assert.throws(() => loadScope({origin: ORIGIN, overrides: {...LOCAL, auth: 'basic'}}), {code: 2});
});

test('identity cookie placement is limited to one exact bearer identity route', t => {
  const dir = tempDir(t);
  const file = writeScopeFile(dir, {include: ['/api'], identities: {
    identityPath: '/api/me', identityCookieName: 'token'}});
  const {scope} = loadScope({file, origin: ORIGIN, overrides: LOCAL});
  const env = {OWNER_TOKEN: 'owner-token'};
  assert.deepEqual(credentialHeaders(scope, 'owner', env, `${ORIGIN}/api/me`),
    {cookie: 'token=owner-token'});
  assert.deepEqual(credentialHeaders(scope, 'owner', env, `${ORIGIN}/api/items`),
    {authorization: 'Bearer owner-token'});
  const noPath = writeScopeFile(dir, {identities: {identityCookieName: 'token'}}, 'no-path.json');
  assert.throws(() => loadScope({file: noPath, origin: ORIGIN, overrides: LOCAL}), /identityCookieName/);
  const wrongAuth = writeScopeFile(dir, {identities: {
    auth: 'cookie', identityPath: '/api/me', identityCookieName: 'token'}}, 'wrong-auth.json');
  assert.throws(() => loadScope({file: wrongAuth, origin: ORIGIN, overrides: LOCAL}), /identityCookieName/);
  const badName = writeScopeFile(dir, {identities: {
    identityPath: '/api/me', identityCookieName: 'token;admin'}}, 'bad-name.json');
  assert.throws(() => loadScope({file: badName, origin: ORIGIN, overrides: LOCAL}), /identityCookieName/);
});

test('scope accepts bounded DNS word seeds and rejects wildcard, nested or malformed names', t => {
  const dir = tempDir(t);
  const good = writeScopeFile(dir, {seeds: {dnsWords: ['blue', 'api-dev']}}, 'dns-good.json');
  assert.deepEqual(loadScope({file: good, origin: ORIGIN, overrides: LOCAL}).scope.seeds.dnsWords,
    ['blue', 'api-dev']);
  for (const [index, words] of [['*.example'], ['two.labels'], ['UPPER'], [''],
    Array.from({length: 2001}, () => 'api'), 'custom'].entries()) {
    const file = writeScopeFile(dir, {seeds: {dnsWords: words}}, `dns-bad-${index}.json`);
    assert.throws(() => loadScope({file, origin: ORIGIN, overrides: LOCAL}), /seeds\.dnsWords/);
  }
});

test('loadScope: file fields are type-checked, unknown fields refused, omitted never is empty', t => {
  const dir = tempDir(t);
  const load = (content, name) => loadScope({file: writeScopeFile(dir, content, name), origin: ORIGIN, overrides: LOCAL});
  assert.throws(() => load({nevr: ['x']}, 'typo.json'), {code: 2, message: /nevr/});
  assert.throws(() => load({limits: {rps: 'fast'}}, 'type.json'), {code: 2, message: /limits\.rps/});
  assert.deepEqual(load({methods: ['GET', 'POST']}, 'post.json').scope.methods,
    ['GET', 'POST']);
  assert.throws(() => load({methods: ['GET', 'post']}, 'invalid-method.json'), {code: 2});
  assert.throws(() => load({discovery: {external: {osv: 'yes'}}}, 'osv-string.json'),
    /discovery\.external\.osv.*boolean/);
  assert.throws(() => load({target: {origin: 'http://127.0.0.1:9999'}}, 'other.json'), {code: 2});
  assert.throws(() => load({expiresAt: '2020-01-01T00:00:00Z'}, 'expired.json'), {code: 3});
  assert.throws(() => load({credentialOrigins: ['https://api.example.com']}, 'remote.json'), {code: 3});
  assert.throws(() => loadScope({file: path.join(dir, 'missing.json'), origin: ORIGIN, overrides: LOCAL}), {code: 2});
  fs.writeFileSync(path.join(dir, 'broken.json'), '{"never": [');
  assert.throws(() => loadScope({file: path.join(dir, 'broken.json'), origin: ORIGIN, overrides: LOCAL}), {code: 2});
  assert.deepEqual(load({methods: ['GET']}, 'default.json').scope.never, []);
  const {scope} = load({never: ['export'], methods: ['GET'], harvest: {redactFields: ['ssn']}, seeds: {words: ['ledger']}}, 'ok.json');
  assert.deepEqual(scope.never, ['export']);
  assert.deepEqual(scope.methods, ['GET']);
  assert.deepEqual(scope.harvest.redactFields, ['email', 'phone', 'ssn']);
  assert.deepEqual(scope.seeds.words, ['ledger']);
});

test('an explicit never list confines methods, origins, and paths', t => {
  const file = writeScopeFile(tempDir(t), {target: {origin: ORIGIN},
    include: ['/api'], methods: ['GET', 'HEAD'], never: ['/api/delete/*', 'logout']});
  const {scope} = loadScope({file, origin: ORIGIN});
  assert.deepEqual(scope.never, ['/api/delete/*', 'logout']);
  assert.equal(validateUrl(scope, '/api/verify/status', {method: 'GET'}).ok, true);
  assert.equal(validateUrl(scope, '/api/delete/record', {method: 'GET'}).reason, 'never');
  assert.equal(validateUrl(scope, '/api/logout', {method: 'GET'}).reason, 'never');
  assert.equal(validateUrl(scope, '/api/verify/status', {method: 'POST'}).reason, 'method');
  assert.equal(validateUrl(scope, '/outside/verify', {method: 'GET'}).reason, 'include');
  assert.equal(validateUrl(scope, 'http://127.0.0.1:4330/api/verify/status',
    {method: 'GET'}).reason, 'origin');
});

test('loadScope: include and domain overrides may only narrow the scope file', t => {
  const dir = tempDir(t);
  const file = writeScopeFile(dir, {include: ['/api'], domains: ['example.test']});
  const fixture = {...LOCAL, testResolver: true};
  assert.deepEqual(loadScope({file, origin: ORIGIN, overrides: {...fixture, includes: '/api/v1,/api/v2'}}).scope.include, ['/api/v1', '/api/v2']);
  assert.throws(() => loadScope({file, origin: ORIGIN, overrides: {...fixture, includes: ['/admin']}}), {code: 2, message: /exceeds scope/});
  assert.throws(() => loadScope({file, origin: ORIGIN, overrides: {...fixture, domains: 'other.test'}}), {code: 2, message: /exceeds scope/});
  assert.throws(() => loadScope({origin: ORIGIN, overrides: {...LOCAL, includes: ['/api/*']}}), {code: 2});
});

test('matchNever: verbs match delete, delete-all, deleteUser, delete_user; not charges, presets, exports, sender, runs', () => {
  const scope = scopeWith({never: ['delete']});
  for (const pathname of ['/api/users/u-1/delete', '/api/delete-all', '/api/deleteUser', '/api/delete_user', '/API/Delete']) {
    assert.deepEqual(matchNever(scope, pathname, ''), {refused: true, rule: 'never', match: 'delete'}, pathname);
  }
  // Even with charge, export, run and preset added as verbs, the next-letter rule keeps the plural nouns readable.
  const stricter = scopeWith({never: ['delete', 'charge', 'export', 'run', 'preset']});
  for (const pathname of ['/api/charges', '/api/presets', '/api/exports', '/api/sender', '/api/runs']) {
    assert.deepEqual(matchNever(stricter, pathname, ''), {refused: false}, pathname);
    assert.deepEqual(matchNever(scope, pathname, ''), {refused: false}, pathname);
  }
});

test('matchNever: path globs span slashes; query keys and values are matched decoded', () => {
  const scope = scopeWith({never: ['/api/billing/*', 'logout', 'delete', 'reset']});
  assert.deepEqual(matchNever(scope, '/api/billing/invoices', ''), {refused: true, rule: 'never', match: '/api/billing/*'});
  assert.equal(matchNever(scope, '/api/billing/a/b/c', '').match, '/api/billing/*');
  assert.equal(matchNever(scope, '/API/Billing/x', '').match, '/api/billing/*');
  assert.equal(matchNever(scope, '/api/billingx/a', '').refused, false);
  assert.equal(matchNever(scope, '/api/bill', '').refused, false);
  assert.equal(matchNever(scope, '/api/auth/logout', '').match, 'logout');
  assert.equal(matchNever(scope, '/api/items', '?action=delete').match, 'delete');
  assert.equal(matchNever(scope, '/api/items', '?op=%64elete').match, 'delete');
  assert.equal(matchNever(scope, '/api/items', 'Reset=1').match, 'reset');
  assert.deepEqual(matchNever(scope, '/api/items', '?sender=me&page=2'), {refused: false});
});

test('inInclude: prefixes match whole segments and are case-sensitive', () => {
  const scope = scopeWith({include: ['/api', '/v1/']});
  assert.ok(inInclude(scope, '/api'));
  assert.ok(inInclude(scope, '/api/invoices/inv-1'));
  assert.ok(inInclude(scope, '/v1/x'));
  assert.ok(!inInclude(scope, '/apiv2/x'));
  assert.ok(!inInclude(scope, '/API/invoices'));
  assert.ok(!inInclude(scope, '/'));
  assert.ok(inInclude(scopeWith({include: ['/']}), '/anything/at/all'));
});

test('validateUrl accepts in-scope reads and returns the normalized absolute URL', () => {
  const scope = scopeWith({include: ['/api']});
  assert.deepEqual(validateUrl(scope, '/api/invoices/inv-101?page=2', {identity: 'outsider'}), {ok: true, url: `${ORIGIN}/api/invoices/inv-101?page=2`});
  assert.deepEqual(validateUrl(scope, `${ORIGIN}/api/me`, {identity: 'owner', method: 'HEAD'}), {ok: true, url: `${ORIGIN}/api/me`});
  assert.equal(validateUrl(scope, '/api/x?a=1&b=2&c=3&d=4&e=5&f=6&g=7&h=8').ok, true);
});

test('read-only action names stay in scope while clearly mutating GET actions need exact review', () => {
  const scope = scopeWith();
  for (const path of ['/api/reset-password', '/api/verify-email', '/api/oauth/callback',
    '/api/webhook/events', '/api/execute-preview', '/api/billing/invoices', '/api/billing/charges']) {
    assert.equal(validateUrl(scope, path).ok, true, path);
  }
  for (const path of ['/api/account/logout', '/api/orders/checkout', '/api/items/delete',
    '/api/items?action=delete', '/api/delete/42', '/api/checkout/abc',
    '/api/billing/charge', '/api/charge/42']) {
    assert.equal(validateUrl(scope, path).reason, 'read-action-review', path);
  }
  const reviewed = scopeWith({discover: [...DEFAULT_SCOPE.discover, '/api/account/logout']});
  assert.equal(validateUrl(reviewed, '/api/account/logout').ok, true);
  const queryReviewed = scopeWith({discover: [...DEFAULT_SCOPE.discover, '/api/items?action=delete']});
  assert.equal(validateUrl(queryReviewed, '/api/items?action=delete').ok, true);
  const reviewedDiscovery = scopeWith({include: ['/api'],
    discover: [...DEFAULT_SCOPE.discover, '/outside?action=delete']});
  assert.equal(validateUrl(reviewedDiscovery, '/outside?action=delete',
    {purpose: 'discover'}).ok, true);
  assert.equal(validateUrl(scopeWith({discover: [...DEFAULT_SCOPE.discover, '/api/items']}),
    '/api/items?action=delete').reason, 'read-action-review');
  const explicitlyExcluded = scopeWith({never: ['/api/account/logout'],
    discover: [...DEFAULT_SCOPE.discover, '/api/account/logout']});
  assert.equal(validateUrl(explicitlyExcluded, '/api/account/logout').reason, 'never');
  assert.equal(validateUrl(scope, '/api/account/logout', {method: 'POST'}).ok, true);
});

test('validateUrl refuses every documented reason', () => {
  const scope = scopeWith({include: ['/api'], never: ['delete']});
  const reason = (url, options = {}) => validateUrl(scope, url, {identity: 'outsider', ...options}).reason;
  const offOrigin = ['http://127.0.0.1:4330/api/x', 'https://127.0.0.1:4329/api/x', 'http://localhost:4329/api/x', '//evil.example/api/x',
    'http://user:pw@127.0.0.1:4329/api/x', '/api/x#top', 'http://[::1', '', undefined];
  for (const url of offOrigin) assert.equal(reason(url), 'origin', url);
  for (const method of ['PUT', 'OPTIONS', 'get']) assert.equal(reason('/api/x', {method}), 'method', method);
  for (const method of ['POST', 'PATCH', 'DELETE']) assert.equal(reason('/api/x', {method}), undefined, method);
  for (const url of ['/api/inv%2D1', '/api/%2e%2e/admin', '/api/%252e', '/api/{id}', '/api/a b']) assert.equal(reason(url), 'percent', url);
  const traversal = ['/api/..;/admin', '/api/../admin', '/api/./x', '/api/x;jsessionid=1', '/api\\..\\admin', '/api/.git/config', '/api/x\n/../y'];
  for (const url of traversal) assert.equal(reason(url), 'segment', JSON.stringify(url));
  for (const url of ['/admin/users', '/apiv2/x', '/']) assert.equal(reason(url), 'include', url);
  assert.deepEqual(validateUrl(scope, '/api/invoices/inv-1/delete'), {ok: false, reason: 'never', match: 'delete'});
  assert.equal(reason('/api/x?a=1&b=2&c=3&d=4&e=5&f=6&g=7&h=8&i=9'), 'query-count');
  for (const url of ['/api/x?token=abc', '/api/x?API_KEY=1', '/api/x?Signature=z', '/api/x?to%6Ben=abc', '/api/x?page=1&access_token=a']) {
    assert.equal(reason(url), undefined, url);
  }
  for (const url of ['/api/x?auth.token=abc', '/api/x?auth%252Etoken=abc',
    '/api/x?filter%5Bsecret%5D=abc', '/api/x?sessionId=abc']) {
    assert.equal(reason(url), undefined, url);
  }
  assert.equal(validateUrl(scope, '/api/x?source.file=guide.txt').ok, true);
});

test('standalone proof sends an in-scope credential-named query', async t => {
  const api = await startApi(t);
  for (const url of ['/api/echo?auth.token=value', '/api/echo?auth%252Etoken=value']) {
    await checkProof({kind: 'open-redirect', origin: api.origin,
      include: ['/api'], never: [], request: {url, as: 'anonymous'},
      expectedLocation: 'https://bypass-audit.invalid/one'}, {});
  }
  assert.equal(api.hits['/api/echo'], 2);
});

test('validateUrl never routes credentials to an origin outside credentialOrigins', () => {
  const anonymousOnly = scopeWith({credentialOrigins: []});
  assert.equal(validateUrl(anonymousOnly, '/api/x', {identity: 'owner'}).reason, 'credential-origin');
  assert.equal(validateUrl(anonymousOnly, '/api/x', {identity: 'anonymous'}).ok, true);
  const second = scopeWith({credentialOrigins: ['http://127.0.0.1:4400']});
  assert.equal(validateUrl(second, '/api/x', {identity: 'outsider'}).reason, 'credential-origin');
  assert.equal(validateUrl(second, 'http://127.0.0.1:4400/api/x', {identity: 'outsider'}).ok, true);
});

test('validateUrl: discover documents and same-origin scripts are anonymous-only outside include', () => {
  const scope = scopeWith({include: ['/api']});
  assert.equal(validateUrl(scope, '/openapi.json', {purpose: 'discover', identity: 'anonymous'}).ok, true);
  assert.equal(validateUrl(scope, '/openapi.json', {purpose: 'discover', identity: 'owner'}).reason, 'include');
  assert.equal(validateUrl(scope, '/openapi.json', {purpose: 'task', identity: 'anonymous'}).reason, 'include');
  assert.equal(validateUrl(scope, '/admin', {purpose: 'discover', identity: 'anonymous'}).reason, 'include');
  assert.equal(validateUrl(scope, '/static/app.js', {purpose: 'asset', identity: 'anonymous'}).ok, true);
  assert.equal(validateUrl(scope, '/static/app.js.map', {purpose: 'asset'}).ok, true);
  assert.equal(validateUrl(scope, '/static/app.js', {purpose: 'asset', identity: 'outsider'}).reason, 'include');
  assert.equal(validateUrl(scope, '/static/page.html', {purpose: 'asset'}).reason, 'include');
  const open = scopeWith();
  assert.equal(validateUrl(open, '/.env', {purpose: 'discover', identity: 'anonymous'}).ok, true);
  assert.equal(validateUrl(open, '/.env', {purpose: 'task', identity: 'outsider'}).reason, 'segment');
  assert.equal(validateUrl(open, '/x/../.env', {purpose: 'discover'}).reason, 'segment');
  // The URL parser strips tab, CR and LF, which would turn '.\n.' into a '..' segment after validation.
  assert.equal(validateUrl(open, '/x/.\n./.env', {purpose: 'discover'}).reason, 'segment');
  assert.equal(validateUrl(open, '/static/.\t./app.js', {purpose: 'asset'}).reason, 'segment');
  assert.throws(() => validateUrl(open, '/x', {purpose: 'probe'}), {code: 2});
});

test('validateUrl confines approved asset hosts to anonymous static files on exact hostnames', () => {
  const scope = scopeWith({include: ['/api'], never: ['/api/billing/*'],
    discovery: {...structuredClone(DEFAULT_SCOPE.discovery), assetHosts: ['cdn.example.test']}});
  assert.equal(validateUrl(scope, 'https://cdn.example.test/static/app.js', {purpose: 'asset'}).ok, true);
  assert.equal(validateUrl(scope, 'https://cdn.example.test/static/app.js.map', {purpose: 'asset'}).ok, true);
  assert.equal(validateUrl(scope, 'https://other.example.test/static/app.js', {purpose: 'asset'}).reason, 'origin');
  assert.equal(validateUrl(scope, 'https://cdn.example.test/static/config.json', {purpose: 'asset'}).reason, 'origin');
  assert.equal(validateUrl(scope, 'https://cdn.example.test/static/app.js', {purpose: 'task'}).reason, 'origin');
  assert.equal(validateUrl(scope, 'https://cdn.example.test/static/app.js', {purpose: 'asset', identity: 'owner'}).reason, 'origin');
  assert.equal(validateUrl(scope, 'https://cdn.example.test/static/app.js?token=secret', {purpose: 'asset'}).ok, true);
  assert.equal(validateUrl(scope, 'https://cdn.example.test/api/billing/remove.js', {purpose: 'asset'}).reason, 'never');
});

test('credentialHeaders places the credential by scheme and fails closed when it is missing', () => {
  const env = {OWNER_TOKEN: 'tok-owner-1', OTHER_TOKEN: 'tok-other-2'};
  const scope = scopeWith();
  assert.deepEqual(credentialHeaders(scope, 'owner', env), {authorization: 'Bearer tok-owner-1'});
  assert.deepEqual(credentialHeaders(scope, 'anonymous', env), {});
  const cookie = scopeWith({identities: {...DEFAULT_SCOPE.identities, auth: 'cookie'}});
  assert.deepEqual(credentialHeaders(cookie, 'outsider', env), {cookie: 'tok-other-2'});
  const header = scopeWith({identities: {...DEFAULT_SCOPE.identities, auth: 'header:X-Api-Key'}});
  assert.deepEqual(credentialHeaders(header, 'owner', env), {'X-Api-Key': 'tok-owner-1'});
  assert.throws(() => credentialHeaders(scope, 'outsider', {}),
    error => error.code === 3 && error.details.reason === 'credential_missing' && error.details.env === 'OTHER_TOKEN');
  assert.throws(() => credentialHeaders(scope, 'owner', {OWNER_TOKEN: 'line\nbreak'}),
    error => error.code === 3 && error.details.reason === 'credential_invalid' && !error.message.includes('break'));
  assert.throws(() => credentialHeaders(scope, 'admin', env), {code: 2});
});

test('createLimiter spaces requests: 10 takes at 50 rps take at least 180 ms; halve() halves the rate', async () => {
  const limiter = createLimiter(50);
  const started = performance.now();
  for (let take = 0; take < 10; take += 1) await limiter.take();
  const elapsed = performance.now() - started;
  assert.ok(elapsed >= 180, `10 takes took ${elapsed} ms`);
  assert.equal(limiter.rate(), 50);
  limiter.halve();
  assert.equal(limiter.rate(), 25);
  assert.throws(() => createLimiter(0), {code: 2});
});

test('jsonShape records key types to the requested depth; ownershipFields follows the contract pattern', () => {
  const body = {id: 'a', n: 1, ok: true, none: null, list: [1], user: {profile: {name: 'x'}, uid: 'u'}};
  assert.deepEqual(jsonShape(body), {id: 'string', n: 'number', ok: 'boolean', none: 'null', list: 'array', user: {profile: 'object', uid: 'string'}});
  assert.equal(jsonShape([{id: 1}]), 'array');
  assert.equal(jsonShape('text'), 'string');
  assert.deepEqual(jsonShape({a: {b: 1}}, 1), {a: 'object'});
  const record = {id: 'x', ownerId: 'u', owner_uid: 'u', uid: 'u', email: 'e', createdBy: 'u', accountId: 'a', tenantId: 't',
    projectId: 'p', assigneeUserId: 'u', run_uid: 'r', title: 't'};
  assert.deepEqual(ownershipFields(record),
    ['ownerId', 'owner_uid', 'uid', 'email', 'createdBy', 'accountId', 'tenantId', 'projectId', 'assigneeUserId', 'run_uid']);
  assert.deepEqual(ownershipFields(null), []);
  assert.deepEqual(ownershipFields(['ownerId']), []);
});

test('requester: results are cached per identity, method and URL', async t => {
  const {api, ledger, request} = await requesterFixture(t);
  const first = await request({url: '/api/items/inv-101', identity: 'owner', step: 'recon'});
  const again = await request({url: `${api.origin}/api/items/inv-101`, identity: 'owner', step: 'control'});
  assert.equal(again.evidenceId, first.evidenceId);
  assert.equal(api.hits['/api/items/inv-101'], 1);
  const fresh = await request({url: '/api/items/inv-101', identity: 'owner', step: 'reverify', noCache: true, headers: {'cache-control': 'no-cache'}});
  assert.notEqual(fresh.evidenceId, first.evidenceId);
  await request({url: '/api/items/inv-101', identity: 'outsider', step: 'task'});
  await request({url: '/api/items/inv-101', identity: 'owner', method: 'HEAD', step: 'recon'});
  assert.equal(api.hits['/api/items/inv-101'], 4);
  // Concurrent agents asking for the same control share one in-flight exchange.
  const [left, right] = await Promise.all([1, 2].map(() => request({url: '/api/echo', identity: 'owner', step: 'control'})));
  assert.equal(left.evidenceId, right.evidenceId);
  assert.equal(api.hits['/api/echo'], 1);
  assert.deepEqual({...request.stats}, {sent: 5, cached: 2, refused: 0, blocked: 0, rate: 500});
  assert.equal(ledger.count(), 5);
});

test('requester: response facts come from the body; set-cookie and unlisted headers are never stored', async t => {
  const {ledger, request} = await requesterFixture(t);
  const result = await request({url: '/api/items/inv-101', identity: 'owner', step: 'recon'});
  assert.equal(result.status, 200);
  assert.equal(result.type, 'application/json');
  assert.equal(result.hash, `sha256:${hash(ITEM_BODY)}`);
  assert.equal(result.bytes, Buffer.byteLength(ITEM_BODY));
  assert.equal(result.body, ITEM_BODY);
  assert.deepEqual(result.shape, {id: 'string', ownerId: 'string', email: 'string', total: 'number'});
  assert.deepEqual(result.ids, ['inv-101', 'u-1']);
  assert.deepEqual(result.ownership, {ownerId: hash('u-1'), email: hash('alice@example.com')});
  assert.deepEqual(Object.keys(result.headers).sort(), ['cache-control', 'content-type', 'etag']);
  const line = ledgerLines(ledger)[0];
  for (const leaked of ['set-cookie', 'cookie-secret-123456', 'x-internal-token', 'header-secret-777', 'alice@example.com']) {
    assert.ok(!line.includes(leaked), leaked);
  }
  const record = JSON.parse(line);
  assert.deepEqual([record.id, record.run, record.step, record.identity], [result.evidenceId, 'bx-test', 'recon', 'owner']);
  assert.deepEqual(record.request.headers, ['accept', 'authorization']);
  assert.equal(record.response.hash, result.hash);
  assert.match(record.excerpt, /"email":"\[email\]"/);
});

test('requester retains API document facts without saving credential examples in evidence', async t => {
  const {ledger, request} = await requesterFixture(t);
  const result = await request({url: '/openapi.json', identity: 'anonymous',
    purpose: 'discover', step: 'discovery'});
  assert.equal(result.status, 200);
  assert.ok(result.body.includes('shortsecret'), 'the parser still receives the document in memory');
  const record = JSON.parse(ledgerLines(ledger)[0]);
  assert.equal(record.excerpt, undefined);
  assert.equal(record.response.hash, result.hash);
  assert.ok(!fs.readFileSync(ledger.file, 'utf8').includes('shortsecret'));
});

test('requester: credential values are scrubbed from the ledger line, the body and stored headers', async t => {
  const {ledger, request} = await requesterFixture(t);
  const owner = await request({url: '/api/echo', identity: 'owner', step: 'identity'});
  const outsider = await request({url: '/api/echo', identity: 'outsider', step: 'identity'});
  assert.deepEqual([owner.status, outsider.status], [200, 200]);
  assert.equal(JSON.parse(owner.body).seen, '[REDACTED]');
  assert.equal(owner.headers.location, '/login?token=[REDACTED]&next=/home');
  assert.equal(owner.headers['www-authenticate'], 'Bearer');
  const anonymous = await request({url: '/api/echo', step: 'identity'});
  assert.equal(anonymous.status, 401);
  const text = fs.readFileSync(ledger.file, 'utf8');
  for (const value of Object.values(CREDENTIALS)) assert.ok(!text.includes(value), 'credential value in the ledger');
  assert.equal(ledgerLines(ledger).length, 3);
});

test('requester: refusals are recorded with step refused and never reach the server', async t => {
  const {api, ledger, limiter, scope} = await requesterFixture(t);
  const restricted = structuredClone(scope);
  restricted.never = ['delete'];
  const request = createRequester(restricted, {ledger, limiter, env: CREDENTIALS, allowLocal: true});
  const refused = await request({url: '/api/items/inv-101/delete', identity: 'outsider', step: 'task', task: 't-001', agent: 3});
  assert.deepEqual(refused, {refused: true, reason: 'never', evidenceId: 'ev-0001'});
  assert.equal(api.hits['/api/items/inv-101/delete'], undefined);
  const record = JSON.parse(ledgerLines(ledger)[0]);
  assert.deepEqual([record.step, record.task, record.agent, record.identity], ['refused', 't-001', 3, 'outsider']);
  assert.deepEqual(record.refused, {rule: 'never', match: 'delete'});
  const withoutCredentials = createRequester(restricted, {ledger, env: {}, allowLocal: true});
  const missing = await withoutCredentials({url: '/api/items/inv-101', identity: 'owner', step: 'control'});
  assert.equal(missing.reason, 'credential_missing');
  assert.deepEqual(JSON.parse(ledgerLines(ledger)[1]).refused, {rule: 'credential_missing', match: 'OWNER_CRED'});
  assert.equal(request.stats.refused, 1);
  assert.equal(Object.keys(api.hits).length, 0);
  const authHeader = await request({url: '/api/items/inv-101', step: 'recon', noCache: true,
    headers: {Authorization: 'Bearer x'}});
  const hostHeader = await request({url: '/api/items/inv-101', step: 'recon', noCache: true,
    headers: {Host: 'evil.example'}});
  assert.equal(authHeader.refused, undefined);
  assert.equal(hostHeader.refused, undefined);
  assert.equal(api.hits['/api/items/inv-101'], 2);
  await assert.rejects(request({url: '/api/items/inv-101', step: 'probe'}), {code: 2});
});

test('requester sends credential-named inputs while redacting their values', async t => {
  const {api, ledger, request} = await requesterFixture(t);
  const queryValue = 'fixture-query-code-123';
  const bodyValue = 'fixture-body-code-456';
  const get = await request({url: `/api/echo?code=${queryValue}`, step: 'task',
    noCache: true});
  const post = await request({url: '/api/body-echo', method: 'POST',
    purpose: 'json-body', headers: {'content-type': 'application/json'},
    body: JSON.stringify({code: bodyValue}), noCache: true, step: 'task'});
  assert.equal(get.status, 401);
  assert.equal(post.status, 200);
  assert.equal(api.hits['/api/echo'], 1);
  assert.equal(api.hits['/api/body-echo'], 1);
  const stored = fs.readFileSync(ledger.file, 'utf8');
  assert.ok(!stored.includes(queryValue));
  assert.ok(!stored.includes(bodyValue));
  assert.match(stored, /code=\[REDACTED\]/);
  assert.ok(!post.body.includes(bodyValue));
});

test('requester: a timeout is recorded as blocked, not retried and not cached', async t => {
  const {api, ledger, request} = await requesterFixture(t);
  const started = performance.now();
  const result = await request({url: '/api/slow', identity: 'owner', step: 'task', timeout: 100});
  assert.equal(result.blocked, true);
  assert.match(result.reason, /timeout/i);
  assert.ok(performance.now() - started < 400);
  assert.equal(api.hits['/api/slow'], 1);
  assert.deepEqual(JSON.parse(ledgerLines(ledger)[0]).blocked, {reason: result.reason});
  const again = await request({url: '/api/slow', identity: 'owner', step: 'task', timeout: 100});
  assert.notEqual(again.evidenceId, result.evidenceId);
  assert.equal(request.stats.blocked, 2);
});

test('requester: a 5xx is retried once and a 429 halves the rate', async t => {
  const events = [];
  const {api, ledger, limiter, request} = await requesterFixture(t, {log: event => events.push(event)});
  const flaky = await request({url: '/api/flaky', identity: 'owner', step: 'task'});
  assert.equal(flaky.status, 200);
  assert.equal(api.hits['/api/flaky'], 2);
  assert.deepEqual(ledgerLines(ledger).map(line => JSON.parse(line).response.status), [503, 200]);
  const limited = await request({url: '/api/limited', identity: 'owner', step: 'task'});
  assert.equal(limited.status, 429);
  assert.equal(limited.headers['retry-after'], '1');
  assert.equal(limiter.rate(), 250);
  assert.equal(request.stats.rate, 250);
  assert.ok(events.some(event => event.stage === 'request' && /429/.test(event.message) && event.evidenceId === limited.evidenceId));
});

test('requester: a refused connection is retried once, then recorded as blocked', async t => {
  const dir = tempDir(t);
  const closed = await port();
  const {scope} = loadScope({origin: `http://127.0.0.1:${closed}`, overrides: {...LOCAL, rps: 500}});
  const ledger = createLedger(dir, {run: 'bx-test'});
  const request = createRequester(scope, {ledger, env: {}, allowLocal: true});
  const result = await request({url: '/api/x', step: 'recon'});
  assert.equal(result.blocked, true);
  assert.match(result.reason, /ECONNREFUSED/);
  assert.deepEqual({...request.stats}, {sent: 2, cached: 0, refused: 0, blocked: 1, rate: 500});
  assert.deepEqual(ledgerLines(ledger).map(line => JSON.parse(line).blocked.reason), [result.reason, result.reason]);
});

test('requester: cookie credentials are scrubbed whole and by their value parts', async t => {
  const env = {OWNER_CRED: 'sid=cookie-value-0a1b2c3d; theme=dark', OTHER_CRED: 'sid=cookie-value-9z8y7x6w'};
  const {ledger, request} = await requesterFixture(t, {env, scopeOverrides: {auth: 'cookie'}});
  const result = await request({url: '/api/cookie-echo', identity: 'owner', step: 'identity'});
  assert.deepEqual(JSON.parse(result.body), {sid: '[REDACTED]', theme: 'dark'});
  const text = fs.readFileSync(ledger.file, 'utf8');
  for (const leaked of ['cookie-value-0a1b2c3d', 'cookie-value-9z8y7x6w']) assert.ok(!text.includes(leaked), leaked);
  assert.deepEqual(JSON.parse(text).request.headers, ['accept', 'cookie']);
});

test('ledger: records are chained and verifiable; a tampered or deleted line is detected', t => {
  const dir = tempDir(t);
  const ledger = createLedger(dir, {run: 'bx-20261028-ab12'});
  const request = {method: 'GET', url: 'http://127.0.0.1:1/api/x'};
  const ids = ['recon', 'task', 'control'].map(step => ledger.append({step, identity: 'owner', request}));
  assert.deepEqual(ids, ['ev-0001', 'ev-0002', 'ev-0003']);
  assert.equal(ledger.count(), 3);
  const lines = ledgerLines(ledger);
  const records = lines.map(line => JSON.parse(line));
  assert.equal(records[0].prev, null);
  assert.equal(records[1].prev, `sha256:${hash(lines[0])}`);
  assert.equal(records[2].run, 'bx-20261028-ab12');
  assert.ok(Number.isFinite(Date.parse(records[0].at)));
  assert.deepEqual(verifyLedger(ledger.file), {ok: true, records: 3, brokenAt: null});
  fs.writeFileSync(ledger.file, `${[lines[0], lines[1].replace('"step":"task"', '"step":"recon"'), lines[2]].join('\n')}\n`);
  assert.deepEqual(verifyLedger(ledger.file), {ok: false, records: 3, brokenAt: 'ev-0003'});
  fs.writeFileSync(ledger.file, `${[lines[0], lines[2]].join('\n')}\n`);
  assert.deepEqual(verifyLedger(ledger.file), {ok: false, records: 2, brokenAt: 'ev-0002'});
});

test('ledger: reopening continues the chain; a closed ledger refuses appends', t => {
  const dir = tempDir(t);
  const first = createLedger(dir, {run: 'bx-1'});
  first.append({step: 'recon'});
  first.close();
  assert.throws(() => first.append({step: 'recon'}), {code: 2});
  const second = createLedger(dir, {run: 'bx-1'});
  assert.equal(second.count(), 1);
  assert.equal(second.append({step: 'reverify'}), 'ev-0002');
  assert.deepEqual(verifyLedger(second.file), {ok: true, records: 2, brokenAt: null});
  assert.throws(() => verifyLedger(path.join(dir, 'missing.jsonl')), {code: 2});
});

test('ledger: secrets are scrubbed by exact value before redact(); excerpts are masked and capped at 2 KB', t => {
  const dir = tempDir(t);
  const secret = 'sup3r/s3cret+value';
  const ledger = createLedger(dir, {run: 'bx-1', redactFields: ['ssn'], secrets: [secret]});
  const excerpt = `{"ssn":"123-45-6789","mail":"bob@example.org","raw":"${secret}","escaped":"${secret.replace('/', '\\/')}"}${'z'.repeat(5000)}`;
  ledger.append({
    id: 'ev-9999', prev: 'forged', step: 'task', note: 'Authorization: Bearer "abc', auth: 'Bearer live-token-xyz',
    request: {method: 'GET', url: `http://127.0.0.1:1/api/x?q=${encodeURIComponent(secret)}`},
    response: {status: 200, headers: {location: `/next/${secret}`}},
    excerpt,
  });
  const text = fs.readFileSync(ledger.file, 'utf8');
  for (const leaked of ['s3cret', '123-45-6789', 'bob@example.org']) assert.ok(!text.includes(leaked), leaked);
  const record = JSON.parse(text);
  assert.deepEqual([record.id, record.prev, record.note, record.auth], ['ev-0001', null, 'Authorization: Bearer "abc', 'Bearer [REDACTED]']);
  assert.ok(record.excerpt.length <= 2048);
  assert.match(record.excerpt, /^\{"ssn":"\[redacted\]","mail":"\[email\]","raw":"\[REDACTED\]","escaped":"\[REDACTED\]"\}z+$/);
});

test('maskExcerpt masks redact fields, emails, phones and secret-looking values, and keeps ordinary numbers', () => {
  const json = '{"email":"alice@example.com","phone":"+1 555 123 4567","ssn":"123-45-6789","name":"Alice","total":1200,"id":"inv-1234567890"}';
  assert.equal(maskExcerpt(json, ['email', 'phone', 'ssn']),
    '{"email":"[email]","phone":"[phone]","ssn":"[redacted]","name":"Alice","total":1200,"id":"inv-1234567890"}');
  assert.equal(maskExcerpt('write to bob@example.org or call (555) 123-4567 today'), 'write to [email] or call [phone] today');
  for (const kept of ['2026-10-27 14:02:11', 'order 12345678901', 'v1.12.4 on 203.0.113.8', '{"amount":4500}']) {
    assert.equal(maskExcerpt(kept), kept, kept);
  }
  assert.equal(maskExcerpt('DB_PASSWORD=hunter2\nSECRET_KEY=abc\n'), 'DB_PASSWORD=[redacted]\nSECRET_KEY=[redacted]\n');
  assert.equal(maskExcerpt('{"apiToken":"t-123","label":"x"}'), '{"apiToken":"[redacted]","label":"x"}');
  assert.equal(maskExcerpt('/api?auth%252Etoken=shortsecret&source.file=guide.txt'),
    '/api?auth%252Etoken=[REDACTED]&source.file=guide.txt');
  assert.equal(maskExcerpt('key AKIAIOSFODNN7EXAMPLE at https://admin:pa55@db.internal/x'), 'key [redacted] at https://admin:[redacted]@db.internal/x');
});

test('scrub replaces each secret deeply, longest first, in values and keys, without mutating the input', () => {
  const input = {url: '/x?t=tok-123456', list: ['tok-123456', 'ok'], nested: {'tok-123456': 'tok-1234567890'}, n: 5, none: null};
  const output = scrub(input, ['tok-123456', 'tok-1234567890', '']);
  assert.deepEqual(output, {url: '/x?t=[REDACTED]', list: ['[REDACTED]', 'ok'], nested: {'[REDACTED]': '[REDACTED]'}, n: 5, none: null});
  assert.equal(input.list[0], 'tok-123456');
  assert.equal(scrub('a+b/c', ['a+b/c']), '[REDACTED]');
  assert.equal(scrub(`q=${encodeURIComponent('a+b/c')}`, ['a+b/c']), 'q=[REDACTED]');
  assert.equal(scrub('nothing here', []), 'nothing here');
});

test('guarded requester accepts a 16 MiB response cap for reviewed asset reads', async t => {
  const api = await startApi(t);
  const dir = tempDir(t);
  const scope = loadScope({origin: api.origin, overrides: {acceptLocal: true}}).scope;
  const ledger = createLedger(dir, {run: 'bx-large-asset-cap'});
  const request = createRequester(scope, {ledger, allowLocal: true});
  const maxBytes = 16 * 1024 * 1024;
  const result = await request({url: '/', identity: 'anonymous', method: 'GET',
    purpose: 'asset', step: 'recon', noCache: true, maxBytes});
  assert.equal(typeof result.status, 'number');
  await assert.rejects(request({url: '/', identity: 'anonymous', method: 'GET',
    purpose: 'asset', step: 'recon', noCache: true, maxBytes: maxBytes + 1}),
  /maxBytes must be a whole number up to 16777216/);
});

test('guarded requester captures large scoped responses by default without retaining them in cache', async t => {
  const {api, request} = await requesterFixture(t);
  const url = `${api.origin}/api/large`;
  const first = await request({url, identity: 'anonymous', method: 'GET',
    purpose: 'task', step: 'recon'});
  const second = await request({url, identity: 'anonymous', method: 'GET',
    purpose: 'task', step: 'recon'});
  assert.equal(first.status, 200);
  assert.ok(first.bytes > 700 * 1024);
  assert.equal(second.status, 200);
  assert.equal(api.hits['/api/large'], 2);
  assert.equal(request.stats.cached, 0);
});
