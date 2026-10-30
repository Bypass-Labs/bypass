import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import http from 'node:http';
import os from 'node:os';
import path from 'node:path';
import {randomBytes} from 'node:crypto';
import {loadScope} from '../src/blackbox/scope.mjs';
import {createLedger} from '../src/blackbox/ledger.mjs';
import {proveFindings, verifyRun, exportRun} from '../src/blackbox/poc.mjs';
import {check, validModelAuthLogin} from '../src/blackbox/poc-runtime.mjs';
import {execFile} from '../src/util.mjs';

test('sealed login proof uses fresh invalid passwords and transient tokens, then clears after repair', async t => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'bypass-auth-login-proof-'));
  t.after(() => fs.rmSync(root, {recursive: true, force: true}));
  const suffix = randomBytes(4).toString('hex');
  const loginPath = `/api/login-${suffix}`;
  const privatePath = `/api/me-${suffix}`;
  const userPayloads = ["admin' OR '1'='1", "root' OR '2'='2"];
  let vulnerable = true;
  const issued = new Set(), seenPasswords = new Set(), requests = [];
  const server = http.createServer(async (request, response) => {
    const url = new URL(request.url, 'http://fixture');
    response.setHeader('content-type', 'application/json');
    response.setHeader('cache-control', 'no-store');
    requests.push(`${request.method} ${url.pathname}`);
    if (request.method === 'POST' && url.pathname === loginPath) {
      const chunks = [];
      for await (const chunk of request) chunks.push(chunk);
      const body = JSON.parse(Buffer.concat(chunks).toString());
      seenPasswords.add(body.password);
      if (vulnerable && userPayloads.includes(body.username) &&
          /^bx-invalid-[0-9a-f]{24}$/.test(body.password)) {
        const token = `token-${randomBytes(18).toString('hex')}`;
        issued.add(token);
        return response.end(JSON.stringify({authentication: {token}}));
      }
      response.statusCode = 401;
      return response.end(JSON.stringify({error: 'invalid credentials'}));
    }
    if (request.method === 'GET' && url.pathname === privatePath) {
      const bearer = String(request.headers.authorization ?? '').replace(/^Bearer /, '');
      return response.end(issued.has(bearer) ?
        JSON.stringify({user: {id: 'owner-42', role: 'member'}}) : '{}');
    }
    response.statusCode = 404;
    response.end('{}');
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  t.after(() => new Promise(resolve => server.close(resolve)));
  const origin = `http://127.0.0.1:${server.address().port}`;
  const scopeFile = path.join(root, 'scope.json');
  fs.writeFileSync(scopeFile, JSON.stringify({schemaVersion: 1, target: {origin},
    include: ['/'], limits: {rps: 100}}));
  const scope = loadScope({file: scopeFile, origin}).scope;
  const webProof = {kind: 'model-auth-login',
    request: {method: 'POST', url: loginPath, as: 'anonymous'},
    loginPath, userField: 'username', passwordField: 'password',
    userPayloads, tokenPointer: '/authentication/token',
    privatePath, principalPointer: '/user/id'};
  const spec = {schemaVersion: 1, origin, include: ['/'], never: [], rps: 100,
    auth: 'bearer', targetEnvironment: 'local', reviewedAuthPosts: [{path: loginPath,
      usernameField: 'username', passwordField: 'password'}], ...webProof};
  assert.equal(validModelAuthLogin(spec), true);
  const beforeInvalid = requests.length;
  assert.equal((await check({...spec, reviewedAuthPosts: []})).verdict, 'inconclusive');
  assert.equal((await check({...spec, principalPointer: '/authentication/token'})).verdict,
    'inconclusive');
  assert.equal(requests.length, beforeInvalid);
  const direct = await check(spec);
  assert.equal(direct.verdict, 'confirmed', JSON.stringify(direct));
  assert.ok(seenPasswords.size >= 2);
  assert.ok([...seenPasswords].every(value => /^bx-invalid-[0-9a-f]{24}$/.test(value)));
  assert.equal(JSON.stringify(direct).includes('token-'), false);
  const run = 'bx-20261028-abcdef12';
  const runDir = path.join(root, '.bypass/runs', run);
  fs.mkdirSync(runDir, {recursive: true});
  fs.writeFileSync(path.join(runDir, 'run.json'), JSON.stringify({run, status: 'complete'}));
  const ledger = createLedger(runDir);
  const finding = {id: 'f-001', kind: 'model-auth-login', verdict: 'confirmed',
    severity: 'high', pattern: loginPath, url: new URL(loginPath, origin).href,
    confirmation: [], webProof};
  const surface = {patterns: [], authBodyOperations: [{path: loginPath,
    method: 'POST', contentType: 'application/json', fields: ['username', 'password'],
    usernameField: 'username', passwordField: 'password'}]};
  const kept = await proveFindings([finding], [], {runDir, surface, scope,
    env: process.env, ledger, web: {results: []}});
  assert.equal(kept.length, 1, fs.readFileSync(ledger.file, 'utf8').slice(-1200));
  ledger.close();
  const sealed = JSON.parse(fs.readFileSync(path.join(runDir, 'poc/f-001/spec.json')));
  assert.equal(validModelAuthLogin(sealed), true);
  assert.deepEqual(sealed.reviewedAuthPosts, [{path: loginPath,
    usernameField: 'username', passwordField: 'password'}]);
  assert.equal(JSON.stringify(sealed).includes('bx-invalid-'), false);
  assert.equal((await verifyRun(root, run)).proofs[0].verdict, 'confirmed');
  const exported = exportRun(root, run, {out: path.join(root, 'regression')});
  const regression = () => execFile(process.execPath, ['--test', ...exported.files],
    {env: {...process.env, NODE_TEST_CONTEXT: undefined}, timeout: 20000});
  assert.equal((await regression()).code, 1);
  vulnerable = false;
  assert.equal((await verifyRun(root, run)).proofs[0].verdict, 'not_reproduced');
  assert.equal((await regression()).code, 0);
  assert.ok(requests.every(value => value === `POST ${loginPath}` ||
    value === `GET ${privatePath}`));
});
