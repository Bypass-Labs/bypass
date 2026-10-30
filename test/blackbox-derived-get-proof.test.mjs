import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import http from 'node:http';
import os from 'node:os';
import path from 'node:path';
import {randomBytes} from 'node:crypto';
import {check} from '../src/blackbox/poc-runtime.mjs';
import {proveFindings, verifyRun, exportRun} from '../src/blackbox/poc.mjs';
import {createLedger} from '../src/blackbox/ledger.mjs';
import {execFile} from '../src/util.mjs';

test('derived GET proof refreshes login, verifies, and exports a red-green regression',
  {timeout: 90000}, async t => {
    const root = fs.mkdtempSync(path.join(os.tmpdir(), 'bypass-derived-get-proof-'));
    t.after(() => fs.rmSync(root, {recursive: true, force: true}));
    let fixed = false, issuedCount = 0;
    const issued = new Set();
    const server = http.createServer(async (request, response) => {
      response.setHeader('cache-control', 'no-store');
      if (request.method === 'POST' && request.url === '/login') {
        let body = '';
        for await (const chunk of request) body += chunk;
        const input = JSON.parse(body);
        if (input.username !== "admin' OR '1'='1" ||
            !/^bx-invalid-[0-9a-f]{24}$/.test(input.password ?? '')) {
          response.writeHead(401, {'content-type': 'application/json'});
          response.end('{}');
          return;
        }
        const token = `bx-derived-${randomBytes(16).toString('hex')}`;
        issued.add(token);
        issuedCount++;
        response.writeHead(200, {'content-type': 'application/json'});
        response.end(JSON.stringify({authentication: {token}}));
        return;
      }
      if (request.url?.startsWith('/private') || request.url?.startsWith('/view')) {
        if (!issued.has(request.headers.authorization?.slice(7))) {
          response.writeHead(401, {'content-type': 'application/json'});
          response.end('{}');
          return;
        }
        if (request.url.startsWith('/private')) {
          response.writeHead(200, {'content-type': 'application/json'});
          response.end('{"ok":true}');
          return;
        }
        const input = new URL(request.url, 'http://localhost').searchParams.get('q') ?? '';
        const match = /^\{\{(\d+)\*(\d+)\}\}$/.exec(input);
        response.writeHead(200, {'content-type': 'text/plain'});
        response.end(fixed || !match ? input : String(Number(match[1]) * Number(match[2])));
        return;
      }
      response.writeHead(404); response.end();
    });
    await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
    t.after(() => new Promise(resolve => server.close(resolve)));
    const origin = `http://127.0.0.1:${server.address().port}`;
    const derivedLogin = {kind: 'model-auth-login', proofMode: 'protected-status',
      request: {method: 'POST', url: '/login', as: 'anonymous'}, loginPath: '/login',
      privatePath: '/private', userField: 'username', passwordField: 'password',
      userPayloads: ["admin' OR '1'='1"], tokenPointer: '/authentication/token',
      reviewedAuthPosts: [{path: '/login', usernameField: 'username', passwordField: 'password'}]};
    const webProof = {kind: 'ssti-arithmetic', request: {method: 'GET', url: '/view', as: 'derived'},
      parameter: 'q', derivedLogin};
    const standalone = {schemaVersion: 1, id: 'f-001', origin, include: ['/'], never: [],
      rps: 100, expiresAt: null, identities: {}, auth: 'bearer', targetEnvironment: 'local',
      ...webProof};
    const first = await check(standalone, {});
    assert.equal(first.verdict, 'confirmed', JSON.stringify(first));
    assert.equal(first.controls[0].label, 'fresh-login-boundary');
    assert.equal(first.controls[0].verdict, 'confirmed');
    const run = 'bx-20261029-12345678';
    const runDir = path.join(root, '.bypass/runs', run);
    fs.mkdirSync(runDir, {recursive: true});
    fs.writeFileSync(path.join(runDir, 'run.json'), '{}');
    const ledger = createLedger(runDir, {run});
    const scope = {target: {origin, environment: 'local'}, include: ['/'], never: [],
      domains: [], discovery: {auditDomains: []}, limits: {rps: 100},
      identities: {owner: {env: 'OWNER_TOKEN'}, outsider: {env: 'OTHER_TOKEN'},
        auth: 'bearer', identityPath: null, identityCookieName: null}};
    const finding = {id: 'f-001', kind: 'ssti-arithmetic', pattern: '/view',
      url: `${origin}/view`, task: null, confirmation: [], webProof};
    const kept = await proveFindings([finding], [], {runDir, surface: {patterns: []},
      scope, env: {}, ledger});
    assert.equal(kept.length, 1, 'generated proof must not downgrade the derived finding');
    assert.ok(kept[0].proof);
    assert.equal((await verifyRun(root, run, {env: {}})).proofs[0].verdict, 'confirmed');
    const output = exportRun(root, run, {out: path.join(root, 'regression')});
    assert.equal(output.files.length, 1);
    const runRegression = () => execFile(process.execPath, ['--test', ...output.files],
      {env: {...process.env, NODE_TEST_CONTEXT: undefined}, timeout: 30000});
    assert.equal((await runRegression()).code, 1);
    fixed = true;
    assert.equal((await verifyRun(root, run, {env: {}})).proofs[0].verdict, 'not_reproduced');
    assert.equal((await runRegression()).code, 0);
    assert.ok(issuedCount >= 10, 'each proof and retest must obtain a fresh session');
    const artifacts = [path.join(runDir, 'poc/f-001/spec.json'), ...output.files]
      .map(file => fs.readFileSync(file, 'utf8')).join('\n');
    assert.doesNotMatch(artifacts, /bx-derived-[0-9a-f]{32}/);
  });
