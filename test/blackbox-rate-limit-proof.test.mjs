import test from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import {check} from '../src/blackbox/poc-runtime.mjs';
import {proveFindings} from '../src/blackbox/poc.mjs';
import {loadScope} from '../src/blackbox/scope.mjs';
import {mergeProofSurfaces} from '../src/blackbox/index.mjs';

async function fixture(handler) {
  const server = http.createServer(handler);
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  return {server, origin: `http://127.0.0.1:${server.address().port}`};
}

function spec(origin) {
  return {schemaVersion: 1, kind: 'rate-limit-auth-gate', origin,
    include: ['/'], never: [], rps: 100, expiresAt: null, allowRemoteHttp: false,
    targetEnvironment: 'local', request: {method: 'POST',
      url: `${origin}/api/beta/unlock`, as: 'anonymous'},
    mode: 'access-gate', placement: 'json', field: 'code', fields: ['code'],
    userField: null, contentType: 'application/json', attemptCount: 20,
    minimumRps: 10, reviewedRateLimitOperations: [{method: 'POST',
      path: '/api/beta/unlock', placement: 'json', fields: ['code']}]};
}

test('rate-limit proof independently replays an unthrottled access gate', async t => {
  let requests = 0;
  const {server, origin} = await fixture((request, response) => {
    requests++;
    request.resume();
    response.writeHead(200, {'content-type': 'application/json',
      'cache-control': 'no-store'});
    response.end('{"ok":false}');
  });
  t.after(() => server.close());
  const result = await check(spec(origin));
  assert.equal(result.verdict, 'confirmed', JSON.stringify(result));
  assert.equal(requests, 20);
  assert.ok(result.achievedRps >= 10);
});

test('rate-limit proof treats 429 and Retry-After as effective throttling', async t => {
  let requests = 0;
  const {server, origin} = await fixture((request, response) => {
    requests++;
    request.resume();
    const throttled = requests >= 5;
    response.writeHead(throttled ? 429 : 200, {'content-type': 'application/json',
      ...(throttled ? {'retry-after': '30'} : {})});
    response.end('{"ok":false}');
  });
  t.after(() => server.close());
  const result = await check(spec(origin));
  assert.equal(result.verdict, 'not_reproduced', JSON.stringify(result));
  assert.equal(requests, 20);
});

test('rate-limit proof replaces one connection reset with a fresh invalid attempt', async t => {
  let requests = 0;
  const {server, origin} = await fixture((request, response) => {
    requests++;
    request.resume();
    if (requests === 7) {request.socket.destroy(); return;}
    response.writeHead(200, {'content-type': 'application/json'});
    response.end('{"ok":false}');
  });
  t.after(() => server.close());
  const result = await check(spec(origin));
  assert.equal(result.verdict, 'confirmed', JSON.stringify(result));
  assert.equal(requests, 21);
});

test('confirmed rate-limit findings survive generated proof replay', async t => {
  let requests = 0;
  const {server, origin} = await fixture((request, response) => {
    requests++;
    request.resume();
    response.writeHead(200, {'content-type': 'application/json'});
    response.end('{"ok":false}');
  });
  t.after(() => server.close());
  const runDir = fs.mkdtempSync(path.join(os.tmpdir(), 'bypass-rate-limit-proof-'));
  t.after(() => fs.rmSync(runDir, {recursive: true, force: true}));
  const {scope} = loadScope({origin, overrides: {acceptLocal: true, rps: 100}});
  const surface = {patterns: [], jsonBodyOperations: [{path: '/api/beta/unlock',
    method: 'POST', fields: ['code'], contentType: 'application/json'}]};
  const finding = {id: 'f-0001', kind: 'rate-limit-auth-gate',
    pattern: '/api/beta/unlock', url: `${origin}/api/beta/unlock`,
    evidence: ['ev-a'], confirmation: ['ev-b'], webProof: {
      kind: 'rate-limit-auth-gate', request: {method: 'POST',
        url: `${origin}/api/beta/unlock`, as: 'anonymous'},
      mode: 'access-gate', placement: 'json', field: 'code', fields: ['code'],
      userField: null, contentType: 'application/json', attemptCount: 20,
      minimumRps: 10}};
  const kept = await proveFindings([finding], [], {runDir, surface, scope,
    env: {}, ledger: {append: () => 'ev-proof'}, web: {results: []}});
  assert.equal(kept.length, 1);
  assert.equal(kept[0].proof.endsWith('/poc/f-0001/poc.mjs'), true);
  assert.equal(requests, 20);
});

test('proof replay receives an auth-gate contract discovered after initial recon', async t => {
  let requests = 0;
  const {server, origin} = await fixture((request, response) => {
    requests++;
    request.resume();
    response.writeHead(200, {'content-type': 'application/json'});
    response.end('{"ok":false}');
  });
  t.after(() => server.close());
  const runDir = fs.mkdtempSync(path.join(os.tmpdir(), 'bypass-late-rate-proof-'));
  t.after(() => fs.rmSync(runDir, {recursive: true, force: true}));
  const {scope} = loadScope({origin, overrides: {acceptLocal: true, rps: 100}});
  const surface = mergeProofSurfaces({patterns: [], jsonBodyOperations: []}, [
    {jsonBodyOperations: [{path: '/api/beta/unlock', method: 'POST',
      fields: ['code'], contentType: 'application/json'}]}]);
  const finding = {id: 'f-late', kind: 'rate-limit-auth-gate',
    pattern: '/api/beta/unlock', url: `${origin}/api/beta/unlock`,
    evidence: ['ev-a'], confirmation: ['ev-b'], webProof: {
      kind: 'rate-limit-auth-gate', request: {method: 'POST',
        url: `${origin}/api/beta/unlock`, as: 'anonymous'},
      mode: 'access-gate', placement: 'json', field: 'code', fields: ['code'],
      userField: null, contentType: 'application/json', attemptCount: 20,
      minimumRps: 10}};
  const kept = await proveFindings([finding], [], {runDir, surface, scope,
    env: {}, ledger: {append: () => 'ev-proof'}, web: {results: []}});
  assert.ok(kept[0]?.proof?.endsWith('/poc/f-late/poc.mjs'), JSON.stringify(kept));
  assert.equal(requests, 20);
});
