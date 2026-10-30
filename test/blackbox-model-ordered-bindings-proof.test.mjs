import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import http from 'node:http';
import os from 'node:os';
import path from 'node:path';
import {randomBytes} from 'node:crypto';
import {check, validModelHttpSequence} from '../src/blackbox/poc-runtime.mjs';
import {proveFindings, verifyRun, exportRun} from '../src/blackbox/poc.mjs';
import {createLedger} from '../src/blackbox/ledger.mjs';
import {execFile} from '../src/util.mjs';

test('sealed proof replays two fresh bindings across three reviewed POSTs', async t => {
  const suffix = randomBytes(4).toString('hex');
  const start = `/api/${suffix}/start`, exchange = `/api/${suffix}/exchange`;
  const finish = `/api/${suffix}/finish`, privatePath = `/api/${suffix}/private`;
  const privateBody = JSON.stringify({owner: 'fixture-owner', private: true,
    note: `Owner-only ${suffix} ` + 'account note. '.repeat(5)});
  const marker = `bx${randomBytes(6).toString('hex')}`;
  const secondMarker = `bx${randomBytes(6).toString('hex')}`;
  let fixed = false, issued = 0;
  const nonces = new Set(), tickets = new Set(), requests = [];
  const server = http.createServer(async (request, response) => {
    response.setHeader('cache-control', 'no-store');
    response.setHeader('content-type', 'application/json');
    const url = new URL(request.url, 'http://fixture');
    requests.push({method: request.method, path: url.pathname,
      cacheControl: request.headers['cache-control']});
    if (request.method === 'GET' && url.pathname === privatePath) {
      if (request.headers.authorization !== 'Bearer fixture-owner') {
        response.writeHead(403); response.end('{"error":"owner only"}'); return;
      }
      response.end(privateBody); return;
    }
    let input = {};
    if (request.method === 'POST') {
      let body = '';
      for await (const chunk of request) body += chunk;
      try {input = JSON.parse(body);} catch { /* malformed request remains public */ }
    }
    if (request.method === 'POST' && url.pathname === start && input.seed === 1) {
      const nonce = `n${(++issued).toString(36)}`;
      nonces.add(nonce);
      response.end(JSON.stringify({nonce})); return;
    }
    if (request.method === 'POST' && url.pathname === exchange) {
      if (!nonces.delete(input.nonce)) {
        response.writeHead(400); response.end('{"error":"nonce"}'); return;
      }
      const ticket = `t${(++issued).toString(36)}`;
      tickets.add(ticket);
      response.end(JSON.stringify({ticket})); return;
    }
    if (request.method === 'POST' && url.pathname === finish) {
      const valid = tickets.delete(input.ticket);
      if (valid && input.claim === 'signal-a') {
        response.end(JSON.stringify({result: marker})); return;
      }
      if (valid && input.claim === 'signal-b') {
        response.end(JSON.stringify({result: secondMarker})); return;
      }
      response.end(valid && !fixed && input.claim === 'owner' ? privateBody :
        '{"owner":"public","private":false}'); return;
    }
    response.writeHead(404); response.end('{}');
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  t.after(() => new Promise(resolve => server.close(resolve)));
  const origin = `http://127.0.0.1:${server.address().port}`;
  const reviewedOperations = [
    {method: 'POST', path: start, placement: 'json', fields: ['seed'],
      requiredFields: ['seed'], contentType: 'application/json'},
    {method: 'POST', path: exchange, placement: 'json', fields: ['nonce'],
      requiredFields: ['nonce'], contentType: 'application/json'},
    {method: 'POST', path: finish, placement: 'json', fields: ['claim', 'ticket'],
      requiredFields: ['claim', 'ticket'], contentType: 'application/json'}];
  const spec = {schemaVersion: 1, id: 'f-001', kind: 'model-access-boundary',
    comparison: 'sequence-exact-body', origin, include: ['/'], never: [],
    rps: 100, expiresAt: null, identities: {owner: 'OWNER_TOKEN'}, auth: 'bearer',
    targetEnvironment: 'local', reviewedPostPaths: {json: [start, exchange, finish]},
    reviewedOperations, as: 'anonymous', protectedPath: privatePath,
    prelude: [
      {method: 'POST', path: start, placement: 'json', key: 'seed',
        value: '1', valueEncoding: 'json', fixedFields: [], bodyTemplate: '',
        headers: [], as: 'anonymous', contentType: 'application/json'},
      {method: 'POST', path: exchange, placement: 'json', key: 'nonce',
        value: 'audit', fixedFields: [], bodyTemplate: '', headers: [],
        as: 'anonymous', contentType: 'application/json'}],
    subject: {method: 'POST', path: finish, placement: 'json', key: 'claim',
      fixedFields: [], bodyTemplate: '', headers: [], contentType: 'application/json'},
    observe: [], bindings: [
      {from: 0, pointer: '/nonce', to: 'prelude', index: 1, key: 'nonce'},
      {from: 1, pointer: '/ticket', to: 'subject', index: 0, key: 'ticket'}],
    bindingReviews: [
      {sourcePath: start, sourceAs: 'anonymous', sourcePointer: '/nonce',
        sourceType: 'string', sourceStatus: '2xx', sourceMethod: 'POST',
        sourcePlacement: 'json', sourceFields: ['seed'], targetPath: exchange,
        targetPlacement: 'json', targetFields: ['nonce']},
      {sourcePath: exchange, sourceAs: 'anonymous', sourcePointer: '/ticket',
        sourceType: 'string', sourceStatus: '2xx', sourceMethod: 'POST',
        sourcePlacement: 'json', sourceFields: ['nonce'], targetPath: finish,
        targetPlacement: 'json', targetFields: ['claim', 'ticket']}],
    controlValue: 'public', firstValue: 'owner', secondValue: 'owner2',
    marker: '', secondMarker: '', assertion: {step: 'subject', index: 0,
      location: 'body', name: ''}};
  assert.equal(validModelHttpSequence(spec), true);
  const vulnerable = await check(spec, {OWNER_TOKEN: 'fixture-owner'});
  assert.equal(vulnerable.verdict, 'confirmed', JSON.stringify(vulnerable));
  const generic = {...spec, kind: 'model-http-sequence',
    controlValue: 'public', firstValue: 'signal-a', secondValue: 'signal-b',
    marker, secondMarker};
  assert.equal(validModelHttpSequence(generic), true);
  assert.equal((await check(generic, {OWNER_TOKEN: 'fixture-owner'})).verdict,
    'observed', 'generic response transformation must replay both captures');
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'bypass-ordered-proof-'));
  t.after(() => fs.rmSync(root, {recursive: true, force: true}));
  const run = 'bx-20261029-abcdef79';
  const runDir = path.join(root, '.bypass/runs', run);
  fs.mkdirSync(runDir, {recursive: true});
  fs.writeFileSync(path.join(runDir, 'run.json'), '{}');
  const ledger = createLedger(runDir, {run});
  const scope = {target: {origin, environment: 'local'}, include: ['/'],
    domains: [], never: [], limits: {rps: 100}, discovery: {auditDomains: []},
    identities: {owner: {env: 'OWNER_TOKEN'}, outsider: {env: 'OTHER_TOKEN'},
      auth: 'bearer'}, probes: {jsonPostPaths: [start, exchange, finish],
      xmlPostPaths: [], formPostPaths: [], writeOperations: reviewedOperations}};
  const surface = {patterns: [], methodOperations: reviewedOperations};
  const finding = {id: 'f-001', kind: 'model-access-boundary', pattern: finish,
    url: `${origin}${finish}`, task: null, confirmation: [],
    webProof: {...spec, reviewedPostPaths: undefined, reviewedOperations: undefined}};
  const kept = await proveFindings([finding], [], {runDir, surface, scope,
    env: {OWNER_TOKEN: 'fixture-owner'}, ledger});
  assert.equal(kept.length, 1);
  const sealed = JSON.parse(fs.readFileSync(path.join(runDir, 'poc/f-001/spec.json'), 'utf8'));
  assert.equal(sealed.bindings?.length, 2);
  assert.ok(!JSON.stringify(sealed).includes('fixture-owner'));
  assert.equal((await verifyRun(root, run,
    {env: {OWNER_TOKEN: 'fixture-owner'}})).proofs[0].verdict, 'confirmed');
  const exported = exportRun(root, run, {out: path.join(root, 'regression')});
  const regression = () => execFile(process.execPath, ['--test', ...exported.files],
    {env: {...process.env, OWNER_TOKEN: 'fixture-owner',
      NODE_TEST_CONTEXT: undefined}, timeout: 30000});
  assert.equal((await regression()).code, 1);
  fixed = true;
  assert.equal((await check(spec, {OWNER_TOKEN: 'fixture-owner'})).verdict,
    'not_reproduced');
  assert.equal((await verifyRun(root, run,
    {env: {OWNER_TOKEN: 'fixture-owner'}})).proofs[0].verdict, 'not_reproduced');
  assert.equal((await regression()).code, 0);
  assert.ok(issued >= 6, 'each control and replay needs fresh captures');
  assert.ok(requests.every(item => item.cacheControl === 'no-cache' &&
    [start, exchange, finish, privatePath].includes(item.path)));
});
