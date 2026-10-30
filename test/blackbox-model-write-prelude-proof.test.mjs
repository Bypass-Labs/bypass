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

test('sealed protected-content proof refreshes a reviewed POST prelude and binds its fresh scalar',
  async t => {
    const suffix = randomBytes(4).toString('hex');
    const begin = `/api/${suffix}/begin`, complete = `/api/${suffix}/complete`;
    const privatePath = `/api/${suffix}/private`;
    const privateBody = JSON.stringify({statement: `Owner-only ${suffix} ` +
      'billing note and private account annotation. '.repeat(4)});
    let fixed = false, issued = 0;
    const nonces = new Set();
    const exchanges = [];
    const server = http.createServer(async (request, response) => {
      response.setHeader('cache-control', 'no-store');
      response.setHeader('content-type', 'application/json');
      const pathname = new URL(request.url, 'http://fixture').pathname;
      exchanges.push({method: request.method, path: pathname,
        cacheControl: request.headers['cache-control']});
      if (request.method === 'GET' && pathname === privatePath) {
        if (request.headers.authorization !== 'Bearer fixture-owner') {
          response.writeHead(403); response.end('{"error":"owner only"}'); return;
        }
        response.end(privateBody); return;
      }
      let input = {};
      if (request.method === 'POST') {
        let body = '';
        for await (const chunk of request) body += chunk;
        try {input = JSON.parse(body);} catch { /* ordinary malformed input */ }
      }
      if (request.method === 'POST' && pathname === begin && input.seed === 1 &&
          request.headers.accept === 'application/json') {
        const nonce = `n${(++issued).toString(36)}`;
        nonces.add(nonce);
        response.end(JSON.stringify({nonce})); return;
      }
      if (request.method === 'POST' && pathname === complete) {
        const valid = nonces.delete(input.nonce);
        response.end(valid && !fixed && ['owner', 'owner2'].includes(input.claim) ?
          privateBody : '{"statement":"Public record"}'); return;
      }
      response.writeHead(404); response.end('{}');
    });
    await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
    t.after(() => new Promise(resolve => server.close(resolve)));
    const origin = `http://127.0.0.1:${server.address().port}`;
    const reviewedOperations = [
      {method: 'POST', path: begin, placement: 'json', fields: ['seed'],
        requiredFields: ['seed'], contentType: 'application/json'},
      {method: 'POST', path: complete, placement: 'json', fields: ['claim', 'nonce'],
        requiredFields: ['claim', 'nonce'], contentType: 'application/json'}];
    const spec = {schemaVersion: 1, id: 'f-001', kind: 'model-access-boundary',
      comparison: 'sequence-exact-body', origin, include: ['/'], never: [],
      rps: 100, expiresAt: null, identities: {owner: 'OWNER_TOKEN'}, auth: 'bearer',
      targetEnvironment: 'local', reviewedPostPaths: {json: [begin, complete]},
      reviewedOperations, as: 'anonymous', protectedPath: privatePath,
      prelude: [{method: 'POST', path: begin, placement: 'json', key: 'seed',
        value: '1', valueEncoding: 'json', fixedFields: [], bodyTemplate: '',
        headers: [{name: 'Accept', value: 'application/json'}],
        as: 'anonymous', contentType: 'application/json'}],
      subject: {method: 'POST', path: complete, placement: 'json', key: 'claim',
        fixedFields: [], bodyTemplate: '', headers: [], contentType: 'application/json'},
      observe: [], binding: {from: 0, pointer: '/nonce', to: 'subject',
        index: 0, key: 'nonce'}, bindingReview: {sourcePath: begin,
        sourceAs: 'anonymous', sourcePointer: '/nonce', sourceType: 'string',
        sourceStatus: 200, sourceEvidenceId: null, sourceMethod: 'POST',
        sourcePlacement: 'json', sourceFields: ['seed'], targetPath: complete,
        targetPlacement: 'json', targetFields: ['claim', 'nonce']},
      controlValue: 'public', firstValue: 'owner', secondValue: 'owner2',
      marker: '', secondMarker: '', assertion: {step: 'subject', index: 0,
        location: 'body', name: ''}};
    assert.equal(validModelHttpSequence(spec), true);
    const vulnerable = await check(spec, {OWNER_TOKEN: 'fixture-owner'});
    assert.equal(vulnerable.verdict, 'confirmed', JSON.stringify(vulnerable));
    const root = fs.mkdtempSync(path.join(os.tmpdir(), 'bypass-write-prelude-proof-'));
    t.after(() => fs.rmSync(root, {recursive: true, force: true}));
    const run = 'bx-20261029-abcdef77';
    const runDir = path.join(root, '.bypass/runs', run);
    fs.mkdirSync(runDir, {recursive: true});
    fs.writeFileSync(path.join(runDir, 'run.json'), '{}');
    const ledger = createLedger(runDir, {run});
    const scope = {target: {origin, environment: 'local'}, include: ['/'],
      domains: [],
      never: [], limits: {rps: 100}, discovery: {auditDomains: []},
      identities: {owner: {env: 'OWNER_TOKEN'}, outsider: {env: 'OTHER_TOKEN'},
        auth: 'bearer'}, probes: {jsonPostPaths: [begin, complete],
        xmlPostPaths: [], formPostPaths: [], writeOperations: reviewedOperations}};
    const surface = {patterns: [], methodOperations: reviewedOperations};
    const finding = {id: 'f-001', kind: 'model-access-boundary', pattern: complete,
      url: `${origin}${complete}`, task: null, confirmation: [],
      webProof: {...spec, reviewedPostPaths: undefined,
        reviewedOperations: undefined}};
    const kept = await proveFindings([finding], [], {runDir, surface,
      scope, env: {OWNER_TOKEN: 'fixture-owner'}, ledger});
    assert.equal(kept.length, 1, 'the fresh generated proof must keep the finding');
    const sealed = JSON.parse(fs.readFileSync(path.join(runDir,
      'poc/f-001/spec.json'), 'utf8'));
    assert.ok(sealed.reviewedOperations.some(item => item.path === begin));
    assert.ok(!JSON.stringify(sealed).includes('fixture-owner'));
    assert.equal((await verifyRun(root, run,
      {env: {OWNER_TOKEN: 'fixture-owner'}})).proofs[0].verdict, 'confirmed');
    const exported = exportRun(root, run, {out: path.join(root, 'regression')});
    const regression = () => execFile(process.execPath, ['--test', ...exported.files],
      {env: {...process.env, OWNER_TOKEN: 'fixture-owner',
        NODE_TEST_CONTEXT: undefined}, timeout: 30000});
    assert.equal((await regression()).code, 1);
    fixed = true;
    const repaired = await check(spec, {OWNER_TOKEN: 'fixture-owner'});
    assert.equal(repaired.verdict, 'not_reproduced', JSON.stringify(repaired));
    assert.equal((await verifyRun(root, run,
      {env: {OWNER_TOKEN: 'fixture-owner'}})).proofs[0].verdict,
    'not_reproduced');
    assert.equal((await regression()).code, 0);
    assert.ok(issued >= 6, 'each control and retest must obtain its own nonce');
    assert.ok(exchanges.every(item => item.cacheControl === 'no-cache' &&
      [begin, complete, privatePath].includes(item.path)));
  });
