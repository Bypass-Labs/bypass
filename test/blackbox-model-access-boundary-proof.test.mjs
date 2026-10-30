import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import http from 'node:http';
import os from 'node:os';
import path from 'node:path';
import {randomBytes} from 'node:crypto';
import {boundaryMatch, validBoundaryShape} from '../src/blackbox/boundary-oracle.mjs';
import {check} from '../src/blackbox/poc-runtime.mjs';
import {proveFindings, verifyRun, exportRun} from '../src/blackbox/poc.mjs';
import {createLedger} from '../src/blackbox/ledger.mjs';
import {loadScope} from '../src/blackbox/scope.mjs';
import {execFile} from '../src/util.mjs';

test('boundary oracle requires an owner-only object and two exact primitive fields', () => {
  const plan = {protectedPath: '/api/private/item-41',
    subject: {method: 'POST', path: '/api/filter', placement: 'json', key: 'q',
      fixedFields: [{field: 'tenant', value: 'demo'}]},
    controlValue: 'plain', firstValue: 'one', secondValue: 'two',
    ownerPointer: '', candidatePointer: '/records', identityField: 'id',
    matchFields: ['id', 'label']};
  const owner = JSON.stringify({id: 'item-41', label: 'private label', token: 'must-stay-private'});
  assert.equal(validBoundaryShape(plan), true);
  assert.deepEqual(boundaryMatch(owner, JSON.stringify({records: [
    {id: 'item-41', label: 'private label'}]}), plan),
    {match: true, ownerValid: true, candidateCount: 1});
  assert.equal(boundaryMatch(owner, JSON.stringify({records: [
    {id: 'item-41', label: 'different'}]}), plan).match, false);
  assert.equal(boundaryMatch(owner, JSON.stringify({records: []}), plan).match, false);
  assert.equal(boundaryMatch(JSON.stringify({id: 'another', label: 'private label'}),
    JSON.stringify({records: [{id: 'another', label: 'private label'}]}), plan).match, true,
    'a protected route alias need not end with its returned record ID');
  assert.equal(validBoundaryShape({...plan, matchFields: ['id']}), false);
  assert.equal(validBoundaryShape({...plan, subject: {...plan.subject,
    fixedFields: [{field: 'q', value: 'demo'}]}}), false);
});

test('sealed generic access-boundary PoC and exported regression turn green after repair', async t => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'bypass-boundary-proof-'));
  t.after(() => fs.rmSync(root, {recursive: true, force: true}));
  const suffix = randomBytes(4).toString('hex');
  const recordId = `item-${suffix}`;
  const protectedPath = `/api/private/member-${suffix}`;
  const postPath = `/api/filter-${suffix}`;
  const ownerRecord = {id: recordId, label: 'private label', owner: 'fixture owner'};
  let fixed = false, firstPositive = true;
  const seenPosts = [];
  const server = http.createServer(async (request, response) => {
    const url = new URL(request.url, 'http://fixture');
    response.setHeader('content-type', 'application/json');
    response.setHeader('cache-control', 'no-store');
    if (request.method === 'GET' && url.pathname === protectedPath) {
      response.statusCode = request.headers.authorization === 'Bearer fixture-owner' ? 200 : 403;
      return response.end(JSON.stringify(response.statusCode === 200 ? ownerRecord :
        {error: 'forbidden'}));
    }
    if (request.method === 'POST' && url.pathname === postPath) {
      const chunks = [];
      for await (const chunk of request) chunks.push(chunk);
      const body = JSON.parse(Buffer.concat(chunks).toString());
      seenPosts.push(body);
      if (body.tenant !== 'demo') {
        response.statusCode = 400;
        return response.end(JSON.stringify({error: 'tenant required'}));
      }
      const exposed = !fixed && (body.q === 'wide-two' ||
        firstPositive && body.q === 'wide-one');
      return response.end(JSON.stringify({records: exposed ? [ownerRecord] :
        [{id: recordId, label: 'public decoy'}]}));
    }
    response.statusCode = 404;
    response.end(JSON.stringify({error: 'missing'}));
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  t.after(() => new Promise(resolve => server.close(resolve)));
  const origin = `http://127.0.0.1:${server.address().port}`;
  const scopePath = path.join(root, 'scope.json');
  fs.writeFileSync(scopePath, JSON.stringify({schemaVersion: 1, target: {origin},
    include: ['/'], probes: {jsonPostPaths: [postPath]}, limits: {rps: 50}}));
  const scope = loadScope({file: scopePath, origin}).scope;
  const env = {...process.env, OWNER_TOKEN: 'fixture-owner'};
  const webProof = {protectedPath, subject: {method: 'POST', path: postPath,
    placement: 'json', key: 'q', fixedFields: [{field: 'tenant', value: 'demo'}]},
  controlValue: 'plain', firstValue: 'wide-one', secondValue: 'wide-two',
  ownerPointer: '', candidatePointer: '/records', identityField: 'id',
  matchFields: ['id', 'label']};
  const spec = {schemaVersion: 1, id: 'f-001', kind: 'model-access-boundary',
    origin, include: ['/'], never: [], rps: 50, expiresAt: null,
    identities: {owner: 'OWNER_TOKEN'}, auth: 'bearer',
    targetEnvironment: 'local', reviewedPostPaths: {json: [postPath]},
    reviewedPostFields: ['q', 'tenant'], ...webProof};
  const direct = await check(spec, env);
  assert.equal(direct.verdict, 'confirmed', JSON.stringify(direct));
  firstPositive = false;
  const singlePositive = await check(spec, env);
  assert.equal(singlePositive.verdict, 'confirmed', JSON.stringify(singlePositive));
  assert.ok(singlePositive.controls.some(item => item.label === 'positive-repeat' &&
    item.positive === 'second' && item.ownerObjectMatched));
  assert.ok(singlePositive.controls.some(item => item.label === 'baseline-final' &&
    item.excludesOwnerObject));
  const run = 'bx-20261028-abcdef12';
  const runDir = path.join(root, '.bypass/runs', run);
  fs.mkdirSync(runDir, {recursive: true});
  fs.writeFileSync(path.join(runDir, 'run.json'), JSON.stringify({run, status: 'complete'}));
  const ledger = createLedger(runDir);
  const finding = {id: 'f-001', kind: 'model-access-boundary', verdict: 'confirmed',
    severity: 'high', pattern: postPath, url: new URL(postPath, origin).href,
    confirmation: [], webProof};
  const surface = {patterns: [], jsonBodyOperations: [{method: 'POST', path: postPath,
    fields: ['q', 'tenant'], requiredFields: ['tenant']}], exposures: []};
  const kept = await proveFindings([finding], [], {runDir, surface, scope, env,
    ledger, web: {results: []}});
  assert.equal(kept.length, 1, fs.readFileSync(ledger.file, 'utf8').slice(-1200));
  ledger.close();
  const sealedSpec = JSON.parse(fs.readFileSync(path.join(runDir, 'poc/f-001/spec.json')));
  assert.deepEqual(sealedSpec.reviewedPostFields, ['q', 'tenant']);
  assert.equal(JSON.stringify(sealedSpec).includes('fixture-owner'), false);
  assert.equal((await verifyRun(root, run, {env})).proofs[0].verdict, 'confirmed');
  const oraclePath = path.join(runDir, 'poc/boundary-oracle.mjs');
  const oracle = fs.readFileSync(oraclePath, 'utf8');
  fs.appendFileSync(oraclePath, '\n// altered after proof\n');
  await assert.rejects(() => verifyRun(root, run, {env}), /modified boundary oracle/);
  fs.writeFileSync(oraclePath, oracle);
  const exported = exportRun(root, run, {out: path.join(root, 'regression')});
  assert.equal(exported.files.length, 1);
  assert.ok(fs.existsSync(path.join(exported.output, 'boundary-oracle.mjs')));
  const testEnv = {...env, NODE_TEST_CONTEXT: undefined};
  const regression = () => execFile(process.execPath, ['--test', ...exported.files],
    {env: testEnv, timeout: 20000});
  assert.equal((await regression()).code, 1);
  fixed = true;
  assert.equal((await verifyRun(root, run, {env})).proofs[0].verdict, 'not_reproduced');
  assert.equal((await regression()).code, 0);
  assert.ok(seenPosts.every(item => item.tenant === 'demo'));
});
