import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import http from 'node:http';
import os from 'node:os';
import path from 'node:path';
import {randomBytes} from 'node:crypto';
import {loadScope, createRequester} from '../src/blackbox/scope.mjs';
import {createLedger} from '../src/blackbox/ledger.mjs';
import {planAccessBoundaries, runAccessBoundaries} from '../src/blackbox/access-boundary.mjs';
import {proveFindings, verifyRun, exportRun} from '../src/blackbox/poc.mjs';
import {check} from '../src/blackbox/poc-runtime.mjs';
import {execFile} from '../src/util.mjs';

test('observed GET query exposes an owner-only object and sealed regression clears after repair', async t => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'bypass-boundary-get-'));
  t.after(() => fs.rmSync(root, {recursive: true, force: true}));
  const suffix = randomBytes(4).toString('hex');
  const recordId = `private-${suffix}`;
  const protectedPath = `/api/${suffix}/record/${recordId}`;
  const queryPath = `/api/${suffix}/lookup`;
  const record = {id: recordId, title: `owner title ${suffix}`, owner: 'fixture owner'};
  let repaired = false;
  let firstPositive = true;
  const seen = [];
  const server = http.createServer((request, response) => {
    const url = new URL(request.url, 'http://fixture');
    response.setHeader('content-type', 'application/json');
    response.setHeader('cache-control', 'no-store');
    seen.push({path: url.pathname, method: request.method, query: url.search});
    if (request.method === 'GET' && url.pathname === protectedPath) {
      response.statusCode = request.headers.authorization === 'Bearer fixture-owner' ? 200 : 403;
      return response.end(JSON.stringify(response.statusCode === 200 ? record : {error: 'denied'}));
    }
    if (request.method === 'GET' && url.pathname === queryPath) {
      const term = url.searchParams.get('term');
      const exposed = !repaired && (term === 'wide-two' || firstPositive && term === 'wide-one');
      return response.end(JSON.stringify({records: exposed ? [record] :
        [{id: recordId, title: 'public decoy', owner: 'public'}]}));
    }
    response.statusCode = 404;
    response.end(JSON.stringify({error: 'missing'}));
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  t.after(() => new Promise(resolve => server.close(resolve)));
  const origin = `http://127.0.0.1:${server.address().port}`;
  const scopeFile = path.join(root, 'scope.json');
  fs.writeFileSync(scopeFile, JSON.stringify({schemaVersion: 1, target: {origin},
    include: ['/'], identities: {identityPath: protectedPath}, limits: {rps: 100}}));
  const scope = loadScope({file: scopeFile, origin}).scope;
  const env = {...process.env, OWNER_TOKEN: 'fixture-owner'};
  const surface = {patterns: [
    {pattern: protectedPath, methods: ['GET'], params: {},
      fingerprint: {owner: {status: 200}, anonymous: {status: 403}}},
    {pattern: queryPath, methods: ['GET'], params: {term: ['plain']},
      fingerprint: {anonymous: {status: 200}}}], jsonBodyOperations: []};
  const proposal = {family: 'query access boundary', why: 'The public lookup may include an owner-only record',
    priority: 8, protectedPath,
    subject: {method: 'GET', path: queryPath, placement: 'query', key: 'term', fixedFields: []},
    controlValue: 'plain', firstValue: 'wide-one', secondValue: 'wide-two',
    ownerPointer: '', candidatePointer: '/records', identityField: 'id',
    matchFields: ['id', 'title', 'owner']};
  const infer = async (_model, messages) => {
    const context = JSON.parse(messages[1].content);
    assert.deepEqual(context.publicGets[0].fields, ['term']);
    assert.equal(context.protectedReads[0].path, protectedPath);
    return {tests: [{...proposal, subject: {...proposal.subject, key: 'unobserved'}}, proposal]};
  };
  const plan = await planAccessBoundaries(surface, scope, {infer, model: 'fixture', env,
    budget: 2, modelCallsAvailable: 1});
  assert.equal(plan.leads.length, 1);
  assert.equal(plan.coverage.getsSent, 1);
  assert.deepEqual(plan.decisions.map(item => item.reason), ['unobserved-field', undefined]);
  const run = 'bx-20261028-abcdef12';
  const runDir = path.join(root, '.bypass/runs', run);
  fs.mkdirSync(runDir, {recursive: true});
  fs.writeFileSync(path.join(runDir, 'run.json'), JSON.stringify({run, status: 'complete'}));
  const ledger = createLedger(runDir);
  const requester = createRequester(scope, {ledger, env, allowLocal: true});
  const result = await runAccessBoundaries(plan.leads, scope, {requester, surface, env});
  assert.equal(result.results[0].verdict, 'confirmed', JSON.stringify(result.results));
  assert.equal(result.findings.length, 1);
  assert.equal(result.findings[0].webProof.request.method, 'GET');
  const findings = [{...result.findings[0], id: 'f-001'}];
  const kept = await proveFindings(findings, [], {runDir, surface, scope, env, ledger,
    web: {results: result.results}});
  assert.equal(kept.length, 1, fs.readFileSync(ledger.file, 'utf8').slice(-1200));
  ledger.close();
  const sealed = JSON.parse(fs.readFileSync(path.join(runDir, 'poc/f-001/spec.json')));
  assert.deepEqual(sealed.reviewedGetInputs, [{path: queryPath, parameters: ['term']}]);
  assert.equal(JSON.stringify(sealed).includes('fixture-owner'), false);
  assert.equal((await verifyRun(root, run, {env})).proofs[0].verdict, 'confirmed');
  assert.equal((await check({...sealed, reviewedGetInputs: []}, env)).verdict, 'inconclusive');
  firstPositive = false;
  assert.equal((await check(sealed, env)).verdict, 'confirmed',
    'a single positive must repeat with fresh owner and anonymous controls');
  const exported = exportRun(root, run, {out: path.join(root, 'regression')});
  const testEnv = {...env, NODE_TEST_CONTEXT: undefined};
  const regression = () => execFile(process.execPath, ['--test', ...exported.files],
    {env: testEnv, timeout: 20000});
  assert.equal((await regression()).code, 1);
  repaired = true;
  assert.equal((await verifyRun(root, run, {env})).proofs[0].verdict, 'not_reproduced');
  assert.equal((await regression()).code, 0);
  assert.ok(seen.every(item => item.method === 'GET' &&
    [queryPath, protectedPath].includes(item.path)));
});
