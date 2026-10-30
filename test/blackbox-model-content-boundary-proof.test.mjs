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

test('Muse-selected protected text disclosure has sealed proof and red-green regression', async t => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'bypass-content-proof-'));
  t.after(() => fs.rmSync(root, {recursive: true, force: true}));
  const suffix = randomBytes(4).toString('hex');
  const protectedPath = `/private/${suffix}/statement`;
  const lookupPath = `/public/${suffix}/download`;
  const decoyPath = `/private/${suffix}/delete`;
  const privateBody = `Owner-only export ${suffix}: ` +
    `billing details and account annotations for this test identity. `.repeat(3);
  let repaired = false, decoyHits = 0;
  const seen = [];
  const server = http.createServer((request, response) => {
    const url = new URL(request.url, 'http://fixture');
    seen.push({method: request.method, path: url.pathname,
      cacheControl: request.headers['cache-control']});
    response.setHeader('content-type', 'text/plain; charset=utf-8');
    response.setHeader('cache-control', 'no-store');
    if (url.pathname === decoyPath) {decoyHits++; response.statusCode = 405;
      return response.end('Protected decoy');}
    if (request.method === 'GET' && url.pathname === protectedPath) {
      if (request.headers.authorization !== 'Bearer fixture-owner') {
        response.statusCode = 403; return response.end('Owner only');
      }
      return response.end(privateBody);
    }
    if (request.method === 'GET' && url.pathname === lookupPath) {
      const name = url.searchParams.get('name');
      return response.end(!repaired && ['all', 'archive'].includes(name) ?
        privateBody : `Public file ${name ?? 'none'}.`);
    }
    response.statusCode = 404;
    response.end('Not found');
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  t.after(() => new Promise(resolve => server.close(resolve)));
  const origin = `http://127.0.0.1:${server.address().port}`;
  const scopeFile = path.join(root, 'scope.json');
  fs.writeFileSync(scopeFile, JSON.stringify({schemaVersion: 1, target: {origin},
    include: ['/'], identities: {identityPath: protectedPath},
    never: [decoyPath], limits: {rps: 100}}));
  const scope = loadScope({file: scopeFile, origin}).scope;
  const env = {...process.env, OWNER_TOKEN: 'fixture-owner'};
  const surface = {patterns: [
    {pattern: protectedPath, methods: ['GET'], params: {},
      fingerprint: {owner: {status: 200, type: 'text/plain',
        bytes: Buffer.byteLength(privateBody)}, anonymous: {status: 403}}},
    {pattern: lookupPath, methods: ['GET'], params: {name: ['normal']},
      fingerprint: {anonymous: {status: 200}}}], jsonBodyOperations: []};
  const proposal = {family: 'private content disclosure',
    why: 'A public download selector may expose owner-only content', priority: 8,
    comparison: 'exact-body', protectedPath,
    subject: {method: 'GET', path: lookupPath, placement: 'query',
      key: 'name', fixedFields: []},
    controlValue: 'normal', firstValue: 'all', secondValue: 'archive',
    ownerPointer: '', candidatePointer: '', identityField: '', matchFields: []};
  const infer = async () => ({tests: [proposal]});
  const plan = await planAccessBoundaries(surface, scope, {infer,
    model: 'fixture', env, budget: 1, modelCallsAvailable: 1});
  assert.equal(plan.leads.length, 1);
  const run = 'bx-20261028-abcdef23';
  const runDir = path.join(root, '.bypass/runs', run);
  fs.mkdirSync(runDir, {recursive: true});
  fs.writeFileSync(path.join(runDir, 'run.json'), JSON.stringify({run, status: 'complete'}));
  const ledger = createLedger(runDir);
  const requester = createRequester(scope, {ledger, env, allowLocal: true});
  const result = await runAccessBoundaries(plan.leads, scope,
    {requester, surface, env});
  assert.equal(result.results[0].verdict, 'confirmed');
  const findings = [{...result.findings[0], id: 'f-001'}];
  const kept = await proveFindings(findings, [], {runDir, surface, scope,
    env, ledger, web: {results: result.results}});
  assert.equal(kept.length, 1);
  ledger.close();
  const spec = JSON.parse(fs.readFileSync(path.join(runDir, 'poc/f-001/spec.json')));
  assert.equal(spec.comparison, 'exact-body');
  assert.equal(JSON.stringify(spec).includes(privateBody), false);
  assert.equal(JSON.stringify(spec).includes('fixture-owner'), false);
  assert.equal((await verifyRun(root, run, {env})).proofs[0].verdict, 'confirmed');
  assert.equal((await check({...spec, reviewedGetInputs: []}, env)).verdict,
    'inconclusive');
  const exported = exportRun(root, run, {out: path.join(root, 'regression')});
  const regression = () => execFile(process.execPath, ['--test', ...exported.files],
    {env: {...env, NODE_TEST_CONTEXT: undefined}, timeout: 20000});
  assert.equal((await regression()).code, 1);
  repaired = true;
  assert.equal((await verifyRun(root, run, {env})).proofs[0].verdict,
    'not_reproduced');
  assert.equal((await regression()).code, 0);
  assert.equal(decoyHits, 0);
  assert.ok(seen.every(item => item.method === 'GET' &&
    [protectedPath, lookupPath].includes(item.path) &&
    item.cacheControl === 'no-cache'));
});
