import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import http from 'node:http';
import path from 'node:path';
import {randomBytes} from 'node:crypto';
import {temp} from './helpers.mjs';
import {DEFAULT_SCOPE} from '../src/blackbox/scope.mjs';
import {createLedger, verifyLedger} from '../src/blackbox/ledger.mjs';
import {proveFindings, verifyRun, exportRun} from '../src/blackbox/poc.mjs';

test('independent anonymous exposure proofs overlap but commit evidence in finding order',
  {timeout: 30000}, async t => {
    const project = temp();
    const run = 'bx-20261029-7654abcd';
    const runDir = path.join(project, '.bypass/runs', run);
    fs.mkdirSync(runDir, {recursive: true});
    fs.writeFileSync(path.join(runDir, 'run.json'), '{}');
    t.after(() => fs.rmSync(project, {recursive: true, force: true}));
    const suffix = randomBytes(4).toString('hex');
    const paths = [`/leak-${suffix}-one`, `/leak-${suffix}-two`];
    let vulnerable = true, active = 0, peak = 0;
    const server = http.createServer(async (request, response) => {
      active++;
      peak = Math.max(peak, active);
      await new Promise(resolve => setTimeout(resolve, 180));
      active--;
      response.writeHead(vulnerable && paths.includes(request.url) ? 200 : 403,
        {'content-type': 'text/plain', 'cache-control': 'no-store'});
      response.end(vulnerable && paths.includes(request.url) ?
        'DEMO_SETTING=fixture\nMODE=test\n' : 'Denied');
    });
    await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
    t.after(() => new Promise(resolve => server.close(resolve)));
    const origin = `http://127.0.0.1:${server.address().port}`;
    const scope = structuredClone(DEFAULT_SCOPE);
    scope.target.origin = origin;
    scope.credentialOrigins = [origin];
    scope.limits.rps = 40;
    scope.limits.agents = 4;
    const findings = paths.map((route, index) => ({
      id: `f-${String(index + 1).padStart(3, '0')}`, kind: 'exposure',
      pattern: route, url: `${origin}${route}`, confirmation: []}));
    const surface = {patterns: [], exposures: paths.map(route => ({
      path: route, signature: 'environment key-value lines'}))};
    const kept = await proveFindings(findings, [], {runDir, surface, scope,
      env: {}, ledger: createLedger(runDir), web: {results: []}});
    assert.deepEqual(kept.map(item => item.id), ['f-001', 'f-002']);
    assert.ok(peak >= 2, 'the server must receive overlapping independent proof requests');
    const records = fs.readFileSync(path.join(runDir, 'evidence.jsonl'), 'utf8')
      .trim().split('\n').map(line => JSON.parse(line));
    const proofRecords = records.filter(item => item.step === 'poc' && item.proof?.path);
    assert.deepEqual(proofRecords.map(item => path.basename(path.dirname(item.proof.path))),
      ['f-001', 'f-002']);
    assert.deepEqual(kept.map(item => item.confirmation[0]),
      proofRecords.map(item => item.id));
    const schedule = records.find(item => item.kind === 'proof-schedule');
    assert.equal(schedule.workerPeak, 2);
    assert.equal(schedule.parallelProofs, 2);
    assert.equal(verifyLedger(path.join(runDir, 'evidence.jsonl')).ok, true);
    const replay = await verifyRun(project, run, {env: {}});
    assert.deepEqual(replay.proofs.map(item => item.verdict), ['confirmed', 'confirmed']);
    assert.equal(exportRun(project, run, {out: path.join(project, 'regression')}).files.length, 2);
    vulnerable = false;
    const fixed = await verifyRun(project, run, {env: {}});
    assert.deepEqual(fixed.proofs.map(item => item.verdict),
      ['not_reproduced', 'not_reproduced']);
  });
