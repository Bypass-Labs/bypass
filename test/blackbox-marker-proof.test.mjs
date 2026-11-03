import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import http from 'node:http';
import os from 'node:os';
import path from 'node:path';
import {randomBytes} from 'node:crypto';
import {exec} from 'node:child_process';
import {createLedger} from '../src/blackbox/ledger.mjs';
import {proveFindings} from '../src/blackbox/poc.mjs';
import {createRequester, loadScope} from '../src/blackbox/scope.mjs';
import {runResearchFlows, validateResearchFlow} from '../src/blackbox/research-flow.mjs';
import {execFile} from '../src/util.mjs';

test('source-focused typed marker proof replays a POST with fresh response bindings', async t => {
  if (process.platform === 'win32') return t.skip('fixture uses the POSIX shell');
  const suffix = randomBytes(4).toString('hex');
  const begin = `/api/${suffix}/begin`;
  const execute = `/api/${suffix}/execute`;
  const marker = `bx${randomBytes(6).toString('hex')}`;
  const secondMarker = `bx${randomBytes(6).toString('hex')}`;
  const encode = text => `bx;printf '${[...text].map(char =>
    `\\${char.charCodeAt(0).toString(8).padStart(3, '0')}`).join('')}'`;
  const issued = new Set(), consumed = [];
  let vulnerable = true;
  const server = http.createServer(async (request, response) => {
    response.setHeader('content-type', 'application/json');
    response.setHeader('cache-control', 'no-store');
    if (request.method !== 'POST') {
      response.statusCode = 404;
      return response.end('{}');
    }
    let text = '';
    for await (const chunk of request) text += chunk;
    const body = JSON.parse(text);
    if (request.url === begin) {
      const challenge = randomBytes(16).toString('hex');
      issued.add(challenge);
      return response.end(JSON.stringify({challenge}));
    }
    if (request.url !== execute || !issued.delete(body.challenge)) {
      response.statusCode = 401;
      return response.end('{"error":"missing fresh challenge"}');
    }
    consumed.push(body.challenge);
    const output = vulnerable ? await new Promise(resolve =>
      exec(`echo Checking ${body.target}`, {timeout: 1000},
        (error, stdout) => resolve(error ? 'command failed' : stdout))) :
      `Checking ${body.target}`;
    response.end(JSON.stringify({output}));
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  t.after(() => new Promise(resolve => server.close(resolve)));
  const origin = `http://127.0.0.1:${server.address().port}`;
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'bypass-marker-proof-'));
  t.after(() => fs.rmSync(dir, {recursive: true, force: true}));
  const operations = [
    {method: 'POST', path: begin, placement: 'json', contentType: 'application/json',
      fields: ['user'], requiredFields: ['user']},
    {method: 'POST', path: execute, placement: 'json', contentType: 'application/json',
      fields: ['target', 'challenge'], requiredFields: ['target', 'challenge']},
  ];
  const scopeFile = path.join(dir, 'scope.json');
  fs.writeFileSync(scopeFile, JSON.stringify({schemaVersion: 1,
    target: {origin}, include: ['/api'], methods: ['GET', 'HEAD', 'POST'],
    probes: {jsonPostPaths: [begin, execute], writeOperations: operations.map(
      ({method, path, placement}) => ({method, path, placement}))},
    limits: {rps: 100}}));
  const scope = loadScope({file: scopeFile, origin}).scope;
  const surface = {patterns: [], methodOperations: operations,
    jsonBodyOperations: operations,
    focus: {findingId: `finding_${suffix}`, path: execute, method: 'POST',
      sourceSnapshotMatches: true, category: 'OS command injection',
      hypothesis: 'The target is interpolated into a shell command and may execute another command.',
      source: {file: 'src/fixture.ts', line: 42,
        quote: 'exec(`echo Checking ${target}`)'}}};
  const proposal = {family: 'source-grounded command output',
    why: 'Source shows the controlled target is interpolated into a shell command',
    priority: 8, as: 'anonymous', oracle: 'marker',
    prelude: [{method: 'POST', path: begin, placement: 'json', key: 'user',
      value: 'fixture-user', fixedFields: [], bodyTemplate: '', headers: []}],
    subject: {method: 'POST', path: execute, placement: 'json', key: 'target',
      fixedFields: [], bodyTemplate: '', headers: []},
    observe: [], binding: {from: 0, pointer: '/challenge', to: 'subject',
      index: 0, key: 'challenge'},
    controlValue: 'plain', firstValue: encode(marker),
    secondValue: encode(secondMarker), marker, secondMarker,
    assertion: {step: 'subject', index: 0, location: 'body', name: ''}};
  const reviewed = validateResearchFlow(proposal, surface, scope);
  assert.equal(reviewed.ok, true, JSON.stringify(reviewed));
  const ledger = createLedger(dir);
  t.after(() => ledger.close());
  const requester = createRequester(scope, {ledger, allowLocal: true});
  const unqualified = await runResearchFlows([reviewed.lead], scope, {
    surface: {...surface, focus: undefined}, ledger, requester,
    model: 'fixture', modelCallsAvailable: 1,
    infer: async () => ({flows: [{...proposal, oracle: 'marker-proof'}]})});
  assert.equal(unqualified.results[0].verdict, 'observed');
  assert.equal(unqualified.findings.length, 1,
    'the initial observation remains available for research');
  assert.equal(unqualified.findings[0].verdict, 'observed');
  const mismatched = await runResearchFlows([reviewed.lead], scope, {
    surface: {...surface, focus: {...surface.focus,
      revision: {status: 'mismatched'}}}, ledger, requester,
    modelCallsAvailable: 0});
  assert.equal(mismatched.results[0].verdict, 'observed');
  assert.equal(mismatched.findings[0].verdict, 'observed');
  const beforeFocused = consumed.length;
  const run = await runResearchFlows([reviewed.lead], scope, {surface, ledger,
    requester, modelCallsAvailable: 0});
  assert.ok(run.decisions.some(item =>
    item.mode === 'source-observation-to-marker-proof' && item.accepted));
  assert.equal(run.results[0].verdict, 'confirmed', JSON.stringify(run.results[0]));
  assert.equal(run.findings.length, 1);
  assert.equal(run.findings[0].webProof.oracle, 'marker-proof');
  assert.equal(consumed.length - beforeFocused, 9);
  assert.equal(new Set(consumed).size, consumed.length,
    'each phase must bind a fresh challenge');
  const proved = await proveFindings([{...run.findings[0], id: 'f-001'}], [],
    {runDir: dir, surface, scope, env: {}, ledger, web: run});
  assert.equal(proved.length, 1, 'the generated PoC must replay the same typed proof');
  assert.equal(consumed.length - beforeFocused, 15);
  vulnerable = false;
  const fixed = await execFile(process.execPath, [proved[0].proof, '--expect-fixed'],
    {env: process.env, timeout: 20000});
  assert.equal(fixed.code, 0, fixed.stdout);
});
