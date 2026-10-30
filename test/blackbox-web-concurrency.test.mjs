import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import http from 'node:http';
import os from 'node:os';
import path from 'node:path';
import {createLedger, verifyLedger} from '../src/blackbox/ledger.mjs';
import {summaryText} from '../src/blackbox/report.mjs';
import {createLimiter, createRequester, loadScope} from '../src/blackbox/scope.mjs';
import {runWebProbes} from '../src/blackbox/web-probes.mjs';

test('anonymous web workers overlap independent controls and keep verdicts in lead order',
  {timeout: 20000}, async t => {
    const root = fs.mkdtempSync(path.join(os.tmpdir(), 'bypass-web-workers-'));
    t.after(() => fs.rmSync(root, {recursive: true, force: true}));
    let active = 0, mostActive = 0;
    const completedPaths = [];
    const server = http.createServer(async (request, response) => {
      const url = new URL(request.url, 'http://fixture.invalid');
      if (!['/jump-safe', '/jump-open'].includes(url.pathname)) {
        response.writeHead(404); response.end(); return;
      }
      active++;
      mostActive = Math.max(mostActive, active);
      await new Promise(resolve => setTimeout(resolve,
        url.pathname === '/jump-safe' ? 320 : 100));
      active--;
      completedPaths.push(url.pathname);
      response.writeHead(302, {location: url.pathname === '/jump-open' ?
        url.searchParams.get('next') : '/safe', 'cache-control': 'no-store'});
      response.end();
    });
    await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
    t.after(() => new Promise(resolve => server.close(resolve)));
    const origin = `http://127.0.0.1:${server.address().port}`;
    const scope = loadScope({origin, overrides: {acceptLocal: true,
      agents: 2, rps: 40}}).scope;
    const ledger = createLedger(root, {run: 'worker-test'});
    t.after(() => ledger.close());
    const requester = createRequester(scope, {ledger,
      limiter: createLimiter(scope.limits.rps), allowLocal: true});
    const surface = {patterns: ['/jump-safe', '/jump-open'].map(pattern =>
      ({pattern, methods: ['GET'], params: {next: ['/safe']},
        responseFacts: {status: 302, type: 'text/plain'}, source: ['public-link']}))};
    const run = await runWebProbes(surface, scope, {requester, ledger, budget: 2,
      researchDeadline: Date.now() + 10000});
    assert.ok(mostActive >= 2, `expected overlapping HTTP controls, saw ${mostActive}`);
    assert.equal(completedPaths[0], '/jump-open',
      'the later ranked check completed first on the server');
    assert.deepEqual(run.results.map(item => [item.kind, item.lead.path, item.verdict]), [
      ['open-redirect', '/jump-safe', 'not_reproduced'],
      ['open-redirect', '/jump-open', 'confirmed'],
    ]);
    assert.deepEqual(run.findings.map(item => [item.kind, item.pattern]),
      [['open-redirect', '/jump-open']]);
    assert.equal(run.modelCoverage.webWorkersConfigured, 2);
    assert.equal(run.modelCoverage.webWorkersPeak, 2);
    assert.equal(run.modelCoverage.concurrentAnonymousReadsStarted, 2);
    assert.match(summaryText({run: 'worker-test', origin, runDir: root,
      stats: {webWorkersPeak: run.modelCoverage.webWorkersPeak,
        webWorkersConfigured: run.modelCoverage.webWorkersConfigured}}),
    /Web workers\s+2 active at peak · 2 configured/);
    assert.equal(new Set(run.results.map(item => item.leadKey)).size, 2);
    assert.equal(verifyLedger(ledger.file).ok, true);
  });

test('a deferred model experiment does not serialize ready web checks', async () => {
  const scope = loadScope({origin: 'http://127.0.0.1:4337',
    overrides: {acceptLocal: true, agents: 2}}).scope;
  const surface = {patterns: ['/jump-one', '/jump-two'].map(pattern => ({
    pattern, methods: ['GET'], params: {next: ['/safe']},
    responseFacts: {status: 302, type: 'text/plain'}, source: ['public-link']}))};
  let active = 0, peak = 0, requests = 0;
  const requester = async request => {
    active++;
    peak = Math.max(peak, active);
    await new Promise(resolve => setTimeout(resolve, 20));
    active--;
    const url = new URL(request.url, scope.target.origin);
    const body = url.pathname === '/candidate' ? '{}' : '';
    return {status: url.pathname === '/candidate' ? 200 : 302,
      type: url.pathname === '/candidate' ? 'application/json' : 'text/plain',
      body, rawBody: body, bytes: body.length, hash: body,
      headers: {location: '/safe'}, evidenceId: `ev-${++requests}`};
  };
  const experiment = {path: '/candidate', parameter: 'x', as: 'anonymous',
    family: 'observed-input-behavior', why: 'Test a read-only candidate',
    oracle: 'observation', controlValue: 'plain', firstValue: 'one',
    secondValue: 'two', marker: '', secondMarker: '', prelude: [], headers: []};
  const run = await runWebProbes(surface, scope, {requester, budget: 3,
    carryForward: [{kind: 'model-differential', lead: experiment, priority: 10}]});
  assert.equal(run.modelCoverage.webWorkersPeak, 2);
  assert.ok(peak >= 2, `expected overlapping ready web checks, saw ${peak}`);
  assert.equal(run.results.filter(item => item.kind === 'open-redirect').length, 2);
  assert.equal(run.results.filter(item => item.kind === 'model-differential').length, 1);
});

test('fresh independent Muse GET experiments overlap and keep ordered checkpoints', async () => {
  const scope = loadScope({origin: 'http://127.0.0.1:4338',
    overrides: {acceptLocal: true, agents: 2}}).scope;
  const surface = {patterns: ['/candidate-one', '/candidate-two'].map(pattern => ({
    pattern, methods: ['GET'], params: {x: ['plain']},
    responseFacts: {status: 200, type: 'application/json'}, source: ['public-link']}))};
  const carryForward = ['/candidate-one', '/candidate-two'].map(path => ({
    kind: 'model-differential', priority: 10,
    lead: {path, parameter: 'x', as: 'anonymous', family: 'observed-input-behavior',
      why: 'Compare an observed input', oracle: 'observation',
      controlValue: 'plain', firstValue: 'one', secondValue: 'two',
      marker: '', secondMarker: '', prelude: [], headers: []}}));
  let active = 0, peak = 0, requests = 0;
  const checkpoints = [];
  const requester = async () => {
    active++;
    peak = Math.max(peak, active);
    await new Promise(resolve => setTimeout(resolve, 20));
    active--;
    return {status: 200, type: 'application/json', body: '{}', rawBody: '{}',
      bytes: 2, hash: 'stable', headers: {}, evidenceId: `ev-${++requests}`};
  };
  const run = await runWebProbes(surface, scope, {requester, budget: 2,
    carryForward, onResearchCheckpoint: state => checkpoints.push({
      cursor: state.cursor, phase: state.active?.phase ?? null,
      modelCalls: state.modelCalls})});
  assert.ok(peak >= 2, `expected overlapping Muse GET experiments, saw ${peak}`);
  assert.equal(run.modelCoverage.adaptiveInitialWorkersPeak, 2);
  assert.equal(run.modelCoverage.adaptiveAttempts, 2);
  assert.equal(run.modelCoverage.adaptiveModelCalls, 0);
  assert.deepEqual(run.results.filter(item => item.kind === 'model-differential')
    .map(item => item.lead.path), ['/candidate-one', '/candidate-two']);
  assert.ok(checkpoints.some(item => item.cursor === 0 && item.phase === 'attempted'));
  assert.ok(checkpoints.some(item => item.cursor === 1 && item.phase === 'attempted'));
  assert.deepEqual(checkpoints.at(-1), {cursor: 2, phase: null, modelCalls: 0});
});

test('a fast Muse GET worker starts the next lead while another lead is slow', async () => {
  const scope = loadScope({origin: 'http://127.0.0.1:4339',
    overrides: {acceptLocal: true, agents: 2}}).scope;
  const paths = ['/slow', '/fast-one', '/fast-two'];
  const surface = {patterns: paths.map(pattern => ({pattern, methods: ['GET'],
    params: {x: ['plain']}, responseFacts: {status: 200, type: 'application/json'},
    source: ['public-link']}))};
  const carryForward = paths.map(path => ({kind: 'model-differential', priority: 10,
    lead: {path, parameter: 'x', as: 'anonymous', family: 'observed-input-behavior',
      why: 'Compare an observed input', oracle: 'observation',
      controlValue: 'plain', firstValue: 'one', secondValue: 'two',
      marker: '', secondMarker: '', prelude: [], headers: []}}));
  const completed = [], checkpoints = [];
  let active = 0, peak = 0, requests = 0;
  const requester = async request => {
    const url = new URL(request.url, scope.target.origin);
    active++;
    peak = Math.max(peak, active);
    await new Promise(resolve => setTimeout(resolve,
      url.pathname === '/slow' ? 50 : 2));
    active--;
    if (url.searchParams.get('x') === 'two') completed.push(url.pathname);
    return {status: 200, type: 'application/json', body: '{}', rawBody: '{}',
      bytes: 2, hash: 'stable', headers: {}, evidenceId: `ev-${++requests}`};
  };
  const run = await runWebProbes(surface, scope, {requester, budget: 3,
    carryForward, onResearchCheckpoint: state => checkpoints.push(state.cursor)});
  assert.equal(peak, 2);
  assert.ok(completed.indexOf('/fast-two') < completed.indexOf('/slow'),
    `expected the third lead before the slow lead; got ${completed.join(', ')}`);
  assert.deepEqual(run.results.filter(item => item.kind === 'model-differential')
    .map(item => item.lead.path), paths);
  assert.equal(run.modelCoverage.adaptiveAttempts, 3);
  assert.equal(run.modelCoverage.adaptiveModelCalls, 0);
  assert.equal(checkpoints.at(-1), 3);
});
