import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import http from 'node:http';
import {randomBytes} from 'node:crypto';
import {spawn} from 'node:child_process';
import {loadScope} from '../src/blackbox/scope.mjs';
import {planResearchFlows} from '../src/blackbox/research-flow.mjs';
import {runWebProbes} from '../src/blackbox/web-probes.mjs';

const sleep = ms => new Promise(resolve => setTimeout(resolve, ms));
const waitExit = child => new Promise(resolve => child.once('exit', resolve));

test('an interrupted Muse route-page run resumes the next page without repeating page one',
  {timeout: 180000}, async t => {
    const root = fs.mkdtempSync(path.join(os.tmpdir(), 'bypass-sequence-page-'));
    t.after(() => {if (!process.env.BX_KEEP_TEST_ROOT)
      fs.rmSync(root, {recursive: true, force: true});});
    const suffix = randomBytes(4).toString('hex');
    const routes = Array.from({length: 20}, (_, index) => `/api/${suffix}/r${index}`);
    const server = http.createServer((request, response) => {
      const url = new URL(request.url, 'http://127.0.0.1');
      response.setHeader('cache-control', 'no-store');
      if (url.pathname === '/') {
        response.writeHead(200, {'content-type': 'text/html'});
        response.end('<html><a href="/openapi.json">API reference</a></html>');
      } else if (url.pathname === '/openapi.json') {
        response.writeHead(200, {'content-type': 'application/json'});
        response.end(JSON.stringify({openapi: '3.0.0', info: {title: 'Fixture', version: '1'},
          paths: Object.fromEntries(routes.map(route => [route, {get: {
            summary: 'Read a public value', parameters: [{in: 'query', name: 'q',
              schema: {type: 'string'}}], responses: {'200': {description: 'Value',
              content: {'application/json': {schema: {type: 'object',
                properties: {result: {type: 'string'}}}}}}}}}]))}));
      } else if (routes.includes(url.pathname) && request.method === 'GET') {
        response.writeHead(200, {'content-type': 'application/json'});
        response.end(JSON.stringify({result: url.searchParams.get('q') ?? ''}));
      } else {
        response.writeHead(404, {'content-type': 'application/json'});
        response.end('{"error":"not found"}');
      }
    });
    await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
    t.after(() => server.close());
    const origin = `http://127.0.0.1:${server.address().port}`;
    const scopeFile = path.join(root, 'blackbox.scope.json');
    const scope = {schemaVersion: 1, target: {origin}, include: ['/'],
      limits: {rps: 100, maxUrls: 100, minutes: 3, modelCalls: 60, tasks: 100}};
    fs.writeFileSync(scopeFile, JSON.stringify(scope));
    const runner = path.join(import.meta.dirname,
      'fixtures/blackbox-sequence-page-runner.mjs');
    const launch = (resumeFrom = '', extraEnv = {}) => spawn(process.execPath,
      [runner, root, origin, resumeFrom], {stdio: ['ignore', 'ignore', 'pipe'],
        env: {...process.env, ...extraEnv}});
    const first = launch('', {BX_SLOW_PAGE2: '1'});
    t.after(() => {if (first.exitCode == null) first.kill('SIGKILL');});
    const runsDir = path.join(root, '.bypass/runs');
    const pageLog = path.join(root, 'sequence-pages.jsonl');
    let runId, checkpoint;
    const until = Date.now() + 50000;
    while (Date.now() < until) {
      const found = fs.existsSync(runsDir) ? fs.readdirSync(runsDir).find(name =>
        fs.existsSync(path.join(runsDir, name,
          'http-sequence-page-checkpoint.json'))) : null;
      if (found) {
        runId = found;
        checkpoint = JSON.parse(fs.readFileSync(path.join(runsDir, found,
          'http-sequence-page-checkpoint.json'), 'utf8'));
        const firstPageSaved = checkpoint.pages?.some(item => item.pass === 'primary' &&
          item.nextRouteOffset > 0 && item.nextRouteOffset < item.totalRoutes);
        const secondPageSent = fs.existsSync(pageLog) &&
          fs.readFileSync(pageLog, 'utf8').split('\n').filter(Boolean).length >= 2;
        if (firstPageSaved && secondPageSent) break;
      }
      if (first.exitCode != null) break;
      await sleep(50);
    }
    const page = checkpoint?.pages?.find(item => item.pass === 'primary');
    assert.ok(page && page.nextRouteOffset > 0 &&
      page.nextRouteOffset < page.totalRoutes,
    JSON.stringify({root, runId, checkpoint}));
    first.kill('SIGKILL');
    await waitExit(first);
    const firstPages = fs.readFileSync(pageLog, 'utf8')
      .trim().split('\n').map(line => JSON.parse(line));
    assert.ok(firstPages.length >= 2, JSON.stringify(firstPages));
    const firstPagePath = firstPages[0].routes.find(route => route.startsWith('/api/'));
    assert.ok(firstPagePath);
    const firstLedger = fs.readFileSync(path.join(runsDir, runId, 'evidence.jsonl'), 'utf8');
    assert.ok(firstLedger.includes(firstPagePath));

    // Existing reviewed-scope enforcement still applies to page continuation.
    fs.writeFileSync(scopeFile, JSON.stringify({...scope, never: [firstPagePath]}));
    const drift = launch(runId);
    let driftError = '';
    drift.stderr.on('data', chunk => { driftError += chunk; });
    const driftExit = await waitExit(drift);
    assert.equal(driftExit, 1);
    assert.match(driftError, /different scope or target/);
    fs.writeFileSync(scopeFile, JSON.stringify(scope));

    const resumed = launch(runId);
    let resumedError = '';
    resumed.stderr.on('data', chunk => { resumedError += chunk; });
    const resumedExit = await waitExit(resumed);
    assert.equal(resumedExit, 0, `${resumedError}\n${root}`);
    const result = JSON.parse(fs.readFileSync(path.join(root,
      'resumed-result.json'), 'utf8'));
    const resumedPages = fs.readFileSync(path.join(root, 'sequence-pages.jsonl'), 'utf8')
      .trim().split('\n').map(line => JSON.parse(line)).filter(item => item.resumed);
    assert.ok(resumedPages.length, root);
    assert.ok(!resumedPages[0].routes.includes(firstPagePath),
      JSON.stringify(resumedPages[0]));
    assert.ok(resumedPages[0].priorSequenceResults?.some(item =>
      item.path === firstPagePath), JSON.stringify(resumedPages[0]));
    const resumedLedger = fs.readFileSync(path.join(result.runDir,
      'evidence.jsonl'), 'utf8').trim().split('\n').map(line => JSON.parse(line));
    assert.equal(resumedLedger.filter(item => item.kind ===
      'model-http-sequence-attempt' && item.path === firstPagePath).length, 0);
    assert.ok(resumedLedger.some(item => item.kind ===
      'model-http-sequence-attempt' && item.path !== firstPagePath));
    const started = JSON.parse(fs.readFileSync(path.join(result.runDir,
      'run-start.json'), 'utf8'));
    assert.equal(started.resumedFrom, runId);
  });

test('derived-session page continuation starts after its saved route prefix', async () => {
  const origin = 'http://127.0.0.1:43998';
  const scope = loadScope({origin, overrides: {acceptLocal: true}}).scope;
  const surface = {origin, patterns: Array.from({length: 20}, (_, index) => ({
    pattern: `/api/derived/r${index}`, methods: ['GET'],
    params: {q: []}, source: ['authenticated-recon'],
    responseFacts: {status: 200, type: 'application/json',
      shape: {result: 'string'}}}))};
  const pages = [];
  const infer = async (_model, messages) => {
    const system = messages[0].content;
    if (system.startsWith('Allocate the next black-box investigation effort'))
      return {priorities: ['sequence', 'web', 'access', 'session', 'stored', 'json']
        .map(name => ({name, weight: name === 'sequence' ? 100 : 1,
          why: 'Observed authenticated query routes'}))};
    if (system.startsWith('You are planning bounded, authorized HTTP research.')) {
      const context = JSON.parse(messages[1].content);
      pages.push(context.routes.map(item => item.path));
      return {flows: []};
    }
    return {flows: [], priorities: [], strategies: [], experiments: []};
  };
  let saved;
  await planResearchFlows(surface, scope, {infer, model: {model: 'fixture'},
    budget: 20, modelCallsAvailable: 1,
    onPageCheckpoint: item => { saved = item; }});
  assert.ok(saved.nextRouteOffset > 0 &&
    saved.nextRouteOffset < saved.totalRoutes);
  const pageOnePath = pages[0][0];
  pages.length = 0;
  const requester = async () => ({status: 200, type: 'application/json',
    body: '{"result":""}', headers: {}, bytes: 13,
    shape: {result: 'string'}, evidenceId: 'ev-0001'});
  const result = await runWebProbes(surface, scope, {requester, infer,
    model: {model: 'fixture'}, budget: 50, maxModelPages: 20,
    derivedSession: {loginProof: {kind: 'fixture'},
      requestAuthenticated: requester},
    flowPagePass: 'derived-late',
    resumeResearch: {kind: 'http-sequence-page', pass: 'derived-late',
      origin, ...saved}});
  assert.ok(pages.length, JSON.stringify(result.modelCoverage));
  assert.ok(!pages[0].includes(pageOnePath), JSON.stringify(pages[0]));
  assert.ok(result.modelCoverage.httpSequenceSent > 0);
});
