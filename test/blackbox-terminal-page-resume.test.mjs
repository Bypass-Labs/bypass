import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import http from 'node:http';
import {spawn} from 'node:child_process';

const waitExit = child => new Promise(resolve => child.once('exit', resolve));

test('CLI resume executes an accepted lead after the final Muse route page',
  {timeout: 90000}, async t => {
    const root = fs.mkdtempSync(path.join(os.tmpdir(), 'bypass-terminal-page-'));
    t.after(() => fs.rmSync(root, {recursive: true, force: true}));
    const route = '/api/terminal-deferred';
    const hits = [];
    const server = http.createServer((request, response) => {
      const url = new URL(request.url, 'http://fixture.invalid');
      hits.push(`${request.method} ${url.pathname}${url.search}`);
      response.setHeader('cache-control', 'no-store');
      if (url.pathname === '/') {
        response.writeHead(200, {'content-type': 'text/html'});
        response.end('<a href="/openapi.json">API reference</a>');
      } else if (url.pathname === '/openapi.json') {
        response.writeHead(200, {'content-type': 'application/json'});
        response.end(JSON.stringify({openapi: '3.0.0',
          info: {title: 'Terminal page fixture', version: '1'},
          paths: {[route]: {get: {parameters: [{in: 'query', name: 'q',
            schema: {type: 'string'}}], responses: {'200': {description: 'Value',
            content: {'application/json': {schema: {type: 'object',
              properties: {result: {type: 'string'}}}}}}}}}}}));
      } else if (url.pathname === route) {
        response.writeHead(200, {'content-type': 'application/json'});
        response.end(JSON.stringify({result: url.searchParams.get('q') ?? ''}));
      } else {
        response.writeHead(404, {'content-type': 'application/json'});
        response.end('{"error":"missing"}');
      }
    });
    await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
    t.after(() => server.close());
    const origin = `http://127.0.0.1:${server.address().port}`;
    fs.writeFileSync(path.join(root, 'blackbox.scope.json'), JSON.stringify({
      schemaVersion: 1, target: {origin}, include: ['/'],
      limits: {rps: 100, maxUrls: 50, minutes: 1, modelCalls: 25, tasks: 50}}));
    const runner = path.join(import.meta.dirname,
      'fixtures/blackbox-sequence-page-runner.mjs');
    const launch = resumeFrom => spawn(process.execPath,
      [runner, root, origin, resumeFrom ?? ''],
      {stdio: ['ignore', 'ignore', 'pipe']});
    const initial = launch();
    let initialError = '';
    initial.stderr.on('data', chunk => {initialError += chunk;});
    assert.equal(await waitExit(initial), 0, initialError);
    const prior = JSON.parse(fs.readFileSync(path.join(root,
      'initial-result.json'), 'utf8'));
    const priorFile = path.join(prior.runDir,
      'http-sequence-page-checkpoint.json');
    const checkpoint = JSON.parse(fs.readFileSync(priorFile, 'utf8'));
    const page = checkpoint.pages.find(item => item.pass === 'primary');
    assert.ok(page?.totalRoutes > 0, JSON.stringify(checkpoint));
    page.nextRouteOffset = page.totalRoutes;
    page.pendingLeads = [{proposalId: 'terminal-accepted-lead',
      family: 'query response', why: 'Observed public input', priority: 8,
      as: 'anonymous', oracle: 'observation', prelude: [], observe: [],
      binding: null, protectedPath: '',
      subject: {method: 'GET', path: route, placement: 'query', key: 'q',
        fixedFields: [], bodyTemplate: '', headers: []},
      controlValue: 'plain', firstValue: 'terminal-one',
      secondValue: 'terminal-two', marker: '', secondMarker: '',
      assertion: {step: 'subject', index: 0, location: 'body', name: ''}}];
    page.pendingCompletedIds = [];
    page.pendingActiveById = {};
    fs.writeFileSync(priorFile, JSON.stringify(checkpoint));
    assert.equal(hits.filter(hit => hit === `GET ${route}?q=terminal-one`).length, 0);

    const resumed = launch(prior.run);
    let resumedError = '';
    resumed.stderr.on('data', chunk => {resumedError += chunk;});
    assert.equal(await waitExit(resumed), 0, resumedError);
    assert.ok(hits.some(hit => hit === `GET ${route}?q=terminal-one`),
      'the accepted terminal-page lead reached the scoped HTTP runner');
    const result = JSON.parse(fs.readFileSync(path.join(root,
      'resumed-result.json'), 'utf8'));
    const ledger = fs.readFileSync(path.join(result.runDir,
      'evidence.jsonl'), 'utf8').trim().split('\n').map(line => JSON.parse(line));
    assert.equal(ledger.filter(item => item.kind === 'model-http-sequence-attempt' &&
      item.path === route).length, 1);
    const saved = JSON.parse(fs.readFileSync(path.join(result.runDir,
      'http-sequence-page-checkpoint.json'), 'utf8'));
    assert.ok(!saved.pages.find(item => item.pass === 'primary').pendingLeads?.length);
  });
