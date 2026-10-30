import test from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import {createHash} from 'node:crypto';
import {loadScope} from '../src/blackbox/scope.mjs';
import {runWebProbes} from '../src/blackbox/web-probes.mjs';

test('early web checks update outer progress while Muse sequence feedback is running',
  {timeout: 10000}, async t => {
    const server = http.createServer((_request, response) => {
      response.writeHead(200, {'content-type': 'application/json',
        'cache-control': 'no-store'});
      response.end('{"items":[]}');
    });
    await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
    t.after(() => new Promise(resolve => server.close(resolve)));
    const origin = 'http://127.0.0.1:' + server.address().port;
    const {scope} = loadScope({origin, overrides: {acceptLocal: true,
      agents: 2, rps: 100}});
    const route = '/api/search';
    const surface = {patterns: [{pattern: route, methods: ['GET'],
      params: {q: ['plain']}, responseFacts: {status: 200,
        type: 'application/json'}, source: ['public-openapi']}]};
    let requestCount = 0, revisionEntered;
    const revisionStarted = new Promise(resolve => {revisionEntered = resolve;});
    let releaseRevision;
    const revisionWait = new Promise(resolve => {releaseRevision = resolve;});
    const progress = [];
    const infer = async (_model, messages) => {
      const prompt = messages[0].content;
      const context = JSON.parse(messages[1].content);
      if (prompt.startsWith('Allocate the next black-box investigation effort'))
        return {priorities: [
          {name: 'sequence', weight: 100, why: 'Observed query route'},
          {name: 'web', weight: 80, why: 'Observed read input'},
        ]};
      if (prompt.startsWith('You are planning bounded, authorized HTTP research.'))
        return {flows: [{family: 'observed-query-behavior',
          why: 'Compare the observed search input', priority: 9,
          as: 'anonymous', oracle: 'observation', protectedPath: '',
          prelude: [], observe: [], binding: null,
          subject: {method: 'GET', path: route, placement: 'query', key: 'q',
            fixedFields: [], bodyTemplate: '', headers: []},
          controlValue: 'plain-0', firstValue: 'candidate-one-0',
          secondValue: 'candidate-two-0', marker: context.marker,
          secondMarker: context.secondMarker,
          assertion: {step: 'subject', index: 0, location: 'body', name: ''}}]};
      if (prompt.startsWith('Revise at most one bounded, authorized HTTP experiment')) {
        revisionEntered();
        await revisionWait;
        return {flows: []};
      }
      return {priorities: [], strategies: [], experiments: [],
        flows: [], tests: [], checks: []};
    };
    const requester = async ({url, method = 'GET', body, headers = {}}) => {
      requestCount++;
      const response = await fetch(new URL(url, origin), {method, body, headers,
        redirect: 'manual'});
      const content = await response.text();
      return {status: response.status, type: response.headers.get('content-type'),
        body: content, bytes: Buffer.byteLength(content),
        hash: createHash('sha256').update(content).digest('hex'),
        headers: Object.fromEntries(response.headers), cached: false,
        evidenceId: 'ev-' + requestCount};
    };
    const audit = runWebProbes(surface, scope, {requester, infer,
      model: {model: 'fixture'}, budget: 16, maxModelPages: 12,
      remainingModelCalls: () => 100,
      researchDeadline: Date.now() + 8000,
      onProgressCheckpoint: state => progress.push(state)});
    let timeoutId;
    let liveProgress = false;
    let result;
    try {
      await Promise.race([
        revisionStarted,
        audit.then(() => {throw Error('sequence revision never started');}),
        new Promise((_, reject) => {timeoutId = setTimeout(() =>
          reject(Error('sequence revision did not start in time')), 3000);}),
      ]);
      assert.ok(requestCount > 0, 'an early web check should execute first');
      liveProgress = progress.some(state => state.phase === 'running' &&
        state.completed > 0 && state.planned >= state.completed);
    } finally {
      clearTimeout(timeoutId);
      releaseRevision();
      result = await audit;
    }
    assert.ok(result.modelCoverage.earlyWebChecksExecuted > 0,
      'the fixture must finish an early web check before sequence feedback');
    assert.ok(liveProgress,
      'outer progress stayed stale while the early web pool completed work');
  });
