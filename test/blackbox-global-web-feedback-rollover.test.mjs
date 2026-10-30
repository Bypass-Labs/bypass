import test from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import {createHash} from 'node:crypto';
import {loadScope} from '../src/blackbox/scope.mjs';
import {runWebProbes} from '../src/blackbox/web-probes.mjs';

test('a Muse GET observation gets a revision while global model calls remain',
  {timeout: 15000}, async t => {
    const seen = [];
    const server = http.createServer((request, response) => {
      const value = new URL(request.url, 'http://fixture').searchParams.get('expression');
      seen.push(value);
      response.writeHead(200, {'content-type': 'application/json',
        'cache-control': 'no-store'});
      response.end(JSON.stringify({result: value}));
    });
    await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
    t.after(() => new Promise(resolve => server.close(resolve)));
    const origin = `http://127.0.0.1:${server.address().port}`;
    const {scope} = loadScope({origin, overrides: {acceptLocal: true, rps: 100}});
    const route = '/api/evaluate';
    const surface = {patterns: [{pattern: route, methods: ['GET'],
      params: {expression: ['plain']}, source: ['public-openapi'],
      responseFacts: {status: 200, type: 'application/json'}}]};
    let modelCalls = 0, revisionCalls = 0, evidence = 0;
    const experiment = (context, version) => ({
      family: 'observed-expression-behavior', path: route,
      parameter: 'expression', oracle: 'observation',
      controlValue: `plain-${version}`,
      firstValue: `candidate-one-${version}`,
      secondValue: `candidate-two-${version}`,
      marker: context.canary, secondMarker: context.secondCanary,
      prelude: [], headers: [], priority: 10,
      why: 'Compare the documented expression response'});
    const infer = async (_model, messages) => {
      modelCalls++;
      const prompt = messages[0].content;
      const context = JSON.parse(messages[1].content);
      if (prompt.startsWith('Allocate the next black-box investigation effort'))
        return {priorities: [
          {name: 'web', weight: 100, why: 'Observed expression input'},
          {name: 'sequence', weight: 1, why: 'Observed GET route'},
        ]};
      if (prompt.startsWith('Rank only the supplied observed read-only web-test candidates'))
        return {priorities: [], strategies: [], experiments: [experiment(context, 0)]};
      if (prompt.startsWith('Revise one inconclusive or negative, observed, read-only GET experiment')) {
        revisionCalls++;
        return {experiments: revisionCalls === 1 ? [experiment(context, 1)] : []};
      }
      return {priorities: [], strategies: [], experiments: [], flows: [],
        checks: [], tests: []};
    };
    const requester = async ({url, method = 'GET', body, headers = {}}) => {
      const response = await fetch(new URL(url, origin), {method, body,
        headers, redirect: 'manual'});
      const content = await response.text();
      return {status: response.status, type: response.headers.get('content-type'),
        body: content, bytes: Buffer.byteLength(content),
        hash: createHash('sha256').update(content).digest('hex'),
        headers: Object.fromEntries(response.headers), cached: false,
        evidenceId: `ev-${String(++evidence).padStart(4, '0')}`};
    };
    const run = await runWebProbes(surface, scope, {requester, infer,
      model: {model: 'fixture'}, budget: 12, maxModelPages: 3,
      remainingModelCalls: () => 100 - modelCalls,
      researchDeadline: Date.now() + 10000});
    assert.ok(run.strategyDecisions.some(item =>
      item.mode === 'experiment' && item.accepted),
    'Muse must first admit the observed GET experiment');
    assert.ok(seen.includes('candidate-one-0'),
      'the first inconclusive experiment must execute through HTTP');
    assert.ok(modelCalls < 100, 'the global Muse budget remains available');
    assert.ok(revisionCalls >= 1,
      `local planning allocation stranded a GET experiment despite ${100 - modelCalls} global calls left`);
    assert.ok(seen.includes('candidate-one-1'),
      'Muse feedback must produce a second executed HTTP attempt');
  });
