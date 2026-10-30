import test from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import {createHash} from 'node:crypto';
import {loadScope} from '../src/blackbox/scope.mjs';
import {runWebProbes} from '../src/blackbox/web-probes.mjs';

test('an inconclusive Muse sequence gets feedback while global model calls remain',
  {timeout: 15000}, async t => {
    const seen = [];
    const server = http.createServer((request, response) => {
      seen.push(request.url);
      response.writeHead(200, {'content-type': 'application/json',
        'cache-control': 'no-store'});
      response.end(JSON.stringify({items: []}));
    });
    await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
    t.after(() => new Promise(resolve => server.close(resolve)));
    const origin = `http://127.0.0.1:${server.address().port}`;
    const {scope} = loadScope({origin, overrides: {acceptLocal: true, rps: 100}});
    const route = '/api/lookup';
    const surface = {patterns: [{pattern: route, methods: ['GET'],
      params: {q: ['plain']}, responseFacts: {status: 200,
        type: 'application/json'}}]};
    let modelCalls = 0, revisionCalls = 0, evidence = 0;
    const flow = (context, version) => ({family: 'observed-query-behavior',
      why: 'Compare the documented query response', priority: 10,
      as: 'anonymous', oracle: 'observation', protectedPath: '',
      prelude: [], observe: [], binding: null,
      subject: {method: 'GET', path: route, placement: 'query', key: 'q',
        fixedFields: [], bodyTemplate: '', headers: []},
      controlValue: `plain-${version}`,
      firstValue: `candidate-one-${version}`,
      secondValue: `candidate-two-${version}`,
      marker: context.marker, secondMarker: context.secondMarker,
      assertion: {step: 'subject', index: 0, location: 'body', name: ''}});
    const infer = async (_model, messages) => {
      modelCalls++;
      const prompt = messages[0].content;
      const context = JSON.parse(messages[1].content);
      if (prompt.startsWith('Allocate the next black-box investigation effort'))
        return {priorities: [
          {name: 'sequence', weight: 100, why: 'Observed query contract'},
          {name: 'web', weight: 40, why: 'Observed response route'},
        ]};
      if (prompt.startsWith('You are planning bounded, authorized HTTP research.'))
        return {flows: [flow(context, 0)]};
      if (prompt.startsWith('Revise at most one bounded, authorized HTTP experiment')) {
        revisionCalls++;
        return {flows: revisionCalls === 1 ? [flow(context, 1)] : []};
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
    assert.ok(run.modelCoverage.httpSequenceAccepted >= 1,
      'Muse must first admit the observed HTTP sequence');
    assert.ok(seen.some(url => url.includes('candidate-one-0')),
      'the first inconclusive sequence must execute through HTTP');
    assert.ok(modelCalls < 100, 'the global Muse budget remains available');
    assert.ok(revisionCalls >= 1,
      `local planning allocation stranded an inconclusive sequence despite ${100 - modelCalls} global calls left`);
    assert.ok(seen.some(url => url.includes('candidate-one-1')),
      'Muse feedback must produce a second executed request');
  });

test('independent saved HTTP feedback turns overlap and keep their evidence separate',
  {timeout: 15000}, async t => {
    const server = http.createServer((request, response) => {
      response.writeHead(200, {'content-type': 'application/json',
        'cache-control': 'no-store'});
      response.end(JSON.stringify({route: new URL(request.url,
        'http://fixture.invalid').pathname, items: []}));
    });
    await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
    t.after(() => new Promise(resolve => server.close(resolve)));
    const origin = `http://127.0.0.1:${server.address().port}`;
    const {scope} = loadScope({origin, overrides: {acceptLocal: true,
      rps: 100, modelAgents: 2}});
    const routes = ['/api/read-one', '/api/read-two'];
    const surface = {patterns: routes.map(pattern => ({pattern,
      methods: ['GET'], params: {q: ['plain']}, responseFacts: {
        status: 200, type: 'application/json'}}))};
    let modelCalls = 0, evidence = 0, planningPages = 0;
    let activeRevisions = 0, peakRevisions = 0;
    const flow = (context, route) => ({family: 'observed read behavior',
      why: `Compare the observed ${route} query`, priority: 10,
      as: 'anonymous', oracle: 'observation', protectedPath: '',
      prelude: [], observe: [], binding: null,
      subject: {method: 'GET', path: route, placement: 'query', key: 'q',
        fixedFields: [], bodyTemplate: '', headers: []},
      controlValue: 'plain', firstValue: 'first', secondValue: 'second',
      marker: context.marker, secondMarker: context.secondMarker,
      assertion: {step: 'subject', index: 0, location: 'body', name: ''}});
    const infer = async (_model, messages) => {
      modelCalls++;
      const prompt = messages[0].content;
      const context = JSON.parse(messages[1].content);
      if (prompt.startsWith('Allocate the next black-box investigation effort'))
        return {priorities: [{name: 'sequence', weight: 100,
          why: 'Two observed query routes'}, {name: 'web', weight: 20,
          why: 'Ordinary response checks'}]};
      if (prompt.startsWith('You are planning bounded, authorized HTTP research.'))
        return {flows: ++planningPages === 1 ? routes.map(route => flow(context, route)) : []};
      if (prompt.startsWith('Revise at most one bounded, authorized HTTP experiment')) {
        activeRevisions++;
        peakRevisions = Math.max(peakRevisions, activeRevisions);
        await new Promise(resolve => setTimeout(resolve, 100));
        activeRevisions--;
        return {flows: []};
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
      model: {model: 'fixture'}, budget: 20, maxModelPages: 3,
      remainingModelCalls: () => 100 - modelCalls,
      researchDeadline: Date.now() + 10000});
    assert.equal(run.modelCoverage.httpSequenceAccepted, 2);
    assert.ok(run.modelCoverage.httpSequenceFeedbackRolloverCalls >= 2,
      `expected both ready continuations to receive a call: ${JSON.stringify(run.modelCoverage)}`);
    assert.equal(peakRevisions, 2,
      'independent HTTP feedback revisions must overlap');
    const investigations = run.investigations.filter(item =>
      routes.includes(item.initial?.path));
    assert.equal(investigations.length, 2);
    for (const item of investigations)
      assert.ok(item.attempts.every(attempt => attempt.path === item.initial.path),
        'each Muse worker saw only its own route history');
  });
