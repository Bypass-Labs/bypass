import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import {loadScope} from '../src/blackbox/scope.mjs';
import {runWebProbes} from '../src/blackbox/web-probes.mjs';

test('sequence-first planning starts accepted access and JSON work before sequence feedback ends',
  {timeout: 15000}, async t => {
    const root = fs.mkdtempSync(path.join(os.tmpdir(), 'bypass-track-fairness-'));
    t.after(() => fs.rmSync(root, {recursive: true, force: true}));
    const origin = 'http://127.0.0.1:49389';
    const scopeFile = path.join(root, 'scope.json');
    fs.writeFileSync(scopeFile, JSON.stringify({schemaVersion: 1,
      target: {origin}, probes: {jsonPostPaths: ['/api/transform']}}));
    const scope = loadScope({file: scopeFile, origin,
      overrides: {acceptLocal: true}}).scope;
    const surface = {patterns: [
      {pattern: '/private/item', methods: ['GET'], params: {},
        responseFacts: {identity: 'derived-session', status: 200,
          anonymousStatus: 401, type: 'application/json'}},
      ...Array.from({length: 12}, (_, index) => ({
        pattern: index ? `/query-${index}` : '/query', methods: ['GET'],
        params: {q: ['plain']}, responseFacts: {status: 200,
          type: 'application/json'}}))],
      jsonBodyOperations: [{path: '/api/transform', method: 'POST',
        contentType: 'application/json', fields: ['value'],
        requiredFields: []}]};
    const events = [];
    let releaseFeedback;
    const feedbackGate = new Promise(resolve => {releaseFeedback = resolve;});
    const releaseWhenBothStarted = () => {
      if (events.includes('access-http') && events.includes('json-http'))
        releaseFeedback();
    };
    let sequencePages = 0, evidence = 0;
    const respond = (status, value) => {
      const body = JSON.stringify({value});
      return {status, body, bytes: body.length, type: 'application/json',
        headers: {'content-type': 'application/json',
          'cache-control': 'no-store'}, evidenceId: `ev-${++evidence}`};
    };
    const requester = async ({url, method = 'GET', body,
      identity = 'anonymous'}) => {
      const target = new URL(url, origin);
      if (target.pathname === '/api/transform' && method === 'POST') {
        events.push('json-http');
        releaseWhenBothStarted();
        return respond(200, JSON.parse(body).value);
      }
      if (target.pathname === '/private/item')
        return respond(identity === 'derived' ? 200 : 401,
          identity === 'derived' ? 'private record '.repeat(10) : 'denied');
      if (target.pathname === '/query' &&
          target.searchParams.get('q') === 'access-one') {
        events.push('access-http');
        releaseWhenBothStarted();
      }
      return respond(200, target.searchParams.get('q') ?? 'plain');
    };
    const flow = context => ({family: 'query-response',
      why: 'Compare a reviewed query input', priority: 8,
      as: 'anonymous', oracle: 'observation', protectedPath: '',
      prelude: [], observe: [], binding: null,
      subject: {method: 'GET', path: '/query', placement: 'query',
        key: 'q', fixedFields: [], bodyTemplate: '', headers: []},
      controlValue: 'sequence-plain', firstValue: 'sequence-one',
      secondValue: 'sequence-two', marker: context.marker,
      secondMarker: context.secondMarker,
      assertion: {step: 'subject', index: 0, location: 'body', name: ''}});
    const infer = async (_model, messages) => {
      const prompt = messages[0].content;
      const context = JSON.parse(messages[1].content);
      if (prompt.startsWith('Allocate the next black-box investigation effort'))
        return {priorities: ['sequence', 'access', 'json', 'web', 'stored']
          .map((name, index) => ({name, weight: 100 - index * 15,
            why: 'Reviewed routes and fields'}))};
      if (prompt.startsWith('You are investigating whether an observed anonymous GET'))
        return {tests: [{family: 'Record boundary',
          why: 'Compare a protected item with a public query', priority: 8,
          comparison: 'exact-body', protectedPath: '/private/item',
          subject: {method: 'GET', path: '/query', placement: 'query',
            key: 'q', fixedFields: []}, controlValue: 'plain',
          firstValue: 'access-one', secondValue: 'access-two',
          ownerPointer: '', candidatePointer: '', identityField: '',
          matchFields: []}]};
      if (prompt.startsWith('Select distinct harmless response-transformation experiments'))
        return {experiments: [{family: 'Transform response',
          path: '/api/transform', field: 'value', as: 'anonymous',
          oracle: 'observation', controlValue: 'plain',
          firstValue: 'json-one', secondValue: 'json-two',
          marker: context.marker, secondMarker: context.secondMarker,
          fixedFields: [], prelude: [], observePath: '', observeAs: 'anonymous',
          why: 'Inspect the observed transform field', priority: 8}]};
      if (prompt.startsWith('You are planning bounded, authorized HTTP research.'))
        return {flows: ++sequencePages === 1 ? [flow(context)] : []};
      if (prompt.startsWith('Revise at most one bounded, authorized HTTP experiment')) {
        events.push('sequence-feedback-start');
        await new Promise(resolve => {
          const timeout = setTimeout(resolve, 800);
          feedbackGate.then(() => {clearTimeout(timeout); resolve();});
        });
        events.push('sequence-feedback-end');
        return {flows: []};
      }
      return {priorities: [], strategies: [], experiments: [], flows: [],
        tests: [], checks: []};
    };
    const run = await runWebProbes(surface, scope, {requester, infer,
      model: {model: 'fixture'}, budget: 100, maxModelPages: 35,
      remainingModelCalls: () => 35, researchDeadline: Date.now() + 10000,
      derivedSession: {loginProof: {kind: 'fixture'},
        requestAuthenticated: async () => respond(200,
          'private record '.repeat(10))}});
    assert.ok(sequencePages > 1, 'the later sequence page was planned');
    assert.ok(events.includes('access-http') && events.includes('json-http'),
      `accepted tracks must execute: ${events.join(', ')}`);
    assert.ok(events.includes('sequence-feedback-end'),
      `the sequence feedback loop did not run: ${events.join(', ')}`);
    assert.ok(events.indexOf('access-http') < events.indexOf('sequence-feedback-end') &&
      events.indexOf('json-http') < events.indexOf('sequence-feedback-end'),
    `accepted tracks waited behind sequence feedback: ${events.join(', ')}`);
    assert.ok(run.results.some(item => item.kind === 'model-access-boundary' &&
      item.verdict !== 'untested'));
    assert.ok(run.results.some(item => item.kind.startsWith('model-json') &&
      item.verdict !== 'untested'));
  });
