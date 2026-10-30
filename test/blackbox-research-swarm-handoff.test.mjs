import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import {loadScope} from '../src/blackbox/scope.mjs';
import {runResearchSwarm} from '../src/blackbox/web-probes.mjs';

test('a ready stateful handoff starts before an unrelated slow investigator finishes',
  {timeout: 10000}, async t => {
    const root = fs.mkdtempSync(path.join(os.tmpdir(), 'bypass-handoff-queue-'));
    t.after(() => fs.rmSync(root, {recursive: true, force: true}));
    const origin = 'http://127.0.0.1:49397';
    const scopeFile = path.join(root, 'scope.json');
    fs.writeFileSync(scopeFile, JSON.stringify({schemaVersion: 1,
      target: {origin}, include: ['/'],
      probes: {jsonPostPaths: ['/api/post']},
      limits: {rps: 100, modelConcurrency: 2, modelCalls: 4,
        maxUrls: 30, minutes: 1}}));
    const scope = loadScope({file: scopeFile, origin,
      overrides: {acceptLocal: true}}).scope;
    const surface = {patterns: ['/api/read-a', '/api/read-b'].map(pattern =>
      ({pattern, methods: ['GET'], params: {q: ['clean']},
        source: ['public-openapi'], responseFacts: {status: 200,
          type: 'application/json'}})),
    jsonBodyOperations: [{path: '/api/post', method: 'POST',
      contentType: 'application/json', fields: ['value'], requiredFields: [],
      source: ['public-openapi']}]};
    const leads = ['/api/read-a', '/api/read-b'].map((route, index) => ({
      proposalId: `lead-${index}`, family: 'observed read',
      why: `Test the reviewed ${route} input`, priority: 8,
      as: 'anonymous', oracle: 'observation', prelude: [], observe: [],
      subject: {method: 'GET', path: route, placement: 'query', key: 'q',
        fixedFields: [], bodyTemplate: '', headers: []},
      controlValue: 'clean', firstValue: 'one', secondValue: 'two',
      marker: '', secondMarker: '',
      assertion: {step: 'subject', index: 0, location: 'body', name: ''}}));
    const events = [], checkpoints = new Map();
    let evidence = 0;
    const requester = async ({url, method = 'GET'}) => {
      const route = new URL(url, origin).pathname;
      events.push(`${method} ${route}`);
      const body = '{"result":"stable"}';
      return {status: 200, type: 'application/json', body,
        bytes: Buffer.byteLength(body),
        headers: {'content-type': 'application/json',
          'cache-control': 'no-store'},
        evidenceId: `ev-${++evidence}`};
    };
    const infer = async (_model, messages) => {
      const route = JSON.parse(messages[1].content).recentAttempts?.[0]?.path;
      if (route === '/api/read-b') {
        events.push('slow-feedback-start');
        await new Promise(resolve => setTimeout(resolve, 700));
        events.push('slow-feedback-end');
        return {flows: []};
      }
      if (route !== '/api/read-a') return {flows: []};
      events.push('fast-feedback-done');
      return {flows: [{family: 'reviewed post pivot',
        why: 'Check the observed POST after the public read',
        priority: 8, as: 'anonymous', oracle: 'observation', prelude: [],
        subject: {method: 'POST', path: '/api/post', placement: 'json',
          key: 'value', fixedFields: [], bodyTemplate: '', headers: []},
        observe: [], controlValue: 'clean', firstValue: 'one',
        secondValue: 'two', marker: '', secondMarker: '',
        assertion: {step: 'subject', index: 0, location: 'body', name: ''}}]};
    };
    const run = await runResearchSwarm(leads, scope, {requester, infer,
      model: {model: 'fixture'}, surface, modelCallsAvailable: 4,
      remainingModelCalls: () => 4,
      onResearchCheckpoint: state => checkpoints.set(
        state.leads[0]?.proposalId, structuredClone(state)),
      researchDeadline: Date.now() + 5000});
    assert.ok(events.includes('fast-feedback-done') &&
      events.includes('slow-feedback-end') &&
      events.includes('POST /api/post'), events.join(', '));
    assert.ok(events.indexOf('POST /api/post') <
      events.indexOf('slow-feedback-end'),
    `the ready handoff waited for an unrelated peer: ${events.join(', ')}`);
    assert.deepEqual(run.results.map(item => item.proposalId),
      leads.map(item => item.proposalId));
    assert.ok(run.modelCalls <= 4);
    assert.equal(run.workersPeak, 2);
    for (const lead of leads)
      assert.equal(checkpoints.get(lead.proposalId)?.cursor, 1);
  });
