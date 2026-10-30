import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import http from 'node:http';
import os from 'node:os';
import path from 'node:path';
import {createHash} from 'node:crypto';
import {createLedger, verifyLedger} from '../src/blackbox/ledger.mjs';
import {createLimiter, createRequester, loadScope} from '../src/blackbox/scope.mjs';
import {runResearchSwarm, runWebProbes} from '../src/blackbox/web-probes.mjs';

test('research workers share Muse time while keeping controls, pivots and checkpoints separate',
  {timeout: 30000}, async t => {
    const root = fs.mkdtempSync(path.join(os.tmpdir(), 'bypass-research-workers-'));
    t.after(() => fs.rmSync(root, {recursive: true, force: true}));
    const events = [];
    const server = http.createServer(async (request, response) => {
      const url = new URL(request.url, 'http://fixture.invalid');
      events.push(`${request.method} ${url.pathname}`);
      response.writeHead(200, {'content-type': 'application/json',
        'cache-control': 'no-store'});
      if (request.method === 'POST' && url.pathname === '/api/post') {
        for await (const _ of request) { /* drain the reviewed small JSON body */ }
        return response.end('{"result":"post-ok"}');
      }
      if (request.method === 'GET' && ['/api/read-a', '/api/read-b'].includes(url.pathname))
        return response.end('{"result":"stable"}');
      response.statusCode = 404;
      response.end('{"error":"missing"}');
    });
    await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
    t.after(() => new Promise(resolve => server.close(resolve)));
    const origin = `http://127.0.0.1:${server.address().port}`;
    const scopeFile = path.join(root, 'scope.json');
    fs.writeFileSync(scopeFile, JSON.stringify({schemaVersion: 1,
      target: {origin}, include: ['/'], probes: {jsonPostPaths: ['/api/post']},
      limits: {rps: 100, agents: 1, modelConcurrency: 2,
        modelCalls: 4, maxUrls: 30, minutes: 1}}));
    const scope = loadScope({file: scopeFile, origin}).scope;
    const ledger = createLedger(root, {run: 'research-workers'});
    t.after(() => ledger.close());
    const requester = createRequester(scope, {ledger,
      limiter: createLimiter(scope.limits.rps), allowLocal: true});
    const surface = {patterns: ['/api/read-a', '/api/read-b'].map(pattern =>
      ({pattern, methods: ['GET'], params: {q: ['clean']},
        source: ['public-openapi'], responseFacts: {status: 200,
          type: 'application/json'}})), jsonBodyOperations: [{path: '/api/post',
      method: 'POST', contentType: 'application/json', fields: ['value'],
      requiredFields: [], source: ['public-openapi']}]};
    const leads = ['/api/read-a', '/api/read-b'].map((route, index) => ({
      proposalId: `proposal-${index}`, family: 'read contract',
      why: `Observed independent ${route} input`, priority: 8,
      as: 'anonymous', oracle: 'observation', prelude: [], observe: [],
      subject: {method: 'GET', path: route, placement: 'query', key: 'q',
        fixedFields: [], bodyTemplate: '', headers: []},
      controlValue: 'clean', firstValue: 'one', secondValue: 'two',
      marker: '', secondMarker: '',
      assertion: {step: 'subject', index: 0, location: 'body', name: ''}}));
    const checkpoints = new Map(), modelInputs = [];
    const checkpoint = state => {
      const id = state.leads[0]?.proposalId;
      assert.ok(id && state.leads.length === 1,
        'each concurrent checkpoint owns one accepted lead');
      const name = `http-sequence-page-${createHash('sha256').update(id)
        .digest('hex').slice(0, 12)}-checkpoint.json`;
      fs.writeFileSync(path.join(root, name), JSON.stringify(state));
      checkpoints.set(id, name);
    };
    let activeModels = 0, peakModels = 0;
    const infer = async (_model, messages) => {
      const context = JSON.parse(messages[1].content);
      const route = context.recentAttempts?.[0]?.path;
      assert.ok(['/api/read-a', '/api/read-b', '/api/post'].includes(route),
        JSON.stringify(context.recentAttempts));
      modelInputs.push({route, evidence: context.recentAttempts[0].evidence ?? []});
      events.push(`Muse start ${route}`);
      activeModels++;
      peakModels = Math.max(peakModels, activeModels);
      await new Promise(resolve => setTimeout(resolve, 90));
      activeModels--;
      events.push(`Muse end ${route}`);
      if (route !== '/api/read-a') return {flows: []};
      return {flows: [{family: 'post preview', why: 'Test the reviewed local POST',
        priority: 8, as: 'anonymous', oracle: 'observation', prelude: [],
        subject: {method: 'POST', path: '/api/post', placement: 'json',
          key: 'value', fixedFields: [], bodyTemplate: '', headers: []},
        observe: [], controlValue: 'clean', firstValue: 'one', secondValue: 'two',
        marker: '', secondMarker: '',
        assertion: {step: 'subject', index: 0, location: 'body', name: ''}}]};
    };
    const run = await runResearchSwarm(leads, scope, {requester, infer,
      model: {model: 'fixture'}, surface, ledger, modelCallsAvailable: 4,
      remainingModelCalls: () => 4, onResearchCheckpoint: checkpoint,
      researchDeadline: Date.now() + 15000});
    assert.equal(peakModels, 2,
      'two task-specific Muse revisions overlap even with one HTTP worker');
    assert.equal(run.workersPeak, 2);
    assert.equal(run.results.length, 2, 'the serial pivot did not duplicate a verdict');
    assert.deepEqual(run.results.map(item => item.proposalId),
      leads.map(item => item.proposalId));
    assert.ok(run.modelCalls <= 4);
    assert.ok(events.indexOf('POST /api/post') > events.indexOf('Muse end /api/read-a'),
      'the accepted POST pivot follows its own read feedback');
    const records = fs.readFileSync(ledger.file, 'utf8').trim().split('\n')
      .map(line => JSON.parse(line));
    const pathFor = id => new URL(records.find(item => item.id === id).request.url).pathname;
    const firstTaskInputs = modelInputs.filter(item => item.evidence.length);
    assert.deepEqual(firstTaskInputs.map(item => item.route).toSorted(),
      ['/api/read-a', '/api/read-b']);
    for (const item of firstTaskInputs)
      assert.ok(item.evidence.length && item.evidence.every(id =>
        pathFor(id) === item.route), 'Muse received only its task-specific read evidence');
    assert.equal(verifyLedger(ledger.file).ok, true);
    assert.equal(checkpoints.size, 2);
    assert.equal(new Set(checkpoints.values()).size, 2);
    for (const name of checkpoints.values()) {
      const state = JSON.parse(fs.readFileSync(path.join(root, name), 'utf8'));
      assert.equal(state.cursor, 1);
    }

    // Simulate a process interruption immediately after each accepted lead is
    // checkpointed, then replay both saved queues through the normal resume path.
    const interrupted = new Map();
    await assert.rejects(runResearchSwarm(leads, scope, {requester, infer,
      model: {model: 'fixture'}, surface, ledger, modelCallsAvailable: 2,
      remainingModelCalls: () => 2, researchDeadline: Date.now() + 15000,
      onResearchCheckpoint: state => {
        const id = state.leads[0]?.proposalId;
        interrupted.set(id, structuredClone(state));
        if (state.cursor === 0 && !state.active)
          throw Error('fixture interruption after durable checkpoint');
      }}), /fixture interruption/);
    assert.equal(interrupted.size, 2);
    for (const lead of leads) {
      const saved = interrupted.get(lead.proposalId);
      assert.equal(saved.cursor, 0);
      const resumed = await runWebProbes(surface, scope, {requester, ledger,
        infer, model: {model: 'fixture'}, budget: 1, resumeOnly: true,
        resumeResearch: {...saved, kind: 'http-sequence'},
        maxModelPages: 2, remainingModelCalls: () => 2,
        researchDeadline: Date.now() + 15000,
        onResumeCheckpoint: state => interrupted.set(lead.proposalId, state)});
      assert.equal(resumed.results.length, 1);
      assert.equal(interrupted.get(lead.proposalId).cursor, 1);
    }
  });

test('independent reviewed POST investigations start together and retain separate checkpoints',
  {timeout: 30000}, async t => {
    const root = fs.mkdtempSync(path.join(os.tmpdir(), 'bypass-post-workers-'));
    t.after(() => fs.rmSync(root, {recursive: true, force: true}));
    let active = 0, peak = 0;
    const server = http.createServer(async (request, response) => {
      active++;
      peak = Math.max(peak, active);
      for await (const _ of request) { /* drain a small reviewed body */ }
      await new Promise(resolve => setTimeout(resolve, 100));
      active--;
      response.writeHead(200, {'content-type': 'application/json'});
      response.end('{"result":"ok"}');
    });
    await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
    t.after(() => new Promise(resolve => server.close(resolve)));
    const origin = `http://127.0.0.1:${server.address().port}`;
    const scopeFile = path.join(root, 'scope.json');
    fs.writeFileSync(scopeFile, JSON.stringify({schemaVersion: 1,
      target: {origin}, include: ['/'],
      probes: {jsonPostPaths: ['/api/a', '/api/b']},
      limits: {rps: 100, agents: 1, modelConcurrency: 2,
        modelCalls: 4, maxUrls: 30, minutes: 1}}));
    const scope = loadScope({file: scopeFile, origin}).scope;
    const ledger = createLedger(root, {run: 'post-workers'});
    t.after(() => ledger.close());
    const requester = createRequester(scope, {ledger,
      limiter: createLimiter(scope.limits.rps), allowLocal: true});
    const surface = {patterns: [], jsonBodyOperations: ['/api/a', '/api/b']
      .map(path => ({path, method: 'POST', contentType: 'application/json',
        fields: ['value'], requiredFields: [], source: ['public-openapi']}))};
    const leads = ['/api/a', '/api/b'].map((route, index) => ({
      proposalId: `post-${index}`, family: 'reviewed POST',
      why: `Test the observed ${route} body`, priority: 8,
      as: 'anonymous', oracle: 'observation', prelude: [], observe: [],
      subject: {method: 'POST', path: route, placement: 'json', key: 'value',
        fixedFields: [], bodyTemplate: '', headers: []},
      controlValue: 'clean', firstValue: 'one', secondValue: 'two',
      marker: '', secondMarker: '',
      assertion: {step: 'subject', index: 0, location: 'body', name: ''}}));
    const checkpoints = new Map();
    const run = await runResearchSwarm(leads, scope, {requester,
      infer: async () => ({flows: []}), model: {model: 'fixture'}, surface,
      ledger, modelCallsAvailable: 4, remainingModelCalls: () => 4,
      researchDeadline: Date.now() + 15000,
      onResearchCheckpoint: state => checkpoints.set(
        state.leads[0]?.proposalId, structuredClone(state))});
    assert.equal(peak, 2, 'independent reviewed POSTs must overlap');
    assert.equal(run.workersPeak, 2);
    assert.deepEqual(run.results.map(item => item.proposalId),
      leads.map(item => item.proposalId));
    for (const lead of leads) assert.equal(checkpoints.get(lead.proposalId)?.cursor, 1);
  });

test('research queue starts another ready lead when a worker finishes before a slow lead',
  {timeout: 30000}, async t => {
    const root = fs.mkdtempSync(path.join(os.tmpdir(), 'bypass-ready-queue-'));
    t.after(() => fs.rmSync(root, {recursive: true, force: true}));
    const events = [];
    const server = http.createServer(async (request, response) => {
      const route = new URL(request.url, 'http://fixture.invalid').pathname;
      events.push(`start ${route}`);
      await new Promise(resolve => setTimeout(resolve, route === '/slow' ? 250 : 20));
      events.push(`end ${route}`);
      response.writeHead(200, {'content-type': 'application/json'});
      response.end('{"result":"ok"}');
    });
    await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
    t.after(() => new Promise(resolve => server.close(resolve)));
    const origin = `http://127.0.0.1:${server.address().port}`;
    const scopeFile = path.join(root, 'scope.json');
    fs.writeFileSync(scopeFile, JSON.stringify({schemaVersion: 1,
      target: {origin}, include: ['/'],
      limits: {rps: 100, agents: 1, modelConcurrency: 2,
        modelCalls: 4, maxUrls: 30, minutes: 1}}));
    const scope = loadScope({file: scopeFile, origin}).scope;
    const ledger = createLedger(root, {run: 'ready-queue'});
    t.after(() => ledger.close());
    const requester = createRequester(scope, {ledger,
      limiter: createLimiter(scope.limits.rps), allowLocal: true});
    const routes = ['/slow', '/fast-one', '/fast-two'];
    const surface = {patterns: routes.map(pattern => ({pattern, methods: ['GET'],
      params: {q: ['clean']}, source: ['public-openapi'],
      responseFacts: {status: 200, type: 'application/json'}}))};
    const leads = routes.map((route, index) => ({proposalId: `ready-${index}`,
      family: 'observed read', why: `Test ${route}`, priority: 8,
      as: 'anonymous', oracle: 'observation', prelude: [], observe: [],
      subject: {method: 'GET', path: route, placement: 'query', key: 'q',
        fixedFields: [], bodyTemplate: '', headers: []},
      controlValue: 'clean', firstValue: 'one', secondValue: 'two',
      marker: '', secondMarker: '',
      assertion: {step: 'subject', index: 0, location: 'body', name: ''}}));
    const run = await runResearchSwarm(leads, scope, {requester,
      infer: async () => ({flows: []}), model: {model: 'fixture'}, surface,
      ledger, modelCallsAvailable: 4, remainingModelCalls: () => 4,
      researchDeadline: Date.now() + 15000});
    assert.ok(events.indexOf('start /fast-two') < events.indexOf('end /slow'),
      `a free worker waited behind the slow lead: ${events.join(', ')}`);
    assert.deepEqual(run.results.map(item => item.proposalId),
      leads.map(item => item.proposalId));
  });

test('an accepted stateful pivot gets a turn before later queued baselines',
  {timeout: 30000}, async t => {
    const root = fs.mkdtempSync(path.join(os.tmpdir(), 'bypass-pivot-queue-'));
    t.after(() => fs.rmSync(root, {recursive: true, force: true}));
    const events = [];
    const server = http.createServer(async (request, response) => {
      const route = new URL(request.url, 'http://fixture.invalid').pathname;
      events.push(`${request.method} ${route}`);
      for await (const _ of request) { /* drain reviewed body */ }
      response.writeHead(200, {'content-type': 'application/json'});
      response.end('{"result":"ok"}');
    });
    await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
    t.after(() => new Promise(resolve => server.close(resolve)));
    const origin = `http://127.0.0.1:${server.address().port}`;
    const scopeFile = path.join(root, 'scope.json');
    fs.writeFileSync(scopeFile, JSON.stringify({schemaVersion: 1,
      target: {origin}, include: ['/'],
      probes: {jsonPostPaths: ['/api/post']},
      limits: {rps: 100, agents: 1, modelConcurrency: 2,
        modelCalls: 6, maxUrls: 30, minutes: 1}}));
    const scope = loadScope({file: scopeFile, origin}).scope;
    const ledger = createLedger(root, {run: 'pivot-queue'});
    t.after(() => ledger.close());
    const requester = createRequester(scope, {ledger,
      limiter: createLimiter(scope.limits.rps), allowLocal: true});
    const routes = ['/api/read-a', '/api/read-b', '/api/read-c'];
    const surface = {patterns: routes.map(pattern => ({pattern, methods: ['GET'],
      params: {q: ['clean']}, source: ['public-openapi'],
      responseFacts: {status: 200, type: 'application/json'}})),
    jsonBodyOperations: [{path: '/api/post', method: 'POST',
      contentType: 'application/json', fields: ['value'], requiredFields: [],
      source: ['public-openapi']}]};
    const leads = routes.map((route, index) => ({proposalId: `pivot-${index}`,
      family: 'observed read', why: `Test ${route}`, priority: 8,
      as: 'anonymous', oracle: 'observation', prelude: [], observe: [],
      subject: {method: 'GET', path: route, placement: 'query', key: 'q',
        fixedFields: [], bodyTemplate: '', headers: []},
      controlValue: 'clean', firstValue: 'one', secondValue: 'two',
      marker: '', secondMarker: '',
      assertion: {step: 'subject', index: 0, location: 'body', name: ''}}));
    const infer = async (_model, messages) => {
      const route = JSON.parse(messages[1].content).recentAttempts?.[0]?.path;
      if (route === '/api/read-b')
        await new Promise(resolve => setTimeout(resolve, 120));
      if (route !== '/api/read-a') return {flows: []};
      return {flows: [{family: 'reviewed post pivot', why: 'Check the observed POST',
        priority: 8, as: 'anonymous', oracle: 'observation', prelude: [],
        subject: {method: 'POST', path: '/api/post', placement: 'json', key: 'value',
          fixedFields: [], bodyTemplate: '', headers: []}, observe: [],
        controlValue: 'clean', firstValue: 'one', secondValue: 'two',
        marker: '', secondMarker: '',
        assertion: {step: 'subject', index: 0, location: 'body', name: ''}}]};
    };
    const run = await runResearchSwarm(leads, scope, {requester, infer,
      model: {model: 'fixture'}, surface, ledger, modelCallsAvailable: 6,
      remainingModelCalls: () => 6, researchDeadline: Date.now() + 15000});
    assert.ok(events.indexOf('POST /api/post') >= 0,
      `accepted POST pivot did not execute: ${events.join(', ')}`);
    assert.ok(events.indexOf('POST /api/post') < events.indexOf('GET /api/read-c'),
      `the accepted pivot waited behind the later baseline: ${events.join(', ')}`);
    assert.deepEqual(run.results.map(item => item.proposalId),
      leads.map(item => item.proposalId));
  });

test('a shared write prelude and subject do not overlap their controls',
  {timeout: 30000}, async t => {
    const root = fs.mkdtempSync(path.join(os.tmpdir(), 'bypass-shared-route-'));
    t.after(() => fs.rmSync(root, {recursive: true, force: true}));
    let activeWrites = 0, peakWrites = 0;
    const server = http.createServer(async (request, response) => {
      const route = new URL(request.url, 'http://fixture.invalid').pathname;
      for await (const _ of request) { /* drain reviewed body */ }
      if (request.method === 'POST' && route === '/api/shared') {
        activeWrites++;
        peakWrites = Math.max(peakWrites, activeWrites);
        await new Promise(resolve => setTimeout(resolve, 45));
        activeWrites--;
      }
      response.writeHead(200, {'content-type': 'application/json'});
      response.end('{"result":"ok"}');
    });
    await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
    t.after(() => new Promise(resolve => server.close(resolve)));
    const origin = `http://127.0.0.1:${server.address().port}`;
    const scopeFile = path.join(root, 'scope.json');
    fs.writeFileSync(scopeFile, JSON.stringify({schemaVersion: 1,
      target: {origin}, include: ['/'],
      probes: {jsonPostPaths: ['/api/shared']},
      limits: {rps: 100, agents: 1, modelConcurrency: 2,
        modelCalls: 4, maxUrls: 30, minutes: 1}}));
    const scope = structuredClone(loadScope({file: scopeFile, origin}).scope);
    scope.localAutoPostContracts = {'json /api/shared': {
      contentType: 'application/json', fields: ['value']}};
    const ledger = createLedger(root, {run: 'shared-route'});
    t.after(() => ledger.close());
    const requester = createRequester(scope, {ledger,
      limiter: createLimiter(scope.limits.rps), allowLocal: true});
    const surface = {patterns: [{pattern: '/api/read-a', methods: ['GET'],
      params: {q: ['clean']}, source: ['public-openapi'],
      responseFacts: {status: 200, type: 'application/json'}}],
    jsonBodyOperations: [{path: '/api/shared', method: 'POST',
      contentType: 'application/json', fields: ['value'], requiredFields: [],
      source: ['public-openapi']}]};
    const write = {method: 'POST', path: '/api/shared', placement: 'json',
      key: 'value', fixedFields: [], bodyTemplate: '', headers: []};
    const common = {family: 'shared-route', why: 'Test observed contracts',
      priority: 8, as: 'anonymous', oracle: 'observation', observe: [],
      controlValue: 'clean', firstValue: 'one', secondValue: 'two',
      marker: '', secondMarker: '',
      assertion: {step: 'subject', index: 0, location: 'body', name: ''}};
    const leads = [{...common, proposalId: 'shared-prelude',
      prelude: [{...write, value: 'seed'}],
      subject: {method: 'GET', path: '/api/read-a', placement: 'query',
        key: 'q', fixedFields: [], bodyTemplate: '', headers: []}},
    {...common, proposalId: 'shared-subject', prelude: [], subject: write}];
    const run = await runResearchSwarm(leads, scope, {requester,
      infer: async () => ({flows: []}), model: {model: 'fixture'}, surface,
      ledger, modelCallsAvailable: 4, remainingModelCalls: () => 4,
      researchDeadline: Date.now() + 15000});
    assert.equal(peakWrites, 1, 'shared resource controls must not race');
    assert.deepEqual(run.results.map(item => item.proposalId),
      leads.map(item => item.proposalId));
  });
