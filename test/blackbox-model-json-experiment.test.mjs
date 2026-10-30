import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import http from 'node:http';
import path from 'node:path';
import {createHash, randomBytes} from 'node:crypto';
import {spawn} from 'node:child_process';
import {temp} from './helpers.mjs';
import {execFile} from '../src/util.mjs';
import {CLI} from '../src/demo.mjs';
import {createLedger} from '../src/blackbox/ledger.mjs';
import {createRequester, loadScope} from '../src/blackbox/scope.mjs';
import {planJsonExperiments, runJsonExperiments} from '../src/blackbox/json-experiment.mjs';

test('an accepted JSON plan deferred by time retains its full in-memory request for a later pass', async () => {
  const origin = 'http://127.0.0.1:4329';
  const scope = loadScope({origin, overrides: {acceptLocal: true}}).scope;
  const lead = {path: '/api/review', parameter: 'value', as: 'anonymous', origin,
    oracle: 'observation', fixedFields: [], observedFields: ['value'],
    prelude: [], observePath: '', observeAs: 'anonymous',
    family: 'response-behavior', why: 'Inspect a reviewed input',
    controlValue: 'plain', firstValue: 'first', secondValue: 'second',
    marker: 'bx111111111111', secondMarker: 'bx222222222222',
    proposalId: 'accepted-plan-1'};
  const run = await runJsonExperiments([lead], scope, {
    requester: async () => {throw Error('The time-deferred plan must not send a request.');},
    researchDeadline: 0});
  assert.equal(run.results[0].verdict, 'untested');
  assert.equal(run.results[0].proposalId, 'accepted-plan-1');
  assert.equal(run.deferredLeads[0].firstValue, 'first');
});

test('a refused local JSON contract records a blocked experiment and leaves the run alive', async t => {
  const root = temp();
  t.after(() => fs.rmSync(root, {recursive: true, force: true}));
  const origin = 'http://127.0.0.1:49381', route = '/api/inspect';
  const file = path.join(root, 'scope.json');
  fs.writeFileSync(file, JSON.stringify({schemaVersion: 1, target: {origin},
    probes: {jsonPostPaths: [route]}}));
  const scope = structuredClone(loadScope({file, origin}).scope);
  scope.localAutoPostContracts = {'json /api/inspect': {
    contentType: 'application/json', fields: ['q']}};
  const ledger = createLedger(root, {run: 'bx-json-contract-refusal'});
  const requester = createRequester(scope, {ledger, allowLocal: true});
  const lead = {path: route, parameter: 'q', as: 'anonymous', origin,
    fixedFields: [{field: 'unseen', value: 'safe'}], observedFields: ['q', 'unseen'],
    prelude: [], observePath: '', observeAs: 'anonymous',
    family: 'input-behavior', why: 'Review a local JSON input',
    controlValue: 'plain', firstValue: 'first', secondValue: 'second',
    marker: 'bx111111111111', secondMarker: 'bx222222222222'};
  const run = await runJsonExperiments([lead], scope, {requester, ledger});
  assert.equal(run.results[0].verdict, 'blocked');
  assert.equal(requester.stats.sent, 0);
  assert.equal(run.investigations[0].stopReason, 'blocked');
  const records = fs.readFileSync(ledger.file, 'utf8').trim().split('\n').map(JSON.parse);
  assert.ok(records.some(item => item.refused?.rule === 'local-auto-post-contract'));
  assert.ok(records.some(item => item.kind === 'model-json-attempt' && item.verdict === 'blocked'));
});

test('JSON research stops on repeated identical responses but permits seven changing attempts', async t => {
  const root = temp();
  t.after(() => fs.rmSync(root, {recursive: true, force: true}));
  const origin = 'http://127.0.0.1:3000';
  const route = `/api/inspect-${randomBytes(4).toString('hex')}`;
  const file = path.join(root, 'scope.json');
  fs.writeFileSync(file, JSON.stringify({schemaVersion: 1, target: {origin},
    probes: {jsonPostPaths: [route]}, limits: {researchCallsPerHypothesis: 20}}));
  const scope = loadScope({file, origin}).scope;
  const surface = {patterns: [], jsonBodyOperations: [{path: route, method: 'POST',
    contentType: 'application/json', fields: ['q'], requiredFields: []}]};
  const initial = {path: route, parameter: 'q', as: 'anonymous',
    origin, fixedFields: [], observedFields: ['q'], prelude: [],
    observePath: '', observeAs: 'anonymous', family: 'unclassified-behavior',
    why: 'Test a reviewed input', controlValue: 'control0',
    firstValue: 'first0', secondValue: 'second0',
    marker: 'bx111111111111', secondMarker: 'bx222222222222'};
  const fragments = ['a1b2c3d4', 'c3d4e5f6', 'e5f6a7b8', 'b7c8d9e0'];
  const scenario = async changing => {
    let requests = 0;
    const requester = async request => {
      const value = JSON.parse(request.body).q;
      const stage = changing ? Number(value.match(/\d+$/)?.[0] ?? 0) : 0;
      const body = JSON.stringify({data: [], stage});
      return {status: 200, type: 'application/json', body,
        bytes: Buffer.byteLength(body),
        hash: `sha256:${createHash('sha256').update(body).digest('hex')}`,
        headers: {'content-type': 'application/json', 'cache-control': 'no-store'},
        evidenceId: `ev-${++requests}`};
    };
    const infer = async (_model, messages) => {
      const context = JSON.parse(messages[1].content);
      if (changing && context.attemptsSoFar >= 7) return {experiments: []};
      const next = context.attemptsSoFar;
      return {experiments: [{family: 'unclassified-behavior', path: route,
        field: 'q', controlValue: changing ? `control${next}` : 'plain',
        firstValue: changing ? `first${next}` : `bx${fragments[next]}`,
        secondValue: changing ? `second${next}` : `prv${fragments[next]}`,
        marker: context.marker, secondMarker: context.secondMarker,
        fixedFields: [], prelude: [], observePath: '', observeAs: 'anonymous',
        why: 'Try a distinct observed input'}]};
    };
    const lead = changing ? initial : {...initial, controlValue: 'plain',
      firstValue: `bx${fragments[0]}`, secondValue: `prv${fragments[0]}`};
    return runJsonExperiments([lead], scope, {requester, infer, model: 'fixture',
      surface, modelCallsAvailable: 20});
  };
  const flat = await scenario(false);
  assert.equal(flat.investigations[0].attempts.length, 3);
  assert.equal(flat.investigations[0].stopReason, 'repeated-behavior');
  assert.equal(flat.modelCalls, 2);
  const changing = await scenario(true);
  assert.equal(changing.investigations[0].attempts.length, 7);
  assert.equal(changing.investigations[0].stopReason, 'model-stopped');
  assert.equal(changing.modelCalls, 7);
});

test('JSON research treats fresh record IDs and submitted email echoes as stalled evidence', async () => {
  const origin = 'http://127.0.0.1:4329', route = '/api/records';
  const scope = loadScope({origin, overrides: {acceptLocal: true}}).scope;
  const surface = {patterns: [], jsonBodyOperations: [{path: route, method: 'POST',
    contentType: 'application/json', fields: ['email'], requiredFields: []}]};
  const initial = {path: route, parameter: 'email', as: 'anonymous', origin,
    oracle: 'observation', fixedFields: [], observedFields: ['email'], prelude: [],
    observePath: '', observeAs: 'anonymous', family: 'registration-observation',
    why: 'Inspect a reviewed registration input', controlValue: 'base0@example.com',
    firstValue: 'first0@example.com', secondValue: 'second0@example.com',
    marker: 'bx111111111111', secondMarker: 'bx222222222222'};
  let sent = 0, calls = 0;
  const requester = async request => {
    const email = JSON.parse(request.body).email;
    const body = JSON.stringify({status: 'success', data: {id: ++sent, email,
      role: 'customer'}});
    return {status: 201, type: 'application/json', body, bytes: body.length,
      hash: `sha256:${createHash('sha256').update(body).digest('hex')}`,
      headers: {'content-type': 'application/json'}, evidenceId: `ev-${sent}`};
  };
  const run = await runJsonExperiments([initial], scope, {requester, surface,
    model: 'fixture', modelCallsAvailable: 20,
    infer: async (_model, messages) => {
      calls++;
      const context = JSON.parse(messages[1].content);
      const next = context.attemptsSoFar;
      return {experiments: [{family: initial.family, path: route, field: 'email',
        oracle: 'observation', controlValue: `base${next}@example.com`,
        firstValue: `first${next}@example.com`, secondValue: `second${next}@example.com`,
        marker: context.marker, secondMarker: context.secondMarker,
        fixedFields: [], prelude: [], observePath: '', observeAs: 'anonymous',
        why: 'Check a distinct observed input'}]};
    }});
  assert.equal(run.investigations[0].stopReason, 'repeated-behavior');
  assert.equal(run.investigations[0].attempts.length, 3);
  assert.equal(calls, 2);
  assert.equal(sent, 9);
  assert.ok(run.investigations[0].attempts.every(item => item.verdict === 'inconclusive'));
  assert.ok(run.decisions.every(item => item.accepted));
});

test('JSON revision reuses reviewed companion fields when Muse supplies an invalid replacement', async t => {
  const root = temp();
  t.after(() => fs.rmSync(root, {recursive: true, force: true}));
  const origin = 'http://127.0.0.1:4329', route = '/api/review';
  const file = path.join(root, 'scope.json');
  fs.writeFileSync(file, JSON.stringify({schemaVersion: 1, target: {origin},
    probes: {jsonPostPaths: [route]}}));
  const scope = loadScope({file, origin}).scope;
  const surface = {patterns: [], jsonBodyOperations: [{path: route, method: 'POST',
    contentType: 'application/json', fields: ['value', 'mode'], requiredFields: ['mode']}]};
  const initial = {path: route, parameter: 'value', as: 'anonymous', origin,
    oracle: 'observation', fixedFields: [{field: 'mode', value: 'preview'}],
    observedFields: ['value', 'mode'], prelude: [], observePath: '', observeAs: 'anonymous',
    family: 'response-behavior', why: 'Inspect a reviewed input',
    controlValue: 'plain', firstValue: 'first', secondValue: 'second',
    marker: 'bx111111111111', secondMarker: 'bx222222222222'};
  const bodies = [];
  const requester = async request => {
    const parsed = JSON.parse(request.body);
    bodies.push(parsed);
    const body = JSON.stringify({result: parsed.value});
    return {status: 200, type: 'application/json', body, bytes: body.length,
      hash: `sha256:${createHash('sha256').update(body).digest('hex')}`,
      headers: {'content-type': 'application/json'}, evidenceId: `ev-${bodies.length}`};
  };
  let replies = 0;
  const run = await runJsonExperiments([initial], scope, {requester, surface,
    model: 'fixture', modelCallsAvailable: 2, infer: async (_model, messages) => {
      const context = JSON.parse(messages[1].content);
      if (replies++) return {experiments: []};
      return {experiments: [{family: 'response-behavior', path: route, field: 'value',
        oracle: 'observation', controlValue: 'plain2', firstValue: 'first2',
        secondValue: 'second2', marker: context.marker, secondMarker: context.secondMarker,
        fixedFields: [{field: 'unseen', value: 'wrong'}], prelude: [],
        observePath: '', observeAs: 'anonymous', why: 'Retry with fresh values'}]};
    }});
  assert.equal(run.decisions[0]?.accepted, true);
  assert.equal(run.decisions[0]?.normalizedFixedFields, true);
  assert.equal(bodies.length, 6);
  assert.ok(bodies.every(item => item.mode === 'preview' && !Object.hasOwn(item, 'unseen')));
});

test('Muse JSON POST proposals need a reviewed route and an observed body field', async t => {
  const root = temp();
  t.after(() => fs.rmSync(root, {recursive: true, force: true}));
  const origin = 'http://127.0.0.1:3000';
  const file = path.join(root, 'scope.json');
  fs.writeFileSync(file, JSON.stringify({schemaVersion: 1, target: {origin},
    probes: {jsonPostPaths: ['/api/evaluate']}}));
  const scope = loadScope({file, origin}).scope;
  const surface = {jsonBodyOperations: [
    {path: '/api/evaluate', method: 'POST', contentType: 'application/json',
      fields: ['expression', 'mode', 'token'], purpose: 'Evaluate an expression',
      source: '/openapi.json'}]};
  const infer = async (_model, messages) => {
    const context = JSON.parse(messages[1].content);
    assert.equal(context.operations[0].purpose, 'Evaluate an expression');
    const candidate = (route, field, fixedFields = []) => ({family: 'response-transform', path: route, field,
      as: 'anonymous', controlValue: '7', firstValue: '1+1', secondValue: '2+2',
      marker: context.marker, secondMarker: context.secondMarker,
      fixedFields, prelude: [], observePath: '', observeAs: 'anonymous',
      why: 'Check the observed response transform', priority: 5});
    return {experiments: [candidate('/api/other', 'expression'),
      candidate('/api/evaluate', 'guessed'),
      candidate('/api/evaluate', 'expression', [{field: 'ghost', value: 'preview'}]),
      candidate('/api/evaluate', 'expression', [{field: 'token', value: 'demo'}]),
      candidate('/api/evaluate', 'expression', [{field: 'mode', value: 'preview'}])]};
  };
  const plan = await planJsonExperiments(surface, scope, {infer, model: 'fixture', budget: 3,
    modelCallsAvailable: 1});
  assert.equal(plan.coverage.available, 1);
  assert.equal(plan.coverage.sent, 1);
  assert.deepEqual(plan.decisions.map(item => [item.accepted, item.reason]),
    [[false, 'unobserved-post-field'], [false, 'unobserved-post-field'],
      [false, 'invalid-fixed-fields'], [false, 'invalid-fixed-fields'], [true, undefined]]);
  assert.deepEqual(plan.leads.map(item => [item.path, item.parameter]),
    [['/api/evaluate', 'expression']]);
  assert.deepEqual(plan.leads[0].fixedFields, [{field: 'mode', value: 'preview'}]);
});

test('Muse can plan distinct JSON experiments on one observed POST route', async t => {
  const root = temp();
  t.after(() => fs.rmSync(root, {recursive: true, force: true}));
  const origin = 'http://127.0.0.1:3000', route = '/api/evaluate';
  const file = path.join(root, 'scope.json');
  fs.writeFileSync(file, JSON.stringify({schemaVersion: 1, target: {origin},
    probes: {jsonPostPaths: [route]}}));
  const scope = loadScope({file, origin}).scope;
  const surface = {jsonBodyOperations: [{path: route, method: 'POST',
    contentType: 'application/json', fields: ['expression']}]};
  const plan = await planJsonExperiments(surface, scope, {model: 'fixture',
    budget: 4, modelCallsAvailable: 1, infer: async (_model, messages) => {
      const {marker, secondMarker} = JSON.parse(messages[1].content);
      const proposal = (family, firstValue, secondValue) => ({family,
        path: route, field: 'expression', as: 'anonymous',
        controlValue: 'plain', firstValue, secondValue,
        marker, secondMarker, oracle: 'observation', fixedFields: [],
        prelude: [], observePath: '', observeAs: 'anonymous',
        why: 'Compare distinct response behavior', priority: 5});
      return {experiments: [proposal('template arithmetic', '2+3', '3+4'),
        proposal('parser normalization', '2%2B3', '3%2B4'),
        proposal('same request restated', '2+3', '3+4')]};
    }});
  assert.deepEqual(plan.leads.map(item => item.firstValue), ['2+3', '2%2B3']);
  assert.ok(plan.decisions.every(item => item.accepted));
  assert.equal(plan.decisions[2].coalescedWith, 1);
});

test('JSON planning executes an observed read outside the current model page', async t => {
  const root = temp();
  t.after(() => fs.rmSync(root, {recursive: true, force: true}));
  const origin = 'http://127.0.0.1:4329', route = '/api/evaluate';
  const file = path.join(root, 'scope.json');
  fs.writeFileSync(file, JSON.stringify({schemaVersion: 1, target: {origin},
    probes: {jsonPostPaths: [route]}}));
  const scope = loadScope({file, origin}).scope;
  const observePath = '/api/read-399';
  const surface = {patterns: Array.from({length: 400}, (_, index) => ({
    pattern: `/api/read-${index}`, methods: ['GET']})),
  jsonBodyOperations: [{path: route, method: 'POST', contentType: 'application/json',
    fields: ['value']}]};
  const plan = await planJsonExperiments(surface, scope, {model: 'fixture', budget: 1,
    modelCallsAvailable: 1, infer: async (_model, messages) => {
      const context = JSON.parse(messages[1].content);
      assert.ok(!context.readRoutes.some(item => item.path === observePath));
      return {experiments: [{family: 'response-behavior', path: route, field: 'value',
        as: 'anonymous', oracle: 'observation', controlValue: 'plain',
        firstValue: 'first', secondValue: 'second', marker: context.marker,
        secondMarker: context.secondMarker, fixedFields: [], prelude: [],
        observePath, observeAs: 'anonymous', why: 'Read an observed route', priority: 5}]};
    }});
  assert.equal(plan.decisions[0]?.accepted, true);
  assert.equal(plan.leads[0]?.observePath, observePath);
});

test('JSON proposal rejections record marker and syntax reasons without payloads', async t => {
  const root = temp();
  t.after(() => fs.rmSync(root, {recursive: true, force: true}));
  const origin = 'http://127.0.0.1:4329', route = '/api/evaluate';
  const file = path.join(root, 'scope.json');
  fs.writeFileSync(file, JSON.stringify({schemaVersion: 1, target: {origin},
    probes: {jsonPostPaths: [route]}}));
  const scope = loadScope({file, origin}).scope;
  const surface = {jsonBodyOperations: [{path: route, method: 'POST',
    contentType: 'application/json', fields: ['expression'], requiredFields: []}]};
  const plan = await planJsonExperiments(surface, scope, {model: 'fixture', budget: 2,
    modelCallsAvailable: 1, infer: async (_model, messages) => {
      const context = JSON.parse(messages[1].content);
      const base = {family: 'response-transform', path: route, field: 'expression',
        as: 'anonymous', controlValue: 'plain', firstValue: '1+1', secondValue: '2+2',
        marker: context.marker, secondMarker: context.secondMarker,
        fixedFields: [], prelude: [], observePath: '', observeAs: 'anonymous',
        why: 'Inspect response transform', priority: 5};
      return {experiments: [{...base, marker: 'bx000000000000'},
        {...base, firstValue: '<script>alert(1)</script>'}]};
    }});
  assert.deepEqual(plan.decisions.map(item => [item.reason, item.controlReason]),
    [['marker-mismatch', undefined], ['invalid-controls', 'unsafe-syntax']]);
  assert.equal(JSON.stringify(plan.decisions).includes('<script>'), false);
});

test('Muse can repair a rejected JSON control on the same reviewed field', async t => {
  const root = temp();
  t.after(() => fs.rmSync(root, {recursive: true, force: true}));
  const origin = 'http://127.0.0.1:4329', route = '/api/inspect';
  const file = path.join(root, 'scope.json');
  fs.writeFileSync(file, JSON.stringify({schemaVersion: 1, target: {origin},
    probes: {jsonPostPaths: [route]}}));
  const scope = loadScope({file, origin}).scope;
  const surface = {jsonBodyOperations: [{path: route, method: 'POST',
    contentType: 'application/json', fields: ['value'], requiredFields: []}]};
  let calls = 0;
  const plan = await planJsonExperiments(surface, scope, {model: 'fixture',
    budget: 2, modelCallsAvailable: 2, infer: async (_model, messages) => {
      calls++;
      const context = JSON.parse(messages[1].content);
      const base = {family: 'response-transform', path: route, field: 'value',
        as: 'anonymous', controlValue: 'plain', firstValue: 'alpha',
        secondValue: 'beta', marker: context.marker,
        secondMarker: context.secondMarker, fixedFields: [], prelude: [],
        observePath: '', observeAs: 'anonymous', why: 'Compare responses',
        priority: 5, oracle: 'observation'};
      if (calls === 1) return {experiments: [{...base,
        firstValue: '<script>alert(1)</script>', oracle: 'marker'}]};
      assert.match(messages[0].content, /Repair these JSON POST experiments/);
      assert.equal(context.rejected[0].controlReason, 'unsafe-syntax');
      assert.equal(messages[1].content.includes('<script>'), false);
      return {experiments: [base]};
    }});
  assert.equal(plan.modelCalls, 2);
  assert.equal(plan.leads.length, 1);
  assert.equal(plan.leads[0].firstValue, 'alpha');
  assert.equal(plan.leads[0].oracle, 'observation');
  assert.deepEqual(plan.decisions.map(item => [item.accepted, item.reason]),
    [[false, 'invalid-controls'], [true, undefined]]);
  assert.equal(plan.coverage.repairAccepted, 1);
});

test('literal Muse canaries on a reviewed JSON POST become feedback, not a finding', async t => {
  const root = temp();
  t.after(() => fs.rmSync(root, {recursive: true, force: true}));
  const origin = 'http://127.0.0.1:4329', route = '/api/echo';
  const file = path.join(root, 'scope.json');
  fs.writeFileSync(file, JSON.stringify({schemaVersion: 1, target: {origin},
    probes: {jsonPostPaths: [route]}}));
  const scope = loadScope({file, origin}).scope;
  const surface = {jsonBodyOperations: [{path: route, method: 'POST',
    contentType: 'application/json', fields: ['value']}], patterns: []};
  const planned = await planJsonExperiments(surface, scope, {model: 'fixture',
    budget: 1, modelCallsAvailable: 1, infer: async (_model, messages) => {
      const context = JSON.parse(messages[1].content);
      return {experiments: [{family: 'response reflection', path: route, field: 'value',
        as: 'anonymous', controlValue: 'plain', firstValue: context.marker,
        secondValue: context.secondMarker, marker: context.marker,
        secondMarker: context.secondMarker, fixedFields: [], prelude: [],
        observePath: '', observeAs: 'anonymous', why: 'Inspect exact echo behavior',
        priority: 5}]};
    }});
  assert.equal(planned.leads.length, 1);
  assert.equal(planned.leads[0].oracle, 'observation');
  assert.equal(planned.decisions[0].translatedTo, 'observation');
  let requests = 0;
  const requester = async request => {
    const body = JSON.stringify({value: JSON.parse(request.body).value});
    return {status: 200, type: 'application/json', body,
      hash: `sha256:${createHash('sha256').update(body).digest('hex')}`,
      evidenceId: `ev-${++requests}`};
  };
  const run = await runJsonExperiments(planned.leads, scope, {requester,
    surface, model: 'fixture', modelCallsAvailable: 1,
    infer: async () => ({experiments: []})});
  assert.equal(requests, 3);
  assert.equal(run.results[0].kind, 'model-json-observation');
  assert.equal(run.results[0].verdict, 'inconclusive');
  assert.match(run.results[0].reason, /unclassified/);
  assert.equal(run.findings.length, 0);
  assert.equal(run.investigations[0].attempts.length, 1);
});

test('Muse may plan an exact observed JSON POST on a verified deployed target', async t => {
  const root = temp();
  t.after(() => fs.rmSync(root, {recursive: true, force: true}));
  const origin = 'https://app.example.test', route = '/api/evaluate';
  const expiresAt = new Date(Date.now() + 86400000).toISOString();
  const target = {url: origin, environment: 'staging',
    ownership: {status: 'verified', method: 'dns', expiresAt},
    authorization: {origin, paths: ['/api'], methods: ['GET', 'HEAD', 'POST'],
      maxRequestsPerSecond: 2, expiresAt}};
  const file = path.join(root, 'scope.json');
  fs.writeFileSync(file, JSON.stringify({schemaVersion: 1, target: {origin},
    include: ['/api'], probes: {jsonPostPaths: [route]}, limits: {rps: 2}}));
  const scope = loadScope({file, origin, targets: [target]}).scope;
  const surface = {jsonBodyOperations: [{path: route, method: 'POST',
    contentType: 'application/json', fields: ['expression'], requiredFields: [],
    purpose: 'Evaluate a supplied expression'}]};
  let called = 0;
  const infer = async (_model, messages) => {
    called++;
    const context = JSON.parse(messages[1].content);
    assert.equal(context.operations[0].path, route);
    assert.match(messages[0].content, /authorized deployed test/);
    return {experiments: [{family: 'response transform', path: route,
      field: 'expression', as: 'anonymous', controlValue: '7',
      firstValue: '1+1', secondValue: '2+2', marker: context.marker,
      secondMarker: context.secondMarker, fixedFields: [], prelude: [],
      observePath: '', observeAs: 'anonymous', why: 'Observed calculator input',
      priority: 8}]};
  };
  const plan = await planJsonExperiments(surface, scope, {infer, model: 'fixture',
    budget: 1, modelCallsAvailable: 1});
  assert.equal(called, 1);
  assert.equal(plan.coverage.available, 1);
  assert.equal(plan.leads.length, 1);
  assert.equal(plan.decisions[0].accepted, true);
  const readOnly = structuredClone(target);
  readOnly.authorization.methods = ['GET', 'HEAD'];
  const readOnlyFile = path.join(root, 'read-only.json');
  fs.writeFileSync(readOnlyFile, JSON.stringify({schemaVersion: 1, target: {origin},
    include: ['/api'], limits: {rps: 2}}));
  const restricted = loadScope({file: readOnlyFile, origin, targets: [readOnly]}).scope;
  const denied = await planJsonExperiments(surface, restricted, {infer: async () => {
    throw Error('Unreviewed deployed POST must not reach Muse.');
  }, model: 'fixture', budget: 1, modelCallsAvailable: 1});
  assert.equal(denied.coverage.available, 0);
  assert.equal(denied.modelCalls, 0);
});

test('Muse reviews a JSON POST route beyond the first model page', async t => {
  const root = temp();
  t.after(() => fs.rmSync(root, {recursive: true, force: true}));
  const origin = 'http://127.0.0.1:3000';
  const routes = Array.from({length: 13}, (_, index) => `/api/evaluate-${index}`);
  const file = path.join(root, 'scope.json');
  fs.writeFileSync(file, JSON.stringify({schemaVersion: 1, target: {origin},
    probes: {jsonPostPaths: routes}}));
  const scope = loadScope({file, origin}).scope;
  const surface = {jsonBodyOperations: routes.map(route => ({path: route, method: 'POST',
    contentType: 'application/json', fields: ['expression'], source: '/openapi.json'}))};
  const infer = async (_model, messages) => {
    const context = JSON.parse(messages[1].content);
    if (!context.operations.some(item => item.path === routes[12])) return {experiments: []};
    return {experiments: [{family: 'response-transform', path: routes[12], field: 'expression',
      as: 'anonymous', controlValue: '7', firstValue: '1+1', secondValue: '2+2',
      marker: context.marker, secondMarker: context.secondMarker,
      fixedFields: [], prelude: [], observePath: '', observeAs: 'anonymous',
      why: 'Check the observed response transform', priority: 5}]};
  };
  const plan = await planJsonExperiments(surface, scope, {infer, model: 'fixture', budget: 1,
    modelCallsAvailable: 2});
  assert.deepEqual(plan.coverage, {available: 13, sent: 13, readsAvailable: 0,
    readsSent: 0, fieldsCut: 0});
  assert.equal(plan.modelCalls, 2);
  assert.deepEqual(plan.leads.map(item => item.path), [routes[12]]);
});

test('Muse can select an observed read after the former 64-route JSON context window', async t => {
  const root = temp();
  t.after(() => fs.rmSync(root, {recursive: true, force: true}));
  const origin = 'http://127.0.0.1:3000';
  const post = '/api/transform';
  const reads = Array.from({length: 80}, (_, index) => `/api/read-${index}`);
  const file = path.join(root, 'scope.json');
  fs.writeFileSync(file, JSON.stringify({schemaVersion: 1, target: {origin},
    probes: {jsonPostPaths: [post]}}));
  const scope = loadScope({file, origin}).scope;
  const surface = {jsonBodyOperations: [{path: post, method: 'POST',
    contentType: 'application/json', fields: ['expression']}],
  patterns: reads.map(pattern => ({pattern, methods: ['GET']}))};
  const plan = await planJsonExperiments(surface, scope, {model: 'fixture',
    budget: 1, modelCallsAvailable: 1, infer: async (_model, messages) => {
      const context = JSON.parse(messages[1].content);
      assert.ok(context.readRoutes.some(item => item.path === reads.at(-1)));
      return {experiments: [{family: 'response-transform', path: post,
        field: 'expression', as: 'anonymous', controlValue: 'plain',
        firstValue: 'first', secondValue: 'second', marker: context.marker,
        secondMarker: context.secondMarker, fixedFields: [], prelude: [],
        observePath: reads.at(-1), observeAs: 'anonymous',
        why: 'Observed late read may show the effect', priority: 5}]};
    }});
  assert.equal(plan.coverage.readsSent, 80);
  assert.equal(plan.leads[0]?.observePath, reads.at(-1));
});

test('JSON POST planning reports body fields omitted from the model page', async t => {
  const root = temp();
  t.after(() => fs.rmSync(root, {recursive: true, force: true}));
  const origin = 'http://127.0.0.1:3000';
  const file = path.join(root, 'scope.json');
  fs.writeFileSync(file, JSON.stringify({schemaVersion: 1, target: {origin},
    probes: {jsonPostPaths: ['/api/process']}}));
  const scope = loadScope({file, origin}).scope;
  const fields = Array.from({length: 20}, (_, index) => `input${index}`);
  const surface = {jsonBodyOperations: [{path: '/api/process', method: 'POST',
    contentType: 'application/json', fields, source: '/openapi.json'}]};
  const infer = async (_model, messages) => {
    const context = JSON.parse(messages[1].content);
    assert.equal(context.operations[0].fields.length, 16);
    return {experiments: [{family: 'response-transform', path: '/api/process',
      field: fields[19], as: 'anonymous', controlValue: '7', firstValue: '1+1',
      secondValue: '2+2', marker: context.marker,
      secondMarker: context.secondMarker, fixedFields: [], prelude: [],
      observePath: '', observeAs: 'anonymous', why: 'Check the field', priority: 5}]};
  };
  const plan = await planJsonExperiments(surface, scope, {infer, model: 'fixture',
    budget: 1, modelCallsAvailable: 1});
  assert.equal(plan.coverage.fieldsCut, 4);
  assert.equal(plan.leads.length, 0);
  assert.equal(plan.decisions[0].reason, 'unobserved-post-field');
});

test('actual CLI proves a Muse-selected reviewed JSON POST transformation and replays its fix', async t => {
  const liveMuse = process.env.BLACKBOX_LIVE_JSON === '1';
  const root = temp();
  if (!liveMuse) t.after(() => fs.rmSync(root, {recursive: true, force: true}));
  const route = `/api/process-${randomBytes(4).toString('hex')}`;
  const requested = [];
  let vulnerable = true;
  const server = http.createServer(async (request, response) => {
    const url = new URL(request.url, 'http://fixture');
    requested.push(`${request.method} ${url.pathname}`);
    const json = (status, body) => {
      response.writeHead(status, {'content-type': 'application/json', 'cache-control': 'no-store'});
      response.end(JSON.stringify(body));
    };
    if (url.pathname === '/') return json(200, {app: 'processor'});
    if (url.pathname === '/openapi.json') return json(200, {openapi: '3.0.0', paths: {
      [route]: {post: {summary: 'Evaluate a JavaScript expression and return its result',
        requestBody: {$ref: '#/components/requestBodies/ProcessorInput'}}},
      '/api/delete': {post: {requestBody: {content: {'application/json': {
        schema: {type: 'object', properties: {expression: {type: 'string'}}}}}}}},
    }, components: {requestBodies: {ProcessorInput: {content: {'application/json': {
      schema: {$ref: '#/components/schemas/ProcessorInput'}}}}},
    schemas: {ProcessorInput: {allOf: [{$ref: '#/components/schemas/ProcessorFields'}]},
      ProcessorFields: {type: 'object', required: ['expression'],
        properties: {expression: {$ref: '#/components/schemas/Expression'}}},
      Expression: {type: 'string'}}}});
    if (url.pathname === route && request.method === 'POST') {
      const chunks = [];
      for await (const chunk of request) chunks.push(chunk);
      let expression = '';
      try {expression = JSON.parse(Buffer.concat(chunks).toString()).expression;} catch {return json(400, {error: 'invalid'});}
      let value = expression;
      if (vulnerable) try {value = Function(`return (${expression})`)();}
      catch {value = 'invalid';}
      return json(200, {result: value});
    }
    return json(url.pathname === '/api/delete' ? 500 : 404, {error: 'missing'});
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  t.after(() => new Promise(resolve => server.close(resolve)));
  const origin = `http://127.0.0.1:${server.address().port}`;
  const scope = path.join(root, 'blackbox.scope.json');
  fs.writeFileSync(scope, JSON.stringify({schemaVersion: 1, target: {origin},
    include: ['/'], probes: {jsonPostPaths: [route]}}));
  const bin = path.join(root, 'bin');
  fs.mkdirSync(bin);
  if (!liveMuse) fs.writeFileSync(path.join(bin, 'muse'), [
    '#!' + process.execPath,
    "const fs=require('node:fs');",
    'const args=process.argv.slice(2);',
    'const value=flag=>args[args.indexOf(flag)+1];',
    "if(args.includes('--version')){console.log('muse fixture');process.exit(0);}",
    "if(args[0]!=='exec'||!args.includes('--disable-shell')||!args.includes('--output-schema')||value('--provider')!=='meta')process.exit(2);",
    "const messages=JSON.parse(fs.readFileSync(value('--prompt-file'),'utf8'));",
    'const system=messages[0].content;',
    'let answer;',
    "if(system.includes('Select up to five local stored-XSS tests'))answer={checks:[]};",
    "else if(system.includes('Select distinct harmless response-transformation experiments for the reviewed JSON POST routes')){",
    'const context=JSON.parse(messages[1].content);',
    'const operation=context.operations.find(item=>item.path===process.env.BX_ROUTE&&item.fields.includes(\'expression\'));',
    "answer={experiments:operation?[{family:'unsafe-json-expression-evaluation',path:operation.path,field:'expression',as:'anonymous',controlValue:'7',firstValue:'<script>alert(1)</script>',secondValue:'8',marker:context.marker,secondMarker:context.secondMarker,fixedFields:[],prelude:[],observePath:'',observeAs:'anonymous',why:'The reviewed JSON field is evaluated',priority:10}]:[]};",
    '}',
    "else if(system.includes('Repair these JSON POST experiments')){",
    'const context=JSON.parse(messages[1].content);',
    'const operation=context.operations.find(item=>item.path===process.env.BX_ROUTE&&item.fields.includes(\'expression\'));',
    'const firstValue=`String.fromCharCode(${[...context.marker].map(char=>char.charCodeAt(0)).join(\',\')})`;',
    "const secondValue=`[${[...context.secondMarker].map(char=>JSON.stringify(char)).join(',')}].join('')`;",
    "answer={experiments:operation?[{family:'unsafe-json-expression-evaluation',path:operation.path,field:'expression',as:'anonymous',controlValue:'7',firstValue,secondValue,marker:context.marker,secondMarker:context.secondMarker,fixedFields:[],prelude:[],observePath:'',observeAs:'anonymous',why:'The reviewed JSON field is evaluated',priority:10}]:[]};",
    '}',
    "else if(system.includes('Interpret only the extracted')){",
    'const context=JSON.parse(messages[1].content);',
    "answer={files:context.files.map(file=>({id:file.id,role:'app',why:'Observed public client',authFlow:'',routes:file.routes.map(route=>({path:route.path,method:route.method,purpose:'Observed route',parameters:[]}))}))};",
    '}',
    "else if(system.includes('Assess only these independently proved'))answer={notes:[]};",
    "else if(system.includes('mapping an authorized web API'))answer={paths:[],notes:[]};",
    "else if(system.includes('Propose bounded GET access-control'))answer={tasks:[]};",
    "else if(system.includes('Rank only the supplied observed read-only web-test candidates'))answer={priorities:[],strategies:[],experiments:[]};",
    'else process.exit(3);',
    "console.log(JSON.stringify({payload:{kind:'run_terminal',terminal:'completed',text:JSON.stringify(answer)}}));",
  ].join('\n') + '\n', {mode: 0o700});
  const env = {...(!liveMuse ? {PATH: `${bin}${path.delimiter}${process.env.PATH}`} : {}),
    BX_ROUTE: route};
  const cli = async (...args) => {
    const completed = await execFile(process.execPath,
      [CLI, 'blackbox', ...args, '--project', root, '--json', '--non-interactive'],
      {cwd: root, env, timeout: liveMuse ? 660000 : 90000});
    return {code: completed.code, data: JSON.parse(completed.stdout)};
  };
  const baseline = await cli(origin, '--scope', scope, '--no-model', '--rps', '20');
  assert.ok(!baseline.data.findings.some(item => item.kind === 'model-json-differential'));
  assert.equal(requested.filter(item => item === `POST ${route}`).length, 0);
  const modeled = await cli(origin, '--scope', scope, '--rps', '20');
  const web = JSON.parse(fs.readFileSync(path.join(modeled.data.runDir, 'web-probes.json'), 'utf8'));
  const surface = JSON.parse(fs.readFileSync(path.join(modeled.data.runDir, 'surface.json'), 'utf8'));
  assert.deepEqual(surface.jsonBodyOperations.find(item => item.path === route)?.fields, ['expression']);
  assert.deepEqual(surface.jsonBodyOperations.find(item => item.path === route)?.requiredFields, ['expression']);
  assert.equal(surface.apiSchemaCuts, 0);
  assert.ok(web.strategyDecisions.some(item => item.mode === 'json-experiment' &&
    item.reason === 'invalid-controls' && item.controlReason === 'unsafe-syntax'));
  assert.ok(web.strategyDecisions.some(item => item.mode === 'json-experiment' &&
    item.accepted && item.repaired));
  assert.equal(modeled.code, 3, JSON.stringify({error: modeled.data.modelError,
    findings: modeled.data.findings, decisions: web.strategyDecisions, results: web.results,
    jsonBodyOperations: surface.jsonBodyOperations, modelCoverage: web.modelCoverage}));
  const finding = modeled.data.findings.find(item => item.kind === 'model-json-differential');
  assert.ok(finding?.proof, JSON.stringify(modeled.data.findings));
  assert.equal(finding.pattern, route);
  assert.equal(modeled.data.modelOutput.jsonExperiments, 1);
  assert.ok(web.strategyDecisions.some(item => item.mode === 'json-experiment' && item.accepted));
  assert.ok(requested.filter(item => item === `POST ${route}`).length >= 6);
  assert.ok(!requested.includes('POST /api/delete'));
  assert.equal((await cli('verify', modeled.data.run)).code, 1);
  const exported = await cli('export', modeled.data.run, '--out', path.join(root, 'regression'));
  assert.equal(exported.code, 0);
  const runExport = () => new Promise((resolve, reject) => {
    const child = spawn(process.execPath, ['--test', ...exported.data.files],
      {env: Object.fromEntries(Object.entries(process.env).filter(([key]) => key !== 'NODE_TEST_CONTEXT')),
        stdio: 'ignore'});
    child.once('error', reject);
    child.once('close', resolve);
  });
  assert.equal(await runExport(), 1);
  vulnerable = false;
  assert.equal((await cli('verify', modeled.data.run)).code, 0);
  assert.equal(await runExport(), 0);
});

test('actual CLI repeats five Muse-selected GET preludes, JSON POST, and GET in its proof', async t => {
  const root = temp();
  t.after(() => fs.rmSync(root, {recursive: true, force: true}));
  const suffix = randomBytes(4).toString('hex');
  const preludes = Array.from({length: 5}, (_, index) =>
    `/api/prepare-${suffix}-${index}`);
  const action = `/api/execute-${suffix}`;
  const observe = `/api/result-${suffix}`;
  const requested = [];
  let vulnerable = true, stored = null;
  const ready = new Set();
  const server = http.createServer(async (request, response) => {
    const url = new URL(request.url, 'http://fixture');
    requested.push(`${request.method} ${url.pathname}`);
    const json = (status, body) => {
      response.writeHead(status, {'content-type': 'application/json', 'cache-control': 'no-store'});
      response.end(JSON.stringify(body));
    };
    if (url.pathname === '/') return json(200, {app: 'stored processor'});
    if (url.pathname === '/openapi.json') return json(200, {openapi: '3.0.0', paths: {
      ...Object.fromEntries(preludes.map(path => [path, {get: {}}])),
      [observe]: {get: {}},
      [action]: {post: {requestBody: {content: {'application/json': {
        schema: {type: 'object', required: ['expression', 'mode'],
          properties: {expression: {type: 'string'}, mode: {type: 'string'}}}}}}}},
      '/api/delete': {post: {requestBody: {content: {'application/json': {
        schema: {type: 'object', properties: {expression: {type: 'string'}}}}}}}},
    }});
    if (request.method === 'GET' && preludes.includes(url.pathname)) {
      ready.add(url.pathname);
      return json(200, {ready: true});
    }
    if (request.method === 'GET' && url.pathname === observe) return json(200, {result: stored});
    if (request.method === 'POST' && url.pathname === action) {
      const chunks = [];
      for await (const chunk of request) chunks.push(chunk);
      let expression = '', mode = '';
      try {({expression, mode} = JSON.parse(Buffer.concat(chunks).toString()));}
      catch {return json(400, {error: 'invalid'});}
      if (mode !== 'preview') return json(400, {error: 'mode required'});
      if (!preludes.every(path => ready.has(path)))
        return json(409, {error: 'not prepared'});
      ready.clear();
      stored = expression;
      if (vulnerable) try {stored = Function(`return (${expression})`)();}
      catch {stored = 'invalid';}
      return json(200, {saved: true});
    }
    return json(url.pathname === '/api/delete' ? 500 : 404, {error: 'missing'});
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  t.after(() => new Promise(resolve => server.close(resolve)));
  const origin = `http://127.0.0.1:${server.address().port}`;
  const scope = path.join(root, 'blackbox.scope.json');
  fs.writeFileSync(scope, JSON.stringify({schemaVersion: 1, target: {origin},
    probes: {jsonPostPaths: [action]}}));
  const bin = path.join(root, 'bin');
  fs.mkdirSync(bin);
  fs.writeFileSync(path.join(bin, 'muse'), [
    '#!' + process.execPath,
    "const fs=require('node:fs');",
    'const args=process.argv.slice(2);',
    'const value=flag=>args[args.indexOf(flag)+1];',
    "if(args.includes('--version')){console.log('muse fixture');process.exit(0);}",
    "if(args[0]!=='exec'||!args.includes('--disable-shell')||!args.includes('--output-schema')||value('--provider')!=='meta')process.exit(2);",
    "const messages=JSON.parse(fs.readFileSync(value('--prompt-file'),'utf8'));",
    'const system=messages[0].content;',
    'let answer;',
    "if(system.includes('Select up to five local stored-XSS tests'))answer={checks:[]};",
    "else if(system.includes('Select distinct harmless response-transformation experiments for the reviewed JSON POST routes')){",
    'const context=JSON.parse(messages[1].content);',
    "const action=context.operations.find(item=>item.path===process.env.BX_ACTION&&item.fields.includes('expression')&&item.requiredFields.includes('mode'));",
    'const required=JSON.parse(process.env.BX_PRELUDES);',
    'const preludes=required.map(path=>context.readRoutes.find(item=>item.path===path)).filter(Boolean);',
    "const observe=context.readRoutes.find(item=>item.path===process.env.BX_OBSERVE);",
    "const firstValue=`String.fromCharCode(${[...context.marker].map(char=>char.charCodeAt(0)).join(',')})`;",
    "const secondValue=`[${[...context.secondMarker].map(char=>JSON.stringify(char)).join(',')}].join('')`;",
    "answer={experiments:action&&preludes.length===required.length&&observe?[{family:'stored-expression-evaluation',path:action.path,field:'expression',as:'anonymous',controlValue:'7',firstValue,secondValue,marker:context.marker,secondMarker:context.secondMarker,fixedFields:[{field:'mode',value:'preview'}],prelude:preludes.map(item=>item.path),observePath:observe.path,observeAs:'anonymous',why:'The GET after POST shows the computed value',priority:10}]:[]};",
    '}',
    "else if(system.includes('Interpret only the extracted')){",
    'const context=JSON.parse(messages[1].content);',
    "answer={files:context.files.map(file=>({id:file.id,role:'app',why:'Observed public client',authFlow:'',routes:file.routes.map(route=>({path:route.path,method:route.method,purpose:'Observed route',parameters:[]}))}))};",
    '}',
    "else if(system.includes('Assess only these independently proved'))answer={notes:[]};",
    "else if(system.includes('Continue mapping this authorized primary application'))answer={paths:[]};",
    "else if(system.includes('mapping an authorized web API'))answer={paths:[],notes:[]};",
    "else if(system.includes('Propose bounded GET access-control'))answer={tasks:[]};",
    "else if(system.includes('Rank only the supplied observed read-only web-test candidates'))answer={priorities:[],strategies:[],experiments:[]};",
    'else process.exit(3);',
    "console.log(JSON.stringify({payload:{kind:'run_terminal',terminal:'completed',text:JSON.stringify(answer)}}));",
  ].join('\n') + '\n', {mode: 0o700});
  const env = {PATH: `${bin}${path.delimiter}${process.env.PATH}`,
    BX_ACTION: action, BX_PRELUDES: JSON.stringify(preludes), BX_OBSERVE: observe};
  const cli = async (...args) => {
    const completed = await execFile(process.execPath,
      [CLI, 'blackbox', ...args, '--project', root, '--json', '--non-interactive'],
      {cwd: root, env, timeout: 90000});
    return {code: completed.code, data: JSON.parse(completed.stdout)};
  };
  const baseline = await cli(origin, '--scope', scope, '--no-model', '--rps', '20');
  assert.ok(!baseline.data.findings.some(item => item.kind === 'model-json-differential'));
  assert.ok(!requested.includes(`POST ${action}`));
  const modeled = await cli(origin, '--scope', scope, '--rps', '20');
  const web = JSON.parse(fs.readFileSync(path.join(modeled.data.runDir, 'web-probes.json'), 'utf8'));
  const surface = JSON.parse(fs.readFileSync(path.join(modeled.data.runDir, 'surface.json'), 'utf8'));
  const finding = modeled.data.findings.find(item => item.kind === 'model-json-differential');
  assert.equal(modeled.code, 3, JSON.stringify({error: modeled.data.modelError,
    findings: modeled.data.findings, decisions: web.strategyDecisions,
    results: web.results, jsonBodyOperations: surface.jsonBodyOperations,
    modelCoverage: web.modelCoverage}));
  assert.ok(finding?.proof);
  assert.deepEqual(finding.webProof.prelude, preludes);
  assert.equal(finding.webProof.observePath, observe);
  assert.deepEqual(finding.webProof.fixedFields, [{field: 'mode', value: 'preview'}]);
  assert.ok(web.modelCoverage.some(item => item.jsonReadSent >= preludes.length + 1 &&
    item.jsonReadSent === item.jsonReadAvailable));
  assert.ok(requested.filter(item => item === `POST ${action}`).length >= 6);
  for (const path of preludes)
    assert.ok(requested.filter(item => item === `GET ${path}`).length >= 6,
      `proof must replay prerequisite ${path}`);
  assert.ok(!requested.includes('POST /api/delete'));
  assert.equal((await cli('verify', modeled.data.run)).code, 1);
  const exported = await cli('export', modeled.data.run, '--out', path.join(root, 'regression'));
  assert.equal(exported.code, 0);
  const runExport = () => new Promise((resolve, reject) => {
    const child = spawn(process.execPath, ['--test', ...exported.data.files],
      {env: Object.fromEntries(Object.entries(process.env).filter(([key]) => key !== 'NODE_TEST_CONTEXT')),
        stdio: 'ignore'});
    child.once('error', reject);
    child.once('close', resolve);
  });
  assert.equal(await runExport(), 1);
  vulnerable = false;
  assert.equal((await cli('verify', modeled.data.run)).code, 0);
  assert.equal(await runExport(), 0);
});

test('JSON POST researcher pivots and refines after negative feedback, then replays proof', async t => {
  const root = temp();
  t.after(() => fs.rmSync(root, {recursive: true, force: true}));
  const suffix = randomBytes(4).toString('hex');
  const intake = `/api/intake-${suffix}`;
  const compute = `/api/compute-${suffix}`;
  const observe = `/api/result-${suffix}`;
  let vulnerable = true;
  let stored = null;
  const requested = [];
  const server = http.createServer(async (request, response) => {
    const url = new URL(request.url, 'http://fixture');
    requested.push(`${request.method} ${url.pathname}`);
    const json = (status, body) => {
      response.writeHead(status, {'content-type': 'application/json', 'cache-control': 'no-store'});
      response.end(JSON.stringify(body));
    };
    if (url.pathname === '/') return json(200, {app: 'expression processor'});
    if (url.pathname === '/openapi.json') return json(200, {openapi: '3.0.0', paths: {
      [intake]: {post: {requestBody: {content: {'application/json': {
        schema: {type: 'object', required: ['expression', 'mode'],
          properties: {expression: {type: 'string'}, mode: {type: 'string'}}}}}}}},
      [compute]: {post: {requestBody: {content: {'application/json': {
        schema: {type: 'object', required: ['expression', 'mode'],
          properties: {expression: {type: 'string'}, mode: {type: 'string'}}}}}}}},
      [observe]: {get: {}},
      '/api/delete': {post: {requestBody: {content: {'application/json': {
        schema: {type: 'object', properties: {expression: {type: 'string'}}}}}}}},
    }});
    if (request.method === 'GET' && url.pathname === observe)
      return json(200, {result: stored});
    if (request.method === 'POST' && [intake, compute].includes(url.pathname)) {
      const chunks = [];
      for await (const chunk of request) chunks.push(chunk);
      let body;
      try {body = JSON.parse(Buffer.concat(chunks).toString());}
      catch {return json(400, {error: 'Invalid JSON'});}
      if (body.mode !== 'preview') return json(422, {error: 'Preview mode is required'});
      if (url.pathname === intake) return json(200, {error: 'Compute route handles expressions'});
      const expression = body.expression;
      if (!vulnerable) {
        stored = expression;
        return json(200, {result: stored});
      }
      if (/^String\.fromCharCode\([\d,]+\)$/.test(expression)) {
        stored = Function('return ' + expression)();
        return json(200, {result: stored});
      }
      stored = null;
      const number = /^probe(\d+)$/.exec(expression);
      return json(200, {error: number && Number(number[1]) >= 6 ?
        'Try String.fromCharCode for this expression syntax' :
        'Unsupported expression syntax'});
    }
    return json(url.pathname === '/api/delete' ? 500 : 404, {error: 'Missing'});
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  t.after(() => new Promise(resolve => server.close(resolve)));
  const origin = `http://127.0.0.1:${server.address().port}`;
  const scope = path.join(root, 'blackbox.scope.json');
  fs.writeFileSync(scope, JSON.stringify({schemaVersion: 1, target: {origin},
    probes: {jsonPostPaths: [intake, compute]}}));
  const bin = path.join(root, 'bin');
  fs.mkdirSync(bin);
  fs.writeFileSync(path.join(bin, 'muse'), [
    '#!' + process.execPath,
    "const fs=require('node:fs');",
    'const args=process.argv.slice(2);',
    'const value=flag=>args[args.indexOf(flag)+1];',
    "if(args.includes('--version')){console.log('muse fixture');process.exit(0);}",
    "if(args[0]!=='exec'||!args.includes('--disable-shell')||!args.includes('--output-schema')||value('--provider')!=='meta')process.exit(2);",
    "const messages=JSON.parse(fs.readFileSync(value('--prompt-file'),'utf8'));",
    'const system=messages[0].content;',
    'let answer;',
    "if(system.includes('Select up to five local stored-XSS tests'))answer={checks:[]};",
    "else if(system.includes('Select distinct harmless response-transformation experiments for the reviewed JSON POST routes')){",
    'const context=JSON.parse(messages[1].content);',
    "const operation=context.operations.find(item=>item.path===process.env.BX_INTAKE&&item.fields.includes('expression'));",
    "answer={experiments:operation?[{family:'unknown-expression-evaluation',path:operation.path,field:'expression',as:'anonymous',controlValue:'plain',firstValue:'probe0',secondValue:'check0',marker:context.marker,secondMarker:context.secondMarker,fixedFields:[{field:'mode',value:'preview'}],prelude:[],observePath:'',observeAs:'anonymous',why:'Investigate the observed expression field',priority:10}]:[]};",
    '}',
    "else if(system.includes('Revise one negative or inconclusive experiment on an explicitly reviewed local JSON POST route')){",
    'const context=JSON.parse(messages[1].content);',
    'const last=context.recentAttempts.at(-1);',
    'const moved=last.responses.some(item=>item.post.fields?.error?.length===33);',
    'const hinted=last.responses.some(item=>item.post.fields?.error?.length===50);',
    "const path=moved?process.env.BX_COMPUTE:context.observedPosts.find(item=>item.path===process.env.BX_COMPUTE)?process.env.BX_COMPUTE:context.observedPosts[0].path;",
    "let firstValue='probe'+context.attemptsSoFar;let secondValue='check'+context.attemptsSoFar;",
    "if(hinted){firstValue='String.fromCharCode('+[...context.marker].map(char=>char.charCodeAt(0)).join(',')+')';secondValue='String.fromCharCode('+[...context.secondMarker].map(char=>char.charCodeAt(0)).join(',')+')';}",
    "answer={experiments:[{family:'unknown-expression-evaluation',path,field:'expression',controlValue:'plain',firstValue,secondValue,marker:context.marker,secondMarker:context.secondMarker,fixedFields:[{field:'mode',value:'preview'}],prelude:[],observePath:context.attemptsSoFar===1?'/api/unseen-read':process.env.BX_OBSERVE,observeAs:'anonymous',why:moved?'Pivot after response named compute route':hinted?'Use the observed expression syntax':'Refine after negative result'}]};",
    '}',
    "else if(system.includes('Repair only the read steps in this JSON POST experiment')){",
    'const context=JSON.parse(messages[1].content);',
    "const observed=context.observedReads.find(path=>path===process.env.BX_OBSERVE);",
    'answer={prelude:[],observePath:observed||\'\'};',
    '}',
    "else if(system.includes('Interpret only the extracted')){const context=JSON.parse(messages[1].content);answer={files:context.files.map(file=>({id:file.id,role:'app',why:'Observed public asset',authFlow:'',routes:[]}))};}",
    "else if(system.includes('Assess only these independently proved'))answer={notes:[]};",
    "else if(system.includes('mapping an authorized web API'))answer={paths:[],notes:[]};",
    "else if(system.includes('Propose bounded GET access-control'))answer={tasks:[]};",
    "else if(system.includes('Rank only the supplied observed read-only web-test candidates'))answer={priorities:[],strategies:[],experiments:[]};",
    'else answer={paths:[],notes:[],tasks:[],checks:[],experiments:[],files:[]};',
    "console.log(JSON.stringify({payload:{kind:'run_terminal',terminal:'completed',text:JSON.stringify(answer)}}));",
  ].join('\n') + '\n', {mode: 0o700});
  const env = {PATH: `${bin}${path.delimiter}${process.env.PATH}`,
    BX_INTAKE: intake, BX_COMPUTE: compute, BX_OBSERVE: observe};
  const cli = async (...args) => {
    const completed = await execFile(process.execPath,
      [CLI, 'blackbox', ...args, '--project', root, '--json', '--non-interactive'],
      {cwd: root, env, timeout: 120000});
    return {code: completed.code, data: JSON.parse(completed.stdout)};
  };
  const baseline = await cli(origin, '--scope', scope, '--no-model', '--rps', '30');
  assert.ok(!baseline.data.findings.some(item => item.kind === 'model-json-differential'));
  assert.ok(!requested.includes(`POST ${intake}`));
  const modeled = await cli(origin, '--scope', scope, '--rps', '30');
  assert.ok(modeled.data.runDir, JSON.stringify(modeled));
  const web = JSON.parse(fs.readFileSync(path.join(modeled.data.runDir, 'web-probes.json'), 'utf8'));
  assert.equal(modeled.code, 3, JSON.stringify({error: modeled.data.modelError,
    findings: modeled.data.findings, decisions: web.strategyDecisions,
    investigations: web.investigations}));
  const finding = modeled.data.findings.find(item =>
    item.kind === 'model-json-differential' && item.pattern === compute);
  assert.ok(finding?.proof, JSON.stringify(modeled.data.findings));
  const investigation = web.investigations.find(item => item.initial.path === intake);
  assert.ok(investigation, JSON.stringify(web.investigations));
  assert.ok(investigation.attempts.length >= 8, JSON.stringify(investigation));
  assert.equal(investigation.final.path, compute);
  assert.equal(investigation.final.verdict, 'confirmed');
  assert.ok(web.strategyDecisions.some(item => item.mode === 'json-experiment-revision' &&
    item.accepted && item.path === compute));
  assert.ok(web.strategyDecisions.some(item => item.mode === 'json-experiment-revision' &&
    item.accepted && item.repairedReadStep && item.readStepRepairAttempted));
  assert.ok(requested.includes(`GET ${observe}`));
  assert.ok(!requested.includes('GET /api/unseen-read'));
  const ledger = fs.readFileSync(path.join(modeled.data.runDir, 'evidence.jsonl'), 'utf8')
    .trim().split('\n').map(line => JSON.parse(line));
  assert.ok(ledger.filter(item => item.kind === 'model-json-attempt').length >= 8);
  assert.ok(!requested.includes('POST /api/delete'));
  assert.equal((await cli('verify', modeled.data.run)).code, 1);
  const exported = await cli('export', modeled.data.run, '--out', path.join(root, 'regressions'));
  assert.equal(exported.code, 0);
  const runExport = () => new Promise((resolve, reject) => {
    const child = spawn(process.execPath, ['--test', ...exported.data.files],
      {env: Object.fromEntries(Object.entries(process.env).filter(([key]) => key !== 'NODE_TEST_CONTEXT')),
        stdio: 'ignore'});
    child.once('error', reject);
    child.once('close', resolve);
  });
  assert.equal(await runExport(), 1);
  vulnerable = false;
  assert.equal((await cli('verify', modeled.data.run)).code, 0);
  assert.equal(await runExport(), 0);
});
