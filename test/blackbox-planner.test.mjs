import test from 'node:test';
import assert from 'node:assert/strict';
import {DEFAULT_SCOPE} from '../src/blackbox/scope.mjs';
import {planTasks, validateTask} from '../src/blackbox/planner.mjs';
import {hash} from '../src/util.mjs';

test('a concrete account-bound sensitive GET receives an anonymous-access check', async () => {
  const scope = structuredClone(DEFAULT_SCOPE);
  scope.include = ['/api'];
  const owner = {status: 200, hash: 'owner-response', shape: {ownerId: 'string', balance: 'number'},
    ownership: {ownerId: hash('u-1')}};
  const outsider = {status: 200, hash: 'outsider-response', shape: owner.shape,
    ownership: {ownerId: hash('u-2')}};
  const surface = {identity: {principals: {owner: 'u-1', outsider: 'u-2'}}, patterns: [
    {pattern: '/api/export', label: {kind: 'export'}, fingerprint: {owner, outsider}, params: {}},
    {pattern: '/api/public', label: {kind: 'public'}, fingerprint: {owner,
      outsider: {...owner}}, params: {}},
    {pattern: '/api/opaque', label: {kind: 'unknown'}, fingerprint: {owner: {...owner,
      shape: {ownerId: 'string'}}, outsider}, params: {}},
  ]};
  const plan = await planTasks(surface, scope);
  assert.deepEqual(plan.tasks.filter(item => item.kind === 'missing-auth').map(item =>
    [item.pattern, item.request.as]), [['/api/export', 'outsider']]);
});

test('Muse planning pages through later routes, assets, hosts and notes, and records its cut', async () => {
  const scope = structuredClone(DEFAULT_SCOPE);
  scope.include = ['/api'];
  const surface = {
    patterns: Array.from({length: 75}, (_, index) => ({pattern: `/api/route${index}`, params: {}, ids: {ownerIds: [], outsiderIds: []}})),
    mined: {endpoints: Array.from({length: 75}, (_, index) => ({path: `/api/asset${index}`, method: 'GET', params: []}))},
    modelNotes: Array.from({length: 37}, (_, index) => ({path: `/api/note${index}`, purpose: 'test'})),
    identity: {principals: {owner: 'u-1', outsider: 'u-2'}},
  };
  const discovery = {hosts: Array.from({length: 25}, (_, index) =>
    ({host: `app${index}.example.test`, stack: [], exposures: []}))};
  const contexts = [];
  const infer = async (_model, messages) => {
    const context = JSON.parse(messages[1].content);
    contexts.push(context);
    return {tasks: context.patterns.some(item => item.pattern === '/api/route74') ? [{
      kind: 'missing-auth', pattern: '/api/route74',
      request: {method: 'GET', url: '/api/route74', as: 'anonymous'},
      control: {url: '/api/route74', as: 'owner'}, why: 'The late route may be private.', priority: 9,
    }] : []};
  };
  const plan = await planTasks(surface, scope, {infer, model: {model: 'fixture'}, discovery});
  assert.equal(plan.modelCalls, 4);
  assert.deepEqual(contexts.map(item => item.page), [1, 2, 3, 4]);
  assert.equal(contexts.at(-1).pages, 4);
  assert.equal(plan.modelCoverage.patternsSent, 75);
  assert.equal(plan.modelCoverage.assetEndpointsSent, 75);
  assert.equal(plan.modelCoverage.discoveredHostsSent, 25);
  assert.equal(plan.modelCoverage.routeNotesSent, 37);
  assert.equal(plan.tasks.find(item => item.pattern === '/api/route74')?.origin, 'model');

  const cut = await planTasks(surface, scope, {infer, model: {model: 'fixture'}, discovery, maxModelPages: 2});
  assert.equal(cut.modelCalls, 2);
  assert.equal(cut.modelCoverage.pagesSent, 2);
  assert.equal(cut.modelCoverage.pagesAvailable, 4);
  assert.equal(cut.modelCoverage.patternsSent, 40);
  assert.ok(!cut.tasks.some(item => item.pattern === '/api/route74'));
});

test('a model task needs an authorized owner control even when its request URL is identical', () => {
  const scope = structuredClone(DEFAULT_SCOPE);
  scope.credentialOrigins = [];
  const surface = {patterns: [{pattern: '/api/private', params: {}, ids: {ownerIds: [], outsiderIds: []}}]};
  const candidate = {kind: 'missing-auth', pattern: '/api/private',
    request: {method: 'GET', url: '/api/private', as: 'anonymous'},
    control: {url: '/api/private', as: 'owner'}, origin: 'model'};
  assert.equal(validateTask(candidate, surface, scope), 'credential-origin');
});

test('long route summaries are split into valid model inputs without dropping routes', async () => {
  const scope = structuredClone(DEFAULT_SCOPE);
  const refs = Object.fromEntries(Array.from({length: 8}, (_, index) => [`field${index}`, 'x'.repeat(512)]));
  const surface = {patterns: Array.from({length: 20}, (_, index) => ({
    pattern: `/api/large${index}`, params: {}, refs, ids: {ownerIds: [], outsiderIds: []},
  })), mined: {endpoints: []}, modelNotes: [], identity: {principals: {}}};
  const seen = new Set();
  const infer = async (_model, messages) => {
    assert.ok(Buffer.byteLength(messages[1].content) <= 24000);
    for (const item of JSON.parse(messages[1].content).patterns) seen.add(item.pattern);
    return {tasks: []};
  };
  const plan = await planTasks(surface, scope, {infer, model: {model: 'fixture'}});
  assert.equal(plan.modelError, null);
  assert.equal(plan.modelCoverage.pagesSent, plan.modelCoverage.pagesAvailable);
  assert.equal(plan.modelCoverage.patternsSent, 20);
  assert.equal(seen.size, 20);
});
