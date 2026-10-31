import test from 'node:test';
import assert from 'node:assert/strict';
import {loadScope} from '../src/blackbox/scope.mjs';
import {planAccessBoundaries} from '../src/blackbox/access-boundary.mjs';
import {planResearchFlows, runResearchFlows} from '../src/blackbox/research-flow.mjs';

function accessFixture() {
  const origin = 'http://127.0.0.1:43291';
  const scope = loadScope({origin, overrides: {acceptLocal: true}}).scope;
  const privatePath = '/api/private-record';
  const publicPath = '/api/public-filter';
  const surface = {patterns: [
    {pattern: privatePath, methods: ['GET'], fingerprint: {
      owner: {status: 200}, anonymous: {status: 403}}},
    {pattern: publicPath, methods: ['GET'], params: {q: ['plain']},
      fingerprint: {anonymous: {status: 200}}},
  ]};
  const proposal = {family: 'record-boundary', why: 'Compare public filter to private record',
    priority: 8, comparison: 'object', protectedPath: privatePath,
    subject: {method: 'GET', path: publicPath, placement: 'query', key: 'q',
      fixedFields: []}, controlValue: 'plain', firstValue: 'candidate-one',
    secondValue: 'candidate-two', ownerPointer: '', candidatePointer: '/records',
    identityField: 'id', matchFields: ['id', 'title']};
  return {scope, surface, proposal, publicPath};
}

test('Muse can repair duplicate access controls against an observed route', async () => {
  const {scope, surface, proposal} = accessFixture();
  let calls = 0;
  const plan = await planAccessBoundaries(surface, scope, {
    model: 'fixture', env: {OWNER_TOKEN: 'fixture-owner'}, budget: 1,
    modelCallsAvailable: 2, infer: async (_model, messages) => {
      calls++;
      if (calls === 1) return {tests: [{...proposal, firstValue: 'plain'}]};
      const context = JSON.parse(messages[1].content);
      assert.equal(context.failure, 'invalid-boundary-duplicate-values');
      return {tests: [proposal]};
    }});
  assert.equal(calls, 2);
  assert.equal(plan.leads.length, 1);
  assert.equal(plan.decisions[0].repairedByMuse, true);
  assert.deepEqual([plan.leads[0].controlValue, plan.leads[0].firstValue,
    plan.leads[0].secondValue], ['plain', 'candidate-one', 'candidate-two']);
});

test('Muse can repair a route outside the observed access pair', async () => {
  const {scope, surface, proposal, publicPath} = accessFixture();
  let calls = 0;
  const plan = await planAccessBoundaries(surface, scope, {
    model: 'fixture', env: {OWNER_TOKEN: 'fixture-owner'}, budget: 1,
    modelCallsAvailable: 2, infer: async (_model, messages) => {
      calls++;
      if (calls === 1) return {tests: [{...proposal, subject: {
        ...proposal.subject, path: '/api/unseen'}}]};
      const context = JSON.parse(messages[1].content);
      assert.equal(context.failure, 'unobserved-route');
      assert.ok(context.observedInputs.some(item => item.path === publicPath));
      return {tests: [proposal]};
    }});
  assert.equal(calls, 2);
  assert.equal(plan.leads.length, 1);
  assert.equal(plan.leads[0].subject.path, publicPath);
  assert.equal(plan.decisions[0].repairedByMuse, true);
});

test('an empty companion field is removed from a reviewed JSON method contract', async () => {
  const origin = 'http://127.0.0.1:43292';
  const scope = structuredClone(loadScope({origin,
    overrides: {acceptLocal: true}}).scope);
  scope.methods.push('PUT');
  const path = '/api/wallet-preview';
  scope.probes.writeOperations.push({method: 'PUT', path, placement: 'json'});
  const surface = {patterns: [], methodOperations: [{path, method: 'PUT',
    placement: 'json', contentType: 'application/json',
    fields: ['balance', 'paymentId'], requiredFields: []}]};
  const proposal = {family: 'wallet-observation', why: 'Inspect reviewed method response',
    priority: 8, as: 'anonymous', oracle: 'observation', protectedPath: '',
    prelude: [], observe: [], binding: null, bindings: [],
    subject: {method: 'PUT', path, placement: 'json', key: 'balance',
      fixedFields: [{field: 'paymentId', value: 'preview'},
        {field: '', value: ''}], bodyTemplate: '', headers: []},
    controlValue: 'plain', firstValue: 'candidate-one',
    secondValue: 'candidate-two', marker: '', secondMarker: '',
    assertion: {step: 'subject', index: 0, location: 'body', name: ''}};
  const plan = await planResearchFlows(surface, scope, {model: 'fixture',
    budget: 1, modelCallsAvailable: 1,
    infer: async () => ({flows: [proposal]})});
  assert.equal(plan.leads.length, 1);
  assert.deepEqual(plan.leads[0].subject.fixedFields,
    [{field: 'paymentId', value: 'preview'}]);
  assert.equal(plan.decisions[0].normalizedEmptyFixedField, true);
  const sent = [];
  const run = await runResearchFlows(plan.leads, scope, {surface,
    modelCallsAvailable: 0,
    requester: async request => {
      sent.push(request);
      return {status: 200, type: 'application/json', body: '{"ok":true}',
        headers: {}, cached: false, evidenceId: `ev-${sent.length}`};
    }});
  assert.equal(run.results.length, 1);
  assert.ok(sent.length >= 3);
  assert.ok(sent.every(request => request.method === 'PUT' &&
    Object.keys(JSON.parse(request.body)).sort().join(',') === 'balance,paymentId'));
});
