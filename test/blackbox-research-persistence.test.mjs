import test from 'node:test';
import assert from 'node:assert/strict';
import {loadScope} from '../src/blackbox/scope.mjs';
import {planResearchFlows, runResearchFlows} from '../src/blackbox/research-flow.mjs';

test('Muse can execute a third revision after two identical negative response shapes', async () => {
  const origin = 'http://127.0.0.1:43319';
  const scope = structuredClone(loadScope({origin,
    overrides: {acceptLocal: true}}).scope);
  const surface = {patterns: [{pattern: '/probe', methods: ['GET'],
    params: {q: ['plain']}}]};
  const values = [];
  let evidence = 0, revisions = 0;
  const flow = prefix => ({family: 'context-dependent-input',
    why: 'Observed query input may need a different value shape', priority: 8,
    as: 'anonymous', oracle: 'observation', prelude: [],
    subject: {method: 'GET', path: '/probe', placement: 'query', key: 'q',
      fixedFields: [], bodyTemplate: '', headers: []}, observe: [], binding: null,
    controlValue: `${prefix}-control`, firstValue: `${prefix}-first`,
    secondValue: `${prefix}-second`, marker: '', secondMarker: '',
    assertion: {step: 'subject', index: 0, location: 'body', name: ''}});
  const run = await runResearchFlows([flow('initial')], scope, {
    surface, model: 'fixture', modelCallsAvailable: 3,
    requester: async ({url}) => {
      const value = new URL(url, origin).searchParams.get('q');
      values.push(value);
      const third = value?.startsWith('third-');
      const body = JSON.stringify({result: third ? 'changed' : 'ordinary'});
      return {status: third ? 201 : 200, type: 'application/json', body,
        headers: {'cache-control': 'no-store'},
        hash: `sha256:fixture-${third ? 'third' : 'same'}`,
        evidenceId: `ev-${String(++evidence).padStart(4, '0')}`};
    },
    infer: async (_model, messages) => {
      revisions++;
      const context = JSON.parse(messages[1].content);
      if (revisions === 3) assert.match(context.noProgress,
        /same response status and structure/i);
      return {flows: [flow(['first', 'second', 'third'][revisions - 1])]};
    }});
  assert.equal(revisions, 3);
  assert.equal(run.investigations[0].attempts.length, 4);
  assert.ok(values.includes('third-first'),
    'the third Muse revision must reach the observed route');
  assert.equal(run.modelCalls, 3);
});

test('Muse revision receives the owner-only read that can prove a write-side impact', async () => {
  const origin = 'http://127.0.0.1:43320';
  const scope = structuredClone(loadScope({origin,
    overrides: {acceptLocal: true}}).scope);
  const protectedPath = '/api/record-ab12cd34';
  const writePath = `${protectedPath}/review`;
  scope.probes.writeOperations = [{method: 'PATCH', path: writePath,
    placement: 'json'}];
  scope.localAutoMethodContracts = {[`PATCH json ${writePath}`]:
    {contentType: 'application/json', fields: ['reviewState']}};
  const surface = {patterns: [{pattern: protectedPath, methods: ['GET'],
    fingerprint: {owner: {status: 200}, anonymous: {status: 403}}}],
  methodOperations: [{method: 'PATCH', path: writePath, placement: 'json',
    fields: ['reviewState'], contentType: 'application/json'}]};
  const flow = {family: 'record-write', why: 'An observed write may change an owner record',
    priority: 8, as: 'anonymous', oracle: 'observation', prelude: [],
    subject: {method: 'PATCH', path: writePath, placement: 'json',
      key: 'reviewState', fixedFields: [], bodyTemplate: '', headers: [],
      contentType: 'application/json'}, observe: [], binding: null,
    controlValue: 'ordinary', firstValue: 'candidate-one',
    secondValue: 'candidate-two', marker: '', secondMarker: '',
    assertion: {step: 'subject', index: 0, location: 'body', name: ''}};
  let revisionContext = null;
  const run = await runResearchFlows([flow], scope, {surface,
    env: {OWNER_TOKEN: 'fixture-owner'}, model: 'fixture', modelCallsAvailable: 1,
    requester: async () => ({status: 200, type: 'application/json',
      body: '{"updated":true}', headers: {'cache-control': 'no-store'},
      hash: 'sha256:same', evidenceId: 'ev-0001'}),
    infer: async (_model, messages) => {
      revisionContext = JSON.parse(messages[1].content);
      assert.match(messages[0].content, /identical write responses do not rule out owner-visible mutation/i);
      return {flows: []};
    }});
  assert.ok(revisionContext, JSON.stringify(run));
  assert.deepEqual(revisionContext.protectedReadRoutes, [protectedPath]);
  assert.deepEqual(revisionContext.readWriteLinks.map(item =>
    [item.writePath, item.readPath, item.relation]),
  [[writePath, protectedPath, 'read-prefix-of-write']]);
  assert.equal(revisionContext.readWriteLinksCut, 0);
  assert.ok(revisionContext.observedRoutes.some(item => item.path === writePath));
});

test('Muse sees a linked owner read beyond 32 earlier protected routes and can plan its write', async () => {
  const origin = 'http://127.0.0.1:43321';
  const scope = structuredClone(loadScope({origin,
    overrides: {acceptLocal: true}}).scope);
  const protectedPath = '/api/records/late-record';
  const writePath = `${protectedPath}/review`;
  scope.probes.writeOperations = [{method: 'PATCH', path: writePath,
    placement: 'json'}];
  scope.localAutoMethodContracts = {[`PATCH json ${writePath}`]:
    {contentType: 'application/json', fields: ['reviewState']}};
  const surface = {patterns: [
    ...Array.from({length: 40}, (_, index) => ({
      pattern: `/api/records/unrelated-${index}`, methods: ['GET'],
      fingerprint: {owner: {status: 200}, anonymous: {status: 403}}})),
    {pattern: protectedPath, methods: ['GET'],
      fingerprint: {owner: {status: 200}, anonymous: {status: 403}}}],
  methodOperations: [{method: 'PATCH', path: writePath, placement: 'json',
    fields: ['reviewState'], contentType: 'application/json'}]};
  const env = {OWNER_TOKEN: 'fixture-owner'};
  let context = null;
  const result = await planResearchFlows(surface, scope, {env, model: 'fixture',
    budget: 1, modelCallsAvailable: 1,
    infer: async (_model, messages) => {
      context = JSON.parse(messages[1].content);
      assert.match(messages[0].content, /owner reads before and after the write/i);
      return {flows: [{family: 'owner-record-write', priority: 8,
        why: 'An observed anonymous write may affect an owner-only record',
        as: 'anonymous', oracle: 'state-change', protectedPath,
        prelude: [], observe: [], binding: null,
        subject: {method: 'PATCH', path: writePath, placement: 'json',
          key: 'reviewState', fixedFields: [], bodyTemplate: '', headers: []},
        controlValue: 'plain', firstValue: 'bxfirstcandidate',
        secondValue: 'bxsecondcandidate', marker: context.marker,
        secondMarker: context.secondMarker,
        assertion: {step: 'subject', index: 0, location: 'body', name: ''}}]};
    }});
  assert.ok(context, JSON.stringify(result));
  assert.equal(context.protectedReadRoutesAvailable, 41);
  assert.equal(context.protectedReadRoutesCut, 9);
  assert.ok(context.protectedReadRoutes.includes(protectedPath));
  assert.deepEqual(context.readWriteLinks.map(item =>
    [item.writePath, item.readPath, item.method, item.relation]),
  [[writePath, protectedPath, 'PATCH', 'read-prefix-of-write']]);
  assert.equal(context.readWriteLinksAvailable, 1);
  assert.equal(context.readWriteLinksCut, 0);
  assert.equal(result.coverage.protectedReadsAvailable, 41);
  assert.equal(result.coverage.readWriteLinksSent, 1);
  assert.equal(result.leads.length, 1, JSON.stringify({decisions: result.decisions,
    modelError: result.modelError}));
});
