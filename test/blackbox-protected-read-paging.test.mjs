import test from 'node:test';
import assert from 'node:assert/strict';
import {loadScope} from '../src/blackbox/scope.mjs';
import {planResearchFlows} from '../src/blackbox/research-flow.mjs';

test('HTTP sequence pages let Muse select an unlinked protected read after the first 32', async () => {
  const origin = 'http://127.0.0.1:49831';
  const scope = structuredClone(loadScope({origin,
    overrides: {acceptLocal: true}}).scope);
  const linkedPath = '/private/linked';
  const latePath = '/private/late-unlinked';
  const writePath = '/private/linked/item';
  scope.probes.writeOperations = [{method: 'PATCH', path: writePath,
    placement: 'json'}];
  scope.localAutoMethodContracts = {[`PATCH json ${writePath}`]:
    {contentType: 'application/json', fields: ['note']}};
  const protectedRoute = path => ({pattern: path, methods: ['GET'],
    fingerprint: {owner: {status: 200}, anonymous: {status: 403}}});
  const surface = {patterns: [
    {pattern: '/api/probe', methods: ['GET'], params: {q: ['plain']}},
    ...Array.from({length: 44}, (_, index) =>
      protectedRoute(`/private/archive-${index}`)),
    protectedRoute(linkedPath), protectedRoute(latePath),
  ], methodOperations: [{method: 'PATCH', path: writePath,
    placement: 'json', fields: ['note'], requiredFields: ['note'],
    contentType: 'application/json'}]};
  const contexts = [];
  const plan = await planResearchFlows(surface, scope, {
    env: {OWNER_TOKEN: 'fixture-owner'}, model: 'fixture',
    budget: 1, modelCallsAvailable: 12,
    infer: async (_model, messages) => {
      const context = JSON.parse(messages[1].content);
      contexts.push(context);
      if (!context.protectedReadRoutes.includes(latePath)) return {flows: []};
      return {flows: [{family: 'record-disclosure', priority: 8,
        why: 'A public observed query may return an owner-only record',
        as: 'anonymous', oracle: 'protected-body', protectedPath: latePath,
        prelude: [], observe: [], binding: null,
        subject: {method: 'GET', path: '/api/probe', placement: 'query',
          key: 'q', fixedFields: [], bodyTemplate: '', headers: []},
        controlValue: 'plain', firstValue: 'one', secondValue: 'two',
        marker: '', secondMarker: '',
        assertion: {step: 'subject', index: 0, location: 'body', name: ''}}]};
    }});
  assert.ok(contexts.length > 1, 'the route inventory needed multiple Muse pages');
  assert.ok(contexts[0].protectedReadRoutes.includes(linkedPath),
    'a read linked to the first write is prioritized');
  assert.ok(contexts.some(context => context.protectedReadRoutes.includes(latePath)),
    'an unrelated protected read must appear on a later page');
  assert.ok(plan.leads.some(lead => lead.protectedPath === latePath),
    'Muse could select the later owner-only read for an independent proof');
  assert.equal(plan.coverage.protectedReadsCut, 0);
});
