import test from 'node:test';
import assert from 'node:assert/strict';
import {loadScope, taskAllowance} from '../src/blackbox/scope.mjs';
import {planWebLeads} from '../src/blackbox/web-probes.mjs';

test('a fresh scope plans more than 400 observed leads without a hidden task cut', async () => {
  const {scope} = loadScope({origin: 'http://127.0.0.1:4329',
    overrides: {acceptLocal: true}});
  const surface = {patterns: Array.from({length: 450}, (_, index) => ({
    pattern: `/api/search/${index}`, representative: `/api/search/${index}`,
    methods: ['GET'], params: {q: ['item']}, source: ['observed-openapi'],
    responseFacts: {status: 200, type: 'application/json'},
  }))};
  const planned = await planWebLeads(surface, scope, {budget: taskAllowance(scope)});
  assert.ok(planned.leads.length > 400, `${planned.leads.length} leads selected`);
  assert.equal(planned.cut, 0);
  const capped = await planWebLeads(surface, {...scope,
    limits: {...scope.limits, tasks: 400}}, {budget: 400});
  assert.equal(capped.leads.length, 400);
  assert.ok(capped.cut > 0);
});
