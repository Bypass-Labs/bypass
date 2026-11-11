import test from 'node:test';
import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import {loadScope} from '../src/blackbox/scope.mjs';
import {runWebProbes} from '../src/blackbox/web-probes.mjs';

test('newly reviewed web leads execute without waiting for an HTTP sequence revision',
  {timeout: 10000}, async () => {
    const origin = 'http://127.0.0.1:43199';
    const scope = loadScope({origin, overrides: {acceptLocal: true,
      agents: 2, httpWorkers: 2, rps: 100}}).scope;
    const publicPatterns = Array.from({length: 40}, (_, index) => ({
      pattern: `/api/item-${String(index).padStart(3, '0')}`,
      methods: ['GET'], params: {q: ['plain']},
      responseFacts: {status: 200, type: 'application/json'},
    }));
    const surface = {patterns: [...publicPatterns, {
      pattern: '/api/private', methods: ['GET'], params: {},
      fingerprint: {anonymous: {status: 403}, owner: {status: 200}},
      responseFacts: {status: 403, type: 'application/json'},
    }]};
    const events = [];
    let firstLead, lateLead, sequencePlans = 0, webPages = 0, evidence = 0;
    const flow = (context) => ({family: 'observed-query-behavior',
      why: 'Compare harmless values for the observed input', priority: 9,
      as: 'anonymous', oracle: 'observation', protectedPath: '',
      prelude: [], observe: [], binding: null,
      subject: {method: 'GET', path: context.routes[0].path,
        placement: 'query', key: 'q', fixedFields: [], bodyTemplate: '',
        headers: []},
      controlValue: 'ordinary-one', firstValue: 'alternate-one',
      secondValue: 'alternate-two', marker: context.marker,
      secondMarker: context.secondMarker,
      assertion: {step: 'subject', index: 0, location: 'body', name: ''}});
    const infer = async (_model, messages, {schema} = {}) => {
      const prompt = messages[0].content;
      const context = JSON.parse(messages[1].content);
      if (prompt.startsWith('Allocate the next black-box investigation effort'))
        return {priorities: ['access', 'web', 'sequence'].map((name, index) =>
          ({name, weight: 100 - index, why: 'Observed GET query contracts'}))};
      if (prompt.startsWith('Rank only the supplied observed read-only web-test candidates')) {
        webPages++;
        events.push(`web-page-${webPages}:${context.candidates.length}`);
        const candidate = webPages === 1 ?
          context.candidates.find(item => item.kind === 'sql-boolean') :
          context.candidates.find(item => item.path !== firstLead?.path &&
            item.kind !== firstLead?.kind);
        if (webPages === 1) firstLead = candidate;
        if (webPages > 1 && candidate && !lateLead) {
          lateLead = candidate;
          events.push('late-page-reviewed');
        }
        return {priorities: candidate ? [{kind: candidate.kind,
          path: candidate.path, parameter: candidate.parameter,
          priority: 10, why: 'Observed query input'}] : [],
        strategies: [], experiments: []};
      }
      if (prompt.startsWith('You are planning bounded, authorized HTTP research.')) {
        sequencePlans++;
        return {flows: sequencePlans === 2 ? [flow(context)] : []};
      }
      if (prompt.startsWith('Revise at most one bounded, authorized HTTP experiment')) {
        events.push('sequence-revision-started');
        await new Promise(resolve => setTimeout(resolve, 700));
        events.push('sequence-revision-finished');
        return {flows: []};
      }
      const blank = item => item?.type === 'object' ? Object.fromEntries(
        (item.required ?? []).map(key => [key, blank(item.properties?.[key])])) :
        item?.type === 'array' ? [] : item?.type === 'integer' ||
        item?.type === 'number' ? 0 : item?.type === 'boolean' ? false :
        item?.enum?.[0] ?? '';
      return blank(schema);
    };
    const requester = async ({url}) => {
      const target = new URL(url, origin);
      if (target.pathname.startsWith('/api/item-') &&
          !events.includes('first-http')) events.push('first-http');
      if (lateLead && target.pathname === lateLead.path &&
          target.searchParams.get('q')?.startsWith('bx-control-'))
        events.push('late-http');
      const body = '{"items":[{"id":"1"}]}';
      return {status: 200, type: 'application/json', body,
        bytes: Buffer.byteLength(body),
        hash: createHash('sha256').update(body).digest('hex'),
        ids: ['1'], headers: {'content-type': 'application/json'},
        evidenceId: `ev-${String(++evidence).padStart(4, '0')}`};
    };
    const run = await runWebProbes(surface, scope, {requester, infer,
      model: {model: 'fixture'}, budget: 64, maxModelPages: 24,
      env: {[scope.identities.owner.env]: 'fixture-owner'},
      remainingModelCalls: () => 24,
      researchDeadline: Date.now() + 5000});
    assert.ok(run.modelCoverage.earlyWebChecksExecuted > 0,
      'the first Muse web page must start an early verifier pool');
    assert.ok(events.indexOf('first-http') >= 0 &&
      events.indexOf('first-http') < events.indexOf('sequence-revision-finished'),
    `the first web batch waited for sequence feedback: ${events.join(', ')}`);
    assert.ok(lateLead && lateLead.path !== firstLead?.path &&
      lateLead.kind !== firstLead?.kind,
      `Muse never selected an input on a later page: ${JSON.stringify(events)}`);
    assert.ok(events.includes('sequence-revision-started'),
      `no independent sequence revision ran: ${JSON.stringify(events)}`);
    assert.ok(events.includes('late-http'),
      `the later web lead never reached HTTP: ${JSON.stringify(events)}`);
    assert.ok(events.indexOf('late-http') < events.indexOf('sequence-revision-finished'),
      `the later web lead waited behind sequence feedback: ${events.join(', ')}`);
    assert.equal(run.results.filter(item => item.kind === lateLead.kind &&
      item.lead.path === lateLead.path &&
      item.lead.parameter === lateLead.parameter).length, 1,
    'the early pool and ordinary verifier must not report the same lead twice');
  });
