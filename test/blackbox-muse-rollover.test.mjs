import test from 'node:test';
import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import {loadScope} from '../src/blackbox/scope.mjs';
import {runWebProbes} from '../src/blackbox/web-probes.mjs';
import {planResearchFlows} from '../src/blackbox/research-flow.mjs';
import {remainingDeferredCut} from '../src/blackbox/index.mjs';

test('an early protected share carries a valid overflow HTTP proposal into the later pass', async () => {
  const origin = 'http://127.0.0.1:43997';
  const scope = loadScope({origin, overrides: {acceptLocal: true}}).scope;
  const surface = {origin, patterns: ['/api/first', '/api/second'].map(pattern => ({
    pattern, methods: ['GET'], params: {q: []}, source: ['public-asset'],
    responseFacts: {status: 200, type: 'application/json', shape: {result: 'string'}}}))};
  let planningCalls = 0, requests = 0;
  const infer = async (_model, messages) => {
    const system = messages[0].content;
    if (system.startsWith('Allocate the next black-box investigation effort'))
      return {priorities: ['sequence', 'web', 'access', 'session', 'stored', 'json']
        .map(name => ({name, weight: name === 'sequence' ? 100 : 1,
          why: 'Observed scoped GET input'}))};
    if (system.startsWith('You are planning bounded, authorized HTTP research.')) {
      planningCalls++;
      if (planningCalls > 1) return {flows: []};
      const flow = path => ({family: 'response-shape', why: 'Observed query input',
        priority: 5, as: 'anonymous', oracle: 'observation', prelude: [],
        subject: {method: 'GET', path, placement: 'query', key: 'q',
          fixedFields: [], bodyTemplate: '', headers: []}, observe: [], binding: null,
        controlValue: 'plain', firstValue: 'one', secondValue: 'two',
        marker: '', secondMarker: '',
        assertion: {step: 'subject', index: 0, location: 'body', name: ''}});
      return {flows: [flow('/api/first'), flow('/api/second')]};
    }
    if (system.startsWith('Rank only the supplied observed read-only web-test candidates'))
      return {priorities: [], strategies: [], experiments: []};
    return {flows: []};
  };
  const requester = async request => {
    const value = new URL(request.url, origin).searchParams.get('q') ?? '';
    const body = JSON.stringify({result: value});
    return {status: 200, type: 'application/json', body,
      shape: {result: 'string'}, bytes: Buffer.byteLength(body),
      hash: `sha256:${createHash('sha256').update(body).digest('hex')}`,
      headers: {'cache-control': 'no-store'}, evidenceId: `ev-${++requests}`};
  };
  const earlyEvents = [];
  const early = await runWebProbes(surface, scope, {requester, infer,
    model: {model: 'fixture'}, budget: 1, maxModelPages: 5,
    deferOverflow: true, log: event => earlyEvents.push(event)});
  assert.equal(early.deferredLeads.length, 1);
  assert.equal(early.deferredLeads[0].lead.subject.path, '/api/second');
  assert.equal(early.modelCoverage.httpSequenceDeferred, 1);
  assert.equal(early.modelCoverage.httpSequenceRejected, 0);
  assert.ok(early.cut > 0);
  assert.ok(earlyEvents.some(event => event.stage === 'web-probes' &&
    event.message.includes('deferred to later pass')));
  const late = await runWebProbes(surface, scope, {requester, infer,
    model: {model: 'fixture'}, budget: 50, maxModelPages: 5,
    carryForward: early.deferredLeads});
  assert.ok(late.results.some(item =>
    item.proposalId === early.deferredLeads[0].proposalId &&
    item.lead.path === '/api/second' && item.verdict !== 'untested'));
  assert.equal(remainingDeferredCut(early, late), 0);
});

test('unused Muse calls continue HTTP-sequence planning at unreviewed routes', async () => {
  const origin = 'http://127.0.0.1:43997';
  const scope = loadScope({origin, overrides: {acceptLocal: true}}).scope;
  const late = '/api/r69';
  const surface = {origin, patterns: Array.from({length: 70}, (_, index) => ({
    pattern: `/api/r${index}`, methods: ['GET'],
    params: index === 69 ? {q: []} : {}, source: ['public-asset'],
    responseFacts: {status: 200, type: 'application/json', shape: {result: 'string'}},
  }))};
  const pages = [];
  const infer = async (_model, messages) => {
    const system = messages[0].content;
    if (system.startsWith('Allocate the next black-box investigation effort'))
      return {priorities: [
        {name: 'sequence', weight: 2, why: 'Observed route and query input'},
        {name: 'web', weight: 2, why: 'Observed query input'},
        {name: 'access', weight: 1, why: 'Keep available'},
        {name: 'session', weight: 1, why: 'Keep available'},
        {name: 'stored', weight: 1, why: 'Keep available'},
        {name: 'json', weight: 1, why: 'Keep available'},
      ]};
    if (system.startsWith('You are planning bounded, authorized HTTP research.')) {
      const context = JSON.parse(messages[1].content);
      pages.push(context.routes.map(route => route.path));
      const flow = route => ({family: 'query-observation', why: 'Compare an observed query input',
        priority: 8, as: 'anonymous', oracle: 'observation', prelude: [],
        subject: {method: 'GET', path: route, placement: 'query', key: 'q',
          fixedFields: [], bodyTemplate: '', headers: []}, observe: [], binding: null,
        controlValue: 'plain', firstValue: 'one', secondValue: 'two',
        marker: '', secondMarker: '',
        assertion: {step: 'subject', index: 0, location: 'body', name: ''}});
      return {flows: context.routes.some(route => route.path === late) ? [flow(late)] : []};
    }
    if (system.startsWith('Rank only the supplied observed read-only web-test candidates'))
      return {priorities: [], strategies: [], experiments: []};
    return {flows: []};
  };
  const model = {model: 'fixture'};
  const initial = await planResearchFlows(surface, scope, {infer, model,
    budget: 6, modelCallsAvailable: 3});
  assert.equal(initial.coverage.sent, 24);
  assert.equal(initial.coverage.nextRouteOffset, 24);
  assert.equal(initial.leads.length, 0);
  assert.ok(!pages.flat().includes(late));
  pages.length = 0;
  let count = 0;
  const progress = [];
  const requester = async request => {
    const url = new URL(request.url, origin);
    const body = JSON.stringify({result: url.searchParams.get('q') ?? ''});
    return {status: 200, type: 'application/json', body,
      shape: {result: 'string'}, bytes: Buffer.byteLength(body),
      hash: `sha256:${createHash('sha256').update(body).digest('hex')}`,
      headers: {'cache-control': 'no-store'}, evidenceId: `ev-${++count}`};
  };
  const result = await runWebProbes(surface, scope, {requester, infer, model,
    budget: 6, maxModelPages: 16,
    onProgressCheckpoint: snapshot => progress.push(snapshot)});
  assert.ok(result.modelCoverage.httpSequenceRolloverCalls >= 1);
  assert.ok(result.modelCoverage.httpSequenceRolloverRoutesSent >= 10);
  assert.equal(result.modelCoverage.httpSequenceSent, 70);
  assert.equal(result.modelCoverage.httpSequenceAccepted, 1);
  assert.ok(pages.some(page => page.includes(late)));
  assert.ok(result.strategyDecisions.some(decision => decision.planningPass ===
    'unused-call-rollover' && decision.accepted && decision.path === late));
  assert.ok(result.results.some(item => item.kind === 'model-http-observation' &&
    item.lead?.path === late), JSON.stringify(result.results.map(item =>
    ({kind: item.kind, path: item.lead?.subject?.path ?? item.lead?.path,
      verdict: item.verdict}))));
  assert.equal(progress.at(-1)?.phase, 'complete');
});
