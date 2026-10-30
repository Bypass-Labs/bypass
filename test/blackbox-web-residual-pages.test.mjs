import test from 'node:test';
import assert from 'node:assert/strict';
import {loadScope} from '../src/blackbox/scope.mjs';
import {planWebLeads} from '../src/blackbox/web-probes.mjs';
import {validateJSON} from '../src/schema.mjs';

const scope = loadScope({origin: 'http://127.0.0.1:43198',
  overrides: {acceptLocal: true}}).scope;
const route = index => ({pattern: `/api/record-${index}`, methods: ['GET'],
  params: {q: ['plain']}, responseFacts: {status: 200, type: 'application/json'}});

test('a Muse-generated web candidate does not create a phantom unreviewed page', async () => {
  const surface = {patterns: [route(0)]};
  const baseline = await planWebLeads(surface, scope, {budget: 100});
  let modelCalls = 0;
  const infer = async (_model, messages) => {
    modelCalls++;
    const context = JSON.parse(messages[1].content);
    return {priorities: [], strategies: [], experiments: [{
      family: 'observed-query-behavior', path: '/api/record-0', parameter: 'q',
      priority: 10, why: 'Compare three observed query behaviors',
      oracle: 'observation', controlValue: 'plain',
      firstValue: 'alternate-one', secondValue: 'alternate-two',
      marker: context.canary, secondMarker: context.secondCanary,
      prelude: [], headers: [],
    }]};
  };
  const firstLog = [];
  const first = await planWebLeads(surface, scope, {budget: 100,
    model: 'fixture', infer, maxModelPages: 8,
    log: event => firstLog.push(event)});
  assert.equal(first.modelCoverage.pagesSent, first.modelCoverage.pagesAvailable);
  assert.ok(first.leads.some(item => item.kind === 'model-differential'),
    'Muse must add one executable candidate beyond the baseline inventory');
  assert.ok(first.rankedCandidates.length > baseline.modelCoverage.candidatesAvailable,
    'the model reply must expand the candidate inventory');
  assert.equal(first.modelCoverage.candidatesSent,
    first.modelCoverage.candidatesAvailable,
    'every baseline or Muse-authored candidate was reviewed');
  assert.equal(first.modelCoverage.candidatesPresented,
    baseline.modelCoverage.candidatesAvailable,
    'baseline rows are actually presented to Muse');
  assert.equal(first.modelCoverage.candidatesAuthored,
    first.modelCoverage.candidatesAvailable - baseline.modelCoverage.candidatesAvailable,
    'Muse-authored leads are accounted separately from presented rows');
  assert.ok(firstLog.some(event => /authored/.test(event.message ?? '')),
    `planning log should distinguish authored leads: ${JSON.stringify(firstLog)}`);
  const before = modelCalls;
  const residualLog = [];
  const second = await planWebLeads(surface, scope, {budget: 100,
    model: 'fixture', infer, maxModelPages: 0,
    skipReviewKeys: first.reviewedCandidateKeys,
    carryCandidates: first.rankedCandidates, log: event => residualLog.push(event)});
  assert.equal(modelCalls, before, 'the residual pass has no model-call allowance');
  assert.equal(second.modelCoverage.pagesAvailable, 0,
    'Muse already reviewed the baseline and authored the added candidate');
  assert.ok(!residualLog.some(event =>
    /Muse reviewed 0 of \d+ web candidates/.test(event.message ?? '')),
  `a no-op continuation must not claim Muse skipped the full inventory: ${JSON.stringify(residualLog)}`);
});

test('a genuinely unreviewed baseline page remains available to Muse', async () => {
  const surface = {patterns: Array.from({length: 24}, (_, index) => route(index))};
  const seen = new Set();
  const infer = async (_model, messages) => {
    const context = JSON.parse(messages[1].content);
    for (const item of context.candidates)
      seen.add(`${item.kind} ${item.path} ${item.parameter}`);
    return {priorities: [], strategies: [], experiments: []};
  };
  const first = await planWebLeads(surface, scope, {budget: 1000,
    model: 'fixture', infer, maxModelPages: 1});
  assert.ok(first.modelCoverage.pagesAvailable > 1);
  assert.equal(first.modelCoverage.pagesSent, 1);
  const seenAfterFirst = seen.size;
  const second = await planWebLeads(surface, scope, {budget: 1000,
    model: 'fixture', infer, maxModelPages: 100,
    skipReviewKeys: first.reviewedCandidateKeys,
    carryCandidates: first.rankedCandidates});
  assert.ok(second.modelCoverage.pagesAvailable > 0);
  assert.equal(second.modelCoverage.pagesSent, second.modelCoverage.pagesAvailable);
  assert.ok(seen.size > seenAfterFirst,
    'the continuation must present previously unseen candidates');
});

for (const failure of ['incomplete', 'malformed']) {
  test(`web planning retries a ${failure} model page without losing later candidates`, async () => {
    const surface = {patterns: Array.from({length: 12}, (_, index) => route(index))};
    const baseline = await planWebLeads(surface, scope, {budget: 1000});
    const seen = new Set();
    let calls = 0;
    const infer = async (_model, messages) => {
      calls++;
      if (calls === 1) {
        const error = new Error(failure === 'malformed' ?
          'Invalid type for security_action.priorities.' :
          'Provider response incomplete (max_output_tokens); no action executed.');
        if (failure === 'incomplete') error.details = {reason: 'incomplete_output'};
        throw error;
      }
      for (const item of JSON.parse(messages[1].content).candidates)
        seen.add(`${item.kind} ${item.path} ${item.parameter}`);
      return {priorities: [], strategies: [], experiments: []};
    };
    const plan = await planWebLeads(surface, scope, {budget: 1000,
      model: 'fixture', infer, maxModelPages: 100});
    assert.equal(plan.modelError, null);
    assert.equal(plan.modelCoverage.pageRetries, 1);
    assert.equal(plan.modelCoverage.pagesSent, plan.modelCoverage.pagesAvailable);
    assert.equal(plan.modelCoverage.candidatesSent, baseline.modelCoverage.candidatesAvailable);
    assert.equal(seen.size, baseline.modelCoverage.candidatesAvailable);
  });
}

test('one persistently incomplete web candidate does not hide later pages', async () => {
  const surface = {patterns: Array.from({length: 12}, (_, index) => route(index))};
  const later = new Set();
  const infer = async (_model, messages) => {
    const candidates = JSON.parse(messages[1].content).candidates;
    if (candidates.some(item => item.path === '/api/record-0')) {
      const error = new Error('Provider response incomplete (max_output_tokens); no action executed.');
      error.details = {reason: 'incomplete_output'};
      throw error;
    }
    candidates.forEach(item => later.add(item.path));
    return {priorities: [], strategies: [], experiments: []};
  };
  const plan = await planWebLeads(surface, scope, {budget: 1000,
    model: 'fixture', infer, maxModelPages: 100});
  assert.match(plan.modelError, /incomplete/);
  assert.ok(plan.modelCoverage.candidatesSent > 0);
  assert.ok(later.has('/api/record-11'), 'later candidate pages still reach Muse');
});

test('an extra Muse proposal field does not discard the whole web page', async () => {
  const infer = async (_model, messages, options) => {
    const context = JSON.parse(messages[1].content);
    const reply = {priorities: [], strategies: [], experiments: [{
      family: 'observed-query-behavior', path: '/api/record-0', parameter: 'q',
      priority: 8, why: 'Compare three observed query behaviors',
      oracle: 'observation', controlValue: 'plain', firstValue: 'other-one',
      secondValue: 'other-two', marker: context.canary,
      secondMarker: context.secondCanary, prelude: [], headers: [],
      modelNote: 'Additional hypothesis text is ignored by the executor',
    }]};
    return validateJSON(options.schema, reply, 'security_action');
  };
  const plan = await planWebLeads({patterns: [route(0)]}, scope,
    {budget: 100, model: 'fixture', infer});
  const authored = plan.leads.find(item => item.kind === 'model-differential');
  assert.equal(plan.modelError, null);
  assert.ok(authored);
  assert.equal(authored.lead.modelNote, undefined);
});
