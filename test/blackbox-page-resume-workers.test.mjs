import test from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import {createHash} from 'node:crypto';
import {loadScope} from '../src/blackbox/scope.mjs';
import {runResearchSwarm, runWebProbes} from '../src/blackbox/web-probes.mjs';

test('saved route-page leads resume with separate evidence and concurrent Muse feedback',
  {timeout: 20000}, async t => {
    const server = http.createServer((request, response) => {
      const url = new URL(request.url, 'http://fixture.invalid');
      response.writeHead(200, {'content-type': 'application/json',
        'cache-control': 'no-store'});
      response.end(JSON.stringify({value: url.searchParams.get('q') ?? ''}));
    });
    await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
    t.after(() => new Promise(resolve => server.close(resolve)));
    const origin = `http://127.0.0.1:${server.address().port}`;
    const {scope} = loadScope({origin, overrides: {acceptLocal: true,
      modelAgents: 2, httpWorkers: 2, rps: 100}});
    const routes = ['/api/alpha', '/api/beta'];
    const surface = {patterns: routes.map(pattern => ({pattern,
      methods: ['GET'], params: {q: ['plain']},
      responseFacts: {status: 200, type: 'application/json'}}))};
    const leads = routes.map((route, index) => ({
      proposalId: `resume-${index}`, family: 'observed-query-behavior',
      why: 'Compare the observed query response with harmless alternatives',
      priority: 8, as: 'anonymous', oracle: 'observation',
      prelude: [], observe: [],
      subject: {method: 'GET', path: route, placement: 'query', key: 'q',
        fixedFields: [], bodyTemplate: '', headers: []},
      controlValue: 'plain', firstValue: 'first', secondValue: 'second',
      marker: '', secondMarker: '',
      assertion: {step: 'subject', index: 0, location: 'body', name: ''}}));
    let evidence = 0;
    const requester = async ({url, method = 'GET', headers = {}}) => {
      const response = await fetch(new URL(url, origin), {method, headers,
        redirect: 'manual'});
      const body = await response.text();
      return {status: response.status, type: response.headers.get('content-type'),
        body, bytes: Buffer.byteLength(body),
        hash: createHash('sha256').update(body).digest('hex'),
        headers: Object.fromEntries(response.headers), cached: false,
        evidenceId: `ev-${String(++evidence).padStart(4, '0')}`};
    };
    const saved = {};
    await runResearchSwarm(leads, scope, {requester, surface,
      infer: async () => ({flows: []}), model: {model: 'fixture'},
      modelCallsAvailable: 0, remainingModelCalls: () => 0,
      onResearchCheckpoint: state => {
        if (state.active?.phase === 'attempted')
          saved[state.leads[0].proposalId] = structuredClone(state.active);
      }});
    assert.deepEqual(Object.keys(saved).toSorted(), leads.map(item =>
      item.proposalId));
    const priorRequests = evidence;
    const pathsSeen = [];
    let activeModels = 0, peakModels = 0, pageCheckpoint;
    const infer = async (_model, messages) => {
      const prompt = messages[0].content;
      if (!prompt.startsWith('Revise at most one bounded, authorized HTTP experiment'))
        return {flows: [], priorities: [], strategies: [], experiments: []};
      const context = JSON.parse(messages[1].content);
      pathsSeen.push(context.recentAttempts?.[0]?.path);
      activeModels++;
      peakModels = Math.max(peakModels, activeModels);
      await new Promise(resolve => setTimeout(resolve, 120));
      activeModels--;
      return {flows: []};
    };
    const run = await runWebProbes(surface, scope, {requester, infer,
      model: {model: 'fixture'}, budget: 2, maxModelPages: 2,
      remainingModelCalls: () => 2, flowPagePass: 'primary',
      resumeResearch: {kind: 'http-sequence-page', pass: 'primary', origin,
        pendingLeads: leads, pendingCompletedIds: [], pendingActiveById: saved},
      onFlowPageCheckpoint: state => {pageCheckpoint = state;},
      researchDeadline: Date.now() + 10000});
    assert.equal(peakModels, 2,
      'independent saved investigations waited behind one Muse revision');
    assert.deepEqual(pathsSeen.toSorted(), routes);
    assert.equal(evidence, priorRequests,
      'resuming an attempted lead must not repeat its original HTTP controls');
    assert.deepEqual(run.results.filter(item => item.proposalId)
      .map(item => item.proposalId).toSorted(), leads.map(item =>
      item.proposalId));
    assert.equal(pageCheckpoint.pendingLeads.length, 0);

    pathsSeen.length = 0;
    pageCheckpoint = null;
    await runWebProbes(surface, scope, {requester, infer,
      model: {model: 'fixture'}, budget: 2, maxModelPages: 1,
      remainingModelCalls: () => 1, flowPagePass: 'primary',
      resumeResearch: {kind: 'http-sequence-page', pass: 'primary', origin,
        pendingLeads: leads, pendingCompletedIds: [], pendingActiveById: saved},
      onFlowPageCheckpoint: state => {pageCheckpoint = state;},
      researchDeadline: Date.now() + 10000});
    assert.equal(pathsSeen.length, 1);
    assert.deepEqual(pageCheckpoint.pendingCompletedIds,
      [leads[0].proposalId]);
    assert.deepEqual(pageCheckpoint.pendingLeads.map(item => item.proposalId),
      leads.map(item => item.proposalId),
      'the page keeps uncompleted leads until every one has run');
    assert.ok(pageCheckpoint.pendingActiveById[leads[1].proposalId]);

    pathsSeen.length = 0;
    pageCheckpoint = null;
    let allowanceReads = 0;
    await runWebProbes(surface, scope, {requester, infer,
      model: {model: 'fixture'}, budget: 2, maxModelPages: 2,
      remainingModelCalls: () => ++allowanceReads === 1 ? 2 : 0,
      flowPagePass: 'primary',
      resumeResearch: {kind: 'http-sequence-page', pass: 'primary', origin,
        pendingLeads: leads, pendingCompletedIds: [], pendingActiveById: saved},
      onFlowPageCheckpoint: state => {pageCheckpoint = state;},
      researchDeadline: Date.now() + 10000});
    assert.equal(pathsSeen.length, 0);
    assert.deepEqual(pageCheckpoint.pendingCompletedIds, [],
      'a shared call-budget change must not consume a saved investigation');
    assert.deepEqual(Object.keys(pageCheckpoint.pendingActiveById).toSorted(),
      leads.map(item => item.proposalId));

    pageCheckpoint = null;
    let failedCalls = 0;
    const failingInfer = async (_model, messages) => {
      if (messages[0].content.startsWith(
          'Revise at most one bounded, authorized HTTP experiment')) {
        failedCalls++;
        throw Error('fixture Muse connection interrupted');
      }
      return {flows: [], priorities: [], strategies: [], experiments: []};
    };
    await runWebProbes(surface, scope, {requester, infer: failingInfer,
      model: {model: 'fixture'}, budget: 2, maxModelPages: 2,
      remainingModelCalls: () => 2, flowPagePass: 'primary',
      resumeResearch: {kind: 'http-sequence-page', pass: 'primary', origin,
        pendingLeads: leads, pendingCompletedIds: [], pendingActiveById: saved},
      onFlowPageCheckpoint: state => {pageCheckpoint = state;},
      researchDeadline: Date.now() + 10000});
    assert.equal(failedCalls, 2);
    assert.deepEqual(pageCheckpoint.pendingCompletedIds, []);
    assert.deepEqual(Object.keys(pageCheckpoint.pendingActiveById).toSorted(),
      leads.map(item => item.proposalId),
      'a failed Muse call must not erase either saved attempt');
  });
