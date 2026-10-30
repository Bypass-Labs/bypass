import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import http from 'node:http';
import os from 'node:os';
import path from 'node:path';
import {createLedger} from '../src/blackbox/ledger.mjs';
import {createLimiter, createRequester, loadScope} from '../src/blackbox/scope.mjs';
import {planResearchFlows} from '../src/blackbox/research-flow.mjs';
import {runResearchSwarm} from '../src/blackbox/web-probes.mjs';

test('a failed research worker leaves a successful peer in the page results',
  {timeout: 30000}, async t => {
    const root = fs.mkdtempSync(path.join(os.tmpdir(), 'bypass-partial-research-'));
    t.after(() => fs.rmSync(root, {recursive: true, force: true}));
    const requests = [];
    const server = http.createServer((request, response) => {
      requests.push(new URL(request.url, 'http://fixture.invalid').pathname);
      response.writeHead(200, {'content-type': 'application/json'});
      response.end('{"result":"stable"}');
    });
    await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
    t.after(() => new Promise(resolve => server.close(resolve)));
    const origin = `http://127.0.0.1:${server.address().port}`;
    const scopeFile = path.join(root, 'scope.json');
    fs.writeFileSync(scopeFile, JSON.stringify({schemaVersion: 1,
      target: {origin}, include: ['/'], limits: {rps: 100,
        modelConcurrency: 2, modelCalls: 8, maxUrls: 20, minutes: 1}}));
    const scope = loadScope({file: scopeFile, origin}).scope;
    const ledger = createLedger(root, {run: 'partial-research'});
    t.after(() => ledger.close());
    const requester = createRequester(scope, {ledger,
      limiter: createLimiter(scope.limits.rps), allowLocal: true});
    const surface = {patterns: ['/fail', '/good'].map(pattern => ({pattern,
      methods: ['GET'], params: {q: ['clean']}, source: ['public-openapi'],
      responseFacts: {status: 200, type: 'application/json'}}))};
    const flow = route => ({family: 'observed response', why: `Check ${route}`,
      priority: 8, as: 'anonymous', oracle: 'observation', prelude: [], observe: [],
      subject: {method: 'GET', path: route, placement: 'query', key: 'q',
        fixedFields: [], bodyTemplate: '', headers: []},
      controlValue: 'clean', firstValue: 'one', secondValue: 'two',
      marker: '', secondMarker: '',
      assertion: {step: 'subject', index: 0, location: 'body', name: ''}});
    const interruptOne = state => {
      if (state.leads[0]?.subject?.path === '/fail' &&
          state.cursor === 0 && !state.active)
        throw Error('fixture worker interruption');
    };
    const infer = async (_model, messages) =>
      messages[0].content.startsWith('You are planning bounded, authorized HTTP research.') ?
        {flows: [flow('/fail'), flow('/good')]} : {flows: []};
    const options = {requester, infer, model: {model: 'fixture'}, surface,
      ledger, modelCallsAvailable: 4, remainingModelCalls: () => 4,
      researchDeadline: Date.now() + 15000,
      onResearchCheckpoint: interruptOne};

    const leads = [flow('/fail'), flow('/good')].map((lead, index) =>
      ({...lead, proposalId: `proposal-${index}`}));
    await assert.rejects(runResearchSwarm(leads, scope, options), error => {
      assert.match(error.message, /fixture worker interruption/);
      assert.equal(Object.keys(error).includes('partialRun'), false);
      assert.deepEqual(error.partialRun.results.map(item => item.proposalId),
        ['proposal-1']);
      return true;
    });
    assert.ok(requests.includes('/good'), 'the peer sent real scoped requests');

    const planned = await planResearchFlows(surface, scope, {
      infer, model: {model: 'fixture'}, requester, ledger,
      budget: 2, modelCallsAvailable: 4, remainingModelCalls: () => 4,
      researchDeadline: Date.now() + 15000,
      onAcceptedPage: (fresh, page) => runResearchSwarm(fresh, scope, {
        ...options, modelCallsAvailable: page.modelCallsAvailable})});
    assert.equal(planned.pageRuns.length, 1);
    const page = planned.pageRuns[0];
    assert.match(page.modelError, /fixture worker interruption/);
    assert.equal(page.results.length, 2);
    assert.equal(page.results.filter(item => item.lead.path === '/good').length, 1,
      'the successful later lead must not be duplicated');
    assert.equal(page.results.find(item => item.lead.path === '/fail')?.verdict,
      'untested', 'the failed earlier lead must remain visible');
    assert.deepEqual(page.deferredLeads.map(item => item.subject.path), ['/fail']);
  });
