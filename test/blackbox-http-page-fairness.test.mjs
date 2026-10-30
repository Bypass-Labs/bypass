import test from 'node:test';
import assert from 'node:assert/strict';
import {spawn} from 'node:child_process';
import {createHash, randomBytes} from 'node:crypto';
import {loadScope} from '../src/blackbox/scope.mjs';
import {planResearchFlows, runResearchFlows} from '../src/blackbox/research-flow.mjs';

test('accepted HTTP feedback yields model calls to later route pages and remains resumable',
  {timeout: 20000}, async t => {
    const fixture = spawn(process.execPath, ['-e', [
      "const http=require('node:http');",
      "const server=http.createServer((request,response)=>{",
      " const url=new URL(request.url,'http://fixture.invalid');",
      " response.writeHead(200,{'content-type':'application/json','cache-control':'no-store'});",
      " response.end(JSON.stringify({result:url.searchParams.get('q')??''}));",
      "});",
      "server.listen(0,'127.0.0.1',()=>process.stdout.write(String(server.address().port)+'\\n'));",
    ].join('\n')], {stdio: ['ignore', 'pipe', 'inherit']});
    t.after(() => fixture.kill());
    const port = await new Promise((resolve, reject) => {
      fixture.stdout.once('data', chunk => resolve(Number(String(chunk).trim())));
      fixture.once('error', reject);
      fixture.once('exit', code => reject(Error(`fixture exited ${code}`)));
    });
    const origin = `http://127.0.0.1:${port}`;
    const prefix = `/api/${randomBytes(4).toString('hex')}`;
    const paths = Array.from({length: 32}, (_, index) =>
      `${prefix}/r${String(index).padStart(2, '0')}`);
    const first = paths[0], later = paths[31];
    const scope = loadScope({origin, overrides: {acceptLocal: true}}).scope;
    const surface = {origin, patterns: paths.map(pattern => ({pattern,
      methods: ['GET'], params: {q: ['plain']}, source: ['public-asset'],
      responseFacts: {status: 200, type: 'application/json',
        shape: {result: 'string'}}}))};
    const pages = [], pageShares = [], requests = [];
    let revisions = 0;
    const flow = (path, suffix) => ({family: 'observed-query-response',
      why: 'Observed query input accepts distinct harmless values', priority: 8,
      as: 'anonymous', oracle: 'observation', protectedPath: '',
      prelude: [], observe: [], binding: null,
      subject: {method: 'GET', path, placement: 'query', key: 'q',
        fixedFields: [], bodyTemplate: '', headers: []},
      controlValue: `plain-${suffix}`, firstValue: `first-${suffix}`,
      secondValue: `second-${suffix}`, marker: '', secondMarker: '',
      assertion: {step: 'subject', index: 0, location: 'body', name: ''}});
    const infer = async (_model, messages) => {
      const system = messages[0].content;
      const context = JSON.parse(messages[1].content);
      if (system.startsWith('You are planning bounded, authorized HTTP research.')) {
        pages.push(context.routes.map(item => item.path));
        if (context.routes.some(item => item.path === first))
          return {flows: [flow(first, 'initial')]};
        if (context.routes.some(item => item.path === later))
          return {flows: [flow(later, 'later')]};
        return {flows: []};
      }
      if (system.startsWith('Revise at most one bounded, authorized HTTP experiment')) {
        if (context.hypothesis.family === 'observed-query-response' &&
            context.observedRoutes.some(item => item.path === first))
          return {flows: [flow(first, `revision-${++revisions}`)]};
        return {flows: []};
      }
      return {flows: []};
    };
    const requester = async request => {
      const url = new URL(request.url, origin);
      requests.push(url.pathname);
      const response = await fetch(url, {method: request.method ?? 'GET',
        headers: request.headers});
      const body = await response.text();
      return {status: response.status, type: response.headers.get('content-type'),
        body, bytes: Buffer.byteLength(body),
        hash: `sha256:${createHash('sha256').update(body).digest('hex')}`,
        shape: {result: 'string'}, headers: Object.fromEntries(response.headers),
        evidenceId: `ev-${String(requests.length).padStart(4, '0')}`};
    };
    const active = new Map();
    const capture = state => {
      if (state.active?.initial)
        active.set(state.active.initial.proposalId, structuredClone(state.active));
    };
    const plan = await planResearchFlows(surface, scope, {infer,
      model: {model: 'fixture'}, budget: 8, modelCallsAvailable: 20,
      requester, researchDeadline: Date.now() + 10000,
      onAcceptedPage: async (leads, page) => {
        pageShares.push(page.modelCallsAvailable);
        return runResearchFlows(leads, scope, {requester, infer,
          model: {model: 'fixture'}, surface,
          modelCallsAvailable: page.modelCallsAvailable,
          onResearchCheckpoint: capture});
      }});
    assert.equal(plan.coverage.sent, 32, JSON.stringify(plan.coverage));
    assert.ok(pages.some(page => page.includes(later)), JSON.stringify(pages));
    assert.ok(requests.includes(later), 'later accepted route was never tested');
    assert.ok(pageShares[0] <= 4,
      `first page consumed calls reserved for later pages: ${pageShares}`);
    const firstRun = plan.pageRuns[0];
    const firstInvestigation = firstRun?.investigations.find(item =>
      item.initial.path === first);
    assert.equal(firstInvestigation?.stopReason, 'model-or-hypothesis-budget');
    const firstLead = plan.leads.find(item => item.subject.path === first);
    const continuation = active.get(firstLead?.proposalId);
    assert.ok(continuation?.history?.length,
      'the accepted first-page investigation lost its feedback checkpoint');
    const requestsBeforeResume = requests.filter(path => path === first).length;
    const resumed = await runResearchFlows([firstLead], scope, {requester, infer,
      model: {model: 'fixture'}, surface, modelCallsAvailable: 2,
      resumeResearch: {kind: 'http-sequence', active: continuation},
      onResearchCheckpoint: capture});
    assert.ok(resumed.investigations[0].attempts.length >
      firstInvestigation.attempts.length,
    'remaining calls did not return to the saved investigation');
    assert.ok(requests.filter(path => path === first).length > requestsBeforeResume);
  });
