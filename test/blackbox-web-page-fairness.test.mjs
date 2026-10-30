import test from 'node:test';
import assert from 'node:assert/strict';
import {spawn} from 'node:child_process';
import {createHash} from 'node:crypto';
import {loadScope} from '../src/blackbox/scope.mjs';
import {planWebLeads, runWebProbes} from '../src/blackbox/web-probes.mjs';

test('Muse reviews later web pages and the selected late route gets a real HTTP check',
  {timeout: 30000}, async t => {
    const server = spawn(process.execPath, ['-e', [
      "const http=require('node:http');",
      "const server=http.createServer((request,response)=>{",
      " const body=JSON.stringify({items:[{id:'1'}]});",
      " response.writeHead(200,{'content-type':'application/json','cache-control':'no-store'});",
      ' response.end(body);',
      '});',
      "server.listen(0,'127.0.0.1',()=>process.stdout.write(String(server.address().port)+'\\n'));",
    ].join('\n')], {stdio: ['ignore', 'pipe', 'inherit']});
    t.after(() => server.kill());
    const port = await new Promise((resolve, reject) => {
      server.stdout.once('data', chunk => resolve(Number(String(chunk).trim())));
      server.once('error', reject);
      server.once('exit', code => reject(Error(`fixture exited ${code}`)));
    });
    const origin = `http://127.0.0.1:${port}`;
    const scope = loadScope({origin, overrides: {acceptLocal: true}}).scope;
    const latePath = '/api/z023/item';
    const surface = {patterns: Array.from({length: 24}, (_, index) => ({
      pattern: `/api/z${String(index).padStart(3, '0')}/item`, methods: ['GET'],
      params: {q: ['1']}, responseFacts: {status: 200, type: 'application/json'},
    }))};
    const baseline = await planWebLeads(surface, scope, {budget: 1000});
    assert.ok(baseline.modelCoverage.pagesAvailable > 1);
    const shown = new Set(), repeated = new Set(), seenPages = [], planningTurns = [];
    let revisions = 0;
    const flow = (context, number) => ({family: 'observed-query-behavior',
      why: 'Observed item query accepts harmless alternate values', priority: 9,
      as: 'anonymous', oracle: 'observation', protectedPath: '',
      prelude: [], observe: [], binding: null,
      subject: {method: 'GET', path: '/api/z000/item', placement: 'query',
        key: 'q', fixedFields: [], bodyTemplate: '', headers: []},
      controlValue: `ordinary-${number}`, firstValue: `first-${number}`,
      secondValue: `second-${number}`, marker: context.marker,
      secondMarker: context.secondMarker,
      assertion: {step: 'subject', index: 0, location: 'body', name: ''}});
    const infer = async (_model, messages, {schema} = {}) => {
      const prompt = messages[0].content;
      const context = JSON.parse(messages[1].content);
      if (prompt.startsWith('Allocate the next black-box investigation effort'))
        return {priorities: [
          {name: 'sequence', weight: 100, why: 'Observed route contracts'},
          {name: 'web', weight: 1, why: 'Observed query inputs'},
        ]};
      if (prompt.startsWith('Rank only the supplied observed read-only web-test candidates')) {
        planningTurns.push('web');
        const keys = context.candidates.map(item =>
          `${item.kind} ${item.path} ${item.parameter}`);
        for (const key of keys) {
          if (shown.has(key)) repeated.add(key);
          shown.add(key);
        }
        seenPages.push(context.page);
        const late = context.candidates.find(item =>
          item.kind === 'sql-boolean' && item.path === latePath);
        return {priorities: late ? [{kind: late.kind, path: late.path,
          parameter: late.parameter, priority: 10,
          why: 'Observed numeric item query on a later web page'}] : [],
        strategies: [], experiments: []};
      }
      if (prompt.startsWith('You are planning bounded, authorized HTTP research.')) {
        planningTurns.push('sequence');
        return {flows: context.routes.some(item => item.path === '/api/z000/item') ?
          [flow(context, 0)] : []};
      }
      if (prompt.startsWith('Revise at most one bounded, authorized HTTP experiment')) {
        planningTurns.push('sequence-revision');
        await new Promise(resolve => setTimeout(resolve, 65));
        return {flows: revisions++ < 12 ? [flow(context, revisions)] : []};
      }
      const blank = item => item?.type === 'object' ? Object.fromEntries(
        (item.required ?? []).map(key => [key, blank(item.properties?.[key])])) :
        item?.type === 'array' ? [] : item?.type === 'integer' ||
        item?.type === 'number' ? 0 : item?.type === 'boolean' ? false :
        item?.enum?.[0] ?? '';
      return blank(schema);
    };
    let nextEvidence = 0;
    const requested = [];
    const requester = async ({url, method = 'GET', body, headers = {}}) => {
      const target = new URL(url, origin);
      requested.push(target);
      if (target.pathname === latePath && /\b(?:AND|OR)\b/i.test(
        target.searchParams.get('q') ?? '')) planningTurns.push('late-sql-http');
      const response = await fetch(target, {method, body, headers,
        redirect: 'manual'});
      const text = await response.text();
      return {status: response.status, type: response.headers.get('content-type'),
        body: text, bytes: Buffer.byteLength(text),
        hash: createHash('sha256').update(text).digest('hex'), ids: ['1'],
        headers: Object.fromEntries(response.headers),
        evidenceId: `ev-${String(++nextEvidence).padStart(4, '0')}`};
    };
    const run = await runWebProbes(surface, scope, {requester, infer,
      model: {model: 'fixture'}, budget: 40, maxModelPages: 18,
      remainingModelCalls: () => 18, researchDeadline: Date.now() + 25000});
    assert.equal(repeated.size, 0, `Muse saw duplicate candidates: ${[...repeated]}`);
    assert.equal(shown.size, baseline.modelCoverage.candidatesAvailable,
      JSON.stringify({shown: shown.size, coverage: run.modelCoverage}));
    assert.equal(run.modelCoverage.candidatesSent,
      run.modelCoverage.candidatesAvailable, JSON.stringify(run.modelCoverage));
    assert.ok(seenPages.length >= baseline.modelCoverage.pagesAvailable,
      JSON.stringify({seenPages, coverage: run.modelCoverage}));
    const secondSequence = planningTurns.indexOf('sequence',
      planningTurns.indexOf('sequence') + 1);
    assert.ok(secondSequence > planningTurns.lastIndexOf('web'),
      `later web pages waited behind deep sequence planning: ${planningTurns}`);
    assert.ok(planningTurns.indexOf('late-sql-http') >= 0 &&
      planningTurns.indexOf('late-sql-http') < secondSequence,
    `the late Muse-selected SQL check waited behind deep sequence planning: ${planningTurns}`);
    assert.ok(run.plan.some(item => item.kind === 'sql-boolean' &&
      item.path === latePath && item.by === 'model'));
    assert.ok(run.results.some(item => item.kind === 'sql-boolean' &&
      item.lead.path === latePath && item.verdict !== 'untested'));
    assert.equal(run.results.filter(item => item.kind === 'sql-boolean' &&
      item.lead.path === latePath).length, 1,
    'an early verifier result must not be duplicated in the ordinary pass');
    assert.equal(run.results.length, run.plan.length,
    'every selected lead must have exactly one executed or queued result');
    assert.ok(run.modelCoverage.earlyWebChecksExecuted > 0);
    assert.ok(requested.some(url => url.pathname === latePath &&
      /\b(?:AND|OR)\b/i.test(url.searchParams.get('q') ?? '')),
    'the late Muse-ranked route must receive a real boolean SQL check');
  });
