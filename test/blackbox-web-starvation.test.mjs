import test from 'node:test';
import assert from 'node:assert/strict';
import {spawn} from 'node:child_process';
import {createHash, randomBytes} from 'node:crypto';
import {loadScope} from '../src/blackbox/scope.mjs';
import {runWebProbes} from '../src/blackbox/web-probes.mjs';

test('web workers confirm a late observed SQL lead while Muse refines an HTTP sequence',
  {timeout: 10000}, async t => {
    const prefix = `/api/${randomBytes(5).toString('hex')}`;
    const search = `${prefix}/search`;
    const fixture = spawn(process.execPath, ['-e', [
      "const http=require('node:http');",
      `const search=${JSON.stringify(search)};`,
      "const server=http.createServer((request,response)=>{",
      " const url=new URL(request.url,'http://fixture.invalid');",
      " const value=url.searchParams.get('q')??'';",
      " const condition=/\\bOR (\\d+)=(\\d+)--$/.exec(value);",
      " const ids=url.pathname===search ? condition ?",
      "   condition[1]===condition[2] ? ['a','b'] : [] :",
      "   value==='present' ? ['a'] : [] : ['decoy'];",
      " response.writeHead(200,{'content-type':'application/json','cache-control':'no-store'});",
      " response.end(JSON.stringify({items:ids.map(id=>({id}))}));",
      "});",
      "server.listen(0,'127.0.0.1',()=>process.stdout.write(String(server.address().port)+'\\n'));",
    ].join('\n')], {stdio: ['ignore', 'pipe', 'inherit']});
    t.after(() => fixture.kill());
    const port = await new Promise((resolve, reject) => {
      fixture.stdout.once('data', chunk => resolve(Number(String(chunk).trim())));
      fixture.once('error', reject);
      fixture.once('exit', code => reject(Error(`fixture exited ${code}`)));
    });
    assert.ok(Number.isInteger(port) && port > 0);
    const origin = `http://127.0.0.1:${port}`;
    const {scope} = loadScope({origin, overrides: {acceptLocal: true,
      agents: 2, rps: 40}});
    const decoys = Array.from({length: 32}, (_, index) => `${prefix}/item-${index}`);
    const surface = {patterns: [...decoys, search].map(pattern => ({
      pattern, methods: ['GET'], params: {q: ['present']},
      responseFacts: pattern === search ? {status: 200, type: 'application/json'} :
        {status: 200},
      source: ['public-api-document'],
    }))};
    const events = [];
    const webPages = [];
    let searchPage = null;
    let evidence = 0;
    const flow = (context, number) => ({family: 'observed-query-behavior',
      why: 'The observed query accepts harmless alternate values', priority: 9,
      as: 'anonymous', oracle: 'observation', protectedPath: '',
      prelude: [], observe: [], binding: null,
      subject: {method: 'GET', path: decoys[0], placement: 'query', key: 'q',
        fixedFields: [], bodyTemplate: '', headers: []},
      controlValue: `ordinary-${number}`, firstValue: `first-${number}`,
      secondValue: `second-${number}`, marker: context.marker,
      secondMarker: context.secondMarker,
      assertion: {step: 'subject', index: 0, location: 'body', name: ''}});
    const infer = async (_model, messages, {schema} = {}) => {
      const prompt = messages[0].content;
      const context = JSON.parse(messages[1].content);
      if (prompt.startsWith('Allocate the next black-box investigation effort'))
        return {priorities: ['sequence', 'web'].map((name, index) =>
          ({name, weight: 100 - index * 50,
            why: 'Observed routes support both methods'}))};
      if (prompt.startsWith('You are planning bounded, authorized HTTP research.')) {
        events.push('sequence-planned');
        return {flows: [flow(context, 0)]};
      }
      if (prompt.startsWith('Revise at most one bounded, authorized HTTP experiment')) {
        events.push('sequence-revision-started');
        await new Promise(resolve => setTimeout(resolve, 1450));
        events.push('sequence-revision-finished');
        return {flows: [flow(context, 1)]};
      }
      if (prompt.startsWith('Rank only the supplied observed read-only web-test candidates')) {
        webPages.push(context.page);
        if (context.candidates.some(item => item.path === search &&
          item.kind === 'sql-boolean')) searchPage = context.page;
        return {priorities: searchPage === context.page ?
          [{kind: 'sql-boolean', path: search, parameter: 'q', priority: 10,
            why: 'Observed public search query'}] : [],
        strategies: [], experiments: []};
      }
      const blank = item => item?.type === 'object' ? Object.fromEntries(
        (item.required ?? []).map(key => [key, blank(item.properties?.[key])])) :
        item?.type === 'array' ? [] : item?.type === 'integer' ||
        item?.type === 'number' ? 0 : item?.type === 'boolean' ? false :
        item?.enum?.[0] ?? '';
      return blank(schema);
    };
    const requester = async ({url, method = 'GET', body, headers = {}}) => {
      const target = new URL(url, origin);
      if (target.pathname === search && /\bOR\b/i.test(target.searchParams.get('q') ?? ''))
        events.push('search-sql-request');
      const response = await fetch(target, {method, body, headers,
        redirect: 'manual'});
      const content = await response.text();
      return {status: response.status, type: response.headers.get('content-type'),
        body: content, bytes: Buffer.byteLength(content),
        hash: createHash('sha256').update(content).digest('hex'),
        ids: JSON.parse(content).items.map(item => item.id),
        headers: Object.fromEntries(response.headers), cached: false,
        evidenceId: `ev-${String(++evidence).padStart(4, '0')}`};
    };
    const run = await runWebProbes(surface, scope, {requester, infer,
      model: {model: 'fixture'}, budget: 85, maxModelPages: 28,
      remainingModelCalls: () => 28, researchDeadline: Date.now() + 1100});
    assert.ok(run.modelCoverage.httpSequenceAccepted >= 1,
      `Muse's accepted sequence was lost: ${JSON.stringify(run.modelCoverage)}`);
    assert.ok(run.plan.some(item => item.kind === 'model-http-sequence'),
      'an accepted Muse sequence must remain in the task plan');
    assert.ok(webPages.length > 1 && searchPage > webPages[0],
      `the late SQL lead was not reviewed on a later Muse page: ${JSON.stringify({
        webPages, searchPage, coverage: run.modelCoverage})}`);
    assert.ok(run.modelCoverage.webWorkersPeak > 0,
      `the ordinary web pool never started: ${JSON.stringify({events,
        coverage: run.modelCoverage})}`);
    const sql = run.results.find(item => item.kind === 'sql-boolean' &&
      item.lead.path === search);
    assert.equal(sql?.verdict, 'confirmed', JSON.stringify({events,
      results: run.results.map(item => [item.kind, item.lead?.path, item.verdict,
        item.reason])}));
    const sqlRequestAt = events.indexOf('search-sql-request');
    const slowFeedbackFinishedAt = events.indexOf('sequence-revision-finished');
    assert.ok(sqlRequestAt >= 0 &&
      (slowFeedbackFinishedAt < 0 || sqlRequestAt < slowFeedbackFinishedAt),
    `the late SQL request waited for slow sequence feedback: ${events.join(', ')}`);
    assert.equal(run.results.filter(item => item.kind === 'sql-boolean' &&
      item.lead.path === search).length, 1,
    'a lead must have one task verdict even when planned in multiple turns');
    assert.equal(new Set(run.results.map(item => item.leadKey)).size,
      run.results.length, 'task verdicts must not duplicate lead keys');
  });
