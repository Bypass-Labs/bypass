import test from 'node:test';
import assert from 'node:assert/strict';
import {spawn} from 'node:child_process';
import {createHash, randomBytes} from 'node:crypto';
import {loadScope} from '../src/blackbox/scope.mjs';
import {planWebLeads, runWebProbes} from '../src/blackbox/web-probes.mjs';

test('a first-ranked HTTP sequence yields to two queued SQL checks between revisions',
  {timeout: 20000}, async t => {
    const fixture = spawn(process.execPath, ['-e', [
      "const http=require('node:http');",
      "const server=http.createServer((request,response)=>{",
      " const url=new URL(request.url,'http://fixture.invalid');",
      " const value=url.searchParams.get('q')??'1';",
      " const body=JSON.stringify({items:[{id:String(value.length)}]});",
      " response.writeHead(200,{'content-type':'application/json','cache-control':'no-store'});",
      " response.end(body);",
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
    const routes = Array.from({length: 20}, () =>
      `/api/${randomBytes(5).toString('hex')}/item`);
    const [route, secondRoute] = routes.slice(-2);
    const scope = loadScope({origin, overrides: {acceptLocal: true,
      httpWorkers: 1}}).scope;
    const surface = {patterns: routes.map(pattern =>
      ({pattern, methods: ['GET'], params: {q: ['1']},
        responseFacts: {status: 200, type: 'application/json'}}))};
    const carryForward = (await planWebLeads(surface, scope,
      {budget: 1000})).leads.filter(item => item.kind === 'sql-boolean');
    assert.equal(carryForward.length, routes.length);
    const events = [];
    let revision = 0, requestNumber = 0;
    const flow = (context, number) => ({family: 'observed-query-behavior',
      why: 'The observed item query accepts distinct harmless values', priority: 9,
      as: 'anonymous', oracle: 'observation', protectedPath: '',
      prelude: [], observe: [], binding: null,
      subject: {method: 'GET', path: route, placement: 'query', key: 'q',
        fixedFields: [], bodyTemplate: '', headers: []},
      controlValue: `ordinary-${number}`, firstValue: `first-${number}`,
      secondValue: `second-${number}`, marker: context.marker,
      secondMarker: context.secondMarker,
      assertion: {step: 'subject', index: 0, location: 'body', name: ''}});
    const infer = async (_model, messages, {schema} = {}) => {
      const prompt = messages[0].content;
      const context = JSON.parse(messages[1].content);
      if (prompt.startsWith('Allocate the next black-box investigation effort'))
        return {priorities: ['sequence', 'web', 'access', 'session', 'stored', 'json']
          .map((name, index) => ({name, weight: 100 - index * 10,
            why: 'Observed query route supports both sequence and input checks'}))};
      if (prompt.startsWith('You are planning bounded, authorized HTTP research.'))
        return {flows: [flow(context, 0)]};
      if (prompt.startsWith('Revise at most one bounded, authorized HTTP experiment')) {
        revision++;
        events.push(`revision-${revision}`);
        await new Promise(resolve => setTimeout(resolve, 110));
        return {flows: [flow(context, revision)]};
      }
      if (prompt.startsWith('Rank only the supplied observed read-only web-test candidates'))
        return {priorities: routes.map((path, index) =>
          ({kind: 'sql-boolean', path, parameter: 'q',
            priority: 10 - index, why: 'Documented numeric item lookup'})),
          strategies: [], experiments: []};
      const blank = item => item?.type === 'object' ? Object.fromEntries(
        (item.required ?? []).map(key => [key, blank(item.properties?.[key])])) :
        item?.type === 'array' ? [] : item?.type === 'integer' ||
        item?.type === 'number' ? 0 : item?.type === 'boolean' ? false :
        item?.enum?.[0] ?? '';
      return blank(schema);
    };
    const requester = async ({url, method = 'GET', body, headers = {}}) => {
      const target = new URL(url, origin);
      const value = target.searchParams.get('q') ?? '';
      if (/\b(?:AND|OR)\b/i.test(value)) events.push(`sql-request:${target.pathname}`);
      const response = await fetch(target, {method, body, headers,
        redirect: 'manual'});
      const text = await response.text();
      const parsed = JSON.parse(text);
      return {status: response.status, type: response.headers.get('content-type'),
        body: text, bytes: Buffer.byteLength(text),
        hash: createHash('sha256').update(text).digest('hex'),
        ids: parsed.items.map(item => item.id),
        headers: Object.fromEntries(response.headers),
        evidenceId: `ev-${String(++requestNumber).padStart(4, '0')}`};
    };
    const run = await runWebProbes(surface, scope, {requester, infer,
      model: {model: 'fixture'}, carryForward,
      budget: 80, maxModelPages: 35,
      remainingModelCalls: () => 35,
      researchDeadline: Date.now() + 6000});
    const sqlAt = events.indexOf(`sql-request:${route}`);
    assert.ok(sqlAt >= 0, `queued SQL check never sent a request: ${JSON.stringify({
      revisions: revision, verdicts: run.results.map(item => [item.kind, item.verdict,
        item.reason])})}`);
    const laterRevision = events.findIndex((event, index) =>
      index > sqlAt && event.startsWith('revision-'));
    assert.ok(laterRevision > sqlAt,
      `HTTP sequence did not resume refinement after the SQL request: ${events.join(', ')}`);
    const secondSqlAt = events.indexOf(`sql-request:${secondRoute}`);
    assert.ok(secondSqlAt > sqlAt,
      `the second queued SQL route waited behind sequence revisions: ${events.join(', ')}`);
    const revisionsBetweenSqlChecks = events.slice(sqlAt + 1, secondSqlAt)
      .filter(event => event.startsWith('revision-')).length;
    assert.equal(revisionsBetweenSqlChecks, 0,
      `ready web checks waited for sequence feedback: ${events.join(', ')}`);
  });
