import test from 'node:test';
import assert from 'node:assert/strict';
import {spawn} from 'node:child_process';
import {createHash, randomBytes} from 'node:crypto';
import {loadScope} from '../src/blackbox/scope.mjs';
import {runWebProbes} from '../src/blackbox/web-probes.mjs';

test('early protected pass plans and executes a web lead before slower HTTP research',
  {timeout: 10000}, async t => {
    const fixture = spawn(process.execPath, ['-e', [
      "const http=require('node:http');",
      "const server=http.createServer((request,response)=>{",
      " const url=new URL(request.url,'http://fixture.invalid');",
      " response.writeHead(200,{'content-type':'application/json','cache-control':'no-store'});",
      " response.end(JSON.stringify({items:[{id:url.searchParams.get('q')??'plain'}]}));",
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
    const prefix = `/api/${randomBytes(5).toString('hex')}`;
    const route = `${prefix}/search`;
    const otherRoutes = Array.from({length: 12}, (_, index) =>
      `${prefix}/search-${index}`);
    const scope = loadScope({origin, overrides: {acceptLocal: true}}).scope;
    const surface = {patterns: [route, ...otherRoutes].map(pattern =>
      ({pattern, methods: ['GET'], params: {q: ['plain']},
        responseFacts: {status: 200, type: 'application/json'}}))};
    const events = [];
    let evidence = 0;
    const infer = async (_model, messages, {schema} = {}) => {
      const prompt = messages[0].content;
      if (prompt.startsWith('Allocate the next black-box investigation effort'))
        return {priorities: [
          {name: 'sequence', weight: 100, why: 'The observed route accepts a query'},
          {name: 'web', weight: 1, why: 'The observed route accepts a query'},
        ]};
      if (prompt.startsWith('You are planning bounded, authorized HTTP research.')) {
        events.push('sequence-plan');
        await new Promise(resolve => setTimeout(resolve, 900));
        events.push('sequence-plan-finished');
        return {flows: []};
      }
      if (prompt.startsWith('Rank only the supplied observed read-only web-test candidates')) {
        events.push('web-plan');
        return {priorities: [{kind: 'sql-boolean', path: route, parameter: 'q',
          priority: 10, why: 'Observed public query input'}],
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
      events.push('web-request');
      const response = await fetch(new URL(url, origin), {method, body,
        headers, redirect: 'manual'});
      const text = await response.text();
      return {status: response.status, type: response.headers.get('content-type'),
        body: text, bytes: Buffer.byteLength(text),
        hash: createHash('sha256').update(text).digest('hex'),
        ids: JSON.parse(text).items.map(item => item.id),
        headers: Object.fromEntries(response.headers),
        evidenceId: `ev-${String(++evidence).padStart(4, '0')}`};
    };
    const result = await runWebProbes(surface, scope, {requester, infer,
      model: {model: 'fixture'}, budget: 20, maxModelPages: 12,
      remainingModelCalls: () => 12, prioritizeWebTurn: true,
      researchDeadline: Date.now() + 3000});
    assert.ok(events.includes('web-plan'), JSON.stringify(events));
    assert.ok(events.includes('web-request'), JSON.stringify(events));
    assert.ok(events.indexOf('web-plan') < events.indexOf('sequence-plan-finished'),
      `the web planner waited for HTTP research to finish: ${events.join(', ')}`);
    assert.ok(events.indexOf('web-request') < events.indexOf('sequence-plan-finished'),
      `a web lead did not execute during HTTP research: ${events.join(', ')}`);
    assert.ok(events.filter(item => item === 'web-plan').length > 1,
      `the early pass must review multiple affordable pages: ${events.join(', ')}`);
    assert.ok(events.slice(0, events.indexOf('sequence-plan-finished'))
      .filter(item => item === 'web-request').length > 1,
    `the early pass must execute more than one web lead: ${events.join(', ')}`);
    assert.ok(result.modelCoverage?.pagesSent > 1,
      'the early pass must record multiple Muse-reviewed web pages');
  });
