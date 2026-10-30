import test from 'node:test';
import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import {loadScope} from '../src/blackbox/scope.mjs';
import {runWebProbes} from '../src/blackbox/web-probes.mjs';

test('the highest Muse-ranked web lead runs before a lower-ranked earlier family',
  {timeout: 15000}, async () => {
    const origin = 'http://127.0.0.1:43191';
    const scope = loadScope({origin, overrides: {acceptLocal: true}}).scope;
    const surface = {patterns: [
      {pattern: '/jump', methods: ['GET'], params: {next: ['/safe']},
        responseFacts: {status: 302, type: 'text/plain'}},
      {pattern: '/item', methods: ['GET'], params: {q: ['1']},
        responseFacts: {status: 200, type: 'application/json'}},
    ]};
    const infer = async (_model, messages, {schema} = {}) => {
      const prompt = messages[0].content;
      if (prompt.startsWith('Allocate the next black-box investigation effort'))
        return {priorities: ['web', 'sequence', 'access', 'session', 'stored', 'json']
          .map((name, index) => ({name, weight: 100 - index * 10,
            why: 'Observed independent web inputs'}))};
      if (prompt.startsWith('Rank only the supplied observed read-only web-test candidates'))
        return {priorities: [
          {kind: 'sql-boolean', path: '/item', parameter: 'q', priority: 10,
            why: 'Observed numeric item lookup'},
          {kind: 'open-redirect', path: '/jump', parameter: 'next', priority: 9,
            why: 'Observed redirect input'},
        ], strategies: [], experiments: []};
      const blank = item => item?.type === 'object' ? Object.fromEntries(
        (item.required ?? []).map(key => [key, blank(item.properties?.[key])])) :
        item?.type === 'array' ? [] : item?.type === 'integer' ||
        item?.type === 'number' ? 0 : item?.type === 'boolean' ? false :
        item?.enum?.[0] ?? '';
      return blank(schema);
    };
    let requestNumber = 0;
    const requestedPaths = [];
    const executedPaths = [];
    const requester = async ({url}) => {
      const target = new URL(url, origin);
      requestedPaths.push(target.pathname);
      if (target.pathname === '/item' && /\b(?:AND|OR)\b/i.test(
        target.searchParams.get('q') ?? '') ||
        target.pathname === '/jump' && /^https:\/\/bypass-audit\.invalid\//.test(
          target.searchParams.get('next') ?? '')) executedPaths.push(target.pathname);
      const redirect = target.pathname === '/jump';
      const body = redirect ? '' : '{"items":[{"id":"1"}]}';
      return {status: redirect ? 302 : 200,
        type: redirect ? 'text/plain' : 'application/json', body,
        bytes: Buffer.byteLength(body),
        hash: createHash('sha256').update(body).digest('hex'),
        ids: redirect ? [] : ['1'],
        headers: redirect ? {location: '/safe'} : {},
        evidenceId: `ev-${String(++requestNumber).padStart(4, '0')}`};
    };
    const run = await runWebProbes(surface, scope, {requester, infer,
      model: {model: 'fixture'}, budget: 24, maxModelPages: 8,
      remainingModelCalls: () => 8, researchDeadline: Date.now() + 10000});
    const sql = run.plan.find(item => item.kind === 'sql-boolean' && item.path === '/item');
    const redirect = run.plan.find(item => item.kind === 'open-redirect' && item.path === '/jump');
    assert.ok(sql && redirect, JSON.stringify(run.plan));
    assert.ok(sql.priority > redirect.priority, JSON.stringify({sql, redirect}));
    assert.ok(executedPaths.includes('/item') && executedPaths.includes('/jump'),
      JSON.stringify({run: run.plan, executedPaths}));
    // Concurrent checks can reach their attack payloads in a different order.
    // The first guarded request identifies which ranked task was dispatched first.
    assert.equal(requestedPaths[0], '/item', JSON.stringify(requestedPaths));
  });
