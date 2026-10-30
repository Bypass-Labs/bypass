import test from 'node:test';
import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import {loadScope} from '../src/blackbox/scope.mjs';
import {runWebProbes} from '../src/blackbox/web-probes.mjs';

test('later web pages are reviewed while an earlier access investigation receives feedback',
  {timeout: 15000}, async () => {
    const origin = 'http://127.0.0.1:49398';
    const scope = loadScope({origin, overrides: {acceptLocal: true,
      agents: 2, httpWorkers: 2, rps: 100}}).scope;
    const surface = {patterns: [
      {pattern: '/private/item', methods: ['GET'], params: {},
        responseFacts: {identity: 'derived-session', status: 200,
          anonymousStatus: 401, type: 'application/json'}},
      ...Array.from({length: 40}, (_, index) => ({
        pattern: `/query-${index}`, methods: ['GET'],
        params: {q: ['plain']}, responseFacts: {status: 200,
          type: 'application/json'}}))]};
    const events = [], accessCheckpoints = [];
    let webPages = 0, sequencePages = 0, evidence = 0;
    const response = (status, value) => {
      const body = JSON.stringify({value});
      return {status, type: 'application/json', body,
        bytes: Buffer.byteLength(body),
        hash: createHash('sha256').update(body).digest('hex'),
        headers: {'content-type': 'application/json',
          'cache-control': 'no-store'}, evidenceId: `ev-${++evidence}`};
    };
    const requester = async ({url, identity = 'anonymous'}) => {
      const target = new URL(url, origin);
      if (target.pathname === '/private/item')
        return response(identity === 'derived' ? 200 : 401,
          identity === 'derived' ? 'private record '.repeat(10) : 'denied');
      return response(200, target.searchParams.get('q') ?? 'plain');
    };
    const infer = async (_model, messages) => {
      const prompt = messages[0].content;
      if (prompt.startsWith('Allocate the next black-box investigation effort'))
        return {priorities: ['access', 'web', 'sequence'].map((name, index) =>
          ({name, weight: 100 - index * 10,
            why: 'Observed protected read and public query inputs'}))};
      if (prompt.startsWith('You are investigating whether an observed anonymous GET'))
        return {tests: [{family: 'Record boundary',
          why: 'Compare a protected item with a public query', priority: 8,
          comparison: 'exact-body', protectedPath: '/private/item',
          subject: {method: 'GET', path: '/query-0', placement: 'query',
            key: 'q', fixedFields: []}, controlValue: 'plain',
          firstValue: 'access-one', secondValue: 'access-two',
          ownerPointer: '', candidatePointer: '', identityField: '',
          matchFields: []}]};
      if (prompt.startsWith('Revise one authorized, read-only access-boundary experiment')) {
        events.push('access-feedback-start');
        await new Promise(resolve => setTimeout(resolve, 700));
        events.push('access-feedback-end');
        return {tests: []};
      }
      if (prompt.startsWith('Rank only the supplied observed read-only web-test candidates')) {
        events.push(`web-page-${++webPages}`);
        return {priorities: [], strategies: [], experiments: []};
      }
      if (prompt.startsWith('You are planning bounded, authorized HTTP research.')) {
        events.push(`sequence-page-${++sequencePages}`);
        return {flows: []};
      }
      return {priorities: [], strategies: [], experiments: [], flows: [],
        tests: [], checks: []};
    };
    const run = await runWebProbes(surface, scope, {requester, infer,
      model: {model: 'fixture'}, budget: 1000, maxModelPages: 35,
      remainingModelCalls: () => 35,
      onAccessCheckpoint: state => accessCheckpoints.push(structuredClone(state)),
      researchDeadline: Date.now() + 10000,
      derivedSession: {loginProof: {kind: 'fixture'},
        requestAuthenticated: async () => response(200,
          'private record '.repeat(10))}});
    assert.ok(events.includes('access-feedback-start'),
      `access feedback never ran: ${events.join(', ')}`);
    assert.ok(events.includes('web-page-2'),
      `the later web page was not reviewed: ${events.join(', ')}`);
    assert.ok(events.indexOf('web-page-2') < events.indexOf('access-feedback-end'),
      `web planning waited for independent access feedback: ${events.join(', ')}`);
    assert.ok(events.includes('sequence-page-2'),
      `the later sequence page was not reviewed: ${events.join(', ')}`);
    assert.ok(events.indexOf('sequence-page-2') <
      events.indexOf('access-feedback-end'),
    `sequence planning waited for independent access feedback: ${events.join(', ')}`);
    assert.ok(run.modelCoverage.pagesSent >= 2);
    assert.ok(accessCheckpoints.some(state => state.cursor >= 1),
      'the accepted access lead must reach a durable completed checkpoint');
    assert.ok(run.results.some(item => item.kind === 'model-access-boundary' &&
      item.verdict !== 'untested'), 'the accepted access lead must retain a verdict');
  });
