import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import {createHash} from 'node:crypto';
import {loadScope} from '../src/blackbox/scope.mjs';
import {runWebProbes} from '../src/blackbox/web-probes.mjs';

test('first access, web, and sequence Muse pages overlap before verifier execution',
  {timeout: 10000}, async t => {
    const root = fs.mkdtempSync(path.join(os.tmpdir(), 'bypass-first-page-'));
    t.after(() => fs.rmSync(root, {recursive: true, force: true}));
    const origin = 'http://127.0.0.1:49396';
    const scopeFile = path.join(root, 'scope.json');
    fs.writeFileSync(scopeFile, JSON.stringify({schemaVersion: 1,
      target: {origin}, include: ['/'],
      limits: {rps: 100, agents: 2, modelConcurrency: 2,
        modelCalls: 30, maxUrls: 30, minutes: 1}}));
    const scope = loadScope({file: scopeFile, origin,
      overrides: {acceptLocal: true}}).scope;
    const surface = {patterns: [
      {pattern: '/private/item', methods: ['GET'], params: {},
        responseFacts: {identity: 'derived-session', status: 200,
          anonymousStatus: 401, type: 'application/json'}},
      ...Array.from({length: 12}, (_, index) => ({
        pattern: `/query-${index}`, methods: ['GET'],
        params: {q: ['plain']}, responseFacts: {status: 200,
          type: 'application/json'}}))]};
    const events = [];
    let accessPages = 0, webPages = 0, sequencePages = 0, evidence = 0;
    const response = (status, value) => {
      const body = JSON.stringify({value});
      return {status, body, bytes: Buffer.byteLength(body),
        type: 'application/json',
        hash: createHash('sha256').update(body).digest('hex'),
        headers: {'content-type': 'application/json',
          'cache-control': 'no-store'}, evidenceId: `ev-${++evidence}`};
    };
    const requester = async ({url, identity = 'anonymous'}) => {
      const target = new URL(url, origin);
      if (target.pathname === '/private/item')
        return response(identity === 'derived' ? 200 : 401,
          identity === 'derived' ? 'private record '.repeat(10) : 'denied');
      if (target.searchParams.get('q') === 'sequence-try')
        events.push('sequence-http');
      return response(200, target.searchParams.get('q') ?? 'plain');
    };
    const infer = async (_model, messages) => {
      const prompt = messages[0].content;
      if (prompt.startsWith('Allocate the next black-box investigation effort'))
        return {priorities: ['access', 'web', 'sequence'].map((name, index) =>
          ({name, weight: 100 - index * 10,
            why: 'Observed protected read and public query'}))};
      if (prompt.startsWith('You are investigating whether an observed anonymous GET')) {
        events.push(`access-plan-${++accessPages}-start`);
        if (accessPages === 1)
          await new Promise(resolve => setTimeout(resolve, 700));
        events.push(`access-plan-${accessPages}-end`);
        return {tests: accessPages === 1 ? [{family: 'Record boundary',
          why: 'Check public query against private read', priority: 8,
          comparison: 'exact-body', protectedPath: '/private/item',
          subject: {method: 'GET', path: '/query-0', placement: 'query',
            key: 'q', fixedFields: []}, controlValue: 'plain',
          firstValue: 'access-one', secondValue: 'access-two',
          ownerPointer: '', candidatePointer: '', identityField: '',
          matchFields: []}] : []};
      }
      if (prompt.startsWith('Rank only the supplied observed read-only web-test candidates')) {
        events.push(`web-plan-${++webPages}-start`);
        events.push(`web-plan-${webPages}-end`);
        return {priorities: [], strategies: [], experiments: []};
      }
      if (prompt.startsWith('You are planning bounded, authorized HTTP research.')) {
        events.push(`sequence-plan-${++sequencePages}-start`);
        return {flows: sequencePages === 1 ? [{family: 'bounded-read',
          why: 'Check an observed query', priority: 8, as: 'anonymous',
          oracle: 'raw-observation', rawRequests: [{method: 'GET',
            path: '/query-0?q=sequence-try'}]}] : []};
      }
      return {priorities: [], strategies: [], experiments: [], flows: [],
        tests: [], checks: []};
    };
    const run = await runWebProbes(surface, scope, {requester, infer,
      model: {model: 'fixture'}, budget: 1000, maxModelPages: 30,
      remainingModelCalls: () => 30,
      researchDeadline: Date.now() + 7000,
      derivedSession: {loginProof: {kind: 'fixture'},
        requestAuthenticated: async () => response(200,
          'private record '.repeat(10))}});
    assert.ok(events.includes('web-plan-1-start') &&
      events.includes('access-plan-1-end') &&
      events.includes('sequence-plan-1-start'), events.join(', '));
    assert.ok(events.indexOf('web-plan-1-start') <
      events.indexOf('access-plan-1-end'),
    `independent first Muse pages ran serially: ${events.join(', ')}`);
    assert.ok(events.indexOf('sequence-plan-1-start') <
      events.indexOf('access-plan-1-end'),
    `sequence planning waited for an independent page: ${events.join(', ')}`);
    assert.ok(events.indexOf('sequence-http') >
      events.indexOf('access-plan-1-end'),
    `sequence verification bypassed the first-page barrier: ${events.join(', ')}`);
    assert.ok(run.results.some(item => item.kind === 'model-access-boundary' &&
      item.verdict !== 'untested'));
    assert.ok(run.results.some(item => item.kind === 'sql-boolean' ||
      item.kind === 'xss-reflected'));
  });
