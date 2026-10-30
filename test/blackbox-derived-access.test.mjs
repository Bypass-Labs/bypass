import test from 'node:test';
import assert from 'node:assert/strict';
import {loadScope} from '../src/blackbox/scope.mjs';
import {checkDerivedAnonymousAccess} from '../src/blackbox/derived-access.mjs';
import {derivedAnonymousSurface} from '../src/blackbox/derived-session-recon.mjs';

test('authenticated routes stay in Muse surface while unchanged public reads reuse their evidence', async () => {
  const origin = 'http://127.0.0.1:43991';
  const scope = loadScope({origin, overrides: {acceptLocal: true}}).scope;
  const mapped = {origin, contracts: [], routes: [
    {path: '/same', method: 'GET', status: 200, type: 'application/json',
      shape: {items: 'array'}},
    {path: '/changed', method: 'GET', status: 200, type: 'application/json',
      shape: {items: 'array', private: 'boolean'}},
    {path: '/new', method: 'GET', status: 200, type: 'application/json',
      shape: {items: 'array'}},
  ]};
  const publicSurface = {patterns: [
    {pattern: '/same', methods: ['GET'], responseFacts: {status: 200,
      type: 'application/json', shape: {items: 'array'}}},
    {pattern: '/changed', methods: ['GET'], responseFacts: {status: 200,
      type: 'application/json', shape: {items: 'array'}}},
  ]};
  const surface = derivedAnonymousSurface(mapped, publicSurface);
  assert.deepEqual(surface.patterns.map(item => item.pattern),
    ['/same', '/changed', '/new']);
  const requested = [];
  const result = await checkDerivedAnonymousAccess(mapped, surface, scope, {
    budget: 10, requestAuthenticated: async () => {throw Error('unneeded');},
    requester: async ({url}) => {
      requested.push(url);
      return {status: 200, type: 'application/json', body: '{"items":[]}',
        evidenceId: `ev-${requested.length}`};
    },
  });
  assert.equal(result.alreadyMeasured, 1);
  assert.equal(result.tested, 2);
  assert.equal(result.cut, 0);
  assert.deepEqual(requested, ['/changed', '/new']);
});

test('private JSON follow-up leaves large static assets to Muse without a blocked task', async () => {
  const origin = 'http://127.0.0.1:43990';
  const scope = loadScope({origin, overrides: {acceptLocal: true}}).scope;
  const mapped = {origin, contracts: [], routes: [
    {path: '/chunk-1qQQGal7.js', method: 'GET', status: 200,
      type: 'application/javascript'},
    {path: '/private/profile', method: 'GET', status: 200,
      type: 'application/json'},
  ]};
  const surface = derivedAnonymousSurface(mapped, {patterns: []});
  const requested = [];
  const result = await checkDerivedAnonymousAccess(mapped, surface, scope, {
    budget: 10, requestAuthenticated: async () => {throw Error('unneeded');},
    requester: async request => {
      requested.push(request);
      return {status: 200, type: 'application/json', body: '{}'};
    },
  });
  assert.ok(surface.patterns.some(item => item.pattern === '/chunk-1qQQGal7.js'));
  assert.deepEqual(requested.map(item => item.url), ['/private/profile']);
  assert.equal(requested[0].maxBytes, 16 * 1024 * 1024);
  assert.equal(result.nonJsonSkipped, 1);
  assert.equal(result.tested, 1);
  assert.equal(result.results[0].verdict, 'inconclusive');
});

test('a response beyond the requester ceiling is inconclusive with a size reason', async () => {
  const origin = 'http://127.0.0.1:43990';
  const scope = loadScope({origin, overrides: {acceptLocal: true}}).scope;
  const mapped = {origin, contracts: [], routes: [
    {path: '/private/profile', method: 'GET', status: 200,
      type: 'application/json'},
  ]};
  const surface = derivedAnonymousSurface(mapped, {patterns: []});
  const result = await checkDerivedAnonymousAccess(mapped, surface, scope, {
    budget: 1, requestAuthenticated: async () => {throw Error('unneeded');},
    requester: async () => ({blocked: true,
      reason: 'Request failed: Response exceeds size limit'}),
  });
  assert.equal(result.results[0].verdict, 'inconclusive');
  assert.match(result.results[0].reason, /16 MiB requester limit/);
});
