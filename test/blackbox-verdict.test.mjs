import test from 'node:test';
import assert from 'node:assert/strict';
import {decide} from '../src/blackbox/verdict.mjs';
import {hash} from '../src/util.mjs';

test('anonymous access to an owner-bound sensitive GET requires a distinct outsider control', () => {
  const O = {status: 200, type: 'application/json', hash: 'owner-response',
    shape: {ownerId: 'string', balance: 'number'}, ownership: {ownerId: hash('u-1')}, headers: {}};
  const T = {...O, hash: 'outsider-response', ownership: {ownerId: hash('u-2')}};
  const A = {...O};
  const task = {kind: 'missing-auth', pattern: '/api/export',
    request: {method: 'GET', url: '/api/export', as: 'outsider'},
    control: {url: '/api/export', as: 'owner'}};
  const surface = {identity: {principals: {owner: 'u-1', outsider: 'u-2'}},
    patterns: [{pattern: '/api/export', label: {kind: 'export'}, private: {}, ids: {}}]};
  const scope = {identities: {identityPath: null}};
  assert.equal(decide(task, {O, T, A, surface, scope}).rule,
    'confirmed/missing-auth/owner-resource');
  assert.equal(decide(task, {O, T: {...T, ownership: {}}, A, surface, scope}).verdict,
    'inconclusive');
  assert.equal(decide(task, {O, T, A: {...A, status: 401}, surface, scope}).verdict,
    'not_reproduced');
});

test('a public profile with an email field is public, not an IDOR or missing-authentication finding', () => {
  const profile = {status: 200, type: 'application/json', hash: 'same', shape: {id: 'string', email: 'string'},
    ids: ['u-1'], ownership: {}, headers: {}};
  const pattern = {pattern: '/api/profiles/{id}', ids: {ownerIds: ['u-1'], outsiderIds: []},
    private: {}, label: {kind: 'item'}};
  const surface = {patterns: [pattern]};
  const idor = {kind: 'idor', pattern: pattern.pattern, control: {url: '/api/profiles/u-1'}};
  assert.equal(decide(idor, {O: profile, T: profile, A: profile, surface}).verdict, 'public');
  const anonymous = {...idor, kind: 'missing-auth'};
  assert.equal(decide(anonymous, {O: profile, T: profile, A: profile, surface}).verdict, 'public');
});

test('a raw list response with a foreign owner ID confirms a list leak', () => {
  const owner = {status: 200, type: 'application/json', hash: 'owner', shape: 'array', ids: ['itm-101'],
    body: '[{"id":"itm-101"}]', headers: {}};
  const outsider = {status: 200, type: 'application/json', hash: 'both', shape: 'array', ids: ['itm-101', 'itm-202'],
    body: '[{"id":"itm-101"},{"id":"itm-202"}]', headers: {}};
  const anonymous = {status: 401, headers: {}};
  const task = {kind: 'list-leak', pattern: '/api/items', control: {url: '/api/items?all=1'}};
  const surface = {patterns: [{pattern: '/api/items', label: {kind: 'list'},
    ids: {ownerIds: ['itm-101'], outsiderIds: ['itm-202']}, private: {'itm-101': {by: 'list'}}}]};
  assert.equal(decide(task, {O: owner, T: outsider, A: anonymous, surface}).verdict, 'confirmed');
});
