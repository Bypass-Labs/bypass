// Tests for src/blackbox/swarm.mjs: task agents (design 8), re-verification (9.3), the mirror and the
// identity re-check (9.4), plus the swarm-to-report pipeline. A loopback fixture records concurrency and hits.
// The requester and decide are fakes that follow the T1/T4 contracts; the last test uses the real modules when present.
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import http from 'node:http';
import path from 'node:path';
import { temp, port } from './helpers.mjs';
import { safeRequest } from '../src/network.mjs';
import { hash } from '../src/util.mjs';
import { runSwarm, reverify, mirror, identityRecheck } from '../src/blackbox/swarm.mjs';
import { buildFindings, renderReport } from '../src/blackbox/report.mjs';

const TOKENS = { 'owner-token-1': 'u-1', 'other-token-2': 'u-2' };
const CREDENTIALS = { owner: 'owner-token-1', outsider: 'other-token-2' };
const INVOICES = { 'inv-101': 'u-1', 'inv-102': 'u-1', 'inv-201': 'u-2' };
const PROJECTS = { 'p-1': 'u-1', 'p-2': 'u-2' };
const PROJECT_TASKS = { 't-900': 'p-1', 't-901': 'p-2' };
const DENIED = [401, 403, 404];

// ---- Loopback fixture: an invoices API with switchable bugs, an in-flight counter and a hit log.

async function startApp(t, options = {}) {
  const state = { idor: false, asymmetric: false, echoDenial: false, listLeak: false, nested: false, delayMs: 0, inFlight: 0, maxInFlight: 0, hits: [], ...options };
  const server = http.createServer((req, res) => {
    state.inFlight += 1;
    state.maxInFlight = Math.max(state.maxInFlight, state.inFlight);
    res.on('close', () => { state.inFlight -= 1; });
    const user = TOKENS[(req.headers.authorization ?? '').replace(/^Bearer /, '')] ?? null;
    const url = new URL(req.url, 'http://fixture');
    state.hits.push({ path: `${url.pathname}${url.search}`, user, cacheControl: req.headers['cache-control'] ?? null });
    const [status, body] = route(url, user, state);
    setTimeout(() => {
      res.writeHead(status, { 'content-type': 'application/json', 'cache-control': 'no-store' });
      res.end(JSON.stringify(body));
    }, state.delayMs);
  });
  const listenPort = await port();
  await new Promise(resolve => server.listen(listenPort, '127.0.0.1', resolve));
  t.after(() => new Promise(resolve => server.close(resolve)));
  return { origin: `http://127.0.0.1:${listenPort}`, state };
}

function route(url, user, state) {
  if (url.pathname === '/api/me') return user ? [200, { id: user, email: `${user}@example.test`, role: 'member' }] : [401, { error: 'login required' }];
  if (!user) return [401, { error: 'login required' }];
  if (url.pathname === '/api/invoices') {
    const everyone = state.listLeak && url.searchParams.get('all') === '1';
    const items = Object.entries(INVOICES).filter(([, owner]) => everyone || owner === user).map(([id, ownerId]) => ({ id, ownerId, total: 100 }));
    return [200, { items }];
  }
  const item = /^\/api\/invoices\/([^/]+)$/.exec(url.pathname);
  if (item) {
    const owner = INVOICES[item[1]];
    if (!owner) return [404, { error: 'not found' }];
    const foreign = owner !== user;
    if (foreign && state.echoDenial && user === 'u-1') return [200, { error: 'forbidden', id: item[1] }];
    if (foreign && (!state.idor || (state.asymmetric && user === 'u-1'))) return [403, { error: 'forbidden' }];
    return [200, { id: item[1], ownerId: owner, total: 100 }];
  }
  const nested = /^\/api\/projects\/([^/]+)\/tasks\/([^/]+)$/.exec(url.pathname);
  if (nested) {
    const [, project, taskId] = nested;
    if (PROJECTS[project] !== user) return [403, { error: 'not a member' }];
    const memberOnlyCheck = state.nested && PROJECT_TASKS[taskId];
    if (!memberOnlyCheck && PROJECT_TASKS[taskId] !== project) return [404, { error: 'not found' }];
    return [200, { id: taskId, projectId: PROJECT_TASKS[taskId], title: 'task' }];
  }
  const slow = /^\/api\/slow\/(\d+)$/.exec(url.pathname);
  if (slow) return [200, { id: `s-${slow[1]}`, ownerId: user }];
  return [404, { error: 'not found' }];
}

// ---- Fakes that follow the contracts: requester (T1 createRequester) and decide (T4 verdict.decide).

function fakeRequester(origin, { refuse = [] } = {}) {
  const credentials = { ...CREDENTIALS };
  const cache = new Map();
  const calls = [];
  const stats = { sent: 0, cached: 0, refused: 0, blocked: 0, rate: 0 };
  let sequence = 0;
  const nextEvidence = () => `ev-${String(++sequence).padStart(4, '0')}`;
  // Like the contract's cache: the pending exchange is shared, so concurrent identical requests send once.
  function request({ url, identity, method = 'GET', headers = {}, step, task = null, agent = null, noCache = false }) {
    calls.push({ url, identity, method, headers, step, task, agent, noCache });
    if (refuse.includes(url)) {
      stats.refused += 1;
      return Promise.resolve({ refused: true, reason: 'never', evidenceId: nextEvidence() });
    }
    const key = `${identity} ${method} ${url}`;
    if (!noCache && cache.has(key)) {
      stats.cached += 1;
      return cache.get(key);
    }
    const pending = exchange({ url, identity, method, headers });
    if (!noCache) cache.set(key, pending);
    return pending;
  }
  async function exchange({ url, identity, method, headers }) {
    const auth = identity === 'anonymous' ? {} : { authorization: `Bearer ${credentials[identity]}` };
    let response;
    try {
      response = await safeRequest(new URL(url, origin).href, { allowLocal: true, method, headers: { ...headers, ...auth }, timeout: 2000 });
    } catch (error) {
      stats.blocked += 1;
      return { blocked: true, reason: error.message, evidenceId: nextEvidence() };
    }
    stats.sent += 1;
    const json = JSON.parse(response.body);
    return {
      status: response.status, type: response.headers['content-type'], bytes: Buffer.byteLength(response.body), hash: `sha256:${hash(response.body)}`,
      body: response.body, headers: { 'content-type': response.headers['content-type'] }, shape: shapeOf(json), ids: idsOf(json), ownership: {}, ms: 1,
      evidenceId: nextEvidence(),
    };
  }
  return Object.assign(request, { stats, calls, credentials });
}

function shapeOf(json) {
  if (json === null || typeof json !== 'object' || Array.isArray(json)) return Array.isArray(json) ? 'array' : typeof json;
  return Object.fromEntries(Object.entries(json).map(([key, value]) => [key, Array.isArray(value) ? 'array' : value === null ? 'null' : typeof value]));
}

function idsOf(value, depth = 0) {
  if (depth > 2 || value === null || typeof value !== 'object') return [];
  if (Array.isArray(value)) return value.flatMap(item => idsOf(item, depth + 1));
  return Object.entries(value).flatMap(([key, item]) => (/^id$|Id$/.test(key) && typeof item !== 'object' ? [String(item)] : idsOf(item, depth + 1)));
}

function stubDecide(task, { O, T, A }) {
  const evidence = [O.evidenceId, T.evidenceId, A.evidenceId];
  if (O.status !== 200) return { verdict: 'blocked', rule: 'blocked/control-failed', reason: `owner control returned ${O.status}`, evidence };
  const leaked = task.resourceId ? T.ids.includes(task.resourceId) : T.ids.some(id => task.ownerOnlyIds.includes(id));
  if (T.status === 200 && leaked) return { verdict: 'confirmed', rule: task.resourceId ? 'idor/id-match' : 'list-leak/owner-only-id', reason: '', evidence };
  if (DENIED.includes(T.status) || T.status === 200) return { verdict: 'not_reproduced', rule: 'not_reproduced/denied', reason: '', evidence };
  return { verdict: 'inconclusive', rule: 'inconclusive/other', reason: `task returned ${T.status}`, evidence };
}

// ---- Tasks, scope and surface in the shared record shapes.

function itemTask(n, id, { as = 'outsider', base = '/api/invoices', control } = {}) {
  const url = `${base}/${id}`;
  return {
    id: `t-${String(n).padStart(3, '0')}`, kind: as === 'anonymous' ? 'missing-auth' : 'idor', pattern: `${base}/{id}`,
    request: { method: 'GET', url, as }, control: { url: control ?? url, as: 'owner' }, expect: 'denied', why: '', priority: 5,
    origin: 'baseline', dependsOn: [], resourceId: id, ownerOnlyIds: [], sensitiveFields: [],
  };
}

function listTask(n, query) {
  return {
    id: `t-${String(n).padStart(3, '0')}`, kind: 'list-leak', pattern: '/api/invoices',
    request: { method: 'GET', url: `/api/invoices?${query}`, as: 'outsider' }, control: { url: '/api/invoices', as: 'owner' },
    expect: 'denied', why: '', priority: 5, origin: 'baseline', dependsOn: [], resourceId: null, ownerOnlyIds: ['inv-101', 'inv-102'], sensitiveFields: [],
  };
}

function scopeFor(origin, limits = {}) {
  return {
    schemaVersion: 1, target: { origin, environment: 'local', acknowledged: 'local-owner' }, domains: [], credentialOrigins: [origin],
    include: ['/'], never: [], methods: ['GET', 'HEAD'],
    identities: { owner: { env: 'OWNER_TOKEN', role: 'member' }, outsider: { env: 'OTHER_TOKEN', role: 'member' }, auth: 'bearer', identityPath: '/api/me' },
    limits: { rps: 50, tasks: 400, agents: 40, waves: 1, modelCalls: 60, maxUrls: 200, minutes: 10, ...limits },
  };
}

function surfaceFor(origin, { outsiderIds = ['inv-201'], identityPath = '/api/me' } = {}) {
  return {
    origin,
    identity: {
      path: identityPath, principals: { owner: 'u-1', outsider: 'u-2' }, aliases: { owner: ['u-1'], outsider: ['u-2'] },
      roles: { owner: { role: 'member' }, outsider: { role: 'member' } }, evidence: [], verified: !!identityPath,
    },
    patterns: [
      {
        pattern: '/api/invoices/{id}', methods: ['GET'], source: ['harvest:/api/invoices'],
        ids: { format: 'prefixed', selector: 'id', samples: ['inv-101'], sequential: 1, ownerIds: ['inv-101', 'inv-102'], outsiderIds, shared: [] },
        params: {}, refs: {}, private: { 'inv-101': { by: 'ownership-field', field: 'ownerId' }, 'inv-102': { by: 'ownership-field', field: 'ownerId' } },
        label: { kind: 'item', by: 'code' }, fingerprint: {}, evidence: [],
      },
      {
        pattern: '/api/invoices', methods: ['GET'], source: ['link'], ids: { format: 'none', ownerIds: [], outsiderIds: [], shared: [] },
        params: {}, refs: {}, private: {}, label: { kind: 'list', by: 'code' }, fingerprint: {}, evidence: [],
      },
    ],
    outOfScope: [], never: [], exposures: [], mined: null, stats: { urls: 0, requests: 0, patterns: 2 },
  };
}

function swarmOptions(origin, requester, extra = {}) {
  return { requester, surface: surfaceFor(origin), scope: scopeFor(origin), agents: 4, decide: stubDecide, log: () => {}, run: 'bx-test', ...extra };
}

const hitsFor = (state, pathName, user) => state.hits.filter(hit => hit.path === pathName && hit.user === user).length;

test('runSwarm bounds concurrency to min(agents, scope.limits.agents)', async t => {
  const { origin, state } = await startApp(t, { delayMs: 40 });
  const tasks = Array.from({ length: 9 }, (_, index) => itemTask(index + 1, String(index + 1), { base: '/api/slow' }));
  const requester = fakeRequester(origin);
  const { results, stats } = await runSwarm(tasks, swarmOptions(origin, requester, { agents: 3 }));
  assert.ok(state.maxInFlight <= 3, `at most 3 requests in flight, saw ${state.maxInFlight}`);
  assert.ok(state.maxInFlight >= 2, `agents ran in parallel, saw ${state.maxInFlight}`);
  assert.deepEqual(results.map(result => result.task.id), tasks.map(task => task.id), 'results keep task order');
  assert.equal(stats.tasks, 9);
  assert.equal(stats.requests, 27, 'owner control, task request and anonymous request per task');
  assert.equal(stats.cached, 0);
  assert.equal(stats.agents, 3);
  assert.ok(stats.elapsedMs >= 0 && stats.rps > 0);

  const capped = await startApp(t, { delayMs: 40 });
  await runSwarm(tasks, swarmOptions(capped.origin, fakeRequester(capped.origin), { agents: 10, scope: scopeFor(capped.origin, { agents: 2 }) }));
  assert.ok(capped.state.maxInFlight <= 2, `scope.limits.agents caps the swarm, saw ${capped.state.maxInFlight}`);
});

test('runSwarm shares one owner control per URL and keeps summaries without bodies', async t => {
  const { origin, state } = await startApp(t, { idor: true });
  const tasks = [itemTask(1, 'inv-101'), itemTask(2, 'inv-101', { as: 'anonymous' }), itemTask(3, 'inv-102')];
  const requester = fakeRequester(origin);
  const { results, stats } = await runSwarm(tasks, swarmOptions(origin, requester, { agents: 3 }));
  assert.equal(hitsFor(state, '/api/invoices/inv-101', 'u-1'), 1, 'one owner control for inv-101 across two concurrent tasks');
  assert.equal(hitsFor(state, '/api/invoices/inv-101', null), 1, 'the anonymous request is shared too');
  assert.equal(stats.requests, 6);
  assert.equal(stats.cached, 2);
  assert.deepEqual(results.map(result => result.verdict), ['confirmed', 'not_reproduced', 'confirmed']);
  assert.deepEqual([stats.confirmed, stats.notReproduced, stats.inconclusive, stats.blocked], [2, 1, 0, 0]);
  const [first, second] = results;
  assert.equal(first.rule, 'idor/id-match');
  assert.equal(first.task, tasks[0]);
  assert.deepEqual(first.evidence, [first.O.evidenceId, first.T.evidenceId, first.A.evidenceId]);
  for (const summary of [first.O, first.T, first.A]) {
    assert.equal(summary.body, undefined, 'bodies are not kept in results');
    assert.match(summary.hash, /^sha256:/);
  }
  assert.equal(second.A.evidenceId, second.T.evidenceId, 'an anonymous task is its own anonymous request');
  assert.equal(first.A.evidenceId, second.T.evidenceId);
  const steps = requester.calls.filter(call => call.task === 't-003').map(call => call.step);
  assert.deepEqual(steps, ['control', 'task', 'anonymous']);
  assert.ok(requester.calls.every(call => Number.isInteger(call.agent) && call.agent >= 1));
});

test('runSwarm turns refused and failed exchanges into blocked tasks and stops that task early', async t => {
  const { origin } = await startApp(t);
  const closed = await port();
  const unreachable = itemTask(1, 'inv-101', { control: `http://127.0.0.1:${closed}/api/invoices/inv-101` });
  const refused = { ...itemTask(2, 'inv-101'), request: { method: 'GET', url: '/api/invoices/inv-101/remove', as: 'outsider' } };
  const requester = fakeRequester(origin, { refuse: ['/api/invoices/inv-101/remove'] });
  const { results, stats } = await runSwarm([unreachable, refused], swarmOptions(origin, requester));
  assert.equal(results[0].verdict, 'blocked');
  assert.equal(results[0].rule, 'blocked/request-failed');
  assert.match(results[0].reason, /^control request failed: /);
  assert.equal(requester.calls.filter(call => call.task === 't-001').length, 1, 'no task request after a failed control');
  assert.equal(results[1].verdict, 'blocked');
  assert.equal(results[1].rule, 'blocked/refused');
  assert.match(results[1].reason, /^task request refused: never/);
  assert.equal(results[1].evidence.length, 2, 'control and refusal evidence are kept');
  assert.equal(stats.blocked, 2);
});

test('reverify re-executes confirmed results fresh and attaches confirmation evidence', async t => {
  const { origin, state } = await startApp(t, { idor: true });
  const requester = fakeRequester(origin);
  const options = swarmOptions(origin, requester);
  const { results } = await runSwarm([itemTask(1, 'inv-101'), itemTask(2, 'inv-102', { as: 'anonymous' })], options);
  const original = [...results[0].evidence];
  const before = requester.calls.length;
  const returned = await reverify(results, options);
  assert.equal(returned, results, 'results are updated in place and returned');
  const fresh = requester.calls.slice(before);
  assert.equal(fresh.length, 3, 'only the confirmed result is re-executed');
  assert.ok(fresh.every(call => call.step === 'reverify' && call.noCache === true && call.headers['cache-control'] === 'no-cache'));
  assert.equal(state.hits.filter(hit => hit.cacheControl === 'no-cache').length, 3);
  assert.equal(results[0].verdict, 'confirmed');
  assert.equal(results[0].confirmation.length, 3);
  assert.ok(results[0].confirmation.every(id => !original.includes(id)), 'confirmation cites the second execution');
  assert.equal(results[1].confirmation, undefined);
});

test('independent confirmation and mirror checks overlap through the shared requester', async t => {
  const {origin, state} = await startApp(t, {idor: true, delayMs: 45});
  const requester = fakeRequester(origin);
  const options = swarmOptions(origin, requester, {
    agents: 2, scope: scopeFor(origin, {agents: 2}),
  });
  const tasks = [itemTask(1, 'inv-101'), itemTask(2, 'inv-102')];
  const {results} = await runSwarm(tasks, options);
  assert.deepEqual(results.map(item => item.verdict), ['confirmed', 'confirmed']);

  state.maxInFlight = 0;
  const before = requester.calls.length;
  assert.equal(await reverify(results, options), results);
  assert.equal(state.maxInFlight, 2,
    'fresh controls for separate findings should run concurrently within the configured width');
  const calls = requester.calls.slice(before);
  for (const task of tasks) {
    const exchanges = calls.filter(item => item.task === task.id);
    assert.deepEqual(exchanges.map(item => item.identity), ['owner', 'outsider', 'anonymous'],
      'the controls within each finding stay ordered');
    assert.ok(exchanges.every(item => item.noCache && item.step === 'reverify'));
  }
  assert.ok(results.every(item => item.confirmation.length === 3));

  state.maxInFlight = 0;
  assert.equal(await mirror(results, options), results);
  assert.equal(state.maxInFlight, 2,
    'independent role-parity mirrors should overlap within the configured width');
  assert.ok(results.every(item => item.mirror.result === 'both-open'));

  state.maxInFlight = 0;
  options.scope.limits.agents = 1;
  await reverify(results, options);
  assert.equal(state.maxInFlight, 1, 'the configured width also caps confirmation replay');
});

test('reverify downgrades a confirmation that does not reproduce and keeps both evidence sets', async t => {
  const { origin, state } = await startApp(t, { idor: true });
  const requester = fakeRequester(origin);
  const options = swarmOptions(origin, requester);
  const { results } = await runSwarm([itemTask(1, 'inv-101')], options);
  const original = [...results[0].evidence];
  state.idor = false;
  await reverify(results, options);
  const [result] = results;
  assert.equal(result.verdict, 'inconclusive');
  assert.equal(result.rule, 'inconclusive/reverify');
  assert.match(result.reason, /^not reproduced on re-verification/);
  assert.match(result.reason, /not_reproduced\/denied/);
  assert.ok(original.every(id => result.evidence.includes(id)));
  assert.equal(result.evidence.length, original.length + 3);
});

test('mirror marks both-open when the owner can read an outsider-only id on the same pattern', async t => {
  const { origin, state } = await startApp(t, { idor: true });
  const requester = fakeRequester(origin);
  const options = swarmOptions(origin, requester);
  const { results } = await runSwarm([itemTask(1, 'inv-101')], options);
  const returned = await mirror(results, options);
  assert.equal(returned, results);
  const [result] = results;
  assert.equal(result.verdict, 'confirmed');
  assert.equal(result.mirror.result, 'both-open');
  assert.equal(result.mirror.url, '/api/invoices/inv-201');
  assert.equal(result.mirror.evidence.length, 1);
  assert.ok(!(result.tags ?? []).includes('role-asymmetric'));
  assert.equal(hitsFor(state, '/api/invoices/inv-201', 'u-1'), 1);
  const call = requester.calls.find(entry => entry.step === 'mirror');
  assert.deepEqual([call.identity, call.noCache, call.task], ['owner', true, 't-001']);
});

test('mirror downgrades an asymmetric finding to inconclusive tagged role-asymmetric', async t => {
  const { origin } = await startApp(t, { idor: true, asymmetric: true });
  const options = swarmOptions(origin, fakeRequester(origin));
  const { results } = await runSwarm([itemTask(1, 'inv-101')], options);
  assert.equal(results[0].verdict, 'confirmed', 'the outsider can read the owner invoice');
  await mirror(results, options);
  const [result] = results;
  assert.equal(result.mirror.result, 'asymmetric');
  assert.equal(result.verdict, 'inconclusive');
  assert.equal(result.rule, 'inconclusive/role-asymmetric');
  assert.match(result.reason, /owner was denied/);
  assert.ok(result.tags.includes('role-asymmetric'));
});

test('mirror keeps role-unverified without an outsider-only id and skips non-cross-account kinds', async t => {
  const { origin, state } = await startApp(t, { idor: true });
  const requester = fakeRequester(origin);
  const options = swarmOptions(origin, requester, { surface: surfaceFor(origin, { outsiderIds: [] }) });
  const { results } = await runSwarm([itemTask(1, 'inv-101')], options);
  const anonymous = { ...results[0], task: itemTask(2, 'inv-102', { as: 'anonymous' }), tags: [] };
  results.push(anonymous);
  await mirror(results, options);
  assert.equal(results[0].verdict, 'confirmed');
  assert.equal(results[0].mirror.result, 'unverified');
  assert.ok(results[0].tags.includes('role-unverified'));
  assert.equal(anonymous.mirror.result, 'unverified');
  assert.equal(anonymous.mirror.reason, 'not a cross-account finding');
  assert.deepEqual(anonymous.tags, []);
  assert.equal(requester.calls.filter(call => call.step === 'mirror').length, 0);
  assert.equal(hitsFor(state, '/api/invoices/inv-201', 'u-1'), 0);
});

test('mirror does not read a 200 denial that echoes the requested id as both-open', async t => {
  const { origin } = await startApp(t, { idor: true, echoDenial: true });
  const options = swarmOptions(origin, fakeRequester(origin));
  const { results } = await runSwarm([itemTask(1, 'inv-101')], options);
  await mirror(results, options);
  assert.equal(results[0].mirror.result, 'unverified');
  assert.equal(results[0].verdict, 'confirmed');
  assert.ok(results[0].tags.includes('role-unverified'));
});

test('mirror on a nested route swaps in an outsider inner id under the owner outer id', async t => {
  const { origin, state } = await startApp(t, { nested: true });
  const task = {
    ...itemTask(1, 't-900'), kind: 'nested-idor', pattern: '/api/projects/{id}/tasks/{id}',
    request: { method: 'GET', url: '/api/projects/p-2/tasks/t-900', as: 'outsider' }, control: { url: '/api/projects/p-1/tasks/t-900', as: 'owner' },
  };
  const surface = surfaceFor(origin);
  surface.patterns.push({
    pattern: '/api/projects/{id}/tasks/{id}', methods: ['GET'], source: ['harvest:/api/projects/{id}/tasks'],
    ids: { format: 'prefixed', selector: 'id', samples: [], sequential: 0, ownerIds: ['p-1', 't-900'], outsiderIds: ['p-2', 't-901'], shared: [] },
    params: {}, refs: {}, private: {}, label: { kind: 'item', by: 'code' }, fingerprint: {}, evidence: [],
  });
  const options = swarmOptions(origin, fakeRequester(origin), { surface });
  const { results } = await runSwarm([task], options);
  assert.equal(results[0].verdict, 'confirmed', 'membership of the outer id only is checked');
  await mirror(results, options);
  assert.equal(results[0].mirror.url, '/api/projects/p-1/tasks/t-901', 'the inner slot gets an inner-shaped outsider id');
  assert.equal(results[0].mirror.result, 'both-open');
  assert.equal(hitsFor(state, '/api/projects/p-1/tasks/t-901', 'u-1'), 1);
});

test('mirror on a list finding sends the same parameter as the owner and looks for outsider-only ids', async t => {
  const { origin, state } = await startApp(t, { listLeak: true });
  const options = swarmOptions(origin, fakeRequester(origin));
  const { results } = await runSwarm([listTask(1, 'all=1')], options);
  assert.equal(results[0].verdict, 'confirmed');
  assert.equal(results[0].T.items, 3, 'list length of the leaked list');
  assert.deepEqual(results[0].T.fields, { id: 'string', ownerId: 'string', total: 'number' });
  assert.equal(results[0].O.items, 2);
  await mirror(results, options);
  assert.equal(results[0].mirror.result, 'both-open');
  assert.equal(results[0].mirror.url, '/api/invoices?all=1');
  assert.equal(state.hits.filter(hit => hit.path === '/api/invoices?all=1' && hit.user === 'u-1').length, 1);
});

test('identityRecheck confirms both principals and downgrades not_reproduced verdicts when it fails', async t => {
  const { origin } = await startApp(t);
  const requester = fakeRequester(origin);
  const options = swarmOptions(origin, requester);
  const healthy = await identityRecheck(options.surface, { requester, scope: options.scope });
  assert.equal(healthy.ok, true);
  assert.equal(healthy.evidence.length, 2);
  const calls = requester.calls.filter(call => call.step === 'identity');
  assert.deepEqual(calls.map(call => [call.url, call.identity, call.noCache]), [['/api/me', 'owner', true], ['/api/me', 'outsider', true]]);

  const { results } = await runSwarm([itemTask(1, 'inv-101'), itemTask(2, 'inv-102')], options);
  assert.deepEqual(results.map(result => result.verdict), ['not_reproduced', 'not_reproduced']);
  results[1].verdict = 'confirmed';
  requester.credentials.outsider = 'expired-token';
  const failed = await identityRecheck(options.surface, { requester, scope: options.scope, results });
  assert.equal(failed.ok, false);
  assert.match(failed.reason, /outsider identity request returned 401/);
  assert.equal(results[0].verdict, 'inconclusive');
  assert.equal(results[0].reason, 'credential may have expired mid-wave');
  assert.equal(results[1].verdict, 'confirmed', 'confirmed results are not downgraded');

  const unknown = await identityRecheck(surfaceFor(origin, { identityPath: null }), { requester, scope: { ...options.scope, identities: { ...options.scope.identities, identityPath: null } } });
  assert.equal(unknown.ok, false);
  assert.match(unknown.reason, /identity endpoint/);
});

test('swarm results flow into findings and a report that carries placeholders, never credential values', async t => {
  const before = { OWNER_TOKEN: process.env.OWNER_TOKEN, OTHER_TOKEN: process.env.OTHER_TOKEN };
  Object.assign(process.env, { OWNER_TOKEN: CREDENTIALS.owner, OTHER_TOKEN: CREDENTIALS.outsider });
  t.after(() => {
    for (const [name, value] of Object.entries(before)) {
      if (value === undefined) delete process.env[name];
      else process.env[name] = value;
    }
  });
  const { origin } = await startApp(t, { idor: true, listLeak: true });
  const requester = fakeRequester(origin);
  const options = swarmOptions(origin, requester);
  const { results, stats } = await runSwarm([itemTask(1, 'inv-101'), listTask(2, 'all=1'), itemTask(3, 'inv-102', { as: 'anonymous' })], options);
  const recheck = await identityRecheck(options.surface, { requester, scope: options.scope, results });
  await reverify(results, options);
  await mirror(results, options);
  const findings = buildFindings(results, {
    surface: options.surface, scope: options.scope,
    severityFor: kind => (kind === 'idor' ? 'high' : 'medium'), classify: () => ({ owasp: 'API1:2023', cwe: 'CWE-639' }), dataClasses: () => [],
  });
  assert.deepEqual(findings.map(finding => [finding.kind, finding.mirror.result]), [['idor', 'both-open'], ['list-leak', 'both-open']]);
  const { markdown, json } = renderReport({ run: 'bx-test', scope: options.scope, scopeHash: 'abc', surface: options.surface, findings, results, stats, recheck });
  assert.ok(markdown.includes('$OWNER_TOKEN') && markdown.includes('$OTHER_TOKEN'));
  for (const value of Object.values(CREDENTIALS)) {
    assert.ok(!markdown.includes(value) && !JSON.stringify(json).includes(value), 'no credential value in the report');
    assert.ok(!JSON.stringify(results).includes(value), 'no credential value in the results');
  }
});

const sibling = name => new URL(`../src/blackbox/${name}`, import.meta.url);
const realRequester = fs.existsSync(sibling('scope.mjs')) && fs.existsSync(sibling('ledger.mjs'));
test('the swarm runs on the real requester and ledger (and the real decide when present)', { skip: !realRequester && 'scope.mjs and ledger.mjs (T1) not present yet' }, async t => {
  const { loadScope, createRequester, createLimiter } = await import(sibling('scope.mjs'));
  const { createLedger, verifyLedger } = await import(sibling('ledger.mjs'));
  const verdict = fs.existsSync(sibling('verdict.mjs')) ? await import(sibling('verdict.mjs')) : null;
  const dir = temp();
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  const { origin, state } = await startApp(t, { idor: true });
  const env = { OWNER_TOKEN: CREDENTIALS.owner, OTHER_TOKEN: CREDENTIALS.outsider };
  const { scope } = loadScope({ origin, overrides: { acceptLocal: true, ownerEnv: 'OWNER_TOKEN', otherEnv: 'OTHER_TOKEN' }, env });
  const ledger = createLedger(dir, { run: 'bx-test', redactFields: scope.harvest?.redactFields ?? [], secrets: Object.values(env) });
  t.after(() => ledger.close?.());
  const requester = createRequester(scope, { ledger, limiter: createLimiter(scope.limits.rps), env, allowLocal: true, log: () => {}, run: 'bx-test' });
  const decide = verdict?.decide ?? stubDecide;
  const options = { requester, surface: surfaceFor(origin), scope, agents: 4, decide, log: () => {}, run: 'bx-test' };
  const { results, stats } = await runSwarm([itemTask(1, 'inv-101'), itemTask(2, 'inv-102', { as: 'anonymous' })], options);
  await reverify(results, options);
  assert.equal(results[0].verdict, 'confirmed', `${results[0].rule}: ${results[0].reason}`);
  assert.equal(results[0].confirmation.length > 0, true);
  assert.equal(results[1].verdict, 'not_reproduced', `${results[1].rule}: ${results[1].reason}`);
  assert.ok(stats.requests > 0);
  assert.equal(state.hits.filter(hit => hit.path === '/api/invoices/inv-101' && hit.user === 'u-1').length, 2, 'one control in the wave, one fresh control at re-verification');
  const ledgerFile = ledger.file ?? path.join(dir, 'evidence.jsonl');
  const lines = fs.readFileSync(ledgerFile, 'utf8');
  for (const value of Object.values(CREDENTIALS)) assert.ok(!lines.includes(value), 'no credential value in the ledger');

  const classifiers = verdict ?? { severityFor: () => 'high', classify: () => ({ owasp: 'API1:2023', cwe: 'CWE-639' }), dataClasses: () => [] };
  const findings = buildFindings(results, { surface: options.surface, scope, ...pick(classifiers, ['severityFor', 'classify', 'dataClasses']) });
  const { markdown } = renderReport({
    run: 'bx-test', scope, scopeHash: 'abc', surface: options.surface, findings, results, stats, ledgerFile, integrity: verifyLedger(ledgerFile),
  });
  assert.match(markdown, /ledger intact \(\d+ records\)/);
  const control = results[0].O.evidenceId;
  assert.match(markdown, new RegExp(`^\\| ${control} \\| \\d{4}-[^|]+ \\| owner \\| GET \\| \`${origin}/api/invoices/inv-101\` \\| 200 \\|`, 'm'),
    'the appendix row comes from the ledger T1 wrote');
  for (const value of Object.values(CREDENTIALS)) assert.ok(!markdown.includes(value), 'no credential value in the report');
});

function pick(source, names) {
  return Object.fromEntries(names.map(name => [name, source[name]]));
}
