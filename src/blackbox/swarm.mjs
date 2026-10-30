// Task agents, re-verification, the mirror request and the identity re-check.
// Implements design section 8 (a bounded pool of async agents over one queue; the per-run request cache of
// section 15 is the requester's), 9.3 (fresh re-execution of confirmed results) and 9.4 (identity control, role parity).
// Every exchange goes through the injected guarded requester; verdicts come from the injected decide().
import {harvestIds} from './recon.mjs';

const MAX_AGENTS = 100;
const DENIED = new Set([401, 403, 404]);
const ID_FIELD = /^(id|_id|uuid|slug|key)$|Id$|_id$|_uid$/;
const WAVE_STEPS = { control: 'control', task: 'task', anonymous: 'anonymous' };
const REVERIFY_STEPS = { control: 'reverify', task: 'reverify', anonymous: 'reverify' };
const VERDICT_COUNTS = {
  confirmed: 'confirmed', not_reproduced: 'notReproduced', inconclusive: 'inconclusive', blocked: 'blocked', public: 'public', shared: 'shared',
};

const unique = values => [...new Set(values.filter(Boolean))];
const isObject = value => value !== null && typeof value === 'object' && !Array.isArray(value);
const principalValue = principal => (isObject(principal) ? principal.value ?? null : principal ?? null);
const failed = response => !!(response.refused || response.blocked);
const fresh = options => ({ ...options, noCache: true, headers: { 'cache-control': 'no-cache' } });

async function runIndependent(items, width, visit) {
  let next = 0;
  let stopped = false;
  const worker = async () => {
    try {
      while (!stopped && next < items.length) await visit(items[next++]);
    } catch (error) {
      stopped = true;
      throw error;
    }
  };
  // Let in-flight checks finish before the caller can close the evidence ledger.
  const settled = await Promise.allSettled(Array.from({length: Math.min(width, items.length)}, worker));
  const failedWorker = settled.find(item => item.status === 'rejected');
  if (failedWorker) throw failedWorker.reason;
}

function verificationWidth(count, scope, agents) {
  const configured = Math.max(1, Math.floor(Number(scope?.limits?.agents ?? 2)) || 1);
  const requested = Math.max(1, Math.floor(Number(agents ?? configured)) || 1);
  return Math.min(count, configured, requested, MAX_AGENTS);
}

/**
 * Run tasks on min(agents, scope.limits.agents, 100) concurrent agents (design 8.1, 8.2).
 * Each agent sends the owner control, the task request and the anonymous request, then calls decide().
 * Tasks that share a control or an anonymous URL share one exchange through the requester's cache.
 * @returns {Promise<{results: object[], stats: object}>} results in task order; bodies are not kept
 */
export async function runSwarm(tasks, { requester, surface, scope, agents, log = () => {}, decide, run }) {
  const requested = Number.isInteger(agents) && agents > 0 ? agents : scope.limits.agents;
  const width = Math.max(1, Math.min(requested, scope.limits.agents, MAX_AGENTS, tasks.length));
  const before = counters(requester);
  const started = Date.now();
  const results = new Array(tasks.length);
  let next = 0;
  let completed = 0;
  let stopped = false;
  log({ stage: 'swarm', message: `${tasks.length} tasks on ${width} agents`, run, tasks: tasks.length, agents: width });
  log({stage: 'progress', type: 'task-total', total: tasks.length});

  async function agent(number) {
    try {
      while (!stopped && next < tasks.length) {
        const index = next++;
        const task = tasks[index];
        results[index] = await runTask(task, { send: requester, agent: number, steps: WAVE_STEPS, decide, surface, scope });
        completed++;
        log({stage: 'progress', type: 'task-done', confirmed: results[index].verdict === 'confirmed'});
        if (results[index].verdict === 'confirmed') {
          log({ stage: 'swarm', message: `confirmed ${task.id} ${task.kind} ${task.pattern}`, run, task: task.id });
        }
      }
    } catch (error) {
      stopped = true; // the other agents finish their current task and take no new one
      throw error;
    }
  }

  const outcomes = await Promise.allSettled(Array.from({ length: width }, (_, index) => agent(index + 1)));
  const rejected = outcomes.find(outcome => outcome.status === 'rejected');
  if (rejected) throw rejected.reason;
  const stats = swarmStats(results, { before, after: counters(requester), started, agents: width });
  const summary = `${stats.tasks} tasks, ${stats.requests} requests (${stats.cached} cached), ${stats.confirmed} confirmed in ${stats.elapsedMs} ms`;
  log({ stage: 'swarm', message: summary, run, ...stats });
  return { results, stats };
}

// One agent's work on one task (design 8.2): control first, then the task identity, then anonymous; a refused
// or failed exchange ends the task as blocked with its reason, before any further request.
async function runTask(task, { send, agent, steps, decide, surface, scope }) {
  const method = task.request.method ?? 'GET';
  const exchange = (identity, verb, url, step) => send({ url, identity, method: verb, step, task: task.id, agent });
  const O = await exchange(task.control.as ?? 'owner', 'GET', task.control.url, steps.control);
  if (failed(O)) return blockedResult(task, 'control', [O]);
  const T = await exchange(task.request.as, method, task.request.url, steps.task);
  if (failed(T)) return blockedResult(task, 'task', [O, T]);
  const A = task.request.as === 'anonymous' ? T : await exchange('anonymous', method, task.request.url, steps.anonymous);
  if (failed(A)) return blockedResult(task, 'anonymous', [O, T, A]);
  const verdict = decide(task, { O, T, A, surface, scope });
  return {
    task, verdict: verdict.verdict, rule: verdict.rule, reason: verdict.reason ?? '',
    evidence: unique([...(task.supportEvidence ?? []), ...(verdict.evidence ?? []),
      O.evidenceId, T.evidenceId, A.evidenceId]),
    O: summarize(O), T: summarize(T), A: summarize(A),
  };
}

function blockedResult(task, label, exchanges) {
  const last = exchanges.at(-1);
  const [O, T, A] = exchanges.map(summarize);
  return {
    task, verdict: 'blocked', rule: last.refused ? 'blocked/refused' : 'blocked/request-failed',
    reason: `${label} request ${last.refused ? 'refused' : 'failed'}: ${last.reason}`,
    evidence: unique(exchanges.map(exchange => exchange.evidenceId)), O: O ?? null, T: T ?? null, A: A ?? null,
  };
}

// What a result keeps of an exchange: the fingerprint fields, never the body. For a list it adds the list
// length and the field types of its records, since the shape stops at 'array' and severity depends on what
// the records carry (design 13).
function summarize(response) {
  if (!response) return null;
  if (response.refused) return { refused: true, reason: response.reason, evidenceId: response.evidenceId };
  if (response.blocked) return { blocked: true, reason: response.reason, evidenceId: response.evidenceId };
  const { status, type, bytes, hash, shape, ownership, headers, evidenceId } = response;
  const records = listRecords(response.body);
  const list = records ? { items: records.length, fields: recordFields(records) } : { items: null, fields: null };
  return { status, type, bytes, hash, shape, ids: responseIds(response, records), ownership, headers, evidenceId, ...list };
}

function responseIds(response, records = listRecords(response.body)) {
  return unique([...(response.ids ?? []).map(String), ...harvestIds(records ?? []).map(item => item.id)]);
}

// Design 6.6: a list is a JSON array of objects, or the first array of objects with an id-like field found
// under a wrapper key at depth 2 or less. Anything else (an item, HTML, text) is not a list.
function listRecords(body) {
  const json = typeof body === 'string' ? parseJson(body) : body;
  if (Array.isArray(json)) return json.every(isObject) ? json : null;
  if (!isObject(json)) return null;
  const levelOne = Object.values(json);
  const levelTwo = levelOne.filter(isObject).flatMap(value => Object.values(value));
  return [...levelOne, ...levelTwo].find(isRecordArray) ?? null;
}

function recordFields(records) {
  const fields = {};
  for (const record of records) {
    for (const [key, value] of Object.entries(record)) fields[key] ??= value === null ? 'null' : Array.isArray(value) ? 'array' : typeof value;
  }
  return fields;
}

function isRecordArray(value) {
  return Array.isArray(value) && value.length > 0 && value.every(isObject) && value.some(item => Object.keys(item).some(key => ID_FIELD.test(key)));
}

// Bodies are untrusted data: HTML, text or malformed JSON simply carry no list and no principal.
function parseJson(text) {
  try {
    return JSON.parse(text);
  } catch {
    return null;
  }
}

function counters(requester) {
  return { sent: requester.stats?.sent ?? 0, cached: requester.stats?.cached ?? 0 };
}

function swarmStats(results, { before, after, started, agents }) {
  const elapsedMs = Date.now() - started;
  const requests = after.sent - before.sent;
  const counts = { confirmed: 0, notReproduced: 0, inconclusive: 0, blocked: 0, public: 0, shared: 0 };
  for (const result of results) {
    const key = VERDICT_COUNTS[result.verdict];
    if (key) counts[key] += 1;
  }
  const rps = Math.round((requests * 10000) / Math.max(elapsedMs, 1)) / 10;
  return { tasks: results.length, requests, cached: after.cached - before.cached, ...counts, agents, elapsedMs, rps };
}

/**
 * Re-execute every confirmed result once with fresh requests (design 9.3): noCache, Cache-Control: no-cache,
 * step 'reverify'. Agreement on verdict and rule attaches the new evidence IDs as `confirmation`;
 * disagreement downgrades the result to inconclusive and keeps both evidence sets.
 * Updates the results in place and returns the same array.
 */
export async function reverify(results, { requester, surface, scope, agents, decide, log = () => {} }) {
  const send = options => requester(fresh(options));
  const confirmed = results.filter(entry => entry.verdict === 'confirmed');
  await runIndependent(confirmed, verificationWidth(confirmed.length, scope, agents), async result => {
    const second = await runTask(result.task, { send, agent: null, steps: REVERIFY_STEPS, decide, surface, scope });
    if (second.verdict === result.verdict && second.rule === result.rule) {
      result.confirmation = second.evidence;
      return;
    }
    log({ stage: 'reverify', message: `${result.task.id} not reproduced on re-verification (${second.rule})`, task: result.task.id });
    Object.assign(result, {
      verdict: 'inconclusive',
      rule: 'inconclusive/reverify',
      reason: `not reproduced on re-verification (first ${result.rule}, second ${second.rule})`,
      evidence: unique([...result.evidence, ...second.evidence]),
    });
  });
  return results;
}

/**
 * Role parity for every confirmed cross-account result (design 9.4). The owner requests an outsider-only
 * resource on the same pattern, or for a list the same query with the outsider's principal in place of the
 * owner's. 'both-open' keeps the result; 'asymmetric' (owner denied) downgrades it to inconclusive tagged
 * role-asymmetric; 'unverified' (no outsider-only id, or an ambiguous answer) tags it role-unverified.
 * Updates the results in place and returns the same array.
 */
export async function mirror(results, { requester, surface, scope, agents, log = () => {} }) {
  const confirmed = results.filter(entry => entry.verdict === 'confirmed');
  await runIndependent(confirmed, verificationWidth(confirmed.length, scope, agents), async result => {
    const plan = mirrorPlan(result, surface);
    const outcome = plan.url ? await requestMirror(result, plan, requester) : plan;
    result.mirror = { result: outcome.result, url: plan.url ?? null, evidence: outcome.evidence ?? [], reason: outcome.reason };
    if (outcome.result === 'asymmetric') {
      Object.assign(result, { verdict: 'inconclusive', rule: 'inconclusive/role-asymmetric', reason: outcome.reason });
      result.tags = unique([...(result.tags ?? []), 'role-asymmetric']);
      log({ stage: 'mirror', message: `${result.task.id} role-asymmetric: ${outcome.reason}`, task: result.task.id });
    } else if (outcome.result === 'unverified' && plan.crossAccount) {
      result.tags = unique([...(result.tags ?? []), 'role-unverified']);
    }
  });
  return results;
}

// Which owner request mirrors a confirmed result: item kinds swap an outsider-only id into the owner's own
// URL (for nested routes, under the owner's outer id); list kinds replay the outsider's query as the owner.
function mirrorPlan({ task, O }, surface) {
  if (task.request.as !== 'outsider') return { result: 'unverified', reason: 'not a cross-account finding', crossAccount: false };
  if (task.kind === 'graphql-bola') return task.graphql?.mirrorUrl
    ? {url: task.graphql.mirrorUrl, mode: 'graphql', id: task.graphql.mirrorId,
      field: task.graphql.itemField, ownerField: task.graphql.ownerField,
      outsiderPrincipal: task.graphql.outsiderPrincipal, crossAccount: true}
    : {result: 'unverified', reason: 'no outsider-owned GraphQL object in the observed list', crossAccount: true};
  if (task.kind === 'bfla') {
    return task.control.url === task.request.url && O?.status === 200
      ? { result: 'both-open', reason: 'the owner control read the same route', evidence: [O.evidenceId], crossAccount: true }
      : { result: 'unverified', reason: 'no owner read of the same route', crossAccount: true };
  }
  const outsiderIds = outsiderOnlyIds(surface, task.pattern);
  if (!outsiderIds.length) return { result: 'unverified', reason: 'no outsider-only id on the pattern', crossAccount: true };
  if (!task.resourceId) return { url: swapPrincipal(task.request.url, surface), mode: 'list', ids: outsiderIds, crossAccount: true };
  // Prefer an id shaped like the resource id (same text before the trailing digits): on a nested pattern the
  // harvested ids may mix outer and inner ids, and an outer id in the inner slot would 404 and look like a denial.
  const shape = id => String(id).replace(/\d+$/, '');
  const id = outsiderIds.find(candidate => shape(candidate) === shape(task.resourceId)) ?? outsiderIds[0];
  const url = swapId(task.control.url, task.resourceId, id);
  return url
    ? { url, mode: 'item', id, crossAccount: true }
    : { result: 'unverified', reason: 'the control URL does not carry the resource id', crossAccount: true };
}

// Outsider-only ids of a pattern, including ids harvested from it into item patterns (source 'harvest:<pattern>').
function outsiderOnlyIds(surface, pattern) {
  const records = (surface?.patterns ?? []).filter(record => record.pattern === pattern || (record.source ?? []).includes(`harvest:${pattern}`));
  return unique(records.flatMap(({ ids = {} }) => {
    const notOutsiderOnly = new Set([...(ids.ownerIds ?? []), ...(ids.shared ?? [])]);
    return (ids.outsiderIds ?? []).filter(id => !notOutsiderOnly.has(id));
  }));
}

function swapId(url, from, to) {
  return rewrite(url, parsed => {
    const segments = parsed.pathname.split('/');
    const index = segments.lastIndexOf(encodeURIComponent(from));
    if (index < 0) return false;
    segments[index] = encodeURIComponent(to);
    parsed.pathname = segments.join('/');
    return true;
  });
}

function swapPrincipal(url, surface) {
  const owner = principalValue(surface?.identity?.principals?.owner);
  const outsider = principalValue(surface?.identity?.principals?.outsider);
  return rewrite(url, parsed => {
    if (owner === null || outsider === null) return true;
    // Only touch the query when a value matches, so an unchanged URL stays byte-identical.
    for (const [key, value] of [...parsed.searchParams]) {
      if (value === String(owner)) parsed.searchParams.set(key, String(outsider));
    }
    return true;
  });
}

// Applies an edit to a task URL and returns it in the same form (relative stays relative), or null.
function rewrite(url, edit) {
  const parsed = new URL(url, 'http://relative.invalid');
  if (!edit(parsed)) return null;
  return url.startsWith('/') ? `${parsed.pathname}${parsed.search}` : parsed.href;
}

async function requestMirror(result, plan, requester) {
  const response = await requester(fresh({ url: plan.url, identity: 'owner', method: 'GET', step: 'mirror', task: result.task.id, agent: null }));
  const evidence = unique([response.evidenceId]);
  if (failed(response)) {
    return { result: 'unverified', reason: `mirror request ${response.refused ? 'refused' : 'failed'}: ${response.reason}`, evidence };
  }
  if (DENIED.has(response.status) && !rateLimited(response)) {
    const reason = `the owner was denied (${response.status}) on the outsider's resource while the outsider read the owner's;`
      + ' the outsider may be privileged or the resource shared';
    return { result: 'asymmetric', reason, evidence };
  }
  const ids = responseIds(response);
  const graphql = plan.mode === 'graphql' && response.status === 200 ? graphqlItem(response.body, plan.field) : null;
  const open = response.status === 200 && (plan.mode === 'graphql'
    ? graphql && String(graphql.id) === plan.id &&
      String(graphql[plan.ownerField]) === plan.outsiderPrincipal
    : plan.mode === 'item'
    ? ids.includes(plan.id) && sameKeys(response.shape, result.T?.shape)
    : ids.some(id => plan.ids.includes(id)));
  return open
    ? { result: 'both-open', reason: "the owner read the outsider's resource the same way", evidence }
    : { result: 'unverified', reason: `the owner received ${response.status} without the outsider's resource`, evidence };
}

function graphqlItem(body, field) {
  try {
    const value = JSON.parse(body)?.data?.[field];
    return isObject(value) ? value : null;
  } catch {return null;}
}

// A 403 or 429 that carries rate-limit headers is throttling, not a denial (design 9.2 rule 5).
function rateLimited(response) {
  const headers = response.headers ?? {};
  return headers['retry-after'] != null || headers['x-ratelimit-remaining'] === '0';
}

// Same resource type: both bodies have the same top-level keys, which a 200 denial echoing the id does not.
function sameKeys(a, b) {
  const keys = shape => (isObject(shape) ? Object.keys(shape).sort().join(',') : JSON.stringify(shape));
  return keys(a) === keys(b);
}

/**
 * Re-request the identity path as owner and outsider at the end of a wave (design 9.4): ok when each still
 * answers 200 carrying its own principal. On failure every not_reproduced result in `results` is downgraded
 * to inconclusive ('credential may have expired mid-wave'), so an expired token never reads as a denial.
 * @returns {Promise<{ok: boolean, reason: string, evidence: string[], downgraded: number}>}
 */
export async function identityRecheck(surface, { requester, scope, results = [], log = () => {} }) {
  const check = await checkIdentity(surface, requester, scope);
  if (check.ok) return { ...check, downgraded: 0 };
  const stale = results.filter(result => result.verdict === 'not_reproduced');
  for (const result of stale) {
    Object.assign(result, { verdict: 'inconclusive', rule: 'inconclusive/identity-recheck', reason: 'credential may have expired mid-wave' });
  }
  const message = `identity re-check failed: ${check.reason}; ${stale.length} not_reproduced results downgraded`;
  log({ stage: 'identity', message, downgraded: stale.length });
  return { ...check, downgraded: stale.length };
}

async function checkIdentity(surface, requester, scope) {
  const path = surface?.identity?.path ?? scope?.identities?.identityPath ?? null;
  const principals = {
    owner: principalValue(surface?.identity?.principals?.owner),
    outsider: principalValue(surface?.identity?.principals?.outsider),
  };
  if (!path || principals.owner === null || principals.outsider === null) {
    return { ok: false, reason: 'identity endpoint unknown; credentials could not be re-checked', evidence: [] };
  }
  const evidence = [];
  for (const identity of ['owner', 'outsider']) {
    const response = await requester(fresh({ url: path, identity, method: 'GET', step: 'identity', task: null, agent: null }));
    if (response.evidenceId) evidence.push(response.evidenceId);
    if (failed(response)) {
      return { ok: false, reason: `${identity} identity request ${response.refused ? 'refused' : 'failed'}: ${response.reason}`, evidence };
    }
    if (response.status !== 200) return { ok: false, reason: `${identity} identity request returned ${response.status}`, evidence };
    if (!carries(response.body, principals[identity])) return { ok: false, reason: `${identity} principal changed`, evidence };
  }
  return { ok: true, reason: 'owner and outsider principals unchanged', evidence };
}

// Design 6.5: the principal sits at the top level of the identity body or one level down (user, data, ...).
function carries(body, principal) {
  const json = typeof body === 'string' ? parseJson(body) : body;
  const levels = isObject(json) ? [json, ...Object.values(json).filter(isObject)] : [];
  return levels.some(level => Object.values(level).some(value => ['string', 'number'].includes(typeof value) && String(value) === String(principal)));
}
