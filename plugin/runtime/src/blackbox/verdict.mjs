// Deterministic access-control verdicts. The model may propose a request, but only recorded
// HTTP responses and the reconnaissance map can confirm a finding.
import { hash } from '../util.mjs';
import {detectList, harvestIds} from './recon.mjs';

const DENIED = new Set([401, 403, 404]);
const SENSITIVE = /^(email|phone|address|ssn|dob|iban|card|token|secret|password|salary|balance)$/i;
const PRIVILEGED = /(^|\/)(admin|internal|manage|staff|audit|config|debug|settings|logs|metrics|stats|dashboard)(\/|$)/i;
const CROSS_ACCOUNT = new Set(['idor', 'nested-idor', 'list-leak', 'param-filter']);

const sameShape = (a, b) => JSON.stringify(a?.shape ?? null) === JSON.stringify(b?.shape ?? null);
const ids = value => new Set([...(value?.ids ?? []).map(String),
  ...harvestIds(recordsOf(value) ?? []).map(item => item.id)]);
const intersects = (a, b) => [...a].some(value => b.has(value));
const rule = (verdict, name, reason = '') => ({verdict, rule: `${verdict}/${name}`, reason});

function patternFor(surface, task) {
  return surface?.patterns?.find(item => item.pattern === task.pattern) ?? null;
}

function ownerOnly(pattern) {
  const outsider = new Set((pattern?.ids?.outsiderIds ?? []).map(String));
  return new Set((pattern?.ids?.ownerIds ?? []).map(String).filter(id => !outsider.has(id)));
}

function itemId(task, pattern) {
  const value = new URL(task.control.url, 'http://blackbox.invalid').pathname;
  const slots = task.pattern.split('/');
  const parts = value.split('/');
  const at = slots.findLastIndex(part => /^\{[^}]+\}$/.test(part));
  return at < 0 ? null : parts[at] ?? null;
}

function ownerEvidence(task, O, pattern, scope) {
  if (task.kind === 'missing-auth' && task.pattern === scope?.identities?.identityPath && ids(O).size) return true;
  const id = itemId(task, pattern);
  if (id && pattern?.private?.[id]) return true;
  if (intersects(ids(O), ownerOnly(pattern))) return true;
  return false;
}

function accountBoundSensitive(O, T, surface) {
  if (O?.status !== 200 || T?.status !== 200 || !O.hash || O.hash === T.hash) return false;
  const principal = value => value && typeof value === 'object' ? value.value : value;
  const owner = principal(surface?.identity?.principals?.owner);
  const outsider = principal(surface?.identity?.principals?.outsider);
  if (owner == null || outsider == null || String(owner) === String(outsider)) return false;
  const ownerHash = hash(owner), outsiderHash = hash(outsider);
  const fields = {...(O.shape ?? {}), ...(O.fields ?? {})};
  return Object.keys(fields).some(field => SENSITIVE.test(field)) &&
    Object.entries(O.ownership ?? {}).some(([field, value]) => value === ownerHash &&
      T.ownership?.[field] === outsiderHash);
}

function missingAuthEvidence(task, O, T, pattern, scope, surface) {
  if (task.pattern === scope?.identities?.identityPath && ids(O).size) return true;
  const id = itemId(task, pattern);
  const privateIds = new Set(Object.keys(pattern?.private ?? {}));
  return id ? privateIds.has(id) : intersects(ids(O), privateIds) ||
    task.request.as === 'outsider' && accountBoundSensitive(O, T, surface);
}

function privateControl(task, O, pattern, scope) {
  if (ownerEvidence(task, O, pattern, scope)) return true;
  const fields = {...(O?.shape ?? {}), ...(O?.fields ?? {})};
  return Object.keys(fields).some(field => SENSITIVE.test(field));
}

function ownerResource(task, O, T, pattern) {
  if (T.status !== 200 || O.status !== 200) return false;
  if (O.hash && O.hash === T.hash && sameShape(O, T)) return true;
  const ownership = Object.entries(O.ownership ?? {});
  if (ownership.length && !ownership.some(([field, value]) => value && T.ownership?.[field] === value)) return false;
  const id = itemId(task, pattern);
  if (id && ids(T).has(id) && sameShape(O, T)) return true;
  return Object.entries(O.ownership ?? {}).some(([field, value]) => value && T.ownership?.[field] === value && sameShape(O, T));
}

function recordsOf(response) {
  let value;
  try {value = JSON.parse(response?.body ?? '');} catch {return null;}
  return detectList(value)?.items ?? null;
}

function foreignList(T, pattern) {
  const count = T?.items ?? recordsOf(T)?.length ?? 0;
  return count > 0 && intersects(ids(T), ownerOnly(pattern));
}

function filteredField(T, pattern, scope) {
  const baseline = pattern?.fingerprint?.outsider;
  const known = new Set(Object.keys({...baseline?.shape, ...baseline?.fields}));
  const fields = Object.keys({...T?.shape, ...T?.fields,
    ...(recordsOf(T)?.[0] ?? {})});
  const extra = new Set([...(scope?.harvest?.redactFields ?? []), 'email', 'phone', 'address', 'ssn', 'dob', 'iban', 'card', 'token', 'secret', 'password', 'salary', 'balance'].map(x => x.toLowerCase()));
  return fields.some(field => extra.has(field.toLowerCase()) && !known.has(field));
}

function throttled(response) {
  return response?.headers?.['retry-after'] != null || response?.headers?.['x-ratelimit-remaining'] === '0';
}

function graphqlValue(response, field) {
  if (response?.status !== 200 || !/json/i.test(response.type ?? '')) return null;
  try {return JSON.parse(response.body)?.data?.[field] ?? null;} catch {return null;}
}

function graphqlDenied(response, field) {
  if (DENIED.has(response?.status) && !throttled(response)) return true;
  if (response?.status !== 200 || !/json/i.test(response.type ?? '')) return false;
  try {
    const body = JSON.parse(response.body);
    return body?.data?.[field] == null && (!Array.isArray(body.errors) || body.errors.length === 0 ||
      body.errors.every(error => ['FORBIDDEN', 'UNAUTHENTICATED', 'NOT_FOUND'].includes(error?.extensions?.code)));
  } catch {return false;}
}

function graphqlBola(task, {O, T, A}) {
  const proof = task.graphql;
  if (!proof || [O, T, A].some(response => !response || response.refused || response.blocked))
    return rule('blocked', 'graphql/request-failed');
  if ([O, T, A].some(response => response.status === 429 || response.status >= 500 ||
      response.status >= 300 && response.status < 400 || response.headers?.age != null ||
      /HIT/i.test(response.headers?.['x-cache'] ?? '')))
    return rule('inconclusive', 'graphql/response-status');
  const expected = value => value && typeof value === 'object' && !Array.isArray(value) &&
    String(value.id) === proof.recordId && String(value[proof.ownerField]) === proof.ownerPrincipal;
  if (!expected(graphqlValue(O, proof.itemField)))
    return rule('blocked', 'graphql/control-failed', 'Owner query did not return the owner-listed object.');
  if (expected(graphqlValue(A, proof.itemField))) return rule('public', 'graphql/anonymous-read');
  if (expected(graphqlValue(T, proof.itemField))) return rule('confirmed', 'graphql-bola/owner-object');
  if (graphqlDenied(T, proof.itemField)) return rule('not_reproduced', 'graphql/denied');
  return rule('inconclusive', 'graphql/insufficient-evidence');
}

/** Pure verdict over one owner control, task response and anonymous response. */
export function decide(task, {O, T, A, surface, scope} = {}) {
  if (task.kind === 'graphql-bola') return graphqlBola(task, {O, T, A});
  const pattern = patternFor(surface, task);
  if (O?.status !== 200 || !O?.hash || (pattern?.label?.kind === 'list' && !O?.items && !ids(O).size)) {
    return rule('blocked', 'control-failed', 'Owner control did not return a real resource.');
  }
  if (!T || !A || T.blocked || A.blocked || T.refused || A.refused) return rule('blocked', 'request-failed');
  if ([O, T, A].some(x => x.status === 429 || x.status >= 500 || (x.status >= 300 && x.status < 400)))
    return rule('inconclusive', 'response-status');
  if ([O, T, A].some(x => x.status === 200 && x.type && !/json|\+json/i.test(x.type)))
    return rule('inconclusive', 'non-json');
  if ([O, T, A].some(x => x.status === 200 && (x.headers?.age || /HIT/i.test(x.headers?.['x-cache'] ?? ''))))
    return rule('inconclusive', 'cached-response');

  const isPrivate = privateControl(task, O, pattern, scope);
  const same = ownerResource(task, O, T, pattern);
  if (task.kind === 'missing-auth' && missingAuthEvidence(task, O, T, pattern, scope, surface) &&
      (ownerResource(task, O, A, pattern) || foreignList(A, pattern)))
    return rule('confirmed', 'missing-auth/owner-resource');
  if (T.status === 200 && A.status === 200 && same && ownerResource(task, O, A, pattern))
    return rule('public', 'same-resource');
  if (!isPrivate && T.status === 200 && same) return rule('shared', 'same-resource');
  if (['idor', 'nested-idor'].includes(task.kind) && isPrivate && same)
    return rule('confirmed', `${task.kind}/owner-resource`);
  if (task.kind === 'list-leak' && T.status === 200 && foreignList(T, pattern))
    return rule('confirmed', 'list-leak/owner-id');
  if (task.kind === 'param-filter' && T.status === 200 && (foreignList(T, pattern) || filteredField(T, pattern, scope)))
    return rule('confirmed', 'param-filter/extra-data');
  const declared = scope?.identities?.outsider?.role ?? '';
  const observed = surface?.identity?.roles?.outsider?.role ?? '';
  if (task.kind === 'bfla' && /admin|staff|superuser/i.test(`${declared} ${observed}`))
    return rule('inconclusive', 'requester-privileged', 'The requester may legitimately hold a privileged role.');
  if (task.kind === 'bfla' && PRIVILEGED.test(task.pattern) && DENIED.has(A.status) && T.status === 200 &&
      (foreignList(T, pattern) ||
       (surface?.identity?.principals?.owner != null && Object.values(T.ownership ?? {}).some(value => value === hash(surface.identity.principals.owner)))))
    return rule('confirmed', 'bfla/foreign-data');
  if (task.kind === 'enumeration' && T.status === 200) return rule('inconclusive', 'enumeration-needs-idor');
  const denied = task.kind === 'missing-auth' ? A : T;
  if (DENIED.has(denied.status) && !throttled(denied)) return rule('not_reproduced', 'denied');
  if (T.status === 200 && !same && !foreignList(T, pattern)) return rule('inconclusive', 'different-resource');
  return rule('inconclusive', 'insufficient-evidence');
}

const META = {
  idor: ['API1 Broken Object Level Authorization', 'CWE-639', 'high'],
  'graphql-bola': ['API1 Broken Object Level Authorization', 'CWE-639', 'high'],
  'nested-idor': ['API1 Broken Object Level Authorization', 'CWE-639', 'high'],
  'missing-auth': ['API2 Broken Authentication', 'CWE-306', 'high'],
  bfla: ['API5 Broken Function Level Authorization', 'CWE-862', 'high'],
  'list-leak': ['API1 Broken Object Level Authorization', 'CWE-639', 'medium'],
  'param-filter': ['API3 Broken Object Property Level Authorization', 'CWE-200', 'medium'],
  enumeration: ['API1 Broken Object Level Authorization', 'CWE-340', 'low'],
  exposure: ['API8 Security Misconfiguration', 'CWE-538', 'high'],
};

export function classify(kind) {
  const [owasp, cwe] = META[kind] ?? [null, null];
  return {owasp, cwe};
}

export function severityFor(kind, {pii = false, credentialLike = false, list = false, chain = false} = {}) {
  if (credentialLike || chain) return 'critical';
  if (kind === 'missing-auth' && list) return 'critical';
  if (pii && (kind === 'list-leak' || kind === 'param-filter')) return 'high';
  return META[kind]?.[2] ?? 'info';
}

export function dataClasses(response) {
  const keys = Object.keys({...response?.shape, ...response?.fields});
  return keys.filter(key => SENSITIVE.test(key));
}
