// Reconnaissance -> bounded, reviewable HTTP tasks. Model ideas use the same validator as code tasks.
import { taskAllowance, validateUrl } from './scope.mjs';
import { neighbors } from './recon.mjs';
import {safeAssetHint} from './asset-interpret.mjs';

const KINDS = new Set(['idor', 'nested-idor', 'missing-auth', 'bfla', 'list-leak', 'param-filter', 'enumeration', 'existence']);
const PRIVILEGED = /(^|\/)(admin|internal|manage|staff|audit|config|debug|settings|logs|metrics|stats|dashboard)(\/|$)/i;
const SENSITIVE_FIELD = /^(email|phone|address|ssn|dob|iban|card|token|secret|password|salary|balance)$/i;
const HIGH_SENSITIVITY_FIELD = /^(ssn|dob|iban|card|token|secret|password|salary|balance)$/i;
const MODEL_PAGE = Object.freeze({patterns: 20, assetEndpoints: 20, discoveredHosts: 10, routeNotes: 10});
const DEFAULT_MODEL_PAGES = 8;
const MAX_MODEL_CONTEXT_BYTES = 24000;
const unique = list => [...new Set(list)];
const short = (value, length = 300) => String(value ?? '').slice(0, length);

/** Split a row-bounded page again if unusually long routes would exceed the model input budget. */
function fitModelPage(page) {
  if (Buffer.byteLength(JSON.stringify(page)) <= MAX_MODEL_CONTEXT_BYTES) return [page];
  const entries = Object.keys(MODEL_PAGE).flatMap(field => page[field].map(item => ({field, item})));
  if (entries.length <= 1) return [page];
  const half = Math.ceil(entries.length / 2);
  const part = rows => Object.fromEntries(Object.keys(MODEL_PAGE).map(field =>
    [field, rows.filter(row => row.field === field).map(row => row.item)]));
  return [...fitModelPage(part(entries.slice(0, half))), ...fitModelPage(part(entries.slice(half)))];
}

function fill(pattern, ids) {
  let at = 0;
  return pattern.replace(/\{[^}]+\}/g, () => ids[at++] ?? '');
}

function task(kind, pattern, url, as = 'outsider', control = url, why = '', priority = 5) {
  return {kind, pattern, request: {method: 'GET', url, as}, control: {url: control, as: 'owner'},
    expect: 'denied', why, priority, origin: 'baseline', dependsOn: []};
}

function query(url, name, value) {
  const parsed = new URL(url, 'http://blackbox.invalid');
  parsed.searchParams.set(name, value);
  return `${parsed.pathname}${parsed.search}`;
}

function baseline(surface, scope) {
  const tasks = [];
  const byPattern = new Map(surface.patterns.map(record => [record.pattern, record]));
  for (const record of surface.patterns) {
    const pattern = record.pattern;
    const slots = [...pattern.matchAll(/\{[^}]+\}/g)].length;
    const ownerIds = unique(record.ids?.ownerIds ?? []);
    const outsiderIds = new Set(record.ids?.outsiderIds ?? []);
    if (pattern === scope.identities.identityPath && slots === 0) {
      tasks.push(task('missing-auth', pattern, pattern, 'anonymous', pattern,
        'Check the explicitly configured account identity endpoint without a session.', 9));
    }
    if (slots === 1) {
      for (const id of ownerIds.slice(0, 3)) {
        const url = fill(pattern, [id]);
        tasks.push(task('idor', pattern, url, 'outsider', url, 'Try an owner resource as another account.', 9));
        tasks.push(task('missing-auth', pattern, url, 'anonymous', url, 'Try the private resource without a session.', 9));
        for (const neighbor of (scope.harvest.thirdParty === 'read' ? neighbors(id, scope.harvest.sequentialNeighbors) : [])
          .filter(value => !outsiderIds.has(value))) {
          tasks.push(task('enumeration', pattern, fill(pattern, [neighbor]), 'outsider', url,
            'Test a neighboring identifier within scope.', 2));
        }
      }
      if (record.fingerprint?.outsider?.status === 200 && ownerIds.length) {
        const url = fill(pattern, [ownerIds[0]]);
        for (const key of scope.probes.expandKeys) for (const value of scope.probes.expandValues)
          tasks.push(task('param-filter', pattern, query(url, key, value), 'outsider', query(url, key, value),
            'Check whether a response parameter reveals private properties.', 5));
      }
    } else if (slots >= 2 && ownerIds.length) {
      const parentPattern = pattern.split('/').slice(0, -2).join('/');
      const parent = byPattern.get(parentPattern);
      for (const outer of (parent?.ids?.outsiderIds ?? []).slice(0, 2)) for (const inner of ownerIds.slice(0, 2)) {
        const control = record.canonical?.[inner];
        if (control) tasks.push(task('nested-idor', pattern, fill(pattern, [outer, inner]), 'outsider', control,
          'Try an owner child under an outsider parent.', 9));
      }
    }

    if (record.label?.kind === 'list') {
      tasks.push(task('missing-auth', pattern, pattern, 'anonymous', pattern, 'Read a private list without a session.', 8));
      tasks.push(task('list-leak', pattern, pattern, 'outsider', pattern, 'Compare account lists.', 8));
      for (const constant of scope.harvest.thirdParty === 'read' ? scope.probes.massExposure : []) {
        const [key, value] = constant.split('=');
        if (key && value != null) tasks.push(task('list-leak', pattern, query(pattern, key, value), 'outsider', query(pattern, key, value),
          'Check a bounded list expansion parameter.', 6));
      }
      const principal = surface.identity?.principals?.owner;
      if (principal != null) for (const key of unique([...scope.probes.identityFilters, ...Object.keys(record.params ?? {})])) {
        tasks.push(task('list-leak', pattern, query(pattern, key, principal), 'outsider', query(pattern, key, principal),
          'Check whether a filter trusts an account identifier.', 6));
      }
    }
    if (slots === 0 && record.label?.kind !== 'list' && pattern !== scope.identities.identityPath) {
      const owner = record.fingerprint?.owner, outsider = record.fingerprint?.outsider;
      const accountBound = owner?.status === 200 && outsider?.status === 200 &&
        owner.hash && outsider.hash && owner.hash !== outsider.hash &&
        Object.entries(owner.ownership ?? {}).some(([field, value]) => value &&
          outsider.ownership?.[field] && outsider.ownership[field] !== value);
      if (accountBound && Object.keys(owner.shape ?? {}).some(field => SENSITIVE_FIELD.test(field)))
        tasks.push(task('missing-auth', pattern, pattern, 'outsider', pattern,
          'Compare distinct account-bound sensitive responses with an anonymous read.', 8));
    }
    if (PRIVILEGED.test(pattern) && slots === 0) {
      tasks.push(task('bfla', pattern, pattern, 'outsider', pattern, 'Check a privileged route as an ordinary account.', 7));
      tasks.push(task('bfla', pattern, pattern, 'anonymous', pattern, 'Check a privileged route without a session.', 7));
    }
  }
  return tasks;
}

/** With one account, keep only anonymous reads tied to a verified owner identity and sensitive item data. */
export function oneAccountMissingAuthCandidate(candidate, surface, scope) {
  if (candidate?.kind !== 'missing-auth' || candidate.request?.as !== 'anonymous') return false;
  if (candidate.pattern === scope.identities.identityPath) return true;
  if (!surface.identity?.ownerVerified || !candidate.resourceId) return false;
  const record = surface.patterns.find(item => item.pattern === candidate.pattern);
  if (record?.private?.[candidate.resourceId]?.by !== 'ownership-field' ||
      record.fingerprint?.owner?.status !== 200) return false;
  return Object.keys(record.fingerprint.owner.shape ?? {}).some(field => HIGH_SENSITIVITY_FIELD.test(field));
}

function patternMatches(pattern, pathname) {
  const parts = pattern.split('/'), value = pathname.split('/');
  return parts.length === value.length && parts.every((part, index) => /^\{[^}]+\}$/.test(part) ? !!value[index] : part === value[index]);
}

/** Returns a reason for dropping a proposal, or null when its method, identities, URL and IDs are safe. */
export function validateTask(candidate, surface, scope) {
  if (!candidate || !KINDS.has(candidate.kind)) return 'kind';
  const pattern = surface.patterns.find(record => record.pattern === candidate.pattern);
  if (!pattern) return 'pattern';
  if (!candidate.request || !candidate.control || candidate.request.method !== 'GET') return 'method';
  if (!['outsider', 'anonymous'].includes(candidate.request.as) || candidate.control.as !== 'owner') return 'identity-mismatch';
  for (const [raw, identity] of [[candidate.request.url, candidate.request.as], [candidate.control.url, 'owner']]) {
    if (typeof raw !== 'string') return 'url';
    const check = validateUrl(scope, raw, {purpose: 'task', identity});
    if (!check.ok) return check.reason;
    if (new URL(check.url).origin !== scope.target.origin) return 'origin';
  }
  const requested = new URL(candidate.request.url, scope.target.origin);
  const control = new URL(candidate.control.url, scope.target.origin);
  if (scope.harvest.thirdParty !== 'read' && candidate.kind === 'list-leak' && requested.searchParams.size) {
    const principal = value => value && typeof value === 'object' ? value.value : value;
    const allowed = new Set([principal(surface.identity?.principals?.owner),
      principal(surface.identity?.principals?.outsider)].filter(value => value != null).map(String));
    if ([...requested.searchParams].some(([key, value]) =>
      !scope.probes.identityFilters.includes(key) || !allowed.has(value))) return 'third-party-read';
  }
  if (candidate.origin === 'model' && [...requested.searchParams.keys()].some(key =>
    !Object.hasOwn(pattern.params ?? {}, key) && !scope.probes.expandKeys.includes(key) &&
    !scope.probes.identityFilters.includes(key) &&
    !scope.probes.massExposure.some(entry => entry.startsWith(`${key}=`)))) return 'query-provenance';
  if (!patternMatches(candidate.pattern, requested.pathname) || !patternMatches(candidate.pattern, control.pathname)) return 'pattern-url';
  if (candidate.kind === 'nested-idor') {
    const inner = requested.pathname.split('/').at(-1);
    if (pattern.canonical?.[inner] !== `${control.pathname}${control.search}`) return 'control-mismatch';
  } else if (candidate.kind !== 'enumeration' && requested.href !== control.href) return 'control-mismatch';
  const slots = candidate.pattern.split('/');
  const values = requested.pathname.split('/');
  const known = new Set(surface.patterns.flatMap(item => [...(item.ids?.ownerIds ?? []), ...(item.ids?.outsiderIds ?? []), ...(item.ids?.shared ?? [])]));
  for (const [index, part] of slots.entries()) if (/^\{[^}]+\}$/.test(part) && !known.has(values[index])) {
    if (candidate.kind !== 'enumeration' || !surface.patterns.some(item => item.pattern === candidate.pattern &&
      item.ids?.ownerIds?.some(id => neighbors(id, scope.harvest.sequentialNeighbors).includes(values[index])))) return 'id-provenance';
  }
  return null;
}

/** Baseline is always generated first; Muse sees bounded pages and adds only validated tasks. */
export async function planTasks(surface, scope, {infer = null, model = null, discovery = null,
  maxModelPages = DEFAULT_MODEL_PAGES, log = () => {}} = {}) {
  const proposals = baseline(surface, scope);
  let modelCalls = 0;
  let modelError = null;
  const patterns = surface.patterns.map(record => ({pattern: record.pattern, label: record.label?.kind,
    ids: {owner: record.ids?.ownerIds?.slice(0, 2).map(id => short(id, 200)),
      outsider: record.ids?.outsiderIds?.slice(0, 2).map(id => short(id, 200))},
    params: Object.keys(record.params ?? {}).slice(0, 16).map(name => short(name, 100)),
    refs: Object.fromEntries(Object.entries(record.refs ?? {}).slice(0, 8)
      .map(([field, path]) => [short(field, 100), short(path, 512)])),
    statuses: record.fingerprint ? Object.fromEntries(['owner', 'outsider', 'anonymous']
      .map(as => [as, record.fingerprint[as]?.status])) : {}}));
  const assetEndpoints = (surface.mined?.endpoints ?? []).map(item => ({path: item.path, method: item.method,
    params: (item.params ?? []).slice(0, 16).map(name => short(name, 100)),
    examples: Object.fromEntries(Object.entries(item.examples ?? {}).slice(0, 16)
      .map(([key, values]) => [short(key, 100), (values ?? []).slice(0, 4).map(value => short(value, 80))])),
    purpose: short(item.purpose, 300),
    parameterMeanings: (item.parameterMeanings ?? []).slice(0, 16)
      .map(note => ({name: short(note.name, 100), meaning: short(note.meaning, 200)})),
    sourceFiles: (item.sources ?? []).slice(0, 8).map(safeAssetHint),
    source: short(item.source ?? 'asset', 120)}));
  const discoveredHosts = (discovery?.hosts ?? []).map(host => ({host: host.host,
    stack: (host.stack ?? []).slice(0, 8).map(item => typeof item === 'object' && item !== null ?
      {product: short(item.product, 100), version: short(item.version, 60), by: short(item.by, 60)} : short(item, 100)),
    exposures: (host.exposures ?? []).slice(0, 10).map(item => short(item.path, 300))}));
  const routeNotes = (surface.modelNotes ?? []).map(note => ({path: short(note.path, 512),
    purpose: short(note.purpose), why: short(note.why), by: short(note.by, 80),
    methods: (note.methods ?? []).slice(0, 8).map(method => short(method, 20)),
    parameters: (note.parameters ?? []).slice(0, 16).map(param => short(param, 100)),
    sourceFiles: (note.sourceFiles ?? []).slice(0, 8).map(safeAssetHint)}));
  const sources = {patterns, assetEndpoints, discoveredHosts, routeNotes};
  const basePages = Math.max(1, ...Object.entries(MODEL_PAGE).map(([field, size]) =>
    Math.ceil(sources[field].length / size)));
  const pages = Array.from({length: basePages}, (_, page) => Object.fromEntries(Object.entries(MODEL_PAGE)
    .map(([field, size]) => [field, sources[field].slice(page * size, (page + 1) * size)]))).flatMap(fitModelPage);
  const pagesAvailable = pages.length;
  const modelCoverage = {pagesAvailable, pagesSent: 0, patternsAvailable: patterns.length, patternsSent: 0,
    assetEndpointsAvailable: assetEndpoints.length, assetEndpointsSent: 0,
    discoveredHostsAvailable: discoveredHosts.length, discoveredHostsSent: 0,
    routeNotesAvailable: routeNotes.length, routeNotesSent: 0};
  if (infer && model) {
    for (let page = 0; page < Math.min(pagesAvailable, maxModelPages); page++) {
      const section = pages[page];
      const context = {origin: scope.target.origin, page: page + 1, pages: pagesAvailable,
        ...section, principals: surface.identity?.principals};
      if (Buffer.byteLength(JSON.stringify(context)) > MAX_MODEL_CONTEXT_BYTES) {
        modelError ??= `Planning page ${page + 1} exceeds the ${MAX_MODEL_CONTEXT_BYTES}-byte model context limit.`;
        log({stage: 'plan', message: modelError});
        continue;
      }
      try {
        modelCalls++;
        const response = await infer(model, [{role: 'system', content: 'Propose bounded GET access-control tests from the supplied HTTP, asset and source-assisted map. Understand route purposes and parameter meanings before proposing concrete owner controls and outsider requests. Return JSON tasks only. Every task needs kind, pattern, request, control, why, priority. Never request writes, authentication values, or off-scope hosts.'},
          {role: 'user', content: JSON.stringify(context)}],
        {schema: {type: 'object', properties: {tasks: {type: 'array', maxItems: 30, items: {type: 'object',
          properties: {kind: {type: 'string'}, pattern: {type: 'string'}, request: {type: 'object', properties: {method: {type: 'string'}, url: {type: 'string'}, as: {type: 'string'}}, required: ['method', 'url', 'as'], additionalProperties: false},
            control: {type: 'object', properties: {url: {type: 'string'}, as: {type: 'string'}}, required: ['url', 'as'], additionalProperties: false}, why: {type: 'string'}, priority: {type: 'integer'}},
          required: ['kind', 'pattern', 'request', 'control', 'why', 'priority'], additionalProperties: false}}},
          required: ['tasks'], additionalProperties: false}});
        for (const proposal of response.tasks ?? []) proposals.push({...proposal, origin: 'model', dependsOn: []});
        modelCoverage.pagesSent++;
        for (const field of Object.keys(MODEL_PAGE)) modelCoverage[`${field}Sent`] += context[field].length;
      } catch (error) {
        modelError = error.message;
        log({stage: 'plan', message: `Muse planning failed on page ${page + 1}: ${error.message}`});
        break;
      }
    }
    log({stage: 'plan', message: `Muse received ${modelCoverage.pagesSent} of ${pagesAvailable} planning pages`});
  }
  const dropped = [], tasks = [], seen = new Set();
  for (const proposal of proposals) {
    const reason = validateTask(proposal, surface, scope);
    if (reason) { dropped.push({task: proposal, reason}); continue; }
    const key = `${proposal.kind} ${proposal.request.as} ${new URL(proposal.request.url, scope.target.origin).href}`;
    if (seen.has(key)) continue;
    seen.add(key);
    const segments = proposal.pattern.split('/');
    const resourceId = segments.at(-1)?.startsWith('{') ?
      new URL(proposal.request.url, scope.target.origin).pathname.split('/').at(-1) : null;
    tasks.push({...proposal, resourceId, priority: Math.max(0, Math.min(10, Number(proposal.priority) || 0))});
  }
  tasks.sort((a, b) => b.priority - a.priority || (a.origin === 'baseline' ? -1 : 1));
  tasks.forEach((entry, index) => {entry.id = `t-${String(index + 1).padStart(3, '0')}`;});
  const untested = tasks.splice(taskAllowance(scope));
  log({stage: 'plan', message: `${tasks.length} tasks planned; ${untested.length} beyond budget; ${dropped.length} dropped`});
  return {tasks, dropped, untested, modelCalls, modelError, modelCoverage};
}
