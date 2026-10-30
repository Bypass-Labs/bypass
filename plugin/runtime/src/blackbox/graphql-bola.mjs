// GraphQL object authorization plans from observed read-only schema signatures and real account lists.
import {validateUrl} from './scope.mjs';
import {maskSecrets} from './assets.mjs';
import {MODEL_RESPONSE_BYTES, responseSizeLimited} from './response-size.mjs';

const NAME = /^[_A-Za-z][_A-Za-z0-9]{0,79}$/;
const ID = /^[A-Za-z0-9_.@-]{1,96}$/;
const OWNER_FIELDS = ['ownerId', 'userId', 'owner_uid'];
const MAX_TYPES = 8;
const MAX_PAIRS = 8;
const MAX_CANDIDATES = 128;
const MODEL_PAGE_ITEMS = 16;
const MODEL_MAX_BYTES = 16000;
const MAX_BODY = MODEL_RESPONSE_BYTES;

const principal = value => value && typeof value === 'object' ? value.value : value;
const object = value => value !== null && typeof value === 'object' && !Array.isArray(value);
const unique = values => [...new Set(values.filter(Boolean))];
const safeName = value => typeof value === 'string' && NAME.test(value);
const safePrincipal = value => typeof value === 'string' && value.length > 0 && value.length <= 200 ? value :
  typeof value === 'number' && Number.isFinite(value) ? String(value) : null;

function parsed(response) {
  if (response?.status !== 200 || !/json/i.test(response.type ?? '') ||
      typeof response.body !== 'string' || response.headers?.age != null ||
      /HIT/i.test(response.headers?.['x-cache'] ?? '')) return null;
  try {return JSON.parse(response.body);} catch {return null;}
}

function listRows(response, field) {
  const body = parsed(response);
  if (!body || Array.isArray(body.errors) && body.errors.length || !Array.isArray(body.data?.[field])) return null;
  const rows = body.data[field];
  return rows.every(object) ? rows : null;
}

function typeFieldNames(response, expectedType) {
  const body = parsed(response);
  if (body?.data?.__type?.name !== expectedType || !Array.isArray(body.data.__type.fields)) return [];
  return body.data.__type.fields.filter(field => safeName(field?.name) &&
    (field.name === 'id' || OWNER_FIELDS.includes(field.name)) &&
    ['ID', 'String'].includes(namedType(field.type))).map(field => field.name);
}

function namedType(type) {
  for (let at = 0; type && at < 6; at++, type = type.ofType)
    if (typeof type.name === 'string') return type.name;
  return null;
}

function gqlUrl(origin, endpoint, query) {
  const url = new URL(endpoint, origin);
  url.searchParams.set('query', query);
  return url.href;
}

function pairCandidates(inventory) {
  const queries = (inventory?.operations ?? []).filter(item => item.kind === 'query' &&
    safeName(item.name) && safeName(item.returns));
  const lists = queries.filter(item => item.returnsList && item.args.length === 0);
  const items = queries.filter(item => !item.returnsList && item.args.length === 1 &&
    /^(?:id|[A-Za-z_][A-Za-z0-9_]*(?:Id|_id))$/.test(item.args[0].name) &&
    ['ID', 'String'].includes(item.args[0].type));
  return lists.flatMap(list => items.filter(item => item.endpoint === list.endpoint &&
    item.returns === list.returns).map(item => ({list, item})));
}

function modelPages(pairs, inventory) {
  const notes = new Map((inventory?.notes ?? []).map(note =>
    [`${note.endpoint} ${note.kind} ${note.name}`, note.purpose]));
  const rows = pairs.map(({list, item}) => ({endpoint: item.endpoint,
    list: list.name, item: item.name, type: item.returns,
    listPurpose: String(notes.get(`${list.endpoint} query ${list.name}`) ?? '').slice(0, 240),
    itemPurpose: String(notes.get(`${item.endpoint} query ${item.name}`) ?? '').slice(0, 240)}));
  const pages = [];
  for (let at = 0; at < rows.length; at += MODEL_PAGE_ITEMS)
    pages.push(rows.slice(at, at + MODEL_PAGE_ITEMS));
  return pages;
}

async function rankPairs(pairs, inventory, scope, {infer, model, maxModelPages, log}) {
  const candidates = pairs.slice(0, MAX_CANDIDATES).map((pair, index) =>
    ({...pair, index, priority: 5, by: 'baseline', why: null}));
  const pages = modelPages(candidates, inventory);
  const modelCoverage = {pagesAvailable: pages.length, pagesSent: 0,
    candidatesAvailable: pairs.length, candidatesSent: 0};
  let modelCalls = 0, modelError = null;
  if (infer && model) for (let at = 0; at < Math.min(pages.length, Math.max(0, maxModelPages)); at++) {
    const context = {origin: scope.target.origin, page: at + 1, pages: pages.length,
      candidates: pages[at]};
    if (Buffer.byteLength(JSON.stringify(context)) > MODEL_MAX_BYTES) {
      modelError = `GraphQL planning page ${at + 1} exceeded ${MODEL_MAX_BYTES} bytes.`;
      break;
    }
    const known = new Map(candidates.slice(at * MODEL_PAGE_ITEMS, (at + 1) * MODEL_PAGE_ITEMS)
      .map(pair => [`${pair.item.endpoint} ${pair.list.name} ${pair.item.name}`, pair]));
    try {
      modelCalls++;
      const answer = await infer(model, [{role: 'system', content: 'Rank only these observed GraphQL read-only list/item query pairs for a bounded object-authorization check. Use operation semantics and supplied purpose notes. Return priorities for exact supplied pairs only. Do not invent a field, argument, request, ID, payload, or finding. Code will obtain IDs from real account lists and require independent HTTP proof.'},
        {role: 'user', content: JSON.stringify(context)}], {schema: {type: 'object', properties: {
          priorities: {type: 'array', maxItems: MODEL_PAGE_ITEMS, items: {type: 'object', properties: {
            endpoint: {type: 'string'}, list: {type: 'string'}, item: {type: 'string'},
            priority: {type: 'integer'}, why: {type: 'string', maxLength: 300}},
          required: ['endpoint', 'list', 'item', 'priority', 'why'], additionalProperties: false}}},
        required: ['priorities'], additionalProperties: false}});
      for (const reply of Array.isArray(answer?.priorities) ? answer.priorities : []) {
        const pair = known.get(`${reply.endpoint} ${reply.list} ${reply.item}`);
        if (!pair || !Number.isInteger(reply.priority)) continue;
        pair.priority = Math.max(0, Math.min(10, reply.priority));
        pair.by = 'model';
        pair.why = maskSecrets(String(reply.why ?? '')).replace(/[\x00-\x1f\x7f]/g, ' ').slice(0, 300);
      }
      modelCoverage.pagesSent++;
      modelCoverage.candidatesSent += pages[at].length;
    } catch (error) {modelError = error.message; break;}
  }
  if (infer && model) log({stage: 'graphql-plan', message: `Muse ranked ${modelCoverage.candidatesSent} of ${pairs.length} observed GraphQL query pairs`});
  return {ordered: candidates.sort((a, b) => b.priority - a.priority || a.index - b.index),
    modelCoverage, modelCalls, modelError};
}

/** Plan only an owner-listed object with an explicit owner field and a distinct same-role outsider. */
export async function planGraphqlBola(scope, {inventory, surface, requester, budget = 8,
  infer = null, model = null, maxModelPages = 8, log = () => {}} = {}) {
  const tasks = [], typeAttempts = [], listAttempts = [];
  const owner = safePrincipal(principal(surface?.identity?.principals?.owner));
  const outsider = safePrincipal(principal(surface?.identity?.principals?.outsider));
  const allPairs = pairCandidates(inventory);
  const emptyCoverage = {pagesAvailable: Math.ceil(Math.min(allPairs.length, MAX_CANDIDATES) / MODEL_PAGE_ITEMS),
    pagesSent: 0, candidatesAvailable: allPairs.length, candidatesSent: 0};
  if (!surface?.identity?.verified || owner == null || outsider == null ||
      owner === outsider || budget <= 0) return {tasks, typeAttempts, listAttempts,
        candidates: allPairs.length, cut: Math.max(0, allPairs.length - Math.max(0, budget)),
        selected: [], modelCoverage: emptyCoverage, modelCalls: 0, modelError: null};
  const ranking = await rankPairs(allPairs, inventory, scope, {infer, model, maxModelPages, log});
  const pairs = ranking.ordered.slice(0, MAX_PAIRS);
  const typeCache = new Map();
  for (const {list, item} of pairs) {
    if (tasks.length >= Math.min(8, budget)) break;
    const typeKey = `${list.endpoint} ${list.returns}`;
    if (!typeCache.has(typeKey)) {
      if (typeCache.size >= MAX_TYPES) break;
      const query = `query BypassObjectType { __type(name:${JSON.stringify(list.returns)}) { name fields { name type { kind name ofType { kind name ofType { kind name } } } } } }`;
      const url = gqlUrl(scope.target.origin, list.endpoint, query);
      const identity = inventory.attempts?.find(attempt => attempt.path === list.endpoint &&
        attempt.result === 'schema')?.identity ?? 'anonymous';
      const allowed = validateUrl(scope, url, {identity});
      const response = allowed.ok ? await requester({url, identity, method: 'GET', step: 'recon',
        purpose: 'task', maxBytes: MAX_BODY, noCache: true}) : null;
      const fields = response ? typeFieldNames(response, list.returns) : [];
      typeAttempts.push({endpoint: list.endpoint, type: list.returns, identity,
        status: response?.status ?? null, evidenceId: response?.evidenceId ?? null,
        fields, reason: responseSizeLimited(response) ? 'response-size-cut' :
          allowed.ok ? null : allowed.reason});
      typeCache.set(typeKey, fields);
    }
    const fields = typeCache.get(typeKey);
    const ownerField = OWNER_FIELDS.find(field => fields.includes(field));
    if (!fields.includes('id') || !ownerField) continue;
    const selection = `id ${ownerField}`;
    const listUrl = gqlUrl(scope.target.origin, list.endpoint,
      `query BypassOwnerList { ${list.name} { ${selection} } }`);
    const allowed = ['owner', 'outsider', 'anonymous'].map(identity => validateUrl(scope, listUrl, {identity}));
    if (allowed.some(item => !item.ok)) {
      listAttempts.push({endpoint: list.endpoint, list: list.name, item: item.name,
        reason: allowed.find(check => !check.ok).reason});
      continue;
    }
    const send = identity => requester({url: listUrl, identity, method: 'GET',
      step: 'control', purpose: 'task', maxBytes: MAX_BODY, noCache: true});
    const ownerList = await send('owner');
    const outsiderList = await send('outsider');
    const anonymousList = await send('anonymous');
    const ownerRows = listRows(ownerList, list.name);
    const outsiderRows = listRows(outsiderList, list.name);
    const anonymousRows = listRows(anonymousList, list.name);
    const record = ownerRows?.find(row => ID.test(String(row.id ?? '')) &&
      String(row[ownerField]) === owner &&
      !outsiderRows?.some(other => String(other.id) === String(row.id)) &&
      !anonymousRows?.some(other => String(other.id) === String(row.id)));
    const mirror = outsiderRows?.find(row => ID.test(String(row.id ?? '')) &&
      String(row[ownerField]) === outsider &&
      !ownerRows?.some(other => String(other.id) === String(row.id)));
    listAttempts.push({endpoint: list.endpoint, list: list.name, item: item.name,
      ownerStatus: ownerList.status ?? null, outsiderStatus: outsiderList.status ?? null,
      anonymousStatus: anonymousList.status ?? null,
      evidence: unique([ownerList.evidenceId, outsiderList.evidenceId, anonymousList.evidenceId]),
      ...([ownerList, outsiderList, anonymousList].some(responseSizeLimited) ?
        {reason: 'response-size-cut'} : {}),
      ownerRecord: !!record, mirrorRecord: !!mirror});
    if (!record) continue;
    const itemQuery = id => `query BypassObjectCheck { ${item.name}(${item.args[0].name}:${JSON.stringify(String(id))}) { ${selection} } }`;
    const itemUrl = gqlUrl(scope.target.origin, item.endpoint, itemQuery(record.id));
    if (['owner', 'outsider', 'anonymous'].some(identity =>
      !validateUrl(scope, itemUrl, {identity}).ok)) continue;
    const mirrorUrl = mirror ? gqlUrl(scope.target.origin, item.endpoint, itemQuery(mirror.id)) : null;
    tasks.push({id: `t-gql-${tasks.length + 1}`, kind: 'graphql-bola', pattern: item.endpoint,
      control: {url: itemUrl, as: 'owner'}, request: {url: itemUrl, as: 'outsider', method: 'GET'},
      supportEvidence: unique([ownerList.evidenceId, outsiderList.evidenceId, anonymousList.evidenceId]),
      graphql: {listField: list.name, itemField: item.name, ownerField,
        recordId: String(record.id), ownerPrincipal: owner, outsiderPrincipal: outsider,
        listUrl, mirrorUrl, mirrorId: mirror ? String(mirror.id) : null}});
  }
  const cut = Math.max(0, allPairs.length - Math.min(MAX_PAIRS, Math.max(0, budget)));
  log({stage: 'graphql', message: `${tasks.length} GraphQL object-authorization tasks planned from ${allPairs.length} observed query pairs`});
  return {tasks, typeAttempts, listAttempts, candidates: allPairs.length, cut,
    selected: pairs.map(({list, item, priority, by, why}) =>
      ({endpoint: item.endpoint, list: list.name, item: item.name, priority, by, why})),
    modelCoverage: ranking.modelCoverage, modelCalls: ranking.modelCalls,
    modelError: ranking.modelError};
}
