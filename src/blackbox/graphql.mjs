// Read-only GraphQL schema inventory. Only root signatures are retained; no resolver is executed.
import {maskSecrets} from './assets.mjs';
import {validateUrl} from './scope.mjs';
import {MODEL_RESPONSE_BYTES, responseSizeLimited} from './response-size.mjs';

const QUERY = 'query BypassSchemaInventory { __schema { queryType { name fields { name args { name type { kind name ofType { kind name ofType { kind name } } } } type { kind name ofType { kind name ofType { kind name ofType { kind name ofType { kind name } } } } } } } mutationType { name fields { name args { name type { kind name ofType { kind name ofType { kind name } } } } } } } }';
const NAME = /^[_A-Za-z][_A-Za-z0-9]{0,79}$/;
const MAX_BODY = MODEL_RESPONSE_BYTES;
const MAX_PATHS = 4;
const MAX_QUERY_FIELDS = 80;
const MAX_MUTATION_FIELDS = 40;
const MAX_ARGS = 16;
const MODEL_PAGE_ITEMS = 16;
const MODEL_MAX_BYTES = 16000;

function safeName(value) {
  return typeof value === 'string' && NAME.test(value) && maskSecrets(value) === value ? value : null;
}

function safeNote(value, limit) {
  return maskSecrets(String(value ?? '')).replace(/[\x00-\x1f\x7f]/g, ' ').slice(0, limit);
}

function typeName(type) {
  for (let depth = 0; type && depth < 6; depth++, type = type.ofType) {
    const name = safeName(type.name);
    if (name) return name;
  }
  return null;
}

function listType(type) {
  for (let depth = 0; type && depth < 6; depth++, type = type.ofType)
    if (type.kind === 'LIST') return true;
  return false;
}

function rootFields(root, kind, limit, endpoint, evidenceId) {
  if (!Array.isArray(root?.fields)) return {operations: [], cut: 0};
  const operations = [];
  let total = 0;
  for (const field of root.fields) {
    const name = safeName(field?.name);
    if (!name || name.startsWith('__')) continue;
    total++;
    if (operations.length >= limit) continue;
    const args = [];
    for (const arg of Array.isArray(field.args) ? field.args.slice(0, MAX_ARGS) : []) {
      const argName = safeName(arg?.name);
      if (argName) args.push({name: argName, type: typeName(arg.type)});
    }
    operations.push({endpoint, kind, name, args, returns: typeName(field.type),
      returnsList: listType(field.type), evidenceId});
  }
  return {operations, cut: Math.max(0, total - operations.length)};
}

function candidatePaths(scope, observed = []) {
  const paths = new Set(['/graphql']);
  for (const raw of observed) {
    const path = typeof raw === 'string' ? raw : raw?.path ?? raw?.pattern;
    if (typeof path === 'string' && /^\/(?:[A-Za-z0-9_-]+\/){0,4}(?:graphql|gql)\/?$/i.test(path))
      paths.add(path);
  }
  const eligible = [...paths].filter(path => validateUrl(scope, path, {identity: 'anonymous'}).ok);
  return {paths: eligible.slice(0, MAX_PATHS), available: eligible.length};
}

function modelPages(operations) {
  const pages = [];
  for (let at = 0; at < operations.length; at += MODEL_PAGE_ITEMS) {
    const page = operations.slice(at, at + MODEL_PAGE_ITEMS);
    if (Buffer.byteLength(JSON.stringify({operations: page})) <= MODEL_MAX_BYTES) pages.push(page);
    else for (const operation of page) pages.push([operation]);
  }
  return pages;
}

/** One anonymous GET per candidate, optional owner retry after a denial, then bounded Muse interpretation. */
export async function inspectGraphql(scope, {requester, observed = [], infer = null, model = null,
  maxModelPages = 8, allowOwner = false, log = () => {}} = {}) {
  const {paths, available} = candidatePaths(scope, observed);
  const attempts = [], operations = [], notes = [];
  let fieldsCut = 0, modelCalls = 0, modelError = null, operationsSent = 0;
  for (const path of paths) {
    const url = new URL(path, scope.target.origin);
    url.searchParams.set('query', QUERY);
    const send = identity => requester({url: url.href, identity, method: 'GET',
      purpose: 'task', step: 'recon', maxBytes: MAX_BODY, noCache: true,
      headers: {accept: 'application/graphql-response+json, application/json;q=0.9'}});
    const anonymous = await send('anonymous');
    const responses = [{identity: 'anonymous', response: anonymous}];
    if (allowOwner && [401, 403].includes(anonymous.status) &&
        validateUrl(scope, path, {identity: 'owner'}).ok)
      responses.push({identity: 'owner', response: await send('owner')});
    for (const {identity, response} of responses) {
      const attempt = {path, identity, status: response.status ?? null,
        evidenceId: response.evidenceId ?? null, result: 'unavailable'};
      if (responseSizeLimited(response)) attempt.result = 'response-size-cut';
      if (response.status === 405) attempt.result = 'get-not-supported';
      if (response.status === 200 && /json/i.test(response.type ?? '') &&
          typeof response.body === 'string' && Buffer.byteLength(response.body) <= MAX_BODY) {
        let schema;
        try {schema = JSON.parse(response.body)?.data?.__schema;} catch { /* invalid JSON is not a schema */ }
        if (Array.isArray(schema?.queryType?.fields)) {
          const query = rootFields(schema.queryType, 'query', MAX_QUERY_FIELDS, path, response.evidenceId);
          const mutation = rootFields(schema.mutationType, 'mutation', MAX_MUTATION_FIELDS, path, response.evidenceId);
          operations.push(...query.operations, ...mutation.operations);
          fieldsCut += query.cut + mutation.cut;
          attempt.result = 'schema';
          attempt.queryFields = query.operations.length;
          attempt.mutationFields = mutation.operations.length;
        }
      }
      attempts.push(attempt);
    }
  }
  const pages = modelPages(operations);
  if (infer && model) for (let at = 0; at < Math.min(pages.length, Math.max(0, maxModelPages)); at++) {
    const context = {page: at + 1, pages: pages.length, operations: pages[at]};
    if (Buffer.byteLength(JSON.stringify(context)) > MODEL_MAX_BYTES) {
      modelError = `GraphQL interpretation page ${at + 1} exceeded ${MODEL_MAX_BYTES} bytes.`;
      break;
    }
    try {
      modelCalls++;
      const answer = await infer(model, [{role: 'system', content: 'Interpret only the observed GraphQL root operation signatures. Explain query or mutation purpose and argument meaning as unverified hypotheses. Do not invent operations, arguments, values, findings, or requests. Mutation signatures are inventory only; no mutation will be executed. Return JSON only.'},
        {role: 'user', content: JSON.stringify(context)}], {schema: {type: 'object', properties: {
          notes: {type: 'array', maxItems: MODEL_PAGE_ITEMS, items: {type: 'object', properties: {
            endpoint: {type: 'string'}, kind: {type: 'string'}, name: {type: 'string'},
            purpose: {type: 'string'}, arguments: {type: 'array', items: {type: 'object', properties: {
              name: {type: 'string'}, meaning: {type: 'string'}}, required: ['name', 'meaning'], additionalProperties: false}}},
          required: ['endpoint', 'kind', 'name', 'purpose', 'arguments'], additionalProperties: false}}},
        required: ['notes'], additionalProperties: false}});
      operationsSent += pages[at].length;
      const known = new Map(pages[at].map(item => [`${item.endpoint} ${item.kind} ${item.name}`, item]));
      for (const reply of Array.isArray(answer?.notes) ? answer.notes : []) {
        const operation = known.get(`${reply.endpoint} ${reply.kind} ${reply.name}`);
        if (!operation) continue;
        const allowed = new Set(operation.args.map(arg => arg.name));
        notes.push({endpoint: operation.endpoint, kind: operation.kind, name: operation.name,
          purpose: safeNote(reply.purpose, 300),
          arguments: (Array.isArray(reply.arguments) ? reply.arguments : [])
            .filter(arg => allowed.has(arg.name)).slice(0, MAX_ARGS)
            .map(arg => ({name: arg.name, meaning: safeNote(arg.meaning, 200)})),
          evidenceId: operation.evidenceId, by: 'model'});
      }
    } catch (error) {modelError = error.message; break;}
  }
  const coverage = {pathsAvailable: available, pathsTried: new Set(attempts.map(item => item.path)).size,
    pathsCut: Math.max(0, available - paths.length),
    requests: attempts.length,
    responseSizeCut: attempts.filter(item => item.result === 'response-size-cut').length,
    operationsAvailable: operations.length, operationsSent, pagesAvailable: pages.length,
    pagesSent: modelCalls, fieldsCut};
  log({stage: 'graphql', message: `${attempts.filter(item => item.result === 'schema').length} schemas, ${operations.length} root fields, ${fieldsCut} fields cut`});
  return {attempts, operations, notes, coverage, modelCalls, modelError};
}
