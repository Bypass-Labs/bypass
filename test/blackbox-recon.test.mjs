// Tests for src/blackbox/recon.mjs (design sections 5.5 and 6.1 to 6.10):
// pure helpers first, then the baseline recon pass against a loopback invoices fixture
// started inside this file.
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import http from 'node:http';
import path from 'node:path';
import {randomBytes} from 'node:crypto';
import { temp, port } from './helpers.mjs';
import { loadScope, createRequester, createLimiter } from '../src/blackbox/scope.mjs';
import { createLedger } from '../src/blackbox/ledger.mjs';
import { anonymousSurface } from '../src/blackbox/anonymous.mjs';
import {
  templatePath, idFormat, numericTail, sequentialityScore, neighbors, detectList, itemOf,
  harvestIds, principalOf, roleFields, parseOpenApi, WORDS, CHILDREN, recon
} from '../src/blackbox/recon.mjs';

const UUID = '3f2b6c1e-8a4d-4f2a-9b7c-1d2e3f4a5b6c';
const OBJECT_ID = '5f8d0d55b54764421b7156c3';

test('idFormat and numericTail classify identifier shapes', () => {
  assert.equal(idFormat(UUID), 'uuid');
  assert.equal(idFormat(OBJECT_ID), 'objectid');
  assert.equal(idFormat('42'), 'numeric');
  assert.equal(idFormat(42), 'numeric');
  assert.equal(idFormat('inv-101'), 'prefixed');
  assert.equal(idFormat('run_2024_17'), 'prefixed');
  assert.equal(idFormat('pro-plan'), 'slug');
  assert.equal(idFormat(''), 'none');
  assert.equal(idFormat('a b'), 'none');
  assert.equal(numericTail('inv-101'), 101);
  assert.equal(numericTail('run_2024_17'), 17);
  assert.equal(numericTail('42'), 42);
  assert.equal(numericTail(UUID), null);
  assert.equal(numericTail(OBJECT_ID), null);
  assert.equal(numericTail('pro-plan'), null);
});

test('templatePath turns uuid, objectid, numeric, prefixed and known ids into {id}', () => {
  assert.deepEqual(templatePath(`/api/users/${UUID}`), {pattern: '/api/users/{id}', slots: [{segmentIndex: 3, value: UUID, format: 'uuid'}]});
  assert.equal(templatePath(`/api/docs/${OBJECT_ID}`).pattern, '/api/docs/{id}');
  assert.equal(templatePath('/api/orders/17/items/3').pattern, '/api/orders/{id}/items/{id}');
  assert.equal(templatePath('/api/invoices/inv-101/pdf').pattern, '/api/invoices/{id}/pdf');
  assert.equal(templatePath('/api/teams/blue-team').pattern, '/api/teams/blue-team');
  assert.deepEqual(templatePath('/api/teams/blue-team', ['blue-team']).slots, [{segmentIndex: 3, value: 'blue-team', format: 'slug'}]);
  assert.equal(templatePath('/api/v1/me').pattern, '/api/v1/me');
  assert.deepEqual(templatePath('/api/me').slots, []);
});

test('sequentialityScore and neighbors follow design 6.7', () => {
  assert.equal(sequentialityScore(['inv-101', 'inv-102', 'inv-105']), 1);
  assert.equal(sequentialityScore(['inv-101', 'inv-102', 'inv-201']), 0.5);
  assert.equal(sequentialityScore(['inv-101', 'inv-301']), 0);
  assert.equal(sequentialityScore([UUID, '7d0f6a1e-8a4d-4f2a-9b7c-1d2e3f4a5b6c']), 0);
  assert.equal(sequentialityScore(['inv-101']), 0);
  assert.deepEqual(neighbors('inv-101', 3), ['inv-100', 'inv-102', 'inv-103']);
  assert.deepEqual(neighbors('7', 2), ['6', '8']);
  assert.deepEqual(neighbors('inv-007', 3), ['inv-006', 'inv-008', 'inv-009']);
  assert.deepEqual(neighbors('0', 3), ['1', '2']);
  assert.deepEqual(neighbors(UUID, 3), []);
  assert.deepEqual(neighbors(OBJECT_ID, 3), []);
  assert.deepEqual(neighbors('inv-101', 0), []);
});

test('detectList finds arrays at the root, under any wrapper and in paged shapes', () => {
  const rows = [{id: 'a'}, {id: 'b'}];
  assert.deepEqual(detectList(rows), {items: rows, wrapper: 'root'});
  assert.deepEqual(detectList({results: rows, total: 2}), {items: rows, wrapper: 'results'});
  assert.deepEqual(detectList({data: {records: rows}, page: 1}), {items: rows, wrapper: 'data.records'});
  assert.deepEqual(detectList({edges: [{node: {id: 'a'}}, {node: {id: 'b'}}]}), {items: [{id: 'a'}, {id: 'b'}], wrapper: 'edges[].node'});
  assert.deepEqual(detectList({items: [], total: 0}), {items: [], wrapper: 'items'});
  assert.equal(detectList({tags: ['x', 'y']}), null);
  assert.equal(detectList({id: 'a', lines: [{sku: 1}]}), null);
  assert.equal(detectList('text'), null);
});

test('itemOf unwraps one level, harvestIds keeps selectors and ownership fields', () => {
  assert.deepEqual(itemOf({id: 'r-1', title: 'x'}), {item: {id: 'r-1', title: 'x'}, wrapper: null});
  assert.deepEqual(itemOf({run: {id: 'r-1'}}), {item: {id: 'r-1'}, wrapper: 'run'});
  assert.equal(itemOf([{id: 1}]), null);
  assert.equal(itemOf({ok: true}), null);
  assert.deepEqual(harvestIds([{id: 'inv-101', ownerId: 'u-1', total: 1}, {_id: 7, owner_uid: 'u-2'}, {uuid: UUID, email: 'a@example.com'}, {title: 'no id'}, {id: '../etc'}]), [
    {id: 'inv-101', selector: 'id', ownership: {ownerId: 'u-1'}},
    {id: '7', selector: '_id', ownership: {owner_uid: 'u-2'}},
    {id: UUID, selector: 'uuid', ownership: {email: 'a@example.com'}}
  ]);
});

test('principalOf follows the field order and one-level unwrap of design 6.5', () => {
  assert.deepEqual(principalOf({id: 'u-1', email: 'a@example.com'}), {value: 'u-1', field: 'id'});
  assert.deepEqual(principalOf({user: {uid: 'abc'}}), {value: 'abc', field: 'user.uid'});
  assert.deepEqual(principalOf({owner_uid: 'fb-9'}), {value: 'fb-9', field: 'owner_uid'});
  assert.deepEqual(principalOf({data: {email: 'b@example.com'}}), {value: 'b@example.com', field: 'data.email'});
  assert.equal(principalOf({user: null}), null);
  assert.equal(principalOf([{id: 1}]), null);
  assert.deepEqual(roleFields({id: 'u-1', role: 'member', isAdmin: false, name: 'A'}), {role: 'member', isAdmin: false});
  assert.deepEqual(roleFields({user: {id: 'u-1', roles: ['member']}}), {roles: ['member']});
});

test('parseOpenApi prefixes servers, keeps path params and tags', () => {
  const doc = {openapi: '3.0.0', servers: [{url: '/api'}], paths: {
    '/invoices': {get: {tags: ['invoices'], parameters: [{name: 'status', in: 'query', schema: {enum: ['open', 'paid']}}]}, post: {}},
    '/invoices/{invoiceId}': {parameters: [{name: 'invoiceId', in: 'path', example: 'inv-101'}], get: {}},
    '/me': {get: {tags: ['me']}}
  }};
  const parsed = parseOpenApi(doc, 'http://127.0.0.1:9');
  assert.equal(parsed.prefix, '/api');
  assert.deepEqual(parsed.servers, ['/api']);
  assert.deepEqual(parsed.operations, [
    {path: '/api/invoices', method: 'GET', params: [{name: 'status', in: 'query', example: 'open'}], tag: 'invoices'},
    {path: '/api/invoices', method: 'POST', params: [], tag: null},
    {path: '/api/invoices/{invoiceId}', method: 'GET', params: [{name: 'invoiceId', in: 'path', example: 'inv-101'}], tag: null},
    {path: '/api/me', method: 'GET', params: [], tag: 'me'}
  ]);
  assert.equal(parseOpenApi({openapi: '3.1.0', servers: [{url: 'http://127.0.0.1:9/v2/'}], paths: {}}, 'http://127.0.0.1:9').prefix, '/v2');
  const offOrigin = parseOpenApi({openapi: '3.1.0', servers: [{url: 'https://api.example.com/v1'}], paths: {'/x': {get: {}}}}, 'http://127.0.0.1:9');
  assert.equal(offOrigin.prefix, '');
  assert.equal(offOrigin.operations[0].path, '/x');
  assert.equal(parseOpenApi({swagger: '2.0', basePath: '/v1', paths: {'/runs': {get: {}}}}, 'http://127.0.0.1:9').operations[0].path, '/v1/runs');
});

test('parseOpenApi keeps login field names and encoding without copying body examples', () => {
  const doc = {openapi: '3.0.0', paths: {'/api/auth/login': {post: {requestBody: {content: {
    'application/json': {schema: {properties: {email: {}, password: {}}},
      example: {email: 'private@example.test', password: 'secret-example'}},
  }}}}}};
  const parsed = parseOpenApi(doc, 'http://127.0.0.1:9');
  assert.deepEqual(parsed.operations, [{path: '/api/auth/login', method: 'POST', params: [], tag: null,
    bodyEncoding: 'json', contentType: 'application/json', bodyFields: ['email', 'password'], bodyStringFields: [],
    bodyRequiredFields: []}]);
  assert.ok(!JSON.stringify(parsed).includes('secret-example'));
  const typed = parseOpenApi({paths: {'/api/process': {post: {requestBody: {content: {
    'application/json': {schema: {required: ['expression', 'limit'],
      properties: {expression: {type: 'string'}, limit: {type: 'integer'}}}},
  }}}}}}, 'http://127.0.0.1:9');
  assert.deepEqual(typed.operations[0].bodyStringFields, ['expression']);
  assert.deepEqual(typed.operations[0].bodyRequiredFields, ['expression', 'limit']);
  assert.equal(parseOpenApi({paths: {'/api/process': {post: {
    summary: 'Evaluate an expression', requestBody: {content: {'application/json': {
      schema: {properties: {expression: {type: 'string'}}}}}}}}}},
  'http://127.0.0.1:9').operations[0].purpose, 'Evaluate an expression');
});

test('OpenAPI carries bounded nested JSON shape and public examples without secret values', () => {
  const media = {schema: {type: 'object', properties: {selector: {
    type: 'object', properties: {match: {type: 'string'},
      variant: {type: 'integer'}, token: {type: 'string'}}},
    metadata: {type: 'object', properties: {contact: {type: 'string'}}},
    sampleContact: {type: 'object', properties: {contact: {type: 'string'}}}}},
    examples: {public: {value: {selector: {match: 'public', variant: 0}}},
      sensitive: {value: {selector: {match: 'owner', token: 'secret-example'}}},
      personal: {value: {metadata: {contact: 'alice@company.com'}}},
      synthetic: {value: {sampleContact: {contact: 'owner@example.test'}}}}};
  const doc = {openapi: '3.0.0', paths: {'/filter': {post: {requestBody: {
    content: {'application/json': media}}}}}};
  const operation = parseOpenApi(doc, 'http://127.0.0.1:9').operations[0];
  assert.deepEqual(operation.fieldShapes.selector.properties,
    {match: {type: 'string'}, variant: {type: 'integer'}, token: {type: 'string'}});
  assert.deepEqual(operation.fieldValueExamples.selector,
    ['{"match":"public","variant":0}']);
  assert.equal(operation.fieldValueExamples.metadata, undefined);
  assert.deepEqual(operation.fieldValueExamples.sampleContact,
    ['{"contact":"owner@example.test"}']);
  assert.ok(!JSON.stringify(operation).includes('secret-example'));
  assert.ok(!JSON.stringify(operation).includes('alice@company.com'));
});

test('OpenAPI keeps only bounded 2xx JSON response field names and types for staged workflows', () => {
  const doc = {openapi: '3.0.0', paths: {'/api/begin': {post: {
    requestBody: {content: {'application/json': {schema: {type: 'object',
      properties: {kind: {type: 'string'}}}}}},
    responses: {'201': {$ref: '#/components/responses/Started'},
      '401': {content: {'application/json': {schema: {type: 'object',
        properties: {error: {type: 'string'}}}}}}}}}}, components: {
    responses: {Started: {content: {'application/json': {schema: {type: 'object',
      properties: {nonce: {type: 'string'}, data: {type: 'object',
        properties: {sequence: {type: 'integer'}}},
        'alice@company.com': {type: 'string'}}},
      example: {nonce: 'private-example-value'}}}}}}};
  const operation = parseOpenApi(doc, 'http://127.0.0.1:9').operations[0];
  assert.deepEqual(operation.responseJsonFields, [{status: 201, fields: [
    {pointer: '/nonce', type: 'string'},
    {pointer: '/data/sequence', type: 'integer'}]}]);
  assert.ok(!JSON.stringify(operation).includes('private-example-value'));
  assert.ok(!JSON.stringify(operation).includes('alice@company.com'));
});

test('parseOpenApi resolves bounded local request, schema and parameter refs', () => {
  const doc = {openapi: '3.1.0', paths: {
    '/api/process': {parameters: [{$ref: '#/components/parameters/Mode'}], post: {
      summary: 'Evaluate an expression', requestBody: {$ref: '#/components/requestBodies/Processor'}}},
    '/api/form': {post: {requestBody: {content: {'application/x-www-form-urlencoded': {
      schema: {$ref: '#/components/schemas/Form'}}}}}},
    '/api/xml': {post: {requestBody: {content: {'application/xml': {
      schema: {$ref: '#/components/schemas/Xml'}}}}}},
    '/api/broken': {post: {requestBody: {content: {'application/json': {
      schema: {$ref: '#/components/schemas/CycleA'}}}}}},
    '/api/external': {post: {requestBody: {content: {'application/json': {
      schema: {$ref: 'https://outside.example/schema.json'}}}}}}
  }, components: {
    parameters: {Mode: {name: 'mode', in: 'query', schema: {$ref: '#/components/schemas/Mode'}}},
    requestBodies: {Processor: {content: {'application/json': {
      schema: {$ref: '#/components/schemas/Input'}}}}},
    schemas: {
      Mode: {type: 'string', enum: ['dry-run', 'execute']},
      Input: {allOf: [{$ref: '#/components/schemas/Fields'}]},
      Fields: {type: 'object', required: ['expression'], properties: {
        expression: {$ref: '#/components/schemas/Expression'}, count: {type: 'integer'}}},
      Expression: {type: ['null', 'string']},
      Form: {type: 'object', required: ['message'], properties: {
        message: {type: 'string'}, retries: {type: 'integer'}}},
      Xml: {type: 'object', xml: {name: 'ImportRequest'}, required: ['source'],
        properties: {source: {type: 'string'}}},
      CycleA: {$ref: '#/components/schemas/CycleB'},
      CycleB: {$ref: '#/components/schemas/CycleA'}
    }
  }};
  const parsed = parseOpenApi(doc, 'http://127.0.0.1:9');
  const at = path => parsed.operations.find(item => item.path === path);
  assert.deepEqual(at('/api/process').params, [{name: 'mode', in: 'query', example: 'dry-run'}]);
  assert.deepEqual(at('/api/process').bodyFields, ['expression', 'count']);
  assert.deepEqual(at('/api/process').bodyStringFields, ['expression']);
  assert.deepEqual(at('/api/process').bodyRequiredFields, ['expression']);
  assert.equal(at('/api/process').purpose, 'Evaluate an expression');
  assert.deepEqual(at('/api/form').bodyStringFields, ['message']);
  assert.deepEqual(at('/api/form').bodyRequiredFields, ['message']);
  assert.deepEqual(at('/api/xml').bodyFields, ['source']);
  assert.equal(at('/api/xml').rootElement, 'ImportRequest');
  assert.deepEqual(at('/api/broken').bodyFields, []);
  assert.deepEqual(at('/api/external').bodyFields, []);
  assert.ok(parsed.schemaCuts >= 2);
});

test('referenced OpenAPI examples reach reviewed JSON and form operations without credentials', async t => {
  const jsonPath = `/api/json-${randomBytes(4).toString('hex')}`;
  const formPath = `/api/form-${randomBytes(4).toString('hex')}`;
  const doc = {openapi: '3.1.0', paths: {
    [jsonPath]: {post: {requestBody: {$ref: '#/components/requestBodies/Json'}}},
    [formPath]: {post: {requestBody: {content: {'application/x-www-form-urlencoded': {
      schema: {$ref: '#/components/schemas/Form'}, examples: {
        basic: {value: {message: 'hello', secretKey: 'sensitive-value'}}}}}}}}
  }, components: {
    requestBodies: {Json: {content: {'application/json': {
      schema: {$ref: '#/components/schemas/Json'}, example: {mode: 'preview'}}}}},
    schemas: {
      Json: {allOf: [{$ref: '#/components/schemas/JsonFields'}]},
      JsonFields: {required: ['expression'], properties: {
        expression: {$ref: '#/components/schemas/Expression'},
        mode: {type: 'string', example: 'password123'},
        apiToken: {type: 'string', example: 'sensitive-value'}}},
      Expression: {type: 'string', example: '7', enum: ['1+1', '8', '9'],
        examples: ['<script>alert(1)</script>']},
      Form: {required: ['message'], properties: {
        message: {type: 'string'}, secretKey: {type: 'string', example: 'sensitive-value'}}}
    }
  }};
  const parsed = parseOpenApi(doc, 'http://127.0.0.1:9');
  assert.deepEqual(parsed.operations.find(item => item.path === jsonPath).fieldExamples,
    {expression: ['7', '1+1', '8'], mode: ['preview']});
  assert.deepEqual(parsed.operations.find(item => item.path === formPath).fieldExamples,
    {message: ['hello']});
  assert.ok(!JSON.stringify(parsed).includes('sensitive-value'));
  assert.ok(!JSON.stringify(parsed).includes('password123'));
  const dir = temp();
  t.after(() => fs.rmSync(dir, {recursive: true, force: true}));
  const file = path.join(dir, 'scope.json');
  fs.writeFileSync(file, JSON.stringify({schemaVersion: 1,
    target: {origin: 'http://127.0.0.1:9'}, include: ['/'],
    probes: {jsonPostPaths: [jsonPath], formPostPaths: [formPath]}}));
  const {scope} = loadScope({file, origin: 'http://127.0.0.1:9'});
  const surface = await anonymousSurface(scope, async ({url}) =>
    url === '/openapi.json' ? {status: 200, body: JSON.stringify(doc)} :
      {status: 404, body: ''}, null);
  assert.deepEqual(surface.jsonBodyOperations.find(item => item.path === jsonPath).fieldExamples,
    {expression: ['7', '1+1', '8'], mode: ['preview']});
  assert.deepEqual(surface.formBodyOperations.find(item => item.path === formPath).fieldExamples,
    {message: ['hello']});
});

test('WORDS and CHILDREN carry the design 6.4 lists', () => {
  assert.equal(WORDS.length, 34);
  assert.ok(WORDS.includes('admin/users') && WORDS.includes('invoices') && WORDS.includes('me'));
  assert.deepEqual(CHILDREN, ['tasks', 'members', 'files', 'comments', 'settings', 'users', 'invoices', 'runs', 'notes', 'threads']);
});

// ---- Loopback fixture: a reduced copy of the invoices app of the contracts ("Fixture") -----------

const ENV = {OWNER_TOKEN: 'owner-token-1', OTHER_TOKEN: 'other-token-2'};
const USERS = {'owner-token-1': {id: 'u-1', email: 'alice@example.com', role: 'member'}, 'other-token-2': {id: 'u-2', email: 'bob@example.com', role: 'member'}};
const INVOICES = [
  {id: 'inv-101', ownerId: 'u-1', total: 120, email: 'alice@example.com'},
  {id: 'inv-102', ownerId: 'u-1', total: 80, email: 'alice@example.com'},
  {id: 'inv-201', ownerId: 'u-2', total: 45, email: 'bob@example.com'}
];
const PLANS = [{id: 'plan-1', name: 'Free'}, {id: 'plan-2', name: 'Pro'}];
const OPENAPI = {openapi: '3.0.0', servers: [{url: '/api'}], paths: {
  '/invoices': {get: {}, post: {}},
  '/invoices/{invoiceId}': {get: {parameters: [{name: 'invoiceId', in: 'path'}]}},
  '/plans': {get: {}},
  '/plans/{planId}': {get: {}}
}};
// What mining the fixture's bundle yields (the shape of MinedSummary from src/blackbox/assets.mjs).
const MINED = {files: [], hosts: [], secrets: [], libraries: [], sourceMaps: [], stats: {files: 1, bytes: 900}, endpoints: [
  {path: '/api/me', method: 'GET', params: [], files: ['/static/app.js']},
  {path: '/api/admin/users', method: 'GET', params: [], files: ['/static/app.js']},
  {path: '/api/invoices/{id}/pdf', method: 'GET', params: [], files: ['/static/app.js']},
  {path: '/api/invoices/{id}/delete', method: 'GET', params: [], files: ['/static/app.js']},
  {path: '/api/invoices', method: 'POST', params: ['total'], files: ['/static/app.js']}
]};
const CATCH_ALL = '<!doctype html><html><body><h1>Invoices</h1><a href="/login">Sign in</a></body></html>';

function route(user, pathname) {
  if (pathname === '/api/plans') return [200, PLANS];
  if (!user) return [401, {error: 'Sign in'}];
  if (pathname === '/api/me') return [200, user];
  if (pathname === '/api/invoices') return [200, INVOICES.filter(invoice => invoice.ownerId === user.id)];
  if (pathname === '/api/admin/users') return [403, {error: 'Admins only'}];
  const plan = /^\/api\/plans\/([^/]+)$/.exec(pathname);
  if (plan) return PLANS.some(entry => entry.id === plan[1]) ? [200, PLANS.find(entry => entry.id === plan[1])] : [404, {error: 'Not found'}];
  const [, id, pdf] = /^\/api\/invoices\/([^/]+)(\/pdf)?$/.exec(pathname);
  const invoice = INVOICES.find(entry => entry.id === id);
  if (!invoice) return [404, {error: 'Not found'}];
  if (invoice.ownerId !== user.id) return [403, {error: 'Not your invoice'}];
  return [200, pdf ? {id, pdf: 'JVBERi0x'} : invoice];
}

const API = /^\/api\/(me|invoices|admin\/users|plans)$|^\/api\/(plans|invoices)\/[^/]+$|^\/api\/invoices\/[^/]+\/pdf$/;

async function startFixture({openapi = true} = {}) {
  const requested = [];
  let deleteHits = 0;
  const server = http.createServer((req, res) => {
    const {pathname} = new URL(req.url, 'http://fixture');
    requested.push({pathname, authorization: req.headers.authorization ?? null});
    const reply = (status, type, body) => {
      res.writeHead(status, {'content-type': type, 'cache-control': 'no-store'});
      res.end(body);
    };
    if (/^\/api\/invoices\/[^/]+\/delete$/.test(pathname)) {
      deleteHits += 1;
      return reply(200, 'application/json', '{"deleted":true}');
    }
    if (pathname === '/') return reply(200, 'text/html', '<!doctype html><html><body><script src="/static/app.js"></script></body></html>');
    if (pathname === '/openapi.json' && openapi) return reply(200, 'application/json', JSON.stringify(OPENAPI));
    if (pathname === '/.env') return reply(200, 'text/plain', 'DB_PASSWORD=hunter2\nSECRET_KEY=abc\n');
    if (!API.test(pathname)) return reply(200, 'text/html', CATCH_ALL);
    const [status, body] = route(USERS[(req.headers.authorization ?? '').replace(/^Bearer /, '')], pathname);
    return reply(status, 'application/json', JSON.stringify(body));
  });
  const free = await port();
  await new Promise(resolve => server.listen(free, '127.0.0.1', resolve));
  return {
    origin: `http://127.0.0.1:${free}`,
    requested,
    deleteHits: () => deleteHits,
    close: () => new Promise(resolve => { server.closeAllConnections(); server.close(resolve); })
  };
}

function guarded(origin, dir, overrides = {}) {
  const {scope} = loadScope({origin, overrides: {acceptLocal: true, ...overrides}});
  const ledger = createLedger(dir, {run: 'bx-test', secrets: Object.values(ENV)});
  const requester = createRequester(scope, {ledger, limiter: createLimiter(1000), env: ENV, allowLocal: true, run: 'bx-test'});
  return {scope, ledger, requester};
}

async function setup(t, {openapi = true, overrides = {}} = {}) {
  const dir = temp();
  t.after(() => fs.rmSync(dir, {recursive: true, force: true}));
  const fixture = await startFixture({openapi});
  t.after(() => fixture.close());
  return {fixture, ...guarded(fixture.origin, dir, overrides)};
}

test('recon maps the fixture: identity, harvested IDs, private flags, labels, never paths and exposures', async t => {
  const {fixture, scope, ledger, requester} = await setup(t);
  const events = [];
  const surface = await recon(scope, {requester, env: ENV, mined: MINED, log: event => events.push(event)});
  const byPattern = Object.fromEntries(surface.patterns.map(record => [record.pattern, record]));

  assert.equal(surface.origin, fixture.origin);
  assert.equal(surface.identity.verified, true);
  assert.equal(surface.identity.path, '/api/me');
  assert.deepEqual(surface.identity.principals, {owner: 'u-1', outsider: 'u-2'});
  assert.deepEqual(surface.identity.aliases.owner, ['u-1', 'alice@example.com']);
  assert.deepEqual(surface.identity.roles, {owner: {role: 'member'}, outsider: {role: 'member'}});
  assert.equal(surface.identity.evidence.length, 3);
  assert.equal(byPattern['/api/me'].label.kind, 'identity');

  const invoice = byPattern['/api/invoices/{id}'];
  assert.ok(invoice, `patterns: ${Object.keys(byPattern).join(', ')}`);
  assert.deepEqual(invoice.ids.ownerIds, ['inv-101', 'inv-102']);
  assert.deepEqual(invoice.ids.outsiderIds, ['inv-201']);
  assert.equal(invoice.ids.format, 'prefixed');
  assert.equal(invoice.ids.selector, 'id');
  assert.equal(invoice.ids.sequential, 0.5);
  assert.deepEqual(invoice.private['inv-101'], {by: 'ownership-field', field: 'ownerId'});
  assert.ok(invoice.source.includes('openapi') && invoice.source.includes('harvest:/api/invoices'));
  assert.equal(invoice.label.kind, 'item');
  assert.deepEqual([invoice.fingerprint.owner.status, invoice.fingerprint.outsider.status, invoice.fingerprint.anonymous.status, invoice.fingerprint.notFound.status], [200, 403, 401, 404]);
  assert.equal(invoice.fingerprint.owner.ownership.ownerId.startsWith('sha256:') || /^[0-9a-f]{64}$/.test(invoice.fingerprint.owner.ownership.ownerId), true);
  assert.equal(byPattern['/api/invoices'].label.kind, 'list');
  assert.deepEqual(byPattern['/api/invoices'].ids.ownerIds, ['inv-101', 'inv-102']);
  assert.ok(byPattern['/api/invoices/{id}/pdf'].source.includes('asset:app.js'));
  assert.equal(byPattern['/api/invoices/{id}/pdf'].fingerprint.owner.status, 200);

  const admin = byPattern['/api/admin/users'];
  assert.equal(admin.label.kind, 'admin');
  assert.deepEqual([admin.fingerprint.owner.status, admin.fingerprint.anonymous.status], [403, 401]);

  const plan = byPattern['/api/plans/{id}'];
  assert.deepEqual(plan.ids.shared, ['plan-1', 'plan-2']);
  assert.deepEqual(plan.ids.ownerIds, []);
  assert.deepEqual(plan.private, {});
  assert.equal(plan.fingerprint.owner.hash, plan.fingerprint.outsider.hash);
  assert.equal(plan.fingerprint.anonymous.status, 401);
  assert.equal(byPattern['/api/plans'].label.kind, 'public');

  assert.deepEqual(surface.never, []);
  assert.ok(surface.outOfScope.some(entry => entry.reason === 'read-action-review' &&
    entry.url.endsWith('/delete')));
  assert.equal(fixture.deleteHits(), 0);
  assert.ok(surface.outOfScope.some(entry => entry.reason === 'method' && entry.method === 'POST' && entry.url === '/api/invoices'));

  assert.deepEqual(surface.exposures.map(({path, severity, signature}) => ({path, severity, signature})), [
    {path: '/.env', severity: 'critical', signature: 'KEY=value lines'},
    {path: '/openapi.json', severity: 'info', signature: 'OpenAPI document'}
  ]);
  assert.match(surface.exposures[0].evidenceId, /^ev-\d{4,}$/);
  assert.ok(fixture.requested.some(entry => entry.pathname === '/admin'), 'the catch-all answered /admin and was not counted');

  assert.equal(surface.mined, MINED);
  assert.ok(surface.stats.urls > 0 && surface.stats.urls <= scope.limits.maxUrls);
  assert.equal(surface.stats.patterns, surface.patterns.length);
  assert.ok(events.some(event => event.stage === 'recon' && /Identity endpoint \/api\/me/.test(event.message)));
  assert.ok(fixture.requested.filter(entry => entry.authorization).every(entry => !/^\/(\.env|openapi\.json)?$/.test(entry.pathname)), 'documents and exposures are anonymous');
  const artifacts = JSON.stringify(surface) + fs.readFileSync(ledger.file, 'utf8') + JSON.stringify(events);
  for (const token of Object.values(ENV)) assert.ok(!artifacts.includes(token), 'credential value leaked into an artifact');
});

test('a pinned identity path still gets owner and anonymous controls after the walk URL cap', async t => {
  const {fixture, scope, requester} = await setup(t, {openapi: false,
    overrides: {identityPath: '/api/me'}});
  const surface = await recon(scope, {requester, env: ENV,
    mined: {...MINED, endpoints: []}, limits: {...scope.limits, maxUrls: 1}});
  assert.equal(surface.identity.path, '/api/me');
  assert.equal(surface.identity.verified, true);
  assert.deepEqual(surface.identity.principals, {owner: 'u-1', outsider: 'u-2'});
  assert.equal(surface.stats.urls, 1);
  assert.equal(surface.stats.pinnedIdentityBudgetBypass, true);
  assert.equal(surface.stats.pinnedIdentityRequests, 3);
  assert.equal(surface.identity.evidence.length, 3);
  assert.deepEqual(fixture.requested.filter(item => item.pathname === '/api/me')
    .map(item => item.authorization).sort(), [`Bearer ${ENV.OWNER_TOKEN}`, `Bearer ${ENV.OTHER_TOKEN}`, null].sort());
  assert.ok(!surface.outOfScope.some(item => item.url === '/api/me' && item.reason === 'budget'));
});

test('recon falls back to the resource wordlist when nothing documents the API', async t => {
  const {fixture, scope, requester} = await setup(t, {openapi: false, overrides: {includes: ['/api']}});
  const surface = await recon(scope, {requester, env: ENV});
  const byPattern = Object.fromEntries(surface.patterns.map(record => [record.pattern, record]));
  assert.ok(byPattern['/api/invoices']?.source.includes('wordlist'), `patterns: ${Object.keys(byPattern).join(', ')}`);
  assert.deepEqual(byPattern['/api/invoices/{id}'].ids.ownerIds, ['inv-101', 'inv-102']);
  assert.equal(byPattern['/api/admin/users'].label.kind, 'admin');
  assert.equal(surface.identity.path, '/api/me');
  assert.ok(!byPattern['/api/orders'] && !byPattern['/api/users'], 'catch-all answers are not patterns');
  assert.ok(surface.patterns.every(record => record.pattern.startsWith('/api/')));
  assert.ok(fixture.requested.every(entry => entry.pathname.startsWith('/api') || !entry.authorization), 'credentials stay inside include');
  assert.deepEqual(surface.exposures.map(item => item.path), ['/.env'],
    'anonymous sensitive-path checks still run when the authenticated API include is /api');
});

test('recon refuses to start when a JWT credential expires inside the run budget', async () => {
  const claims = Buffer.from(JSON.stringify({sub: 'u-1', exp: Math.floor(Date.now() / 1000) + 60})).toString('base64url');
  const jwt = `eyJhbGciOiJIUzI1NiJ9.${claims}.c2lnbmF0dXJl`;
  const {scope} = loadScope({origin: 'http://127.0.0.1:9', overrides: {acceptLocal: true}});
  const requester = async () => assert.fail('no request may be sent');
  await assert.rejects(recon(scope, {requester, env: {OWNER_TOKEN: jwt, OTHER_TOKEN: 'opaque'}}), error => {
    assert.equal(error.code, 3);
    assert.deepEqual(error.details, {reason: 'credential_expiring', env: 'OWNER_TOKEN'});
    assert.ok(!error.message.includes(jwt) && error.message.includes('OWNER_TOKEN'));
    return true;
  });
});

test('Muse recon follows several guarded response rounds and requests exact query variants', async t => {
  const dir = temp();
  t.after(() => fs.rmSync(dir, {recursive: true, force: true}));
  const suffix = randomBytes(4).toString('hex');
  const start = `/api/start-${suffix}`;
  const requested = [];
  const server = http.createServer((request, response) => {
    const url = new URL(request.url, 'http://local');
    requested.push(`${url.pathname}${url.search}`);
    let status = 404, body = {error: 'missing'};
    if (url.pathname === '/') {status = 200; body = {service: 'stages'};}
    else if (url.pathname === '/openapi.json') {status = 200;
      body = {openapi: '3.0.0', paths: {[start]: {get: {}},
        [`/api/status-${suffix}`]: {get: {}}, [`/api/info-${suffix}`]: {get: {}}}};}
    else if (url.pathname === start) {status = 200; body = {slug: `stage1-${suffix}`};}
    else if ([`/api/status-${suffix}`, `/api/info-${suffix}`].includes(url.pathname)) {
      status = 200; body = {service: 'stages'};
    } else {
      const match = /^\/api\/stage(\d+)-([a-f0-9]+)$/.exec(url.pathname);
      if (match?.[2] === suffix && Number(match[1]) <= 6) {
        status = 200;
        const stage = Number(match[1]);
        body = stage === 6 ? {done: true} : stage === 3 ?
          {slug: `stage4-${suffix}`, variant: 'full'} : stage === 4 &&
          url.searchParams.get('mode') !== 'full' ? {error: 'mode required'} :
          {slug: `stage${stage + 1}-${suffix}`};
      }
    }
    response.writeHead(status, {'content-type': 'application/json', 'cache-control': 'no-store'});
    response.end(JSON.stringify(body));
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  t.after(() => new Promise(resolve => server.close(resolve)));
  const origin = `http://127.0.0.1:${server.address().port}`;
  const {scope, requester, ledger} = guarded(origin, dir);
  let feedbackCalls = 0;
  const infer = async (_model, messages) => {
    if (messages[0].content.includes('mapping an authorized web API'))
      return {paths: [], notes: []};
    assert.match(messages[0].content, /Continue mapping this authorized web API/);
    feedbackCalls++;
    const context = JSON.parse(messages[1].content);
    const slug = context.observations.flatMap(item => item.hints ?? [])
      .find(item => item.field === 'slug')?.value;
    return {paths: slug ? [`/api/${slug}${slug.startsWith('stage4-') ? '?mode=full' : ''}`,
      '/api/delete'] : []};
  };
  const surface = await recon(scope, {requester, infer, model: {model: 'fixture'},
    maxModelPages: 20});
  ledger.close();
  assert.ok(feedbackCalls >= 7, JSON.stringify(surface.modelCoverage));
  assert.equal(surface.modelCoverage.followupPathsSent,
    surface.modelCoverage.followupPathsAvailable);
  assert.ok(surface.modelFollowup.some(page => page.observations.some(item =>
    item.path === `/api/stage4-${suffix}?mode=full` && item.status === 200)));
  assert.ok(requested.includes(`/api/stage4-${suffix}?mode=full`));
  assert.ok(requested.includes(`/api/stage6-${suffix}`));
  assert.ok(!requested.includes('/api/delete'));
});
