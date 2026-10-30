import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import http from 'node:http';
import path from 'node:path';
import {randomBytes} from 'node:crypto';
import {spawn} from 'node:child_process';
import {execFile} from '../src/util.mjs';
import {CLI} from '../src/demo.mjs';
import {temp} from './helpers.mjs';
import {DEFAULT_SCOPE} from '../src/blackbox/scope.mjs';
import {inspectGraphql} from '../src/blackbox/graphql.mjs';
import {planGraphqlBola} from '../src/blackbox/graphql-bola.mjs';
import {runAudit} from '../src/blackbox/index.mjs';
import {verifyRun} from '../src/blackbox/poc.mjs';

const schema = (suffix = 'A') => ({data: {__schema: {
  queryType: {name: 'Query', fields: [
    {name: `viewer${suffix}`, args: [{name: 'id', type: {kind: 'NON_NULL', ofType: {name: 'ID'}}}],
      type: {name: 'Viewer'}},
    {name: `search${suffix}`, args: [{name: 'term', type: {name: 'String'}}], type: {name: 'SearchResult'}},
  ]},
  mutationType: {name: 'Mutation', fields: [
    {name: `deleteViewer${suffix}`, args: [{name: 'id', type: {name: 'ID'}}]},
  ]},
}}});

test('GraphQL inventory uses only read-only GET introspection and rejects invented model notes', async () => {
  const scope = structuredClone(DEFAULT_SCOPE);
  scope.include = ['/api'];
  const suffix = randomBytes(3).toString('hex');
  const endpoint = `/api/v${suffix}/graphql`;
  const calls = [];
  const result = await inspectGraphql(scope, {observed: [{path: endpoint}, {path: '/admin/graphql'},
    {path: 'https://outside.example/graphql'}], requester: async request => {
    calls.push(request);
    return {status: 200, type: 'application/json', body: JSON.stringify(schema(suffix)), evidenceId: 'e-1'};
  }, model: {model: 'fixture'}, infer: async (_model, messages) => {
    const context = JSON.parse(messages[1].content);
    assert.equal(context.operations.length, 3);
    return {notes: [
      {endpoint, kind: 'query', name: `viewer${suffix}`, purpose: 'Read viewer profile',
        arguments: [{name: 'id', meaning: 'viewer identifier'}, {name: 'injected', meaning: 'invented'}]},
      {endpoint, kind: 'query', name: 'inventedField', purpose: 'fabricated', arguments: []},
    ]};
  }});
  assert.equal(calls.length, 1);
  assert.equal(calls[0].method, 'GET');
  assert.equal(calls[0].identity, 'anonymous');
  assert.equal(new URL(calls[0].url).pathname, endpoint);
  assert.match(new URL(calls[0].url).searchParams.get('query'), /^query BypassSchemaInventory/);
  assert.equal(result.attempts[0].result, 'schema');
  assert.deepEqual(result.operations.map(item => `${item.kind}:${item.name}`),
    [`query:viewer${suffix}`, `query:search${suffix}`, `mutation:deleteViewer${suffix}`]);
  assert.deepEqual(result.notes.map(item => item.name), [`viewer${suffix}`]);
  assert.deepEqual(result.notes[0].arguments.map(item => item.name), ['id']);
  assert.equal(result.coverage.operationsAvailable, 3);
  assert.equal(result.coverage.operationsSent, 3);
});

test('GraphQL inventory accepts a schema response larger than the old 64 KiB cap', async () => {
  const scope = structuredClone(DEFAULT_SCOPE);
  const body = JSON.stringify({...schema(), padding: 'x'.repeat(80 * 1024)});
  let captureLimit;
  const result = await inspectGraphql(scope, {observed: ['/graphql'],
    requester: async request => {
      captureLimit = request.maxBytes;
      return captureLimit >= Buffer.byteLength(body) ?
        {status: 200, type: 'application/json', body, evidenceId: 'e-large-schema'} :
        {blocked: true, reason: 'Request failed: Response exceeds size limit'};
    }});
  assert.ok(captureLimit >= Buffer.byteLength(body));
  assert.equal(result.attempts[0].result, 'schema');
  assert.equal(result.operations.length, 3);
});

test('a denied anonymous schema is retried only with an explicitly enabled owner identity', async () => {
  const scope = structuredClone(DEFAULT_SCOPE);
  scope.include = ['/api'];
  const calls = [];
  const result = await inspectGraphql(scope, {observed: ['/api/graphql'], allowOwner: true,
    requester: async request => {
      calls.push(request);
      return request.identity === 'owner' ? {status: 200, type: 'application/json',
        body: JSON.stringify(schema()), evidenceId: 'e-owner'} :
        {status: 401, type: 'application/json', body: '{}', evidenceId: 'e-anonymous'};
    }});
  assert.deepEqual(calls.map(item => item.identity), ['anonymous', 'owner']);
  assert.deepEqual(result.attempts.map(item => item.result), ['unavailable', 'schema']);
  assert.equal(result.operations.length, 3);
  assert.equal(result.coverage.requests, 2);
  assert.equal(result.coverage.pathsTried, 1);
});

test('GraphQL inventory reports allowed endpoints omitted by its path cap', async () => {
  const scope = structuredClone(DEFAULT_SCOPE);
  scope.include = ['/api'];
  const paths = Array.from({length: 5}, (_, index) => `/api/v${index}/graphql`);
  const calls = [];
  const result = await inspectGraphql(scope, {observed: paths, requester: async request => {
    calls.push(new URL(request.url).pathname);
    return {status: 404, evidenceId: `e-${calls.length}`};
  }});
  assert.equal(result.coverage.pathsAvailable, 5);
  assert.equal(result.coverage.pathsTried, 4);
  assert.equal(result.coverage.pathsCut, 1);
  assert.deepEqual(calls, paths.slice(0, 4));
});

test('Muse can rank the last of 128 observed GraphQL pairs within a one-task budget', async () => {
  const scope = structuredClone(DEFAULT_SCOPE);
  scope.include = ['/api'];
  const endpoint = '/api/graphql';
  const operations = Array.from({length: 128}, (_, index) => [
    {endpoint, kind: 'query', name: `records${index}`, args: [],
      returns: `Record${index}`, returnsList: true},
    {endpoint, kind: 'query', name: `record${index}`, args: [{name: 'id', type: 'ID'}],
      returns: `Record${index}`, returnsList: false},
  ]).flat();
  const inventory = {operations, attempts: [{path: endpoint, result: 'schema', identity: 'anonymous'}],
    notes: [{endpoint, kind: 'query', name: 'record127', purpose: 'Owner document by ID'}]};
  const surface = {identity: {verified: true, principals: {owner: {value: 'user-a'},
    outsider: {value: 'user-b'}}}};
  const calls = [];
  const requester = async request => {
    const query = new URL(request.url).searchParams.get('query');
    calls.push({query, identity: request.identity});
    if (query.includes('__type')) {
      const type = /__type\(name:"(Record\d+)"\)/.exec(query)?.[1];
      return {status: 200, type: 'application/json', evidenceId: 'e-type',
        body: JSON.stringify({data: {__type: {name: type, fields: [
          {name: 'id', type: {name: 'ID'}}, {name: 'ownerId', type: {name: 'ID'}},
        ]}}})};
    }
    const list = /\{ (records\d+) \{/.exec(query)?.[1];
    const id = request.identity === 'owner' ? 'record-a' : 'record-b';
    const ownerId = request.identity === 'owner' ? 'user-a' : 'user-b';
    return request.identity === 'anonymous' ? {status: 401, evidenceId: 'e-anon'} :
      {status: 200, type: 'application/json', evidenceId: `e-${request.identity}`,
        body: JSON.stringify({data: {[list]: [{id, ownerId}]}})};
  };
  const contexts = [];
  const infer = async (_model, messages) => {
    const context = JSON.parse(messages[1].content);
    contexts.push(context);
    return {priorities: context.page === 8 ? [
      {endpoint, list: 'records127', item: 'record127', priority: 10, why: 'Observed owner object lookup'},
      {endpoint, list: 'invented', item: 'invented', priority: 10, why: 'not observed'},
    ] : []};
  };
  const baseline = await planGraphqlBola(scope,
    {inventory, surface, requester, budget: 1});
  assert.equal(baseline.tasks[0].graphql.itemField, 'record0');
  const modeled = await planGraphqlBola(scope,
    {inventory, surface, requester, budget: 1, infer, model: {model: 'fixture'}});
  assert.equal(modeled.tasks[0].graphql.itemField, 'record127');
  assert.equal(modeled.selected[0].by, 'model');
  assert.equal(modeled.modelCoverage.candidatesSent, 128);
  assert.equal(modeled.modelCoverage.pagesSent, 8);
  assert.deepEqual(contexts.map(item => item.candidates.length), Array(8).fill(16));
  assert.ok(contexts[7].candidates.some(item => item.item === 'record127' &&
    item.itemPurpose === 'Owner document by ID'));
  assert.ok(!JSON.stringify(contexts).includes('user-a'));
  assert.ok(calls.every(item => !item.query.startsWith('mutation')));
  const cut = await planGraphqlBola(scope,
    {inventory, surface, requester, budget: 1, infer, model: {model: 'fixture'}, maxModelPages: 1});
  assert.equal(cut.modelCoverage.candidatesSent, 16);
  assert.equal(cut.modelCoverage.candidatesAvailable, 128);
  assert.equal(cut.tasks[0].graphql.itemField, 'record0');
});

test('actual blackbox CLI inventories a randomized GraphQL route without executing mutations', async t => {
  const root = temp();
  t.after(() => fs.rmSync(root, {recursive: true, force: true}));
  const suffix = randomBytes(4).toString('hex');
  const endpoint = `/api/v${suffix}/graphql`;
  const requests = [];
  const server = http.createServer((request, response) => {
    const url = new URL(request.url, 'http://127.0.0.1');
    requests.push({method: request.method, path: url.pathname, query: url.searchParams.get('query')});
    if (url.pathname === '/') {
      response.writeHead(200, {'content-type': 'text/html'});
      return response.end('<script src="/client.js"></script>');
    }
    if (url.pathname === '/client.js') {
      response.writeHead(200, {'content-type': 'application/javascript'});
      return response.end(`fetch('${endpoint}?query=%7Bviewer${suffix}%7Bid%7D%7D');`);
    }
    if (url.pathname === endpoint && url.searchParams.get('query')?.startsWith('query BypassSchemaInventory')) {
      response.writeHead(200, {'content-type': 'application/json'});
      return response.end(JSON.stringify(schema(suffix)));
    }
    response.writeHead(404);
    response.end();
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  t.after(() => new Promise(resolve => server.close(resolve)));
  const origin = `http://127.0.0.1:${server.address().port}`;
  const configured = await execFile(process.execPath, [CLI, 'blackbox', 'scope', origin, '--include', '/api',
    '--project', root, '--json', '--non-interactive'], {cwd: root, timeout: 90000});
  assert.equal(configured.code, 0, configured.stderr);
  const completed = await execFile(process.execPath, [CLI, 'blackbox', origin, '--accept-local', '--no-model',
    '--project', root, '--json', '--non-interactive'], {cwd: root, timeout: 90000});
  const run = JSON.parse(completed.stdout);
  assert.equal(run.kind, 'blackbox-audit');
  const inventory = JSON.parse(fs.readFileSync(path.join(run.runDir, 'graphql.json'), 'utf8'));
  const report = JSON.parse(fs.readFileSync(path.join(run.runDir, 'report.json'), 'utf8'));
  assert.ok(inventory.attempts.some(item => item.path === endpoint && item.result === 'schema'),
    JSON.stringify(inventory.attempts));
  assert.deepEqual(inventory.operations.filter(item => item.endpoint === endpoint)
    .map(item => `${item.kind}:${item.name}`),
  [`query:viewer${suffix}`, `query:search${suffix}`, `mutation:deleteViewer${suffix}`]);
  assert.equal(report.surface.application.graphql.operations.length, 3);
  assert.ok(requests.some(item => item.path === endpoint && item.query?.startsWith('query BypassSchemaInventory')));
  assert.ok(requests.every(item => item.method === 'GET' || item.method === 'HEAD'));
  assert.ok(requests.every(item => !item.query || !/^\s*mutation\b/.test(item.query)));
  assert.deepEqual(run.findings, []);
});

test('actual blackbox CLI inventories an owner-only GraphQL schema after anonymous denial', async t => {
  const root = temp();
  t.after(() => fs.rmSync(root, {recursive: true, force: true}));
  const suffix = randomBytes(4).toString('hex');
  const endpoint = `/api/private-${suffix}/graphql`;
  const calls = [];
  const server = http.createServer((request, response) => {
    const url = new URL(request.url, 'http://127.0.0.1');
    calls.push({method: request.method, path: url.pathname,
      query: url.searchParams.get('query'), authorization: request.headers.authorization ?? null});
    if (url.pathname === '/') {
      response.writeHead(200, {'content-type': 'text/html'});
      return response.end('<script src="/client.js"></script>');
    }
    if (url.pathname === '/client.js') {
      response.writeHead(200, {'content-type': 'application/javascript'});
      return response.end(`fetch('${endpoint}?query=%7Bviewer${suffix}%7Bid%7D%7D');`);
    }
    if (url.pathname === '/api/me') {
      const owner = request.headers.authorization === 'Bearer owner-token';
      response.writeHead(owner ? 200 : 401, {'content-type': 'application/json'});
      return response.end(JSON.stringify(owner ? {id: 'owner-1', role: 'member'} : {error: 'Sign in'}));
    }
    if (url.pathname === endpoint) {
      const owner = request.headers.authorization === 'Bearer owner-token';
      response.writeHead(owner ? 200 : 401, {'content-type': 'application/json'});
      return response.end(JSON.stringify(owner && url.searchParams.get('query')?.startsWith('query BypassSchemaInventory') ?
        schema(suffix) : {errors: [{message: 'Denied'}]}));
    }
    response.writeHead(404);
    response.end();
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  t.after(() => new Promise(resolve => server.close(resolve)));
  const origin = `http://127.0.0.1:${server.address().port}`;
  const configured = await execFile(process.execPath, [CLI, 'blackbox', 'scope', origin, '--include', '/api',
    '--identity-path', '/api/me', '--project', root, '--json', '--non-interactive'],
  {cwd: root, timeout: 90000});
  assert.equal(configured.code, 0, configured.stderr);
  const completed = await execFile(process.execPath, [CLI, 'blackbox', origin, '--accept-local', '--no-model',
    '--project', root, '--json', '--non-interactive'],
  {cwd: root, env: {...process.env, OWNER_TOKEN: 'owner-token'}, timeout: 90000});
  const run = JSON.parse(completed.stdout);
  assert.equal(run.kind, 'blackbox-audit');
  const inventory = JSON.parse(fs.readFileSync(path.join(run.runDir, 'graphql.json'), 'utf8'));
  assert.deepEqual(inventory.attempts.filter(item => item.path === endpoint)
    .map(item => [item.identity, item.status, item.result]),
  [['anonymous', 401, 'unavailable'], ['owner', 200, 'schema']]);
  assert.ok(inventory.operations.some(item => item.name === `viewer${suffix}`));
  assert.ok(calls.some(item => item.path === endpoint && item.query?.startsWith('query BypassSchemaInventory') &&
    item.authorization === 'Bearer owner-token'));
  assert.ok(calls.every(item => item.method === 'GET' || item.method === 'HEAD'));
  assert.deepEqual(run.findings, []);
});

test('actual CLI proves and replays a GraphQL cross-account object read', async t => {
  const root = temp();
  t.after(() => fs.rmSync(root, {recursive: true, force: true}));
  const suffix = randomBytes(4).toString('hex');
  const endpoint = `/api/v${suffix}/graphql`;
  const people = [`member-${suffix}-a`, `member-${suffix}-b`];
  const records = people.map((ownerId, index) => ({id: `record-${suffix}-${index + 1}`, ownerId}));
  const env = {...process.env, OWNER_TOKEN: `owner-${suffix}`, OTHER_TOKEN: `other-${suffix}`};
  const calls = [];
  let vulnerable = true;
  const reply = (response, status, body) => {
    response.writeHead(status, {'content-type': 'application/json', 'cache-control': 'no-store'});
    response.end(JSON.stringify(body));
  };
  const schemaBody = {data: {__schema: {queryType: {name: 'Query', fields: [
    {name: 'records', args: [], type: {kind: 'NON_NULL', ofType: {kind: 'LIST',
      ofType: {kind: 'NON_NULL', ofType: {kind: 'OBJECT', name: 'Record'}}}}},
    {name: 'record', args: [{name: 'id', type: {kind: 'NON_NULL', ofType: {kind: 'SCALAR', name: 'ID'}}}],
      type: {kind: 'OBJECT', name: 'Record'}},
  ]}, mutationType: {name: 'Mutation', fields: [{name: 'deleteRecord', args: []}]}}}};
  const server = http.createServer((request, response) => {
    const url = new URL(request.url, 'http://127.0.0.1');
    const query = url.searchParams.get('query');
    calls.push({method: request.method, path: url.pathname, query});
    const who = request.headers.authorization === `Bearer ${env.OWNER_TOKEN}` ? people[0] :
      request.headers.authorization === `Bearer ${env.OTHER_TOKEN}` ? people[1] : null;
    if (url.pathname === '/') {
      response.writeHead(200, {'content-type': 'text/html'});
      return response.end('<script src="/client.js"></script>');
    }
    if (url.pathname === '/client.js') {
      response.writeHead(200, {'content-type': 'application/javascript'});
      return response.end(`fetch('${endpoint}?query=%7Brecords%7Bid%20ownerId%7D%7D');`);
    }
    if (url.pathname === '/api/me') return reply(response, who ? 200 : 401,
      who ? {id: who, role: 'member'} : {error: 'Sign in'});
    if (url.pathname === endpoint && query?.startsWith('query BypassSchemaInventory'))
      return reply(response, 200, schemaBody);
    if (url.pathname === endpoint && query?.startsWith('query BypassObjectType'))
      return reply(response, 200, {data: {__type: {name: 'Record', fields: [
        {name: 'id', type: {kind: 'NON_NULL', ofType: {kind: 'SCALAR', name: 'ID'}}},
        {name: 'ownerId', type: {kind: 'SCALAR', name: 'ID'}},
      ]}}});
    if (url.pathname === endpoint && query?.startsWith('query BypassOwnerList'))
      return who ? reply(response, 200, {data: {records: records.filter(item => item.ownerId === who)}}) :
        reply(response, 401, {errors: [{extensions: {code: 'UNAUTHENTICATED'}}]});
    if (url.pathname === endpoint && query?.startsWith('query BypassObjectCheck')) {
      const id = /record\(id:"([A-Za-z0-9_.-]+)"\)/.exec(query)?.[1];
      const record = records.find(item => item.id === id);
      if (!who) return reply(response, 401, {errors: [{extensions: {code: 'UNAUTHENTICATED'}}]});
      if (record && (record.ownerId === who || vulnerable))
        return reply(response, 200, {data: {record}});
      return reply(response, 200, {data: {record: null}, errors: [{extensions: {code: 'FORBIDDEN'}}]});
    }
    if (url.pathname === '/api/delete') return reply(response, 500, {error: 'Protected decoy'});
    return reply(response, 404, {error: 'Not found'});
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  t.after(() => new Promise(resolve => server.close(resolve)));
  const origin = `http://127.0.0.1:${server.address().port}`;
  const command = async (...args) => {
    const completed = await execFile(process.execPath,
      [CLI, 'blackbox', ...args, '--project', root, '--json', '--non-interactive'],
      {cwd: root, env, timeout: 90000});
    return {code: completed.code, data: JSON.parse(completed.stdout), stderr: completed.stderr};
  };
  assert.equal((await command('scope', origin, '--include', '/api',
    '--identity-path', '/api/me')).code, 0);
  const audit = () => command(origin, '--accept-local', '--no-model');
  const first = await audit();
  assert.equal(first.code, 1, JSON.stringify(first.data));
  const finding = first.data.findings.find(item => item.kind === 'graphql-bola' && item.pattern === endpoint);
  assert.ok(finding, JSON.stringify(first.data.findings));
  assert.ok(fs.existsSync(finding.proof));
  const report = JSON.parse(fs.readFileSync(path.join(first.data.runDir, 'report.json'), 'utf8'));
  assert.equal(report.surface.application.graphql.bola.planned, 1);
  assert.equal(report.coverage.requestedClasses.find(item => item.name === 'Broken Object Level Authorization (BOLA)')?.status,
    'partial');
  assert.equal((await command('verify', first.data.run)).code, 1);
  const exported = await command('export', first.data.run, '--out', path.join(root, 'regressions'));
  assert.equal(exported.code, 0);
  const childEnv = Object.fromEntries(Object.entries(env).filter(([key]) => key !== 'NODE_TEST_CONTEXT'));
  const runExport = () => new Promise((resolve, reject) => {
    const child = spawn(process.execPath, ['--test', ...exported.data.files],
      {cwd: root, env: childEnv, stdio: 'ignore'});
    child.on('error', reject);
    child.on('close', resolve);
  });
  assert.equal(await runExport(), 1);
  vulnerable = false;
  assert.equal((await command('verify', first.data.run)).code, 0);
  assert.equal(await runExport(), 0);
  const fixed = await audit();
  assert.deepEqual(fixed.data.findings, []);
  assert.ok(calls.every(item => item.method === 'GET' || item.method === 'HEAD'));
  assert.ok(calls.every(item => !item.query || !/^\s*mutation\b/.test(item.query)));
  assert.ok(!calls.some(item => item.path === '/api/delete'));
});

test('model-enabled audit promotes and proves a late GraphQL object pair', async t => {
  const root = temp();
  t.after(() => fs.rmSync(root, {recursive: true, force: true}));
  const suffix = randomBytes(4).toString('hex');
  const endpoint = `/api/v${suffix}/graphql`;
  const people = [`user-${suffix}-a`, `user-${suffix}-b`];
  const records = people.map((ownerId, index) => ({id: `record-${suffix}-${index + 1}`, ownerId}));
  const operations = Array.from({length: 20}, (_, index) => [
    {name: `records${index}`, args: [], type: {kind: 'LIST',
      ofType: {kind: 'OBJECT', name: `Record${index}`}}},
    {name: `record${index}`, args: [{name: 'id', type: {kind: 'NON_NULL',
      ofType: {kind: 'SCALAR', name: 'ID'}}}], type: {kind: 'OBJECT', name: `Record${index}`}},
  ]).flat();
  let vulnerable = true;
  const calls = [];
  const answer = (response, status, body) => {
    response.writeHead(status, {'content-type': 'application/json', 'cache-control': 'no-store'});
    response.end(JSON.stringify(body));
  };
  const server = http.createServer((request, response) => {
    const url = new URL(request.url, 'http://127.0.0.1');
    const query = url.searchParams.get('query') ?? '';
    calls.push({path: url.pathname, method: request.method, query});
    const who = request.headers.authorization === 'Bearer owner-token' ? people[0] :
      request.headers.authorization === 'Bearer outsider-token' ? people[1] : null;
    if (url.pathname === '/openapi.json') return answer(response, 200,
      {openapi: '3.0.0', paths: {'/api/me': {get: {}}, [endpoint]: {get: {}}}});
    if (url.pathname === '/api/me') return answer(response, who ? 200 : 401,
      who ? {id: who, role: 'member'} : {error: 'Sign in'});
    if (url.pathname !== endpoint) return answer(response, 404, {error: 'Not found'});
    if (query.startsWith('query BypassSchemaInventory')) return answer(response, 200,
      {data: {__schema: {queryType: {name: 'Query', fields: operations}, mutationType: null}}});
    if (query.startsWith('query BypassObjectType')) {
      const type = /__type\(name:"(Record\d+)"\)/.exec(query)?.[1];
      return answer(response, 200, {data: {__type: {name: type, fields: [
        {name: 'id', type: {name: 'ID'}}, {name: 'ownerId', type: {name: 'ID'}},
      ]}}});
    }
    if (query.startsWith('query BypassOwnerList')) {
      const list = /\{ (records\d+) \{/.exec(query)?.[1];
      if (!who) return answer(response, 401, {errors: [{extensions: {code: 'UNAUTHENTICATED'}}]});
      return answer(response, 200, {data: {[list]: list === 'records19' ?
        records.filter(item => item.ownerId === who) : []}});
    }
    if (query.startsWith('query BypassObjectCheck')) {
      const id = /record19\(id:"([A-Za-z0-9_.-]+)"\)/.exec(query)?.[1];
      const record = records.find(item => item.id === id);
      if (!who) return answer(response, 401, {errors: [{extensions: {code: 'UNAUTHENTICATED'}}]});
      return answer(response, 200, record && (record.ownerId === who || vulnerable) ?
        {data: {record19: record}} :
        {data: {record19: null}, errors: [{extensions: {code: 'FORBIDDEN'}}]});
    }
    return answer(response, 400, {errors: [{message: 'Unknown query'}]});
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  t.after(() => new Promise(resolve => server.close(resolve)));
  const origin = `http://127.0.0.1:${server.address().port}`;
  fs.writeFileSync(path.join(root, 'blackbox.scope.json'), JSON.stringify({target: {origin},
    include: ['/api'], identities: {identityPath: '/api/me'}}));
  const env = {OWNER_TOKEN: 'owner-token', OTHER_TOKEN: 'outsider-token'};
  const options = {url: origin, root, env, overrides: {acceptLocal: true}};
  const baseline = await runAudit({...options, noModel: true});
  assert.ok(!baseline.findings.some(item => item.kind === 'graphql-bola'));
  const prompts = [];
  const infer = async (_profile, messages) => {
    const system = messages[0].content;
    prompts.push(system);
    if (system.includes('mapping an authorized web API')) return {paths: [], notes: []};
    if (system.includes('Propose bounded GET access-control')) return {tasks: []};
    if (system.includes('Interpret only the observed GraphQL root operation signatures')) return {notes: []};
    if (system.includes('Rank only these observed GraphQL read-only list/item query pairs')) {
      const context = JSON.parse(messages[1].content);
      const late = context.candidates.find(item => item.item === 'record19');
      return {priorities: late ? [{endpoint, list: 'records19', item: 'record19',
        priority: 10, why: 'Owner document by ID'}] : []};
    }
    if (system.includes('Rank only the supplied observed read-only web-test candidates')) return {priorities: []};
    if (system.includes('Assess only these independently proved')) return {notes: []};
    throw Error(`Unexpected model prompt: ${system}`);
  };
  const modeled = await runAudit({...options, infer});
  const finding = modeled.findings.find(item => item.kind === 'graphql-bola' && item.pattern === endpoint);
  assert.ok(finding, JSON.stringify({findings: modeled.findings, limitations: modeled.limitations}));
  assert.ok(fs.existsSync(finding.proof));
  const inventory = JSON.parse(fs.readFileSync(path.join(modeled.runDir, 'graphql.json'), 'utf8'));
  assert.equal(inventory.bola.selected[0].item, 'record19');
  assert.equal(inventory.bola.selected[0].by, 'model');
  assert.equal(inventory.bola.modelCoverage.candidatesSent, 20);
  assert.ok(prompts.some(item => item.includes('Rank only these observed GraphQL')));
  assert.equal((await verifyRun(root, modeled.run, {env})).exitCode, 1);
  vulnerable = false;
  assert.equal((await verifyRun(root, modeled.run, {env})).exitCode, 0);
  assert.ok(calls.every(item => item.method === 'GET' || item.method === 'HEAD'));
  assert.ok(calls.every(item => !item.query || !/^\s*mutation\b/.test(item.query)));
});
