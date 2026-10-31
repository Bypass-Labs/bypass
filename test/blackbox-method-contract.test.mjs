import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import http from 'node:http';
import os from 'node:os';
import path from 'node:path';
import {authorization, scopeReady} from '../src/network.mjs';
import {anonymousSurface, deriveLocalPostScope} from '../src/blackbox/anonymous.mjs';
import {createLedger} from '../src/blackbox/ledger.mjs';
import {createRequester, loadScope, validateScopeTemplate,
  validateUrl} from '../src/blackbox/scope.mjs';

test('observed method contracts execute authorized PATCH, PUT, DELETE and OPTIONS requests', async t => {
  const hits = [];
  const server = http.createServer(async (request, response) => {
    const chunks = [];
    for await (const chunk of request) chunks.push(chunk);
    hits.push({method: request.method, url: request.url,
      type: request.headers['content-type'] ?? null,
      body: Buffer.concat(chunks).toString()});
    response.setHeader('content-type', 'application/json');
    response.setHeader('cache-control', 'no-store');
    response.statusCode = request.url === '/api/flaky' ? 503 : 200;
    response.end('{"ok":true}');
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  t.after(() => new Promise(resolve => server.close(resolve)));
  const origin = `http://127.0.0.1:${server.address().port}`;
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'bypass-method-contract-'));
  t.after(() => fs.rmSync(dir, {recursive: true, force: true}));
  const file = path.join(dir, 'scope.json');
  fs.writeFileSync(file, JSON.stringify({schemaVersion: 1, target: {origin},
    include: ['/api'], methods: ['GET', 'HEAD', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS']}));
  const scope = loadScope({file, origin}).scope;
  const mined = {endpoints: [
    {method: 'PATCH', path: '/api/patch', bodyEncoding: 'json',
      contentType: 'application/merge-patch+json', bodyFields: ['value']},
    {method: 'PUT', path: '/api/put', bodyEncoding: 'form', bodyFields: ['value']},
    {method: 'DELETE', path: '/api/delete?id=fixture',
      params: [{name: 'id', in: 'query', example: 'fixture'}]},
    {method: 'OPTIONS', path: '/api/options?probe=fixture',
      params: [{name: 'probe', in: 'query', example: 'fixture'}]},
    {method: 'PATCH', path: '/api/flaky', bodyEncoding: 'json',
      bodyFields: ['value']},
    {method: 'DELETE', path: '/api/unreviewed?id=fixture',
      params: [{name: 'id', in: 'query', example: 'fixture'}]}]};
  const noDocument = async () => ({status: 404, body: ''});
  const derived = await deriveLocalPostScope(scope, mined, noDocument);
  assert.deepEqual(derived.methodAdmitted.map(item =>
    [item.method, item.path, item.placement]).sort(), [
    ['DELETE', '/api/delete', 'query'],
    ['DELETE', '/api/unreviewed', 'query'],
    ['OPTIONS', '/api/options', 'query'],
    ['PATCH', '/api/flaky', 'json'],
    ['PATCH', '/api/patch', 'json'],
    ['PUT', '/api/put', 'form']]);
  const surface = await anonymousSurface(derived.scope, noDocument, mined);
  assert.equal(surface.methodOperations.length, 6);
  assert.equal(surface.methodOperations.find(item => item.path === '/api/patch')?.contentType,
    'application/merge-patch+json');
  const ledger = createLedger(dir);
  t.after(() => ledger.close());
  const request = createRequester(derived.scope, {ledger, allowLocal: true});
  const patch = await request({url: '/api/patch', method: 'PATCH', purpose: 'json-body',
    step: 'task', noCache: true, omitExcerpt: true,
    headers: {'content-type': 'application/merge-patch+json'},
    body: JSON.stringify({value: 'audit-marker'})});
  assert.equal(patch.status, 200);
  const put = await request({url: '/api/put', method: 'PUT', purpose: 'form-body',
    step: 'task', noCache: true, omitExcerpt: true,
    headers: {'content-type': 'application/x-www-form-urlencoded'},
    body: 'value=audit-marker'});
  assert.equal(put.status, 200);
  const deletion = await request({url: '/api/delete?id=nonexistent-audit-marker',
    method: 'DELETE', purpose: 'reviewed-method', step: 'task', noCache: true,
    omitExcerpt: true});
  assert.equal(deletion.status, 200);
  const options = await request({url: '/api/options?probe=audit-marker',
    method: 'OPTIONS', purpose: 'reviewed-method', step: 'task', noCache: true,
    omitExcerpt: true});
  assert.equal(options.status, 200);
  const flaky = await request({url: '/api/flaky', method: 'PATCH', purpose: 'json-body',
    step: 'task', noCache: true, omitExcerpt: true,
    headers: {'content-type': 'application/json'}, body: '{"value":"audit-marker"}'});
  assert.equal(flaky.status, 503);
  assert.equal(hits.filter(item => item.url === '/api/flaky').length, 1,
    'a write must not retry after a server error');
  assert.equal(validateUrl(derived.scope, '/api/unreviewed?id=audit-marker',
    {method: 'DELETE', purpose: 'reviewed-method'}).ok, true);
  assert.equal(validateUrl(derived.scope, '/api/other?probe=audit-marker',
    {method: 'OPTIONS', purpose: 'reviewed-method'}).ok, true);
  assert.equal(hits.length, 5);
});

test('POST and PATCH use their selected methods on the same in-scope route', async t => {
  const hits = [];
  const server = http.createServer(async (request, response) => {
    const chunks = [];
    for await (const chunk of request) chunks.push(chunk);
    hits.push({method: request.method, body: Buffer.concat(chunks).toString()});
    response.writeHead(200, {'content-type': 'application/json'});
    response.end('{"ok":true}');
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  t.after(() => new Promise(resolve => server.close(resolve)));
  const origin = `http://127.0.0.1:${server.address().port}`;
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'bypass-method-overlap-'));
  t.after(() => fs.rmSync(dir, {recursive: true, force: true}));
  const file = path.join(dir, 'scope.json');
  fs.writeFileSync(file, JSON.stringify({schemaVersion: 1, target: {origin},
    include: ['/api']}));
  const scope = loadScope({file, origin}).scope;
  const mined = {endpoints: [
    {method: 'POST', path: '/api/reviews', bodyEncoding: 'json',
      bodyFields: ['id']},
    {method: 'PATCH', path: '/api/reviews', bodyEncoding: 'json',
      bodyFields: ['id', 'message']}]};
  const derived = await deriveLocalPostScope(scope, mined,
    async () => ({status: 404, body: ''}));
  assert.deepEqual(derived.admitted.find(item => item.path === '/api/reviews')?.fields,
    ['id']);
  assert.deepEqual(derived.methodAdmitted.find(item =>
    item.path === '/api/reviews' && item.method === 'PATCH')?.fields,
    ['id', 'message']);
  const ledger = createLedger(dir);
  t.after(() => ledger.close());
  const request = createRequester(derived.scope, {ledger, allowLocal: true});
  const base = {url: '/api/reviews', purpose: 'json-body', step: 'task', noCache: true,
    omitExcerpt: true, headers: {'content-type': 'application/json'}};
  const patch = await request({...base, method: 'PATCH',
    body: JSON.stringify({id: '1', message: 'audit-marker'})});
  assert.equal(patch.status, 200);
  assert.deepEqual(hits.map(item => item.method), ['PATCH']);
  const revisedPatch = await request({...base, method: 'PATCH',
    body: JSON.stringify({id: '1', unexpected: 'audit-marker'})});
  assert.equal(revisedPatch.status, 200);
  const post = await request({...base, method: 'POST',
    body: JSON.stringify({id: '1', message: 'audit-marker'})});
  assert.equal(post.status, 200);
  assert.deepEqual(hits.map(item => item.method), ['PATCH', 'PATCH', 'POST']);
});

test('deployed method authorization covers selected methods and paths without write tuples', async t => {
  const origin = 'https://app.example.test';
  const expiresAt = new Date(Date.now() + 86400000).toISOString();
  const target = {url: origin, environment: 'staging',
    ownership: {status: 'verified', method: 'dns', expiresAt}};
  target.authorization = authorization(target, {paths: ['/api'],
    methods: ['GET', 'HEAD', 'POST', 'PATCH', 'DELETE'],
    maxRequestsPerSecond: 2, expiresAt});
  assert.equal(scopeReady(target, '/api/item', 'PATCH'), true);
  assert.equal(scopeReady(target, '/api/other', 'DELETE'), true);
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'bypass-deployed-method-'));
  t.after(() => fs.rmSync(dir, {recursive: true, force: true}));
  const file = path.join(dir, 'scope.json');
  fs.writeFileSync(file, JSON.stringify({schemaVersion: 1, target: {origin},
    include: ['/api'], limits: {rps: 2}}));
  const prepared = loadScope({file, origin, targets: [target]}).scope;
  assert.equal(validateUrl(prepared, '/api/item',
    {method: 'PATCH', purpose: 'json-body'}).ok, true);
  assert.equal(validateUrl(prepared, '/api/other',
    {method: 'DELETE', purpose: 'json-body'}).ok, true);
  assert.equal(validateUrl(prepared, '/outside',
    {method: 'DELETE', purpose: 'reviewed-method'}).ok, false);
  assert.throws(() => scopeReady(target, '/api/item', 'PUT'), /outside the authorized scope/);
  assert.throws(() => validateScopeTemplate({probes: {writeOperations: [
    {method: 'OPTIONS', path: '/api/item', placement: 'json'}]}}),
    /probes.writeOperations/);
});
