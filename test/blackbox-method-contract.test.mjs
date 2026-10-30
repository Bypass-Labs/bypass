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

test('observed local method contracts execute exact bounded PATCH, PUT and reviewed DELETE requests', async t => {
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
    include: ['/api'], probes: {writeOperations: [
      {method: 'DELETE', path: '/api/delete', placement: 'query'},
      {method: 'OPTIONS', path: '/api/options', placement: 'query'}]}}));
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
    ['OPTIONS', '/api/options', 'query'],
    ['PATCH', '/api/flaky', 'json'],
    ['PATCH', '/api/patch', 'json'],
    ['PUT', '/api/put', 'form']]);
  assert.ok(derived.skipped.some(item => item.path === '/api/unreviewed' &&
    item.reason === 'delete-needs-exact-review'));
  const surface = await anonymousSurface(derived.scope, noDocument, mined);
  assert.equal(surface.methodOperations.length, 5);
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
  await assert.rejects(request({url: '/api/patch', method: 'PATCH', purpose: 'json-body',
    step: 'task', noCache: true, headers: {'content-type': 'application/json'},
    body: '{"value":"audit-marker"}'}), /reviewed|content|body/i);
  await assert.rejects(request({url: '/api/put', method: 'PUT', purpose: 'form-body',
    step: 'task', noCache: true,
    headers: {'content-type': 'application/x-www-form-urlencoded'},
    body: 'unobserved=audit-marker'}), /observed|reviewed/i);
  assert.equal(validateUrl(derived.scope, '/api/unreviewed?id=audit-marker',
    {method: 'DELETE', purpose: 'reviewed-method'}).ok, false);
  assert.equal(validateUrl(derived.scope, '/api/other?probe=audit-marker',
    {method: 'OPTIONS', purpose: 'reviewed-method'}).ok, false);
  assert.equal(hits.length, 5);
});

test('a POST contract on the same path does not override an observed PATCH contract', async t => {
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
  await assert.rejects(request({...base, method: 'PATCH',
    body: JSON.stringify({id: '1', unexpected: 'audit-marker'})}),
  /observed fields/);
  assert.deepEqual(hits.map(item => item.method), ['PATCH']);
  const refusedPost = await request({...base, method: 'POST',
    body: JSON.stringify({id: '1', message: 'audit-marker'})});
  assert.equal(refusedPost.refused, true);
  assert.equal(refusedPost.detail, 'unobserved-field');
  assert.deepEqual(hits.map(item => item.method), ['PATCH']);
});

test('deployed method authorization requires an exact reviewed tuple', async t => {
  const origin = 'https://app.example.test';
  const expiresAt = new Date(Date.now() + 86400000).toISOString();
  const target = {url: origin, environment: 'staging',
    ownership: {status: 'verified', method: 'dns', expiresAt}};
  target.authorization = authorization(target, {paths: ['/api'],
    methods: ['GET', 'HEAD', 'PUT'],
    writeOperations: [{method: 'PUT', path: '/api/item', placement: 'json'}],
    maxRequestsPerSecond: 2, expiresAt});
  assert.equal(scopeReady(target, '/api/item', 'PUT'), true);
  assert.equal(scopeReady(target, '/api/other', 'PUT'), true,
    'the main target authorization covers the /api prefix; blackbox checks the exact write tuple below');
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'bypass-deployed-method-'));
  t.after(() => fs.rmSync(dir, {recursive: true, force: true}));
  const file = path.join(dir, 'scope.json');
  fs.writeFileSync(file, JSON.stringify({schemaVersion: 1, target: {origin},
    include: ['/api'], limits: {rps: 2}, probes: {writeOperations: [
      {method: 'PUT', path: '/api/item', placement: 'json'}]}}));
  const prepared = loadScope({file, origin, targets: [target]}).scope;
  assert.equal(validateUrl(prepared, '/api/item',
    {method: 'PUT', purpose: 'json-body'}).ok, true);
  assert.equal(validateUrl(prepared, '/api/other',
    {method: 'PUT', purpose: 'json-body'}).ok, false);
  fs.writeFileSync(file, JSON.stringify({schemaVersion: 1, target: {origin},
    include: ['/api'], limits: {rps: 2}, probes: {writeOperations: [
      {method: 'PUT', path: '/api/other', placement: 'json'}]}}));
  assert.throws(() => loadScope({file, origin, targets: [target]}),
    /needs exact target authorization/);
  assert.throws(() => validateScopeTemplate({probes: {writeOperations: [
    {method: 'OPTIONS', path: '/api/item', placement: 'json'}]}}),
    /probes.writeOperations/);
});
