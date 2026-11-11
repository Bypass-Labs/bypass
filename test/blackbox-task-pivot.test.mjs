import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import http from 'node:http';
import os from 'node:os';
import path from 'node:path';
import {runAudit} from '../src/blackbox/index.mjs';

const blank = schema => schema?.type === 'object' ? Object.fromEntries(
  (schema.required ?? []).map(key => [key, blank(schema.properties?.[key])])) :
  schema?.type === 'array' ? [] : schema?.type === 'integer' ||
  schema?.type === 'number' ? 0 : schema?.type === 'boolean' ? false :
  schema?.enum?.[0] ?? '';

test('a proved task finding gives Muse one separate related check after the primary queue', async t => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'bypass-task-pivot-'));
  t.after(() => fs.rmSync(root, {recursive: true, force: true}));
  const server = http.createServer((request, response) => {
    const url = new URL(request.url, 'http://local');
    const who = request.headers.authorization === 'Bearer owner-token' ? 'u-1' :
      request.headers.authorization === 'Bearer other-token' ? 'u-2' : null;
    let status = 404, body = {error: 'Not found'};
    if (url.pathname === '/') {status = 200; body = '<html>Fixture</html>';}
    if (url.pathname === '/openapi.json') {status = 200; body = {openapi: '3.0.0', paths: {
      '/api/me': {get: {}}, '/api/items': {get: {}},
      '/api/items/{id}': {get: {}}, '/api/items/status': {get: {}}}};}
    if (url.pathname === '/api/me') {status = who ? 200 : 401;
      body = who ? {id: who, role: 'member'} : {error: 'Sign in'};}
    if (url.pathname === '/api/items') {status = who ? 200 : 401;
      body = who ? [{id: who === 'u-1' ? 'item-1' : 'item-2', ownerId: who}] :
        {error: 'Sign in'};}
    if (url.pathname === '/api/items/item-1' || url.pathname === '/api/items/item-2') {
      status = who ? 200 : 401;
      body = who ? {id: url.pathname.split('/').at(-1), ownerId:
        url.pathname.endsWith('item-1') ? 'u-1' : 'u-2'} : {error: 'Sign in'};
    }
    if (url.pathname === '/api/items/status') {status = 200; body = {service: 'ready'};}
    response.writeHead(status, {'content-type': typeof body === 'string' ?
      'text/html' : 'application/json', 'cache-control': 'no-store'});
    response.end(typeof body === 'string' ? body : JSON.stringify(body));
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  t.after(() => new Promise(resolve => server.close(resolve)));
  const origin = `http://127.0.0.1:${server.address().port}`;
  const scopeFile = path.join(root, 'blackbox.scope.json');
  fs.writeFileSync(scopeFile, JSON.stringify({schemaVersion: 1, target: {origin},
    include: ['/'], limits: {rps: 50, minutes: 10, modelCalls: 40}}));
  let pivots = 0;
  const infer = async (_profile, messages, {schema} = {}) => {
    const response = blank(schema);
    if (messages[0].content.startsWith('The primary scoped audit has completed')) {
      pivots++;
      const context = JSON.parse(messages[1].content);
      assert.match(context.confirmedFinding.path, /\/api\/items/);
      response.flows = [{family: 'related item state',
        why: 'Check observed sibling state', priority: 7, as: 'anonymous',
        oracle: 'raw-observation', rawRequests: [{method: 'GET', path: '/api/items/status'}]}];
    }
    return response;
  };
  const audit = await runAudit({url: origin, root, scopeFile, infer,
    noDiscovery: true, env: {OWNER_TOKEN: 'owner-token', OTHER_TOKEN: 'other-token'}});
  assert.ok(audit.findings.some(item => item.kind === 'idor'));
  assert.equal(pivots, 1);
  const web = JSON.parse(fs.readFileSync(path.join(audit.runDir, 'web-probes.json'), 'utf8'));
  assert.ok(web.results.some(item => item.discoveredVia === 'confirmed-task-pivot' &&
    item.lead?.path === '/api/items/status' && item.verdict === 'observed'));
});
