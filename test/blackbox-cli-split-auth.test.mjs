import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import http from 'node:http';
import path from 'node:path';
import {randomBytes} from 'node:crypto';
import {temp} from './helpers.mjs';
import {execFile} from '../src/util.mjs';
import {CLI} from '../src/demo.mjs';

test('CLI verifies identities through an exact cookie route while testing item reads with bearer tokens', async t => {
  const root = temp();
  t.after(() => fs.rmSync(root, {recursive: true, force: true}));
  const suffix = randomBytes(4).toString('hex');
  const recordId = `rec-${suffix}101`;
  const otherId = `rec-${suffix}202`;
  const records = [{id: recordId, ownerId: 'owner-1', email: 'owner@example.test'},
    {id: otherId, ownerId: 'other-2', email: 'other@example.test'}];
  let vulnerable = true;
  const requests = [];
  const server = http.createServer((request, response) => {
    const url = new URL(request.url, 'http://local');
    const cookie = request.headers.cookie;
    const bearer = request.headers.authorization;
    requests.push({path: url.pathname, cookie: !!cookie, bearer: !!bearer});
    let status = 404, body = {error: 'Not found'};
    if (url.pathname === '/openapi.json') {
      status = 200;
      body = {openapi: '3.0.0', paths: {'/api/me': {get: {}},
        '/api/items': {get: {}}, '/api/items/{id}': {get: {}}}};
    } else if (url.pathname === '/api/me') {
      const id = cookie === 'token=owner-token' ? 'owner-1' :
        cookie === 'token=other-token' ? 'other-2' : null;
      status = id ? 200 : 401;
      body = id ? {id, role: 'member'} : {error: 'Sign in'};
    } else if (url.pathname === '/api/items') {
      status = bearer ? 200 : 401;
      body = bearer === 'Bearer owner-token' ? [records[0]] :
        bearer === 'Bearer other-token' ? [records[1]] : {error: 'Sign in'};
    } else if (url.pathname.startsWith('/api/items/')) {
      const record = records.find(item => url.pathname === `/api/items/${item.id}`);
      const principal = bearer === 'Bearer owner-token' ? 'owner-1' :
        bearer === 'Bearer other-token' ? 'other-2' : null;
      status = !principal ? 401 : !record ? 404 :
        principal === record.ownerId || vulnerable ? 200 : 403;
      body = status === 200 ? record : {error: 'Forbidden'};
    }
    response.writeHead(status, {'content-type': 'application/json', 'cache-control': 'no-store'});
    response.end(JSON.stringify(body));
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  t.after(() => new Promise(resolve => server.close(resolve)));
  const origin = `http://127.0.0.1:${server.address().port}`;
  const env = {OWNER_TOKEN: 'owner-token', OTHER_TOKEN: 'other-token'};
  const run = async (...args) => {
    const result = await execFile(process.execPath, [CLI, ...args, '--project', root,
      '--json', '--non-interactive'], {cwd: root, env, timeout: 30000});
    return {code: result.code, data: JSON.parse(result.stdout)};
  };
  const setup = await run('blackbox', 'setup', origin, '--include', '/api',
    '--identity-path', '/api/me', '--identity-cookie-name', 'token');
  assert.equal(setup.code, 0, JSON.stringify(setup.data));
  const audit = await run('blackbox', origin, '--scope', setup.data.scopeFile, '--accept-local',
    '--no-model');
  const surface = JSON.parse(fs.readFileSync(path.join(audit.data.runDir, 'surface.json'), 'utf8'));
  const results = JSON.parse(fs.readFileSync(path.join(audit.data.runDir, 'results.json'), 'utf8'));
  assert.equal(audit.code, 1, JSON.stringify({identity: surface.identity,
    confirmed: results.filter(item => item.verdict === 'confirmed').map(item =>
      ({kind: item.task?.kind, path: item.task?.request?.url, reason: item.reason})),
    findings: audit.data.findings, limitations: audit.data.limitations}));
  assert.equal(surface.identity.verified, true);
  assert.ok(audit.data.findings.some(item => item.kind === 'idor' && item.proof));
  assert.ok(requests.some(item => item.path === '/api/me' && item.cookie && !item.bearer));
  assert.ok(requests.some(item => item.path === `/api/items/${recordId}` && item.bearer && !item.cookie));
  const replay = await run('blackbox', 'verify', audit.data.run);
  assert.equal(replay.code, 1, JSON.stringify(replay.data));
  vulnerable = false;
  const fixed = await run('blackbox', 'verify', audit.data.run);
  assert.equal(fixed.code, 0, JSON.stringify(fixed.data));
});
