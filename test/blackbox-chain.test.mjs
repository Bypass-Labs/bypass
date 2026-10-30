import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import http from 'node:http';
import path from 'node:path';
import {randomBytes} from 'node:crypto';
import {spawn} from 'node:child_process';
import {temp} from './helpers.mjs';
import {execFile} from '../src/util.mjs';
import {CLI} from '../src/demo.mjs';
import {check} from '../src/blackbox/poc-runtime.mjs';

test('actual CLI proves an anonymous list-to-item chain and replays it after the fix', async t => {
  const root = temp();
  t.after(() => fs.rmSync(root, {recursive: true, force: true}));
  const route = `/api/cohort-${randomBytes(3).toString('hex')}/documents`;
  const ownerRecord = {id: 'doc-101', ownerId: 'u-1', title: 'Owner document'};
  const outsiderRecord = {id: 'doc-202', ownerId: 'u-2', title: 'Outsider document'};
  let vulnerable = true, throttledOutsider = false;
  const requested = [];
  const server = http.createServer((request, response) => {
    const url = new URL(request.url, 'http://local');
    requested.push(url.pathname);
    const who = request.headers.authorization === 'Bearer owner-token' ? 'u-1' :
      request.headers.authorization === 'Bearer other-token' ? 'u-2' : null;
    let status = 404, body = {error: 'Not found'};
    if (url.pathname === '/openapi.json') {status = 200;
      body = {openapi: '3.0.0', paths: {'/api/me': {get: {}},
        [route]: {get: {}}, [`${route}/{id}`]: {get: {}}, '/api/delete': {get: {}}}};}
    else if (url.pathname === '/api/me') {status = who ? 200 : 401;
      body = who ? {id: who, role: 'member'} : {error: 'Sign in'};}
    else if (url.pathname === route) {status = who || vulnerable ? 200 : 401;
      body = status === 200 ? who === 'u-2' ? [outsiderRecord] : [ownerRecord] : {error: 'Sign in'};}
    else if (url.pathname === `${route}/${ownerRecord.id}`) {
      status = who === 'u-1' || !who && vulnerable ? 200 : who ? 403 : 401;
      body = status === 200 ? ownerRecord : {error: 'Denied'};
    } else if (url.pathname === `${route}/${outsiderRecord.id}`) {
      status = who === 'u-2' ? 200 : who ? 403 : 401;
      body = status === 200 ? outsiderRecord : {error: 'Denied'};
    } else if (url.pathname === '/api/delete') {status = 500; body = {error: 'Protected decoy'};}
    response.writeHead(status, {'content-type': 'application/json', 'cache-control': 'no-store',
      ...(throttledOutsider && who === 'u-2' && url.pathname === `${route}/${ownerRecord.id}` ?
        {'retry-after': '30'} : {})});
    response.end(JSON.stringify(body));
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  t.after(() => new Promise(resolve => server.close(resolve)));
  const origin = `http://127.0.0.1:${server.address().port}`;
  const env = {OWNER_TOKEN: 'owner-token', OTHER_TOKEN: 'other-token'};
  const cli = async (...args) => {
    const done = await execFile(process.execPath,
      [CLI, 'blackbox', ...args, '--project', root, '--json', '--non-interactive'],
      {cwd: root, env, timeout: 90000});
    return {code: done.code, data: JSON.parse(done.stdout)};
  };
  const first = await cli(origin, '--accept-local', '--no-model');
  assert.equal(first.code, 1, JSON.stringify({findings: first.data.findings,
    limitations: first.data.limitations}));
  const findings = first.data.findings.filter(item => item.kind === 'missing-auth');
  assert.ok(findings.some(item => item.pattern === route));
  assert.ok(findings.some(item => item.pattern === `${route}/{id}`));
  const chains = JSON.parse(fs.readFileSync(path.join(first.data.runDir, 'chains.json'), 'utf8'));
  const chain = chains.find(item => item.template === 'anonymous-list-to-item-read' &&
    item.status === 'confirmed');
  assert.ok(chain, JSON.stringify(chains));
  assert.equal(chain.severity, 'critical');
  assert.equal(chain.findings.length, 2);
  assert.ok(fs.existsSync(chain.proof));
  const spec = JSON.parse(fs.readFileSync(path.join(path.dirname(chain.proof), 'spec.json'), 'utf8'));
  throttledOutsider = true;
  assert.equal((await check(spec, env)).verdict, 'inconclusive',
    'an outsider rate-limit response is not an authorization denial');
  throttledOutsider = false;
  assert.ok(!requested.includes('/api/delete'));
  assert.equal((await cli('verify', first.data.run)).code, 1);
  const exported = await cli('export', first.data.run, '--out', path.join(root, 'regressions'));
  assert.equal(exported.code, 0);
  const childEnv = {...Object.fromEntries(Object.entries(process.env).filter(([key]) => key !== 'NODE_TEST_CONTEXT')),
    ...env};
  const exportedCode = () => new Promise((resolve, reject) => {
    const child = spawn(process.execPath, ['--test', ...exported.data.files], {env: childEnv, stdio: 'ignore'});
    child.on('error', reject);
    child.on('close', resolve);
  });
  assert.equal(await exportedCode(), 1);
  vulnerable = false;
  assert.equal((await cli('verify', first.data.run)).code, 0);
  assert.equal(await exportedCode(), 0);
  const fixed = await cli(origin, '--accept-local', '--no-model');
  assert.deepEqual(fixed.data.findings, []);
  assert.ok(!requested.includes('/api/delete'));
});
