import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import http from 'node:http';
import path from 'node:path';
import {spawn} from 'node:child_process';
import {temp, cli} from './helpers.mjs';
import {createLedger} from '../src/blackbox/ledger.mjs';
import {createRequester, loadScope} from '../src/blackbox/scope.mjs';
import {HOST_HEADER_CANARIES, hostHeaderRedirectOracle} from '../src/blackbox/poc-runtime.mjs';

test('Host redirect oracle requires two exact destinations and rejects cached controls', () => {
  const origin = 'http://127.0.0.1:4329';
  const control = {status: 302, headers: {location: `${origin}/safe?x=1`}};
  const first = {status: 302, headers: {location: `http://${HOST_HEADER_CANARIES[0]}/safe?x=1`}};
  const second = {status: 302, headers: {location: `http://${HOST_HEADER_CANARIES[1]}/safe?x=1`}};
  assert.equal(hostHeaderRedirectOracle(control, first, second, origin), true);
  assert.equal(hostHeaderRedirectOracle(control, first, first, origin), false);
  assert.equal(hostHeaderRedirectOracle(control, first,
    {...second, headers: {...second.headers, 'x-cache': 'HIT'}}, origin), false);
  assert.equal(hostHeaderRedirectOracle({...control, status: 429}, first, second, origin), false);
  assert.equal(hostHeaderRedirectOracle({...control, headers: {location: '/elsewhere'}}, first, second, origin), false);
});

test('scoped requester sends valid model-chosen Host headers', async t => {
  const root = temp();
  t.after(() => fs.rmSync(root, {recursive: true, force: true}));
  const seen = [];
  const server = http.createServer((request, response) => {
    seen.push(request.headers.host);
    response.writeHead(204);
    response.end();
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  t.after(() => new Promise(resolve => server.close(resolve)));
  const origin = `http://127.0.0.1:${server.address().port}`;
  const {scope} = loadScope({origin, overrides: {acceptLocal: true}});
  const requester = createRequester(scope, {ledger: createLedger(root), allowLocal: true});
  const call = host => requester({url: '/api/go', step: 'task', method: 'GET', noCache: true,
    headers: {host}});
  assert.equal((await call('example.invalid')).status, 204);
  assert.deepEqual(seen, ['example.invalid']);
  await assert.rejects(call('bad\r\nHost: injected.invalid'), /HTTP header/);
});

test('real blackbox CLI proves Host redirect poisoning and its exported regression turns green after a fix', async t => {
  const root = temp();
  t.after(() => fs.rmSync(root, {recursive: true, force: true}));
  let vulnerable = true;
  let origin;
  const seenHosts = [];
  const server = http.createServer((request, response) => {
    const url = new URL(request.url, 'http://local');
    if (url.pathname === '/openapi.json') {
      response.writeHead(200, {'content-type': 'application/json'});
      return response.end(JSON.stringify({openapi: '3.0.0', paths: {
        '/api/go': {get: {parameters: [{name: 'next', in: 'query'}]}}}}));
    }
    if (url.pathname === '/api/go') {
      seenHosts.push(request.headers.host);
      const location = vulnerable ? `http://${request.headers.host}/safe` : `${origin}/safe`;
      response.writeHead(302, {location});
      return response.end();
    }
    response.writeHead(404);
    response.end();
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  t.after(() => new Promise(resolve => server.close(resolve)));
  origin = `http://127.0.0.1:${server.address().port}`;
  const audit = () => cli(root, 'blackbox', origin, '--accept-local', '--no-model');
  const first = await audit();
  assert.equal(first.code, 1, JSON.stringify(first.data));
  const finding = first.data.findings.find(item => item.kind === 'host-header-redirect');
  assert.ok(finding, JSON.stringify(first.data.findings));
  assert.ok(fs.existsSync(finding.proof));
  for (const host of HOST_HEADER_CANARIES) assert.ok(seenHosts.includes(host));
  const report = JSON.parse(fs.readFileSync(path.join(first.data.runDir, 'report.json'), 'utf8'));
  const row = report.coverage.requestedClasses.find(item => item.name === 'Host Header Injection');
  assert.equal(row.status, 'partial');
  const reported = report.findings.find(item => item.kind === 'host-header-redirect');
  assert.ok(reported.curl.some(line => line.includes(`Host: ${HOST_HEADER_CANARIES[0]}`)));
  assert.ok(reported.curl.some(line => line.includes(`Host: ${HOST_HEADER_CANARIES[1]}`)));
  assert.equal((await cli(root, 'blackbox', 'verify', first.data.run)).code, 1);
  const exported = await cli(root, 'blackbox', 'export', first.data.run,
    '--out', path.join(root, 'regressions'));
  assert.equal(exported.code, 0);
  assert.ok(exported.data.files.length > 0);
  const childEnv = Object.fromEntries(Object.entries(process.env).filter(([key]) => key !== 'NODE_TEST_CONTEXT'));
  const runExported = () => new Promise((resolve, reject) => {
    const child = spawn(process.execPath, ['--test', ...exported.data.files], {env: childEnv, stdio: 'ignore'});
    child.once('error', reject);
    child.once('exit', resolve);
  });
  assert.equal(await runExported(), 1);
  vulnerable = false;
  assert.equal((await cli(root, 'blackbox', 'verify', first.data.run)).code, 0);
  assert.equal(await runExported(), 0);
  const fixed = await audit();
  assert.ok(!fixed.data.findings.some(item => item.kind === 'host-header-redirect'));
});
