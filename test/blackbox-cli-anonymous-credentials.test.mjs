import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import http from 'node:http';
import path from 'node:path';
import {randomBytes} from 'node:crypto';
import {temp} from './helpers.mjs';
import {execFile} from '../src/util.mjs';
import {CLI} from '../src/demo.mjs';

async function cli(root, ...args) {
  const done = await execFile(process.execPath,
    [CLI, 'blackbox', ...args, '--project', root, '--json', '--non-interactive'],
    {cwd: root, timeout: 90000});
  return {code: done.code, data: JSON.parse(done.stdout)};
}

test('blackbox CLI proves anonymous credential data in a random account route and replays its removal', async t => {
  const root = temp();
  t.after(() => fs.rmSync(root, {recursive: true, force: true}));
  const suffix = randomBytes(4).toString('hex');
  const route = `/api/${suffix}/users`;
  const decoy = `/api/${suffix}/public-users`;
  const hashes = [0, 1].map(() => `$2b$12$${randomBytes(32).toString('hex').slice(0, 53)}`);
  let vulnerable = true;
  const requests = [];
  const server = http.createServer((req, res) => {
    const url = new URL(req.url, 'http://local');
    requests.push(url.pathname);
    const reply = (status, body) => {
      res.writeHead(status, {'content-type': 'application/json', 'cache-control': 'no-store'});
      res.end(JSON.stringify(body));
    };
    if (url.pathname === '/openapi.json') return reply(200, {openapi: '3.0.0', paths: {
      [route]: {get: {}}, [decoy]: {get: {}}, '/api/delete': {get: {}},
    }});
    if (url.pathname === route) return reply(200, [
      {id: `person-a-${suffix}`, name: 'Alice', ...(vulnerable ? {passwordHash: hashes[0]} : {})},
      {id: `person-b-${suffix}`, name: 'Bob', ...(vulnerable ? {passwordHash: hashes[1]} : {})},
    ]);
    if (url.pathname === decoy) return reply(200, [
      {id: 'public-a', passwordHash: 'redacted'}, {id: 'public-b', passwordHash: 'redacted'},
    ]);
    if (url.pathname === '/api/delete') return reply(500, {error: 'protected decoy'});
    reply(404, {error: 'missing'});
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  t.after(() => new Promise(resolve => server.close(resolve)));
  const origin = `http://127.0.0.1:${server.address().port}`;
  const audit = await cli(root, origin, '--accept-local', '--no-model');
  assert.equal(audit.code, 1, JSON.stringify({findings: audit.data.findings, limitations: audit.data.limitations}));
  const finding = audit.data.findings.find(item => item.kind === 'anonymous-credential-data' && item.pattern === route);
  assert.ok(finding?.proof, JSON.stringify(audit.data.findings));
  assert.ok(!audit.data.findings.some(item => item.pattern === decoy));
  const requested = new Map(audit.data.coverage.requestedClasses.map(item => [item.name, item.status]));
  assert.equal(requested.get('Excessive Data Exposure'), 'partial');
  assert.equal(requested.get('API Key Exposure'), 'not tested');
  assert.ok(!requests.includes('/api/delete'));
  const proof = JSON.parse(fs.readFileSync(path.join(path.dirname(finding.proof), 'spec.json'), 'utf8'));
  assert.deepEqual([proof.kind, proof.field, proof.request.as],
    ['anonymous-credential-data', 'passwordHash', 'anonymous']);
  assert.equal((await cli(root, 'verify', audit.data.run)).code, 1);
  const exported = await cli(root, 'export', audit.data.run, '--out', path.join(root, 'regressions'));
  assert.equal(exported.code, 0);
  const regression = exported.data.files.find(file => path.basename(file).includes(finding.id));
  assert.ok(regression);
  const runRegression = () => execFile(process.execPath, [regression],
    {cwd: root, env: {NODE_TEST_CONTEXT: undefined}, timeout: 30000});
  assert.equal((await runRegression()).code, 1);
  vulnerable = false;
  assert.equal((await cli(root, 'verify', audit.data.run)).code, 0);
  assert.equal((await runRegression()).code, 0);
  const artifacts = fs.readdirSync(audit.data.runDir, {recursive: true}).filter(file =>
    fs.statSync(path.join(audit.data.runDir, file)).isFile()).map(file =>
    fs.readFileSync(path.join(audit.data.runDir, file), 'utf8')).join('\n');
  for (const secret of hashes) assert.ok(!artifacts.includes(secret), 'credential values never enter run artifacts');
});
