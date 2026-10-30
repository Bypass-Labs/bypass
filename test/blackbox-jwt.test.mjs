import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import http from 'node:http';
import path from 'node:path';
import {createHmac} from 'node:crypto';
import {spawn} from 'node:child_process';
import {temp} from './helpers.mjs';
import {execFile} from '../src/util.mjs';
import {CLI} from '../src/demo.mjs';
import {jwtUnsignedCanaries, jwtUnsignedOracle} from '../src/blackbox/poc-runtime.mjs';

const encode = value => Buffer.from(JSON.stringify(value)).toString('base64url');

function signedJwt(claims, secret) {
  const input = `${encode({alg: 'HS256', typ: 'JWT'})}.${encode(claims)}`;
  return `${input}.${createHmac('sha256', secret).update(input).digest('base64url')}`;
}

test('unsigned-JWT oracle needs a denied invalid signature and two matching private reads', () => {
  const token = signedJwt({sub: 'owner'}, 'fixture-secret');
  const canaries = jwtUnsignedCanaries(token);
  assert.ok(canaries.first.endsWith('.') && canaries.second.endsWith('.'));
  assert.notEqual(canaries.first, canaries.second);
  assert.equal(jwtUnsignedCanaries('opaque-token'), null);
  const owner = {status: 200, type: 'application/json', hash: 'owner-hash'};
  const denied = {status: 401, headers: {}};
  const read = {status: 200, hash: 'owner-hash'};
  assert.equal(jwtUnsignedOracle(owner, denied, denied, read, read), true);
  assert.equal(jwtUnsignedOracle(owner, denied, read, read, read), false);
  assert.equal(jwtUnsignedOracle(owner, denied, denied, read,
    {...read, hash: 'changed'}), false);
  assert.equal(jwtUnsignedOracle(owner, denied, denied, read,
    {...read, headers: {age: '1'}}), false);
});

test('real blackbox CLI proves alg:none acceptance and its proof and regression clear after a fix', async t => {
  const root = temp();
  t.after(() => fs.rmSync(root, {recursive: true, force: true}));
  const secret = 'fixture-signing-key';
  const ownerToken = signedJwt({sub: 'owner-1', exp: Math.floor(Date.now() / 1000) + 3600}, secret);
  const childEnv = {...process.env, OWNER_TOKEN: ownerToken};
  delete childEnv.OTHER_TOKEN;
  const exportEnv = {...childEnv};
  delete exportEnv.NODE_TEST_CONTEXT;
  let vulnerable = true;
  const server = http.createServer((request, response) => {
    const url = new URL(request.url, 'http://local');
    if (url.pathname === '/openapi.json') {
      response.writeHead(200, {'content-type': 'application/json'});
      return response.end(JSON.stringify({openapi: '3.0.0', paths: {'/api/profile': {get: {}}}}));
    }
    if (url.pathname === '/api/profile') {
      const token = /^Bearer (.+)$/.exec(request.headers.authorization ?? '')?.[1];
      let claims = null;
      if (token) {
        const parts = token.split('.');
        try {
          const header = JSON.parse(Buffer.from(parts[0], 'base64url').toString('utf8'));
          const payload = JSON.parse(Buffer.from(parts[1], 'base64url').toString('utf8'));
          const signature = createHmac('sha256', secret).update(`${parts[0]}.${parts[1]}`).digest('base64url');
          if (header.alg === 'HS256' && parts[2] === signature ||
              vulnerable && header.alg === 'none' && parts[2] === '') claims = payload;
        } catch { /* reject malformed tokens */ }
      }
      response.writeHead(claims?.sub === 'owner-1' ? 200 : 401, {'content-type': 'application/json'});
      return response.end(JSON.stringify(claims?.sub === 'owner-1' ?
        {id: 'owner-1', ownerId: 'owner-1', note: 'private'} : {error: 'Sign in'}));
    }
    response.writeHead(404);
    response.end();
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  t.after(() => new Promise(resolve => server.close(resolve)));
  const origin = `http://127.0.0.1:${server.address().port}`;
  const cli = async (...args) => {
    const completed = await execFile(process.execPath,
      [CLI, ...args, '--project', root, '--json', '--non-interactive'],
      {cwd: root, env: childEnv, timeout: 90000});
    return {code: completed.code, data: JSON.parse(completed.stdout)};
  };
  const audit = () => cli('blackbox', origin, '--accept-local', '--no-model');
  const first = await audit();
  assert.equal(first.code, 1, JSON.stringify(first.data));
  const finding = first.data.findings.find(item => item.kind === 'jwt-unsigned');
  assert.ok(finding, JSON.stringify(first.data.findings));
  assert.ok(fs.existsSync(finding.proof));
  const report = JSON.parse(fs.readFileSync(path.join(first.data.runDir, 'report.json'), 'utf8'));
  assert.equal(report.coverage.requestedClasses.find(item =>
    item.name === 'JWT Signature Verification Flaws')?.status, 'partial');
  assert.ok(report.findings.find(item => item.kind === 'jwt-unsigned')?.curl[0].includes('node '));
  const evidence = fs.readFileSync(path.join(first.data.runDir, 'evidence.jsonl'), 'utf8');
  const canaries = jwtUnsignedCanaries(ownerToken);
  for (const secretValue of [ownerToken, canaries.first, canaries.second])
    assert.ok(!evidence.includes(secretValue));
  assert.equal((await cli('blackbox', 'verify', first.data.run)).code, 1);
  const exported = await cli('blackbox', 'export', first.data.run,
    '--out', path.join(root, 'regressions'));
  assert.equal(exported.code, 0);
  const runExported = () => new Promise((resolve, reject) => {
    const child = spawn(process.execPath, ['--test', ...exported.data.files], {env: exportEnv, stdio: 'ignore'});
    child.once('error', reject);
    child.once('close', resolve);
  });
  assert.equal(await runExported(), 1);
  vulnerable = false;
  assert.equal((await cli('blackbox', 'verify', first.data.run)).code, 0);
  assert.equal(await runExported(), 0);
  const fixed = await audit();
  assert.ok(!fixed.data.findings.some(item => item.kind === 'jwt-unsigned'));
});
