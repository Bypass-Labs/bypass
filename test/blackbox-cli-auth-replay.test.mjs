import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import http from 'node:http';
import path from 'node:path';
import {randomBytes} from 'node:crypto';
import {temp} from './helpers.mjs';
import {execFile} from '../src/util.mjs';
import {CLI} from '../src/demo.mjs';

async function cli(root, env, ...args) {
  const reply = await execFile(process.execPath,
    [CLI, ...args, '--project', root, '--json', '--non-interactive'],
    {cwd: root, env, timeout: 90000});
  return {code: reply.code, data: JSON.parse(reply.stdout)};
}

test('CLI finds an authenticated redirect and replays login from raw credentials in verify and exported tests', async t => {
  const root = temp();
  t.after(() => fs.rmSync(root, {recursive: true, force: true}));
  const suffix = randomBytes(4).toString('hex');
  const jump = `/api/${suffix}/go`;
  const accounts = [
    {id: `u-owner-${suffix}`, email: `owner-${suffix}@example.test`, password: `owner-pw-${suffix}`, token: `owner-token-${suffix}`},
    {id: `u-other-${suffix}`, email: `other-${suffix}@example.test`, password: `other-pw-${suffix}`, token: `other-token-${suffix}`},
  ];
  let vulnerable = true;
  let loginHits = 0;
  const server = http.createServer((req, res) => {
    const url = new URL(req.url, 'http://local');
    const reply = (status, body, headers = {}) => {
      res.writeHead(status, {'content-type': 'application/json', ...headers});
      res.end(JSON.stringify(body));
    };
    if (url.pathname === '/openapi.json') return reply(200, {openapi: '3.0.0', paths: {
      '/api/auth/login': {post: {requestBody: {content: {'application/json': {schema: {
        type: 'object', properties: {email: {type: 'string'}, password: {type: 'string'}}}}}}}},
      '/api/me': {get: {}}, [jump]: {get: {parameters: [{name: 'next', in: 'query'}]}},
    }});
    if (url.pathname === '/api/auth/login' && req.method === 'POST') {
      loginHits++;
      let raw = '';
      req.on('data', chunk => {raw += chunk;});
      req.on('end', () => {
        let body;
        try {body = JSON.parse(raw);} catch {return reply(400, {error: 'bad body'});}
        const account = accounts.find(item => item.email === body.email && item.password === body.password);
        return account ? reply(200, {accessToken: account.token}) : reply(401, {error: 'bad credentials'});
      });
      return;
    }
    const account = accounts.find(item => req.headers.authorization === `Bearer ${item.token}`);
    if (url.pathname === '/api/me') return reply(account ? 200 : 401,
      account ? {id: account.id, role: 'member'} : {error: 'login required'});
    if (url.pathname === jump) {
      if (!account) return reply(401, {error: 'login required'});
      const location = vulnerable ? url.searchParams.get('next') ?? '/safe' : '/safe';
      if (/[\r\n]/.test(location)) return reply(400, {error: 'bad redirect'});
      res.writeHead(302, {location});
      return res.end();
    }
    reply(404, {error: 'missing'});
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  t.after(() => new Promise(resolve => server.close(resolve)));
  const origin = `http://127.0.0.1:${server.address().port}`;
  const env = {OWNER_USER: accounts[0].email, OWNER_PASS: accounts[0].password,
    OTHER_USER: accounts[1].email, OTHER_PASS: accounts[1].password};
  const configured = await cli(root, env, 'blackbox', 'scope', origin, '--identity-path', '/api/me');
  assert.equal(configured.code, 0, JSON.stringify(configured.data));
  const audit = await cli(root, env, 'blackbox', origin, '--accept-local', '--no-model');
  assert.equal(audit.code, 1, JSON.stringify(audit.data));
  const finding = audit.data.findings.find(item => item.kind === 'open-redirect' && item.pattern === jump);
  assert.ok(finding?.proof, JSON.stringify(audit.data.findings));
  const spec = JSON.parse(fs.readFileSync(path.join(path.dirname(finding.proof), 'spec.json'), 'utf8'));
  assert.equal(spec.request.as, 'owner');
  assert.equal(spec.authBootstrap.owner.path, '/api/auth/login');
  assert.equal(spec.authBootstrap.owner.usernameEnv, 'OWNER_USER');
  assert.equal(spec.authBootstrap.owner.passwordEnv, 'OWNER_PASS');
  const beforeVerify = loginHits;
  const verify = await cli(root, env, 'blackbox', 'verify', audit.data.run);
  assert.equal(verify.code, 1, JSON.stringify(verify.data));
  assert.ok(loginHits > beforeVerify, 'verify logged in with raw credentials');
  const exported = await cli(root, env, 'blackbox', 'export', audit.data.run, '--out', path.join(root, 'regression'));
  assert.equal(exported.code, 0);
  const regression = exported.data.files.find(file => path.basename(file).includes(finding.id));
  assert.ok(regression);
  const red = await execFile(process.execPath, [regression],
    {cwd: root, env: {...env, NODE_TEST_CONTEXT: undefined}, timeout: 30000});
  assert.equal(red.code, 1, `${red.stdout}\n${red.stderr}`);
  vulnerable = false;
  const fixed = await cli(root, env, 'blackbox', 'verify', audit.data.run);
  assert.equal(fixed.data.proofs.find(item => item.id === finding.id)?.verdict,
    'not_reproduced', JSON.stringify(fixed.data));
  assert.ok(fixed.data.proofs.some(item => item.kind === 'rate-limit-auth-gate' &&
    item.verdict === 'confirmed'), 'the fixture still lacks login throttling');
  const green = await execFile(process.execPath, [regression],
    {cwd: root, env: {...env, NODE_TEST_CONTEXT: undefined}, timeout: 30000});
  assert.equal(green.code, 0, green.stdout);
  const runText = fs.readdirSync(audit.data.runDir, {recursive: true}).filter(item =>
    fs.statSync(path.join(audit.data.runDir, item)).isFile()).map(item =>
    fs.readFileSync(path.join(audit.data.runDir, item), 'utf8')).join('\n');
  for (const secret of [...Object.values(env), ...accounts.map(item => item.token)])
    assert.ok(!runText.includes(secret), 'run artifacts do not store credentials or session tokens');
});
