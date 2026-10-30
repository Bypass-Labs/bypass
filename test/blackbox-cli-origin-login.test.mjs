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

test('CLI logs into each credential origin separately and replays a secondary-origin IDOR proof', async t => {
  const root = temp();
  t.after(() => fs.rmSync(root, {recursive: true, force: true}));
  const salt = randomBytes(4).toString('hex');
  const users = [
    {id: `u-one-${salt}`, email: `one-${salt}@example.test`, password: `pw-one-${salt}`},
    {id: `u-two-${salt}`, email: `two-${salt}@example.test`, password: `pw-two-${salt}`},
  ];
  const env = {OWNER_USER: users[0].email, OWNER_PASS: users[0].password,
    OTHER_USER: users[1].email, OTHER_PASS: users[1].password};
  const invoices = [{id: `inv-a-${salt}`, ownerId: users[0].id},
    {id: `inv-b-${salt}`, ownerId: users[1].id}];
  let secondaryVulnerable = true;
  const loginHits = [0, 0];
  const origins = [];
  for (const index of [0, 1]) {
    const server = http.createServer((req, res) => {
      const url = new URL(req.url, 'http://local');
      const reply = (status, body, type = 'application/json') => {
        res.writeHead(status, {'content-type': type, 'cache-control': 'no-store'});
        res.end(type === 'text/html' || type === 'application/javascript' ? body : JSON.stringify(body));
      };
      if (url.pathname === '/') return reply(200, '<script src="/app.js"></script>', 'text/html');
      if (url.pathname === '/app.js') return reply(200,
        "fetch('/api/auth/login', {method:'POST', body:JSON.stringify({email, password})});", 'application/javascript');
      if (url.pathname === '/openapi.json') return reply(200, {openapi: '3.0.0', paths: {
        '/api/me': {get: {}}, '/api/invoices': {get: {}}, '/api/invoices/{id}': {get: {}},
      }});
      if (url.pathname === '/api/auth/login' && req.method === 'POST') {
        loginHits[index]++;
        let raw = '';
        req.on('data', chunk => {raw += chunk;});
        req.on('end', () => {
          let body;
          try {body = JSON.parse(raw);} catch {return reply(400, {error: 'bad body'});}
          const user = users.find(item => item.email === body.email && item.password === body.password);
          return user ? reply(200, {token: `session-${index}-${user.id}`}) : reply(401, {error: 'login failed'});
        });
        return;
      }
      const user = users.find(item => req.headers.authorization === `Bearer session-${index}-${item.id}`);
      if (url.pathname === '/api/me') return reply(user ? 200 : 401,
        user ? {id: user.id, role: 'member'} : {error: 'login required'});
      if (url.pathname === '/api/invoices') return reply(user ? 200 : 401,
        user ? invoices.filter(item => item.ownerId === user.id) : {error: 'login required'});
      if (url.pathname.startsWith('/api/invoices/')) {
        const invoice = invoices.find(item => url.pathname === `/api/invoices/${item.id}`);
        return reply(!user ? 401 : !invoice ? 404 : invoice.ownerId === user.id ||
          index === 1 && secondaryVulnerable ? 200 : 403,
        !user ? {error: 'login required'} : !invoice ? {error: 'missing'} :
          invoice.ownerId === user.id || index === 1 && secondaryVulnerable ? invoice : {error: 'denied'});
      }
      reply(404, {error: 'missing'});
    });
    await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
    t.after(() => new Promise(resolve => server.close(resolve)));
    origins.push(`http://127.0.0.1:${server.address().port}`);
  }
  const configured = await cli(root, env, 'blackbox', 'setup', origins[0],
    '--credential-origins', origins[1], '--identity-path', '/api/me');
  assert.equal(configured.code, 0);
  assert.deepEqual(configured.data.credentialOrigins, origins);
  const scope = JSON.parse(fs.readFileSync(configured.data.scopeFile, 'utf8'));
  scope.discovery.sensitivePaths = false;
  fs.writeFileSync(configured.data.scopeFile, JSON.stringify(scope));
  const audit = await cli(root, env, 'blackbox', origins[0], '--accept-local', '--no-model');
  assert.equal(audit.code, 1, JSON.stringify({findings: audit.data.findings, limitations: audit.data.limitations}));
  const finding = audit.data.findings.find(item => item.kind === 'idor' && item.url.startsWith(origins[1]));
  assert.ok(finding?.proof, JSON.stringify(audit.data.findings));
  assert.ok(loginHits[0] >= 2 && loginHits[1] >= 2,
    `both accounts logged in on both origins: ${loginHits}`);
  const spec = JSON.parse(fs.readFileSync(path.join(path.dirname(finding.proof), 'spec.json'), 'utf8'));
  assert.equal(spec.origin, origins[1]);
  assert.equal(spec.authBootstrap.owner.origin, origins[1]);
  assert.equal(spec.authBootstrap.outsider.origin, origins[1]);
  const beforeVerify = loginHits[1];
  assert.equal((await cli(root, env, 'blackbox', 'verify', audit.data.run)).code, 1);
  assert.ok(loginHits[1] > beforeVerify, 'secondary proof obtained fresh secondary sessions');
  secondaryVulnerable = false;
  assert.equal((await cli(root, env, 'blackbox', 'verify', audit.data.run)).code, 0);
});
