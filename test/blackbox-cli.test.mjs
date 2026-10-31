import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import http from 'node:http';
import {temp, cli} from './helpers.mjs';

test('scope, audit, verify and export work through the actual CLI without account tokens', async t => {
  const root = temp();
  t.after(() => fs.rmSync(root, {recursive: true, force: true}));
  const server = http.createServer((req, res) => {
    const url = new URL(req.url, 'http://local');
    if (url.pathname === '/openapi.json') {
      res.writeHead(200, {'content-type': 'application/json'});
      return res.end(JSON.stringify({openapi: '3.0.0', paths: {
        '/api/go': {get: {parameters: [{name: 'next', in: 'query'}]}}}}));
    }
    if (url.pathname === '/api/go') {
      const destination = url.searchParams.get('next') ?? '/';
      if (/[\r\n]/.test(destination)) {res.writeHead(400); return res.end();}
      res.writeHead(302, {location: destination});
      return res.end();
    }
    res.writeHead(404);
    res.end();
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  t.after(() => new Promise(resolve => server.close(resolve)));
  const origin = `http://127.0.0.1:${server.address().port}`;
  const scope = await cli(root, 'blackbox', 'scope', origin, '--include', '/api');
  assert.equal(scope.code, 0);
  assert.ok(fs.existsSync(scope.data.file));
  assert.equal(JSON.parse(fs.readFileSync(scope.data.file, 'utf8')).probes.crlfResponseHeader, true);
  assert.equal(JSON.parse(fs.readFileSync(scope.data.file, 'utf8')).probes.hostHeaderRedirect, true);
  assert.equal(JSON.parse(fs.readFileSync(scope.data.file, 'utf8')).probes.jwtUnsigned, true);
  assert.equal(JSON.parse(fs.readFileSync(scope.data.file, 'utf8')).probes.commandExecution, true);
  assert.equal(JSON.parse(fs.readFileSync(scope.data.file, 'utf8')).probes.pathTraversal, true);
  const audit = await cli(root, 'blackbox', origin, '--accept-local', '--no-model');
  assert.equal(audit.code, 1, JSON.stringify(audit.data));
  assert.ok(audit.data.findings.some(item => item.kind === 'open-redirect'));
  assert.ok(fs.existsSync(audit.data.reportPath));
  const verify = await cli(root, 'blackbox', 'verify', audit.data.run);
  assert.equal(verify.code, 1);
  const exported = await cli(root, 'blackbox', 'export', audit.data.run, '--out', `${root}/regression`);
  assert.equal(exported.code, 0);
  assert.ok(exported.data.files.length > 0);
});

test('scope CLI records explicit descendant audit domains and rejects wider domains', async t => {
  const root = temp();
  t.after(() => fs.rmSync(root, {recursive: true, force: true}));
  const origin = 'https://app.example.test';
  const rejected = await cli(root, 'blackbox', 'scope', origin,
    '--domains', 'example.test', '--audit-domains', 'outside.test');
  assert.notEqual(rejected.code, 0);
  const created = await cli(root, 'blackbox', 'scope', origin,
    '--domains', 'example.test', '--audit-domains', 'example.test');
  assert.equal(created.code, 0);
  const scope = JSON.parse(fs.readFileSync(created.data.file, 'utf8'));
  assert.deepEqual(scope.discovery.auditDomains, ['example.test']);
  assert.equal(scope.probes.crlfResponseHeader, true);
  assert.equal(scope.probes.hostHeaderRedirect, true);
  assert.equal(scope.probes.jwtUnsigned, true);
  assert.equal(scope.probes.commandExecution, true);
  assert.equal(scope.probes.pathTraversal, true);
  assert.equal(scope.probes.xmlExternalEntity, true);
});
