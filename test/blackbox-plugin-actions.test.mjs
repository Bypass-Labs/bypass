import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import http from 'node:http';
import {cli, temp} from './helpers.mjs';
import {mcpClient} from './mcp-client.mjs';
import {execute} from '../src/service.mjs';

test('packaged Muse tools replay and export a CLI finding', async t => {
  const root = temp();
  t.after(() => fs.rmSync(root, {recursive: true, force: true}));
  fs.writeFileSync(path.join(root, 'app.mjs'), 'export const testApp = true;\n');
  await execute('init', [root]);
  const server = http.createServer((request, response) => {
    const url = new URL(request.url, 'http://local');
    if (url.pathname === '/openapi.json') {
      response.writeHead(200, {'content-type': 'application/json'});
      return response.end(JSON.stringify({openapi: '3.0.0', paths: {
        '/api/go': {get: {parameters: [{name: 'next', in: 'query'}]}}}}));
    }
    if (url.pathname === '/api/go') {
      const destination = url.searchParams.get('next') ?? '/';
      if (/[\r\n]/.test(destination)) {
        response.writeHead(400); return response.end();
      }
      response.writeHead(302, {location: destination});
      return response.end();
    }
    response.writeHead(404); response.end('missing');
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  t.after(() => new Promise(resolve => server.close(resolve)));
  const origin = `http://127.0.0.1:${server.address().port}`;
  const audit = await cli(root, 'blackbox', origin, '--accept-local', '--no-model');
  assert.equal(audit.code, 1, JSON.stringify(audit.data));
  assert.ok(audit.data.findings.some(finding => finding.kind === 'open-redirect'));

  const client = await mcpClient(root, {packaged: true, stateDir: temp(),
    env: {META_API_KEY: '', MODEL_API_KEY: ''}});
  t.after(() => client.child.kill());
  const verified = await client.call('bypass_blackbox_verify', {run: audit.data.run});
  assert.ok(verified.proofs.some(proof => proof.verdict === 'confirmed'));
  const exported = await client.call('bypass_blackbox_export',
    {run: audit.data.run, out: 'regression'});
  assert.ok(exported.files.some(file => fs.existsSync(file)));
  assert.equal(await client.close(), 0);
});
