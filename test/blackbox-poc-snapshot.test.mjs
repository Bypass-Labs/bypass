import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import http from 'node:http';
import os from 'node:os';
import path from 'node:path';
import {fileURLToPath, pathToFileURL} from 'node:url';

test('a running audit copies the proof runtime version it loaded before a source edit', async t => {
  const temp = fs.mkdtempSync(path.join(os.tmpdir(), 'bypass-proof-snapshot-'));
  fs.cpSync(fileURLToPath(new URL('../src/', import.meta.url)), path.join(temp, 'src'),
    {recursive: true});
  let hits = 0;
  const server = http.createServer((_request, response) => {
    hits++;
    response.writeHead(200, {'content-type': 'text/plain'});
    response.end('# HELP audit_metric Test metric\n# TYPE audit_metric counter\naudit_metric 1\n');
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  t.after(async () => {
    await new Promise(resolve => server.close(resolve));
    fs.rmSync(temp, {recursive: true, force: true});
  });
  const {proveFindings} = await import(pathToFileURL(
    path.join(temp, 'src/blackbox/poc.mjs')).href);
  // The audit has already imported poc.mjs; a later source edit must not change
  // the runtime it writes beside the generated proof.
  fs.writeFileSync(path.join(temp, 'src/blackbox/poc-runtime.mjs'),
    "throw Error('edited while audit was running');\n");
  const origin = `http://127.0.0.1:${server.address().port}`;
  const scope = {target: {origin, environment: 'local'}, include: ['/'], never: [],
    domains: [], discovery: {auditDomains: []}, limits: {rps: 20},
    identities: {owner: {env: 'OWNER_TOKEN'}, outsider: {env: 'OTHER_TOKEN'},
      auth: 'bearer', identityPath: null, identityCookieName: null}};
  const finding = {id: 'f-001', kind: 'exposure', url: `${origin}/metrics`,
    pattern: '/metrics', confirmation: [], exposureHash: null};
  const kept = await proveFindings([finding], [], {runDir: path.join(temp, 'run'),
    surface: {exposures: [{path: '/metrics', signature: 'metrics exposition'}]},
    scope, env: {}, ledger: {append: () => 'ev-0001'}});
  assert.equal(kept.length, 1);
  assert.equal(hits, 2);
  assert.ok(fs.existsSync(path.join(temp, 'run/poc/content-boundary.mjs')));
  assert.ok(fs.readFileSync(path.join(temp, 'run/poc/runtime.mjs'), 'utf8')
    .includes('export async function check'));
});
