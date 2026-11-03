import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import http from 'node:http';
import os from 'node:os';
import path from 'node:path';
import {randomBytes} from 'node:crypto';
import {createLedger} from '../src/blackbox/ledger.mjs';
import {proveFindings, exportRun, verifyRun} from '../src/blackbox/poc.mjs';
import {check} from '../src/blackbox/poc-runtime.mjs';
import {initStore, change} from '../src/store.mjs';
import {execFile, hash} from '../src/util.mjs';

test('exported regressions use an explicit CI origin while sealed proofs keep their target', async t => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'bypass-export-origin-'));
  t.after(() => fs.rmSync(root, {recursive: true, force: true}));
  const run = `bx-20261103-${randomBytes(4).toString('hex')}`;
  const runDir = path.join(root, '.bypass/runs', run);
  fs.mkdirSync(runDir, {recursive: true});
  const route = `/metrics-${randomBytes(4).toString('hex')}`;
  const metrics = '# HELP audit_metric Test metric\n# TYPE audit_metric counter\naudit_metric 1\n';
  let originalVulnerable = true, ciVulnerable = false;
  let originalHits = 0, ciHits = 0;
  const serve = (vulnerable, hit) => http.createServer((request, response) => {
    hit();
    if (request.url === route && vulnerable()) {
      response.writeHead(200, {'content-type': 'text/plain', 'cache-control': 'no-store'});
      return response.end(metrics);
    }
    response.writeHead(404, {'content-type': 'text/plain', 'cache-control': 'no-store'});
    response.end('Missing');
  });
  const original = serve(() => originalVulnerable, () => { originalHits++; });
  const ci = serve(() => ciVulnerable, () => { ciHits++; });
  await Promise.all([original, ci].map(server => new Promise(resolve =>
    server.listen(0, '127.0.0.1', resolve))));
  t.after(async () => Promise.all([original, ci].map(server => new Promise(resolve =>
    server.close(resolve)))));
  const originalOrigin = `http://127.0.0.1:${original.address().port}`;
  const ciOrigin = `http://127.0.0.1:${ci.address().port}`;
  const scope = {target: {origin: originalOrigin, environment: 'local'},
    include: ['/'], never: [], domains: [], discovery: {auditDomains: []},
    limits: {rps: 20}, identities: {owner: {env: 'OWNER_TOKEN'},
      outsider: {env: 'OTHER_TOKEN'}, auth: 'bearer', identityPath: null,
      identityCookieName: null}};
  const ledger = createLedger(runDir);
  t.after(() => ledger.close());
  const finding = {id: 'f-001', kind: 'exposure', url: `${originalOrigin}${route}`,
    pattern: route, confirmation: [], exposureHash: null};
  const proved = await proveFindings([finding], [], {runDir,
    surface: {exposures: [{path: route, signature: 'metrics exposition'}]},
    scope, env: {}, ledger});
  assert.equal(proved.length, 1);
  fs.writeFileSync(path.join(runDir, 'run.json'), '{}');
  const output = path.join(root, 'regressions');
  const exported = exportRun(root, run, {out: output});
  const file = exported.files[0];
  const newSource = fs.readFileSync(file, 'utf8');
  const spec = JSON.parse(fs.readFileSync(path.join(runDir, 'poc/f-001/spec.json'), 'utf8'));
  assert.equal(spec.request.url, `${originalOrigin}${route}`);
  assert.equal((await check(spec, {})).verdict, 'confirmed');
  const runTest = async target => {
    const env = {NODE_TEST_CONTEXT: undefined, BYPASS_BLACKBOX_TEST_ORIGIN: undefined};
    if (target) env.BYPASS_BLACKBOX_TEST_ORIGIN = target;
    return execFile(process.execPath, ['--test', file], {env, timeout: 20000});
  };
  const first = await runTest(null);
  assert.equal(first.code, 1, `without an override the original proof still fails: ${first.stdout} ${first.stderr}`);
  const beforeCiGuard = originalHits;
  const missingCiOrigin = await execFile(process.execPath, ['--test', file],
    {env: {NODE_TEST_CONTEXT: undefined, CI: 'true'}, timeout: 20000});
  assert.equal(missingCiOrigin.code, 1);
  assert.match(`${missingCiOrigin.stdout}${missingCiOrigin.stderr}`, /Set BYPASS_BLACKBOX_TEST_ORIGIN for CI replay/);
  assert.equal(originalHits, beforeCiGuard, 'CI without an origin never contacts production');
  const before = originalHits;
  assert.equal((await runTest(ciOrigin)).code, 0, 'the patched CI build passes');
  assert.equal(originalHits, before, 'the override never contacted the original target');
  assert.ok(ciHits >= 2, 'CI replay actually contacted its selected origin');
  ciVulnerable = true;
  assert.equal((await runTest(ciOrigin)).code, 1, 'the vulnerable CI build fails');
  ciVulnerable = false;

  for (const [index, body] of [JSON.stringify({callback: `${originalOrigin}/callback`}),
    `callback=${encodeURIComponent(`${originalOrigin}/callback`)}`].entries()) {
    const embeddedSpec = {...spec, kind: 'model-raw-boundary', methods: ['POST'],
      rawRequests: [{method: 'POST', path: route, as: 'anonymous', headers: [], body}],
      rawProof: {baseline: [], negative: [], closedText: '', openText: ''}};
    const embeddedFile = path.join(output, `embedded-${index}.test.mjs`);
    fs.writeFileSync(embeddedFile, newSource.replace(/^const spec=.*;$/m,
      `const spec=${JSON.stringify(embeddedSpec)};`));
    const beforeOriginal = originalHits, beforeCi = ciHits;
    const result = await execFile(process.execPath, ['--test', embeddedFile],
      {env: {NODE_TEST_CONTEXT: undefined, BYPASS_BLACKBOX_TEST_ORIGIN: ciOrigin}, timeout: 20000});
    assert.equal(result.code, 1, `an embedded original origin fails before execution: ${result.stdout} ${result.stderr}`);
    assert.match(`${result.stdout}${result.stderr}`, /cannot rebase an embedded source URL/);
    assert.equal(originalHits, beforeOriginal);
    assert.equal(ciHits, beforeCi);
  }

  const oldExpirySource = newSource.replace(
    'origin:target,expiresAt:target===source?spec.expiresAt:null,',
    'origin:target,expiresAt:null,');
  assert.notEqual(oldExpirySource, newSource);
  fs.writeFileSync(file, oldExpirySource);
  assert.deepEqual(exportRun(root, run, {out: output}).files, [file],
    'the earlier expiry behavior can be refreshed');
  assert.equal(fs.readFileSync(file, 'utf8'), newSource);

  const guardSource = oldExpirySource.replace(
    "if(process.env.CI&&!selected)throw Error('Set BYPASS_BLACKBOX_TEST_ORIGIN for CI replay.');\n", '');
  assert.notEqual(guardSource, newSource);
  fs.writeFileSync(file, guardSource);
  assert.deepEqual(exportRun(root, run, {out: output}).files, [file],
    'the prior CI wrapper can be refreshed');
  assert.equal(fs.readFileSync(file, 'utf8'), newSource);

  const priorSource = guardSource.replace(
    "  if(typeof value==='string'&&target!==source){\n    let decoded=value;\n    try{decoded=decodeURIComponent(value)}catch{}\n    if(decoded.replaceAll('\\\\/','/').includes(source))\n      throw Error('CI origin override cannot rebase an embedded source URL');\n  }\n", '');
  assert.notEqual(priorSource, newSource);
  fs.writeFileSync(file, priorSource);
  assert.deepEqual(exportRun(root, run, {out: output}).files, [file],
    'the earlier CI wrapper can be refreshed');
  assert.equal(fs.readFileSync(file, 'utf8'), newSource);

  const previousSource = priorSource.replace(
    "  targetEnvironment:['localhost','127.0.0.1','::1'].includes(new URL(target).hostname.toLowerCase())?'local':spec.targetEnvironment,\n", '');
  assert.notEqual(previousSource, newSource);
  fs.writeFileSync(file, previousSource);
  assert.deepEqual(exportRun(root, run, {out: output}).files, [file],
    'the earlier CI wrapper can also be refreshed');
  assert.equal(fs.readFileSync(file, 'utf8'), newSource);

  const oldSource = `import test from 'node:test';\nimport assert from 'node:assert/strict';\nimport {check} from './blackbox-runtime.mjs';\nconst spec=${JSON.stringify(spec)};\ntest("f-001 exposure is fixed",async()=>{\n  const result=await check(spec,process.env);\n  assert.equal(result.verdict,'not_reproduced',JSON.stringify(result));\n});\n`;
  fs.writeFileSync(file, oldSource);
  assert.deepEqual(exportRun(root, run, {out: output}).files, [file],
    'an unchanged older Bypass export can be refreshed');
  assert.equal(fs.readFileSync(file, 'utf8'), newSource);
  assert.deepEqual(exportRun(root, run, {out: output}).files, [file],
    'the refreshed export is idempotent');

  const expired = newSource.replace('"expiresAt":null',
    '"expiresAt":"2000-01-01T00:00:00.000Z"');
  assert.notEqual(expired, newSource);
  fs.writeFileSync(file, expired);
  originalVulnerable = false;
  assert.equal((await runTest(null)).code, 1, 'the original expired scope does not replay');
  const sameOrigin = await runTest(originalOrigin);
  assert.equal(sameOrigin.code, 1, 'a same-origin override cannot renew an expired proof');
  assert.match(sameOrigin.stdout + sameOrigin.stderr, /Proof scope has expired/);
  assert.equal((await runTest(ciOrigin)).code, 0,
    'the explicit CI origin is independent of the old production expiry');
  assert.throws(() => exportRun(root, run, {out: output}),
    /differs from Bypass-generated version/, 'user-edited tests are preserved');
});

test('raw boundary regression passes for a stable application rejection, not an edge block', async t => {
  const route = `/api/preview-${randomBytes(4).toString('hex')}`;
  let mode = 'vulnerable';
  const server = http.createServer(async (request, response) => {
    const chunks = [];
    for await (const chunk of request) chunks.push(chunk);
    const input = JSON.parse(Buffer.concat(chunks).toString('utf8'));
    let status = 200, type = 'application/json';
    let body = JSON.stringify({message: input.case === 'candidate' ? 'PRIVATE-RESULT' : 'Route not found'});
    if (mode === 'patched' && input.case === 'candidate') {
      status = 403;
      body = JSON.stringify({error: 'Destination rejected'});
    } else if (mode === 'edge' && input.case === 'candidate') {
      status = 403;
      type = 'text/html';
      body = '<html>Request blocked</html>';
    } else if (mode === 'outage') {
      status = 503;
      body = JSON.stringify({error: 'Unavailable'});
    } else if (mode === 'wrong-app') {
      status = 404;
      body = JSON.stringify({error: 'Unknown route'});
    }
    response.writeHead(status, {'content-type': type, 'cache-control': 'no-store'});
    response.end(body);
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  t.after(() => new Promise(resolve => server.close(resolve)));
  const origin = `http://127.0.0.1:${server.address().port}`;
  const request = variant => ({method: 'POST', path: route, as: 'anonymous',
    headers: [{name: 'content-type', value: 'application/json'}],
    body: JSON.stringify({case: variant})});
  const spec = {kind: 'model-raw-boundary', origin, include: ['/'], never: [],
    rps: 100, expiresAt: null, targetEnvironment: 'local', methods: ['POST'],
    as: 'anonymous', identities: {}, auth: 'bearer',
    rawRequests: [request('candidate')],
    rawProof: {baseline: [request('baseline')], negative: [request('negative')],
      closedText: 'Route not found', openText: 'PRIVATE-RESULT'}};
  assert.equal((await check(spec, {})).verdict, 'confirmed');
  mode = 'patched';
  assert.equal((await check(spec, {})).verdict, 'not_reproduced');
  mode = 'edge';
  assert.equal((await check(spec, {})).verdict, 'inconclusive');
  mode = 'outage';
  assert.equal((await check(spec, {})).verdict, 'inconclusive');
  mode = 'wrong-app';
  assert.equal((await check(spec, {})).verdict, 'inconclusive');

  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'bypass-current-replay-'));
  t.after(() => fs.rmSync(root, {recursive: true, force: true}));
  const run = `bx-20261103-${randomBytes(4).toString('hex')}`;
  const runDir = path.join(root, '.bypass/runs', run);
  const proofDir = path.join(runDir, 'poc/f-001');
  fs.mkdirSync(proofDir, {recursive: true});
  const specFile = path.join(proofDir, 'spec.json');
  const scriptFile = path.join(proofDir, 'poc.mjs');
  const runtimeFile = path.join(runDir, 'poc/runtime.mjs');
  fs.writeFileSync(path.join(runDir, 'run.json'), '{}');
  fs.writeFileSync(specFile, JSON.stringify(spec));
  fs.writeFileSync(scriptFile, "console.log(JSON.stringify({verdict:'confirmed'}));\n");
  fs.writeFileSync(runtimeFile, '// saved old runtime\n');
  const sealed = createLedger(runDir);
  sealed.append({step: 'poc', proof: {path: scriptFile,
    specHash: hash(fs.readFileSync(specFile)), scriptHash: hash(fs.readFileSync(scriptFile)),
    runtimeHash: hash(fs.readFileSync(runtimeFile)), verdict: 'confirmed', exitCode: 1}});
  sealed.close();
  mode = 'patched';
  assert.equal((await verifyRun(root, run, {env: {}})).proofs[0].verdict,
    'not_reproduced', 'fresh retest uses the current fixed-state oracle');
  mode = 'vulnerable';
  assert.equal((await verifyRun(root, run, {env: {}})).proofs[0].verdict, 'confirmed');
  mode = 'edge';
  assert.equal((await verifyRun(root, run, {env: {}})).proofs[0].verdict, 'inconclusive');
});

test('release replay refuses a method no longer authorized before making a request', async t => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'bypass-release-scope-'));
  t.after(() => fs.rmSync(root, {recursive: true, force: true}));
  initStore(root, root);
  const origin = `https://audit-${randomBytes(4).toString('hex')}.invalid`;
  const future = new Date(Date.now() + 60000).toISOString();
  await change(root, state => {state.targets.push({name: 'app', url: origin,
    environment: 'production', ownershipVerification: 'off',
    ownership: {status: 'acknowledged', origin, expiresAt: future},
    authorization: {origin, paths: ['/'], methods: ['GET'],
      maxRequestsPerSecond: 10, expiresAt: future}});});
  const run = `bx-20261103-${randomBytes(4).toString('hex')}`;
  const runDir = path.join(root, '.bypass/runs', run);
  const proofDir = path.join(runDir, 'poc/f-001');
  fs.mkdirSync(proofDir, {recursive: true});
  const specFile = path.join(proofDir, 'spec.json');
  const scriptFile = path.join(proofDir, 'poc.mjs');
  const runtimeFile = path.join(runDir, 'poc/runtime.mjs');
  fs.writeFileSync(path.join(runDir, 'run.json'), '{}');
  fs.writeFileSync(specFile, JSON.stringify({kind: 'model-raw-boundary', origin,
    include: ['/'], methods: ['POST'], rps: 5, expiresAt: future}));
  fs.writeFileSync(scriptFile, "console.log(JSON.stringify({verdict:'confirmed'}));\n");
  fs.writeFileSync(runtimeFile, '// sealed runtime\n');
  const ledger = createLedger(runDir);
  ledger.append({step: 'poc', proof: {path: scriptFile,
    specHash: hash(fs.readFileSync(specFile)), scriptHash: hash(fs.readFileSync(scriptFile)),
    runtimeHash: hash(fs.readFileSync(runtimeFile)), verdict: 'confirmed', exitCode: 1}});
  ledger.close();
  const replay = await verifyRun(root, run, {env: {}});
  assert.equal(replay.proofs[0].verdict, 'inconclusive');
  assert.match(replay.proofs[0].reason, /Method POST is outside the authorized scope/);
});
