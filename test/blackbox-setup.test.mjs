import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import http from 'node:http';
import path from 'node:path';
import {randomBytes} from 'node:crypto';
import {temp, cli} from './helpers.mjs';
import {change} from '../src/store.mjs';
import {execFile} from '../src/util.mjs';
import {CLI} from '../src/demo.mjs';
import {execute} from '../src/service.mjs';
import {inExecutionMode} from '../src/execution-mode.mjs';

test('scope, setup, and direct audit commands keep different deployed apps separate', async t => {
  const root=temp();
  t.after(()=>fs.rmSync(root,{recursive:true,force:true}));
  await execute('init',[root]);
  const first='https://first.example.test',second='https://second.example.test';
  const original=await execute('blackbox scope',[first],{project:root,include:'/'});
  const originalText=fs.readFileSync(original.file,'utf8');
  const setup=await execute('blackbox setup',[second],{project:root,include:'/',
    methods:'GET,HEAD,POST',rps:20});
  assert.notEqual(setup.scopeFile,original.file);
  assert.equal(JSON.parse(fs.readFileSync(setup.scopeFile,'utf8')).target.origin,second);
  assert.equal(fs.readFileSync(original.file,'utf8'),originalText);
  const permission=setup.steps.find(step=>step.kind==='authorization');
  assert.ok(permission);
  await execute('target authorize',[permission.target],{project:root,'scope-file':permission.file,
    accept:true});
  const ready=await execute('blackbox setup',[second],{project:root,include:'/',
    methods:'GET,HEAD,POST',rps:20});
  assert.equal(ready.ready,true);
  await assert.rejects(execute('blackbox',['https://third.example.test'],{project:root}),
    /No reviewed scope exists.*blackbox setup/);
  assert.equal(fs.readFileSync(original.file,'utf8'),originalText);
});

test('a fresh blackbox project reaches the Meta default preflight without project state', async t => {
  const root = temp();
  t.after(() => fs.rmSync(root, {recursive: true, force: true}));
  const result = await execFile(process.execPath, [CLI, 'model', 'test', '--project', root,
    '--json', '--non-interactive'], {cwd: root, timeout: 10000,
    env: {META_API_KEY: '', MODEL_API_KEY: ''}});
  const data = JSON.parse(result.stdout);
  assert.equal(result.code, 3, result.stderr);
  assert.match(data.error, /MODEL_API_KEY/);
  assert.doesNotMatch(data.error, /No Bypass project/);
  assert.ok(!fs.existsSync(path.join(root, '.bypass/state.json')));
});

test('a fresh plugin project keeps model checks in the active Muse session', async t => {
  const root = temp();
  t.after(() => fs.rmSync(root, {recursive: true, force: true}));
  const previousMeta = process.env.META_API_KEY;
  const previousModel = process.env.MODEL_API_KEY;
  process.env.META_API_KEY = '';
  process.env.MODEL_API_KEY = '';
  t.after(() => {
    if (previousMeta === undefined) delete process.env.META_API_KEY;
    else process.env.META_API_KEY = previousMeta;
    if (previousModel === undefined) delete process.env.MODEL_API_KEY;
    else process.env.MODEL_API_KEY = previousModel;
  });
  const result = await inExecutionMode('muse-host', () =>
    execute('model test', [], {project: root}));
  assert.equal(result.ai.mode, 'muse-host');
  assert.equal(result.ai.independentModelRequests, 0);
  assert.ok(!fs.existsSync(path.join(root, '.bypass/state.json')));
});

test('the terminal model check reaches Meta preflight from a fresh blackbox folder',
  {skip: process.platform !== 'linux' || !fs.existsSync('/usr/bin/script')}, async t => {
    const root = temp();
    t.after(() => fs.rmSync(root, {recursive: true, force: true}));
    const quote = value => `'${String(value).replaceAll("'", "'\\''")}'`;
    const command = `${quote(process.execPath)} ${quote(CLI)} model test --project ${quote(root)}`;
    const result = await execFile('script', ['-q', '-e', '-c', command, '/dev/null'],
      {cwd: root, timeout: 10000, env: {META_API_KEY: '', MODEL_API_KEY: ''}});
    assert.equal(result.code, 3, result.stdout.slice(-1200));
    assert.match(result.stdout, /MODEL_API_KEY/);
    assert.ok(!result.stdout.includes('Cannot read Bypass state'));
    assert.ok(!fs.existsSync(path.join(root, '.bypass/state.json')));
  });

test('one blackbox setup command prepares a local scope that the real CLI can audit', async t => {
  const root = temp();
  t.after(() => fs.rmSync(root, {recursive: true, force: true}));
  const suffix = randomBytes(4).toString('hex');
  const resetPath = `/api/reset-${suffix}`;
  const readPath = `/api/execute-preview-${suffix}`;
  const decoyPath = `/api/account/logout`;
  const nestedDecoyPath = `/api/delete/${suffix}`;
  const hits = [];
  const server = http.createServer((request, response) => {
    const url = new URL(request.url, 'http://local');
    hits.push(`${request.method} ${url.pathname}`);
    if (url.pathname === '/openapi.json') {
      response.writeHead(200, {'content-type': 'application/json'});
      response.end(JSON.stringify({openapi: '3.0.0', paths: {
        '/api/go': {get: {parameters: [{name: 'next', in: 'query'}]}},
        [resetPath]: {get: {parameters: [{name: 'next', in: 'query'}]}},
        [readPath]: {get: {parameters: [{name: 'next', in: 'query'}]}},
        [decoyPath]: {get: {}}, [nestedDecoyPath]: {get: {}}}}));
    } else if (url.pathname === '/api/go') {
      const destination = url.searchParams.get('next') ?? '/';
      if (/[\r\n]/.test(destination)) {response.writeHead(400); response.end(); return;}
      response.writeHead(302, {location: destination});
      response.end();
    } else if (url.pathname === resetPath || url.pathname === readPath) {
      response.writeHead(200, {'content-type': 'application/json'});
      response.end('{"status":"ok"}');
    } else if (url.pathname === decoyPath || url.pathname === nestedDecoyPath) {
      response.writeHead(200, {'content-type': 'application/json'});
      response.end('{"sideEffect":"logout"}');
    } else {response.writeHead(404); response.end();}
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  t.after(() => new Promise(resolve => server.close(resolve)));
  const origin = `http://127.0.0.1:${server.address().port}`;
  const setup = await cli(root, 'blackbox', 'setup', origin, '--include', '/api',
    '--model-calls', '97', '--agents', '5', '--http-workers', '6');
  assert.equal(setup.code, 0, JSON.stringify(setup.data));
  assert.equal(setup.data.kind, 'blackbox-setup');
  assert.equal(setup.data.ready, true);
  assert.equal(setup.data.steps.length, 1);
  assert.match(setup.data.modelCheck, /bypass model test --project/);
  assert.ok(fs.existsSync(setup.data.scopeFile));
  const preparedScope = JSON.parse(fs.readFileSync(setup.data.scopeFile, 'utf8'));
  assert.deepEqual(preparedScope.never, []);
  assert.equal(preparedScope.limits.modelCalls, 97);
  assert.equal(preparedScope.limits.modelConcurrency, 5);
  assert.equal(preparedScope.limits.agents, 6);
  assert.ok(!fs.existsSync(path.join(root, '.bypass/state.json')));
  const audit = await cli(root, 'blackbox', origin, '--no-model', '--model-calls', '125',
    '--agents', '9', '--http-workers', '3',
    '--max-urls', '0', '--max-tasks', '850', '--minutes', '41', '--dom-script-bytes', '16777216');
  assert.equal(audit.code, 1, JSON.stringify(audit.data));
  assert.equal(JSON.parse(fs.readFileSync(path.join(audit.data.runDir, 'run.json'), 'utf8'))
    .scope.limits.modelCalls, 125);
  assert.equal(JSON.parse(fs.readFileSync(path.join(audit.data.runDir, 'run.json'), 'utf8'))
    .scope.limits.modelConcurrency, 9, '--agents controls Muse concurrency');
  assert.equal(JSON.parse(fs.readFileSync(path.join(audit.data.runDir, 'run.json'), 'utf8'))
    .scope.limits.agents, 3, '--http-workers independently controls HTTP concurrency');
  assert.equal(JSON.parse(fs.readFileSync(path.join(audit.data.runDir, 'run.json'), 'utf8'))
    .scope.limits.maxUrls, 0);
  assert.equal(JSON.parse(fs.readFileSync(path.join(audit.data.runDir, 'run.json'), 'utf8'))
    .scope.limits.tasks, 850);
  assert.equal(JSON.parse(fs.readFileSync(path.join(audit.data.runDir, 'run.json'), 'utf8'))
    .scope.limits.minutes, 41);
  assert.equal(JSON.parse(fs.readFileSync(path.join(audit.data.runDir, 'run.json'), 'utf8'))
    .scope.limits.domScriptBytes, 16777216);
  assert.equal(JSON.parse(fs.readFileSync(setup.data.scopeFile, 'utf8'))
    .limits.modelCalls, 97, 'the per-run inference budget does not rewrite reviewed scope');
  assert.equal(JSON.parse(fs.readFileSync(setup.data.scopeFile, 'utf8'))
    .limits.modelConcurrency, 5, 'the per-run Muse agent count does not rewrite reviewed scope');
  assert.equal(JSON.parse(fs.readFileSync(setup.data.scopeFile, 'utf8'))
    .limits.agents, 6, 'the per-run HTTP worker count does not rewrite reviewed scope');
  assert.equal(JSON.parse(fs.readFileSync(setup.data.scopeFile, 'utf8'))
    .limits.maxUrls, 400, 'the per-run URL cap does not rewrite reviewed scope');
  assert.equal(JSON.parse(fs.readFileSync(setup.data.scopeFile, 'utf8'))
    .limits.tasks, 0, 'new scopes have no task-count cap');
  assert.equal(JSON.parse(fs.readFileSync(setup.data.scopeFile, 'utf8'))
    .limits.domScriptBytes, 2097152, 'the per-run script byte cap does not rewrite reviewed scope');
  assert.ok(audit.data.findings.some(item => item.kind === 'open-redirect'));
  assert.ok(hits.includes(`GET ${resetPath}`), `a random reset GET enters the audit: ${JSON.stringify(hits)}`);
  assert.ok(hits.includes(`GET ${readPath}`), `a random read-only execute GET enters the audit: ${JSON.stringify(hits)}`);
  const auditEvidence = fs.readFileSync(path.join(audit.data.runDir, 'evidence.jsonl'), 'utf8')
    .trim().split('\n').map(line => JSON.parse(line));
  assert.ok(auditEvidence.some(item => item.step === 'task' &&
    item.request?.url?.includes(resetPath)), 'the reset route received an actual task probe');
  assert.ok(auditEvidence.some(item => item.step === 'task' &&
    item.request?.url?.includes(readPath)), 'the read-only execute route received an actual task probe');
  assert.ok(!hits.includes(`GET ${decoyPath}`), 'a mutating GET decoy is not requested');
  assert.ok(!hits.includes(`GET ${nestedDecoyPath}`), 'an action followed by an ID is not requested');
  const directRoot = temp();
  t.after(() => fs.rmSync(directRoot, {recursive: true, force: true}));
  assert.ok(!fs.existsSync(path.join(directRoot, 'blackbox.scope.json')));
  const direct = await cli(directRoot, 'blackbox', origin, '--rps', '5',
    '--model-calls', '71', '--agents', '7', '--http-workers', '4',
    '--max-urls', '0', '--dom-script-bytes', '16777216', '--no-model');
  assert.equal(direct.code, 1, JSON.stringify(direct.data));
  assert.ok(direct.data.findings.some(item => item.kind === 'open-redirect'));
  const generated = JSON.parse(fs.readFileSync(path.join(directRoot, 'blackbox.scope.json'), 'utf8'));
  assert.deepEqual(generated.include, ['/']);
  assert.deepEqual(generated.never, []);
  assert.equal(generated.target.origin, origin);
  assert.equal(generated.limits.modelCalls, 71);
  assert.equal(generated.limits.modelConcurrency, 7);
  assert.equal(generated.limits.agents, 4);
  assert.equal(generated.limits.maxUrls, 0);
  assert.equal(generated.limits.domScriptBytes, 16777216);
  const effective = JSON.parse(fs.readFileSync(path.join(direct.data.runDir, 'run.json'), 'utf8'));
  assert.equal(effective.scope.limits.rps, 5);
  assert.equal(effective.scope.limits.modelCalls, 71);
  assert.equal(effective.scope.limits.modelConcurrency, 7);
  assert.equal(effective.scope.limits.agents, 4);
  assert.equal(effective.scope.limits.maxUrls, 0);
  assert.equal(effective.scope.limits.domScriptBytes, 16777216);
  const acceptedRoot = temp();
  t.after(() => fs.rmSync(acceptedRoot, {recursive: true, force: true}));
  const accepted = await cli(acceptedRoot, 'blackbox', origin, '--accept-local', '--rps', '5', '--no-model');
  assert.equal(accepted.code, 1, JSON.stringify(accepted.data));
  const acceptedScope = JSON.parse(fs.readFileSync(path.join(acceptedRoot, 'blackbox.scope.json'), 'utf8'));
  assert.equal(acceptedScope.target.origin, origin);
  assert.equal(acceptedScope.limits.minutes, 30);

  const excludedRoot = temp();
  t.after(() => fs.rmSync(excludedRoot, {recursive: true, force: true}));
  const excludedSetup = await cli(excludedRoot, 'blackbox', 'setup', origin,
    '--include', '/api', '--never', resetPath);
  assert.equal(excludedSetup.code, 0, JSON.stringify(excludedSetup.data));
  hits.length = 0;
  const excludedAudit = await cli(excludedRoot, 'blackbox', origin, '--no-model');
  assert.equal(excludedAudit.code, 1, JSON.stringify(excludedAudit.data));
  assert.ok(!hits.includes(`GET ${resetPath}`), 'an explicit never route stays untouched');
  assert.ok(hits.includes(`GET ${readPath}`), 'other in-scope read routes remain testable');
  assert.ok(!hits.includes(`GET ${decoyPath}`), 'the mutating GET decoy stays untouched');
  assert.ok(!hits.includes(`GET ${nestedDecoyPath}`), 'the nested mutating GET decoy stays untouched');
});

test('setup and scope accept rate, Muse calls and recon byte budgets without editing JSON', async t => {
  const root = temp();
  t.after(() => fs.rmSync(root, {recursive: true, force: true}));
  const setup = await cli(root, 'blackbox', 'setup', 'http://127.0.0.1:4329',
    '--rps', '7', '--model-calls', '123', '--max-urls', '450',
    '--minutes', '42',
    '--dom-script-bytes', '16777216');
  assert.equal(setup.code, 0, JSON.stringify(setup.data));
  const scope = JSON.parse(fs.readFileSync(setup.data.scopeFile, 'utf8'));
  assert.deepEqual(scope.include, ['/']);
  assert.equal(scope.limits.rps, 7);
  assert.equal(scope.limits.modelCalls, 123);
  assert.equal(scope.limits.maxUrls, 450);
  assert.equal(scope.limits.minutes, 42);
  assert.equal(scope.limits.domScriptBytes, 16777216);
  const reused = await cli(root, 'blackbox', 'setup', 'http://127.0.0.1:4329',
    '--model-calls', '123', '--max-urls', '450', '--minutes', '42', '--dom-script-bytes', '16777216');
  assert.equal(reused.code, 0, JSON.stringify(reused.data));
  const customCalls = await cli(root, 'blackbox', 'setup', 'http://127.0.0.1:4329', '--model-calls', '240');
  assert.equal(customCalls.code, 0, JSON.stringify(customCalls.data));
  assert.match(customCalls.data.next, /--model-calls 240$/);
  assert.equal(JSON.parse(fs.readFileSync(customCalls.data.scopeFile, 'utf8')).limits.modelCalls, 123);
  const customMinutes = await cli(root, 'blackbox', 'setup', 'http://127.0.0.1:4329', '--minutes', '45');
  assert.equal(customMinutes.code, 0, JSON.stringify(customMinutes.data));
  assert.match(customMinutes.data.next, /--minutes 45$/);
  assert.equal(JSON.parse(fs.readFileSync(customMinutes.data.scopeFile, 'utf8')).limits.minutes, 42);
  const slower = await cli(root, 'blackbox', 'setup', 'http://127.0.0.1:4329', '--rps', '3');
  assert.equal(slower.code, 0, JSON.stringify(slower.data));
  assert.equal(slower.data.created, false);
  assert.match(slower.data.next, /--rps 3$/);
  assert.equal(JSON.parse(fs.readFileSync(slower.data.scopeFile, 'utf8')).limits.rps, 7);
  const faster = await cli(root, 'blackbox', 'setup', 'http://127.0.0.1:4329', '--rps', '8');
  assert.equal(faster.code, 0, JSON.stringify(faster.data));
  assert.equal(faster.data.updated, true);
  const raisedScope = JSON.parse(fs.readFileSync(faster.data.scopeFile, 'utf8'));
  assert.equal(raisedScope.limits.rps, 8);
  assert.equal(raisedScope.limits.modelCalls, 123);
  assert.equal(raisedScope.limits.maxUrls, 450);
  assert.equal(raisedScope.limits.domScriptBytes, 16777216);
  assert.equal(raisedScope.limits.minutes, 42);
  const invalidRate = await cli(root, 'blackbox', 'setup', 'http://127.0.0.1:4329', '--rps', '-1');
  assert.notEqual(invalidRate.code, 0);
  const mismatch = await cli(root, 'blackbox', 'setup', 'http://127.0.0.1:4329',
    '--model-calls', '124', '--max-urls', '451');
  assert.notEqual(mismatch.code, 0);
  const scopeRoot = temp();
  t.after(() => fs.rmSync(scopeRoot, {recursive: true, force: true}));
  const scopeOnly = await cli(scopeRoot, 'blackbox', 'scope', 'http://127.0.0.1:4329',
    '--model-calls', '85', '--max-urls', '0', '--minutes', '12', '--dom-script-bytes', '1048576');
  assert.equal(scopeOnly.code, 0, JSON.stringify(scopeOnly.data));
  assert.equal(JSON.parse(fs.readFileSync(scopeOnly.data.file, 'utf8')).limits.modelCalls, 85);
  assert.equal(JSON.parse(fs.readFileSync(scopeOnly.data.file, 'utf8')).limits.maxUrls, 0);
  assert.equal(JSON.parse(fs.readFileSync(scopeOnly.data.file, 'utf8')).limits.minutes, 12);
  assert.equal(JSON.parse(fs.readFileSync(scopeOnly.data.file, 'utf8')).limits.domScriptBytes, 1048576);
  const invalid = await cli(scopeRoot, 'blackbox', 'scope', 'http://127.0.0.1:4329',
    '--model-calls', '1.5', '--force');
  assert.notEqual(invalid.code, 0);
  const invalidUrls = await cli(scopeRoot, 'blackbox', 'scope', 'http://127.0.0.1:4329',
    '--max-urls', '-1', '--force');
  assert.notEqual(invalidUrls.code, 0);
  const invalidScriptBytes = await cli(scopeRoot, 'blackbox', 'scope', 'http://127.0.0.1:4329',
    '--dom-script-bytes', '16777217', '--force');
  assert.notEqual(invalidScriptBytes.code, 0);
  const invalidMinutes = await cli(scopeRoot, 'blackbox', 'scope', 'http://127.0.0.1:4329',
    '--minutes', '0', '--force');
  assert.notEqual(invalidMinutes.code, 0);
});

test('local and deployed setup retain explicit exclusions without adding hidden path-word rules', async t => {
  const localRoot = temp(), deployedRoot = temp();
  t.after(() => {fs.rmSync(localRoot, {recursive: true, force: true});
    fs.rmSync(deployedRoot, {recursive: true, force: true});});
  const local = await cli(localRoot, 'blackbox', 'setup', 'http://127.0.0.1:4329',
    '--never', '/api/unsafe');
  assert.equal(local.code, 0, JSON.stringify(local.data));
  const localNever = JSON.parse(fs.readFileSync(local.data.scopeFile, 'utf8')).never;
  assert.ok(localNever.includes('/api/unsafe'));
  assert.deepEqual(localNever, ['/api/unsafe']);
  const deployed = await cli(deployedRoot, 'blackbox', 'setup', 'https://app.example.test');
  assert.equal(deployed.code, 0, JSON.stringify(deployed.data));
  assert.deepEqual(JSON.parse(fs.readFileSync(deployed.data.scopeFile, 'utf8')).never, []);
});

test('deployed setup and authorization accept an operator-selected rate up to 32 RPS', async t => {
  const root = temp();
  t.after(() => fs.rmSync(root, {recursive: true, force: true}));
  const origin = 'https://app.example.test';
  const first = await cli(root, 'blackbox', 'setup', origin, '--rps', '12');
  assert.equal(first.code, 0, JSON.stringify(first.data));
  assert.equal(JSON.parse(fs.readFileSync(first.data.scopeFile, 'utf8')).limits.rps, 12);
  const raised = await cli(root, 'blackbox', 'setup', origin, '--rps', '32');
  assert.equal(raised.code, 0, JSON.stringify(raised.data));
  assert.equal(JSON.parse(fs.readFileSync(raised.data.scopeFile, 'utf8')).limits.rps, 32);
  const step = raised.data.steps.find(item => item.kind === 'authorization');
  assert.equal(JSON.parse(fs.readFileSync(step.file, 'utf8')).maxRequestsPerSecond, 32);
  const expiry = new Date(Date.now() + 86400000).toISOString();
  await change(root, state => {
    state.targets[0].ownership = {status: 'verified', method: 'dns', expiresAt: expiry,
      origin};
  });
  const approved = await cli(root, 'target', 'authorize', step.target, '--scope-file', step.file, '--accept');
  assert.equal(approved.code, 0, JSON.stringify(approved.data));
  assert.equal(approved.data.authorization.maxRequestsPerSecond, 32);
  const ready = await cli(root, 'blackbox', 'setup', origin, '--rps', '32');
  assert.equal(ready.code, 0, JSON.stringify(ready.data));
  assert.equal(ready.data.ready, true);
  const tooFast = await cli(root, 'blackbox', 'setup', origin, '--rps', '33');
  assert.notEqual(tooFast.code, 0);
  assert.match(tooFast.data.error, /at most 32/);
  assert.equal(JSON.parse(fs.readFileSync(raised.data.scopeFile, 'utf8')).limits.rps, 32);
});

test('deployed blackbox setup prepares separate app and apex challenges without authorizing them', async t => {
  const root = temp();
  t.after(() => fs.rmSync(root, {recursive: true, force: true}));
  await cli(root, 'init');
  await cli(root, 'config', 'set', 'ownershipVerification', 'dns');
  const origin = 'https://app.example.test';
  const args = ['blackbox', 'setup', origin, '--include', '/api', '--domains', 'example.test',
    '--audit-domains', 'example.test'];
  const first = await cli(root, ...args);
  assert.equal(first.code, 0, JSON.stringify(first.data));
  assert.equal(first.data.ready, false);
  assert.equal(first.data.targets.length, 2);
  const app = first.data.targets.find(target => target.url === origin);
  const apex = first.data.targets.find(target => target.url === 'https://example.test');
  assert.ok(app && apex);
  assert.notEqual(app.challenge.token, apex.challenge.token);
  assert.equal(app.challenge.record, '_bypass-verification.app.example.test');
  assert.equal(apex.challenge.record, '_bypass-verification.example.test');
  assert.equal(first.data.steps.filter(step => step.kind === 'ownership').length, 2);
  assert.equal(first.data.steps.filter(step => step.kind === 'authorization').length, 2);
  const state = JSON.parse(fs.readFileSync(path.join(root, '.bypass/state.json'), 'utf8'));
  assert.ok(state.targets.every(target => target.ownership.status === 'pending' && target.authorization === null));
  for (const step of first.data.steps.filter(item => item.kind === 'authorization')) {
    const allowed = JSON.parse(fs.readFileSync(step.file, 'utf8'));
    assert.deepEqual(allowed.paths, ['/api']);
    assert.deepEqual(allowed.methods, ['GET', 'HEAD', 'POST', 'PATCH', 'DELETE']);
    assert.equal(allowed.productionAcknowledged, false);
  }
  const blocked = await cli(root, 'blackbox', origin, '--scope', first.data.scopeFile, '--no-model');
  assert.equal(blocked.code, 3, JSON.stringify(blocked.data));
  const resumed = await cli(root, ...args);
  assert.equal(resumed.code, 0);
  assert.equal(resumed.data.created, false);
  assert.deepEqual(resumed.data.targets.map(target => target.challenge.token),
    first.data.targets.map(target => target.challenge.token));
  const expiry = new Date(Date.now() + 86400000).toISOString();
  await change(root, state => {
    for (const target of state.targets) target.ownership =
      {status: 'verified', method: 'dns', expiresAt: expiry, origin: target.url};
    return null;
  });
  for (const step of first.data.steps.filter(item => item.kind === 'authorization')) {
    const approved = await cli(root, 'target', 'authorize', step.target, '--scope-file', step.file);
    assert.equal(approved.code, 0, JSON.stringify(approved.data));
  }
  const ready = await cli(root, ...args);
  assert.equal(ready.code, 0);
  assert.equal(ready.data.ready, true);
  assert.deepEqual(ready.data.steps.map(step => step.kind), ['run']);
  const reviewed = JSON.parse(fs.readFileSync(first.data.scopeFile, 'utf8'));
  reviewed.probes.xmlExternalEntity = true;
  reviewed.probes.xmlPostPaths = ['/api/xml/import'];
  fs.writeFileSync(first.data.scopeFile, JSON.stringify(reviewed));
  const expanded = await cli(root, ...args);
  assert.equal(expanded.code, 0);
  assert.equal(expanded.data.ready, true,
    'an already authorized POST method does not need another route authorization');
});

test('setup prepares an extra credential origin with its own ownership and authorization steps', async t => {
  const root = temp();
  t.after(() => fs.rmSync(root, {recursive: true, force: true}));
  await cli(root, 'init');
  await cli(root, 'config', 'set', 'ownershipVerification', 'dns');
  const origin = 'https://app.example.test';
  const secondary = 'https://api.example.test';
  const args = ['blackbox', 'setup', origin, '--include', '/api', '--domains', 'example.test',
    '--audit-domains', 'example.test', '--credential-origins', secondary];
  const first = await cli(root, ...args);
  assert.equal(first.code, 0, JSON.stringify(first.data));
  assert.deepEqual(first.data.credentialOrigins, [origin, secondary]);
  assert.deepEqual(JSON.parse(fs.readFileSync(first.data.scopeFile, 'utf8')).credentialOrigins,
    [origin, secondary]);
  const target = first.data.targets.find(item => item.url === secondary);
  assert.ok(target?.challenge);
  assert.equal(first.data.targets.length, 3);
  assert.equal(first.data.steps.filter(item => item.kind === 'ownership').length, 3);
  const authorization = first.data.steps.find(item => item.kind === 'authorization' &&
    item.target === target.name);
  assert.ok(authorization?.file);
  assert.deepEqual(JSON.parse(fs.readFileSync(authorization.file, 'utf8')).paths, ['/api']);
  const repeated = await cli(root, ...args);
  assert.equal(repeated.code, 0, JSON.stringify(repeated.data));
  assert.equal(repeated.data.created, false);
  assert.equal(repeated.data.targets.find(item => item.url === secondary).challenge.token,
    target.challenge.token);
  const expiry = new Date(Date.now() + 86400000).toISOString();
  await change(root, state => {
    for (const item of state.targets) item.ownership =
      {status: 'verified', method: 'dns', expiresAt: expiry, origin: item.url};
    return null;
  });
  for (const step of first.data.steps.filter(item => item.kind === 'authorization')) {
    const approved = await cli(root, 'target', 'authorize', step.target, '--scope-file', step.file);
    assert.equal(approved.code, 0, JSON.stringify(approved.data));
  }
  assert.equal((await cli(root, ...args)).data.ready, true);
  const reviewed = JSON.parse(fs.readFileSync(first.data.scopeFile, 'utf8'));
  reviewed.identities.login = {path: '/api/auth/login', usernameField: 'email',
    passwordField: 'password', encoding: 'json'};
  fs.writeFileSync(first.data.scopeFile, JSON.stringify(reviewed));
  const loginSetup = await cli(root, ...args);
  assert.equal(loginSetup.code, 0, JSON.stringify(loginSetup.data));
  const loginSteps = loginSetup.data.steps.filter(item => item.kind === 'authorization');
  assert.deepEqual(loginSteps.map(item => item.target).sort(),
    first.data.targets.filter(item => item.url === origin || item.url === secondary)
      .map(item => item.name).sort());
  for (const step of loginSteps) assert.deepEqual(
    JSON.parse(fs.readFileSync(step.file, 'utf8')).loginPaths, ['/api/auth/login']);
  const changed = await cli(root, 'blackbox', 'setup', origin, '--include', '/api',
    '--domains', 'example.test', '--audit-domains', 'example.test',
    '--credential-origins', 'https://other.example.test');
  assert.equal(changed.code, 2);
});

test('scope command writes explicit credential origins without contacting or registering them', async t => {
  const root = temp();
  t.after(() => fs.rmSync(root, {recursive: true, force: true}));
  const primary = 'https://app.example.test';
  const secondary = 'https://api.example.test';
  const prepared = await cli(root, 'blackbox', 'scope', primary,
    '--credential-origins', `${primary},${secondary}`);
  assert.equal(prepared.code, 0, JSON.stringify(prepared.data));
  assert.deepEqual(prepared.data.credentialOrigins, [primary, secondary]);
  assert.deepEqual(JSON.parse(fs.readFileSync(prepared.data.file, 'utf8')).credentialOrigins,
    [primary, secondary]);
  assert.ok(!fs.existsSync(path.join(root, '.bypass/state.json')));
});

test('production blackbox setup carries explicit acknowledgment into its reviewed scope authorization', async t => {
  const root = temp();
  t.after(() => fs.rmSync(root, {recursive: true, force: true}));
  const prepared = await cli(root, 'blackbox', 'setup', 'https://prod.example.test',
    '--environment', 'production', '--include', '/api', '--rps', '12',
    '--methods', 'GET,HEAD,POST,PATCH,DELETE');
  assert.equal(prepared.code, 0, JSON.stringify(prepared.data));
  const scope = JSON.parse(fs.readFileSync(prepared.data.scopeFile, 'utf8'));
  assert.equal(scope.target.environment, 'production');
  const step = prepared.data.steps.find(item => item.kind === 'authorization');
  assert.equal(step.production, true);
  assert.equal(JSON.parse(fs.readFileSync(step.file, 'utf8')).productionAcknowledged, false);
  await change(root, state => {
    state.targets[0].ownership = {status: 'verified', method: 'dns',
      expiresAt: new Date(Date.now() + 86400000).toISOString(),
      origin: state.targets[0].url};
    return null;
  });
  const withoutAcknowledgment = await cli(root, 'target', 'authorize', step.target,
    '--scope-file', step.file, '--accept');
  assert.notEqual(withoutAcknowledgment.code, 0);
  assert.match(withoutAcknowledgment.data.error, /productionAcknowledged/);
  const approved = await cli(root, 'target', 'authorize', step.target,
    '--scope-file', step.file, '--accept', '--production');
  assert.equal(approved.code, 0, JSON.stringify(approved.data));
  assert.deepEqual(approved.data.authorization.methods,
    ['GET', 'HEAD', 'POST', 'PATCH', 'DELETE']);
  assert.equal(approved.data.authorization.maxRequestsPerSecond, 12);
  assert.equal(approved.data.authorization.productionAcknowledged, true);
  assert.equal(JSON.parse(fs.readFileSync(step.file, 'utf8')).productionAcknowledged,
    false, 'the reviewed template stays unchanged');
  const ready = await cli(root, 'blackbox', 'setup', 'https://prod.example.test',
    '--environment', 'production', '--include', '/api', '--rps', '12',
    '--methods', 'GET,HEAD,POST,PATCH,DELETE');
  assert.equal(ready.data.ready, true, JSON.stringify(ready.data));
});

test('blackbox setup rejects malformed scope before registering a target', async t => {
  const root = temp();
  t.after(() => fs.rmSync(root, {recursive: true, force: true}));
  const bad = await cli(root, 'blackbox', 'setup', 'https://app.example.test',
    '--domains', 'example.test/child');
  assert.equal(bad.code, 2);
  assert.ok(!fs.existsSync(path.join(root, '.bypass/state.json')));
  assert.ok(!fs.existsSync(path.join(root, 'blackbox.scope.json')));
});
