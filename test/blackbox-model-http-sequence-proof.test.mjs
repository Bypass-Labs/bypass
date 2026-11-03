import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import http from 'node:http';
import path from 'node:path';
import {randomBytes} from 'node:crypto';
import {spawn} from 'node:child_process';
import {temp} from './helpers.mjs';
import {DEFAULT_SCOPE, validateUrl} from '../src/blackbox/scope.mjs';
import {createLedger} from '../src/blackbox/ledger.mjs';
import {proveFindings, verifyRun, exportRun} from '../src/blackbox/poc.mjs';
import {check, createSequenceCookies, validModelHttpSequence} from '../src/blackbox/poc-runtime.mjs';
import {validateResearchFlow} from '../src/blackbox/research-flow.mjs';
import {execFile, hash} from '../src/util.mjs';

const firstMarker = 'bx0123456789ab';
const secondMarker = 'bxabcdef012345';
const encoded = marker => `hex:${Buffer.from(marker).toString('hex')}`;

test('sequence cookies follow their origin and path and do not replace explicit values', () => {
  const jar = createSequenceCookies();
  const name = `session_${randomBytes(4).toString('hex')}`;
  const value = randomBytes(12).toString('hex');
  const source = 'https://app.example.test/flow/start';
  jar.remember([`${name}=${value}; Path=/flow; Secure; HttpOnly`], source);
  assert.equal(jar.header('https://app.example.test/flow/next'), `${name}=${value}`);
  assert.equal(jar.header('https://app.example.test/other'), '');
  assert.equal(jar.header('http://app.example.test/flow/next'), '');
  assert.equal(jar.header('https://other.example.test/flow/next'), '');
  assert.equal(jar.header('https://app.example.test/flow/next', `${name}=explicit`),
    `${name}=explicit`);
  jar.remember([`${name}=; Path=/flow; Max-Age=0`], source);
  assert.equal(jar.header('https://app.example.test/flow/next'), '');
});

test('a novel scoped GET key can replay an independently controlled owner-body proof', async t => {
  const suffix = Math.random().toString(16).slice(2, 10);
  const protectedPath = `/private/${suffix}`;
  const publicPath = `/public/${suffix}`;
  const novelKey = `probe_${suffix}`;
  const ownerBody = `Owner-only export ${suffix}. `.repeat(6);
  let vulnerable = true;
  const server = http.createServer((request, response) => {
    const url = new URL(request.url, 'http://fixture.invalid');
    response.setHeader('content-type', 'text/plain');
    response.setHeader('cache-control', 'no-store');
    if (url.pathname === protectedPath) {
      if (request.headers.authorization !== 'Bearer fixture-owner') {
        response.statusCode = 403;
        return response.end('Owner only');
      }
      return response.end(ownerBody);
    }
    if (url.pathname === publicPath) {
      const value = url.searchParams.get(novelKey);
      return response.end(vulnerable && ['all', 'archive'].includes(value) ?
        ownerBody : `Public preview ${value ?? 'none'}`);
    }
    response.statusCode = 404;
    response.end('Missing');
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  t.after(() => new Promise(resolve => server.close(resolve)));
  const origin = `http://127.0.0.1:${server.address().port}`;
  const spec = {kind: 'model-access-boundary', comparison: 'exact-body', origin,
    include: ['/'], never: [], rps: 100, targetEnvironment: 'local',
    identities: {owner: 'OWNER_TOKEN'}, auth: 'bearer',
    protectedPath, subject: {method: 'GET', path: publicPath,
      placement: 'query', key: novelKey, fixedFields: []},
    controlValue: 'plain', firstValue: 'all', secondValue: 'archive',
    reviewedGetInputs: [{path: publicPath, parameters: []}],
    queryKeySource: 'muse-hypothesis'};
  const env = {OWNER_TOKEN: 'fixture-owner'};
  const proved = await check(spec, env);
  assert.equal(proved.verdict, 'confirmed', JSON.stringify(proved));
  assert.equal((await check({...spec, reviewedGetInputs: []}, env)).verdict,
    'inconclusive');
  vulnerable = false;
  assert.equal((await check(spec, env)).verdict, 'not_reproduced');
});

test('a generated HTTP sequence proof replays a reviewed POST and becomes a passing regression after repair', async t => {
  const project = temp();
  const run = 'bx-20261028-1234abcd';
  const dir = path.join(project, '.bypass/runs', run);
  fs.mkdirSync(dir, {recursive: true});
  fs.writeFileSync(path.join(dir, 'run.json'), '{}');
  t.after(() => fs.rmSync(project, {recursive: true, force: true}));
  const calls = [];
  let transformed = true;
  let last = 'none';
  const server = http.createServer(async (request, response) => {
    const url = new URL(request.url, 'http://fixture');
    calls.push(`${request.method} ${url.pathname}`);
    const json = (status, data, headers = {}) => {
      response.writeHead(status, {'content-type': 'application/json', 'cache-control': 'no-store', ...headers});
      response.end(JSON.stringify(data));
    };
    if (url.pathname === '/api/prepare' && request.method === 'GET')
      return json(200, {ready: true, padding: 'x'.repeat(20 * 1024)});
    if (url.pathname === '/api/process' && request.method === 'POST') {
      const chunks = [];
      for await (const chunk of request) chunks.push(chunk);
      const value = JSON.parse(Buffer.concat(chunks).toString()).code;
      last = transformed && value.startsWith('hex:') ?
        Buffer.from(value.slice(4), 'hex').toString('utf8') : value;
      return json(200, {accepted: true});
    }
    if (url.pathname === '/api/state' && request.method === 'GET')
      return json(200, {ready: true, padding: 'x'.repeat(20 * 1024)}, {location: last});
    return json(404, {error: 'missing'});
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  t.after(() => new Promise(resolve => server.close(resolve)));
  const origin = `http://127.0.0.1:${server.address().port}`;
  const scope = structuredClone(DEFAULT_SCOPE);
  scope.target.origin = origin;
  scope.credentialOrigins = [origin];
  scope.probes.jsonPostPaths = ['/api/process'];
  const webProof = {kind: 'model-http-sequence', as: 'anonymous',
    prelude: [{method: 'GET', path: '/api/prepare', headers: []}],
    subject: {method: 'POST', path: '/api/process', placement: 'json', key: 'code',
      fixedFields: [], bodyTemplate: '', headers: []},
    observe: [{method: 'GET', path: '/api/state', headers: []}],
    controlValue: 'plain', firstValue: encoded(firstMarker),
    secondValue: encoded(secondMarker), marker: firstMarker, secondMarker,
    assertion: {step: 'observe', index: 0, location: 'header', name: 'location'}};
  const finding = {id: 'f-001', kind: 'model-http-sequence', pattern: '/api/process',
    url: `${origin}/api/process`, confirmation: [], webProof};
  const ledger = createLedger(dir);
  const proved = await proveFindings([finding], [], {runDir: dir, surface: {patterns: []},
    scope, env: {}, ledger, web: {results: []}});
  assert.equal(proved.length, 1);
  const spec = JSON.parse(fs.readFileSync(path.join(dir, 'poc/f-001/spec.json'), 'utf8'));
  assert.deepEqual(spec.reviewedPostPaths, {json: ['/api/process'], xml: [], form: []});
  assert.equal(validModelHttpSequence(spec), true);
  assert.equal(validModelHttpSequence({...spec, subject: {...spec.subject,
    key: 'newProbe'}, reviewedReadInputs: [{path: '/api/lookup',
    methods: ['GET'], parameters: ['mode']}]}), true,
  'a novel subject query key may replay with an observed companion field');
  assert.equal((await execFile(process.execPath, [finding.proof])).code, 1);
  assert.equal((await execFile(process.execPath, [finding.proof, '--expect-fixed'])).code, 3);
  const before = await verifyRun(project, run, {env: {}});
  assert.equal(before.exitCode, 1);
  assert.equal(before.proofs[0].verdict, 'observed');
  assert.equal(before.proofs[0].impact, 'unverified');
  const exported = exportRun(project, run, {out: path.join(project, 'regression')});
  const regression = (target = null) => new Promise((resolve, reject) => {
    const child = spawn(process.execPath, ['--test', ...exported.files],
      {env: {...Object.fromEntries(Object.entries(process.env).filter(([key]) =>
        key !== 'NODE_TEST_CONTEXT')), BYPASS_BLACKBOX_TEST_ORIGIN: target ?? undefined},
      stdio: 'ignore'});
    child.once('error', reject);
    child.once('close', resolve);
  });
  assert.equal(await regression(), 1);
  assert.ok(calls.filter(call => call === 'POST /api/process').length >= 9);
  const beforeUnreviewed = calls.length;
  assert.equal((await check({...spec, reviewedPostPaths: {json: [], xml: [], form: []}})).verdict,
    'inconclusive');
  assert.equal(calls.length, beforeUnreviewed);
  transformed = false;
  assert.equal((await execFile(process.execPath, [finding.proof])).code, 0);
  assert.equal((await execFile(process.execPath, [finding.proof, '--expect-fixed'])).code, 0);
  const after = await verifyRun(project, run, {env: {}});
  assert.equal(after.exitCode, 0);
  assert.equal(after.proofs[0].verdict, 'not_reproduced');
  assert.equal(await regression(), 0);
  const generated = fs.readFileSync(exported.files[0], 'utf8');
  const remote = `https://review-${randomBytes(4).toString('hex')}.example.invalid`;
  const productionSource = generated.replaceAll(origin, remote)
    .replace('"targetEnvironment":"local"', '"targetEnvironment":"production"');
  assert.notEqual(productionSource, generated);
  fs.writeFileSync(exported.files[0], productionSource);
  transformed = true;
  assert.equal(await regression(origin), 1,
    'the explicit local CI origin executes the vulnerable POST sequence');
  transformed = false;
  assert.equal(await regression(origin), 0,
    'the explicit local CI origin passes after the POST sequence is repaired');
});

test('an exact reviewed POST body replays without a legacy POST path entry', async t => {
  const project = temp();
  const run = 'bx-20261028-5678abcd';
  const dir = path.join(project, '.bypass/runs', run);
  fs.mkdirSync(dir, {recursive: true});
  fs.writeFileSync(path.join(dir, 'run.json'), '{}');
  t.after(() => fs.rmSync(project, {recursive: true, force: true}));
  const suffix = Math.random().toString(16).slice(2, 10);
  const postPath = `/api/${suffix}/process`;
  const seen = [];
  let transformed = true;
  const server = http.createServer(async (request, response) => {
    const url = new URL(request.url, 'http://fixture.invalid');
    const chunks = [];
    for await (const chunk of request) chunks.push(chunk);
    const body = Buffer.concat(chunks).toString();
    seen.push({method: request.method, path: url.pathname, body});
    if (url.pathname !== postPath || request.method !== 'POST') {
      response.writeHead(404, {'cache-control': 'no-store'});
      return response.end('Missing');
    }
    const value = JSON.parse(body).expression;
    const output = transformed && value.startsWith('hex:') ?
      Buffer.from(value.slice(4), 'hex').toString('utf8') : value;
    response.writeHead(200, {'content-type': 'application/json',
      'cache-control': 'no-store', location: output});
    response.end(JSON.stringify({accepted: true}));
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  t.after(() => new Promise(resolve => server.close(resolve)));
  const origin = `http://127.0.0.1:${server.address().port}`;
  const scope = structuredClone(DEFAULT_SCOPE);
  scope.target.origin = origin;
  scope.credentialOrigins = [origin];
  scope.probes.writeOperations = [{method: 'POST', path: postPath, placement: 'json'}];
  const operation = {method: 'POST', path: postPath, placement: 'json',
    contentType: 'application/json', fields: ['expression'],
    requiredFields: ['expression']};
  const surface = {patterns: [], methodOperations: [operation]};
  const webProof = {kind: 'model-http-sequence', as: 'anonymous', prelude: [],
    subject: {method: 'POST', path: postPath, placement: 'json', key: 'expression',
      fixedFields: [], bodyTemplate: '', headers: []}, observe: [],
    controlValue: 'plain', firstValue: encoded(firstMarker),
    secondValue: encoded(secondMarker), marker: firstMarker, secondMarker,
    assertion: {step: 'subject', index: 0, location: 'header', name: 'location'}};
  const reviewed = validateResearchFlow({family: 'response-transform',
    why: 'An observed POST field may transform the response', priority: 8,
    oracle: 'marker', ...webProof}, surface, scope);
  assert.equal(reviewed.ok, true, JSON.stringify(reviewed));
  const finding = {id: 'f-001', kind: 'model-http-sequence', pattern: postPath,
    url: `${origin}${postPath}`, confirmation: [], webProof: reviewed.lead};
  const proved = await proveFindings([finding], [], {runDir: dir, surface,
    scope, env: {}, ledger: createLedger(dir), web: {results: []}});
  assert.equal(proved.length, 1, 'the reviewed POST observation must retain its proof');
  const spec = JSON.parse(fs.readFileSync(path.join(dir, 'poc/f-001/spec.json'), 'utf8'));
  assert.deepEqual(spec.reviewedPostPaths, {json: [], xml: [], form: []});
  assert.deepEqual(spec.reviewedOperations, [{...operation, rootElement: null}]);
  assert.equal(validModelHttpSequence(spec), true);
  assert.equal((await verifyRun(project, run, {env: {}})).proofs[0].verdict, 'observed');
  const exported = exportRun(project, run, {out: path.join(project, 'regression')});
  const regression = () => new Promise((resolve, reject) => {
    const child = spawn(process.execPath, ['--test', ...exported.files],
      {env: Object.fromEntries(Object.entries(process.env).filter(([key]) =>
        key !== 'NODE_TEST_CONTEXT')), stdio: 'ignore'});
    child.once('error', reject);
    child.once('close', resolve);
  });
  assert.equal(await regression(), 1);
  assert.ok(seen.filter(item => item.method === 'POST' && item.path === postPath).length >= 9);
  transformed = false;
  assert.equal((await verifyRun(project, run, {env: {}})).proofs[0].verdict, 'not_reproduced');
  assert.equal(await regression(), 0);
});

test('a sealed sequence preserves owner and outsider read identities through proof and regression', async t => {
  const project = temp();
  const run = 'bx-20261028-4321dcba';
  const dir = path.join(project, '.bypass/runs', run);
  fs.mkdirSync(dir, {recursive: true});
  fs.writeFileSync(path.join(dir, 'run.json'), '{}');
  t.after(() => fs.rmSync(project, {recursive: true, force: true}));
  const calls = [];
  let transformed = true;
  let last = 'plain';
  const server = http.createServer(async (request, response) => {
    const url = new URL(request.url, 'http://fixture');
    const role = request.headers.authorization === 'Bearer fixture-owner' ? 'owner' :
      request.headers.authorization === 'Bearer fixture-outsider' ? 'outsider' : 'anonymous';
    calls.push(`${role} ${request.method} ${url.pathname}`);
    const json = (status, data, headers = {}) => {
      response.writeHead(status, {'content-type': 'application/json',
        'cache-control': 'no-store', ...headers});
      response.end(JSON.stringify(data));
    };
    if (url.pathname === '/api/prepare' && request.method === 'GET')
      return json(role === 'owner' ? 200 : 403, {ready: role === 'owner'});
    if (url.pathname === '/api/process' && request.method === 'POST') {
      const chunks = [];
      for await (const chunk of request) chunks.push(chunk);
      const value = JSON.parse(Buffer.concat(chunks).toString()).value;
      last = transformed && value.startsWith('hex:') ?
        Buffer.from(value.slice(4), 'hex').toString('utf8') : value;
      return json(200, {accepted: true});
    }
    if (url.pathname === '/api/state' && request.method === 'GET')
      return json(role === 'outsider' ? 200 : 403, {ready: role === 'outsider'},
        {location: role === 'outsider' ? last : ''});
    return json(404, {error: 'missing'});
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  t.after(() => new Promise(resolve => server.close(resolve)));
  const origin = `http://127.0.0.1:${server.address().port}`;
  const scope = structuredClone(DEFAULT_SCOPE);
  scope.target.origin = origin;
  scope.credentialOrigins = [origin];
  scope.probes.jsonPostPaths = ['/api/process'];
  const env = {...process.env, OWNER_TOKEN: 'fixture-owner', OTHER_TOKEN: 'fixture-outsider'};
  const webProof = {kind: 'model-http-sequence', as: 'anonymous',
    prelude: [{method: 'GET', path: '/api/prepare', as: 'owner', headers: []}],
    subject: {method: 'POST', path: '/api/process', placement: 'json', key: 'value',
      fixedFields: [], bodyTemplate: '', headers: []},
    observe: [{method: 'GET', path: '/api/state', as: 'outsider', headers: []}],
    controlValue: 'plain', firstValue: encoded(firstMarker),
    secondValue: encoded(secondMarker), marker: firstMarker, secondMarker,
    assertion: {step: 'observe', index: 0, location: 'header', name: 'location'}};
  const finding = {id: 'f-001', kind: 'model-http-sequence', pattern: '/api/process',
    url: `${origin}/api/process`, confirmation: [], webProof};
  const ledger = createLedger(dir);
  const proved = await proveFindings([finding], [], {runDir: dir, surface: {patterns: []},
    scope, env, ledger, web: {results: []}});
  assert.equal(proved.length, 1);
  const spec = JSON.parse(fs.readFileSync(path.join(dir, 'poc/f-001/spec.json'), 'utf8'));
  assert.deepEqual(spec.prelude.map(step => step.as), ['owner']);
  assert.deepEqual(spec.observe.map(step => step.as), ['outsider']);
  assert.deepEqual(spec.credentialOrigins, [origin]);
  assert.equal(validModelHttpSequence(spec), true);
  assert.equal((await execFile(process.execPath, [finding.proof], {env})).code, 1);
  assert.equal((await verifyRun(project, run, {env})).proofs[0].verdict, 'observed');
  const exported = exportRun(project, run, {out: path.join(project, 'regression')});
  const regression = () => new Promise((resolve, reject) => {
    const child = spawn(process.execPath, ['--test', ...exported.files],
      {env: Object.fromEntries(Object.entries(env).filter(([key]) =>
        key !== 'NODE_TEST_CONTEXT')), stdio: 'ignore'});
    child.once('error', reject);
    child.once('close', resolve);
  });
  assert.equal(await regression(), 1);
  assert.ok(calls.some(call => call === 'owner GET /api/prepare'));
  assert.ok(calls.some(call => call === 'anonymous POST /api/process'));
  assert.ok(calls.some(call => call === 'outsider GET /api/state'));
  const beforeBlocked = calls.length;
  assert.equal((await check({...spec, credentialOrigins: []}, env)).verdict, 'inconclusive');
  assert.equal(calls.length, beforeBlocked);
  assert.equal(validModelHttpSequence({...spec, observe: [{...spec.observe[0], as: 'admin'}]}), false);
  transformed = false;
  assert.equal((await execFile(process.execPath, [finding.proof, '--expect-fixed'], {env})).code, 0);
  assert.equal((await verifyRun(project, run, {env})).proofs[0].verdict, 'not_reproduced');
  assert.equal(await regression(), 0);
});

test('GET sequence replays a nonliteral response transformation and rejects reflection controls', async t => {
  let transformed = true;
  const server = http.createServer((request, response) => {
    const url = new URL(request.url, 'http://fixture');
    const value = url.searchParams.get('term') ?? '';
    const output = transformed && value.startsWith('hex:') ?
      Buffer.from(value.slice(4), 'hex').toString('utf8') : value;
    response.writeHead(200, {'content-type': 'text/plain', 'cache-control': 'no-store'});
    response.end(output);
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  t.after(() => new Promise(resolve => server.close(resolve)));
  const origin = `http://127.0.0.1:${server.address().port}`;
  const spec = {kind: 'model-http-sequence', origin, include: ['/'], never: [], rps: 100,
    identities: {}, auth: 'bearer', targetEnvironment: 'local', as: 'anonymous',
    prelude: [], subject: {method: 'GET', path: '/api/read', placement: 'query',
      key: 'term', fixedFields: [], bodyTemplate: '', headers: []}, observe: [], controlValue: 'plain',
    firstValue: encoded(firstMarker), secondValue: encoded(secondMarker),
    marker: firstMarker, secondMarker,
    assertion: {step: 'subject', index: 0, location: 'body', name: ''}};
  assert.equal(validModelHttpSequence(spec), true);
  assert.equal((await check(spec)).verdict, 'observed');
  transformed = false;
  assert.equal((await check(spec)).verdict, 'not_reproduced');
  assert.equal(validModelHttpSequence({...spec, firstValue: firstMarker}), false);
  assert.equal(validModelHttpSequence({...spec, subject: {...spec.subject,
    path: `/api/read?known=${firstMarker}`}}), false);
});

test('reviewed local form POST replays through a default word exclusion', async t => {
  let transformed = true;
  const server = http.createServer(async (request, response) => {
    const chunks = [];
    for await (const chunk of request) chunks.push(chunk);
    const value = new URLSearchParams(Buffer.concat(chunks).toString()).get('expression') ?? '';
    const output = transformed && value.startsWith('hex:') ?
      Buffer.from(value.slice(4), 'hex').toString('utf8') : value;
    response.writeHead(200, {'content-type': 'text/plain', 'cache-control': 'no-store',
      location: output});
    response.end('ok');
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  t.after(() => new Promise(resolve => server.close(resolve)));
  const origin = `http://127.0.0.1:${server.address().port}`;
  const scope = structuredClone(DEFAULT_SCOPE);
  scope.target.origin = origin;
  scope.probes.formPostPaths = ['/api/reset'];
  assert.equal(validateUrl(scope, '/api/reset', {purpose: 'form-body', method: 'POST',
    identity: 'anonymous'}).ok, true);
  const spec = {kind: 'model-http-sequence', origin, include: ['/'], never: scope.never,
    rps: 100, identities: {}, auth: 'bearer', targetEnvironment: 'local', as: 'anonymous',
    reviewedPostPaths: {json: [], xml: [], form: ['/api/reset']}, prelude: [],
    subject: {method: 'POST', path: '/api/reset', placement: 'form', key: 'expression',
      fixedFields: [], bodyTemplate: '', headers: []}, observe: [], controlValue: 'plain',
    firstValue: encoded(firstMarker), secondValue: encoded(secondMarker),
    marker: firstMarker, secondMarker,
    assertion: {step: 'subject', index: 0, location: 'header', name: 'location'}};
  assert.equal(validModelHttpSequence(spec), true);
  assert.equal((await check(spec)).verdict, 'observed');
  transformed = false;
  assert.equal((await check(spec)).verdict, 'not_reproduced');
});

test('reviewed derived POST sequence replays a fresh login and keeps its bearer out of the proof', async t => {
  const project = temp();
  const run = 'bx-20261028-fedcba98';
  const dir = path.join(project, '.bypass/runs', run);
  fs.mkdirSync(dir, {recursive: true});
  fs.writeFileSync(path.join(dir, 'run.json'), '{}');
  t.after(() => fs.rmSync(project, {recursive: true, force: true}));
  const issued = new Set();
  const calls = [];
  let transformed = true;
  let last = 'plain';
  let nextToken = 0;
  const server = http.createServer(async (request, response) => {
    const url = new URL(request.url, 'http://fixture');
    const authorized = issued.has(request.headers.authorization?.replace(/^Bearer /, ''));
    calls.push({method: request.method, path: url.pathname, authorized});
    const json = (status, value, headers = {}) => {
      response.writeHead(status, {'content-type': 'application/json',
        'cache-control': 'no-store', ...headers});
      response.end(JSON.stringify(value));
    };
    if (url.pathname === '/api/login' && request.method === 'POST') {
      const chunks = [];
      for await (const chunk of request) chunks.push(chunk);
      const body = JSON.parse(Buffer.concat(chunks).toString());
      if (body.username !== "admin' OR '1'='1") return json(401, {error: 'invalid'});
      const token = `fixture-issued-token-${String(++nextToken).padStart(20, '0')}`;
      issued.add(token);
      return json(200, {authentication: {token}});
    }
    if (url.pathname === '/api/me' && request.method === 'GET')
      return json(authorized ? 200 : 401, authorized ? {ok: true} : {error: 'denied'});
    if (url.pathname === '/api/process' && request.method === 'POST') {
      if (!authorized) return json(401, {error: 'denied'});
      const chunks = [];
      for await (const chunk of request) chunks.push(chunk);
      const input = JSON.parse(Buffer.concat(chunks).toString()).expression;
      last = transformed && input.startsWith('hex:') ?
        Buffer.from(input.slice(4), 'hex').toString('utf8') : input;
      return json(200, {accepted: true});
    }
    if (url.pathname === '/api/result' && request.method === 'GET')
      return authorized ? json(200, {ready: true}, {location: last}) :
        json(401, {error: 'denied'});
    return json(404, {error: 'missing'});
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  t.after(() => new Promise(resolve => server.close(resolve)));
  const origin = `http://127.0.0.1:${server.address().port}`;
  const scope = structuredClone(DEFAULT_SCOPE);
  scope.target.origin = origin;
  scope.credentialOrigins = [origin];
  scope.probes.jsonPostPaths = ['/api/process'];
  const webProof = {kind: 'model-http-sequence', as: 'derived',
    prelude: [], subject: {method: 'POST', path: '/api/process', placement: 'json',
      key: 'expression', fixedFields: [], bodyTemplate: '', headers: []},
    observe: [{method: 'GET', path: '/api/result', headers: []}],
    controlValue: 'plain', firstValue: encoded(firstMarker),
    secondValue: encoded(secondMarker), marker: firstMarker, secondMarker,
    assertion: {step: 'observe', index: 0, location: 'header', name: 'location'},
    derivedLogin: {kind: 'model-auth-login', proofMode: 'protected-status',
      loginPath: '/api/login', privatePath: '/api/me', userField: 'username',
      passwordField: 'password', userPayloads: ["admin' OR '1'='1"],
      tokenPointer: '/authentication/token',
      request: {method: 'POST', as: 'anonymous', url: '/api/login'},
      reviewedAuthPosts: [{path: '/api/login', usernameField: 'username',
        passwordField: 'password'}]}};
  const finding = {id: 'f-001', kind: 'model-http-sequence', pattern: '/api/process',
    url: `${origin}/api/process`, confirmation: [], webProof};
  const ledger = createLedger(dir);
  const proved = await proveFindings([finding], [], {runDir: dir, surface: {patterns: []},
    scope, env: {}, ledger, web: {results: []}});
  assert.equal(proved.length, 1);
  const spec = JSON.parse(fs.readFileSync(path.join(dir, 'poc/f-001/spec.json'), 'utf8'));
  assert.equal(validModelHttpSequence(spec), true);
  assert.equal(spec.subject.method, 'POST');
  assert.equal(spec.as, 'derived');
  assert.equal(fs.readFileSync(path.join(dir, 'poc/f-001/spec.json'), 'utf8')
    .includes('fixture-issued-token-'), false);
  const replay = await verifyRun(project, run, {env: {}});
  assert.equal(replay.proofs[0].verdict, 'observed');
  assert.equal(replay.proofs[0].impact, 'unverified');
  assert.ok(replay.proofs[0].controls.some(item => item.label === 'protected-route-boundary' &&
    item.anonymousStatus === 401 && item.invalidBearerStatus === 401));
  assert.ok(calls.some(item => item.path === '/api/process' && item.authorized));
  assert.ok(calls.every(item => item.path !== '/api/process' || item.authorized));
  const exported = exportRun(project, run, {out: path.join(project, 'regression')});
  const regression = () => new Promise((resolve, reject) => {
    const child = spawn(process.execPath, ['--test', ...exported.files],
      {env: Object.fromEntries(Object.entries(process.env).filter(([key]) =>
        key !== 'NODE_TEST_CONTEXT')), stdio: 'ignore'});
    child.once('error', reject);
    child.once('close', resolve);
  });
  assert.equal(await regression(), 1);
  const withoutReview = await check({...spec, reviewedPostPaths: {json: [], form: [], xml: []}}, {});
  assert.equal(withoutReview.verdict, 'inconclusive');
  transformed = false;
  assert.equal((await verifyRun(project, run, {env: {}})).proofs[0].verdict,
    'not_reproduced');
  assert.equal(await regression(), 0);
});

test('GET query proof keeps observed companion fields and refuses unobserved ones', async t => {
  let transformed = true;
  const seen = [];
  const server = http.createServer((request, response) => {
    const url = new URL(request.url, 'http://fixture');
    seen.push(url.search);
    const q = url.searchParams.get('q') ?? '';
    const mode = url.searchParams.get('mode');
    const result = transformed && q.startsWith('hex:') ?
      Buffer.from(q.slice(4), 'hex').toString('utf8') : q;
    response.writeHead(mode === 'public' ? 200 : 400,
      {'content-type': 'text/plain', 'cache-control': 'no-store',
        location: mode === 'public' ? result : 'missing-mode'});
    response.end('ok');
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  t.after(() => new Promise(resolve => server.close(resolve)));
  const origin = `http://127.0.0.1:${server.address().port}`;
  const webProof = {kind: 'model-http-sequence', as: 'anonymous', prelude: [],
    subject: {method: 'GET', path: '/api/lookup', placement: 'query',
      key: 'q', fixedFields: [{field: 'mode', value: 'public'}],
      bodyTemplate: '', headers: []}, observe: [], controlValue: 'plain',
    firstValue: encoded(firstMarker), secondValue: encoded(secondMarker),
    marker: firstMarker, secondMarker,
    assertion: {step: 'subject', index: 0, location: 'header', name: 'location'}};
  const spec = {...webProof, origin, include: ['/'], never: [], rps: 100,
    identities: {}, auth: 'bearer', targetEnvironment: 'local',
    reviewedReadInputs: [{path: '/api/lookup', methods: ['GET'],
      parameters: ['q', 'mode']}]};
  assert.equal(validModelHttpSequence(spec), true);
  assert.equal((await check(spec)).verdict, 'observed');
  assert.ok(seen.every(search => search.includes('mode=public') && search.includes('q=')));
  const before = seen.length;
  assert.equal((await check({...spec, reviewedReadInputs: []})).verdict, 'inconclusive');
  assert.equal(validModelHttpSequence({...spec, subject: {...spec.subject,
    fixedFields: [{field: 'other', value: 'public'}]}}), false);
  assert.equal(seen.length, before, 'unobserved companion fields must be refused before request');
  const project = temp();
  const run = 'bx-20261028-b1c2d3e4';
  const dir = path.join(project, '.bypass/runs', run);
  fs.mkdirSync(dir, {recursive: true});
  fs.writeFileSync(path.join(dir, 'run.json'), '{}');
  t.after(() => fs.rmSync(project, {recursive: true, force: true}));
  const scope = structuredClone(DEFAULT_SCOPE);
  scope.target.origin = origin;
  scope.credentialOrigins = [origin];
  const surface = {patterns: [{pattern: '/api/lookup', methods: ['GET'],
    params: {q: ['plain'], mode: ['public']}}]};
  const finding = {id: 'f-001', kind: 'model-http-sequence', pattern: '/api/lookup',
    url: `${origin}/api/lookup`, confirmation: [], webProof};
  const proved = await proveFindings([finding], [], {runDir: dir, surface,
    scope, env: {}, ledger: createLedger(dir), web: {results: []}});
  assert.equal(proved.length, 1);
  const sealed = JSON.parse(fs.readFileSync(path.join(dir, 'poc/f-001/spec.json'), 'utf8'));
  assert.deepEqual(sealed.reviewedReadInputs, spec.reviewedReadInputs);
  assert.equal((await verifyRun(project, run, {env: {}})).proofs[0].verdict, 'observed');
  transformed = false;
  assert.equal((await verifyRun(project, run, {env: {}})).proofs[0].verdict,
    'not_reproduced');
});

test('an observed GET query binding replays through its generated proof and regression', async t => {
  let transformed = true;
  let pending = '';
  const requested = [];
  const server = http.createServer((request, response) => {
    const url = new URL(request.url, 'http://fixture');
    requested.push(`${request.method} ${url.pathname}${url.search}`);
    response.setHeader('content-type', 'application/json');
    response.setHeader('cache-control', 'no-store');
    if (url.pathname === '/api/product')
      return response.end(JSON.stringify({name: 'apple'}));
    if (url.pathname === '/api/search' && url.searchParams.has('term')) {
      const value = url.searchParams.get('term');
      pending = transformed && value.startsWith('hex:') ?
        Buffer.from(value.slice(4), 'hex').toString('utf8') : value;
      return response.end(JSON.stringify({accepted: true}));
    }
    if (url.pathname === '/api/search' && url.searchParams.has('q'))
      return response.end(JSON.stringify({result:
        url.searchParams.get('q') === 'apple' ? pending : 'wrong-product'}));
    response.statusCode = 404;
    response.end(JSON.stringify({error: 'missing'}));
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  t.after(() => new Promise(resolve => server.close(resolve)));
  const origin = `http://127.0.0.1:${server.address().port}`;
  const webProof = {kind: 'model-http-sequence', as: 'anonymous',
    prelude: [{method: 'GET', path: '/api/product', headers: []}],
    subject: {method: 'GET', path: '/api/search', placement: 'query',
      key: 'term', fixedFields: [], bodyTemplate: '', headers: []},
    observe: [{method: 'GET', path: '/api/search?q=seed', headers: []}],
    binding: {from: 0, pointer: '/name', to: 'observe', index: 0, key: 'q'},
    bindingReview: {sourcePath: '/api/product', sourceAs: 'anonymous',
      sourcePointer: '/name', sourceType: 'string', sourceStatus: 200,
      sourceEvidenceId: 'e-source', targetPath: '/api/search?q=seed',
      targetPlacement: 'query', targetFields: ['term', 'q']},
    controlValue: 'plain', firstValue: encoded(firstMarker),
    secondValue: encoded(secondMarker), marker: firstMarker, secondMarker,
    assertion: {step: 'observe', index: 0, location: 'body', name: ''}};
  const spec = {...webProof, origin, include: ['/'], never: [], rps: 100,
    identities: {}, auth: 'bearer', targetEnvironment: 'local'};
  assert.equal(validModelHttpSequence(spec), true);
  for (const path of ['/api/search?other=seed', '/api/search?q=seed&q=other'])
    assert.equal(validModelHttpSequence({...spec,
      observe: [{...spec.observe[0], path}],
      bindingReview: {...spec.bindingReview, targetPath: path}}), false);
  assert.equal((await check(spec)).verdict, 'observed');
  const project = temp();
  const run = 'bx-20261028-9876abcd';
  const dir = path.join(project, '.bypass/runs', run);
  fs.mkdirSync(dir, {recursive: true});
  fs.writeFileSync(path.join(dir, 'run.json'), '{}');
  t.after(() => fs.rmSync(project, {recursive: true, force: true}));
  const scope = structuredClone(DEFAULT_SCOPE);
  scope.target.origin = origin;
  scope.credentialOrigins = [origin];
  const surface = {patterns: [
    {pattern: '/api/product', methods: ['GET']},
    {pattern: '/api/search', methods: ['GET'], params: {term: ['plain'], q: ['seed']}}]};
  const finding = {id: 'f-001', kind: 'model-http-sequence', pattern: '/api/search',
    url: `${origin}/api/search`, confirmation: [], webProof};
  const proved = await proveFindings([finding], [], {runDir: dir, surface,
    scope, env: {}, ledger: createLedger(dir), web: {results: []}});
  assert.equal(proved.length, 1);
  assert.equal((await execFile(process.execPath, [finding.proof])).code, 1);
  assert.equal((await verifyRun(project, run, {env: {}})).proofs[0].verdict, 'observed');
  const exported = exportRun(project, run, {out: path.join(project, 'regression')});
  const regression = () => new Promise((resolve, reject) => {
    const child = spawn(process.execPath, ['--test', ...exported.files],
      {env: Object.fromEntries(Object.entries(process.env).filter(([key]) =>
        key !== 'NODE_TEST_CONTEXT')), stdio: 'ignore'});
    child.once('error', reject);
    child.once('close', resolve);
  });
  assert.equal(await regression(), 1);
  assert.ok(requested.filter(item => item === 'GET /api/search?q=apple').length >= 3);
  transformed = false;
  assert.equal((await verifyRun(project, run, {env: {}})).proofs[0].verdict,
    'not_reproduced');
  assert.equal(await regression(), 0);
});

test('a staged POST boundary replays with an observed GET query follow-up', async t => {
  const suffix = randomBytes(4).toString('hex');
  const begin = `/api/${suffix}/begin`;
  const finish = `/api/${suffix}/finish`;
  const observe = `/api/${suffix}/state`;
  const challengeField = `challenge_${suffix}`;
  const ticketField = `ticket_${suffix}`;
  const cookieField = `cookie_${suffix}`;
  const ticketHeader = `x-ticket-${suffix}`;
  const ticketEchoField = `ticket_echo_${suffix}`;
  const cookieName = `session_${suffix}`;
  const optionField = `option_${suffix}`;
  const queryField = `view_${suffix}`;
  const challenges = new Set();
  const tickets = new Map();
  const requests = [];
  const contentTypes = [];
  const boundHeaders = [];
  const submittedBodies = [];
  let vulnerable = true;
  const server = http.createServer(async (request, response) => {
    const url = new URL(request.url, 'http://fixture');
    requests.push(`${request.method} ${url.pathname}${url.search}`);
    if (request.method === 'POST') contentTypes.push(request.headers['content-type']);
    response.setHeader('content-type', 'application/json');
    response.setHeader('cache-control', 'no-store');
    const send = (status, data) => {
      response.statusCode = status;
      response.end(JSON.stringify(data));
    };
    if (request.method === 'POST' && url.pathname === begin) {
      const challenge = randomBytes(24).toString('hex');
      const ticket = randomBytes(12).toString('hex');
      const cookieValue = randomBytes(12).toString('hex');
      challenges.add(challenge);
      tickets.set(challenge, {ticket, cookieValue});
      return send(200, {[challengeField]: challenge,
        [ticketField]: ticket, [cookieField]: cookieValue});
    }
    if (request.method === 'POST' && url.pathname === finish) {
      const chunks = [];
      for await (const chunk of request) chunks.push(chunk);
      const rawBody = Buffer.concat(chunks).toString();
      submittedBodies.push(rawBody);
      const body = JSON.parse(rawBody);
      const issued = tickets.get(body[challengeField]);
      const fresh = challenges.delete(body[challengeField]);
      const bound = issued && request.headers[ticketHeader] === issued.ticket &&
        body[ticketEchoField] === issued.ticket &&
        request.headers.cookie?.split(';').map(part => part.trim())
          .includes(`${cookieName}=${issued.cookieValue}`);
      boundHeaders.push({header: request.headers[ticketHeader],
        cookie: request.headers.cookie, query: url.search});
      return send(fresh && bound && vulnerable && body[optionField] === true ? 200 : 401,
        {accepted: fresh && bound && vulnerable && body[optionField] === true});
    }
    if (request.method === 'GET' && url.pathname === observe &&
        url.searchParams.get(queryField) === 'summary')
      return send(200, {state: 'observed'});
    return send(404, {error: 'missing'});
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  t.after(() => new Promise(resolve => server.close(resolve)));
  const origin = `http://127.0.0.1:${server.address().port}`;
  const operations = [
    {method: 'POST', path: begin, placement: 'json',
      contentType: 'application/json', fields: ['user'], requiredFields: ['user']},
    {method: 'POST', path: finish, placement: 'json',
      contentType: 'application/json', fields: [challengeField, 'code', optionField,
        ticketEchoField],
      requiredFields: [challengeField, 'code', optionField]},
  ];
  const webProof = {kind: 'model-sequence-boundary', oracle: 'status-boundary',
    as: 'anonymous',
    prelude: [{method: 'POST', path: begin, placement: 'json', key: 'user',
      value: 'fixture-user', fixedFields: [], bodyTemplate: '{"user":"{{input}}"}',
      headers: [{name: 'Content-Type', value: 'application/json; charset=utf-8'}]}],
    subject: {method: 'POST', path: finish, placement: 'json', key: optionField,
      valueEncoding: 'json', fixedFields: [{field: 'code', value: 'wrong'}],
      bodyTemplate: `{ "code" : "wrong", "${challengeField}" : "{{binding:${challengeField}}}", "${ticketEchoField}" : "{{binding:${ticketHeader}}}", "${optionField}" : {{input}} }`,
      headers: [{name: 'Content-Type',
        value: 'application/json; charset=utf-8'}]},
    observe: [{method: 'GET', path: observe, placement: 'query', key: queryField,
      value: 'summary', fixedFields: [], bodyTemplate: '', headers: []}],
    bindings: [
      {from: 0, pointer: `/${challengeField}`, to: 'subject',
        index: 0, key: challengeField},
      {from: 0, pointer: `/${ticketField}`, to: 'subject',
        index: 0, key: ticketHeader, placement: 'header'},
      {from: 0, pointer: `/${cookieField}`, to: 'subject',
        index: 0, key: cookieName, placement: 'cookie'}],
    bindingReviews: [
      {sourcePath: begin, sourceAs: 'anonymous', sourcePointer: `/${challengeField}`,
        sourceMethod: 'POST', sourcePlacement: 'json', sourceFields: ['user'],
        sourceType: 'string', sourceStatus: 200, targetPath: finish,
        targetPlacement: 'json', targetFields: [challengeField, 'code', optionField]},
      {sourcePath: begin, sourceAs: 'anonymous', sourcePointer: `/${ticketField}`,
        sourceMethod: 'POST', sourcePlacement: 'json', sourceFields: ['user'],
        sourceType: 'string', sourceStatus: 200, targetPath: finish,
        targetPlacement: 'header', targetFields: [ticketHeader]},
      {sourcePath: begin, sourceAs: 'anonymous', sourcePointer: `/${cookieField}`,
        sourceMethod: 'POST', sourcePlacement: 'json', sourceFields: ['user'],
        sourceType: 'string', sourceStatus: 200, targetPath: finish,
        targetPlacement: 'cookie', targetFields: [cookieName]}],
    controlValue: 'false', firstValue: 'true', secondValue: 'null',
    marker: '', secondMarker: '',
    assertion: {step: 'subject', index: 0, location: 'body', name: ''}};
  const spec = {...webProof, origin, include: ['/api'], never: [], rps: 100,
    targetEnvironment: 'local', methods: ['GET', 'HEAD', 'POST'],
    identities: {}, auth: 'bearer', reviewedOperations: operations,
    reviewedPostPaths: {json: [begin, finish], xml: [], form: []}};
  assert.equal(validModelHttpSequence(spec), true);
  assert.equal((await check(spec)).verdict, 'confirmed');
  assert.ok(contentTypes.length > 0);
  assert.ok(contentTypes.every(type => type === 'application/json; charset=utf-8'));
  assert.ok(boundHeaders.length > 0);
  assert.ok(boundHeaders.every(item => item.header &&
    item.cookie?.includes(`${cookieName}=`) && item.query === ''));
  assert.ok(submittedBodies.every(body => body.startsWith('{ "code" : "wrong", ')));
  assert.ok(requests.some(item => item === `GET ${observe}?${queryField}=summary`));
  const project = temp();
  const run = `bx-20261028-${suffix}`;
  const dir = path.join(project, '.bypass/runs', run);
  fs.mkdirSync(dir, {recursive: true});
  fs.writeFileSync(path.join(dir, 'run.json'), '{}');
  t.after(() => fs.rmSync(project, {recursive: true, force: true}));
  const scope = structuredClone(DEFAULT_SCOPE);
  scope.target.origin = origin;
  scope.include = ['/api'];
  scope.methods = ['GET', 'HEAD', 'POST'];
  scope.probes.jsonPostPaths = [begin, finish];
  scope.probes.writeOperations = operations;
  const surface = {patterns: [{pattern: observe, methods: ['GET'],
    params: {[queryField]: ['summary']}}], methodOperations: operations};
  const finding = {id: 'f-001', kind: 'model-sequence-boundary', pattern: finish,
    url: `${origin}${finish}`, confirmation: [], webProof};
  const proved = await proveFindings([finding], [], {runDir: dir, surface,
    scope, env: {}, ledger: createLedger(dir), web: {results: []}});
  assert.equal(proved.length, 1);
  const savedSpec = fs.readFileSync(path.join(dir, 'poc/f-001/spec.json'), 'utf8');
  for (const {ticket, cookieValue} of tickets.values()) {
    assert.ok(!savedSpec.includes(ticket));
    assert.ok(!savedSpec.includes(cookieValue));
  }
  assert.equal((await verifyRun(project, run, {env: {}})).proofs[0].verdict,
    'confirmed');
  vulnerable = false;
  assert.equal((await verifyRun(project, run, {env: {}})).proofs[0].verdict,
    'not_reproduced');
});

test('reviewed PUT, PATCH, DELETE and OPTIONS sequences preserve exact method and body contract', async t => {
  const seen = [];
  let transformed = true;
  const server = http.createServer(async (request, response) => {
    const url = new URL(request.url, 'http://fixture');
    const chunks = [];
    for await (const chunk of request) chunks.push(chunk);
    const body = Buffer.concat(chunks).toString();
    seen.push({method: request.method, path: url.pathname,
      contentType: request.headers['content-type'] ?? null, body});
    let value = '';
    if (request.method === 'PUT') value = JSON.parse(body).expression;
    else if (request.method === 'PATCH')
      value = new URLSearchParams(body).get('expression') ?? '';
    else if (['DELETE', 'OPTIONS'].includes(request.method))
      value = url.searchParams.get('expression') ?? '';
    const output = transformed && value.startsWith('hex:') ?
      Buffer.from(value.slice(4), 'hex').toString('utf8') : value;
    response.writeHead(200, {'content-type': 'application/json',
      'cache-control': 'no-store', location: output});
    response.end(JSON.stringify({accepted: true}));
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  t.after(() => new Promise(resolve => server.close(resolve)));
  const origin = `http://127.0.0.1:${server.address().port}`;
  const operations = [
    {method: 'PUT', path: '/api/replace', placement: 'json',
      contentType: 'application/json', fields: ['expression'], requiredFields: ['expression']},
    {method: 'PATCH', path: '/api/change', placement: 'form',
      contentType: 'application/x-www-form-urlencoded',
      fields: ['expression'], requiredFields: ['expression']},
    {method: 'DELETE', path: '/api/remove', placement: 'query',
      contentType: null, fields: ['expression'], requiredFields: []},
    {method: 'OPTIONS', path: '/api/capabilities', placement: 'query',
      contentType: null, fields: ['expression'], requiredFields: []},
  ];
  const specForOperation = operation => ({kind: 'model-http-sequence', origin,
    include: ['/'], never: [], rps: 100, identities: {}, auth: 'bearer',
    targetEnvironment: 'local', as: 'anonymous', reviewedOperations: [operation],
    prelude: [], subject: {method: operation.method, path: operation.path,
      placement: operation.placement, key: 'expression', fixedFields: [],
      bodyTemplate: '', headers: []}, observe: [], controlValue: 'plain',
    firstValue: encoded(firstMarker), secondValue: encoded(secondMarker),
    marker: firstMarker, secondMarker,
    assertion: {step: 'subject', index: 0, location: 'header', name: 'location'}});
  for (const operation of operations) {
    const spec = specForOperation(operation);
    assert.equal(validModelHttpSequence(spec), true, operation.method);
    assert.equal((await check(spec)).verdict, 'observed', operation.method);
    const calls = seen.filter(item => item.path === operation.path);
    assert.equal(calls.length, 3);
    assert.ok(calls.every(item => item.method === operation.method &&
      item.contentType === operation.contentType &&
      (operation.placement === 'query' ? item.body === '' : item.body.length > 0)));
    const before = seen.length;
    assert.equal((await check({...spec, reviewedOperations: []})).verdict, 'inconclusive');
    assert.equal((await check({...spec, reviewedOperations: [{...operation,
      method: operation.method === 'DELETE' ? 'PATCH' : 'DELETE'}]})).verdict,
    'inconclusive');
    assert.equal(seen.length, before, 'an unreviewed method must not reach the server');
  }
  const multiMethod = {...specForOperation(operations[1]),
    reviewedOperations: [operations[1], operations[2], operations[0]],
    prelude: [{method: 'DELETE', path: '/api/remove', placement: 'query',
      key: 'expression', value: 'plain', fixedFields: [], bodyTemplate: '', headers: []}],
    observe: [{method: 'PUT', path: '/api/replace', placement: 'json',
      key: 'expression', value: 'plain', fixedFields: [], bodyTemplate: '', headers: []}]};
  const beforeMultiMethod = seen.length;
  assert.equal(validModelHttpSequence(multiMethod), true);
  assert.equal((await check(multiMethod)).verdict, 'observed');
  assert.deepEqual(seen.slice(beforeMultiMethod).map(item => item.method),
    ['DELETE', 'PATCH', 'PUT', 'DELETE', 'PATCH', 'PUT', 'DELETE', 'PATCH', 'PUT']);
  const options = specForOperation(operations[3]);
  assert.equal(validModelHttpSequence({...options,
    subject: {...options.subject, placement: 'json'},
    reviewedOperations: [{...operations[3], placement: 'json',
      contentType: 'application/json'}]}), false,
  'OPTIONS must remain bodyless even if a proof spec claims a JSON contract');
  const project = temp();
  const run = 'bx-20261028-a1b2c3d4';
  const dir = path.join(project, '.bypass/runs', run);
  fs.mkdirSync(dir, {recursive: true});
  fs.writeFileSync(path.join(dir, 'run.json'), '{}');
  t.after(() => fs.rmSync(project, {recursive: true, force: true}));
  const scope = structuredClone(DEFAULT_SCOPE);
  scope.target.origin = origin;
  scope.credentialOrigins = [origin];
  scope.probes.writeOperations = [{method: 'PATCH', path: '/api/change', placement: 'form'}];
  const surface = {patterns: [], methodOperations: operations};
  const webProof = specForOperation(operations[1]);
  const finding = {id: 'f-001', kind: 'model-http-sequence', pattern: '/api/change',
    url: `${origin}/api/change`, confirmation: [], webProof};
  const proved = await proveFindings([finding], [], {runDir: dir, surface,
    scope, env: {}, ledger: createLedger(dir), web: {results: []}});
  assert.equal(proved.length, 1);
  const sealed = JSON.parse(fs.readFileSync(path.join(dir, 'poc/f-001/spec.json'), 'utf8'));
  assert.deepEqual(sealed.reviewedOperations, [{...operations[1], rootElement: null}]);
  assert.equal((await verifyRun(project, run, {env: {}})).proofs[0].verdict, 'observed');
  transformed = false;
  assert.equal((await verifyRun(project, run, {env: {}})).proofs[0].verdict,
    'not_reproduced');
});

test('verify does not promote a legacy proof without a replayable target', async t => {
  const project = temp();
  t.after(() => fs.rmSync(project, {recursive: true, force: true}));
  const run = 'bx-20261028-abcdef12';
  const dir = path.join(project, '.bypass/runs', run);
  const proofDir = path.join(dir, 'poc/f-001');
  fs.mkdirSync(proofDir, {recursive: true});
  fs.writeFileSync(path.join(dir, 'run.json'), '{}');
  const runtime = path.join(dir, 'poc/runtime.mjs');
  const spec = path.join(proofDir, 'spec.json');
  const script = path.join(proofDir, 'poc.mjs');
  fs.writeFileSync(runtime, '// sealed legacy runtime\n');
  fs.writeFileSync(spec, JSON.stringify({kind: 'model-http-sequence'}));
  fs.writeFileSync(script, "console.log(JSON.stringify({verdict:'confirmed'}));process.exitCode=1;\n");
  createLedger(dir).append({step: 'poc', proof: {path: script,
    specHash: hash(fs.readFileSync(spec)), scriptHash: hash(fs.readFileSync(script)),
    runtimeHash: hash(fs.readFileSync(runtime)), verdict: 'confirmed', exitCode: 1}});
  const replay = await verifyRun(project, run, {env: {}});
  assert.equal(replay.exitCode, 3);
  assert.equal(replay.proofs[0].verdict, 'inconclusive');
  assert.match(replay.proofs[0].reason, /valid target origin/);
  assert.equal(replay.proofs[0].kind, 'model-http-sequence');
});
