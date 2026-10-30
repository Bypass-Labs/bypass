import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import http from 'node:http';
import os from 'node:os';
import path from 'node:path';
import {randomBytes} from 'node:crypto';
import {DEFAULT_SCOPE} from '../src/blackbox/scope.mjs';
import {validateResearchFlow, runResearchFlows} from '../src/blackbox/research-flow.mjs';
import {validModelHttpSequence} from '../src/blackbox/poc-runtime.mjs';
import {proveFindings, verifyRun, exportRun} from '../src/blackbox/poc.mjs';
import {createLedger} from '../src/blackbox/ledger.mjs';
import {execFile} from '../src/util.mjs';

test('observed derived HEAD sequence is accepted, replayed with HEAD, and clears after repair',
  {timeout: 90000}, async t => {
    const root = fs.mkdtempSync(path.join(os.tmpdir(), 'bypass-derived-head-'));
    t.after(() => fs.rmSync(root, {recursive: true, force: true}));
    const suffix = randomBytes(5).toString('hex');
    const loginPath = `/api/${suffix}/login`;
    const privatePath = `/api/${suffix}/me`;
    const gatePath = `/api/${suffix}/gate`;
    const metaPath = `/api/${suffix}/meta`;
    let vulnerable = true, issuedCount = 0;
    const issued = new Set(), calls = [];
    const server = http.createServer(async (request, response) => {
      const url = new URL(request.url, 'http://fixture.invalid');
      calls.push(`${request.method} ${url.pathname}`);
      response.setHeader('cache-control', 'no-store');
      const authorized = issued.has(String(request.headers.authorization ?? '').replace(/^Bearer /, ''));
      if (request.method === 'POST' && url.pathname === loginPath) {
        let body = '';
        for await (const chunk of request) body += chunk;
        let input;
        try {input = JSON.parse(body);} catch {input = {};}
        if (input.username === "admin' OR '1'='1" &&
            /^bx-invalid-[0-9a-f]{24}$/.test(String(input.password ?? ''))) {
          const token = `bx-head-${randomBytes(16).toString('hex')}`;
          issued.add(token); issuedCount++;
          response.writeHead(200, {'content-type': 'application/json'});
          return response.end(JSON.stringify({authentication: {token}}));
        }
        response.writeHead(401, {'content-type': 'application/json'});
        return response.end('{}');
      }
      if (request.method === 'GET' && url.pathname === privatePath) {
        response.writeHead(authorized ? 200 : 401,
          {'content-type': 'application/json'});
        return response.end(authorized ? '{"id":"member"}' : '{}');
      }
      if (request.method === 'HEAD' && [gatePath, metaPath].includes(url.pathname)) {
        if (!authorized) {response.writeHead(401); return response.end();}
        const input = url.searchParams.get('probe') ?? '';
        const output = vulnerable && /^hex:(?:[0-9a-f]{2}){4,80}$/i.test(input) ?
          Buffer.from(input.slice(4), 'hex').toString('utf8') : input;
        response.writeHead(200, {'link': `</audit/${output}>; rel=next`});
        return response.end();
      }
      response.writeHead(404); response.end();
    });
    await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
    t.after(() => new Promise(resolve => server.close(resolve)));
    const origin = `http://127.0.0.1:${server.address().port}`;
    const scope = structuredClone(DEFAULT_SCOPE);
    scope.target.origin = origin;
    scope.target.environment = 'local';
    scope.credentialOrigins = [origin];
    const surface = {patterns: [
      {pattern: gatePath, methods: ['HEAD'], params: {}, source: ['api-document']},
      {pattern: metaPath, methods: ['HEAD'], params: {probe: ['plain']},
        source: ['api-document']},
    ], mined: {endpoints: [
      {path: gatePath, method: 'HEAD', params: []},
      {path: metaPath, method: 'HEAD', params: ['probe']},
    ]}};
    const marker = `bx${randomBytes(6).toString('hex')}`;
    const secondMarker = `bx${randomBytes(6).toString('hex')}`;
    const proposal = {family: 'header expression rendering', why: 'Observed protected HEAD metadata includes a query input',
      priority: 8, as: 'derived', oracle: 'marker',
      prelude: [{method: 'HEAD', path: gatePath, as: 'derived', headers: []}],
      subject: {method: 'HEAD', path: metaPath, placement: 'query', key: 'probe',
        fixedFields: [], bodyTemplate: '', headers: []}, observe: [],
      controlValue: 'plain',
      firstValue: `hex:${Buffer.from(marker).toString('hex')}`,
      secondValue: `hex:${Buffer.from(secondMarker).toString('hex')}`,
      marker, secondMarker,
      assertion: {step: 'subject', index: 0, location: 'header', name: 'link'}};
    const accepted = validateResearchFlow(proposal, surface, scope, {derivedAvailable: true});
    assert.equal(accepted.ok, true, JSON.stringify(accepted));
    const derivedLogin = {kind: 'model-auth-login', proofMode: 'protected-status',
      request: {method: 'POST', url: loginPath, as: 'anonymous'}, loginPath,
      privatePath, userField: 'username', passwordField: 'password',
      userPayloads: ["admin' OR '1'='1"], tokenPointer: '/authentication/token',
      reviewedAuthPosts: [{path: loginPath, usernameField: 'username',
        passwordField: 'password'}]};
    const login = await fetch(`${origin}${loginPath}`, {method: 'POST',
      headers: {'content-type': 'application/json'},
      body: JSON.stringify({username: "admin' OR '1'='1",
        password: `bx-invalid-${randomBytes(12).toString('hex')}`})});
    assert.equal(login.status, 200);
    const session = (await login.json()).authentication.token;
    let evidence = 0;
    const send = async (request, token = null) => {
      const response = await fetch(new URL(request.url, origin), {
        method: request.method, body: request.body,
        headers: {...request.headers,
          ...(token ? {authorization: `Bearer ${token}`} : {})}});
      return {status: response.status, body: await response.text(),
        type: response.headers.get('content-type') ?? '',
        headers: Object.fromEntries(response.headers),
        evidenceId: `ev-${++evidence}`};
    };
    const live = await runResearchFlows([accepted.lead], scope, {surface,
      requester: request => send(request), derivedSession: {
        loginProof: derivedLogin,
        requestAuthenticated: request => send(request, session)},
      modelCallsAvailable: 0});
    assert.ok(live.findings.some(item => item.kind === 'model-http-sequence' &&
      item.verdict === 'observed'), JSON.stringify(live.results));
    const webProof = {kind: 'model-http-sequence', ...accepted.lead, derivedLogin};
    const run = 'bx-20261029-1234abcd';
    const runDir = path.join(root, '.bypass/runs', run);
    fs.mkdirSync(runDir, {recursive: true});
    fs.writeFileSync(path.join(runDir, 'run.json'), '{}');
    const finding = {id: 'f-001', kind: 'model-http-sequence', pattern: metaPath,
      url: `${origin}${metaPath}`, confirmation: [], webProof};
    const ledger = createLedger(runDir, {run});
    const proved = await proveFindings([finding], [],
      {runDir, surface, scope, env: {}, ledger, web: {results: []}});
    assert.equal(proved.length, 1);
    const spec = JSON.parse(fs.readFileSync(path.join(runDir,
      'poc/f-001/spec.json'), 'utf8'));
    assert.equal(validModelHttpSequence(spec), true);
    assert.equal((await verifyRun(root, run, {env: {}})).proofs[0].verdict, 'observed');
    assert.ok(calls.some(call => call === `HEAD ${gatePath}`));
    assert.ok(calls.some(call => call === `HEAD ${metaPath}`));
    assert.ok(!calls.some(call => call === `GET ${gatePath}` || call === `GET ${metaPath}`));
    const exported = exportRun(root, run, {out: path.join(root, 'regression')});
    const regression = () => execFile(process.execPath, ['--test', ...exported.files],
      {env: {...process.env, NODE_TEST_CONTEXT: undefined}, timeout: 30000});
    assert.equal((await regression()).code, 1);
    vulnerable = false;
    assert.equal((await verifyRun(root, run, {env: {}})).proofs[0].verdict,
      'not_reproduced');
    assert.equal((await regression()).code, 0);
    assert.ok(issuedCount >= 4, 'proof replay must refresh the derived session');
    const artifacts = [path.join(runDir, 'poc/f-001/spec.json'), ...exported.files]
      .map(file => fs.readFileSync(file, 'utf8')).join('\n');
    assert.doesNotMatch(artifacts, /bx-head-[0-9a-f]{32}/);
  });
