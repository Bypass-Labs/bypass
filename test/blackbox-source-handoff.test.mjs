import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import http from 'node:http';
import os from 'node:os';
import path from 'node:path';
import {randomBytes} from 'node:crypto';
import {runAudit} from '../src/blackbox/index.mjs';
import {checkLiveRevision} from '../src/blackbox/focus.mjs';
import {verifyRun} from '../src/blackbox/poc.mjs';
import {jsonDisclosureOutcome} from '../src/blackbox/poc-runtime.mjs';
import {initStore, change} from '../src/store.mjs';

const blank = schema => schema?.type === 'object' ?
  Object.fromEntries((schema.required ?? []).map(key => [key, blank(schema.properties?.[key])])) :
  schema?.type === 'array' ? [] : schema?.type === 'integer' || schema?.type === 'number' ? 0 :
  schema?.type === 'boolean' ? false : schema?.enum?.[0] ?? '';

test('anonymous JSON proof ignores reflected IDs and unstable selected values', () => {
  const requests = [{path: '/records/7'}, {path: '/records/8'}];
  const response = body => ({status: 200, type: 'application/json',
    headers: {}, body: JSON.stringify(body)});
  assert.equal(jsonDisclosureOutcome([
    response({id: 7}), response({id: 8}),
    response({id: 7}), response({id: 8})], requests, ['/id'],
  {sourcePath: '/records/7', sourceClaim: 'id'}).verdict,
  'not_reproduced');
  assert.equal(jsonDisclosureOutcome([
    response({detail: 'alpha'}), response({detail: 'bravo'}),
    response({detail: 'changed'}), response({detail: 'bravo'})],
  requests, ['/detail'],
  {sourcePath: '/records/7', sourceClaim: 'detail'}).verdict, 'inconclusive');
  assert.equal(jsonDisclosureOutcome([
    response({detail: 'alpha'}), response({detail: 'bravo'}),
    response({detail: 'alpha'}), response({detail: 'bravo'})],
  [{path: '/public/7'}, {path: '/public/8'}], ['/detail'],
  {sourcePath: '/private/7', sourceClaim: 'detail'}).verdict, 'inconclusive');
});

test('a saved source hypothesis reaches focused Muse planning and independent live proof',
  {timeout: 90000}, async t => {
    const suffix = randomBytes(4).toString('hex');
    const route = `/api/control-${suffix}`;
    const header = `x-identity-${suffix}`;
    const value = `crew_${randomBytes(4).toString('hex')}`;
    const requests = [];
    let vulnerable = true;
    const server = http.createServer((request, response) => {
      const pathname = new URL(request.url, 'http://fixture.invalid').pathname;
      requests.push(pathname);
      const opened = vulnerable && pathname === route && request.headers[header] === value;
      response.writeHead(opened ? 200 : 401,
        {'content-type': 'application/json', 'cache-control': 'no-store'});
      response.end(JSON.stringify(opened ? {control: 'armed'} : {error: 'denied'}));
    });
    await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
    t.after(() => new Promise(resolve => server.close(resolve)));
    const origin = `http://127.0.0.1:${server.address().port}`;
    const root = fs.mkdtempSync(path.join(os.tmpdir(), 'bypass-source-handoff-'));
    t.after(() => fs.rmSync(root, {recursive: true, force: true}));
    initStore(root, root, 'fixture');
    await change(root, state => state.findings.push({id: 'finding_fixture',
      title: 'Client header impersonates an operator', category: 'missing-authentication',
      hypothesis: `The unauthenticated ${header} header with ${value} opens ${route}.`,
      resourcePath: route, sourceEvidence: {kind: 'source', file: 'src/server.ts',
        line: 42, quote: `return request.headers['${header}'];`}, status: 'unproven'}));
    let focusedPrompt = false;
    const raw = headers => ({method: 'GET', path: route, headers, body: ''});
    const infer = async (_profile, messages, options) => {
      if (messages[0].content.startsWith('You are planning bounded, authorized HTTP research.')) {
        const context = JSON.parse(messages[1].content);
        if (!context.sourceFinding) return {flows: []};
        focusedPrompt = context.sourceFinding.id === 'finding_fixture' &&
          context.sourceFinding.path === route &&
          context.sourceFinding.hypothesis.includes(header);
        return {flows: [{family: 'source-backed access boundary',
          why: 'Compare the claimed header against anonymous controls', priority: 9,
          as: 'anonymous', oracle: 'raw-proof',
          rawRequests: [raw([{name: header, value}])],
          rawProof: {baseline: [raw([])],
            negative: [raw([{name: header, value: 'wrong'}])],
            closedText: '', openText: ''}}]};
      }
      return blank(options.schema);
    };
    const audit = await runAudit({url: origin, root, findingId: 'finding_fixture',
      infer, env: {}, offline: true,
      modelProfileOverride: {provider: 'fixture', model: 'fixture'},
      overrides: {acceptLocal: true, rps: 80, modelCalls: 40,
        maxTasks: 0, minutes: 2}});
    assert.equal(focusedPrompt, true);
    assert.ok(audit.findings.some(item => item.kind === 'model-raw-boundary'),
      JSON.stringify(audit.findings));
    assert.ok(!requests.includes('/robots.txt') && !requests.includes('/sitemap.xml'));
    assert.ok(requests.every(item => item === route || item === '/'), requests.join(', '));
    const observed = JSON.parse(fs.readFileSync(path.join(audit.runDir,
      'observed-routes.json'), 'utf8'));
    assert.ok(!observed.routes.some(item => item.path === route && item.method === 'GET'));
    assert.equal(fs.existsSync(path.join(audit.runDir, 'confirmed-access-recon.json')), false);
    assert.equal(JSON.parse(fs.readFileSync(path.join(audit.runDir, 'run.json'), 'utf8'))
      .focus.findingId, 'finding_fixture');
    const report = fs.readFileSync(path.join(audit.runDir, 'report.md'), 'utf8');
    assert.match(report, /Focused source finding: `finding_fixture`/);
    assert.match(report, /Source\/live revision: unverified/);
    const replay = await verifyRun(root, audit.run, {env: {}});
    assert.ok(replay.proofs.some(item => item.verdict === 'confirmed'));
    vulnerable = false;
    const fixed = await runAudit({url: origin, root, findingId: 'finding_fixture',
      infer, env: {}, offline: true,
      modelProfileOverride: {provider: 'fixture', model: 'fixture'},
      overrides: {acceptLocal: true, rps: 80, modelCalls: 40,
        maxTasks: 0, minutes: 2}});
    assert.ok(!fixed.findings.some(item => item.kind === 'model-raw-boundary'));
  });

test('source-focused anonymous JSON disclosure gets a fresh proof and stops after the fix',
  {timeout: 90000}, async t => {
    const suffix = randomBytes(4).toString('hex');
    const base = `/api/dossier-${suffix}`;
    const routes = [`${base}/1`, `${base}/2`];
    const field = `private_${suffix}`;
    const values = routes.map(() => `secret_${randomBytes(12).toString('hex')}`);
    const requests = [];
    let vulnerable = true;
    const server = http.createServer((request, response) => {
      const pathname = new URL(request.url, 'http://fixture.invalid').pathname;
      requests.push({method: request.method, path: pathname,
        authorization: request.headers.authorization ?? null,
        cookie: request.headers.cookie ?? null});
      const index = routes.indexOf(pathname);
      const opened = vulnerable && request.method === 'GET' && index !== -1;
      response.writeHead(opened ? 200 : 401,
        {'content-type': 'application/json', 'cache-control': 'no-store'});
      response.end(JSON.stringify(opened ? {id: index + 1, [field]: values[index]} :
        {error: 'authentication required'}));
    });
    await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
    t.after(() => new Promise(resolve => server.close(resolve)));
    const origin = `http://127.0.0.1:${server.address().port}`;
    const root = fs.mkdtempSync(path.join(os.tmpdir(), 'bypass-source-disclosure-'));
    t.after(() => fs.rmSync(root, {recursive: true, force: true}));
    initStore(root, root, 'fixture');
    await change(root, state => state.findings.push({id: 'finding_disclosure',
      title: 'Private dossier records are readable without a session',
      category: 'missing-authentication',
      hypothesis: `GET ${base}/:id returns a private ${field} field without a session.`,
      resourcePath: routes[0], method: 'GET',
      sourceEvidence: {kind: 'source', file: 'src/server.ts', line: 42,
        quote: `sendJson(res, 200, {id, ${field}: privateRecord.${field}});`},
      status: 'unproven'}));
    let focusedPrompt = false;
    const infer = async (_profile, messages, options) => {
      if (messages[0].content.startsWith('You are planning bounded, authorized HTTP research.')) {
        const context = JSON.parse(messages[1].content);
        if (!context.sourceFinding) return {flows: []};
        focusedPrompt = context.sourceFinding.id === 'finding_disclosure' &&
          context.sourceFinding.hypothesis.includes(field);
        return {flows: [{family: 'source-backed anonymous record disclosure',
          why: 'Read two distinct private records without a session', priority: 9,
          as: 'anonymous', oracle: 'anonymous-json-disclosure',
          rawRequests: routes.map(route => ({method: 'GET', path: route})),
          jsonPointers: [`/${field}`]}]};
      }
      return blank(options.schema);
    };
    const options = {url: origin, root, findingId: 'finding_disclosure',
      infer, env: {}, offline: true,
      modelProfileOverride: {provider: 'fixture', model: 'fixture'},
      overrides: {acceptLocal: true, rps: 80, modelCalls: 40,
        maxTasks: 0, minutes: 2}};
    const audit = await runAudit(options);
    assert.equal(focusedPrompt, true);
    const finding = audit.findings.find(item =>
      item.kind === 'model-anonymous-json-disclosure' && item.verdict === 'confirmed');
    assert.ok(finding, JSON.stringify({findings: audit.findings,
      focus: JSON.parse(fs.readFileSync(path.join(audit.runDir,
        'focus.json'), 'utf8')),
      web: JSON.parse(fs.readFileSync(path.join(audit.runDir,
        'web-probes.json'), 'utf8'))}));
    assert.ok(requests.length >= 4);
    assert.ok(requests.every(item => item.method === 'GET' &&
      routes.includes(item.path) && !item.authorization && !item.cookie));
    const replay = await verifyRun(root, audit.run, {env: {}});
    assert.ok(replay.proofs.some(item => item.id === finding.id &&
      item.verdict === 'confirmed'), JSON.stringify(replay.proofs));
    const savedFiles = fs.readdirSync(audit.runDir, {recursive: true, withFileTypes: true})
      .filter(item => item.isFile())
      .map(item => ({file: path.join(item.parentPath, item.name),
        text: fs.readFileSync(path.join(item.parentPath, item.name), 'utf8')}));
    const leaked = savedFiles.filter(item => values.some(value => item.text.includes(value)))
      .map(item => path.relative(audit.runDir, item.file));
    assert.deepEqual(leaked, [], JSON.stringify({message: 'private response values must not appear',
      evidence: fs.readFileSync(path.join(audit.runDir, 'evidence.jsonl'), 'utf8')
        .split('\n').filter(line => values.some(value => line.includes(value)))
        .map(line => {const entry = JSON.parse(line); return {step: entry.step,
          kind: entry.kind, hasExcerpt: !!entry.excerpt};})}));
    vulnerable = false;
    const fixed = await runAudit(options);
    assert.ok(!fixed.findings.some(item =>
      item.kind === 'model-anonymous-json-disclosure' && item.verdict === 'confirmed'));
  });

test('focused POST hypothesis does not invent an observed GET route',
  {timeout: 90000}, async t => {
    const route = `/api/verify-${randomBytes(4).toString('hex')}`;
    const server = http.createServer((request, response) => {
      response.writeHead(request.url === '/' ? 200 : 401,
        {'content-type': request.url === '/' ? 'text/html' : 'application/json'});
      response.end(request.url === '/' ? '<html><body>App</body></html>' : '{}');
    });
    await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
    t.after(() => new Promise(resolve => server.close(resolve)));
    const origin = `http://127.0.0.1:${server.address().port}`;
    const root = fs.mkdtempSync(path.join(os.tmpdir(), 'bypass-source-post-'));
    t.after(() => fs.rmSync(root, {recursive: true, force: true}));
    initStore(root, root, 'fixture');
    await change(root, state => state.findings.push({id: 'finding_post',
      title: 'Second step accepts an invalid code', category: 'authentication-bypass',
      hypothesis: 'A prior step returns a fresh challenge used by this POST route.',
      resourcePath: route, method: 'UNKNOWN',
      sourceEvidence: {kind: 'source', file: 'src/server.ts', line: 1,
        quote: 'if (body.flag) return session;'}, status: 'unproven'}));
    const audit = await runAudit({url: origin, root, findingId: 'finding_post',
      infer: async (_profile, _messages, options) => blank(options.schema),
      env: {}, offline: true,
      modelProfileOverride: {provider: 'fixture', model: 'fixture'},
      overrides: {acceptLocal: true, rps: 80, modelCalls: 8,
        maxTasks: 0, minutes: 2}});
    const observed = JSON.parse(fs.readFileSync(path.join(audit.runDir,
      'observed-routes.json'), 'utf8'));
    assert.equal(observed.routes.some(item => item.path === route && item.method === 'GET'), false);
    const assets = JSON.parse(fs.readFileSync(path.join(audit.runDir, 'assets.json'), 'utf8'));
    assert.ok(assets.endpoints.some(item => item.path === route && item.method === 'UNKNOWN'));
  });

test('focused Muse research proves a source-backed two-POST boundary with fresh response bindings',
  {timeout: 90000}, async t => {
    const suffix = randomBytes(4).toString('hex');
    const begin = `/api/begin-${suffix}`;
    const finish = `/api/finish-${suffix}`;
    const inputField = 'email';
    const passwordField = 'password';
    const loginUser = `pilot_${randomBytes(8).toString('hex')}`;
    const loginPassword = `pass_"\\${randomBytes(16).toString('hex')}`;
    const env = {AUDIT_FIXTURE_USER: loginUser, AUDIT_FIXTURE_PASS: loginPassword};
    const idField = `ticket${suffix}`;
    const optionField = `option${suffix}`;
    const issued = new Set();
    const submitted = [];
    let vulnerable = true;
    const server = http.createServer(async (request, response) => {
      const pathname = new URL(request.url, 'http://fixture.invalid').pathname;
      const chunks = [];
      for await (const chunk of request) chunks.push(chunk);
      let body = {};
      try {body = JSON.parse(Buffer.concat(chunks).toString() || '{}');} catch {}
      const send = (status, value) => {
        response.writeHead(status, {'content-type': 'application/json',
          'cache-control': 'no-store'});
        response.end(JSON.stringify(value));
      };
      if (request.method === 'POST' && pathname === begin) {
        if (body[inputField] !== loginUser || body[passwordField] !== loginPassword)
          return send(401, {error: 'login required'});
        const fresh = randomBytes(24).toString('hex');
        issued.add(fresh);
        return send(200, {[idField]: fresh});
      }
      if (request.method === 'POST' && pathname === finish) {
        submitted.push({id: body[idField], option: body[optionField]});
        if (!issued.delete(body[idField])) return send(400, {error: 'fresh id required'});
        const opened = vulnerable && body[optionField] === true;
        return send(opened ? 200 : 401,
          opened ? {access: 'opened'} : {error: 'denied'});
      }
      return send(404, {error: 'not a read route'});
    });
    await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
    t.after(() => new Promise(resolve => server.close(resolve)));
    const origin = `http://127.0.0.1:${server.address().port}`;
    const root = fs.mkdtempSync(path.join(os.tmpdir(), 'bypass-source-post-handoff-'));
    t.after(() => fs.rmSync(root, {recursive: true, force: true}));
    fs.mkdirSync(path.join(root, 'src'));
    fs.writeFileSync(path.join(root, 'src', 'server.ts'),
      `if (method === 'POST' && path === '${begin}') {\n` +
      `  const body = await readJson(req);\n  requireString(body.${inputField});\n` +
      `  requireString(body.${passwordField});\n` +
      `  sendJson(res, 200, {${idField}: freshToken()});\n}\n` +
      `if (method === 'POST' && path === '${finish}') {\n` +
      `  const body = await readJson(req);\n` +
      `  sendJson(res, consume(body.${idField}) && body.${optionField} === true ? 200 : 401, {});\n}\n`);
    initStore(root, root, 'fixture');
    await change(root, state => state.findings.push({id: 'finding_two_step',
      title: 'A source-backed two-step boundary', category: 'missing-authentication',
      hypothesis: `POST ${begin} with JSON ${inputField} returns ${idField}; ` +
        `POST ${finish} with JSON ${idField} and ${optionField} may open the boundary.`,
      resourcePath: finish, sourceEvidence: {kind: 'source', file: 'src/server.ts',
        line: 5, quote: `if (method === 'POST' && path === '${finish}')`},
      status: 'unproven'}));
    const scopeFile = path.join(root, 'blackbox.scope.json');
    fs.writeFileSync(scopeFile, JSON.stringify({schemaVersion: 1,
      target: {origin}, include: ['/api'], methods: ['GET', 'HEAD', 'POST'],
      identities: {login: {path: begin, usernameField: inputField,
        passwordField, encoding: 'json'}, owner: {login: {
        usernameEnv: 'AUDIT_FIXTURE_USER', passwordEnv: 'AUDIT_FIXTURE_PASS'}}},
      limits: {rps: 80, modelCalls: 40, tasks: 0, minutes: 2}}));
    let focusedPrompt = false;
    const step = (route, key, value, fixedFields = []) => ({method: 'POST', path: route,
      placement: 'json', key, value, fixedFields, bodyTemplate: '', headers: []});
    const infer = async (_profile, messages, options) => {
      if (messages[0].content.startsWith('You are planning bounded, authorized HTTP research.')) {
        const context = JSON.parse(messages[1].content);
        focusedPrompt = context.sourceFinding?.id === 'finding_two_step' &&
          context.sourceFinding.hypothesis.includes(begin) &&
          context.sourceFinding.hypothesis.includes(finish) &&
          context.credentialReferences?.some(item => item.identity === 'owner' &&
            item.username === '{{env:AUDIT_FIXTURE_USER}}' &&
            item.password === '{{env:AUDIT_FIXTURE_PASS}}');
        return {flows: [{family: 'source-backed staged boundary',
          why: 'Use the fresh first response in the second POST', priority: 9,
          as: 'anonymous', oracle: 'status-boundary',
          prelude: [step(begin, inputField, '{{env:AUDIT_FIXTURE_USER}}',
            [{field: passwordField, value: '{{env:AUDIT_FIXTURE_PASS}}'}])],
          subject: {...step(finish, optionField, ''), valueEncoding: 'json'},
          binding: {from: 0, pointer: `/${idField}`, to: 'subject',
            index: 0, key: idField},
          controlValue: 'false', firstValue: 'true', secondValue: 'null',
          marker: '', secondMarker: '',
          assertion: {step: 'subject', index: 0, location: 'body', name: ''}}]};
      }
      return blank(options.schema);
    };
    const audit = await runAudit({url: origin, root, scopeFile,
      findingId: 'finding_two_step', infer, env, offline: true,
      modelProfileOverride: {provider: 'fixture', model: 'fixture'},
      overrides: {acceptLocal: true, rps: 80, modelCalls: 40,
        maxTasks: 0, minutes: 2}});
    const web = JSON.parse(fs.readFileSync(path.join(audit.runDir,
      'web-probes.json'), 'utf8'));
    const source = JSON.parse(fs.readFileSync(path.join(audit.runDir,
      'source.json'), 'utf8'));
    const surface = JSON.parse(fs.readFileSync(path.join(audit.runDir,
      'surface.json'), 'utf8'));
    assert.equal(focusedPrompt, true);
    assert.ok(source.endpoints.some(item => item.path === begin &&
      item.method === 'POST' && item.bodyFields?.includes(inputField)));
    assert.ok(source.endpoints.some(item => item.path === finish &&
      item.method === 'POST' && item.bodyFields?.includes(optionField)));
    assert.ok(surface.authBodyOperations.some(item => item.path === begin &&
      item.method === 'POST'), JSON.stringify(surface.authBodyOperations));
    assert.ok(surface.methodOperations.some(item => item.path === finish &&
      item.method === 'POST'), JSON.stringify(surface.methodOperations));
    assert.ok(web.strategyDecisions.some(item => item.mode === 'http-sequence' &&
      item.accepted), JSON.stringify(web.strategyDecisions));
    assert.ok(submitted.length >= 2, JSON.stringify({submitted,
      decisions: web.strategyDecisions}));
    assert.ok(submitted.every(item => typeof item.id === 'string' &&
      /^[0-9a-f]{48}$/.test(item.id)));
    assert.equal(new Set(submitted.map(item => item.id)).size, submitted.length,
      'every subject must receive a fresh first-step id');
    const finding = audit.findings.find(item => item.verdict === 'confirmed' &&
      item.webProof?.oracle === 'status-boundary');
    assert.ok(finding, JSON.stringify(audit.findings));
    const savedFiles = [];
    const collect = dir => {
      for (const item of fs.readdirSync(dir, {withFileTypes: true})) {
        const file = path.join(dir, item.name);
        if (item.isDirectory()) collect(file);
        else if (item.isFile()) savedFiles.push(file);
      }
    };
    collect(audit.runDir);
    const saved = savedFiles.map(file => fs.readFileSync(file, 'utf8')).join('\n');
    assert.ok(!saved.includes(loginUser) && !saved.includes(loginPassword),
      'configured credentials must stay out of checkpoints, evidence and proofs');
    assert.ok(saved.includes('{{env:AUDIT_FIXTURE_PASS}}'));
    const replay = await verifyRun(root, audit.run, {env});
    assert.ok(replay.proofs.some(item => item.id === finding.id &&
      item.verdict === 'confirmed'), JSON.stringify(replay.proofs));
    vulnerable = false;
    const fixed = await verifyRun(root, audit.run, {env});
    assert.ok(fixed.proofs.some(item => item.id === finding.id &&
      item.verdict === 'not_reproduced'), JSON.stringify(fixed.proofs));
  });

test('live revision comparison reports exact match, mismatch and missing attestation', async () => {
  const sha = randomBytes(20).toString('hex');
  const focus = {sourceRevision: sha};
  const requester = async () => ({body: JSON.stringify({build: {sha}}), evidenceId: 'ev-0001'});
  assert.equal((await checkLiveRevision(focus, requester, '/version', 'build.sha')).status, 'matched');
  assert.equal((await checkLiveRevision({...focus, sourceRevision: randomBytes(20).toString('hex')},
    requester, '/version', 'build.sha')).status, 'mismatched');
  assert.equal((await checkLiveRevision(focus, requester, null)).status, 'unverified');
});
