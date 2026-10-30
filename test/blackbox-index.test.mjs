import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import http from 'node:http';
import path from 'node:path';
import {spawn} from 'node:child_process';
import {spawnSync} from 'node:child_process';
import {temp} from './helpers.mjs';
import {runAudit, classifyAuditModelDeadline} from '../src/blackbox/index.mjs';
import {Fault} from '../src/util.mjs';
import {verifyLedger} from '../src/blackbox/ledger.mjs';
import {verifyRun, exportRun} from '../src/blackbox/poc.mjs';

test('audit-limited Muse timeout is a research cut; provider failures remain model failures', () => {
  const timeout = new Fault('Model did not finish within 3 seconds. Check the model connection.',
    3, {reason: 'model_timeout'});
  const deadline = 10_000;
  const cut = classifyAuditModelDeadline(timeout,
    {auditLimited: true, deadline, nowMs: 9_999});
  assert.equal(cut.details.reason, 'research_deadline');
  assert.match(cut.message, /Audit wall-clock deadline cut a Muse research call/);
  assert.doesNotMatch(cut.message, /model connection/i);
  assert.equal(classifyAuditModelDeadline(timeout,
    {auditLimited: false, deadline, nowMs: 10_000}), timeout);
  assert.equal(classifyAuditModelDeadline(timeout,
    {auditLimited: true, deadline, nowMs: 8_000}), timeout);
  const provider = new Fault('Muse reports a provider usage limit.',
    3, {reason: 'usage_limit'});
  assert.equal(classifyAuditModelDeadline(provider,
    {auditLimited: true, deadline, nowMs: 10_000}), provider);
});

test('CLI runner confirms a real cross-account read, writes evidence, and drops it after the fix', async t => {
  const root = temp();
  t.after(() => fs.rmSync(root, {recursive: true, force: true}));
  let vulnerable = true;
  const users = {owner: {id: 'u-1', role: 'member'}, other: {id: 'u-2', role: 'member'}};
  const invoices = [{id: 'inv-101', ownerId: 'u-1', total: 20}, {id: 'inv-202', ownerId: 'u-2', total: 30}];
  const calls = [];
  const server = http.createServer((req, res) => {
    const requestUrl = new URL(req.url, 'http://local');
    const pathname = requestUrl.pathname;
    calls.push(pathname);
    const who = req.headers.authorization === 'Bearer owner-token' ? users.owner :
      req.headers.authorization === 'Bearer other-token' ? users.other : null;
    let status = 404, body = {error: 'Not found'};
    if (pathname === '/') { status = 200; body = '<html><body>Invoices</body></html>'; }
    else if (pathname === '/openapi.json') { status = 200; body = {openapi: '3.0.0', paths: {
      '/api/me': {get: {}}, '/api/invoices': {get: {}}, '/api/invoices/{id}': {get: {}}}}; }
    else if (pathname === '/api/me') { status = who ? 200 : 401; body = who ?? {error: 'Sign in'}; }
    else if (pathname === '/api/invoices') { status = who ? 200 : 401;
      body = who ? vulnerable && requestUrl.searchParams.get('all') === '1' ? invoices :
        invoices.filter(item => item.ownerId === who.id) : {error: 'Sign in'}; }
    else if (pathname.startsWith('/api/invoices/')) {
      const invoice = invoices.find(item => pathname === `/api/invoices/${item.id}`);
      status = !who ? 401 : !invoice ? 404 : invoice.ownerId === who.id || vulnerable ? 200 : 403;
      body = status === 200 ? invoice : {error: status === 403 ? 'Denied' : 'Not found'};
    }
    res.writeHead(status, {'content-type': typeof body === 'string' ? 'text/html' : 'application/json', 'cache-control': 'no-store'});
    res.end(typeof body === 'string' ? body : JSON.stringify(body));
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  t.after(() => new Promise(resolve => server.close(resolve)));
  const origin = `http://127.0.0.1:${server.address().port}`;
  const options = {url: origin, root, noModel: true, overrides: {acceptLocal: true}, env: {OWNER_TOKEN: 'owner-token', OTHER_TOKEN: 'other-token'}};
  const first = await runAudit(options);
  assert.ok(first.findings.some(finding => finding.kind === 'idor'), JSON.stringify(first.findings));
  assert.ok(first.findings.some(finding => finding.kind === 'list-leak'), JSON.stringify(first.findings));
  assert.ok(first.chains > 0, 'the list-to-item chain was independently proved');
  assert.equal(first.exitCode, 1);
  assert.equal(verifyLedger(`${first.runDir}/evidence.jsonl`).ok, true);
  assert.ok(fs.existsSync(first.reportPath));
  assert.ok(first.findings.every(finding => fs.existsSync(finding.proof)), 'every reported finding has an executed proof');
  assert.ok(!calls.some(path => /delete|reset/.test(path)), 'never paths remain untouched');
  const retestBefore = await verifyRun(root, first.run, {env: options.env});
  assert.equal(retestBefore.exitCode, 1, 'the proof reproduces before the fix');
  const specPath = path.join(path.dirname(first.findings[0].proof), 'spec.json');
  const sealed = fs.readFileSync(specPath, 'utf8');
  fs.writeFileSync(specPath, sealed + '\n');
  await assert.rejects(verifyRun(root, first.run, {env: options.env}), /sealed ledger artifact/);
  fs.writeFileSync(specPath, sealed);
  const exported = exportRun(root, first.run, {out: `${root}/tests/security/blackbox`});
  const childEnv = {...Object.fromEntries(Object.entries(process.env).filter(([key]) => key !== 'NODE_TEST_CONTEXT')),
    ...options.env};
  const runGenerated = () => new Promise((resolve, reject) => {
    const child = spawn(process.execPath, ['--test', ...exported.files], {env: childEnv});
    let stdout = '', stderr = '';
    child.stdout.on('data', chunk => { stdout += chunk; });
    child.stderr.on('data', chunk => { stderr += chunk; });
    child.on('error', reject);
    child.on('close', code => resolve({code, stdout, stderr}));
  });
  const red = await runGenerated();
  assert.equal(red.code, 1, `generated test fails on the vulnerable build: ${red.stdout} ${red.stderr}`);

  vulnerable = false;
  const retestAfter = await verifyRun(root, first.run, {env: options.env});
  assert.equal(retestAfter.exitCode, 0, 'the proof no longer reproduces after the fix');
  const green = await runGenerated();
  assert.equal(green.code, 0, green.stderr);
  const second = await runAudit(options);
  assert.ok(!second.findings.some(finding => finding.kind === 'idor'), JSON.stringify(second.findings));
  const sameAccount = await runAudit({...options, env: {OWNER_TOKEN: 'owner-token', OTHER_TOKEN: 'owner-token'}});
  assert.equal(sameAccount.exitCode, 3, 'one credential repeated under two names is not a two-account control');
  assert.equal(sameAccount.findings.filter(item => item.kind === 'idor').length, 0);
});

test('a second credential origin receives authenticated recon, IDOR tasks and its own proof', async t => {
  const root = temp();
  t.after(() => fs.rmSync(root, {recursive: true, force: true}));
  let secondVulnerable = true;
  const origins = [];
  for (const secondary of [false, true]) {
    const server = http.createServer((request, response) => {
      const url = new URL(request.url, 'http://local');
      const who = request.headers.authorization === 'Bearer owner-token' ? 'u-1' :
        request.headers.authorization === 'Bearer other-token' ? 'u-2' : null;
      const invoices = [{id: 'inv-101', ownerId: 'u-1'}, {id: 'inv-202', ownerId: 'u-2'}];
      let status = 404, body = {error: 'Not found'};
      if (url.pathname === '/') {status = 200; body = '<html>Invoices</html>';}
      else if (url.pathname === '/openapi.json') {status = 200; body = {openapi: '3.0.0', paths: {
        '/api/me': {get: {}}, '/api/invoices': {get: {}}, '/api/invoices/{id}': {get: {}}}};}
      else if (url.pathname === '/api/me') {status = who ? 200 : 401;
        body = who ? {id: who, role: 'member'} : {error: 'Sign in'};}
      else if (url.pathname === '/api/invoices') {status = who ? 200 : 401;
        body = who ? invoices.filter(item => item.ownerId === who) : {error: 'Sign in'};}
      else if (url.pathname.startsWith('/api/invoices/')) {
        const invoice = invoices.find(item => url.pathname === `/api/invoices/${item.id}`);
        status = !who ? 401 : !invoice ? 404 : invoice.ownerId === who || secondary && secondVulnerable ? 200 : 403;
        body = status === 200 ? invoice : {error: 'Denied'};
      }
      response.writeHead(status, {'content-type': typeof body === 'string' ? 'text/html' : 'application/json'});
      response.end(typeof body === 'string' ? body : JSON.stringify(body));
    });
    await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
    t.after(() => new Promise(resolve => server.close(resolve)));
    origins.push(`http://127.0.0.1:${server.address().port}`);
  }
  const scopeFile = path.join(root, 'blackbox.scope.json');
  fs.writeFileSync(scopeFile, JSON.stringify({target: {origin: origins[0]}, credentialOrigins: origins,
    include: ['/api'], discovery: {sensitivePaths: false}, limits: {rps: 200, tasks: 120}}));
  const env = {OWNER_TOKEN: 'owner-token', OTHER_TOKEN: 'other-token'};
  const audit = await runAudit({url: origins[0], root, scopeFile, noModel: true,
    overrides: {acceptLocal: true}, env});
  const secondary = audit.findings.find(item => item.kind === 'idor' && item.url.startsWith(origins[1]));
  assert.ok(secondary, JSON.stringify(audit.findings));
  assert.ok(fs.existsSync(secondary.proof));
  assert.equal(JSON.parse(fs.readFileSync(path.join(path.dirname(secondary.proof), 'spec.json'))).origin, origins[1]);
  const originAudit = JSON.parse(fs.readFileSync(path.join(audit.runDir, 'credential-origins.json')));
  assert.equal(originAudit[0].surface.identity.verified, true);
  assert.ok(originAudit[0].results.some(item => item.verdict === 'confirmed' && item.task.kind === 'idor'));
  const report = JSON.parse(fs.readFileSync(path.join(audit.runDir, 'report.json')));
  assert.equal(report.surface.application.otherOrigins[0].origin, origins[1]);
  assert.ok(report.findings.find(item => item.id === secondary.id).reproduction.every(step =>
    step.url.startsWith(origins[1])));
  assert.equal((await verifyRun(root, audit.run, {env})).exitCode, 1);
  secondVulnerable = false;
  assert.equal((await verifyRun(root, audit.run, {env})).exitCode, 0);
});

test('a secondary credential origin with one account proves its own anonymous sensitive item read', async t => {
  const root = temp();
  t.after(() => fs.rmSync(root, {recursive: true, force: true}));
  let vulnerable = true;
  const origins = [];
  for (const secondary of [false, true]) {
    const server = http.createServer((request, response) => {
      const pathname = new URL(request.url, 'http://local').pathname;
      const owner = request.headers.authorization === 'Bearer owner-token';
      let status = 404, body = {error: 'Not found'};
      if (pathname === '/openapi.json') {status = 200; body = {openapi: '3.0.0', paths: {
        '/api/me': {get: {}}, ...(secondary ? {'/api/records': {get: {}},
          '/api/records/{id}': {get: {}}} : {})}};}
      else if (pathname === '/api/me') {status = owner ? 200 : 401;
        body = owner ? {id: 'u-1', role: 'member'} : {error: 'Sign in'};}
      else if (secondary && pathname === '/api/records') {status = owner ? 200 : 401;
        body = owner ? [{id: 'rec-101', ownerId: 'u-1'}] : {error: 'Sign in'};}
      else if (secondary && pathname === '/api/records/rec-101') {status = owner || vulnerable ? 200 : 401;
        body = status === 200 ? {id: 'rec-101', ownerId: 'u-1', balance: 125} : {error: 'Sign in'};}
      response.writeHead(status, {'content-type': 'application/json', 'cache-control': 'no-store'});
      response.end(JSON.stringify(body));
    });
    await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
    t.after(() => new Promise(resolve => server.close(resolve)));
    origins.push(`http://127.0.0.1:${server.address().port}`);
  }
  const scopeFile = path.join(root, 'blackbox.scope.json');
  fs.writeFileSync(scopeFile, JSON.stringify({target: {origin: origins[0]}, credentialOrigins: origins,
    include: ['/api'], identities: {identityPath: '/api/me'},
    discovery: {sensitivePaths: false}, limits: {rps: 200, tasks: 120}}));
  const env = {OWNER_TOKEN: 'owner-token'};
  const audit = await runAudit({url: origins[0], root, scopeFile, noModel: true,
    overrides: {acceptLocal: true}, env});
  const finding = audit.findings.find(item => item.kind === 'missing-auth' &&
    item.url.startsWith(origins[1]) && item.pattern === '/api/records/{id}');
  assert.ok(finding?.proof, JSON.stringify(audit.findings));
  assert.ok(finding.tags.includes('single-account'));
  assert.ok(finding.tags.includes('owner-identity-only'));
  const originAudit = JSON.parse(fs.readFileSync(path.join(audit.runDir, 'credential-origins.json')));
  assert.equal(originAudit[0].surface.identity.ownerVerified, true);
  assert.equal(originAudit[0].surface.identity.verified, false);
  assert.ok(originAudit[0].results.some(item => item.verdict === 'confirmed' &&
    item.task.pattern === '/api/records/{id}'));
  assert.equal((await verifyRun(root, audit.run, {env})).exitCode, 1);
  vulnerable = false;
  assert.equal((await verifyRun(root, audit.run, {env})).exitCode, 0);
});

test('anonymous source-assisted run proves an open redirect with two canaries and a replayable fix test', async t => {
  const root = temp();
  t.after(() => fs.rmSync(root, {recursive: true, force: true}));
  const source = `${root}/app-source`;
  fs.mkdirSync(source);
  fs.writeFileSync(`${source}/server.js`, "app.get('/api/go', (req, res) => { const next = req.query.next; res.redirect(next); });\n");
  let vulnerable = true;
  const server = http.createServer((req, res) => {
    const url = new URL(req.url, 'http://local');
    if (url.pathname === '/api/go') {
      const destination = vulnerable ? url.searchParams.get('next') ?? '/' : '/home';
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
  const first = await runAudit({url: origin, root, sourcePath: source, noModel: true,
    overrides: {acceptLocal: true}, env: {}});
  assert.equal(first.exitCode, 1);
  assert.ok(first.findings.some(item => item.kind === 'open-redirect'));
  assert.equal(verifyLedger(`${first.runDir}/evidence.jsonl`).ok, true);
  const report = JSON.parse(fs.readFileSync(`${first.runDir}/report.json`, 'utf8'));
  assert.equal(report.findings.find(item => item.kind === 'open-redirect').reproduction.length, 2);
  assert.equal((await verifyRun(root, first.run, {env: {}})).exitCode, 1);
  const exported = exportRun(root, first.run, {out: `${root}/regression`});
  const childEnv = Object.fromEntries(Object.entries(process.env).filter(([key]) => key !== 'NODE_TEST_CONTEXT'));
  const runExport = () => new Promise((resolve, reject) => {
    const child = spawn(process.execPath, ['--test', ...exported.files], {env: childEnv});
    child.on('error', reject);
    child.on('close', resolve);
  });
  assert.equal(await runExport(), 1);
  vulnerable = false;
  assert.equal((await verifyRun(root, first.run, {env: {}})).exitCode, 0);
  assert.equal(await runExport(), 0);
});

test('cookie-authenticated private data with two reflected Origins gets a bounded CORS proof', async t => {
  const root = temp();
  t.after(() => fs.rmSync(root, {recursive: true, force: true}));
  let permissive = true;
  const server = http.createServer((req, res) => {
    const pathname = new URL(req.url, 'http://local').pathname;
    const who = req.headers.cookie === 'sid=owner' ? 'u-1' : req.headers.cookie === 'sid=other' ? 'u-2' : null;
    let status = 404, body = {error: 'Not found'};
    if (pathname === '/openapi.json') {status = 200; body = {openapi: '3.0.0', paths: {
      '/api/me': {get: {}}, '/api/items': {get: {}}}};}
    else if (pathname === '/api/me') {status = who ? 200 : 401; body = who ? {id: who, role: 'member'} : {error: 'Sign in'};}
    else if (pathname === '/api/items') {status = who ? 200 : 401;
      body = who ? [{id: who === 'u-1' ? 'itm-101' : 'itm-202', ownerId: who}] : {error: 'Sign in'};}
    const headers = {'content-type': 'application/json', 'cache-control': 'no-store'};
    if (permissive && pathname === '/api/items' && req.headers.origin) {
      headers['access-control-allow-origin'] = req.headers.origin;
      headers['access-control-allow-credentials'] = 'true';
    }
    res.writeHead(status, headers);
    res.end(JSON.stringify(body));
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  t.after(() => new Promise(resolve => server.close(resolve)));
  const origin = `http://127.0.0.1:${server.address().port}`;
  const options = {url: origin, root, noModel: true, overrides: {acceptLocal: true, auth: 'cookie'},
    env: {OWNER_TOKEN: 'sid=owner', OTHER_TOKEN: 'sid=other'}};
  const audit = await runAudit(options);
  const cors = audit.findings.find(item => item.kind === 'cors-reflection');
  assert.ok(cors, JSON.stringify(audit.findings));
  assert.ok(fs.existsSync(cors.proof));
  assert.equal((await verifyRun(root, audit.run, {env: options.env})).exitCode, 1);
  permissive = false;
  assert.equal((await verifyRun(root, audit.run, {env: options.env})).exitCode, 0);
});

test('one account proves missing authentication on an explicitly configured identity route', async t => {
  const root = temp();
  t.after(() => fs.rmSync(root, {recursive: true, force: true}));
  let vulnerable = true;
  const server = http.createServer((req, res) => {
    const pathname = new URL(req.url, 'http://local').pathname;
    const owner = req.headers.authorization === 'Bearer owner-token';
    let status = 404, body = {error: 'Not found'};
    if (pathname === '/openapi.json') {status = 200; body = {openapi: '3.0.0', paths: {'/api/me': {get: {}}}};}
    if (pathname === '/api/me') {
      status = owner || vulnerable ? 200 : 401;
      body = status === 200 ? {id: 'u-1', email: 'owner@example.test'} : {error: 'Sign in'};
    }
    res.writeHead(status, {'content-type': 'application/json', 'cache-control': 'no-store'});
    res.end(JSON.stringify(body));
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  t.after(() => new Promise(resolve => server.close(resolve)));
  const origin = `http://127.0.0.1:${server.address().port}`;
  const options = {url: origin, root, noModel: true,
    overrides: {acceptLocal: true, identityPath: '/api/me'}, env: {OWNER_TOKEN: 'owner-token'}};
  const audit = await runAudit(options);
  const missing = audit.findings.find(item => item.kind === 'missing-auth');
  assert.ok(missing, JSON.stringify(audit.findings));
  assert.ok(missing.tags.includes('single-account'));
  assert.equal(audit.findings.some(item => item.kind === 'idor'), false);
  assert.equal((await verifyRun(root, audit.run, {env: options.env})).exitCode, 1);
  vulnerable = false;
  assert.equal((await verifyRun(root, audit.run, {env: options.env})).exitCode, 0);
});

test('documented GET URL parameter reaches a local callback twice and exports a red-green SSRF regression', async t => {
  const root = temp();
  t.after(() => fs.rmSync(root, {recursive: true, force: true}));
  let vulnerable = true;
  const server = http.createServer(async (req, res) => {
    const url = new URL(req.url, 'http://local');
    let status = 404, body = {error: 'Not found'};
    if (url.pathname === '/openapi.json') {status = 200; body = {openapi: '3.0.0', paths: {
      '/api/fetch': {get: {parameters: [{name: 'url', in: 'query'}]}}}};}
    else if (url.pathname === '/api/fetch') {
      const destination = url.searchParams.get('url');
      if (!destination) {status = 400; body = {error: 'URL required'};}
      else if (!vulnerable) {status = 403; body = {error: 'Private destinations forbidden'};}
      else if (/^http:\/\/127\.0\.0\.1:\d+\/bx-ssrf\/[0-9a-f]{24}$/.test(destination)) {
        try {await fetch(destination, {redirect: 'manual'}); status = 200; body = {fetched: true};}
        catch {status = 502; body = {error: 'Fetch failed'};}
      } else {status = 400; body = {error: 'Unsupported test URL'};}
    }
    res.writeHead(status, {'content-type': 'application/json', 'cache-control': 'no-store'});
    res.end(JSON.stringify(body));
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  t.after(() => new Promise(resolve => server.close(resolve)));
  const origin = `http://127.0.0.1:${server.address().port}`;
  const audit = await runAudit({url: origin, root, noModel: true, overrides: {acceptLocal: true}, env: {}});
  const finding = audit.findings.find(item => item.kind === 'ssrf-loopback');
  assert.ok(finding, JSON.stringify(audit.findings));
  assert.equal(audit.coverage.rows.find(item => item.family === 'ssrf').status, 'partial');
  assert.equal(verifyLedger(`${audit.runDir}/evidence.jsonl`).ok, true);
  assert.equal((await verifyRun(root, audit.run, {env: {}})).exitCode, 1);
  const exported = exportRun(root, audit.run, {out: `${root}/regression`});
  const childEnv = Object.fromEntries(Object.entries(process.env).filter(([key]) => key !== 'NODE_TEST_CONTEXT'));
  const runExport = () => new Promise((resolve, reject) => {
    const child = spawn(process.execPath, ['--test', ...exported.files], {env: childEnv});
    child.on('error', reject);
    child.on('close', resolve);
  });
  assert.equal(await runExport(), 1);
  vulnerable = false;
  assert.equal((await verifyRun(root, audit.run, {env: {}})).exitCode, 0);
  assert.equal(await runExport(), 0);
});

test('reflected XSS executes inert markers in isolated Chrome and exports a red-green regression', async t => {
  const chrome = process.env.BYPASS_CHROME ?? 'google-chrome';
  if (spawnSync(chrome, ['--version']).error) {t.skip('Chrome is unavailable for browser proof'); return;}
  const root = temp();
  t.after(() => fs.rmSync(root, {recursive: true, force: true}));
  let vulnerable = true;
  const escapeHtml = value => value.replaceAll('&', '&amp;').replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;').replaceAll('"', '&quot;').replaceAll("'", '&#39;');
  const server = http.createServer((req, res) => {
    const url = new URL(req.url, 'http://local');
    if (url.pathname === '/openapi.json') {
      res.writeHead(200, {'content-type': 'application/json'});
      return res.end(JSON.stringify({openapi: '3.0.0', paths: {
        '/api/search': {get: {parameters: [{name: 'q', in: 'query'}]}}}}));
    }
    if (url.pathname === '/api/search') {
      const query = url.searchParams.get('q') ?? '';
      res.writeHead(200, {'content-type': 'text/html', 'cache-control': 'no-store'});
      return res.end(`<html><body><div id="result">${vulnerable ? query : escapeHtml(query)}</div></body></html>`);
    }
    res.writeHead(404);
    res.end();
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  t.after(() => new Promise(resolve => server.close(resolve)));
  const origin = `http://127.0.0.1:${server.address().port}`;
  const audit = await runAudit({url: origin, root, noModel: true, overrides: {acceptLocal: true}, env: {}});
  const finding = audit.findings.find(item => item.kind === 'xss-reflected');
  assert.ok(finding, JSON.stringify(audit.findings));
  assert.equal(audit.coverage.rows.find(item => item.family === 'xss').status, 'partial');
  const browserEvidence = fs.readFileSync(`${audit.runDir}/evidence.jsonl`, 'utf8').trim().split('\n')
    .map(line => JSON.parse(line)).filter(row => row.step === 'browser' && row.kind === 'xss-reflected');
  assert.equal(browserEvidence.filter(row => row.executed).length, 2);
  assert.equal((await verifyRun(root, audit.run, {env: {}})).exitCode, 1);
  const exported = exportRun(root, audit.run, {out: `${root}/regression`});
  const childEnv = Object.fromEntries(Object.entries(process.env).filter(([key]) => key !== 'NODE_TEST_CONTEXT'));
  const runExport = () => new Promise((resolve, reject) => {
    const child = spawn(process.execPath, ['--test', ...exported.files], {env: childEnv});
    child.on('error', reject);
    child.on('close', resolve);
  });
  assert.equal(await runExport(), 1);
  vulnerable = false;
  assert.equal((await verifyRun(root, audit.run, {env: {}})).exitCode, 0);
  assert.equal(await runExport(), 0);
});

test('two harmless template expressions prove server-side evaluation and replay after a fix', async t => {
  const root = temp();
  t.after(() => fs.rmSync(root, {recursive: true, force: true}));
  let vulnerable = true;
  const server = http.createServer((req, res) => {
    const url = new URL(req.url, 'http://local');
    if (url.pathname === '/openapi.json') {
      res.writeHead(200, {'content-type': 'application/json'});
      return res.end(JSON.stringify({openapi: '3.0.0', paths: {
        '/api/render': {get: {parameters: [{name: 'q', in: 'query'}]}}}}));
    }
    if (url.pathname === '/api/render') {
      const query = url.searchParams.get('q') ?? '';
      const expression = /^\{\{(\d{4})\*(\d{4})\}\}$/.exec(query);
      const rendered = vulnerable && expression ? String(Number(expression[1]) * Number(expression[2])) : query;
      res.writeHead(200, {'content-type': 'application/json', 'cache-control': 'no-store'});
      return res.end(JSON.stringify({rendered}));
    }
    res.writeHead(404);
    res.end();
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  t.after(() => new Promise(resolve => server.close(resolve)));
  const origin = `http://127.0.0.1:${server.address().port}`;
  const audit = await runAudit({url: origin, root, noModel: true, overrides: {acceptLocal: true}, env: {}});
  const finding = audit.findings.find(item => item.kind === 'ssti-arithmetic');
  assert.ok(finding, JSON.stringify(audit.findings));
  assert.equal(audit.coverage.rows.find(item => item.family === 'ssti').status, 'partial');
  assert.equal((await verifyRun(root, audit.run, {env: {}})).exitCode, 1);
  const exported = exportRun(root, audit.run, {out: `${root}/regression`});
  const childEnv = Object.fromEntries(Object.entries(process.env).filter(([key]) => key !== 'NODE_TEST_CONTEXT'));
  const runExport = () => new Promise((resolve, reject) => {
    const child = spawn(process.execPath, ['--test', ...exported.files], {env: childEnv});
    child.on('error', reject);
    child.on('close', resolve);
  });
  assert.equal(await runExport(), 1);
  vulnerable = false;
  assert.equal((await verifyRun(root, audit.run, {env: {}})).exitCode, 0);
  assert.equal(await runExport(), 0);
});

test('source-map originals without embedded content are reported as incomplete', async t => {
  const root = temp();
  t.after(() => fs.rmSync(root, {recursive: true, force: true}));
  const map = JSON.stringify({version: 3, mappings: 'AAAA',
    sources: Array.from({length: 202}, (_, index) => `node_modules/vendor-${index}/entry.js`),
    sourcesContent: Array.from({length: 202}, (_, index) => index < 200 ?
      `export const entry${index}=${index};` : null)});
  const server = http.createServer((request, response) => {
    const pages = {'/': ['text/html', '<script src="/app.js"></script>'],
      '/app.js': ['application/javascript', '//# sourceMappingURL=/app.js.map'],
      '/app.js.map': ['application/json', map]};
    const [type, body] = pages[new URL(request.url, 'http://local').pathname] ?? ['text/plain', 'missing'];
    response.writeHead(body === 'missing' ? 404 : 200, {'content-type': type});
    response.end(body);
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  t.after(() => new Promise(resolve => server.close(resolve)));
  const origin = `http://127.0.0.1:${server.address().port}`;
  const audit = await runAudit({url: origin, root, noModel: true, overrides: {acceptLocal: true}, env: {}});
  assert.equal(audit.exitCode, 3);
  assert.ok(audit.limitations.some(item =>
    /Source-map mining requested 2 public original URLs, but they did not return inspectable source text/.test(item)),
  JSON.stringify(audit.limitations));
  const mined = JSON.parse(fs.readFileSync(path.join(audit.runDir, 'assets.json'), 'utf8'));
  assert.equal(mined.stats.sourceMapSourcesCut, 2);
  assert.equal(mined.stats.sourceMapOriginalsFetchFailed, 2);
  const coverage = JSON.parse(fs.readFileSync(path.join(audit.runDir, 'coverage.json'), 'utf8'));
  assert.deepEqual(coverage.sourceMaps, {originalsUnavailable: 2,
    originalsUnresolvable: 0, originalsFetchFailed: 2,
    appLikelyUnavailable: 0, vendorUnavailable: 2,
    bundleNamespaceUnavailable: 0,
    originalsBudgetCut: 0, mapCandidatesBudgetCut: 0});
});
