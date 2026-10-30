import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import http from 'node:http';
import net from 'node:net';
import path from 'node:path';
import {randomBytes} from 'node:crypto';
import {DatabaseSync} from 'node:sqlite';
import {execFileSync, spawn, spawnSync} from 'node:child_process';
import {temp} from './helpers.mjs';
import {execFile} from '../src/util.mjs';
import {CLI} from '../src/demo.mjs';

async function cliWithEnv(root, env, ...args) {
  const completed = await execFile(process.execPath,
    [CLI, ...args, '--project', root, '--json', '--non-interactive'],
    {cwd: root, env, timeout: 90000});
  return {code: completed.code, data: JSON.parse(completed.stdout), stderr: completed.stderr};
}

test('real blackbox CLI proves a source-assisted redirect and reports a source file cut', async t => {
  const root = temp();
  t.after(() => fs.rmSync(root, {recursive: true, force: true}));
  const source = path.join(root, 'app-source');
  fs.mkdirSync(source);
  fs.writeFileSync(path.join(source, '00-server.js'),
    "app.get('/api/go', (req, res) => res.redirect(req.query.next));\n");
  for (let index = 0; index < 120; index++)
    fs.writeFileSync(path.join(source, `zz-${String(index).padStart(3, '0')}.js`), `export const value = ${index};\n`);
  let vulnerable = true;
  const server = http.createServer((request, response) => {
    const url = new URL(request.url, 'http://local');
    const who = request.headers.authorization === 'Bearer owner-token' ? 'u-1' :
      request.headers.authorization === 'Bearer other-token' ? 'u-2' : null;
    if (url.pathname === '/api/me') {
      response.writeHead(who ? 200 : 401, {'content-type': 'application/json'});
      response.end(JSON.stringify(who ? {id: who, role: 'member'} : {error: 'Sign in'}));
    } else if (url.pathname === '/api/go') {
      const destination = vulnerable ? url.searchParams.get('next') ?? '/' : '/safe';
      if (/[\r\n]/.test(destination)) {
        response.writeHead(400);
        return response.end();
      }
      response.writeHead(302, {location: destination});
      response.end();
    } else {
      response.writeHead(404);
      response.end();
    }
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  t.after(() => new Promise(resolve => server.close(resolve)));
  const origin = `http://127.0.0.1:${server.address().port}`;
  const env = {OWNER_TOKEN: 'owner-token', OTHER_TOKEN: 'other-token'};
  const audit = () => cliWithEnv(root, env, 'blackbox', origin, '--accept-local', '--no-model', '--source', source);
  const first = await audit();
  assert.equal(first.code, 1, JSON.stringify(first.data));
  assert.ok(first.data.findings.some(item => item.kind === 'open-redirect'));
  const firstRun = JSON.parse(fs.readFileSync(path.join(root, '.bypass/runs', first.data.run, 'run.json'), 'utf8'));
  assert.ok(firstRun.limitations.some(item => item.includes('1 eligible files beyond its file limit')));
  const report = JSON.parse(fs.readFileSync(path.join(root, '.bypass/runs', first.data.run, 'report.json'), 'utf8'));
  assert.equal(report.surface.application.sourceReview.stats.filesCut, 1);
  vulnerable = false;
  const fixed = await audit();
  assert.equal(fixed.code, 3, JSON.stringify(fixed.data));
  assert.deepEqual(fixed.data.findings, []);
  assert.ok(fixed.data.limitations.some(item => item.includes('1 eligible files beyond its file limit')));
});

test('real blackbox CLI finds and replays a redirect hidden behind a client URL constructor', async t => {
  const root = temp();
  t.after(() => fs.rmSync(root, {recursive: true, force: true}));
  const suffix = randomBytes(4).toString('hex');
  const basePath = `/tenant-${suffix}/app-${suffix}/`;
  const jumpPath = `${basePath}jump`;
  let vulnerable = true;
  const requested = [];
  let origin;
  const server = http.createServer((request, response) => {
    const url = new URL(request.url, 'http://local');
    requested.push(url.pathname);
    if (url.pathname === '/') {
      response.writeHead(200, {'content-type': 'text/html'});
      return response.end('<script src="/app.js"></script>');
    }
    if (url.pathname === '/app.js') {
      response.writeHead(200, {'content-type': 'application/javascript'});
      return response.end(`fetch(new URL("jump?next=/safe", "${origin}${basePath}"));`);
    }
    if (url.pathname === jumpPath) {
      const destination = vulnerable ? url.searchParams.get('next') ?? '/safe' : '/safe';
      if (/[\r\n]/.test(destination)) {response.writeHead(400); return response.end();}
      response.writeHead(302, {location: destination});
      return response.end();
    }
    response.writeHead(404);
    response.end();
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  t.after(() => new Promise(resolve => server.close(resolve)));
  origin = `http://127.0.0.1:${server.address().port}`;
  const audit = () => cliWithEnv(root, {}, 'blackbox', origin, '--accept-local', '--no-model');
  const first = await audit();
  assert.equal(first.code, 1, JSON.stringify(first.data));
  const finding = first.data.findings.find(item => item.kind === 'open-redirect' &&
    item.pattern === jumpPath);
  assert.ok(finding, JSON.stringify(first.data.findings));
  assert.ok(fs.existsSync(finding.proof));
  const report = JSON.parse(fs.readFileSync(path.join(first.data.runDir, 'report.json'), 'utf8'));
  const route = report.surface.application.patterns.find(item => item.pattern === jumpPath);
  const script = report.surface.external.files.find(item => new URL(item.url).pathname === '/app.js');
  assert.ok(script?.operations.some(item => item.method === 'GET' && item.path === jumpPath),
    JSON.stringify(script));
  assert.ok(route?.source.some(source => source === 'public-asset' || source.includes('asset:app.js')),
    JSON.stringify(route));
  assert.ok(requested.includes(jumpPath));
  assert.equal((await cliWithEnv(root, {}, 'blackbox', 'verify', first.data.run)).code, 1);
  vulnerable = false;
  assert.equal((await cliWithEnv(root, {}, 'blackbox', 'verify', first.data.run)).code, 0);
  const fixed = await audit();
  assert.deepEqual(fixed.data.findings, []);
});

test('real blackbox CLI proves a bug on an axios instance route with a random base', async t => {
  const root = temp();
  t.after(() => fs.rmSync(root, {recursive: true, force: true}));
  const suffix = randomBytes(4).toString('hex');
  const basePath = `/workspace-${suffix}/api-${suffix}`;
  const jumpPath = `${basePath}/jump`;
  let vulnerable = true, origin;
  const requested = [];
  const server = http.createServer((request, response) => {
    const url = new URL(request.url, 'http://local');
    requested.push(url.pathname);
    if (url.pathname === '/') {
      response.writeHead(200, {'content-type': 'text/html'});
      return response.end('<script src="/client.js"></script>');
    }
    if (url.pathname === '/client.js') {
      response.writeHead(200, {'content-type': 'application/javascript'});
      return response.end(`const API_ROOT="${origin}${basePath}"; ` +
        'const client=axios.create({baseURL:API_ROOT}); client.get("jump?next=/safe");');
    }
    if (url.pathname === jumpPath) {
      const destination = vulnerable ? url.searchParams.get('next') ?? '/safe' : '/safe';
      if (/[\r\n]/.test(destination)) {response.writeHead(400); return response.end();}
      response.writeHead(302, {location: destination});
      return response.end();
    }
    response.writeHead(404);
    response.end();
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  t.after(() => new Promise(resolve => server.close(resolve)));
  origin = `http://127.0.0.1:${server.address().port}`;
  const audit = () => cliWithEnv(root, {}, 'blackbox', origin, '--accept-local', '--no-model');
  const first = await audit();
  assert.equal(first.code, 1, JSON.stringify(first.data));
  const finding = first.data.findings.find(item => item.kind === 'open-redirect' && item.pattern === jumpPath);
  assert.ok(finding, JSON.stringify(first.data.findings));
  assert.ok(fs.existsSync(finding.proof));
  const report = JSON.parse(fs.readFileSync(path.join(first.data.runDir, 'report.json'), 'utf8'));
  const script = report.surface.external.files.find(item => new URL(item.url).pathname === '/client.js');
  assert.ok(script?.operations.some(item => item.method === 'GET' && item.path === jumpPath),
    JSON.stringify(script));
  assert.ok(requested.includes(jumpPath));
  assert.equal((await cliWithEnv(root, {}, 'blackbox', 'verify', first.data.run)).code, 1);
  vulnerable = false;
  assert.equal((await cliWithEnv(root, {}, 'blackbox', 'verify', first.data.run)).code, 0);
  const fixed = await audit();
  assert.deepEqual(fixed.data.findings, []);
});

test('real blackbox CLI proves duplicate redirect parameter bypass and exported regression', async t => {
  const root = temp();
  t.after(() => fs.rmSync(root, {recursive: true, force: true}));
  const route = `/api/go-${randomBytes(4).toString('hex')}`;
  let vulnerable = true;
  const requested = [];
  const server = http.createServer((request, response) => {
    const url = new URL(request.url, 'http://local');
    requested.push(url.pathname);
    if (url.pathname === '/') {
      response.writeHead(200, {'content-type': 'text/html'});
      return response.end('<html>Redirect fixture</html>');
    }
    if (url.pathname === '/openapi.json') {
      response.writeHead(200, {'content-type': 'application/json'});
      return response.end(JSON.stringify({openapi: '3.0.0', paths: {
        [route]: {get: {parameters: [{name: 'next', in: 'query'}]}}, '/api/delete': {get: {}}}}));
    }
    if (url.pathname === route) {
      const values = url.searchParams.getAll('next');
      if (!vulnerable && values.length > 1) {response.writeHead(400); return response.end();}
      const allowed = values.length && !/^https?:\/\//i.test(values[0]);
      const destination = allowed ? vulnerable ? values.at(-1) : values[0] : '/safe';
      if (/[\r\n]/.test(destination)) {response.writeHead(400); return response.end();}
      response.writeHead(302, {location: destination});
      return response.end();
    }
    if (url.pathname === '/api/delete') {response.writeHead(500); return response.end('Protected');}
    response.writeHead(404);
    response.end();
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  t.after(() => new Promise(resolve => server.close(resolve)));
  const origin = `http://127.0.0.1:${server.address().port}`;
  assert.equal((await cliWithEnv(root, {}, 'blackbox', 'scope', origin, '--include', '/api')).code, 0);
  const audit = () => cliWithEnv(root, {}, 'blackbox', origin, '--accept-local', '--no-model');
  const first = await audit();
  assert.equal(first.code, 1, JSON.stringify(first.data));
  const finding = first.data.findings.find(item => item.kind === 'http-parameter-pollution' && item.pattern === route);
  assert.ok(finding, JSON.stringify(first.data.findings));
  assert.ok(fs.existsSync(finding.proof));
  assert.ok(!first.data.findings.some(item => item.kind === 'open-redirect' && item.pattern === route));
  assert.ok(!requested.includes('/api/delete'));
  const coverage = JSON.parse(fs.readFileSync(path.join(first.data.runDir, 'coverage.json'), 'utf8'));
  assert.equal(coverage.requestedClasses.find(item => item.name === 'HTTP Parameter Pollution')?.status, 'partial');
  assert.equal((await cliWithEnv(root, {}, 'blackbox', 'verify', first.data.run)).code, 1);
  const exported = await cliWithEnv(root, {}, 'blackbox', 'export', first.data.run,
    '--out', path.join(root, 'regressions'));
  assert.equal(exported.code, 0);
  const childEnv = Object.fromEntries(Object.entries(process.env).filter(([key]) => key !== 'NODE_TEST_CONTEXT'));
  const runExport = () => new Promise((resolve, reject) => {
    const child = spawn(process.execPath, ['--test', ...exported.data.files], {env: childEnv, stdio: 'ignore'});
    child.on('error', reject);
    child.on('close', resolve);
  });
  assert.equal(await runExport(), 1);
  vulnerable = false;
  assert.equal((await cliWithEnv(root, {}, 'blackbox', 'verify', first.data.run)).code, 0);
  assert.equal(await runExport(), 0);
  const fixed = await audit();
  assert.deepEqual(fixed.data.findings, []);
  assert.ok(!requested.includes('/api/delete'));
});

test('real blackbox CLI proves an authenticated open redirect and replays it with the owner identity', async t => {
  const root = temp();
  t.after(() => fs.rmSync(root, {recursive: true, force: true}));
  const env = {OWNER_TOKEN: 'owner-token', OTHER_TOKEN: 'other-token'};
  let vulnerable = true;
  const requested = [];
  const server = http.createServer((request, response) => {
    const url = new URL(request.url, 'http://local');
    requested.push(url.pathname);
    const who = request.headers.authorization === 'Bearer owner-token' ? 'u-1' :
      request.headers.authorization === 'Bearer other-token' ? 'u-2' : null;
    if (url.pathname === '/openapi.json') {
      response.writeHead(200, {'content-type': 'application/json'});
      return response.end(JSON.stringify({openapi: '3.0.0', paths: {'/api/me': {get: {}},
        '/api/private/go': {get: {parameters: [{name: 'next', in: 'query'}]}},
        '/api/delete': {get: {}}}}));
    }
    if (url.pathname === '/api/me') {
      response.writeHead(who ? 200 : 401, {'content-type': 'application/json'});
      return response.end(JSON.stringify(who ? {id: who, role: 'member'} : {error: 'Sign in'}));
    }
    if (url.pathname === '/api/private/go') {
      if (!who) {response.writeHead(401); return response.end('Sign in');}
      const destination = vulnerable ? url.searchParams.get('next') ?? '/safe' : '/safe';
      if (/[\r\n]/.test(destination)) {response.writeHead(400); return response.end();}
      response.writeHead(302, {location: destination});
      return response.end();
    }
    response.writeHead(404);
    response.end();
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  t.after(() => new Promise(resolve => server.close(resolve)));
  const origin = `http://127.0.0.1:${server.address().port}`;
  const configured = await cliWithEnv(root, env, 'blackbox', 'scope', origin, '--include', '/api');
  assert.equal(configured.code, 0);
  const audit = () => cliWithEnv(root, env, 'blackbox', origin, '--accept-local', '--no-model');
  const first = await audit();
  assert.equal(first.code, 1, JSON.stringify(first.data));
  const redirect = first.data.findings.find(item => item.kind === 'open-redirect' &&
    item.pattern === '/api/private/go');
  assert.ok(redirect, JSON.stringify(first.data.findings));
  assert.ok(fs.existsSync(redirect.proof));
  const spec = JSON.parse(fs.readFileSync(path.join(path.dirname(redirect.proof), 'spec.json'), 'utf8'));
  assert.equal(spec.request.as, 'owner');
  assert.ok(!requested.includes('/api/delete'));
  assert.equal((await cliWithEnv(root, env, 'blackbox', 'verify', first.data.run)).code, 1);
  vulnerable = false;
  assert.equal((await cliWithEnv(root, env, 'blackbox', 'verify', first.data.run)).code, 0);
  const fixed = await audit();
  assert.deepEqual(fixed.data.findings, []);
  assert.ok(!requested.includes('/api/delete'));
});

test('real blackbox CLI distinguishes five switchable bugs from protected decoys', async t => {
  const root = temp();
  t.after(() => fs.rmSync(root, {recursive: true, force: true}));
  const env = {OWNER_TOKEN: 'owner-token', OTHER_TOKEN: 'other-token'};
  const bugs = {idor: true, redirect: true, ssti: true, xss: true, ssrf: true};
  const calls = [];
  const server = http.createServer(async (request, response) => {
    const url = new URL(request.url, 'http://local');
    calls.push(url.pathname);
    const who = request.headers.authorization === 'Bearer owner-token' ? 'u-1' :
      request.headers.authorization === 'Bearer other-token' ? 'u-2' : null;
    const invoices = [{id: 'inv-101', ownerId: 'u-1', total: 20},
      {id: 'inv-202', ownerId: 'u-2', total: 30}];
    let status = 404, body = {error: 'Not found'}, type = 'application/json', headers = {};
    if (url.pathname === '/') {status = 200; body = '<html>Audit fixture</html>'; type = 'text/html';}
    else if (url.pathname === '/openapi.json') {status = 200; body = {openapi: '3.0.0', paths: {
      '/api/me': {get: {}}, '/api/invoices': {get: {}}, '/api/invoices/{id}': {get: {}},
      '/api/next': {get: {parameters: [{name: 'next', in: 'query'}]}},
      '/api/render': {get: {parameters: [{name: 'expr', in: 'query'}]}},
      '/api/echo': {get: {parameters: [{name: 'input', in: 'query'}]}},
      '/api/fetch': {get: {parameters: [{name: 'url', in: 'query'}]}},
      '/api/delete': {get: {}}, '/api/billing/charge': {get: {}}}};}
    else if (url.pathname === '/api/me') {status = who ? 200 : 401;
      body = who ? {id: who, role: 'member'} : {error: 'Sign in'};}
    else if (url.pathname === '/api/invoices') {status = who ? 200 : 401;
      body = who ? invoices.filter(item => item.ownerId === who) : {error: 'Sign in'};}
    else if (url.pathname.startsWith('/api/invoices/')) {
      const item = invoices.find(invoice => url.pathname === `/api/invoices/${invoice.id}`);
      status = !who ? 401 : !item ? 404 : item.ownerId === who || bugs.idor ? 200 : 403;
      body = status === 200 ? item : {error: 'Denied'};
    } else if (url.pathname === '/api/next') {
      const next = url.searchParams.get('next') ?? '/';
      if (/[\r\n]/.test(next)) {status = 400; body = {error: 'Invalid redirect destination'};}
      else {status = 302; headers.location = bugs.redirect ? next : '/'; body = '';}
    } else if (url.pathname === '/api/render') {
      status = 200; type = 'text/plain';
      const expression = url.searchParams.get('expr') ?? '';
      const match = /^\{\{(\d+)\*(\d+)\}\}$/.exec(expression);
      body = bugs.ssti && match ? String(Number(match[1]) * Number(match[2])) : expression;
    } else if (url.pathname === '/api/echo') {
      status = 200; type = 'text/html';
      const input = url.searchParams.get('input') ?? '';
      const safe = input.replaceAll('&', '&amp;').replaceAll('<', '&lt;').replaceAll('>', '&gt;')
        .replaceAll('"', '&quot;').replaceAll("'", '&#39;');
      body = `<html><body>${bugs.xss ? input : safe}</body></html>`;
    } else if (url.pathname === '/api/fetch') {
      const destination = url.searchParams.get('url') ?? '';
      if (!bugs.ssrf) {status = 403; body = {error: 'Private destinations forbidden'};}
      else if (/^http:\/\/127\.0\.0\.1:\d+\/bx-ssrf\/[0-9a-f]{24}$/.test(destination)) {
        try {await fetch(destination, {redirect: 'manual'}); status = 200; body = {fetched: true};}
        catch {status = 502; body = {error: 'Fetch failed'};}
      } else {status = 400; body = {error: 'Unsupported test URL'};}
    } else if (url.pathname === '/api/delete' || url.pathname === '/api/billing/charge') {
      status = 500; body = {error: 'The audit must never call this route'};
    }
    response.writeHead(status, {'content-type': type, 'cache-control': 'no-store', ...headers});
    response.end(typeof body === 'string' ? body : JSON.stringify(body));
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  t.after(() => new Promise(resolve => server.close(resolve)));
  const origin = `http://127.0.0.1:${server.address().port}`;
  const configured = await cliWithEnv(root, env, 'blackbox', 'scope', origin, '--include', '/api');
  assert.equal(configured.code, 0);
  const first = await cliWithEnv(root, env, 'blackbox', origin, '--accept-local', '--no-model');
  assert.equal(first.code, 1, JSON.stringify(first.data));
  const found = new Set(first.data.findings.map(item => item.kind));
  for (const kind of ['idor', 'open-redirect', 'ssti-arithmetic', 'ssrf-loopback']) assert.ok(found.has(kind),
    `${kind} missing from ${JSON.stringify([...found])}`);
  const chrome = ['google-chrome', 'chromium', 'chromium-browser'].some(binary =>
    spawnSync(binary, ['--version'], {stdio: 'ignore'}).status === 0);
  if (chrome) assert.ok(found.has('xss-reflected'), JSON.stringify([...found]));
  assert.ok(first.data.findings.every(item => fs.existsSync(item.proof)));
  assert.ok(!calls.some(pathname => pathname === '/api/delete' || pathname === '/api/billing/charge'));
  const beforeFix = await cliWithEnv(root, env, 'blackbox', 'verify', first.data.run);
  assert.equal(beforeFix.code, 1);
  const exported = await cliWithEnv(root, env, 'blackbox', 'export', first.data.run,
    '--out', `${root}/regressions`);
  assert.equal(exported.code, 0);
  assert.equal(exported.data.files.length, first.data.findings.length);
  const childEnv = {...Object.fromEntries(Object.entries(process.env)
    .filter(([key]) => key !== 'NODE_TEST_CONTEXT')), ...env};
  const runExport = () => new Promise((resolve, reject) => {
    const child = spawn(process.execPath, ['--test', '--test-reporter=tap', ...exported.data.files],
      {env: childEnv});
    let output = '';
    child.stdout.on('data', chunk => {output += chunk;});
    child.stderr.on('data', chunk => {output += chunk;});
    child.on('error', reject);
    child.on('close', code => resolve({code, output}));
  });
  const red = await runExport();
  assert.equal(red.code, 1, red.output);
  assert.match(red.output, new RegExp(`# fail ${exported.data.files.length}\\b`));
  Object.assign(bugs, {idor: false, redirect: false, ssti: false, xss: false, ssrf: false});
  const afterFix = await cliWithEnv(root, env, 'blackbox', 'verify', first.data.run);
  assert.equal(afterFix.code, 0, JSON.stringify(afterFix.data));
  const green = await runExport();
  assert.equal(green.code, 0, green.output);
  assert.match(green.output, new RegExp(`# pass ${exported.data.files.length}\\b`));
  const fixed = await cliWithEnv(root, env, 'blackbox', origin, '--accept-local', '--no-model');
  assert.deepEqual(fixed.data.findings, [], 'fixed fixture must produce no findings');
  const kinds = {idor: 'idor', redirect: 'open-redirect', ssti: 'ssti-arithmetic',
    xss: 'xss-reflected', ssrf: 'ssrf-loopback'};
  for (const [flag, expected] of Object.entries(kinds)) {
    if (flag === 'xss' && !chrome) continue;
    bugs[flag] = true;
    const isolated = await cliWithEnv(root, env, 'blackbox', origin, '--accept-local', '--no-model');
    assert.deepEqual([...new Set(isolated.data.findings.map(item => item.kind))], [expected],
      `${flag} alone produced ${JSON.stringify(isolated.data.findings)}`);
    assert.ok(isolated.data.findings.every(item => fs.existsSync(item.proof)));
    bugs[flag] = false;
  }
  assert.ok(!calls.some(pathname => pathname === '/api/delete' || pathname === '/api/billing/charge'));
});

test('real blackbox CLI proves credentialed CORS on a private cookie route', async t => {
  const root = temp();
  t.after(() => fs.rmSync(root, {recursive: true, force: true}));
  const env = {OWNER_TOKEN: 'sid=owner', OTHER_TOKEN: 'sid=other'};
  let permissive = true;
  const calls = [];
  const server = http.createServer((request, response) => {
    const pathname = new URL(request.url, 'http://local').pathname;
    calls.push(pathname);
    const who = request.headers.cookie === 'sid=owner' ? 'u-1' :
      request.headers.cookie === 'sid=other' ? 'u-2' : null;
    let status = 404, body = {error: 'Not found'};
    if (pathname === '/openapi.json') {status = 200; body = {openapi: '3.0.0', paths: {
      '/api/me': {get: {}}, '/api/items': {get: {}}, '/api/delete': {get: {}}}};}
    else if (pathname === '/api/me') {status = who ? 200 : 401;
      body = who ? {id: who, role: 'member'} : {error: 'Sign in'};}
    else if (pathname === '/api/items') {status = who ? 200 : 401;
      body = who ? [{id: who === 'u-1' ? 'itm-101' : 'itm-202', ownerId: who}] : {error: 'Sign in'};}
    else if (pathname === '/api/delete') {status = 500; body = {error: 'Protected decoy'};}
    const headers = {'content-type': 'application/json', 'cache-control': 'no-store'};
    if (permissive && pathname === '/api/items' && request.headers.origin) {
      headers['access-control-allow-origin'] = request.headers.origin;
      headers['access-control-allow-credentials'] = 'true';
    }
    response.writeHead(status, headers);
    response.end(JSON.stringify(body));
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  t.after(() => new Promise(resolve => server.close(resolve)));
  const origin = `http://127.0.0.1:${server.address().port}`;
  const configured = await cliWithEnv(root, env, 'blackbox', 'scope', origin,
    '--include', '/api', '--auth', 'cookie');
  assert.equal(configured.code, 0);
  const audit = await cliWithEnv(root, env, 'blackbox', origin, '--accept-local', '--no-model');
  assert.equal(audit.code, 1, JSON.stringify(audit.data));
  const cors = audit.data.findings.find(item => item.kind === 'cors-reflection');
  assert.ok(cors, JSON.stringify(audit.data.findings));
  assert.ok(fs.existsSync(cors.proof));
  assert.ok(!calls.includes('/api/delete'));
  assert.equal((await cliWithEnv(root, env, 'blackbox', 'verify', audit.data.run)).code, 1);
  permissive = false;
  assert.equal((await cliWithEnv(root, env, 'blackbox', 'verify', audit.data.run)).code, 0);
  const fixed = await cliWithEnv(root, env, 'blackbox', origin, '--accept-local', '--no-model');
  assert.deepEqual(fixed.data.findings, []);
  assert.ok(!calls.includes('/api/delete'));
});

test('real blackbox CLI flags an anonymously readable identity route with one account', async t => {
  const root = temp();
  t.after(() => fs.rmSync(root, {recursive: true, force: true}));
  const env = {OWNER_TOKEN: 'owner-token'};
  let vulnerable = true;
  const server = http.createServer((request, response) => {
    const pathname = new URL(request.url, 'http://local').pathname;
    const owner = request.headers.authorization === 'Bearer owner-token';
    let status = 404, body = {error: 'Not found'};
    if (pathname === '/openapi.json') {status = 200; body = {openapi: '3.0.0', paths: {'/api/me': {get: {}}}};}
    else if (pathname === '/api/me') {status = owner || vulnerable ? 200 : 401;
      body = status === 200 ? {id: 'u-1', email: 'owner@example.test'} : {error: 'Sign in'};}
    response.writeHead(status, {'content-type': 'application/json', 'cache-control': 'no-store'});
    response.end(JSON.stringify(body));
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  t.after(() => new Promise(resolve => server.close(resolve)));
  const origin = `http://127.0.0.1:${server.address().port}`;
  const configured = await cliWithEnv(root, env, 'blackbox', 'scope', origin,
    '--include', '/api', '--identity-path', '/api/me');
  assert.equal(configured.code, 0);
  const audit = await cliWithEnv(root, env, 'blackbox', origin, '--accept-local', '--no-model');
  assert.equal(audit.code, 1, JSON.stringify(audit.data));
  const missing = audit.data.findings.find(item => item.kind === 'missing-auth');
  assert.ok(missing, JSON.stringify(audit.data.findings));
  assert.ok(missing.tags.includes('single-account'));
  assert.ok(fs.existsSync(missing.proof));
  assert.equal((await cliWithEnv(root, env, 'blackbox', 'verify', audit.data.run)).code, 1);
  vulnerable = false;
  assert.equal((await cliWithEnv(root, env, 'blackbox', 'verify', audit.data.run)).code, 0);
  const fixed = await cliWithEnv(root, env, 'blackbox', origin, '--accept-local', '--no-model');
  assert.deepEqual(fixed.data.findings, []);
});

test('one-account CLI proves a private item read anonymously while rejecting a public owner-shaped decoy', async t => {
  const root = temp();
  t.after(() => fs.rmSync(root, {recursive: true, force: true}));
  const suffix = randomBytes(3).readUIntBE(0, 3);
  const ownerId = `u-${suffix}`;
  const privateId = `rec-${suffix}`;
  const publicId = `pub-${suffix}`;
  const env = {OWNER_TOKEN: `owner-${suffix}`};
  const aliasToken = `same-account-${suffix}`;
  const calls = [];
  let vulnerable = true, exposeSecret = true, itemOwner = ownerId;
  const server = http.createServer((request, response) => {
    const pathname = new URL(request.url, 'http://local').pathname;
    calls.push(pathname);
    const owner = [env.OWNER_TOKEN, aliasToken].some(token =>
      request.headers.authorization === `Bearer ${token}`);
    let status = 404, body = {error: 'Not found'};
    if (pathname === '/openapi.json') {status = 200; body = {openapi: '3.0.0', paths: {
      '/api/me': {get: {}}, '/api/records': {get: {}}, '/api/records/{id}': {get: {}},
      '/api/public': {get: {}}, '/api/public/{id}': {get: {}}, '/api/delete': {get: {}}}};}
    else if (pathname === '/api/me') {status = owner ? 200 : 401;
      body = owner ? {id: ownerId, role: 'member'} : {error: 'Sign in'};}
    else if (pathname === '/api/records') {status = owner ? 200 : 401;
      body = owner ? [{id: privateId, ownerId}] : {error: 'Sign in'};}
    else if (pathname === `/api/records/${privateId}`) {status = owner || vulnerable ? 200 : 401;
      body = status === 200 ? {id: privateId, ownerId: itemOwner,
        ...(exposeSecret ? {secret: `value-${suffix}`} : {title: 'Public summary'})} : {error: 'Sign in'};}
    else if (pathname === '/api/public') {status = 200; body = [{id: publicId, ownerId}];}
    else if (pathname === `/api/public/${publicId}`) {status = 200;
      body = {id: publicId, ownerId, title: 'Public profile'};}
    else if (pathname === '/api/delete') {status = 500; body = {error: 'Protected decoy'};}
    response.writeHead(status, {'content-type': 'application/json', 'cache-control': 'no-store'});
    response.end(JSON.stringify(body));
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  t.after(() => new Promise(resolve => server.close(resolve)));
  const origin = `http://127.0.0.1:${server.address().port}`;
  const prepared = await cliWithEnv(root, env, 'blackbox', 'setup', origin,
    '--include', '/api', '--identity-path', '/api/me');
  assert.equal(prepared.code, 0);
  const audit = await cliWithEnv(root, env, 'blackbox', origin, '--accept-local', '--no-model');
  assert.equal(audit.code, 1, JSON.stringify(audit.data));
  const finding = audit.data.findings.find(item => item.kind === 'missing-auth' &&
    item.pattern === '/api/records/{id}');
  assert.ok(finding?.proof, JSON.stringify(audit.data.findings));
  assert.ok(finding.tags.includes('single-account'));
  assert.ok(finding.tags.includes('owner-identity-only'));
  assert.ok(!finding.tags.includes('role-mismatch'));
  const spec = JSON.parse(fs.readFileSync(path.join(path.dirname(finding.proof), 'spec.json'), 'utf8'));
  assert.deepEqual(spec.oneAccountPrivateFields, ['secret']);
  assert.equal(spec.oneAccountBoundary.field, 'ownerId');
  assert.ok(!JSON.stringify(spec).includes(ownerId));
  assert.ok(!audit.data.findings.some(item => item.pattern === '/api/public/{id}'));
  assert.ok(!calls.includes('/api/delete'));
  assert.equal((await cliWithEnv(root, env, 'blackbox', 'verify', audit.data.run)).code, 1);
  const exported = await cliWithEnv(root, env, 'blackbox', 'export', audit.data.run,
    '--out', path.join(root, 'regressions'));
  assert.equal(exported.code, 0);
  const exportEnv = {...Object.fromEntries(Object.entries(process.env)
    .filter(([key]) => key !== 'NODE_TEST_CONTEXT')), ...env};
  const runExport = () => new Promise((resolve, reject) => {
    const child = spawn(process.execPath, ['--test', ...exported.data.files], {env: exportEnv});
    let output = '';
    child.stdout.on('data', chunk => {output += chunk;});
    child.stderr.on('data', chunk => {output += chunk;});
    child.on('error', reject);
    child.on('close', code => resolve({code, output}));
  });
  assert.equal((await runExport()).code, 1);
  const aliasAudit = await cliWithEnv(root, {...env, OTHER_TOKEN: aliasToken},
    'blackbox', origin, '--accept-local', '--no-model');
  assert.ok(aliasAudit.data.limitations.some(item => /same account principal/.test(item)));
  assert.ok(!aliasAudit.data.findings.some(item => item.kind === 'idor'));
  itemOwner = `other-${suffix}`;
  assert.equal((await cliWithEnv(root, env, 'blackbox', 'verify', audit.data.run)).code, 0,
    'changing the owner field clears the saved one-account proof');
  assert.equal((await runExport()).code, 0);
  itemOwner = ownerId;
  exposeSecret = false;
  assert.equal((await cliWithEnv(root, env, 'blackbox', 'verify', audit.data.run)).code, 0,
    'removing the sensitive field clears the saved one-account proof');
  assert.equal((await runExport()).code, 0);
  exposeSecret = true;
  vulnerable = false;
  assert.equal((await cliWithEnv(root, env, 'blackbox', 'verify', audit.data.run)).code, 0);
  const green = await runExport();
  assert.equal(green.code, 0, green.output);
  const fixed = await cliWithEnv(root, env, 'blackbox', origin, '--accept-local', '--no-model');
  assert.ok(!fixed.data.findings.some(item => item.pattern === '/api/records/{id}'));
});

test('real blackbox CLI proves anonymous access to an account-bound export and replays its fix', async t => {
  const root = temp();
  t.after(() => fs.rmSync(root, {recursive: true, force: true}));
  const suffix = randomBytes(4).toString('hex');
  const env = {OWNER_TOKEN: `owner-${suffix}`, OTHER_TOKEN: `other-${suffix}`};
  const ownerRecord = {ownerId: `u-one-${suffix}`, balance: 125, exportId: `exp-one-${suffix}`};
  const outsiderRecord = {ownerId: `u-two-${suffix}`, balance: 50, exportId: `exp-two-${suffix}`};
  let vulnerable = true, distinctAccounts = true;
  const server = http.createServer((request, response) => {
    const pathname = new URL(request.url, 'http://local').pathname;
    const who = request.headers.authorization === `Bearer ${env.OWNER_TOKEN}` ? 'owner' :
      request.headers.authorization === `Bearer ${env.OTHER_TOKEN}` ? 'outsider' : 'anonymous';
    let status = 404, body = {error: 'Not found'};
    if (pathname === '/openapi.json') {status = 200; body = {openapi: '3.0.0', paths: {
      '/api/me': {get: {}}, '/api/export': {get: {}}, '/api/public': {get: {}}}};}
    else if (pathname === '/api/me') {status = who === 'anonymous' ? 401 : 200;
      body = status === 200 ? {id: who === 'owner' ? ownerRecord.ownerId : outsiderRecord.ownerId,
        role: 'member'} : {error: 'Sign in'};}
    else if (pathname === '/api/export') {status = who === 'anonymous' && !vulnerable ? 401 : 200;
      body = status === 200 ? who === 'outsider' && distinctAccounts ? outsiderRecord : ownerRecord :
        {error: 'Sign in'};}
    else if (pathname === '/api/public') {status = 200; body = {title: 'Public sample', balance: 0};}
    response.writeHead(status, {'content-type': 'application/json', 'cache-control': 'no-store'});
    response.end(JSON.stringify(body));
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  t.after(() => new Promise(resolve => server.close(resolve)));
  const origin = `http://127.0.0.1:${server.address().port}`;
  const prepared = await cliWithEnv(root, env, 'blackbox', 'setup', origin,
    '--include', '/api', '--identity-path', '/api/me');
  assert.equal(prepared.code, 0);
  const audit = await cliWithEnv(root, env, 'blackbox', origin, '--accept-local', '--no-model');
  assert.equal(audit.code, 1, JSON.stringify(audit.data));
  const finding = audit.data.findings.find(item => item.kind === 'missing-auth' &&
    item.pattern === '/api/export');
  assert.ok(finding?.proof, JSON.stringify(audit.data.findings));
  const spec = JSON.parse(fs.readFileSync(path.join(path.dirname(finding.proof), 'spec.json'), 'utf8'));
  assert.equal(spec.accountBoundary.field, 'ownerId');
  assert.ok(!JSON.stringify(spec).includes(ownerRecord.ownerId));
  assert.ok(!JSON.stringify(spec).includes(outsiderRecord.ownerId));
  assert.ok(!audit.data.findings.some(item => item.pattern === '/api/public'));
  assert.equal((await cliWithEnv(root, env, 'blackbox', 'verify', audit.data.run)).code, 1);
  const exported = await cliWithEnv(root, env, 'blackbox', 'export', audit.data.run,
    '--out', path.join(root, 'regressions'));
  assert.equal(exported.code, 0);
  const exportEnv = {...Object.fromEntries(Object.entries(process.env)
    .filter(([key]) => key !== 'NODE_TEST_CONTEXT')), ...env};
  const runExport = () => new Promise((resolve, reject) => {
    const child = spawn(process.execPath, ['--test', ...exported.data.files], {env: exportEnv});
    child.on('error', reject);
    child.on('close', resolve);
  });
  assert.equal(await runExport(), 1);
  distinctAccounts = false;
  assert.equal((await cliWithEnv(root, env, 'blackbox', 'verify', audit.data.run)).code, 3,
    'replay must not confirm the original account boundary after it disappears');
  distinctAccounts = true;
  vulnerable = false;
  assert.equal((await cliWithEnv(root, env, 'blackbox', 'verify', audit.data.run)).code, 0);
  assert.equal(await runExport(), 0);
  const fixed = await cliWithEnv(root, env, 'blackbox', origin, '--accept-local', '--no-model');
  assert.ok(!fixed.data.findings.some(item => item.pattern === '/api/export'));
});

test('real blackbox CLI discovers randomized API paths and record IDs before proving IDOR', async t => {
  for (let iteration = 0; iteration < 2; iteration++) {
    const root = temp();
    t.after(() => fs.rmSync(root, {recursive: true, force: true}));
    const suffix = randomBytes(4).toString('hex');
    const base = `/api/cohort-${suffix}/records`;
    const records = [{id: `rec-${suffix}101`, ownerId: 'u-1', total: 20},
      {id: `rec-${suffix}202`, ownerId: 'u-2', total: 30}];
    const calls = [];
    let vulnerable = true;
    const server = http.createServer((request, response) => {
      const pathname = new URL(request.url, 'http://local').pathname;
      calls.push(pathname);
      const who = request.headers.authorization === 'Bearer owner-token' ? 'u-1' :
        request.headers.authorization === 'Bearer other-token' ? 'u-2' : null;
      let status = 404, body = {error: 'Not found'};
      if (pathname === '/openapi.json') {status = 200; body = {openapi: '3.0.0', paths: {
        '/api/me': {get: {}}, [base]: {get: {}}, [`${base}/{id}`]: {get: {}},
        '/api/delete': {get: {}}}};}
      else if (pathname === '/api/me') {status = who ? 200 : 401;
        body = who ? {id: who, role: 'member'} : {error: 'Sign in'};}
      else if (pathname === base) {status = who ? 200 : 401;
        body = who ? records.filter(item => item.ownerId === who) : {error: 'Sign in'};}
      else if (pathname.startsWith(`${base}/`)) {
        const item = records.find(record => pathname === `${base}/${record.id}`);
        status = !who ? 401 : !item ? 404 : item.ownerId === who || vulnerable ? 200 : 403;
        body = status === 200 ? item : {error: 'Denied'};
      } else if (pathname === '/api/delete') {status = 500; body = {error: 'Protected decoy'};}
      response.writeHead(status, {'content-type': 'application/json', 'cache-control': 'no-store'});
      response.end(JSON.stringify(body));
    });
    await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
    t.after(() => new Promise(resolve => server.close(resolve)));
    const origin = `http://127.0.0.1:${server.address().port}`;
    const env = {OWNER_TOKEN: 'owner-token', OTHER_TOKEN: 'other-token'};
    assert.equal((await cliWithEnv(root, env, 'blackbox', 'scope', origin, '--include', '/api')).code, 0);
    const audit = await cliWithEnv(root, env, 'blackbox', origin, '--accept-local', '--no-model');
    assert.equal(audit.code, 1, JSON.stringify(audit.data));
    const idor = audit.data.findings.find(item => item.kind === 'idor' && item.pattern === `${base}/{id}`);
    assert.ok(idor, JSON.stringify(audit.data.findings));
    assert.ok(fs.existsSync(idor.proof));
    vulnerable = false;
    assert.equal((await cliWithEnv(root, env, 'blackbox', 'verify', audit.data.run)).code, 0);
    const fixed = await cliWithEnv(root, env, 'blackbox', origin, '--accept-local', '--no-model');
    assert.deepEqual(fixed.data.findings, []);
    assert.ok(!calls.includes('/api/delete'));
  }
});

test('real blackbox CLI finds a query-driven cross-account list leak on generated apps', async t => {
  for (const wrapped of [false, true]) {
    const root = temp();
    t.after(() => fs.rmSync(root, {recursive: true, force: true}));
    const suffix = randomBytes(6).toString('hex');
    const listPath = `/api/${suffix}/ledger`;
    const records = [{id: `entry-${suffix}-a`, ownerId: `user-${suffix}-a`, balance: 10},
      {id: `entry-${suffix}-b`, ownerId: `user-${suffix}-b`, balance: 20}];
    const calls = [];
    let vulnerable = true;
    const server = http.createServer((request, response) => {
      const url = new URL(request.url, 'http://local');
      calls.push(url.pathname);
      const who = request.headers.authorization === 'Bearer owner-token' ? records[0].ownerId :
        request.headers.authorization === 'Bearer other-token' ? records[1].ownerId : null;
      let status = 404, body = {error: 'Not found'};
      if (url.pathname === '/openapi.json') {status = 200; body = {openapi: '3.0.0', paths: {
        '/api/me': {get: {}}, [listPath]: {get: {parameters: [{name: 'all', in: 'query'}]}},
        '/api/delete': {get: {}}}};}
      else if (url.pathname === '/api/me') {status = who ? 200 : 401;
        body = who ? {id: who, role: 'member'} : {error: 'Sign in'};}
      else if (url.pathname === listPath) {status = who ? 200 : 401;
        const items = who ? vulnerable && url.searchParams.get('all') === '1' ? records :
          records.filter(item => item.ownerId === who) : null;
        body = items ? wrapped ? {data: {entries: items}} : items : {error: 'Sign in'};
      } else if (url.pathname === '/api/delete') {status = 500; body = {error: 'Protected decoy'};}
      response.writeHead(status, {'content-type': 'application/json', 'cache-control': 'no-store'});
      response.end(JSON.stringify(body));
    });
    await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
    t.after(() => new Promise(resolve => server.close(resolve)));
    const origin = `http://127.0.0.1:${server.address().port}`;
    const env = {OWNER_TOKEN: 'owner-token', OTHER_TOKEN: 'other-token'};
    assert.equal((await cliWithEnv(root, env, 'blackbox', 'scope', origin, '--include', '/api')).code, 0);
    const audit = await cliWithEnv(root, env, 'blackbox', origin, '--accept-local', '--no-model');
    assert.equal(audit.code, 1, JSON.stringify({findings: audit.data.findings.map(item => item.kind),
      access: JSON.parse(fs.readFileSync(`${audit.data.runDir}/results.json`, 'utf8'))
        .filter(item => item.task?.kind === 'list-leak').slice(0, 4)
        .map(item => ({verdict: item.verdict, rule: item.rule}))}));
    const leak = audit.data.findings.find(item => item.kind === 'list-leak' && item.pattern === listPath);
    assert.ok(leak, JSON.stringify(audit.data.findings));
    assert.equal(leak.mirror.result, 'both-open');
    assert.ok(fs.existsSync(leak.proof));
    const coverage = JSON.parse(fs.readFileSync(`${audit.data.runDir}/coverage.json`, 'utf8'));
    assert.equal(coverage.requestedClasses.find(item => item.name === 'Excessive Data Exposure')?.status, 'partial');
    assert.equal(coverage.requestedClasses.find(item => item.name === 'SQL Injection (SQLi)')?.status, 'not tested');
    assert.equal((await cliWithEnv(root, env, 'blackbox', 'verify', audit.data.run)).code, 1);
    vulnerable = false;
    assert.equal((await cliWithEnv(root, env, 'blackbox', 'verify', audit.data.run)).code, 0);
    const fixed = await cliWithEnv(root, env, 'blackbox', origin, '--accept-local', '--no-model');
    assert.deepEqual(fixed.data.findings, [], 'the fixed generated app must have no findings');
    assert.ok(!calls.includes('/api/delete'));
  }
});

test('real blackbox CLI finds a random IDOR through a linked page and approved CDN script', async t => {
  const root = temp();
  t.after(() => fs.rmSync(root, {recursive: true, force: true}));
  const env = {OWNER_TOKEN: 'owner-token', OTHER_TOKEN: 'other-token'};
  const suffix = randomBytes(4).readUInt32BE(0).toString().padStart(10, '0');
  const base = `/api/cohort-${suffix}/records`;
  const records = [{id: `rec-${suffix}101`, ownerId: 'u-1', total: 20},
    {id: `rec-${suffix}202`, ownerId: 'u-2', total: 30}];
  let vulnerable = true;
  const cdnHits = [];
  const cdn = http.createServer((request, response) => {
    cdnHits.push({path: request.url, authorization: request.headers.authorization, cookie: request.headers.cookie});
    response.writeHead(request.url === '/app.js' ? 200 : 404, {'content-type': 'application/javascript'});
    response.end(request.url === '/app.js'
      ? `axios({url:"/api/me",method:"GET"});axios({url:"${base}",method:"GET"});axios({url:"${base}/"+id,method:"GET"});`
      : '');
  });
  await new Promise(resolve => cdn.listen(0, '127.0.0.1', resolve));
  t.after(() => new Promise(resolve => cdn.close(resolve)));
  const cdnOrigin = `http://127.0.0.1:${cdn.address().port}`;
  const appHits = [];
  const app = http.createServer((request, response) => {
    const pathname = new URL(request.url, 'http://local').pathname;
    appHits.push(pathname);
    const who = request.headers.authorization === 'Bearer owner-token' ? 'u-1' :
      request.headers.authorization === 'Bearer other-token' ? 'u-2' : null;
    let status = 404, body = {error: 'Not found'}, type = 'application/json';
    if (pathname === '/') {
      status = 200;
      type = 'text/html';
      body = '<a href="/app">Open the application</a><a href="/outside">Outside scope</a><a href="/api/delete">Never touch</a>';
    } else if (pathname === '/app') {
      status = 200;
      type = 'text/html';
      body = `<script src="${cdnOrigin}/app.js"></script><script src="http://localhost:${cdn.address().port}/decoy.js"></script>`;
    } else if (pathname === '/api/me') {
      status = who ? 200 : 401;
      body = who ? {id: who, role: 'member'} : {error: 'Sign in'};
    } else if (pathname === base) {
      status = who ? 200 : 401;
      body = who ? records.filter(item => item.ownerId === who) : {error: 'Sign in'};
    } else if (pathname.startsWith(`${base}/`)) {
      const item = records.find(record => pathname === `${base}/${record.id}`);
      status = !who ? 401 : !item ? 404 : item.ownerId === who || vulnerable ? 200 : 403;
      body = status === 200 ? item : {error: 'Denied'};
    }
    response.writeHead(status, {'content-type': type, 'cache-control': 'no-store'});
    response.end(typeof body === 'string' ? body : JSON.stringify(body));
  });
  await new Promise(resolve => app.listen(0, '127.0.0.1', resolve));
  t.after(() => new Promise(resolve => app.close(resolve)));
  const origin = `http://127.0.0.1:${app.address().port}`;
  const configured = await cliWithEnv(root, env, 'blackbox', 'scope', origin,
    '--include', '/app,/api', '--identity-path', '/api/me');
  assert.equal(configured.code, 0);

  const unapproved = await cliWithEnv(root, env, 'blackbox', origin, '--accept-local', '--no-model');
  assert.deepEqual(unapproved.data.findings, []);
  assert.deepEqual(cdnHits, []);
  assert.ok(appHits.includes('/app'), 'the CLI crawled the in-scope linked page');

  const scopeFile = configured.data.file;
  const scope = JSON.parse(fs.readFileSync(scopeFile, 'utf8'));
  scope.discovery.assetHosts = ['127.0.0.1'];
  fs.writeFileSync(scopeFile, JSON.stringify(scope));
  const audit = await cliWithEnv(root, env, 'blackbox', origin, '--accept-local', '--no-model');
  assert.equal(audit.code, 1, JSON.stringify(audit.data));
  assert.ok(audit.data.findings.some(item => item.kind === 'idor'), JSON.stringify(audit.data.findings));
  assert.ok(audit.data.findings.every(item => fs.existsSync(item.proof)));
  assert.ok(cdnHits.some(hit => hit.path === '/app.js'));
  assert.ok(cdnHits.every(hit => !hit.authorization && !hit.cookie && hit.path !== '/decoy.js'));
  assert.ok(!appHits.some(pathname => pathname.includes('delete') || pathname.includes('billing') || pathname === '/outside'));
  assert.equal((await cliWithEnv(root, env, 'blackbox', 'verify', audit.data.run)).code, 1);
  vulnerable = false;
  assert.equal((await cliWithEnv(root, env, 'blackbox', 'verify', audit.data.run)).code, 0);
  const fixed = await cliWithEnv(root, env, 'blackbox', origin, '--accept-local', '--no-model');
  assert.deepEqual(fixed.data.findings, []);
});

test('real blackbox CLI proves fragment DOM XSS in a captured external script', async t => {
  const chrome = process.env.BYPASS_CHROME ?? 'google-chrome';
  if (spawnSync(chrome, ['--version'], {stdio: 'ignore'}).status !== 0) {
    t.skip('Chrome is unavailable for DOM XSS proof');
    return;
  }
  const root = temp();
  t.after(() => fs.rmSync(root, {recursive: true, force: true}));
  let vulnerable = true;
  const calls = [];
  const server = http.createServer((request, response) => {
    const pathname = new URL(request.url, 'http://local').pathname;
    calls.push(pathname);
    let status = 404, type = 'application/json', body = JSON.stringify({error: 'Not found'});
    if (pathname === '/') {status = 200; type = 'text/html';
      body = '<html><body><main id="out"></main><script src="/app.js"></script></body></html>';}
    else if (pathname === '/app.js') {status = 200; type = 'application/javascript';
      body = `document.getElementById('out').${vulnerable ? 'innerHTML' : 'textContent'}=` +
        `decodeURIComponent(location.hash.slice(1));\n/*${'x'.repeat(150000)}*/`;}
    else if (pathname === '/openapi.json') {status = 200;
      body = JSON.stringify({openapi: '3.0.0', paths: {}});}
    else if (pathname === '/api/delete') {status = 500; body = 'Protected decoy';}
    response.writeHead(status, {'content-type': type, 'cache-control': 'no-store'});
    response.end(body);
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  t.after(() => new Promise(resolve => server.close(resolve)));
  const origin = `http://127.0.0.1:${server.address().port}`;
  assert.equal((await cliWithEnv(root, {}, 'blackbox', 'scope', origin, '--include', '/api')).code, 0);
  const audit = await cliWithEnv(root, {}, 'blackbox', origin, '--accept-local', '--no-model',
    '--dom-script-bytes', '3145728');
  assert.equal(audit.code, 1, JSON.stringify(audit.data));
  const dom = audit.data.findings.find(item => item.kind === 'xss-dom-fragment');
  assert.ok(dom, JSON.stringify(audit.data.findings));
  assert.ok(fs.existsSync(dom.proof));
  assert.equal(JSON.parse(fs.readFileSync(path.join(path.dirname(dom.proof), 'spec.json'), 'utf8'))
    .domScriptBytes, 3145728);
  const coverage = JSON.parse(fs.readFileSync(`${audit.data.runDir}/coverage.json`, 'utf8'));
  assert.equal(coverage.requestedClasses.find(item => item.name === 'DOM-Based XSS')?.status, 'partial');
  const report = JSON.parse(fs.readFileSync(`${audit.data.runDir}/report.json`, 'utf8'));
  assert.ok(report.findings.find(item => item.kind === 'xss-dom-fragment')?.reproduction
    .every(step => step.method === 'BROWSER'));
  assert.equal((await cliWithEnv(root, {}, 'blackbox', 'verify', audit.data.run)).code, 1);
  const exported = await cliWithEnv(root, {}, 'blackbox', 'export', audit.data.run,
    '--out', `${root}/regressions`);
  assert.equal(exported.code, 0);
  assert.ok(exported.data.files.length >= 1);
  const childEnv = Object.fromEntries(Object.entries(process.env).filter(([key]) => key !== 'NODE_TEST_CONTEXT'));
  const runExport = () => new Promise((resolve, reject) => {
    const child = spawn(process.execPath, ['--test', ...exported.data.files], {env: childEnv});
    child.on('error', reject);
    child.on('close', resolve);
  });
  assert.equal(await runExport(), 1);
  vulnerable = false;
  assert.equal((await cliWithEnv(root, {}, 'blackbox', 'verify', audit.data.run)).code, 0);
  assert.equal(await runExport(), 0);
  const fixed = await cliWithEnv(root, {}, 'blackbox', origin, '--accept-local', '--no-model');
  assert.deepEqual(fixed.data.findings, []);
  assert.ok(!calls.includes('/api/delete'));
});

test('real blackbox CLI proves SQL boolean injection against SQLite and clears after prepared statements', async t => {
  const root = temp();
  t.after(() => fs.rmSync(root, {recursive: true, force: true}));
  const suffix = randomBytes(6).toString('hex');
  const textPath = `/api/${suffix}/lookup`;
  const numericPath = `/api/${suffix}/number`;
  const textId = `ref-${suffix}`;
  const numericId = 100000 + randomBytes(3).readUIntBE(0, 3) % 800000;
  const db = new DatabaseSync(':memory:');
  t.after(() => db.close());
  db.exec('CREATE TABLE records (text_key TEXT PRIMARY KEY, numeric_key INTEGER UNIQUE, value TEXT)');
  db.prepare('INSERT INTO records VALUES (?, ?, ?)').run(textId, numericId, 'owned-fixture-record');
  const calls = [];
  let vulnerable = true;
  let cached = false;
  const server = http.createServer((request, response) => {
    const url = new URL(request.url, 'http://local');
    calls.push(url.pathname);
    let status = 404, body = {error: 'Not found'};
    if (url.pathname === '/openapi.json') {status = 200; body = {openapi: '3.0.0', paths: {
      [textPath]: {get: {parameters: [{name: 'lookup', in: 'query', example: textId}]}},
      [numericPath]: {get: {parameters: [{name: 'number', in: 'query', example: numericId}]}},
      '/api/delete': {get: {}}}};}
    else if (url.pathname === textPath || url.pathname === numericPath) {
      const numeric = url.pathname === numericPath;
      const input = url.searchParams.get(numeric ? 'number' : 'lookup') ?? '';
      try {
        const row = vulnerable ? numeric ?
          db.prepare(`SELECT text_key AS id, value FROM records WHERE numeric_key=${input}`).get() :
          db.prepare(`SELECT text_key AS id, value FROM records WHERE text_key='${input}'`).get() :
          db.prepare(`SELECT text_key AS id, value FROM records WHERE ${numeric ? 'numeric_key' : 'text_key'}=?`).get(input);
        status = row ? 200 : 404;
        body = row ?? {error: 'Not found'};
      } catch {status = 400; body = {error: 'Invalid query'};}
    } else if (url.pathname === '/api/delete') {status = 500; body = {error: 'Protected decoy'};}
    response.writeHead(status, {'content-type': 'application/json', 'cache-control': 'no-store',
      ...(cached ? {age: '1', 'x-cache': 'HIT'} : {})});
    response.end(JSON.stringify(body));
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  t.after(() => new Promise(resolve => server.close(resolve)));
  const origin = `http://127.0.0.1:${server.address().port}`;
  assert.equal((await cliWithEnv(root, {}, 'blackbox', 'scope', origin, '--include', '/api')).code, 0);
  const audit = await cliWithEnv(root, {}, 'blackbox', origin, '--accept-local', '--no-model');
  assert.equal(audit.code, 1, JSON.stringify(audit.data));
  const sqlFindings = audit.data.findings.filter(item => item.kind === 'sql-boolean');
  assert.deepEqual(sqlFindings.map(item => item.pattern).sort(), [numericPath, textPath].sort());
  assert.ok(sqlFindings.every(item => fs.existsSync(item.proof) && item.confirmation.length >= 2));
  const coverage = JSON.parse(fs.readFileSync(`${audit.data.runDir}/coverage.json`, 'utf8'));
  assert.equal(coverage.requestedClasses.find(item => item.name === 'SQL Injection (SQLi)')?.status, 'partial');
  assert.equal(coverage.requestedClasses.find(item => item.name === 'NoSQL Injection')?.status, 'not tested');
  assert.equal((await cliWithEnv(root, {}, 'blackbox', 'verify', audit.data.run)).code, 1);
  cached = true;
  assert.equal((await cliWithEnv(root, {}, 'blackbox', 'verify', audit.data.run)).code, 3,
    'a cached SQL proof response must be inconclusive');
  cached = false;
  const exported = await cliWithEnv(root, {}, 'blackbox', 'export', audit.data.run,
    '--out', `${root}/regressions`);
  assert.equal(exported.code, 0);
  const childEnv = Object.fromEntries(Object.entries(process.env).filter(([key]) => key !== 'NODE_TEST_CONTEXT'));
  const runExport = () => new Promise((resolve, reject) => {
    const child = spawn(process.execPath, ['--test', ...exported.data.files], {env: childEnv});
    child.on('error', reject);
    child.on('close', resolve);
  });
  assert.equal(await runExport(), 1);
  vulnerable = false;
  assert.equal((await cliWithEnv(root, {}, 'blackbox', 'verify', audit.data.run)).code, 0);
  assert.equal(await runExport(), 0);
  const fixed = await cliWithEnv(root, {}, 'blackbox', origin, '--accept-local', '--no-model');
  assert.deepEqual(fixed.data.findings, []);
  assert.ok(!calls.includes('/api/delete'));
});

test('real blackbox CLI finds SQL search injection from a public client host alias and replays the fix', async t => {
  const root = temp();
  t.after(() => fs.rmSync(root, {recursive: true, force: true}));
  const route = `/rest/${randomBytes(5).toString('hex')}/search`;
  const script = 'class Products {hostServer=config.hostServer; host=this.hostServer+"' + route + '";' +
    'search(q){return this.http.get(`${this.host}?q=${q}`)}' +
    'save(value){return this.http.post(this.host,value)}}' +
    Array.from({length: 513}, (_, index) => `class Empty${index}{}`).join('');
  const db = new DatabaseSync(':memory:');
  t.after(() => db.close());
  db.exec("CREATE TABLE products (id INTEGER PRIMARY KEY, name TEXT); INSERT INTO products VALUES (1,'apple'),(2,'grape'),(3,'pear'),(4,'melon')");
  let vulnerable = true, writes = 0;
  const server = http.createServer((request, response) => {
    const url = new URL(request.url, 'http://local');
    if (url.pathname === '/') {
      response.writeHead(200, {'content-type': 'text/html'});
      response.end('<html><script src="/main.js"></script></html>');
      return;
    }
    if (url.pathname === '/main.js') {
      response.writeHead(200, {'content-type': 'application/javascript'});
      response.end(script);
      return;
    }
    let status = 404, body = {error: 'Not found'};
    if (url.pathname === route) {
      if (request.method !== 'GET') {
        if (request.method === 'POST') writes++;
        response.writeHead(405).end();
        return;
      }
      const q = url.searchParams.get('q') ?? '';
      try {
        const rows = vulnerable ?
          db.prepare(`SELECT id,name FROM products WHERE ((name LIKE '%${q}%'))`).all() :
          db.prepare('SELECT id,name FROM products WHERE ((name LIKE ?))').all(`%${q}%`);
        status = 200;
        body = {data: rows};
      } catch {status = 400; body = {error: 'Invalid query'};}
    }
    response.writeHead(status, {'content-type': 'application/json', 'cache-control': 'no-store'});
    response.end(JSON.stringify(body));
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  t.after(() => new Promise(resolve => server.close(resolve)));
  const origin = `http://127.0.0.1:${server.address().port}`;
  assert.equal((await cliWithEnv(root, {}, 'blackbox', 'scope', origin, '--include', '/')).code, 0);
  const audit = await cliWithEnv(root, {}, 'blackbox', origin, '--accept-local', '--no-model');
  assert.equal(audit.code, 1, JSON.stringify(audit.data));
  const found = audit.data.findings.find(item => item.kind === 'sql-boolean' && item.pattern === route);
  assert.ok(found && fs.existsSync(found.proof), JSON.stringify(audit.data.findings));
  const assets = JSON.parse(fs.readFileSync(`${audit.data.runDir}/assets.json`, 'utf8'));
  assert.ok(assets.endpoints.some(item => item.path === route && item.method === 'GET' &&
    item.params.includes('q') && item.inferredBase === true));
  assert.ok(assets.endpoints.some(item => item.path === route && item.method === 'POST'));
  assert.equal(assets.stats.inferredClassesCut, 2);
  assert.ok(audit.data.limitations.some(item => /did not inspect 2 JavaScript classes/.test(item)));
  assert.equal(writes, 0, 'the listed POST route was never called');
  assert.equal((await cliWithEnv(root, {}, 'blackbox', 'verify', audit.data.run)).code, 1);
  vulnerable = false;
  assert.equal((await cliWithEnv(root, {}, 'blackbox', 'verify', audit.data.run)).code, 0);
});

test('real blackbox CLI proves harmless shell output and clears after argument separation', async t => {
  if (spawnSync('/bin/sh', ['-c', 'true'], {stdio: 'ignore'}).status !== 0) {
    t.skip('a POSIX shell is needed for this command-injection fixture');
    return;
  }
  const root = temp();
  t.after(() => fs.rmSync(root, {recursive: true, force: true}));
  const suffix = randomBytes(6).toString('hex');
  const route = `/api/${suffix}/run`;
  const calls = [];
  let vulnerable = true;
  let cached = false;
  const server = http.createServer((request, response) => {
    const url = new URL(request.url, 'http://local');
    calls.push(url.pathname);
    let status = 404, body = {error: 'Not found'};
    if (url.pathname === '/openapi.json') {status = 200; body = {openapi: '3.0.0', paths: {
      [route]: {get: {parameters: [{name: 'input', in: 'query'}]}},
      '/api/delete': {get: {}}}};}
    else if (url.pathname === route) {
      const input = url.searchParams.get('input') ?? '';
      try {
        const output = vulnerable ?
          execFileSync('/bin/sh', ['-c', `printf '%s' ${input}`],
            {encoding: 'utf8', timeout: 1000, maxBuffer: 4096, stdio: ['ignore', 'pipe', 'ignore']}) :
          execFileSync('printf', ['%s', input],
            {encoding: 'utf8', timeout: 1000, maxBuffer: 4096, stdio: ['ignore', 'pipe', 'ignore']});
        status = 200;
        body = {output};
      } catch {status = 400; body = {error: 'Invalid input'};}
    } else if (url.pathname === '/api/delete') {status = 500; body = {error: 'Protected decoy'};}
    response.writeHead(status, {'content-type': 'application/json', 'cache-control': 'no-store',
      ...(cached ? {age: '1', 'x-cache': 'HIT'} : {})});
    response.end(JSON.stringify(body));
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  t.after(() => new Promise(resolve => server.close(resolve)));
  const origin = `http://127.0.0.1:${server.address().port}`;
  const configured = await cliWithEnv(root, {}, 'blackbox', 'scope', origin, '--include', '/api');
  assert.equal(configured.code, 0);
  assert.equal(JSON.parse(fs.readFileSync(configured.data.file, 'utf8')).probes.commandExecution, true);
  const audit = await cliWithEnv(root, {}, 'blackbox', origin, '--accept-local', '--no-model');
  assert.equal(audit.code, 1, JSON.stringify(audit.data));
  const finding = audit.data.findings.find(item => item.kind === 'command-output' && item.pattern === route);
  assert.ok(finding, JSON.stringify(audit.data.findings));
  assert.ok(fs.existsSync(finding.proof));
  const coverage = JSON.parse(fs.readFileSync(`${audit.data.runDir}/coverage.json`, 'utf8'));
  assert.equal(coverage.requestedClasses.find(item => item.name === 'OS Command Injection')?.status, 'partial');
  assert.equal(coverage.requestedClasses.find(item => item.name === 'Remote Code Execution (RCE)')?.status, 'partial');
  assert.equal((await cliWithEnv(root, {}, 'blackbox', 'verify', audit.data.run)).code, 1);
  cached = true;
  assert.equal((await cliWithEnv(root, {}, 'blackbox', 'verify', audit.data.run)).code, 3,
    'a cache hit during proof replay must be inconclusive');
  cached = false;
  const exported = await cliWithEnv(root, {}, 'blackbox', 'export', audit.data.run,
    '--out', `${root}/regressions`);
  assert.equal(exported.code, 0);
  const childEnv = Object.fromEntries(Object.entries(process.env).filter(([key]) => key !== 'NODE_TEST_CONTEXT'));
  const runExport = () => new Promise((resolve, reject) => {
    const child = spawn(process.execPath, ['--test', ...exported.data.files], {env: childEnv});
    child.on('error', reject);
    child.on('close', resolve);
  });
  assert.equal(await runExport(), 1);
  vulnerable = false;
  assert.equal((await cliWithEnv(root, {}, 'blackbox', 'verify', audit.data.run)).code, 0);
  assert.equal(await runExport(), 0);
  const fixed = await cliWithEnv(root, {}, 'blackbox', origin, '--accept-local', '--no-model');
  assert.deepEqual(fixed.data.findings, []);
  assert.ok(!calls.includes('/api/delete'));
});

test('real blackbox CLI proves a relative file traversal and clears after path confinement', async t => {
  if (process.platform !== 'linux' || !/^127\.0\.0\.1[\t ]+localhost(?:[\t \r]|$)/m
    .test(fs.readFileSync('/etc/hosts', 'utf8'))) {
    t.skip('a standard local hosts file is needed for this file-read fixture');
    return;
  }
  const root = temp();
  t.after(() => fs.rmSync(root, {recursive: true, force: true}));
  const filesDir = path.join(root, 'public', 'files');
  fs.mkdirSync(filesDir, {recursive: true});
  const route = `/api/${randomBytes(6).toString('hex')}/view`;
  const calls = [];
  let vulnerable = true;
  const server = http.createServer((request, response) => {
    const url = new URL(request.url, 'http://local');
    calls.push(url.pathname);
    let status = 404, body = 'Not found', type = 'text/plain';
    if (url.pathname === '/openapi.json') {status = 200; type = 'application/json';
      body = JSON.stringify({openapi: '3.0.0', paths: {
        [route]: {get: {parameters: [{name: 'file', in: 'query'}]}},
        '/api/delete': {get: {}}}});
    } else if (url.pathname === route) {
      const requested = path.resolve(filesDir, url.searchParams.get('file') ?? '');
      if (!vulnerable && !requested.startsWith(`${filesDir}${path.sep}`)) {
        status = 403; body = 'Outside file directory';
      } else {
        try {body = fs.readFileSync(requested, 'utf8'); status = 200;}
        catch {status = 404; body = 'Not found';}
      }
    } else if (url.pathname === '/api/delete') {status = 500; body = 'Protected decoy';}
    response.writeHead(status, {'content-type': type, 'cache-control': 'no-store'});
    response.end(body);
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  t.after(() => new Promise(resolve => server.close(resolve)));
  const origin = `http://127.0.0.1:${server.address().port}`;
  const configured = await cliWithEnv(root, {}, 'blackbox', 'scope', origin, '--include', '/api');
  assert.equal(configured.code, 0);
  assert.equal(JSON.parse(fs.readFileSync(configured.data.file, 'utf8')).probes.pathTraversal, true);
  const audit = await cliWithEnv(root, {}, 'blackbox', origin, '--accept-local', '--no-model');
  assert.equal(audit.code, 1, JSON.stringify(audit.data));
  const finding = audit.data.findings.find(item => item.kind === 'path-traversal-hosts' && item.pattern === route);
  assert.ok(finding, JSON.stringify(audit.data.findings));
  assert.ok(fs.existsSync(finding.proof));
  const coverage = JSON.parse(fs.readFileSync(`${audit.data.runDir}/coverage.json`, 'utf8'));
  assert.equal(coverage.requestedClasses.find(item => item.name === 'Path Traversal')?.status, 'partial');
  assert.equal(coverage.requestedClasses.find(item => item.name === 'Local File Inclusion (LFI)')?.status, 'partial');
  assert.equal(coverage.requestedClasses.find(item => item.name === 'Remote File Inclusion (RFI)')?.status, 'not tested');
  assert.equal((await cliWithEnv(root, {}, 'blackbox', 'verify', audit.data.run)).code, 1);
  const exported = await cliWithEnv(root, {}, 'blackbox', 'export', audit.data.run,
    '--out', `${root}/regressions`);
  assert.equal(exported.code, 0);
  const childEnv = Object.fromEntries(Object.entries(process.env).filter(([key]) => key !== 'NODE_TEST_CONTEXT'));
  const runExport = () => new Promise((resolve, reject) => {
    const child = spawn(process.execPath, ['--test', ...exported.data.files], {env: childEnv});
    child.on('error', reject);
    child.on('close', resolve);
  });
  assert.equal(await runExport(), 1);
  vulnerable = false;
  assert.equal((await cliWithEnv(root, {}, 'blackbox', 'verify', audit.data.run)).code, 0);
  assert.equal(await runExport(), 0);
  const fixed = await cliWithEnv(root, {}, 'blackbox', origin, '--accept-local', '--no-model');
  assert.deepEqual(fixed.data.findings, []);
  assert.ok(!calls.includes('/api/delete'));
});

test('real blackbox CLI proves CRLF response-header injection from raw HTTP behavior', async t => {
  const root = temp();
  t.after(() => fs.rmSync(root, {recursive: true, force: true}));
  let vulnerable = true;
  const calls = [];
  const server = net.createServer(socket => {
    let request = '', answered = false;
    socket.on('error', () => {});
    socket.on('data', chunk => {
      request += chunk.toString('latin1');
      if (answered || !request.includes('\r\n\r\n')) return;
      answered = true;
      const target = request.split('\r\n', 1)[0].split(' ')[1] ?? '/';
      const url = new URL(target, 'http://local');
      calls.push(url.pathname);
      let status = 404, type = 'application/json', body = JSON.stringify({error: 'Not found'}), extra = '';
      if (url.pathname === '/') {status = 200; type = 'text/html'; body = '<html>Header fixture</html>';}
      else if (url.pathname === '/openapi.json') {status = 200;
        body = JSON.stringify({openapi: '3.0.0', paths: {
          '/api/header': {get: {parameters: [{name: 'value', in: 'query'}]}},
          '/api/delete': {get: {}}}});}
      else if (url.pathname === '/api/header') {
        status = 200; type = 'text/plain'; body = 'ok';
        const value = url.searchParams.get('value') ?? '';
        extra = `X-Name: ${vulnerable ? value : value.replace(/[\r\n]/g, '')}\r\n`;
      } else if (url.pathname === '/api/delete') {status = 500; body = 'Protected decoy';}
      const reason = status === 200 ? 'OK' : status === 500 ? 'Internal Server Error' : 'Not Found';
      socket.end(`HTTP/1.1 ${status} ${reason}\r\nContent-Type: ${type}\r\n` +
        `Cache-Control: no-store\r\n${extra}Content-Length: ${Buffer.byteLength(body)}\r\n` +
        `Connection: close\r\n\r\n${body}`);
    });
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  t.after(() => new Promise(resolve => server.close(resolve)));
  const origin = `http://127.0.0.1:${server.address().port}`;
  assert.equal((await cliWithEnv(root, {}, 'blackbox', 'scope', origin, '--include', '/api')).code, 0);
  const audit = await cliWithEnv(root, {}, 'blackbox', origin, '--accept-local', '--no-model');
  assert.equal(audit.code, 1, JSON.stringify(audit.data));
  const crlf = audit.data.findings.find(item => item.kind === 'crlf-header');
  assert.ok(crlf, JSON.stringify(audit.data.findings));
  assert.ok(fs.existsSync(crlf.proof));
  const coverage = JSON.parse(fs.readFileSync(`${audit.data.runDir}/coverage.json`, 'utf8'));
  assert.equal(coverage.requestedClasses.find(item => item.name === 'CRLF Injection')?.status, 'partial');
  assert.equal((await cliWithEnv(root, {}, 'blackbox', 'verify', audit.data.run)).code, 1);
  const exported = await cliWithEnv(root, {}, 'blackbox', 'export', audit.data.run,
    '--out', `${root}/regressions`);
  assert.equal(exported.code, 0);
  const childEnv = Object.fromEntries(Object.entries(process.env).filter(([key]) => key !== 'NODE_TEST_CONTEXT'));
  const runExport = () => new Promise((resolve, reject) => {
    const child = spawn(process.execPath, ['--test', ...exported.data.files], {env: childEnv});
    child.on('error', reject);
    child.on('close', resolve);
  });
  assert.equal(await runExport(), 1);
  vulnerable = false;
  assert.equal((await cliWithEnv(root, {}, 'blackbox', 'verify', audit.data.run)).code, 0);
  assert.equal(await runExport(), 0);
  const fixed = await cliWithEnv(root, {}, 'blackbox', origin, '--accept-local', '--no-model');
  assert.deepEqual(fixed.data.findings, []);
  assert.ok(!calls.includes('/api/delete'));
});

test('real blackbox CLI proves a bracketed equality-operator cross-account bypass', async t => {
  const root = temp();
  t.after(() => fs.rmSync(root, {recursive: true, force: true}));
  const suffix = randomBytes(4).toString('hex');
  const ownerId = `rec-${suffix}101`, otherId = `rec-${suffix}202`;
  const records = [{id: ownerId, ownerId: 'u-1'}, {id: otherId, ownerId: 'u-2'}];
  const env = {OWNER_TOKEN: 'owner-token', OTHER_TOKEN: 'other-token'};
  let vulnerable = true;
  const requested = [];
  const server = http.createServer((request, response) => {
    const url = new URL(request.url, 'http://local');
    requested.push(url.pathname);
    const who = request.headers.authorization === 'Bearer owner-token' ? 'u-1' :
      request.headers.authorization === 'Bearer other-token' ? 'u-2' : null;
    let status = 404, body = {error: 'Not found'};
    if (url.pathname === '/openapi.json') {status = 200; body = {openapi: '3.0.0', paths: {
      '/api/me': {get: {}}, '/api/records': {get: {}},
      '/api/lookup': {get: {parameters: [{name: 'id', in: 'query', example: ownerId}]}},
      '/api/delete': {get: {}}}};}
    else if (url.pathname === '/api/me') {status = who ? 200 : 401;
      body = who ? {id: who, role: 'member'} : {error: 'Sign in'};}
    else if (url.pathname === '/api/records') {status = who ? 200 : 401;
      body = who ? records.filter(item => item.ownerId === who) : {error: 'Sign in'};}
    else if (url.pathname === '/api/lookup') {
      const operator = url.searchParams.has('id[$eq]');
      const selected = url.searchParams.get(operator ? 'id[$eq]' : 'id');
      const record = records.find(item => item.id === selected);
      status = !who ? 401 : operator && !vulnerable ? 400 : !selected ? 400 :
        !record ? 404 : record.ownerId === who || operator && vulnerable ? 200 : 403;
      body = status === 200 ? record : {error: status === 400 ? 'Invalid filter' : 'Denied'};
    } else if (url.pathname === '/api/delete') {status = 500; body = {error: 'Protected decoy'};}
    response.writeHead(status, {'content-type': 'application/json', 'cache-control': 'no-store'});
    response.end(JSON.stringify(body));
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  t.after(() => new Promise(resolve => server.close(resolve)));
  const origin = `http://127.0.0.1:${server.address().port}`;
  const configured = await cliWithEnv(root, env, 'blackbox', 'scope', origin, '--include', '/api');
  assert.equal(configured.code, 0);
  const audit = () => cliWithEnv(root, env, 'blackbox', origin, '--accept-local', '--no-model');
  const first = await audit();
  const finding = first.data.findings.find(item => item.kind === 'nosql-operator-bypass');
  assert.equal(first.code, 1, JSON.stringify(first.data.findings));
  assert.ok(finding, JSON.stringify(first.data.findings));
  assert.ok(fs.existsSync(finding.proof));
  assert.ok(!requested.includes('/api/delete'));
  const coverage = JSON.parse(fs.readFileSync(path.join(first.data.runDir, 'coverage.json'), 'utf8'));
  assert.equal(coverage.requestedClasses.find(item => item.name === 'NoSQL Injection').status, 'partial');
  assert.equal((await cliWithEnv(root, env, 'blackbox', 'verify', first.data.run)).code, 1);
  const exported = await cliWithEnv(root, env, 'blackbox', 'export', first.data.run,
    '--out', path.join(root, 'regressions'));
  assert.equal(exported.code, 0);
  const childEnv = {...Object.fromEntries(Object.entries(process.env)
    .filter(([key]) => key !== 'NODE_TEST_CONTEXT')), ...env};
  const runExport = () => new Promise((resolve, reject) => {
    const child = spawn(process.execPath, ['--test', ...exported.data.files], {env: childEnv, stdio: 'ignore'});
    child.on('error', reject);
    child.on('close', resolve);
  });
  assert.equal(await runExport(), 1);
  vulnerable = false;
  assert.equal((await cliWithEnv(root, env, 'blackbox', 'verify', first.data.run)).code, 0);
  assert.equal(await runExport(), 0);
  const fixed = await audit();
  assert.ok(!fixed.data.findings.some(item => item.kind === 'nosql-operator-bypass'));
  assert.ok(!requested.includes('/api/delete'));
});
