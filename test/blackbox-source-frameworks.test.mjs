import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import http from 'node:http';
import path from 'node:path';
import {spawn} from 'node:child_process';
import {temp} from './helpers.mjs';
import {execFile} from '../src/util.mjs';
import {CLI} from '../src/demo.mjs';

async function assertSourceRedirect(t, sourceFiles, routePath, decoyPath, unprefixedPath) {
  const root = temp();
  t.after(() => fs.rmSync(root, {recursive: true, force: true}));
  const source = path.join(root, 'source');
  fs.mkdirSync(source);
  for (const [file, body] of sourceFiles) {
    const full = path.join(source, file);
    fs.mkdirSync(path.dirname(full), {recursive: true});
    fs.writeFileSync(full, body);
  }
  let vulnerable = true;
  const requested = [];
  const server = http.createServer((request, response) => {
    const url = new URL(request.url, 'http://local');
    requested.push(`${request.method} ${url.pathname}`);
    if (request.method === 'GET' && url.pathname === routePath) {
      const destination = vulnerable ? url.searchParams.get('next') ?? '/safe' : '/safe';
      if (/[\r\n]/.test(destination)) {
        response.writeHead(400);
        return response.end('Invalid destination');
      }
      response.writeHead(302, {location: destination, 'cache-control': 'no-store'});
      return response.end();
    }
    if (url.pathname === decoyPath) {
      response.writeHead(500);
      return response.end('Protected decoy');
    }
    response.writeHead(404);
    response.end();
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  t.after(() => new Promise(resolve => server.close(resolve)));
  const origin = `http://127.0.0.1:${server.address().port}`;
  const cli = async (...args) => {
    const done = await execFile(process.execPath,
      [CLI, 'blackbox', ...args, '--project', root, '--json', '--non-interactive'],
      {cwd: root, timeout: 90000});
    return {code: done.code, data: JSON.parse(done.stdout)};
  };
  const baseline = await cli(origin, '--accept-local', '--no-model');
  assert.ok(!baseline.data.findings.some(item => item.kind === 'open-redirect'));
  const audit = await cli(origin, '--accept-local', '--no-model', '--source', source);
  assert.equal(audit.code, 1, JSON.stringify(audit.data));
  const finding = audit.data.findings.find(item => item.kind === 'open-redirect' && item.pattern === routePath);
  assert.ok(finding, JSON.stringify(audit.data.findings));
  assert.ok(fs.existsSync(finding.proof));
  const sourceResult = JSON.parse(fs.readFileSync(path.join(audit.data.runDir, 'source.json'), 'utf8'));
  assert.ok(sourceResult.endpoints.some(item => item.path === routePath && item.method === 'GET' &&
    item.params.includes('next')));
  assert.ok(sourceResult.endpoints.some(item => item.path === decoyPath && item.method === 'POST'));
  if (unprefixedPath) assert.ok(!sourceResult.endpoints.some(item => item.path === unprefixedPath));
  assert.ok(!requested.some(value => value.endsWith(decoyPath)));
  assert.equal((await cli('verify', audit.data.run)).code, 1);
  const exported = await cli('export', audit.data.run, '--out', path.join(root, 'regressions'));
  assert.equal(exported.code, 0);
  const runExport = () => new Promise((resolve, reject) => {
    const child = spawn(process.execPath, ['--test', ...exported.data.files],
      {env: Object.fromEntries(Object.entries(process.env).filter(([key]) => key !== 'NODE_TEST_CONTEXT')),
        stdio: 'ignore'});
    child.once('error', reject);
    child.once('close', resolve);
  });
  assert.equal(await runExport(), 1);
  vulnerable = false;
  assert.equal((await cli('verify', audit.data.run)).code, 0);
  assert.equal(await runExport(), 0);
  const fixed = await cli(origin, '--accept-local', '--no-model', '--source', source);
  assert.ok(!fixed.data.findings.some(item => item.kind === 'open-redirect'));
}

test('actual CLI finds a redirect known only from a grouped Laravel-style GET source route', async t => {
  await assertSourceRedirect(t, [['api.php',
    "Route::prefix('api')->group(function () {\n" +
    "  Route::get('php-jump', function ($request) { return redirect($request->query('next')); });\n" +
    "  Route::post('/delete', function ($request) { return $request->input('record'); });\n" +
    "});\n"]], '/api/php-jump', '/api/delete', '/php-jump');
});

test('actual CLI finds a redirect only through an imported FastAPI router with an include prefix', async t => {
  await assertSourceRedirect(t, [
    ['app/main.py', 'from .routers import redirects\napp = FastAPI()\n' +
      'app.include_router(redirects.router, prefix="/api")\n'],
    ['app/routers/redirects.py', 'router = APIRouter(prefix="/v1")\n' +
      '@router.get("/python-jump")\n' +
      'def jump(request): return request.query_params.get("next")\n' +
      '@router.post("/delete")\n' +
      'def delete(): return "ok"\n'],
  ], '/api/v1/python-jump', '/api/v1/delete', '/v1/python-jump');
});
