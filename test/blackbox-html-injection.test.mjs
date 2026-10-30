import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import http from 'node:http';
import path from 'node:path';
import {randomBytes} from 'node:crypto';
import {spawn, spawnSync} from 'node:child_process';
import {temp} from './helpers.mjs';
import {execFile} from '../src/util.mjs';
import {CLI} from '../src/demo.mjs';
import {renderCapturedHtml} from '../src/blackbox/poc-runtime.mjs';

async function cli(root, ...args) {
  const done = await execFile(process.execPath,
    [CLI, 'blackbox', ...args, '--project', root, '--json', '--non-interactive'],
    {cwd: root, timeout: 90000});
  return {code: done.code, data: JSON.parse(done.stdout)};
}

test('isolated Chrome distinguishes a parsed canary element from escaped and embedded markup', async t => {
  const chrome = process.env.BYPASS_CHROME ?? 'google-chrome';
  if (spawnSync(chrome, ['--version'], {stdio: 'ignore'}).status !== 0) {
    t.skip('Chrome is unavailable for HTML parsing controls');
    return;
  }
  const marker = randomBytes(12).toString('hex');
  const element = `<b id="bx-html-${marker}"></b>`;
  for (const [label, body, expected] of [
    ['parsed', `<html><body>${element}</body></html>`, true],
    ['escaped', `<html><body>&lt;b id="bx-html-${marker}"&gt;&lt;/b&gt;</body></html>`, false],
    ['attribute', `<html><body><div title='${element}'>safe</div></body></html>`, false],
    ['script text', `<html><body><script>const text='${element}';</script></body></html>`, false],
  ]) {
    const result = await renderCapturedHtml(body, "script-src 'none'", marker, {detectHtml: true});
    assert.equal(result.blocked, undefined, label);
    assert.equal(result.elementInserted, expected, label);
  }
});

test('actual CLI proves markup insertion under a no-script CSP and its regression clears after escaping', async t => {
  const chrome = process.env.BYPASS_CHROME ?? 'google-chrome';
  if (spawnSync(chrome, ['--version'], {stdio: 'ignore'}).status !== 0) {
    t.skip('Chrome is unavailable for HTML-injection proof');
    return;
  }
  const root = temp();
  t.after(() => fs.rmSync(root, {recursive: true, force: true}));
  const suffix = randomBytes(5).toString('hex');
  const route = `/api/${suffix}/view`;
  const safeRoute = `/api/${suffix}/safe`;
  const requests = [];
  let vulnerable = true;
  const escape = value => value.replaceAll('&', '&amp;').replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;').replaceAll('"', '&quot;').replaceAll("'", '&#39;');
  const server = http.createServer((request, response) => {
    const url = new URL(request.url, 'http://local');
    requests.push(url.pathname);
    if (url.pathname === '/openapi.json') {
      response.writeHead(200, {'content-type': 'application/json', 'cache-control': 'no-store'});
      return response.end(JSON.stringify({openapi: '3.0.0', paths: {
        [route]: {get: {parameters: [{name: 'text', in: 'query'}]}},
        [safeRoute]: {get: {parameters: [{name: 'text', in: 'query'}]}},
        '/api/delete': {get: {}},
      }}));
    }
    if (url.pathname === route || url.pathname === safeRoute) {
      const input = url.searchParams.get('text') ?? '';
      const output = url.pathname === route && vulnerable ? input : escape(input);
      response.writeHead(200, {'content-type': 'text/html; charset=utf-8',
        'content-security-policy': "default-src 'none'; script-src 'none'",
        'cache-control': 'no-store'});
      return response.end(`<!doctype html><html><body><p>${output}</p></body></html>`);
    }
    response.writeHead(url.pathname === '/api/delete' ? 500 : 404,
      {'content-type': 'text/plain', 'cache-control': 'no-store'});
    response.end('Unavailable');
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  t.after(() => new Promise(resolve => server.close(resolve)));
  const origin = `http://127.0.0.1:${server.address().port}`;
  assert.equal((await cli(root, 'scope', origin, '--include', '/api')).code, 0);
  const audit = await cli(root, origin, '--accept-local', '--no-model');
  assert.equal(audit.code, 1, JSON.stringify(audit.data));
  const finding = audit.data.findings.find(item => item.kind === 'html-injection' &&
    item.pattern === route);
  assert.ok(finding, JSON.stringify(audit.data.findings));
  assert.ok(fs.existsSync(finding.proof));
  assert.ok(!audit.data.findings.some(item => item.pattern === safeRoute ||
    item.kind === 'xss-reflected'));
  const coverage = JSON.parse(fs.readFileSync(path.join(audit.data.runDir, 'coverage.json'), 'utf8'));
  assert.equal(coverage.requestedClasses.find(item => item.name === 'HTML Injection')?.status, 'partial');
  assert.equal((await cli(root, 'verify', audit.data.run)).code, 1);
  const exported = await cli(root, 'export', audit.data.run, '--out', path.join(root, 'regressions'));
  assert.equal(exported.code, 0);
  const testEnv = Object.fromEntries(Object.entries(process.env).filter(([key]) => key !== 'NODE_TEST_CONTEXT'));
  const runExport = () => new Promise((resolve, reject) => {
    const child = spawn(process.execPath, ['--test', ...exported.data.files],
      {cwd: root, env: testEnv, stdio: 'ignore'});
    child.on('error', reject);
    child.on('close', resolve);
  });
  assert.equal(await runExport(), 1);
  vulnerable = false;
  assert.equal((await cli(root, 'verify', audit.data.run)).code, 0);
  assert.equal(await runExport(), 0);
  const fixed = await cli(root, origin, '--accept-local', '--no-model');
  assert.deepEqual(fixed.data.findings, []);
  assert.ok(!requests.includes('/api/delete'));
});
