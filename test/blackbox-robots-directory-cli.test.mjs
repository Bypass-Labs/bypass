import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import http from 'node:http';
import path from 'node:path';
import {randomBytes} from 'node:crypto';
import {CLI} from '../src/demo.mjs';
import {execFile} from '../src/util.mjs';
import {temp} from './helpers.mjs';
import {parseRobots} from '../src/blackbox/robots-directory.mjs';
import {loadScope} from '../src/blackbox/scope.mjs';

test('robots parser admits scoped literal Allow, Disallow and Sitemap leads only', () => {
  const origin = 'http://127.0.0.1:4329';
  const scope = loadScope({origin, overrides: {acceptLocal: true}}).scope;
  const parsed = parseRobots(`User-agent: *\nDisallow: /hidden\nAllow: /public/info\n` +
    `Sitemap: ${origin}/site-map.xml\nDisallow: https://outside.invalid/malware\n` +
    'Disallow: /api/logout\nDisallow: /search?token=abc\n', origin, scope);
  assert.deepEqual(parsed.map(item => [item.path, item.source]), [
    ['/hidden', 'robots:disallow'], ['/public/info', 'robots:allow'],
    ['/site-map.xml', 'robots:sitemap'], ['/search', 'robots:disallow']]);
});

test('real CLI follows randomized robots directory, verifies file signatures, and clears after fix', async t => {
  const root = temp();
  t.after(() => fs.rmSync(root, {recursive: true, force: true}));
  const suffix = randomBytes(5).toString('hex');
  const hidden = `/hidden-${suffix}`;
  const skipped = `/skip-${suffix}`;
  const archive = `${hidden}/vault.kdbx`;
  const nested = `${hidden}/nested`;
  const sql = `${nested}/backup.sql`;
  const decoy = `${hidden}/decoy.kdbx`;
  const calls = [];
  let vulnerable = true;
  const kdbx = Buffer.concat([Buffer.from('03d9a29a67fb4bb5', 'hex'), randomBytes(32)]);
  const server = http.createServer((request, response) => {
    const url = new URL(request.url, 'http://fixture');
    calls.push(`${request.method} ${url.pathname}`);
    if (url.pathname === '/robots.txt') {
      response.setHeader('content-type', 'text/plain');
      return response.end(`User-agent: *\nDisallow: ${hidden}\nAllow: ${skipped}\n` +
        'Disallow: https://outside.invalid/malware\n');
    }
    if (url.pathname === '/sitemap.xml') {
      response.setHeader('content-type', 'application/xml');
      return response.end(`<urlset><url><loc>http://127.0.0.1:${server.address().port}/docs</loc></url>` +
        '<url><loc>https://outside.invalid/malware</loc></url></urlset>');
    }
    if (url.pathname === '/') {
      response.setHeader('content-type', 'text/html');
      return response.end('<html><a href="/docs">Docs</a><a href="https://outside.invalid/malware">Outside</a></html>');
    }
    if (url.pathname === '/docs') {
      response.setHeader('content-type', 'text/html');
      return response.end('<html><script src="/docs.js"></script><a href="/openapi.json">API</a></html>');
    }
    if (url.pathname === '/docs.js') {
      response.setHeader('content-type', 'text/javascript');
      return response.end('fetch("/api/read-only");');
    }
    if (url.pathname === '/openapi.json') {
      response.setHeader('content-type', 'application/json');
      return response.end(JSON.stringify({openapi: '3.0.0', paths: {'/api/read-only': {get: {summary: 'Read data'}}}}));
    }
    if (url.pathname === skipped) {response.statusCode = 200; return response.end('should never request');}
    if (!vulnerable && (url.pathname === hidden || url.pathname.startsWith(`${hidden}/`))) {
      response.statusCode = 403; return response.end('denied');
    }
    if (url.pathname === hidden || url.pathname === nested) {
      response.statusCode = 301;
      response.setHeader('location', `${url.pathname}/`);
      return response.end();
    }
    if (url.pathname === `${hidden}/`) {
      response.setHeader('content-type', 'text/html');
      return response.end(`<title>listing directory ${hidden}/</title><a href="nested">nested</a>` +
        '<a href="vault.kdbx">vault.kdbx</a><a href="decoy.kdbx">decoy.kdbx</a>' +
        '<a href="download.url">download.url</a><a href="notes.md">notes.md</a>');
    }
    if (url.pathname === `${nested}/`) {
      response.setHeader('content-type', 'text/html');
      return response.end(`<title>listing directory ${nested}/</title><a href="backup.sql">backup.sql</a>`);
    }
    if (url.pathname === archive) {
      response.setHeader('content-type', 'application/octet-stream');
      if (request.headers.range === 'bytes=0-63') {
        response.statusCode = 206;
        response.setHeader('content-range', `bytes 0-${Math.min(63, kdbx.length - 1)}/${kdbx.length}`);
        return response.end(kdbx.subarray(0, 64));
      }
      return response.end(kdbx);
    }
    if (url.pathname === sql) {
      response.setHeader('content-type', 'text/plain');
      const body = Buffer.from('CREATE TABLE users (id int);\nINSERT INTO users VALUES (1);\n');
      if (request.headers.range === 'bytes=0-63') {
        response.statusCode = 206;
        response.setHeader('content-range', `bytes 0-${body.length - 1}/${body.length}`);
      }
      return response.end(body);
    }
    if (url.pathname === decoy) {
      response.setHeader('content-type', 'text/html');
      return response.end('<html>Public page with a misleading filename</html>');
    }
    if (url.pathname === '/api/read-only') {
      response.setHeader('content-type', 'application/json'); return response.end('{"ok":true}');
    }
    response.statusCode = 404;
    response.end();
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  t.after(() => new Promise(resolve => server.close(resolve)));
  const origin = `http://127.0.0.1:${server.address().port}`;
  fs.writeFileSync(path.join(root, 'blackbox.scope.json'), JSON.stringify({schemaVersion: 1,
    target: {origin}, include: ['/'], never: [`${skipped}*`],
    limits: {rps: 100, maxUrls: 80, tasks: 40, minutes: 2}}));
  const cli = async (...args) => {
    const completed = await execFile(process.execPath,
      [CLI, 'blackbox', ...args, '--project', root, '--json', '--non-interactive'],
      {cwd: root, env: {}, timeout: 90000});
    return {code: completed.code, data: JSON.parse(completed.stdout), stderr: completed.stderr};
  };
  const run = await cli(origin, '--no-model');
  assert.equal(run.code, 1, JSON.stringify(run.data));
  const surface = JSON.parse(fs.readFileSync(path.join(run.data.runDir, 'surface.json'), 'utf8'));
  const coverage = JSON.parse(fs.readFileSync(path.join(run.data.runDir, 'coverage.json'), 'utf8'));
  const report = JSON.parse(fs.readFileSync(path.join(run.data.runDir, 'report.json'), 'utf8'));
  const routes = surface.routeRecon.routes;
  assert.ok(routes.find(item => item.path === hidden &&
    item.sources.some(source => source.source === 'robots:disallow')));
  assert.ok(routes.find(item => item.path === `${hidden}/` && item.listing));
  assert.ok(routes.find(item => item.path === `${nested}/` && item.listing));
  assert.ok(routes.find(item => item.path === `${hidden}/notes.md` && item.status === null));
  assert.ok(routes.find(item => item.path === `${hidden}/download.url` && item.status === null));
  assert.ok(surface.mined.files.some(file => new URL(file.url).pathname === '/docs.js'));
  assert.ok(surface.mined.endpoints.some(item => item.path === '/api/read-only'));
  assert.ok(surface.exposures.some(item => item.path === archive && item.signature === 'KeePass KDBX header'));
  assert.ok(surface.exposures.some(item => item.path === sql && item.signature === 'SQL dump statements'));
  assert.ok(!surface.exposures.some(item => item.path === decoy || item.path === hidden));
  assert.equal(coverage.observedRoutes.routes, routes.length);
  assert.ok(report.surface.application.routeRecon.routes.some(item => item.path === archive));
  assert.ok(!calls.some(item => item.endsWith(skipped) || item.endsWith('/download.url')));
  assert.equal((await cli('verify', run.data.run)).code, 1);
  vulnerable = false;
  assert.equal((await cli('verify', run.data.run)).code, 0);
});
