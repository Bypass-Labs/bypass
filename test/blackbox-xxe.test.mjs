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

const SAX = [
  'import io, sys, xml.sax',
  'from xml.sax.handler import ContentHandler, feature_external_ges',
  'class Capture(ContentHandler):',
  '    def __init__(self): self.parts = []',
  '    def characters(self, value): self.parts.append(value)',
  'parser = xml.sax.make_parser()',
  "parser.setFeature(feature_external_ges, sys.argv[1] == '1')",
  'capture = Capture()',
  'parser.setContentHandler(capture)',
  'try: parser.parse(io.StringIO(sys.stdin.read()))',
  'except Exception: sys.exit(2)',
  "sys.stdout.write(''.join(capture.parts))",
].join('\n');

test('real CLI proves XML external-entity file disclosure and its regression clears after disabling entities', async t => {
  if (spawnSync('python3', ['--version']).status !== 0) {
    t.skip('Python XML SAX is needed for the parser fixture'); return;
  }
  const root = temp();
  t.after(() => fs.rmSync(root, {recursive: true, force: true}));
  const suffix = randomBytes(5).toString('hex');
  const route = `/api/${suffix}/xml/parse`;
  const decoy = `/api/${suffix}/xml/decoy`;
  const requested = [];
  let vulnerable = true, rejectDtd = false;
  const server = http.createServer((request, response) => {
    const url = new URL(request.url, 'http://local');
    requested.push(url.pathname);
    if (url.pathname === '/') {
      response.writeHead(200, {'content-type': 'text/html'});
      return response.end('<html><body>XML test</body></html>');
    }
    if (url.pathname === '/openapi.json') {
      response.writeHead(200, {'content-type': 'application/json'});
      return response.end(JSON.stringify({openapi: '3.0.0', paths: {
        [route]: {get: {parameters: [{name: 'document', in: 'query'}]}},
        [decoy]: {get: {parameters: [{name: 'document', in: 'query'}]}},
        '/api/delete': {get: {}},
      }}));
    }
    if (url.pathname === route) {
      const xml = url.searchParams.get('document') ?? '';
      if (rejectDtd && xml.includes('<!DOCTYPE')) {
        response.writeHead(400, {'content-type': 'text/plain', 'cache-control': 'no-store'});
        return response.end('DTD disabled');
      }
      const parsed = spawnSync('python3', ['-c', SAX, vulnerable ? '1' : '0'],
        {input: xml, encoding: 'utf8', timeout: 3000, maxBuffer: 16384});
      response.writeHead(parsed.status === 0 ? 200 : 400,
        {'content-type': 'text/plain', 'cache-control': 'no-store'});
      return response.end(parsed.status === 0 ? parsed.stdout : 'Invalid XML');
    }
    if (url.pathname === decoy) {
      response.writeHead(200, {'content-type': 'text/plain', 'cache-control': 'no-store'});
      return response.end('127.0.0.1 localhost\nstatic banner');
    }
    if (url.pathname === '/api/delete') {
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
  const audit = await cli(origin, '--accept-local', '--no-model');
  assert.equal(audit.code, 1, JSON.stringify(audit.data.findings));
  const finding = audit.data.findings.find(item => item.kind === 'xxe-hosts');
  assert.equal(finding?.pattern, route, JSON.stringify(audit.data.findings));
  assert.ok(fs.existsSync(finding.proof));
  assert.equal(audit.data.coverage.requestedClasses.find(item =>
    item.name === 'XML External Entity Injection (XXE)').status, 'partial');
  const web = JSON.parse(fs.readFileSync(path.join(audit.data.runDir, 'web-probes.json'), 'utf8'));
  assert.ok(web.results.some(item => item.kind === 'xxe-hosts' && item.lead.path === decoy &&
    item.verdict !== 'confirmed'));
  assert.ok(!requested.includes('/api/delete'));
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
  rejectDtd = true;
  assert.equal((await cli('verify', audit.data.run)).code, 0,
    'rejecting DTDs entirely is also a valid fix');
  assert.equal(await runExport(), 0);
  const fixed = await cli(origin, '--accept-local', '--no-model');
  assert.ok(!fixed.data.findings.some(item => item.kind === 'xxe-hosts'));
  assert.ok(!requested.includes('/api/delete'));
});

test('real CLI proves a documented XML POST route and never sends a body outside scope', async t => {
  if (spawnSync('python3', ['--version']).status !== 0) {
    t.skip('Python XML SAX is needed for the parser fixture'); return;
  }
  const root = temp();
  t.after(() => fs.rmSync(root, {recursive: true, force: true}));
  const suffix = randomBytes(5).toString('hex');
  const route = `/api/${suffix}/xml/import`;
  const decoy = `/outside/${suffix}/xml/other`;
  const requested = [];
  let vulnerable = true, rejectDtd = false;
  const server = http.createServer(async (request, response) => {
    const url = new URL(request.url, 'http://local');
    requested.push(`${request.method} ${url.pathname}`);
    if (url.pathname === '/') {
      response.writeHead(200, {'content-type': 'text/html'});
      return response.end('<html><body>XML import test</body></html>');
    }
    if (url.pathname === '/openapi.json') {
      response.writeHead(200, {'content-type': 'application/json'});
      return response.end(JSON.stringify({openapi: '3.0.0', paths: {
        [route]: {post: {requestBody: {content: {'application/xml': {schema: {type: 'string'}}}}}},
        [decoy]: {post: {requestBody: {content: {'application/xml': {schema: {type: 'string'}}}}}},
        '/outside/delete': {post: {requestBody: {content: {'application/xml': {schema: {type: 'string'}}}}}},
      }}));
    }
    if (url.pathname === route && request.method === 'POST') {
      let xml = '';
      for await (const chunk of request) xml += chunk;
      if (rejectDtd && xml.includes('<!DOCTYPE')) {
        response.writeHead(400, {'content-type': 'text/plain', 'cache-control': 'no-store'});
        return response.end('DTD disabled');
      }
      const parsed = spawnSync('python3', ['-c', SAX, vulnerable ? '1' : '0'],
        {input: xml, encoding: 'utf8', timeout: 3000, maxBuffer: 16384});
      response.writeHead(parsed.status === 0 ? 200 : 400,
        {'content-type': 'text/plain', 'cache-control': 'no-store'});
      return response.end(parsed.status === 0 ? parsed.stdout : 'Invalid XML');
    }
    response.writeHead(url.pathname === route ? 405 : 404);
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
  const prepared = await cli('scope', origin, '--include', '/api');
  assert.equal(prepared.code, 0);
  const scope = JSON.parse(fs.readFileSync(prepared.data.file, 'utf8'));
  scope.probes.xmlPostPaths = [route];
  fs.writeFileSync(prepared.data.file, JSON.stringify(scope));
  const audit = await cli(origin, '--accept-local', '--no-model');
  assert.equal(audit.code, 1, JSON.stringify(audit.data.findings));
  const finding = audit.data.findings.find(item => item.kind === 'xxe-body-hosts');
  assert.equal(finding?.pattern, route, JSON.stringify(audit.data.findings));
  assert.ok(fs.existsSync(finding.proof));
  assert.equal(audit.data.coverage.requestedClasses.find(item =>
    item.name === 'XML External Entity Injection (XXE)').status, 'partial');
  const surface = JSON.parse(fs.readFileSync(path.join(audit.data.runDir, 'surface.json'), 'utf8'));
  assert.ok(surface.xmlBodyOperations.some(item => item.path === route && item.method === 'POST'));
  const web = JSON.parse(fs.readFileSync(path.join(audit.data.runDir, 'web-probes.json'), 'utf8'));
  assert.ok(web.plan.some(item => item.kind === 'xxe-body-hosts' && item.path === route));
  assert.ok(!web.plan.some(item => item.kind === 'xxe-body-hosts' && item.path === decoy));
  const ledger = fs.readFileSync(path.join(audit.data.runDir, 'evidence.jsonl'), 'utf8');
  assert.ok(!ledger.includes('<!DOCTYPE') && !ledger.includes('file:///etc/hosts'),
    'XML request bodies stay out of the evidence ledger');
  assert.ok(requested.some(item => item === `POST ${route}`));
  assert.ok(!requested.some(item => item === `POST ${decoy}` || item === 'POST /outside/delete'));
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
  rejectDtd = true;
  assert.equal((await cli('verify', audit.data.run)).code, 0);
  const fixed = await cli(origin, '--accept-local', '--no-model');
  assert.ok(!fixed.data.findings.some(item => item.kind === 'xxe-body-hosts'));
  assert.ok(!requested.some(item => item === `POST ${decoy}` || item === 'POST /api/delete'));
});
