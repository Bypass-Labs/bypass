import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import http from 'node:http';
import {DatabaseSync} from 'node:sqlite';
import {temp} from './helpers.mjs';
import {runAudit} from '../src/blackbox/index.mjs';

test('a three-call audit reads a cited denied route and proves its identity header', async t => {
  const root = temp();
  t.after(() => fs.rmSync(root, {recursive: true, force: true}));
  fs.writeFileSync(`${root}/server.js`,
    "function principal(req) {\n  const claimed = req.headers['x-actor-id'];\n" +
    "  return claimed ? {id: claimed} : null;\n}\n" +
    "app.get('/api/private', (req, res) => {\n" +
    "  const user = principal(req);\n" +
    "  if (!user) return res.status(401).json({error: 'denied'});\n" +
    "  res.json({id: user.id, private: true});\n});\n");
  const server = http.createServer((request, response) => {
    const opened = request.url === '/api/private' &&
      request.headers['x-actor-id'] === '1';
    response.writeHead(opened ? 200 : request.url === '/api/private' ? 401 : 404,
      {'content-type': 'application/json', 'cache-control': 'no-store'});
    response.end(JSON.stringify(opened ? {id: 1, private: true} : {error: 'denied'}));
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  t.after(() => new Promise(resolve => server.close(resolve)));
  const origin = `http://127.0.0.1:${server.address().port}`;
  const modelStages = [];
  const audit = await runAudit({url: origin, root, sourcePath: root,
    env: {META_API_KEY: 'test-only-placeholder'}, noDiscovery: true, offline: true,
    overrides: {acceptLocal: true, minutes: 1, modelCalls: 3,
      maxUrls: 5, maxTasks: 5, rps: 20},
    infer: async (_profile, messages, {schema,onProgress}) => {
      const system = messages[0].content;
      modelStages.push(system);
      onProgress?.({kind: 'usage', inputTokens: 10, outputTokens: 2, totalTokens: 12});
      if (system.startsWith('Interpret these redacted source route excerpts'))
        return {notes: [], paths: [], securityLeads: [{title: 'Header identity trust',
          category: 'authentication-trust', path: '/api/private', method: 'GET',
          hypothesis: 'A caller may claim an actor ID.',
          remediation: 'Use a verified session.', fields: ['x-actor-id'],
          file: 'server.js', line: 1,
          quote: 'return claimed ? {id: claimed} : null;'}]};
      return empty(schema);
    }});
  assert.ok(modelStages.some(stage => stage.startsWith(
    'Interpret these redacted source route excerpts')));
  const header = audit.findings.find(item => item.sourceFinding?.hypothesis ===
    'A caller may claim an actor ID.');
  assert.equal(header?.verdict, 'confirmed', JSON.stringify(audit.findings));
  assert.equal(header?.foundBy, 'source-guided-http-proof');
  assert.ok(audit.stats.modelCalls <= 3);
  assert.equal(audit.stats.modelUsage.reportedCalls, audit.stats.modelCalls);
  assert.equal(audit.stats.modelUsage.totalTokens, audit.stats.modelCalls * 12);
  assert.match(fs.readFileSync(`${audit.runDir}/report.md`, 'utf8'),
    new RegExp(`Model tokens.*${audit.stats.modelCalls * 12} total`));
});

test('a short source-guided audit derives a SQL control from public search results', async t => {
  const root = temp();
  t.after(() => fs.rmSync(root, {recursive: true, force: true}));
  fs.writeFileSync(`${root}/server.js`,
    "app.get('/api/search', (req, res) => {\n" +
    "  const term = req.query.q || '';\n" +
    "  const rows = db.prepare(`SELECT id, signal FROM events WHERE signal LIKE '%${term}%'`).all();\n" +
    "  res.json({items: rows});\n});\n");
  const db = new DatabaseSync(':memory:');
  t.after(() => db.close());
  db.exec('CREATE TABLE events (id INTEGER PRIMARY KEY, signal TEXT)');
  db.prepare('INSERT INTO events (signal) VALUES (?)').run('Telemetry uplink stable');
  db.prepare('INSERT INTO events (signal) VALUES (?)').run('Asteroid scan complete');
  const server = http.createServer((request, response) => {
    const url = new URL(request.url, 'http://fixture');
    if (url.pathname === '/') {
      response.writeHead(200, {'content-type': 'text/html'});
      return response.end('<script src="/app.js"></script>');
    }
    if (url.pathname === '/app.js') {
      response.writeHead(200, {'content-type': 'application/javascript'});
      return response.end("fetch('/api/search?q=test')");
    }
    let status = 200, body;
    try {
      const term = url.searchParams.get('q') ?? '';
      body = url.pathname === '/api/search' ?
        {items: db.prepare(`SELECT id, signal FROM events WHERE signal LIKE '%${term}%'`).all()} :
        {error: 'Not found'};
      if (url.pathname !== '/api/search') status = 404;
    } catch { status = 400; body = {error: 'Invalid query'}; }
    response.writeHead(status, {'content-type': 'application/json', 'cache-control': 'no-store'});
    response.end(JSON.stringify(body));
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  t.after(() => new Promise(resolve => server.close(resolve)));
  const audit = await runAudit({url: `http://127.0.0.1:${server.address().port}`,
    root, sourcePath: root, env: {META_API_KEY: 'test-only-placeholder'},
    noDiscovery: true, offline: true,
    overrides: {acceptLocal: true, minutes: 1, modelCalls: 3,
      maxUrls: 5, maxTasks: 8, rps: 20},
    infer: async (_profile, messages, {schema}) =>
      messages[0].content.startsWith('Interpret these redacted source route excerpts') ?
        {notes: [], paths: [], securityLeads: [{title: 'Unbound search query',
          category: 'injection', path: '/api/search', method: 'GET',
          hypothesis: 'The q search term changes SQL syntax.',
          remediation: 'Bind the query parameter.', fields: ['q'],
          file: 'server.js', line: 3,
          quote: "const rows = db.prepare(`SELECT id, signal FROM events WHERE signal LIKE '%${term}%'`).all();"}]} :
        empty(schema)});
  const surface = JSON.parse(fs.readFileSync(`${audit.runDir}/surface.json`, 'utf8'));
  assert.equal(surface.patterns.find(item => item.pattern === '/api/search')?.params?.q?.[0],
    'Telemetry');
  assert.ok(audit.findings.some(item => item.kind === 'sql-boolean' &&
    item.verdict === 'confirmed'), JSON.stringify(audit.findings));
  assert.ok(audit.stats.modelCalls <= 3);
});

function empty(schema) {
  if (schema?.anyOf) return empty(schema.anyOf[0]);
  const type = Array.isArray(schema?.type) ? schema.type[0] : schema?.type;
  if (type === 'array') return [];
  if (type === 'object') return Object.fromEntries((schema.required ?? [])
    .map(key => [key, empty(schema.properties?.[key])]));
  if (type === 'integer' || type === 'number') return schema.minimum ?? 0;
  if (type === 'boolean') return false;
  return '';
}

test('a fresh standalone blackbox run selects Meta API by default', async t => {
  const root = temp();
  t.after(() => fs.rmSync(root, {recursive: true, force: true}));
  const server = http.createServer((request, response) => {
    if (request.url === '/app.js') {
      response.writeHead(200, {'content-type': 'application/javascript'});
      return response.end("fetch('/api/public?x=1')");
    }
    if (request.url?.startsWith('/api/public')) {
      response.writeHead(200, {'content-type': 'application/json'});
      return response.end('{"items":[]}');
    }
    response.writeHead(200, {'content-type': 'text/html'});
    response.end('<html><script src="/app.js"></script></html>');
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  t.after(() => new Promise(resolve => server.close(resolve)));
  const profiles = [];
  const first = await runAudit({url: `http://127.0.0.1:${server.address().port}`, root,
    env: {META_API_KEY: 'test-only-placeholder'},
    overrides: {acceptLocal: true, minutes: 1, modelCalls: 3, maxUrls: 5, maxTasks: 5},
    infer: async (profile, _messages, options) => {
      profiles.push(profile);
      return empty(options.schema);
    }});
  assert.ok(profiles.length > 0);
  assert.ok(profiles.every(profile => profile.provider === 'meta' &&
    profile.secretEnv === 'META_API_KEY' && profile.model === 'muse-spark-1.3'));
  assert.equal(first.stats.modelUsage.reportedCalls, 0);
  assert.equal(first.stats.modelUsage.callsWithoutUsage, first.stats.modelCalls);
  assert.match(fs.readFileSync(`${first.runDir}/report.md`, 'utf8'),
    /Model tokens.*unavailable/);

  const genericProfiles = [];
  await runAudit({url: `http://127.0.0.1:${server.address().port}`, root,
    env: {LLM_KEY: 'test-only-placeholder'},
    overrides: {acceptLocal: true, minutes: 1, modelCalls: 3, maxUrls: 5, maxTasks: 5},
    infer: async (profile, _messages, options) => {
      genericProfiles.push(profile);
      return empty(options.schema);
    }});
  assert.ok(genericProfiles.length > 0);
  assert.ok(genericProfiles.every(profile => profile.provider === 'meta' &&
    profile.secretEnv === 'LLM_KEY'));
});
