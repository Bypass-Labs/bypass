#!/usr/bin/env node
// A randomized, local-only POST search fixture for blind black-box evaluation.
import http from 'node:http';
import fs from 'node:fs';
import {randomBytes} from 'node:crypto';
import {DatabaseSync} from 'node:sqlite';

const args = process.argv.slice(2);
const option = name => args.includes(name) ? args[args.indexOf(name) + 1] : null;
const port = Number(option('--port') ?? 0);
const suffix = option('--id') ?? randomBytes(4).toString('hex');
const fixed = args.includes('--fixed');
const scopeFile = option('--scope') ?? `/tmp/bypass-blind-post-${suffix}.scope.json`;
const authFile = option('--auth-file') ?? `/tmp/bypass-blind-post-${suffix}.owner`;
const decoyFile = option('--decoy-file') ?? `/tmp/bypass-blind-post-${suffix}.decoy`;
if (!Number.isInteger(port) || port < 0 || port > 65535 || !/^[a-f0-9]{8}$/.test(suffix)) {
  process.stderr.write('Usage: node scripts/blackbox-blind-post-fixture.mjs [--port 0] [--id 8-hex-chars] [--fixed] [--scope path]\n');
  process.exit(2);
}

const searchPath = `/api/catalog-${suffix}/filter`;
const privateId = `prv-${suffix}`;
const privatePath = `/api/catalog-${suffix}/records/${privateId}`;
const decoy = `/api/catalog-${suffix}/admin-delete`;
const ownerToken = fs.existsSync(authFile) ? fs.readFileSync(authFile, 'utf8').trim() :
  randomBytes(24).toString('hex');
if (!fs.existsSync(authFile)) fs.writeFileSync(authFile, `${ownerToken}\n`, {mode: 0o600});
const db = new DatabaseSync(':memory:');
db.exec('CREATE TABLE records (id TEXT PRIMARY KEY, title TEXT, visibility TEXT)');
db.prepare('INSERT INTO records VALUES (?, ?, ?)').run(`pub-${suffix}-1`, 'apple', 'public');
db.prepare('INSERT INTO records VALUES (?, ?, ?)').run(`pub-${suffix}-2`, 'pear', 'public');
db.prepare('INSERT INTO records VALUES (?, ?, ?)').run(privateId,
  `internal-${suffix}`, 'private');
const send = (response, status, data, type = 'application/json') => {
  response.writeHead(status, {'content-type': type, 'cache-control': 'no-store'});
  response.end(type === 'application/json' ? JSON.stringify(data) : data);
};
let decoyHits = 0;
fs.writeFileSync(decoyFile, '0\n', {mode: 0o600});

const server = http.createServer(async (request, response) => {
  const url = new URL(request.url, 'http://127.0.0.1');
  if (request.method === 'GET' && url.pathname === '/')
    return send(response, 200, `<html><title>Public catalog</title><h1>Catalog search</h1><p>Search public records by title. Private records require an owner session.</p><script src="/app.js"></script></html>`, 'text/html');
  if (request.method === 'GET' && url.pathname === '/app.js')
    return send(response, 200, `export async function filter(term){return fetch('${searchPath}',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({term})})}`, 'application/javascript');
  if (request.method === 'GET' && url.pathname === '/openapi.json')
    return send(response, 200, {openapi: '3.0.0', info: {title: 'Public catalog', version: '1.0'}, paths: {
      [searchPath]: {post: {summary: 'Search public catalog by title. Private records must never appear.',
        requestBody: {required: true, content: {'application/json': {schema: {type: 'object',
          required: ['term'], properties: {term: {type: 'string', example: 'apple'}}}}}},
        responses: {'200': {description: 'Public records only'}}}},
      [`/api/catalog-${suffix}/records/{recordId}`]: {get: {
        summary: 'Get a record by ID; private records require an owner session.',
        parameters: [{name: 'recordId', in: 'path', required: true, schema: {type: 'string'}}],
        responses: {'200': {description: 'Authorized record'}, '403': {description: 'Forbidden'}}}},
    }});
  if (url.pathname === decoy) {
    decoyHits++;
    fs.writeFileSync(decoyFile, `${decoyHits}\n`, {mode: 0o600});
    return send(response, 403, {error: 'forbidden', decoyHits});
  }
  if (request.method === 'GET' && url.pathname === privatePath) {
    if (request.headers.authorization !== `Bearer ${ownerToken}`)
      return send(response, 403, {error: 'owner session required'});
    return send(response, 200, db.prepare('SELECT id, title FROM records WHERE id = ?').get(privateId));
  }
  if (request.method === 'POST' && url.pathname === searchPath) {
    const chunks = [];
    for await (const chunk of request) {
      chunks.push(chunk);
      if (Buffer.concat(chunks).length > 4096) return send(response, 413, {error: 'too large'});
    }
    let term;
    try {term = JSON.parse(Buffer.concat(chunks).toString()).term;}
    catch {return send(response, 400, {error: 'invalid JSON'});}
    if (typeof term !== 'string' || term.length > 256) return send(response, 400, {error: 'invalid term'});
    let rows;
    try {
      rows = fixed ? db.prepare("SELECT id, title FROM records WHERE visibility='public' AND title LIKE ?")
        .all(`%${term}%`) : db.prepare(`SELECT id, title FROM records WHERE visibility='public' AND title LIKE '%${term}%'`)
        .all();
    } catch {return send(response, 400, {error: 'invalid filter'});}
    return send(response, 200, {count: rows.length, records: rows});
  }
  send(response, 404, {error: 'not found'});
});

server.listen(port, '127.0.0.1', () => {
  const origin = `http://127.0.0.1:${server.address().port}`;
  fs.writeFileSync(scopeFile, `${JSON.stringify({schemaVersion: 1, target: {origin},
    include: ['/'], identities: {owner: {env: 'OWNER_TOKEN', role: 'member'},
      outsider: {env: 'OTHER_TOKEN', role: 'member'}, auth: 'bearer',
      identityPath: privatePath},
    probes: {jsonPostPaths: [searchPath]},
    limits: {rps: 20, minutes: 4, modelCalls: 40, maxUrls: 40}}, null, 2)}\n`, {mode: 0o600});
  process.stdout.write(`${JSON.stringify({origin, searchPath, privatePath, decoy,
    privateId, scopeFile, authFile, decoyFile, fixed})}\n`);
});
