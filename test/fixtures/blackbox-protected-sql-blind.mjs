// Local black-box fixture. The audit receives only the origin and reviewed scope.
import fs from 'node:fs';
import http from 'node:http';
import path from 'node:path';
import {randomBytes} from 'node:crypto';
import {DatabaseSync} from 'node:sqlite';

const directory = path.resolve(process.argv[2] ?? '.');
fs.mkdirSync(directory, {recursive: true});
const modeFile = path.join(directory, 'mode');
if (process.argv[3]) {
  fs.writeFileSync(modeFile, process.argv[3]);
  process.exit(0);
}
if (!fs.existsSync(modeFile)) fs.writeFileSync(modeFile, 'vulnerable');
const mode = () => fs.readFileSync(modeFile, 'utf8').trim();
const suffixFile = path.join(directory, 'route-suffix');
const suffix = process.env.BX_FIXTURE_SUFFIX ??
  (fs.existsSync(suffixFile) ? fs.readFileSync(suffixFile, 'utf8').trim() :
    randomBytes(5).toString('hex'));
if (!/^[0-9a-f]{10}$/.test(suffix)) throw new Error('Invalid fixture route suffix');
fs.writeFileSync(suffixFile, suffix);
const port = Number(process.env.BX_FIXTURE_PORT ?? 0);
if (!Number.isInteger(port) || port < 0 || port > 65535)
  throw new Error('Invalid fixture port');
const loginPath = `/api/login-${suffix}`;
const identityPath = `/api/me-${suffix}`;
const pagePath = `/workspace-${suffix}/home`;
const scriptPath = `/workspace-${suffix}/app.js`;
const lookupPath = `/api/${suffix}/item`;
const renderPath = `/api/${suffix}/render`;
const protectedDecoyPath = `/api/${suffix}/safe-item`;
const publicDecoyPath = `/api/${suffix}/public-item`;
const decoyCount = Number(process.env.BX_FIXTURE_DECOYS ?? 0);
if (!Number.isInteger(decoyCount) || decoyCount < 0) throw new Error('Invalid fixture decoy count');
const protectedDecoyPaths = Array.from({length: decoyCount}, (_, index) =>
  `/api/${suffix}/decoy-${index + 1}`);
const issued = new Set();
const db = new DatabaseSync(':memory:');
db.exec("CREATE TABLE items (id INTEGER PRIMARY KEY, name TEXT); INSERT INTO items VALUES (1,'apple'),(2,'banana'),(3,'pear')");
const json = (res, status, value) => {
  res.writeHead(status, {'content-type': 'application/json', 'cache-control': 'no-store'});
  res.end(JSON.stringify(value));
};
const escapeHtml = value => String(value).replace(/[&<>"']/g, character => ({
  '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;',
})[character]);
const denied = (res, authenticated) => {
  if (authenticated) return false;
  json(res, 401, {error: 'authentication required'});
  return true;
};
const server = http.createServer(async (req, res) => {
  const url = new URL(req.url, 'http://fixture.invalid');
  const bearer = String(req.headers.authorization ?? '').replace(/^Bearer /, '');
  const authenticated = issued.has(bearer);
  if (req.method === 'GET' && url.pathname === '/') {
    res.writeHead(200, {'content-type': 'text/html', 'cache-control': 'no-store'});
    return res.end('<html><a href="/openapi.json">API description</a></html>');
  }
  if (req.method === 'GET' && url.pathname === '/openapi.json') return json(res, 200, {
    openapi: '3.0.0', paths: {
      [loginPath]: {post: {summary: 'Login with username and password',
        requestBody: {content: {'application/json': {schema: {type: 'object',
          required: ['username', 'password'], properties: {
            username: {type: 'string'}, password: {type: 'string'}}}}}}}},
      [identityPath]: {get: {summary: 'Return the authenticated workspace route'}}}});
  if (req.method === 'POST' && url.pathname === loginPath) {
    const chunks = [];
    for await (const chunk of req) chunks.push(chunk);
    let body;
    try { body = JSON.parse(Buffer.concat(chunks).toString()); }
    catch { return json(res, 400, {error: 'invalid JSON'}); }
    const tautology = /'\s+OR\s+(?:1\s*=\s*1|'1'\s*=\s*'1'?|2\s*=\s*2|'2'\s*=\s*'2'?)/i;
    if (mode() !== 'fixed' && tautology.test(String(body.username ?? '')) &&
        /^bx-invalid-[0-9a-f]{24}$/.test(String(body.password ?? ''))) {
      const token = `token-${randomBytes(24).toString('hex')}`;
      issued.add(token);
      return json(res, 200, {authentication: {token}});
    }
    return json(res, 401, {error: 'invalid credentials'});
  }
  if (req.method === 'GET' && url.pathname === identityPath)
    return authenticated ? json(res, 200, {workspace: pagePath}) :
      json(res, 401, {error: 'authentication required'});
  if (req.method === 'GET' && url.pathname === pagePath) {
    if (denied(res, authenticated)) return;
    res.writeHead(200, {'content-type': 'text/html', 'cache-control': 'no-store'});
    return res.end(`<html><script src="${scriptPath}"></script></html>`);
  }
  if (req.method === 'GET' && url.pathname === scriptPath) {
    if (denied(res, authenticated)) return;
    res.writeHead(200, {'content-type': 'text/javascript', 'cache-control': 'no-store'});
    return res.end(`async function item(){return fetch('${lookupPath}?q=1').then(r=>r.json())}` +
      `async function render(){return fetch('${renderPath}?q=hello').then(r=>r.text())}` +
      `async function safeItem(){return fetch('${protectedDecoyPath}?q=1').then(r=>r.json())}` +
      `async function publicItem(){return fetch('${publicDecoyPath}?q=1').then(r=>r.json())}` +
      protectedDecoyPaths.map((route, index) =>
        `async function decoy${index + 1}(){return fetch('${route}?q=1').then(r=>r.json())}`).join(''));
  }
  if (req.method === 'GET' && url.pathname === renderPath) {
    if (denied(res, authenticated)) return;
    const value = url.searchParams.get('q') ?? '';
    const expression = /^\{\{(\d{4})\*(\d{4})\}\}$/.exec(value);
    const encoded = process.env.BX_FIXTURE_HEX === '1' ?
      /^hex:((?:[0-9a-f]{2}){1,256})$/i.exec(value) : null;
    const currentMode = mode();
    const output = currentMode === 'vulnerable' && encoded ?
      Buffer.from(encoded[1], 'hex').toString('utf8') :
      currentMode === 'vulnerable' && expression ?
        String(Number(expression[1]) * Number(expression[2])) : value;
    res.writeHead(200, {'content-type': 'text/html', 'cache-control': 'no-store'});
    return res.end(`<html><body>${['fixed', 'fixed-html'].includes(currentMode) ?
      escapeHtml(output) : output}</body></html>`);
  }
  if (req.method === 'GET' && url.pathname === lookupPath) {
    if (denied(res, authenticated)) return;
    const lookup = url.searchParams.get('q') ?? '';
    try {
      const row = mode() === 'vulnerable' ?
        db.prepare(`SELECT id,name FROM items WHERE id=${lookup}`).get() :
        db.prepare('SELECT id,name FROM items WHERE id=?').get(lookup);
      return row ? json(res, 200, row) : json(res, 404, {error: 'not found'});
    } catch { return json(res, 400, {error: 'invalid lookup'}); }
  }
  if (req.method === 'GET' && url.pathname === protectedDecoyPath) {
    if (denied(res, authenticated)) return;
    const lookup = url.searchParams.get('q') ?? '';
    const row = /^\d{1,4}$/.test(lookup) ?
      db.prepare('SELECT id,name FROM items WHERE id=?').get(Number(lookup)) : null;
    return row ? json(res, 200, row) : json(res, 404, {error: 'not found'});
  }
  const protectedDecoyIndex = protectedDecoyPaths.indexOf(url.pathname);
  if (req.method === 'GET' && protectedDecoyIndex >= 0) {
    if (denied(res, authenticated)) return;
    return url.searchParams.get('q') === '1' ?
      json(res, 200, {id: protectedDecoyIndex + 1, name: 'decoy'}) :
      json(res, 404, {error: 'not found'});
  }
  if (req.method === 'GET' && url.pathname === publicDecoyPath) {
    const lookup = url.searchParams.get('q') ?? '';
    const row = /^\d{1,4}$/.test(lookup) ?
      db.prepare('SELECT id,name FROM items WHERE id=?').get(Number(lookup)) : null;
    return row ? json(res, 200, row) : json(res, 404, {error: 'not found'});
  }
  return json(res, 404, {error: 'not found'});
});
server.listen(port, '127.0.0.1', () => {
  const origin = `http://127.0.0.1:${server.address().port}`;
  fs.writeFileSync(path.join(directory, 'blackbox.scope.json'), JSON.stringify({
    schemaVersion: 1, target: {origin}, include: ['/'],
    limits: {rps: 15, maxUrls: 80, minutes: 5, modelCalls: 45, tasks: 100},
  }));
  process.stdout.write(`${origin}\n`);
});
process.on('SIGTERM', () => { server.close(); db.close(); });
