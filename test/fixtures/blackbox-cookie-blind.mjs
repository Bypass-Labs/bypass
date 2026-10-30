// Standalone local target for a blind real-Muse cookie-session audit.
// Start: node test/fixtures/blackbox-cookie-blind.mjs .tmp/cookie-blind
// Fix SSTI only: printf fixed-template > .tmp/cookie-blind/mode
// Fix login too: printf fixed > .tmp/cookie-blind/mode
import fs from 'node:fs';
import http from 'node:http';
import path from 'node:path';
import {randomBytes} from 'node:crypto';

const directory = path.resolve(process.argv[2] ?? '.tmp/cookie-blind');
fs.mkdirSync(directory, {recursive: true});
const modeFile = path.join(directory, 'mode');
if (!fs.existsSync(modeFile)) fs.writeFileSync(modeFile, 'vulnerable');
const mode = () => fs.readFileSync(modeFile, 'utf8').trim();
const suffixFile = path.join(directory, 'route-suffix');
const suffix = fs.existsSync(suffixFile) ? fs.readFileSync(suffixFile, 'utf8').trim() :
  randomBytes(5).toString('hex');
if (!/^[0-9a-f]{10}$/.test(suffix)) throw Error('Fixture route suffix is invalid');
fs.writeFileSync(suffixFile, suffix);
const loginPath = `/api/signin-${suffix}`;
const identityPath = `/api/me-${suffix}`;
const pagePath = `/member-${suffix}/home`;
const scriptPath = `/member-${suffix}/app.js`;
const dataPath = `/api/member-${suffix}/data`;
const renderPath = `/api/member-${suffix}/render`;
const safePath = `/api/member-${suffix}/safe`;
const issued = new Set();
const json = (response, status, value, headers = {}) => {
  response.writeHead(status, {'content-type': 'application/json',
    'cache-control': 'no-store', ...headers});
  response.end(JSON.stringify(value));
};
const authenticated = request => String(request.headers.cookie ?? '').split('; ')
  .some(pair => issued.has(pair));
const tautology = /'\s+OR\s+(?:1\s*=\s*1|'1'\s*=\s*'1'?|2\s*=\s*2|'2'\s*=\s*'2'?)/i;

const server = http.createServer(async (request, response) => {
  const url = new URL(request.url, 'http://fixture.invalid');
  if (request.method === 'GET' && url.pathname === '/') {
    response.writeHead(200, {'content-type': 'text/html', 'cache-control': 'no-store'});
    return response.end('<html><a href="/openapi.json">API description</a></html>');
  }
  if (request.method === 'GET' && url.pathname === '/openapi.json') return json(response, 200, {
    openapi: '3.0.0', paths: {
      [loginPath]: {post: {summary: 'Sign in with username and password',
        requestBody: {content: {'application/json': {schema: {type: 'object',
          required: ['username', 'password'], properties: {
            username: {type: 'string'}, password: {type: 'string'}}}}}}}},
      [identityPath]: {get: {summary: 'Return the current member workspace'}},
    }});
  if (request.method === 'POST' && url.pathname === loginPath) {
    const chunks = [];
    for await (const chunk of request) chunks.push(chunk);
    let body;
    try {body = JSON.parse(Buffer.concat(chunks).toString());}
    catch {return json(response, 400, {error: 'invalid JSON'});}
    if (mode() !== 'fixed' && tautology.test(String(body.username ?? '')) &&
        /^bx-invalid-[0-9a-f]{24}$/.test(String(body.password ?? ''))) {
      const session = `bx_session=${randomBytes(24).toString('hex')}`;
      issued.add(session);
      return json(response, 200, {ok: true},
        {'set-cookie': `${session}; HttpOnly; SameSite=Lax; Path=/`});
    }
    return json(response, 401, {error: 'invalid credentials'});
  }
  if (request.method === 'GET' && url.pathname === identityPath)
    return authenticated(request) ? json(response, 200, {workspace: pagePath}) :
      json(response, 401, {error: 'login required'});
  if (request.method === 'GET' && url.pathname === pagePath) {
    if (!authenticated(request)) return json(response, 401, {error: 'login required'});
    response.writeHead(200, {'content-type': 'text/html', 'cache-control': 'no-store'});
    return response.end(`<html><script src="${scriptPath}"></script></html>`);
  }
  if (request.method === 'GET' && url.pathname === scriptPath) {
    if (!authenticated(request)) return json(response, 401, {error: 'login required'});
    response.writeHead(200, {'content-type': 'application/javascript', 'cache-control': 'no-store'});
    return response.end(`fetch('${dataPath}');fetch('${safePath}');` +
      `fetch('${renderPath}?q=hello');`);
  }
  if (request.method === 'GET' && url.pathname === dataPath)
    return authenticated(request) ? json(response, 200, {member: true}) :
      json(response, 401, {error: 'login required'});
  if (request.method === 'GET' && url.pathname === renderPath) {
    if (!authenticated(request)) return json(response, 401, {error: 'login required'});
    const input = url.searchParams.get('q') ?? '';
    const expression = /^\{\{(\d{4})\*(\d{4})\}\}$/.exec(input);
    response.writeHead(200, {'content-type': 'text/plain', 'cache-control': 'no-store'});
    return response.end(mode() === 'vulnerable' && expression ?
      String(Number(expression[1]) * Number(expression[2])) : input);
  }
  if (request.method === 'GET' && url.pathname === safePath)
    return authenticated(request) ? json(response, 200, {safe: true}) :
      json(response, 401, {error: 'login required'});
  return json(response, 404, {error: 'not found'});
});

server.listen(0, '127.0.0.1', () => {
  const origin = `http://127.0.0.1:${server.address().port}`;
  fs.writeFileSync(path.join(directory, 'blackbox.scope.json'), JSON.stringify({
    schemaVersion: 1, target: {origin}, include: ['/'],
    limits: {rps: 20, maxUrls: 80, minutes: 5, modelCalls: 60, tasks: 100},
  }));
  fs.writeFileSync(path.join(directory, 'routes.json'), JSON.stringify({
    loginPath, identityPath, pagePath, scriptPath, dataPath, renderPath, safePath}, null, 2));
  process.stdout.write(`${origin}\n`);
});
process.on('SIGTERM', () => server.close());
