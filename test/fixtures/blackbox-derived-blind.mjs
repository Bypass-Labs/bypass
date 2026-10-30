// Local process fixture: the CLI receives only its origin and discovers the rest.
import fs from 'node:fs';
import http from 'node:http';
import path from 'node:path';
import {randomBytes} from 'node:crypto';

const directory = path.resolve(process.argv[2] ?? '.');
fs.mkdirSync(directory, {recursive: true});
const modeFile = path.join(directory, 'mode');
if (process.argv[3]) {
  fs.writeFileSync(modeFile, process.argv[3]);
  process.exit(0);
}
if (!fs.existsSync(modeFile)) fs.writeFileSync(modeFile, 'vulnerable');
const suffix = randomBytes(5).toString('hex');
const loginPath = `/api/login-${suffix}`;
const privatePath = `/api/me-${suffix}`;
const secondPrivatePath = `/api/settings-${suffix}`;
const pagePath = `/workspace-${suffix}/home`;
const scriptPath = `/workspace-${suffix}/app.js`;
const hiddenPath = `/workspace-${suffix}/accounts`;
const privateDataPath = `/workspace-${suffix}/private-record`;
const issued = new Set();
const apiKeys = Array.from({length: 2}, () => `ak_${randomBytes(24).toString('hex')}`);
const mode = () => fs.readFileSync(modeFile, 'utf8').trim();
const json = (response, status, value) => {
  response.writeHead(status, {'content-type': 'application/json', 'cache-control': 'no-store'});
  response.end(JSON.stringify(value));
};
const server = http.createServer(async (request, response) => {
  const url = new URL(request.url, 'http://fixture.invalid');
  const bearer = String(request.headers.authorization ?? '').replace(/^Bearer /, '');
  const authenticated = issued.has(bearer);
  if (request.method === 'GET' && url.pathname === '/') {
    response.writeHead(200, {'content-type': 'text/html', 'cache-control': 'no-store'});
    return response.end('<html><a href="/openapi.json">API description</a></html>');
  }
  if (request.method === 'GET' && url.pathname === '/openapi.json') return json(response, 200, {
    openapi: '3.0.0', paths: {
      [loginPath]: {post: {summary: 'Login with username and password',
        requestBody: {content: {'application/json': {schema: {type: 'object',
          required: ['username', 'password'], properties: {
            username: {type: 'string'}, password: {type: 'string'}}}}}}}},
      [privatePath]: {get: {summary: 'Return the authenticated principal and workspace'}},
      [secondPrivatePath]: {get: {summary: 'Return protected account settings'}}}});
  if (request.method === 'POST' && url.pathname === loginPath) {
    const chunks = [];
    for await (const chunk of request) chunks.push(chunk);
    let input;
    try { input = JSON.parse(Buffer.concat(chunks).toString()); } catch { return json(response, 400, {error: 'invalid'}); }
    const tautology = /'\s+OR\s+(?:1\s*=\s*1|'1'\s*=\s*'1'?|2\s*=\s*2|'2'\s*=\s*'2'?)/i;
    if (mode() !== 'fixed' && tautology.test(String(input.username ?? '')) &&
        /^bx-invalid-[0-9a-f]{24}$/.test(String(input.password ?? ''))) {
      const token = `token-${randomBytes(24).toString('hex')}`;
      issued.add(token);
      return json(response, 200, {authentication: {token}});
    }
    return json(response, 401, {error: 'invalid credentials'});
  }
  if (request.method === 'GET' && url.pathname === privatePath)
    return authenticated ? json(response, 200, {workspace: pagePath}) :
      json(response, 401, {error: 'unauthorized'});
  if (request.method === 'GET' && url.pathname === secondPrivatePath)
    return authenticated ? json(response, 200, {user: {id: 'owner-fixture'}, workspace: pagePath}) :
      json(response, 401, {error: 'unauthorized'});
  if (request.method === 'GET' && url.pathname === pagePath) {
    if (!authenticated) return json(response, 401, {error: 'unauthorized'});
    response.writeHead(200, {'content-type': 'text/html', 'cache-control': 'no-store'});
    return response.end(`<html><script src="${scriptPath}"></script></html>`);
  }
  if (request.method === 'GET' && url.pathname === scriptPath) {
    if (!authenticated) return json(response, 401, {error: 'unauthorized'});
    response.writeHead(200, {'content-type': 'text/javascript', 'cache-control': 'no-store'});
    return response.end(`async function accounts(){return fetch('${hiddenPath}').then(r=>r.json())}` +
      `async function privateRecord(){return fetch('${privateDataPath}').then(r=>r.json())}`);
  }
  if (request.method === 'GET' && url.pathname === privateDataPath) {
    // Visibility metadata is public data here; it is not an access policy.
    return json(response, 200, {visibility: 'private', ownerId: 'owner-fixture',
      note: `public workspace note for ${suffix}`});
  }
  if (request.method === 'GET' && url.pathname === hiddenPath) {
    if (mode() !== 'vulnerable' && !authenticated)
      return json(response, 401, {error: 'unauthorized'});
    return json(response, 200, {accounts: [
      {id: 'acct-one', apiKey: apiKeys[0]}, {id: 'acct-two', apiKey: apiKeys[1]}]});
  }
  return json(response, 404, {error: 'not found'});
});
server.listen(0, '127.0.0.1', () => process.stdout.write(
  `http://127.0.0.1:${server.address().port}\n`));
