// Randomized disposable record for a real, issue-blind Muse blackbox audit.
// Start: node test/fixtures/blackbox-state-change-blind.mjs .tmp/state-change-live
// Fix only the authorization bug: printf fixed > .tmp/state-change-live/mode
import fs from 'node:fs';
import http from 'node:http';
import path from 'node:path';
import {randomBytes} from 'node:crypto';

const root = path.resolve(process.argv[2] ?? '.tmp/state-change-live');
fs.mkdirSync(root, {recursive: true, mode: 0o700});
const routeFile = path.join(root, 'fixture.json');
const tokenFile = path.join(root, 'owner.token');
const baselineFile = path.join(root, 'baseline.txt');
const stateFile = path.join(root, 'state.txt');
const modeFile = path.join(root, 'mode');
if (!fs.existsSync(routeFile)) {
  const suffix = randomBytes(5).toString('hex');
  fs.writeFileSync(routeFile, JSON.stringify({
    identityPath: '/api/me',
    recordPath: `/api/records/${suffix}`,
    writePath: `/api/records/${suffix}/review`}), {mode: 0o600});
}
if (!fs.existsSync(tokenFile)) fs.writeFileSync(tokenFile,
  `owner-${randomBytes(16).toString('hex')}`, {mode: 0o600});
if (!fs.existsSync(baselineFile)) fs.writeFileSync(baselineFile,
  `pending-${randomBytes(4).toString('hex')}`, {mode: 0o600});
if (!fs.existsSync(stateFile)) fs.copyFileSync(baselineFile, stateFile);
if (!fs.existsSync(modeFile)) fs.writeFileSync(modeFile, 'vulnerable', {mode: 0o600});
const routes = JSON.parse(fs.readFileSync(routeFile, 'utf8'));
const ownerToken = fs.readFileSync(tokenFile, 'utf8').trim();
const owner = request => request.headers.authorization === `Bearer ${ownerToken}`;
const send = (response, status, value, type = 'application/json') => {
  response.writeHead(status, {'content-type': type,
    'cache-control': 'no-store', 'x-content-type-options': 'nosniff'});
  response.end(type === 'application/json' ? JSON.stringify(value) : value);
};
const openApi = () => ({openapi: '3.0.3', info: {title: 'Disposable review record',
  version: '1.0.0'}, paths: {
  [routes.identityPath]: {get: {summary: 'Read the signed-in test identity',
    responses: {'200': {description: 'Owner identity'},
      '401': {description: 'Sign in required'}}}},
  [routes.recordPath]: {get: {summary: 'Read an owner-only disposable review record',
    responses: {'200': {description: 'Owner record', content: {'application/json':
      {schema: {type: 'object', properties: {record: {type: 'object',
        properties: {reviewState: {type: 'string'}}}}}}}},
    '403': {description: 'Not the owner'}}}},
  [routes.writePath]: {patch: {summary: 'Change the disposable record review state',
    description: 'An authenticated owner should be required to change this record.',
    requestBody: {required: true, content: {'application/json':
      {schema: {type: 'object', required: ['reviewState'],
        properties: {reviewState: {type: 'string', example: 'reviewed'}}}}}},
    responses: {'200': {description: 'Review state changed'},
      '403': {description: 'Not authorized'}}}}}});

const server = http.createServer(async (request, response) => {
  const url = new URL(request.url, 'http://fixture');
  if (request.method === 'GET' && url.pathname === '/')
    return send(response, 200,
      '<!doctype html><html><a href="/openapi.json">API</a><script src="/app.js"></script></html>',
      'text/html');
  if (request.method === 'GET' && url.pathname === '/openapi.json')
    return send(response, 200, openApi());
  if (request.method === 'GET' && url.pathname === '/app.js')
    return send(response, 200,
      `export async function reviewState(value) { return fetch('${routes.writePath}', {method:'PATCH',headers:{'content-type':'application/json'},body:JSON.stringify({reviewState:value})}); }\nexport const record='${routes.recordPath}';`,
      'application/javascript');
  if (request.method === 'GET' && url.pathname === routes.identityPath)
    return owner(request) ? send(response, 200, {user: {id: 'test-owner', role: 'owner'}}) :
      send(response, 401, {error: 'login required'});
  if (request.method === 'GET' && url.pathname === routes.recordPath)
    return owner(request) ? send(response, 200, {record: {
      id: routes.recordPath.split('/').at(-1),
      reviewState: fs.readFileSync(stateFile, 'utf8').trim()}}) :
      send(response, 403, {error: 'owner only'});
  if (request.method === 'PATCH' && url.pathname === routes.writePath) {
    const chunks = [];
    for await (const chunk of request) chunks.push(chunk);
    let body;
    try {body = JSON.parse(Buffer.concat(chunks).toString());}
    catch {return send(response, 400, {error: 'invalid JSON'});}
    if (!body || Object.keys(body).length !== 1 ||
        typeof body.reviewState !== 'string' ||
        !/^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$/.test(body.reviewState))
      return send(response, 400, {error: 'invalid review state'});
    if (fs.readFileSync(modeFile, 'utf8').trim() === 'fixed' && !owner(request))
      return send(response, 403, {error: 'owner only'});
    fs.writeFileSync(stateFile, body.reviewState, {mode: 0o600});
    return send(response, 200, {updated: true});
  }
  return send(response, 404, {error: 'missing'});
});
server.listen(0, '127.0.0.1', () => {
  const origin = `http://127.0.0.1:${server.address().port}`;
  fs.writeFileSync(path.join(root, 'target.json'), JSON.stringify({origin,
    identityPath: routes.identityPath}), {mode: 0o600});
  process.stdout.write(`${origin}\n`);
});
