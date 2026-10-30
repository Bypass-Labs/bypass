// A local, randomized target for a real Muse black-box run. Give the audit only
// the printed origin; fixture-routes.json is for checking the result afterward.
import fs from 'node:fs';
import http from 'node:http';
import path from 'node:path';
import {randomBytes} from 'node:crypto';

const root = process.argv[2];
if (!root) throw Error('Fixture directory is required.');
fs.mkdirSync(root, {recursive: true});
const modeFile = path.join(root, 'mode');
if (!fs.existsSync(modeFile)) fs.writeFileSync(modeFile, 'vulnerable');
const suffixFile = path.join(root, 'route-suffix');
const suffix = fs.existsSync(suffixFile) ? fs.readFileSync(suffixFile, 'utf8').trim() :
  randomBytes(5).toString('hex');
if (!/^[0-9a-f]{10}$/.test(suffix)) throw Error('Invalid route suffix.');
fs.writeFileSync(suffixFile, suffix);
const base = `/api/${suffix}`;
const routes = {login: `${base}/session`, private: `${base}/records/member`,
  resolve: `${base}/records/resolve`, public: `${base}/records/public`};
fs.writeFileSync(path.join(root, 'fixture-routes.json'), JSON.stringify(routes, null, 2));
const privateBody = JSON.stringify({id: `member-${suffix}`, visibility: 'private',
  owner: `member-${suffix}`, title: 'Member workspace record',
  note: `Synthetic private record ${suffix} for this local fixture`});
const publicBody = JSON.stringify({id: `public-${suffix}`, visibility: 'public',
  title: 'Public workspace record', note: 'A harmless public example'});
const tokens = new Set();
const mode = () => fs.readFileSync(modeFile, 'utf8').trim();
const respond = (response, status, body, type = 'application/json') => {
  response.writeHead(status, {'content-type': type, 'cache-control': 'no-store'});
  response.end(body);
};
const json = (response, status, value) => respond(response, status, JSON.stringify(value));
const readJson = async request => {
  const chunks = [];
  let size = 0;
  for await (const chunk of request) {
    size += chunk.length;
    if (size > 16384) return null;
    chunks.push(chunk);
  }
  try { return JSON.parse(Buffer.concat(chunks).toString('utf8')); }
  catch { return null; }
};
const operation = (summary, fields) => ({post: {summary,
  requestBody: {required: true, content: {'application/json': {schema: {
    type: 'object', required: fields,
    properties: Object.fromEntries(fields.map(field => [field, {type: 'string'}]))}}}}}});
const openapi = JSON.stringify({openapi: '3.0.0', paths: {
  [routes.login]: operation('Create a member session from username and password',
    ['username', 'password']),
  [routes.private]: {get: {summary: 'Read the current member workspace record'}},
  [routes.public]: {get: {summary: 'Read a public workspace record'}},
  [routes.resolve]: operation('Resolve one public workspace record by a literal name or glob selector',
    ['selector']),
}});
const client = `async function publicRecord() {
  return fetch('${routes.resolve}', {method:'POST', headers:{'content-type':'application/json'},
    body:JSON.stringify({selector:'public'})}).then(response=>response.json());
}
async function memberRecord(token) {
  return fetch('${routes.private}', {headers:{authorization:'Bearer '+token}}).then(response=>response.json());
}`;
const server = http.createServer(async (request, response) => {
  const url = new URL(request.url, 'http://fixture.invalid');
  if (request.method === 'GET' && url.pathname === '/')
    return respond(response, 200,
      '<!doctype html><script src="/client.js"></script><a href="/openapi.json">API</a>',
      'text/html');
  if (request.method === 'GET' && url.pathname === '/client.js')
    return respond(response, 200, client, 'application/javascript');
  if (request.method === 'GET' && url.pathname === '/openapi.json')
    return respond(response, 200, openapi);
  if (request.method === 'GET' && url.pathname === routes.public)
    return respond(response, 200, publicBody);
  if (request.method === 'GET' && url.pathname === routes.private) {
    const bearer = String(request.headers.authorization ?? '').replace(/^Bearer /, '');
    return tokens.has(bearer) ? respond(response, 200, privateBody) :
      json(response, 401, {error: 'authentication required'});
  }
  if (request.method === 'POST' && url.pathname === routes.login) {
    const body = await readJson(request);
    const tautology = /'\s+OR\s+(?:1\s*=\s*1|'1'\s*=\s*'1'?|2\s*=\s*2|'2'\s*=\s*'2'?)/i;
    if (!['fixed-login', 'fixed'].includes(mode()) &&
        tautology.test(String(body?.username ?? '')) &&
        /^bx-invalid-[0-9a-f]{24}$/.test(String(body?.password ?? ''))) {
      const token = `token-${randomBytes(24).toString('hex')}`;
      tokens.add(token);
      return json(response, 200, {authentication: {token}});
    }
    return json(response, 401, {error: 'invalid credentials'});
  }
  if (request.method === 'POST' && url.pathname === routes.resolve) {
    const body = await readJson(request);
    const selector = String(body?.selector ?? '');
    // The glob path omits the public-visibility condition. This is the only
    // disclosure in the fixture; ordinary literal lookups return public data.
    const glob = /[*%]/.test(selector);
    return respond(response, 200,
      glob && !['fixed-disclosure', 'fixed'].includes(mode()) ?
        privateBody : publicBody);
  }
  return json(response, 404, {error: 'not found'});
});
server.listen(0, '127.0.0.1', () => {
  process.stdout.write(`http://127.0.0.1:${server.address().port}\n`);
});
