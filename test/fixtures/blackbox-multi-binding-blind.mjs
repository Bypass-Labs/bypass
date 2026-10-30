import http from 'node:http';
import fs from 'node:fs';
import path from 'node:path';
import {randomBytes} from 'node:crypto';

const root = process.argv[2];
if (!root) throw Error('Fixture directory is required.');
fs.mkdirSync(root, {recursive: true});
if (!fs.existsSync(path.join(root, 'mode')))
  fs.writeFileSync(path.join(root, 'mode'), 'vulnerable');
const prefix = `/api/${randomBytes(6).toString('hex')}`;
const routes = {start: `${prefix}/start`, exchange: `${prefix}/exchange`,
  finish: `${prefix}/finish`, private: `${prefix}/private`};
fs.writeFileSync(path.join(root, 'fixture-routes.json'), JSON.stringify(routes));
const ownerDocument = JSON.stringify({workspace: 'owner', private: true,
  owner: 'synthetic', note: `private-${randomBytes(10).toString('hex')}`});
const publicDocument = JSON.stringify({workspace: 'public', private: false});
const nonces = new Set(), tickets = new Set();
const operation = (summary, required, properties, status, responseProperties) => ({
  post: {summary, requestBody: {required: true, content: {
    'application/json': {schema: {type: 'object', required, properties}}}},
  responses: {[status]: {content: {'application/json': {schema: {
    type: 'object', properties: responseProperties}}}}}}});
const openapi = JSON.stringify({openapi: '3.0.0', paths: {
  [routes.private]: {get: {summary: 'Read the owner workspace'}},
  [routes.start]: operation('Start a disposable workflow', ['kind'],
    {kind: {type: 'string', example: 'audit'}}, '201',
    {nonce: {type: 'string'}}),
  [routes.exchange]: operation('Exchange a one-use nonce for a ticket', ['nonce'],
    {nonce: {type: 'string'}}, '200', {ticket: {type: 'string'}}),
  [routes.finish]: operation('Finish with a one-use ticket and a claim',
    ['ticket', 'claim'], {ticket: {type: 'string'},
      claim: {type: 'string', example: 'plain'}}, '200',
    {workspace: {type: 'string'}, private: {type: 'boolean'}})}});
const client = `async function finishWorkflow() {
  const started = await fetch('${routes.start}', {method:'POST', headers:{'content-type':'application/json'}, body:JSON.stringify({kind:'audit'})}).then(r=>r.json());
  const exchanged = await fetch('${routes.exchange}', {method:'POST', headers:{'content-type':'application/json'}, body:JSON.stringify({nonce:started.nonce})}).then(r=>r.json());
  return fetch('${routes.finish}', {method:'POST', headers:{'content-type':'application/json'}, body:JSON.stringify({ticket:exchanged.ticket,claim:'plain'})});
}`;
const server = http.createServer(async (request, response) => {
  const url = new URL(request.url, 'http://fixture.invalid');
  response.setHeader('cache-control', 'no-store');
  if (request.method === 'GET' && url.pathname === '/') {
    response.setHeader('content-type', 'text/html');
    return response.end('<script src="/client.js"></script><a href="/openapi.json">API</a>');
  }
  if (request.method === 'GET' && url.pathname === '/client.js') {
    response.setHeader('content-type', 'application/javascript');
    return response.end(client);
  }
  response.setHeader('content-type', 'application/json');
  if (request.method === 'GET' && url.pathname === '/openapi.json')
    return response.end(openapi);
  if (request.method === 'GET' && url.pathname === routes.private) {
    if (request.headers.authorization === 'Bearer fixture-owner')
      return response.end(ownerDocument);
    response.statusCode = 403;
    return response.end(JSON.stringify({error: 'forbidden'}));
  }
  if (request.method === 'POST' &&
      [routes.start, routes.exchange, routes.finish].includes(url.pathname)) {
    let raw = '';
    for await (const chunk of request) raw += chunk;
    let body = null;
    try {body = JSON.parse(raw);} catch { /* return 400 below */ }
    if (url.pathname === routes.start && body?.kind === 'audit') {
      const nonce = `n${randomBytes(8).toString('hex')}`;
      nonces.add(nonce);
      response.statusCode = 201;
      return response.end(JSON.stringify({nonce}));
    }
    if (url.pathname === routes.exchange && nonces.delete(body?.nonce)) {
      const ticket = `t${randomBytes(8).toString('hex')}`;
      tickets.add(ticket);
      return response.end(JSON.stringify({ticket}));
    }
    if (url.pathname === routes.finish && tickets.delete(body?.ticket))
      return response.end(body?.claim === 'owner' &&
        fs.readFileSync(path.join(root, 'mode'), 'utf8').trim() !== 'fixed' ?
        ownerDocument : publicDocument);
    response.statusCode = 400;
    return response.end(JSON.stringify({error: 'invalid workflow'}));
  }
  response.statusCode = 404;
  response.end(JSON.stringify({error: 'missing'}));
});
server.listen(0, '127.0.0.1', () => {
  process.stdout.write(`http://127.0.0.1:${server.address().port}\n`);
});
