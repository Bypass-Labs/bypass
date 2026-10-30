// Randomized local fixture for an owner-only JSON field exposed through a
// different anonymous wrapper. The audit engine receives only HTTP evidence.
import fs from 'node:fs';
import http from 'node:http';
import path from 'node:path';
import {randomBytes} from 'node:crypto';

const root = path.resolve(process.argv[2] ?? '.tmp/json-field-blind');
fs.mkdirSync(root, {recursive: true});
const suffix = randomBytes(4).toString('hex');
const protectedPath = `/api/record-${suffix}`;
const filterPath = `/api/filter-${suffix}`;
const sourcePath = `/api/source-${suffix}`;
const echoMode = process.argv[3] === 'echo';
const token = `owner-${randomBytes(12).toString('hex')}`;
const secret = `private-${randomBytes(echoMode ? 6 : 18).toString('hex')}`;
const modeFile = path.join(root, 'mode');
if (!fs.existsSync(modeFile)) fs.writeFileSync(modeFile, 'vulnerable');
const fixed = () => fs.readFileSync(modeFile, 'utf8').trim() === 'fixed';
let serial = 0;
const server = http.createServer((request, response) => {
  const url = new URL(request.url, 'http://fixture');
  response.setHeader('cache-control', 'no-store');
  if (url.pathname === '/') {
    response.setHeader('content-type', 'text/html');
    return response.end('<a href="/openapi.json">API</a><script src="/app.js"></script>');
  }
  if (url.pathname === '/app.js') {
    response.setHeader('content-type', 'application/javascript');
    return response.end(`fetch('${filterPath}?term=all');fetch('${filterPath}?term=archive');${echoMode ? `fetch('${sourcePath}');` : ''}`);
  }
  response.setHeader('content-type', 'application/json');
  if (url.pathname === '/openapi.json') return response.end(JSON.stringify({
    openapi: '3.0.0', paths: {
      [protectedPath]: {get: {summary: 'Read a private owner record'}},
      [filterPath]: {get: {summary: 'Filter the public record index',
        parameters: [{in: 'query', name: 'term', schema: {type: 'string'},
          examples: {ordinary: {value: 'recent'}, wide: {value: 'all'},
            archived: {value: 'archive'}}},
        ...(echoMode ? [{in: 'query', name: 'copy', schema: {type: 'string'}}] : [])]}},
      ...(echoMode ? {[sourcePath]: {get: {summary: 'Get a public source value'}}} : {})}}));
  if (echoMode && request.method === 'GET' && url.pathname === sourcePath)
    return response.end(JSON.stringify({nonce: secret}));
  if (request.method === 'GET' && url.pathname === protectedPath) {
    if (request.headers.authorization !== `Bearer ${token}`) {
      response.statusCode = 403;
      return response.end(JSON.stringify({error: 'forbidden'}));
    }
    return response.end(JSON.stringify({private: true, owner: 'test-owner',
      secret, requestId: ++serial}));
  }
  if (request.method === 'GET' && url.pathname === filterPath) {
    const term = url.searchParams.get('term');
    const exposed = !fixed() && ['all', 'archive'].includes(term);
    return response.end(JSON.stringify({requestId: ++serial,
      result: exposed ? {secret: echoMode ? url.searchParams.get('copy') : secret} : {items: []}}));
  }
  response.statusCode = 404;
  response.end(JSON.stringify({error: 'missing'}));
});
await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
const origin = `http://127.0.0.1:${server.address().port}`;
const scopePath = path.join(root, 'blackbox.scope.json');
fs.writeFileSync(scopePath, JSON.stringify({schemaVersion: 1, target: {origin},
  include: ['/'], identities: {identityPath: protectedPath},
  limits: {rps: 20, maxUrls: 80, minutes: 4, modelCalls: 50, tasks: 0}}));
const manifest = {origin, protectedPath, filterPath, sourcePath, ownerToken: token,
  modeFile, scopePath};
fs.writeFileSync(path.join(root, 'manifest.json'), JSON.stringify(manifest));
process.stdout.write(`${JSON.stringify(manifest)}\n`);
for (const signal of ['SIGINT', 'SIGTERM']) process.on(signal, () =>
  server.close(() => process.exit(0)));
