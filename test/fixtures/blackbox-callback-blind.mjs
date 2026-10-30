// Randomized local server-fetch fixture. Only HTTP responses and a scope file
// are given to the auditor; manifest.json is for the operator's scoring.
import fs from 'node:fs';
import http from 'node:http';
import path from 'node:path';
import {randomBytes} from 'node:crypto';

const root = path.resolve(process.argv[2] ?? '.tmp/callback-blind');
fs.mkdirSync(root, {recursive: true});
const suffix = randomBytes(5).toString('hex');
const previewPath = `/api/preview-${suffix}`;
const samplePath = `/public/sample-${suffix}.txt`;
const modeFile = path.join(root, 'mode');
if (!fs.existsSync(modeFile)) fs.writeFileSync(modeFile, 'vulnerable');
const fixed = () => fs.readFileSync(modeFile, 'utf8').trim() === 'fixed';

let origin;
const server = http.createServer(async (request, response) => {
  const url = new URL(request.url, 'http://fixture');
  response.setHeader('cache-control', 'no-store');
  if (request.method === 'GET' && url.pathname === '/') {
    response.setHeader('content-type', 'text/html; charset=utf-8');
    return response.end('<a href="/openapi.json">API</a><script src="/app.js"></script>');
  }
  if (request.method === 'GET' && url.pathname === '/app.js') {
    response.setHeader('content-type', 'application/javascript');
    return response.end(`fetch('${previewPath}',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({previewUrl:new URL('${samplePath}',location.origin).href})});`);
  }
  if (request.method === 'GET' && url.pathname === '/openapi.json') {
    response.setHeader('content-type', 'application/json');
    return response.end(JSON.stringify({openapi: '3.0.0',
      info: {title: 'Preview API', version: '1.0.0'},
      paths: {[previewPath]: {post: {
        summary: 'Fetch a supplied URL on the server to generate a preview',
        requestBody: {required: true, content: {'application/json': {
          schema: {type: 'object', required: ['previewUrl'],
            properties: {previewUrl: {type: 'string', format: 'uri',
              description: 'URL of the page to preview'}}},
          example: {previewUrl: `${origin}${samplePath}`}}}},
        responses: {200: {description: 'Preview fetched'}}}},
      [samplePath]: {get: {summary: 'Public sample preview document'}}}}));
  }
  if (request.method === 'GET' && url.pathname === samplePath) {
    response.setHeader('content-type', 'text/plain');
    return response.end('A public preview sample.');
  }
  if (request.method !== 'POST' || url.pathname !== previewPath) {
    response.statusCode = 404;
    return response.end('missing');
  }
  const chunks = [];
  for await (const chunk of request) {
    chunks.push(chunk);
    if (Buffer.concat(chunks).length > 4096) {
      response.statusCode = 413;
      return response.end('too large');
    }
  }
  let destination;
  try {destination = JSON.parse(Buffer.concat(chunks).toString()).previewUrl;}
  catch {response.statusCode = 400; return response.end('invalid JSON');}
  if (typeof destination !== 'string' || !URL.canParse(destination)) {
    response.statusCode = 400;
    return response.end('invalid preview URL');
  }
  const target = new URL(destination);
  if (target.protocol !== 'http:' || target.hostname !== '127.0.0.1' ||
      fixed() && target.origin !== origin) {
    response.statusCode = 403;
    return response.end('preview destination denied');
  }
  try {
    const fetched = await fetch(target, {redirect: 'manual',
      signal: AbortSignal.timeout(1500)});
    await fetched.arrayBuffer();
    response.setHeader('content-type', 'application/json');
    response.end(JSON.stringify({previewReady: true, upstreamStatus: fetched.status}));
  } catch {
    response.statusCode = 502;
    response.end('preview fetch failed');
  }
});
await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
origin = `http://127.0.0.1:${server.address().port}`;
const scopePath = path.join(root, 'blackbox.scope.json');
fs.writeFileSync(scopePath, JSON.stringify({schemaVersion: 1, target: {origin},
  include: ['/'], limits: {rps: 15, maxUrls: 100, minutes: 4,
    modelCalls: 60, tasks: 0}}));
const manifest = {origin, previewPath, samplePath, modeFile, scopePath};
fs.writeFileSync(path.join(root, 'manifest.json'), JSON.stringify(manifest));
process.stdout.write(`${JSON.stringify(manifest)}\n`);
for (const signal of ['SIGINT', 'SIGTERM']) process.on(signal, () =>
  server.close(() => process.exit(0)));
