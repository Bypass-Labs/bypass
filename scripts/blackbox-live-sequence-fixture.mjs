#!/usr/bin/env node
// Small randomized localhost target for a blind Muse HTTP-sequence smoke test.
import http from 'node:http';
import fs from 'node:fs';
import {randomBytes} from 'node:crypto';

const args = process.argv.slice(2);
const flag = name => args.includes(name) ? args[args.indexOf(name) + 1] : null;
const port = Number(flag('--port') ?? 0);
const id = flag('--id') ?? randomBytes(4).toString('hex');
const fixed = args.includes('--fixed');
const scopeFile = flag('--scope') ?? `/tmp/bypass-live-sequence-${id}.scope.json`;
if (!Number.isInteger(port) || port < 0 || port > 65535 || !/^[a-f0-9]{8}$/.test(id)) {
  process.stderr.write('Usage: node scripts/blackbox-live-sequence-fixture.mjs [--port 4017] [--id 8-hex-chars] [--fixed] [--scope /tmp/scope.json]\n');
  process.exit(2);
}

const route = `/api/preview-${id}`;
const decoy = `/api/delete-${id}`;
let decoyHits = 0;
const send = (response, status, body, type = 'application/json') => {
  response.writeHead(status, {'content-type': type, 'cache-control': 'no-store'});
  response.end(type === 'application/json' ? JSON.stringify(body) : body);
};
const preview = value => {
  if (fixed) return value;
  const codes = /^String\.fromCharCode\((\d{1,3}(?:,\d{1,3}){1,31})\)$/.exec(value);
  if (codes) {
    const values = codes[1].split(',').map(Number);
    if (values.every(number => number >= 32 && number <= 126))
      return String.fromCharCode(...values);
  }
  const arithmetic = /^(\d{1,2})\s*([+*])\s*(\d{1,2})$/.exec(value);
  if (arithmetic) return String(arithmetic[2] === '+' ?
    Number(arithmetic[1]) + Number(arithmetic[3]) :
    Number(arithmetic[1]) * Number(arithmetic[3]));
  return value;
};

const server = http.createServer(async (request, response) => {
  const url = new URL(request.url, 'http://127.0.0.1');
  if (request.method === 'GET' && url.pathname === '/') return send(response, 200,
    `<html><title>Note preview</title><h1>Note preview</h1><p>Try 2+2 in the text field.</p><script src="/app.js"></script></html>`,
    'text/html');
  if (request.method === 'GET' && url.pathname === '/app.js') return send(response, 200,
    `export async function preview(text){return fetch('${route}',{method:'POST',headers:{'content-type':'application/x-www-form-urlencoded'},body:new URLSearchParams({text})})}`, 'application/javascript');
  if (request.method === 'GET' && url.pathname === '/openapi.json') return send(response, 200, {
    openapi: '3.0.0', info: {title: 'Note preview', version: '1.0'}, paths: {
      [route]: {post: {summary: 'Preview supplied text. A simple expression such as 2+2 returns 4.',
        requestBody: {required: true, content: {'application/x-www-form-urlencoded': {
          schema: {type: 'object', required: ['text'], properties: {text: {type: 'string'}}}}}},
        responses: {'200': {description: 'Preview result'}}}},
    },
  });
  if (request.method === 'GET' && url.pathname === '/api/status') return send(response, 200,
    {service: 'note-preview', example: '2+2', preview: '4'});
  if (url.pathname === decoy) {
    decoyHits++;
    return send(response, 403, {error: 'protected', decoyHits});
  }
  if (url.pathname === route && request.method === 'POST') {
    const chunks = [];
    for await (const chunk of request) {
      chunks.push(chunk);
      if (Buffer.concat(chunks).length > 4096) return send(response, 413, {error: 'too large'});
    }
    const body = Buffer.concat(chunks).toString();
    const params = new URLSearchParams(body);
    const text = params.get('text');
    if (!text || params.getAll('text').length !== 1)
      return send(response, 400, {error: 'one text value required'});
    return send(response, 200, {preview: preview(text)});
  }
  send(response, url.pathname === route ? 405 : 404, {error: 'not found'});
});

server.listen(port, '127.0.0.1', () => {
  const origin = `http://127.0.0.1:${server.address().port}`;
  const scope = {schemaVersion: 1, target: {origin}, include: ['/'],
    probes: {formPostPaths: [route]}, limits: {rps: 20, minutes: 6, modelCalls: 60}};
  fs.writeFileSync(scopeFile, `${JSON.stringify(scope, null, 2)}\n`, {mode: 0o600});
  process.stdout.write(`${JSON.stringify({origin, route, decoy, scopeFile, id, port: server.address().port, fixed})}\n`);
});
