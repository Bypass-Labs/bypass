// Standalone local method-aware target. The audit receives only its origin and scope.
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
const fixed = () => fs.readFileSync(modeFile, 'utf8').trim() === 'fixed';
const suffix = randomBytes(5).toString('hex');
const patchPath = `/api/${suffix}/format`;
const scriptPath = `/assets/${suffix}/client.js`;
const eventsFile = path.join(directory, 'requests.jsonl');
const json = (response, status, body, headers = {}) => {
  response.writeHead(status, {'content-type': 'application/json',
    'cache-control': 'no-store', ...headers});
  response.end(JSON.stringify(body));
};
const server = http.createServer(async (request, response) => {
  const url = new URL(request.url, 'http://fixture.invalid');
  if (request.method === 'GET' && url.pathname === '/') {
    response.writeHead(200, {'content-type': 'text/html', 'cache-control': 'no-store'});
    return response.end(`<html><a href="/openapi.json">API</a><script src="${scriptPath}"></script></html>`);
  }
  if (request.method === 'GET' && url.pathname === scriptPath) {
    response.writeHead(200, {'content-type': 'text/javascript', 'cache-control': 'no-store'});
    return response.end(`export async function preview(expression) {\n` +
      `  return fetch('${patchPath}', {method:'PATCH', headers:{'content-type':'application/json'},\n` +
      `    body:JSON.stringify({expression})});\n}\n` +
      `preview('hex:68656c6c6f');\n`);
  }
  if (request.method === 'GET' && url.pathname === '/openapi.json') return json(response, 200, {
    openapi: '3.0.0', paths: {
      [patchPath]: {patch: {summary: 'Format an expression for preview',
        requestBody: {required: true, content: {'application/json': {schema: {
          type: 'object', required: ['expression'], properties: {
            expression: {type: 'string', example: 'hex:68656c6c6f'}}}}}},
        responses: {'200': {description: 'Rendered preview'}}}},
    }});
  if (request.method === 'PATCH' && url.pathname === patchPath) {
    const chunks = [];
    for await (const chunk of request) chunks.push(chunk);
    let body;
    try {body = JSON.parse(Buffer.concat(chunks).toString());}
    catch {return json(response, 400, {error: 'invalid JSON'});}
    const value = String(body.expression ?? '');
    const encoded = /^hex:(?:[0-9a-f]{2}){1,128}$/i.test(value);
    const rendered = !fixed() && encoded ?
      Buffer.from(value.slice(4), 'hex').toString('utf8') : value;
    fs.appendFileSync(eventsFile, JSON.stringify({method: 'PATCH', path: patchPath,
      contentType: request.headers['content-type'] ?? null,
      inputKind: encoded ? 'hex' : 'plain', transformed: rendered !== value}) + '\n');
    return json(response, 200, {rendered}, {location: rendered});
  }
  return json(response, 404, {error: 'not found'});
});
server.listen(0, '127.0.0.1', () => {
  const origin = `http://127.0.0.1:${server.address().port}`;
  fs.writeFileSync(path.join(directory, 'blackbox.scope.json'), JSON.stringify({
    schemaVersion: 1, target: {origin}, include: ['/'],
    probes: {writeOperations: [{method: 'PATCH', path: patchPath, placement: 'json'}]},
    limits: {rps: 15, maxUrls: 80, minutes: 5, modelCalls: 60, tasks: 120},
  }));
  process.stdout.write(`${origin}\n`);
});
process.on('SIGTERM', () => server.close());
