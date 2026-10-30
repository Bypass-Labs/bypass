import test from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import {check} from '../src/blackbox/poc-runtime.mjs';

test('dynamic Prometheus metrics exposure replays by signature, then clears after access is denied', async t => {
  let available = true, reads = 0;
  const server = http.createServer((request, response) => {
    if (request.url !== '/metrics' || !available) {
      response.writeHead(404); response.end(); return;
    }
    reads++;
    response.writeHead(200, {'content-type': 'text/plain; version=0.0.4; charset=utf-8'});
    response.end(`# HELP app_requests_total Request count\n# TYPE app_requests_total counter\napp_requests_total ${reads}\n`);
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  t.after(() => new Promise(resolve => server.close(resolve)));
  const origin = `http://127.0.0.1:${server.address().port}`;
  const spec = {schemaVersion: 1, kind: 'exposure', origin, include: ['/'], never: [],
    rps: 50, identities: {}, auth: 'bearer', expiresAt: null,
    request: {url: `${origin}/metrics`, as: 'anonymous', method: 'GET'},
    signature: 'metrics exposition', expectedHash: 'sha256:the-body-changes'};
  const red = await check(spec);
  assert.equal(red.verdict, 'confirmed', JSON.stringify(red));
  assert.equal(reads, 2);
  assert.notEqual(red.controls[0].hash, red.controls[1].hash);
  available = false;
  assert.equal((await check(spec)).verdict, 'not_reproduced');
});
