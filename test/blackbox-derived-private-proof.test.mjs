import test from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import {createHash} from 'node:crypto';
import {privateDeclarationSignal} from '../src/blackbox/content-boundary.mjs';
import {check} from '../src/blackbox/poc-runtime.mjs';

test('a self-declared private field alone is never a security proof', async t => {
  const path = '/account/private-record';
  const body = JSON.stringify({private: true, ownerId: 'fixture-account',
    note: 'an account document that is only for its owner'});
  const server = http.createServer((request, response) => {
    response.setHeader('content-type', 'application/json');
    response.setHeader('cache-control', 'no-store');
    if (request.url !== path) {response.statusCode = 404; return response.end('{}');}
    response.end(body);
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  t.after(() => new Promise(resolve => server.close(resolve)));
  const origin = `http://127.0.0.1:${server.address().port}`;
  const hash = `sha256:${createHash('sha256').update(body).digest('hex')}`;
  assert.deepEqual(privateDeclarationSignal(body, 'application/json'),
    {markerKey: 'private', materialField: 'note'});
  assert.equal(privateDeclarationSignal(JSON.stringify({private: true,
    ownerId: 'fixture-account', name: 'public label'}), 'application/json'), null);
  const spec = {schemaVersion: 1, id: 'f-001', kind: 'derived-private-read', origin,
    include: ['/'], never: [], rps: 50, identities: {}, auth: 'bearer',
    request: {method: 'GET', as: 'anonymous', url: `${origin}${path}`},
    expectedHash: hash, markerKey: 'private', materialField: 'note'};
  const result = await check(spec, {});
  assert.equal(result.verdict, 'inconclusive', JSON.stringify(result));
  assert.match(result.reason, /independent access policy/);
  assert.equal(JSON.stringify(result).includes(body), false);
});
