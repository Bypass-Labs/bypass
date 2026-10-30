import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import http from 'node:http';
import {temp} from './helpers.mjs';
import {runAudit} from '../src/blackbox/index.mjs';

function empty(schema) {
  if (schema?.anyOf) return empty(schema.anyOf[0]);
  const type = Array.isArray(schema?.type) ? schema.type[0] : schema?.type;
  if (type === 'array') return [];
  if (type === 'object') return Object.fromEntries((schema.required ?? [])
    .map(key => [key, empty(schema.properties?.[key])]));
  if (type === 'integer' || type === 'number') return schema.minimum ?? 0;
  if (type === 'boolean') return false;
  return '';
}

test('a fresh standalone blackbox run selects Meta API by default', async t => {
  const root = temp();
  t.after(() => fs.rmSync(root, {recursive: true, force: true}));
  const server = http.createServer((request, response) => {
    if (request.url === '/app.js') {
      response.writeHead(200, {'content-type': 'application/javascript'});
      return response.end("fetch('/api/public?x=1')");
    }
    if (request.url?.startsWith('/api/public')) {
      response.writeHead(200, {'content-type': 'application/json'});
      return response.end('{"items":[]}');
    }
    response.writeHead(200, {'content-type': 'text/html'});
    response.end('<html><script src="/app.js"></script></html>');
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  t.after(() => new Promise(resolve => server.close(resolve)));
  const profiles = [];
  await runAudit({url: `http://127.0.0.1:${server.address().port}`, root,
    env: {META_API_KEY: 'test-only-placeholder'},
    overrides: {acceptLocal: true, minutes: 1, modelCalls: 3, maxUrls: 5, maxTasks: 5},
    infer: async (profile, _messages, options) => {
      profiles.push(profile);
      return empty(options.schema);
    }});
  assert.ok(profiles.length > 0);
  assert.ok(profiles.every(profile => profile.provider === 'meta' &&
    profile.secretEnv === 'META_API_KEY' && profile.model === 'muse-spark-1.3'));

  const genericProfiles = [];
  await runAudit({url: `http://127.0.0.1:${server.address().port}`, root,
    env: {LLM_KEY: 'test-only-placeholder'},
    overrides: {acceptLocal: true, minutes: 1, modelCalls: 3, maxUrls: 5, maxTasks: 5},
    infer: async (profile, _messages, options) => {
      genericProfiles.push(profile);
      return empty(options.schema);
    }});
  assert.ok(genericProfiles.length > 0);
  assert.ok(genericProfiles.every(profile => profile.provider === 'meta' &&
    profile.secretEnv === 'LLM_KEY'));
});
