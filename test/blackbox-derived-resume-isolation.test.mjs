import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import http from 'node:http';
import os from 'node:os';
import path from 'node:path';
import {runAudit} from '../src/blackbox/index.mjs';
import {loadScope} from '../src/blackbox/scope.mjs';

const blank = schema => schema?.type === 'object' ? Object.fromEntries(
  (schema.required ?? []).map(key => [key, blank(schema.properties?.[key])])) :
  schema?.type === 'array' ? [] : schema?.type === 'integer' ||
  schema?.type === 'number' ? 0 : schema?.type === 'boolean' ? false :
  schema?.enum?.[0] ?? '';

test('two derived principals from one login route retain separate research checkpoints',
  {timeout: 90000}, async t => {
    const root = fs.mkdtempSync(path.join(os.tmpdir(), 'bypass-derived-isolation-'));
    t.after(() => fs.rmSync(root, {recursive: true, force: true}));
    const sessions = new Map();
    const json = (response, status, value) => {
      response.writeHead(status, {'content-type': 'application/json', 'cache-control': 'no-store'});
      response.end(JSON.stringify(value));
    };
    const server = http.createServer(async (request, response) => {
      const route = new URL(request.url, 'http://fixture.invalid').pathname;
      if (route === '/') return json(response, 200, {docs: '/openapi.json'});
      if (route === '/openapi.json') return json(response, 200, {openapi: '3.0.0', paths: {
        '/api/login': {post: {summary: 'Login with username and password', requestBody: {
          content: {'application/json': {schema: {type: 'object',
            required: ['username', 'password'], properties: {
              username: {type: 'string'}, password: {type: 'string'}}}}}}}},
        '/api/me': {get: {summary: 'Authenticated principal'}},
        '/api/preview': {post: {summary: 'Preview an expression', requestBody: {
          content: {'application/json': {schema: {type: 'object',
            required: ['expression'], properties: {expression: {type: 'string'}}}}}}}}}});
      if (route === '/api/login' && request.method === 'POST') {
        const chunks = [];
        for await (const chunk of request) chunks.push(chunk);
        const body = JSON.parse(Buffer.concat(chunks).toString());
        const principal = /^alpha' OR '[12]'='[12]$/.test(body.username) ? 'alpha' :
          /^beta' OR '[12]'='[12]$/.test(body.username) ? 'beta' : null;
        if (!principal || !/^bx-invalid-[0-9a-f]{24}$/.test(body.password))
          return json(response, 401, {error: 'denied'});
        const token = `audit-${principal}-${Math.random().toString(36).slice(2)}`;
        sessions.set(token, principal);
        return json(response, 200, {token});
      }
      if (route === '/api/me') {
        const principal = sessions.get(String(request.headers.authorization ?? '')
          .replace(/^Bearer /, ''));
        return principal ? json(response, 200, {user: {id: principal}}) :
          json(response, 401, {error: 'denied'});
      }
      if (route === '/api/preview' && request.method === 'POST')
        return json(response, 200, {result: 'ok'});
      return json(response, 404, {error: 'missing'});
    });
    await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
    t.after(() => new Promise(resolve => server.close(resolve)));
    const origin = `http://127.0.0.1:${server.address().port}`;
    const scopeFile = path.join(root, 'blackbox.scope.json');
    fs.writeFileSync(scopeFile, JSON.stringify({schemaVersion: 1, target: {origin},
      include: ['/'], probes: {jsonPostPaths: ['/api/preview']},
      limits: {rps: 50, maxUrls: 40, minutes: 3, modelCalls: 80, tasks: 0}}));
    const infer = async (_model, messages, {schema} = {}) => {
      const system = messages[0].content;
      if (system.startsWith('From only the observed authorized JSON login operations'))
        return {checks: ['alpha', 'beta'].map(name => ({loginPath: '/api/login',
          userField: 'username', passwordField: 'password', proofMode: 'principal',
          userPayloads: [`${name}' OR '1'='1`, `${name}' OR '2'='2`],
          tokenPointer: '/token', privatePath: '/api/me', principalPointer: '/user/id',
          why: 'Observed login may accept synthetic syntax'}))};
      if (system.includes('Allocate the next black-box investigation effort')) {
        const context = JSON.parse(messages.at(-1).content);
        return {priorities: context.tracks.map(row => ({name: row.name,
          weight: row.name === 'json' ? 100 : 1, why: 'Observed preview input'}))};
      }
      if (system.includes('Select distinct harmless response-transformation experiments')) {
        const context = JSON.parse(messages.at(-1).content);
        return {experiments: context.operations.some(item => item.path === '/api/preview') ?
          [{family: 'preview behavior', path: '/api/preview', field: 'expression',
            as: 'anonymous', oracle: 'observation', controlValue: 'plain',
            firstValue: 'first', secondValue: 'second', marker: context.marker,
            secondMarker: context.secondMarker, fixedFields: [], prelude: [],
            observePath: '', observeAs: 'anonymous', why: 'Observed preview field',
            priority: 10}] : []};
      }
      return blank(schema);
    };
    const audit = await runAudit({url: origin, root, scopeFile, infer,
      noDiscovery: true, offline: true});
    const derived = JSON.parse(fs.readFileSync(path.join(audit.runDir,
      'derived-session-recon.json'), 'utf8'));
    assert.equal(derived.sessions.filter(item => item.routes).length, 2,
      'both distinct principals must be mapped');
    const checkpoints = fs.readdirSync(audit.runDir).filter(name =>
      /^json-experiment-derived-.*-checkpoint\.json$/.test(name)).map(name =>
      JSON.parse(fs.readFileSync(path.join(audit.runDir, name), 'utf8')));
    for (const pass of ['derived-early', 'derived-late']) {
      const records = checkpoints.filter(item => item.pass === pass);
      assert.equal(records.length, 2,
        `same login route must retain both principals in the ${pass} checkpoint`);
      const principals = records.map(item => item.principalFingerprint);
      assert.ok(principals.every(value => /^[0-9a-f]{64}$/.test(value ?? '')),
        `${pass} checkpoint must bind its queue to the proved principal`);
      assert.equal(new Set(principals).size, 2,
        `${pass} queues must not alias distinct principals`);
    }
  });

test('a secret added on resume removes its pending executable plan before any POST',
  {timeout: 90000}, async t => {
    const root = fs.mkdtempSync(path.join(os.tmpdir(), 'bypass-new-secret-resume-'));
    t.after(() => fs.rmSync(root, {recursive: true, force: true}));
    const secret = 'fixture-owner-value-7319';
    const submitted = [];
    const server = http.createServer(async (request, response) => {
      const route = new URL(request.url, 'http://fixture.invalid').pathname;
      response.setHeader('content-type', 'application/json');
      response.setHeader('cache-control', 'no-store');
      if (route === '/') return response.end(JSON.stringify({docs: '/openapi.json'}));
      if (route === '/openapi.json') return response.end(JSON.stringify({
        openapi: '3.0.0', paths: {'/api/preview': {post: {
          summary: 'Preview a value', requestBody: {content: {'application/json': {
            schema: {type: 'object', required: ['value'],
              properties: {value: {type: 'string'}}}}}}}}}}));
      if (route === '/api/preview' && request.method === 'POST') {
        const chunks = [];
        for await (const chunk of request) chunks.push(chunk);
        submitted.push(JSON.parse(Buffer.concat(chunks).toString()).value);
        return response.end(JSON.stringify({result: 'previewed'}));
      }
      response.statusCode = 404;
      response.end('{}');
    });
    await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
    t.after(() => new Promise(resolve => server.close(resolve)));
    const origin = `http://127.0.0.1:${server.address().port}`;
    const scopeFile = path.join(root, 'blackbox.scope.json');
    fs.writeFileSync(scopeFile, JSON.stringify({schemaVersion: 1, target: {origin},
      include: ['/'], probes: {jsonPostPaths: ['/api/preview']},
      limits: {rps: 50, maxUrls: 40, minutes: 3, modelCalls: 40, tasks: 0}}));
    const scopeHash = loadScope({file: scopeFile, origin}).hash;
    const previous = 'bx-20261029-aaaaaaaa';
    const previousDir = path.join(root, '.bypass/runs', previous);
    fs.mkdirSync(previousDir, {recursive: true});
    fs.writeFileSync(path.join(previousDir, 'evidence.jsonl'), '');
    fs.writeFileSync(path.join(previousDir, 'run-start.json'), JSON.stringify({
      run: previous, scopeHash, origin, effectiveLimits: loadScope({
        file: scopeFile, origin}).scope.limits}));
    fs.writeFileSync(path.join(previousDir, 'json-experiment-checkpoint.json'),
      JSON.stringify({version: 1, run: previous, scopeHash, origin,
        pass: 'primary', kind: 'json-experiment', cursor: 0, active: null,
        leads: [{path: '/api/preview', parameter: 'value', as: 'anonymous',
          oracle: 'observation', controlValue: 'plain', firstValue: secret,
          secondValue: 'other', marker: 'bx111111111111',
          secondMarker: 'bx222222222222', fixedFields: [],
          observedFields: ['value'], prelude: [], observePath: '',
          observeAs: 'anonymous', family: 'preview', why: 'Observed preview field'}]}));
    const audit = await runAudit({url: origin, root, scopeFile, resumeFrom: previous,
      env: {OWNER_TOKEN: secret}, noDiscovery: true, offline: true,
      infer: async (_model, _messages, {schema} = {}) => blank(schema)});
    const copied = JSON.parse(fs.readFileSync(path.join(audit.runDir,
      'json-experiment-checkpoint.json'), 'utf8'));
    assert.equal(copied.redactedExecutableLeads, 1,
      'the newly supplied secret must invalidate the persisted request');
    assert.ok(!submitted.includes(secret),
      'the invalidated in-memory request must not execute after resume');
  });
