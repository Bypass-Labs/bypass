import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import http from 'node:http';
import os from 'node:os';
import path from 'node:path';
import {randomBytes} from 'node:crypto';
import {spawn} from 'node:child_process';
import {CLI} from '../src/demo.mjs';
import {execFile} from '../src/util.mjs';
import {execute} from '../src/service.mjs';

test('CLI binds a freshly observed JSON value into a later request and replays it', async t => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'bypass-sequence-binding-'));
  t.after(() => fs.rmSync(root, {recursive: true, force: true}));
  const suffix = randomBytes(4).toString('hex');
  const prepare = `/api/context-${suffix}`;
  const transform = `/api/preview-${suffix}`;
  const setupReads = Array.from({length: 4}, (_, index) =>
    `/api/setup-${index}-${suffix}`);
  const observeReads = Array.from({length: 3}, (_, index) =>
    `/api/observe-${index}-${suffix}`);
  const decoy = `/api/delete-${suffix}`;
  const requested = [];
  const workspaces = new Set();
  let vulnerable = true;
  const server = http.createServer((request, response) => {
    const url = new URL(request.url, 'http://fixture');
    requested.push(`${request.method} ${url.pathname}${url.search}`);
    const send = (status, body) => {
      response.writeHead(status, {'content-type': 'application/json',
        'cache-control': 'no-store'});
      response.end(JSON.stringify(body));
    };
    if (url.pathname === '/') return send(200, {service: 'preview workspace'});
    if (url.pathname === '/openapi.json') return send(200, {openapi: '3.0.0', paths: {
      [prepare]: {get: {summary: 'Create a short preview context'}},
      ...Object.fromEntries([...setupReads, ...observeReads].map(route =>
        [route, {get: {summary: 'Read-only workflow step'}}])),
      [transform]: {get: {summary: 'Preview expression within a workspace',
        parameters: [{name: 'workspace', in: 'query', schema: {type: 'string'}},
          {name: 'expression', in: 'query', schema: {type: 'string'}, example: 'plain'}]}}}});
    if (request.method === 'GET' && url.pathname === prepare) {
      const id = `w-${randomBytes(4).toString('hex')}`;
      workspaces.add(id);
      return send(200, {workspace: {id}});
    }
    if (request.method === 'GET' && setupReads.includes(url.pathname))
      return send(200, {ready: true});
    if (request.method === 'GET' && observeReads.includes(url.pathname))
      return send(200, {observed: true});
    if (request.method === 'GET' && url.pathname === transform) {
      const id = url.searchParams.get('workspace');
      const expression = url.searchParams.get('expression') ?? '';
      const active = workspaces.delete(id);
      const result = vulnerable && active && expression.startsWith('hex:') ?
        Buffer.from(expression.slice(4), 'hex').toString('utf8') : expression;
      return send(200, {result});
    }
    if (url.pathname === decoy) return send(200, {deleted: true});
    return send(404, {error: 'missing'});
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  t.after(() => new Promise(resolve => server.close(resolve)));
  const origin = `http://127.0.0.1:${server.address().port}`;
  const scopePath = path.join(root, 'blackbox.scope.json');
  fs.writeFileSync(scopePath, JSON.stringify({schemaVersion: 1, target: {origin},
    never: [decoy], seeds: {paths: [prepare]},
    limits: {rps: 50, maxUrls: 40, minutes: 3,
      modelCalls: 30, tasks: 20}}));
  const blank = schema => schema?.type === 'object' ?
    Object.fromEntries((schema.required ?? []).map(key =>
      [key, blank(schema.properties?.[key])])) :
    schema?.type === 'array' ? [] :
    ['integer', 'number'].includes(schema?.type) ? 0 :
    schema?.type === 'boolean' ? false : schema?.enum?.[0] ?? '';
  const modelServer = http.createServer(async (request, response) => {
    let raw = '';
    for await (const chunk of request) raw += chunk;
    const call = JSON.parse(raw);
    const system = call.input.find(item => item.role === 'system')?.content ?? '';
    const context = call.input.filter(item => item.role === 'user').toReversed()
      .map(item => {try {return JSON.parse(item.content);} catch {return null;}})
      .find(Boolean) ?? {};
    let answer;
    if (system.startsWith('You are planning bounded, authorized HTTP research.')) {
      const subject = context.routes.find(item => item.path === transform &&
        item.kind === 'read' && item.fields.includes('workspace') &&
        item.fields.includes('expression'));
      const source = context.observedReadRoutes.find(item => item.path === prepare);
      const observed = route => context.observedReadRoutes.some(item => item.path === route);
      const step = route => ({method: 'GET', path: route, headers: []});
      const encoded = value => `hex:${Buffer.from(value).toString('hex')}`;
      answer = {flows: subject && source &&
        [...setupReads, ...observeReads].every(observed) ? [{
          family: 'contextual-preview-transform',
          why: 'A fresh workspace context may affect the preview result',
          priority: 9, as: 'anonymous',
          prelude: [...setupReads.slice(0, 2).map(step), step(source.path),
            ...setupReads.slice(2).map(step)],
          subject: {method: 'GET', path: subject.path, placement: 'query',
            key: 'expression', fixedFields: [], bodyTemplate: '', headers: []},
          observe: observeReads.map(step),
          binding: {from: 2, pointer: '/workspace/id', to: 'subject',
            index: 0, key: 'workspace'},
          controlValue: 'plain', firstValue: encoded(context.marker),
          secondValue: encoded(context.secondMarker), marker: context.marker,
          secondMarker: context.secondMarker,
          assertion: {step: 'subject', index: 0, location: 'body', name: ''}}] : []};
    } else answer = blank(call.text.format.schema);
    response.setHeader('content-type', 'application/json');
    response.end(JSON.stringify({status: 'completed', output: [{type: 'message',
      role: 'assistant', content: [{type: 'output_text', text: JSON.stringify(answer)}]}]}));
  });
  await new Promise(resolve => modelServer.listen(0, '127.0.0.1', resolve));
  t.after(() => {modelServer.closeAllConnections(); modelServer.close();});
  const modelOrigin = `http://127.0.0.1:${modelServer.address().port}/v1`;
  await execute('init', [root]);
  await execute('model add', ['sequence-fixture'], {project: root, provider: 'custom',
    'base-url': modelOrigin, model: 'fixture',
    'secret-env': 'BYPASS_SEQUENCE_FIXTURE_KEY', transport: 'responses',
    'response-mode': 'json-schema', stream: false});
  const env = {BYPASS_SEQUENCE_FIXTURE_KEY: 'unit-fixture-key'};
  const cli = async (...args) => {
    const completed = await execFile(process.execPath,
      [CLI, 'blackbox', ...args, '--project', root, '--json', '--non-interactive'],
      {cwd: root, env, timeout: 90000});
    return {code: completed.code, data: JSON.parse(completed.stdout)};
  };
  const audit = await cli(origin, '--scope', scopePath, '--rps', '20');
  const web = JSON.parse(fs.readFileSync(path.join(audit.data.runDir,
    'web-probes.json'), 'utf8'));
  const surface = JSON.parse(fs.readFileSync(path.join(audit.data.runDir,
    'surface.json'), 'utf8'));
  const finding = audit.data.findings.find(item => item.kind === 'model-http-sequence');
  assert.ok(web.strategyDecisions.some(item => item.mode === 'http-sequence' &&
    item.accepted), JSON.stringify({decisions: web.strategyDecisions,
      routes: surface.patterns.map(item => ({path: item.pattern,
        params: item.params, shape: item.fingerprint?.anonymous?.shape})),
      modelCoverage: web.modelCoverage, modelError: audit.data.modelError}));
  const accepted = web.strategyDecisions.find(item => item.mode === 'http-sequence' &&
    item.accepted);
  assert.deepEqual(accepted.requestShape.preludePaths,
    [...setupReads.slice(0, 2), prepare, ...setupReads.slice(2)]);
  assert.deepEqual(accepted.requestShape.observePaths, observeReads);
  assert.equal(finding?.verdict, 'observed');
  assert.equal(finding.severity, 'unrated');
  assert.equal(finding.webProof.prelude.length, 5);
  assert.equal(finding.webProof.observe.length, 3);
  assert.equal(finding.webProof.binding.from, 2);
  assert.equal(finding.webProof.binding.pointer, '/workspace/id');
  assert.equal(finding.webProof.bindingReview.sourceAs, 'anonymous');
  assert.ok(finding.webProof.bindingReview.sourceEvidenceId);
  assert.ok(requested.filter(item => item.startsWith(`GET ${transform}?`) &&
    item.includes('workspace=w-')).length >= 3);
  for (const route of [...setupReads, ...observeReads])
    assert.ok(requested.filter(item => item === `GET ${route}`).length >= 3,
      `the long sequence did not run ${route} in every phase`);
  assert.ok(!requested.some(item => item.startsWith(`GET ${decoy}`)));
  assert.equal((await cli('verify', audit.data.run)).code, 1);
  const exported = await cli('export', audit.data.run, '--out', path.join(root, 'regression'));
  assert.equal(exported.code, 0);
  const regression = () => new Promise((resolve, reject) => {
    const child = spawn(process.execPath, ['--test', ...exported.data.files],
      {env: Object.fromEntries(Object.entries(process.env).filter(([key]) =>
        key !== 'NODE_TEST_CONTEXT')), stdio: 'ignore'});
    child.once('error', reject);
    child.once('close', resolve);
  });
  assert.equal(await regression(), 1);
  vulnerable = false;
  assert.equal((await cli('verify', audit.data.run)).code, 0);
  assert.equal(await regression(), 0);
});
