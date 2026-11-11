import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import {loadScope} from '../src/blackbox/scope.mjs';
import {planResearchFlows} from '../src/blackbox/research-flow.mjs';
import {reviewSource} from '../src/blackbox/source.mjs';

test('a source fallback omitted by Muse reaches the quick live planning page', async t => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'bypass-quick-source-'));
  t.after(() => fs.rmSync(root, {recursive: true, force: true}));
  fs.writeFileSync(path.join(root, 'server.js'),
    'app.post("/api/access/unlock", (req, reply) => {\n' +
    '  const code = String(req.body.code || "");\n' +
    '  const expected = process.env.ACCESS_CODE || "sample-open";\n' +
    '  if (code !== expected) return {ok:false};\n' +
    '  return {ok:true};\n' +
    '});\n');
  const sourceReview = await reviewSource(root, {infer: async () =>
    ({notes: [], paths: [], securityLeads: [{
      title: 'Check access control', category: 'authentication-bypass',
      path: '/api/access/unlock', method: 'POST',
      hypothesis: 'The route may accept a client code.',
      remediation: 'Require a configured code.', fields: ['code'],
      file: 'server.js', line: 2,
      quote: 'const code = String(req.body.code || "");'}]}), model: 'fixture'});
  assert.equal(sourceReview.securityLeads.length, 2);
  const scope = structuredClone(loadScope({origin: 'http://127.0.0.1:49196',
    overrides: {acceptLocal: true}}).scope);
  scope.methods = ['GET', 'HEAD', 'POST'];
  scope.limits.minutes = 10;
  const surface = {sourceReview,
    jsonBodyOperations: [{path: '/api/access/unlock', method: 'POST',
      contentType: 'application/json', fields: ['code'], requiredFields: ['code']}],
    patterns: Array.from({length: 24}, (_, index) => ({
      pattern: `/api/read-${index}`, methods: ['GET'], params: {q: ['plain']}}))};
  const result = await planResearchFlows(surface, scope, {model: 'fixture',
    budget: 1, modelCallsAvailable: 1, firstPageOnly: true,
    infer: async (_model, messages) => {
      const context = JSON.parse(messages[1].content);
      assert.equal(context.routes[0].path, '/api/access/unlock');
      assert.equal(context.sourceFindings[0].path, '/api/access/unlock');
      assert.match(context.sourceFindings[0].source.quote, /sample-open/);
      return {flows: []};
    }});
  assert.equal(result.coverage.sent, 4, result.modelError ?? JSON.stringify(result.decisions));
});

test('quick audits present a small first HTTP-sequence page before broad route paging', async () => {
  const origin = 'http://127.0.0.1:49197';
  const scope = structuredClone(loadScope({origin,
    overrides: {acceptLocal: true}}).scope);
  scope.limits.minutes = 10;
  const surface = {patterns: Array.from({length: 24}, (_, index) => ({
    pattern: `/api/route-${index}`, methods: ['GET'], params: {q: ['plain']},
    responseFacts: {status: 200, type: 'application/json'}})),
  sourceReview: {securityLeads: [
    ...Array.from({length: 9}, (_, index) => ({
      id: `source-later-${index}`, path: `/api/route-${index + 10}`,
      method: 'GET', hypothesis: 'Source cites a possible access gate',
      source: {file: 'src/app.mjs', line: index + 1}})),
    {id: 'source-first', path: '/api/route-0', method: 'GET',
      hypothesis: 'Source cites a possible access gate',
      source: {file: 'src/app.mjs', line: 20}}]}};
  const pages = [], contexts = [], prompts = [], schemas = [];
  const infer = async (_model, messages, options) => {
    const context = JSON.parse(messages[1].content);
    pages.push(context.routes.map(route => route.path));
    contexts.push(context);
    prompts.push(messages[0].content);
    schemas.push(options.schema);
    return {flows: []};
  };
  const first = await planResearchFlows(surface, scope, {infer,
    model: 'fixture', budget: 1, modelCallsAvailable: 1,
    firstPageOnly: true});
  assert.equal(first.coverage.sent, 4);
  assert.equal(first.coverage.nextRouteOffset, 4);
  assert.equal(pages[0].length, 4);
  assert.equal(contexts[0].sourceFindings[0].id, 'source-first');
  assert.ok(Buffer.byteLength(prompts[0]) < 2000);
  assert.match(prompts[0], /rawProof\.openText is required/);
  assert.match(prompts[0], /observed JSON response shape/);
  assert.ok(Buffer.byteLength(JSON.stringify(schemas[0])) < 6000);
  assert.equal(schemas[0].properties.flows.maxItems, 1);

  pages.length = 0;
  const later = await planResearchFlows(surface, scope, {infer,
    model: 'fixture', budget: 1, modelCallsAvailable: 1,
    startRouteOffset: first.coverage.nextRouteOffset});
  assert.equal(later.coverage.sent, 8);
  assert.deepEqual(pages[0], Array.from({length: 8}, (_, index) =>
    `/api/route-${index + 4}`));
});

test('a compact first-page source gate still reaches the shared raw-proof validator', async () => {
  const origin = 'http://127.0.0.1:49198';
  const scope = structuredClone(loadScope({origin,
    overrides: {acceptLocal: true}}).scope);
  scope.limits.minutes = 10;
  const path = '/api/gate';
  const surface = {patterns: Array.from({length: 24}, (_, index) => ({
    pattern: index ? `/api/read-${index}` : path,
    methods: ['GET'], params: {code: ['ordinary']},
    responseFacts: {status: 200, type: 'text/plain'}})),
  sourceReview: {securityLeads: [{id: 'source-gate', path, method: 'GET',
    hypothesis: 'A cited gate may open on a fallback value',
    source: {file: 'src/app.mjs', line: 12, quote: 'fallback gate'}}]}};
  const request = value => ({method: 'GET', path: `${path}?code=${value}`});
  const plan = await planResearchFlows(surface, scope, {model: 'fixture',
    budget: 1, modelCallsAvailable: 1, firstPageOnly: true,
    infer: async (_model, messages, options) => {
      assert.equal(options.schema.properties.flows.maxItems, 1);
      assert.equal(JSON.parse(messages[1].content).sourceFindings[0].id,
        'source-gate');
      return {flows: [{family: 'access-gate', why: 'Test the cited gate',
        priority: 10, as: 'anonymous', oracle: 'raw-proof',
        sourceFindingId: 'source-gate',
        rawRequests: [request('candidate')],
        rawProof: {baseline: [request('ordinary')],
          negative: [request('invalid')], openText: 'opened',
          closedText: ''}}]};
    }});
  assert.equal(plan.coverage.accepted, 1, JSON.stringify(plan.decisions));
  assert.equal(plan.leads[0].oracle, 'raw-proof');
  assert.equal(plan.leads[0].sourceFindingId, 'source-gate');
});
