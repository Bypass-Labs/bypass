import test from 'node:test';
import assert from 'node:assert/strict';
import {loadScope} from '../src/blackbox/scope.mjs';
import {runStoredXss} from '../src/blackbox/stored-xss.mjs';
import {runSessionChains} from '../src/blackbox/session-chain.mjs';
import {inspectGraphql} from '../src/blackbox/graphql.mjs';
import {executeResearchFlow} from '../src/blackbox/research-flow.mjs';
import {MODEL_RESPONSE_BYTES} from '../src/blackbox/response-size.mjs';
import {anonymousCredentialExposure, captureSequenceScalar} from '../src/blackbox/poc-runtime.mjs';
import {auditPublicPrivateKeys} from '../src/blackbox/secret-exposure.mjs';
import {runWebProbes} from '../src/blackbox/web-probes.mjs';

const {scope} = loadScope({origin: 'http://127.0.0.1:4329', overrides: {acceptLocal: true}});
const oversized = {blocked: true, reason: 'Response exceeds size limit', evidenceId: 'ev-size'};

test('oversized stored HTML and account reads remain unassessed', async () => {
  const xss = await runStoredXss([{path: '/api/comments', viewPath: '/comments',
    viewAs: 'anonymous', postAs: 'anonymous', parameter: 'text', fixedFields: [],
    style: 'html-double'}], scope, {requester: async () => oversized});
  assert.equal(xss.results[0].verdict, 'inconclusive');
  assert.match(xss.results[0].reason, /capture byte limit/);
  assert.equal(xss.findings.length, 0);

  const session = await runSessionChains([{path: '/public', privatePath: '/account',
    sourcePath: '/public', tokenPointer: '/token'}], scope,
  {requester: async request => request.identity === 'owner' ? oversized :
    {status: 403, evidenceId: 'ev-denied'}});
  assert.equal(session.results[0].verdict, 'inconclusive');
  assert.match(session.results[0].reason, /capture byte limit/);
  assert.equal(session.findings.length, 0);
});

test('large schema and public asset reads are recorded as size cuts', async () => {
  const graphql = await inspectGraphql(scope, {observed: [{path: '/graphql'}],
    requester: async () => oversized});
  assert.equal(graphql.attempts[0].result, 'response-size-cut');
  assert.equal(graphql.coverage.responseSizeCut, 1);

  const keys = await auditPublicPrivateKeys([{files: [{url: `${scope.target.origin}/assets/app.js`,
    secrets: [{name: 'private-key', public: false}]}]}], scope,
  {requester: async () => oversized});
  assert.equal(keys.results[0].verdict, 'inconclusive');
  assert.match(keys.results[0].reason, /capture byte limit/);
  assert.equal(keys.findings.length, 0);
});

test('HTTP sequence feedback treats an oversized response as unassessed', async () => {
  const lead = {oracle: 'observation', prelude: [], observe: [],
    subject: {path: '/api/search', method: 'GET', placement: 'query', key: 'q',
      headers: [], fixedFields: []},
    assertion: {step: 'subject', index: 0, location: 'body', name: ''},
    controlValue: 'plain', firstValue: 'first', secondValue: 'second',
    marker: 'bxfirst', secondMarker: 'bxsecond'};
  const result = await executeResearchFlow(lead, async () => oversized);
  assert.equal(result.verdict, 'inconclusive');
  assert.match(result.reason, /capture byte limit/);
});

test('model HTTP sequences capture ordinary JSON responses beyond the old 8 KiB cap', async () => {
  const lead = {oracle: 'observation', prelude: [], observe: [],
    subject: {path: '/api/search', method: 'GET', placement: 'query', key: 'q',
      headers: [], fixedFields: []},
    assertion: {step: 'subject', index: 0, location: 'body', name: ''},
    controlValue: 'plain', firstValue: 'first', secondValue: 'second',
    marker: 'bxfirst', secondMarker: 'bxsecond'};
  let requests = 0;
  const result = await executeResearchFlow(lead, async request => {
    assert.equal(request.maxBytes, MODEL_RESPONSE_BYTES);
    requests++;
    return {status: 200, type: 'application/json',
      body: JSON.stringify({id: requests, padding: 'x'.repeat(20 * 1024)}),
      evidenceId: `ev-${requests}`};
  });
  assert.ok(requests >= 1);
  assert.notEqual(result.verdict, 'blocked');
  assert.doesNotMatch(result.reason ?? '', /capture byte limit/);
});

test('sequence binding reads a safe scalar from a JSON response above 8 KiB', () => {
  const body = JSON.stringify({padding: 'x'.repeat(20 * 1024), id: 42});
  assert.equal(captureSequenceScalar(body, '/id'), '42');
});

test('credential exposure proof inspects a large JSON response without storing values', () => {
  const body = JSON.stringify({padding: 'x'.repeat(600 * 1024), users: [
    {id: 1, passwordHash: `$2b$12$${'A'.repeat(53)}`},
    {id: 2, passwordHash: `$2b$12$${'B'.repeat(53)}`},
  ]});
  assert.deepEqual(anonymousCredentialExposure(body),
    {field: 'passwordHash', records: 2});
});

test('web task results do not turn an oversized response into a negative or scope block', async () => {
  const result = await runWebProbes({patterns: [{pattern: '/go',
    params: {next: []}, source: ['public-openapi']}]}, scope,
  {requester: async () => oversized, budget: 1});
  assert.equal(result.results[0].kind, 'open-redirect');
  assert.equal(result.results[0].verdict, 'inconclusive');
  assert.equal(result.results[0].sizeCut, true);
  assert.match(result.results[0].reason, /capture byte limit/);
  assert.equal(result.findings.length, 0);
});
