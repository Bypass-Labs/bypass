import assert from 'node:assert/strict';
import fs from 'node:fs';
import {randomBytes} from 'node:crypto';
import {createServer} from 'node:http';
import os from 'node:os';
import path from 'node:path';
import {after, test} from 'node:test';
import {planAccessBoundaries, runAccessBoundaries} from '../src/blackbox/access-boundary.mjs';
import {contentBoundaryShapeReason, protectedContentMatch,
  verifyContentBoundary} from '../src/blackbox/content-boundary.mjs';
import {loadScope} from '../src/blackbox/scope.mjs';

const privateBody = 'Private export for a test account. This record is deliberately long enough ' +
  'to make an accidental exact match implausible. Its bytes belong only to the owner.\n';
let mode = 'vulnerable';
let stickyState = 'Public result before the first candidate.';
let sequence = 0;
const requests = [];
const server = createServer((request, response) => {
  const url = new URL(request.url, 'http://127.0.0.1');
  requests.push({path: url.pathname, query: url.searchParams.get('name'),
    auth: request.headers.authorization ?? '', noCache: request.headers['cache-control']});
  response.setHeader('content-type', 'text/plain; charset=utf-8');
  if (url.pathname === '/private/export') {
    if (request.headers.authorization !== 'Bearer fixture-owner') {
      response.writeHead(403);
      response.end('Denied');
      return;
    }
    response.end(privateBody);
    return;
  }
  if (url.pathname === '/public/download') {
    const name = url.searchParams.get('name');
    if (mode === 'ordinary-positive' ||
        mode === 'vulnerable' && ['all', 'archive'].includes(name) ||
        ['single-positive', 'cached-positive'].includes(mode) && name === 'all') {
      if (mode === 'cached-positive') response.setHeader('x-cache', 'HIT');
      response.end(privateBody);
      return;
    }
    response.end(`Public result for ${name ?? 'none'}.`);
    return;
  }
  if (url.pathname === '/public/sticky') {
    if (url.searchParams.get('name') === 'first') stickyState = privateBody;
    response.end(stickyState);
    return;
  }
  response.writeHead(404);
  response.end('Not found');
});
await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
after(() => server.close());
const origin = `http://127.0.0.1:${server.address().port}`;

async function requester({url, identity, headers}) {
  const response = await fetch(new URL(url, origin), {headers: {
    ...headers, ...(identity === 'owner' ? {authorization: 'Bearer fixture-owner'} : {})}});
  return {status: response.status, body: await response.text(),
    headers: Object.fromEntries(response.headers), evidenceId: `ev-${++sequence}`};
}
const trial = () => verifyContentBoundary({requester,
  protectedRequest: {url: '/private/export', method: 'GET'},
  makeCandidate: value => ({url: `/public/download?name=${encodeURIComponent(value)}`,
    method: 'GET', identity: 'anonymous'}),
  controlValue: 'normal', firstValue: 'all', secondValue: 'archive'});

test('exact owner-only content leak confirms with fresh uncached controls and clears after repair', async () => {
  mode = 'vulnerable';
  requests.length = 0;
  const vulnerable = await trial();
  assert.equal(vulnerable.verdict, 'confirmed');
  assert.equal(vulnerable.controls.at(-1).firstMatches, true);
  assert.equal(vulnerable.controls.at(-1).secondMatches, true);
  assert.ok(requests.every(item => item.noCache === 'no-cache'));
  assert.ok(!JSON.stringify(vulnerable).includes(privateBody));
  assert.equal(requests.filter(item => item.path === '/private/export' && !item.auth).length, 2);
  mode = 'fixed';
  const fixed = await trial();
  assert.equal(fixed.verdict, 'not_reproduced');
});

test('ordinary public availability and an unstable control cannot become a finding', async () => {
  mode = 'ordinary-positive';
  const publicContent = await trial();
  assert.equal(publicContent.verdict, 'inconclusive');
  assert.match(publicContent.reason, /ordinary public input/);
  assert.equal(protectedContentMatch({status: 200, body: privateBody},
    {status: 200, body: privateBody.slice(0, -1)}), false);
});

test('exact-content boundary captures an owner document larger than the old 8 KiB cap', async () => {
  const document = `Owner test document\n${'x'.repeat(200 * 1024)}`;
  let calls = 0;
  const largeRequester = async ({url, identity, maxBytes}) => {
    calls++;
    assert.ok(maxBytes >= Buffer.byteLength(document));
    const requested = new URL(url, origin);
    const denied = requested.pathname === '/private/export' && identity !== 'owner';
    const candidate = requested.pathname === '/public/download';
    const positive = ['all', 'archive'].includes(requested.searchParams.get('name'));
    return {status: denied ? 403 : 200,
      body: denied ? 'Denied' : !candidate || positive ? document : 'Ordinary public result',
      headers: {}, evidenceId: `large-${calls}`};
  };
  const result = await verifyContentBoundary({requester: largeRequester,
    protectedRequest: {url: '/private/export', method: 'GET'},
    makeCandidate: value => ({url: `/public/download?name=${value}`,
      method: 'GET', identity: 'anonymous'}),
    controlValue: 'normal', firstValue: 'all', secondValue: 'archive'});
  assert.equal(result.verdict, 'confirmed');
  assert.ok(calls >= 7);
});

test('one positive candidate needs a fresh repeat; cached positives are rejected', async () => {
  mode = 'single-positive';
  const repeated = await trial();
  assert.equal(repeated.verdict, 'confirmed');
  assert.equal(repeated.controls.at(-1).repeated, true);
  assert.equal(repeated.controls.at(-1).baselineExcluded, true);
  mode = 'cached-positive';
  const cached = await trial();
  assert.equal(cached.verdict, 'inconclusive');
});

test('a declared private JSON field confirms inside a different wrapper without saving its value', async () => {
  const secret = randomBytes(18).toString('hex');
  let vulnerable = true, count = 0, declaration = true;
  const jsonRequester = async ({url, identity}) => {
    const path = new URL(url, origin);
    const owner = path.pathname === '/private/record';
    const status = owner && identity !== 'owner' ? 403 : 200;
    const positive = ['wide-one', 'wide-two'].includes(path.searchParams.get('term'));
    const body = status === 403 ? JSON.stringify({error: 'denied'}) :
      owner ? JSON.stringify({owner: 'test-owner', ...(declaration ? {private: true} : {}),
        secret, nonce: ++count}) :
        JSON.stringify({requestId: ++count, result: vulnerable && positive ?
          {secret} : {items: []}});
    return {status, body, type: 'application/json', headers: {'content-type': 'application/json'},
      evidenceId: `json-${count}`};
  };
  const run = () => verifyContentBoundary({requester: jsonRequester,
    protectedRequest: {url: '/private/record', method: 'GET'},
    makeCandidate: value => ({url: `/public/filter?term=${value}`,
      method: 'GET', identity: 'anonymous'}),
    controlValue: 'plain', firstValue: 'wide-one', secondValue: 'wide-two',
    comparison: 'json-field'});
  const found = await run();
  assert.equal(found.verdict, 'confirmed');
  assert.equal(found.controls.find(item => item.label === 'content-boundary')?.mode,
    'json-field');
  assert.ok(JSON.stringify(found.controls.find(item => item.label === 'owner-control')?.shape)
    .includes('secret'));
  assert.ok(JSON.stringify(found.controls.find(item => item.label === 'candidate-one')?.shape)
    .includes('result'));
  assert.ok(!JSON.stringify(found).includes(secret));
  vulnerable = false;
  assert.equal((await run()).verdict, 'not_reproduced');
  assert.match((await verifyContentBoundary({requester: jsonRequester,
    protectedRequest: {url: '/private/record', method: 'GET'},
    makeCandidate: value => ({url: `/public/filter?term=${value}`,
      method: 'GET', identity: 'anonymous'}),
    controlValue: 'plain', firstValue: secret, secondValue: 'archive',
    comparison: 'json-field'})).reason, /submitted as input/);
  declaration = false;
  vulnerable = true;
  assert.equal((await run()).verdict, 'inconclusive');
});

test('a common private note without owner linkage is inconclusive', async () => {
  const note = 'Ordinary quarterly update';
  let count = 0;
  const jsonRequester = async ({url, identity}) => {
    const path = new URL(url, origin);
    const owner = path.pathname === '/private/record';
    const positive = ['wide-one', 'wide-two'].includes(path.searchParams.get('term'));
    const status = owner && identity !== 'owner' ? 403 : 200;
    const body = status === 403 ? JSON.stringify({error: 'denied'}) : owner ?
      JSON.stringify({private: true, owner: 'test-owner', note, nonce: ++count}) :
      JSON.stringify({result: positive ? {note} : {items: []}});
    return {status, body, type: 'application/json',
      evidenceId: `common-${++count}`};
  };
  const result = await verifyContentBoundary({requester: jsonRequester,
    protectedRequest: {url: '/private/record', method: 'GET'},
    makeCandidate: value => ({url: `/public/filter?term=${value}`,
      method: 'GET', identity: 'anonymous'}),
    controlValue: 'plain', firstValue: 'wide-one', secondValue: 'wide-two',
    comparison: 'json-field'});
  assert.equal(result.verdict, 'inconclusive');
  assert.match(result.reason, /lacked an owner link/);
  assert.ok(!JSON.stringify(result).includes(note));
});

test('a public route echoing a client-supplied private field stays inconclusive', async () => {
  const secret = `private-${randomBytes(18).toString('hex')}`;
  let count = 0, sent = 0;
  const jsonRequester = async request => {
    sent++;
    const path = new URL(request.url, origin);
    const owner = path.pathname === '/private/record';
    const status = owner && request.identity !== 'owner' ? 403 : 200;
    const positive = ['wide-one', 'wide-two'].includes(path.searchParams.get('term'));
    const copy = path.searchParams.get('copy');
    const body = status === 403 ? JSON.stringify({error: 'denied'}) : owner ?
      JSON.stringify({private: true, owner: 'test-owner', secret,
        nonce: ++count}) : JSON.stringify({result: positive ? {secret: copy} : {items: []}});
    if (copy === secret) assert.deepEqual(request.redactValues, [secret]);
    return {status, body, type: 'application/json',
      evidenceId: `echo-${++count}`};
  };
  const result = await verifyContentBoundary({requester: jsonRequester,
    protectedRequest: {url: '/private/record', method: 'GET'},
    makeCandidate: value => ({url: `/public/filter?term=${value}&copy=${encodeURIComponent(secret)}`,
      method: 'GET', identity: 'anonymous'}),
    controlValue: 'plain', firstValue: 'wide-one', secondValue: 'wide-two',
    comparison: 'json-field'});
  assert.equal(result.verdict, 'inconclusive');
  assert.match(result.reason, /supplied by the client/);
  assert.ok(sent >= 7);
  assert.ok(!JSON.stringify(result).includes(secret));
});

test('a stateful follow-up cannot turn the second candidate into stale owner content', async () => {
  stickyState = 'Public result before the first candidate.';
  const result = await verifyContentBoundary({requester,
    protectedRequest: {url: '/private/export', method: 'GET'},
    runCandidate: async value => {
      const response = await requester({url: `/public/sticky?name=${value}`,
        identity: 'anonymous', headers: {'cache-control': 'no-cache'}});
      return {response, steps: [{response, label: 'observe', method: 'GET',
        path: '/public/sticky', identity: 'anonymous'}], complete: true};
    }, controlValue: 'normal', firstValue: 'first', secondValue: 'second'});
  assert.equal(result.verdict, 'inconclusive');
  assert.match(result.reason, /ordinary control did not restore/);
  assert.equal(result.controls.find(item => item.label === 'public-reset-between')?.hash,
    result.controls.find(item => item.label === 'candidate-one')?.hash);
});

test('Muse can choose exact-content comparison from observed GET and owner-only read', async t => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'bypass-content-boundary-'));
  t.after(() => fs.rmSync(dir, {recursive: true, force: true}));
  const file = path.join(dir, 'scope.json');
  fs.writeFileSync(file, JSON.stringify({schemaVersion: 1, target: {origin},
    include: ['/'], identities: {identityPath: '/private/export'},
    limits: {rps: 100}}));
  const scope = loadScope({file, origin}).scope;
  const surface = {patterns: [
    {pattern: '/private/export', methods: ['GET'],
      fingerprint: {owner: {status: 200, type: 'text/plain',
        bytes: Buffer.byteLength(privateBody)}, anonymous: {status: 403}}},
    {pattern: '/public/download', methods: ['GET'],
      params: {name: ['normal']}, fingerprint: {anonymous: {status: 200}}},
  ]};
  const proposal = {family: 'private export disclosure',
    why: 'A public download selector might return the owner export', priority: 8,
    comparison: 'exact-body', protectedPath: '/private/export',
    subject: {method: 'GET', path: '/public/download', placement: 'query',
      key: 'name', fixedFields: []},
    controlValue: 'normal', firstValue: 'all', secondValue: 'archive',
    ownerPointer: '', candidatePointer: '', identityField: '', matchFields: []};
  assert.equal(contentBoundaryShapeReason(proposal), null);
  const infer = async (_model, messages) => {
    const context = JSON.parse(messages[1].content);
    assert.equal(context.protectedReads[0].ownerType, 'text/plain');
    assert.equal(context.protectedReads[0].ownerBytes,
      Buffer.byteLength(privateBody));
    return {tests: [proposal]};
  };
  const env = {OWNER_TOKEN: 'fixture-owner'};
  const planned = await planAccessBoundaries(surface, scope, {infer,
    model: 'fixture', env, budget: 1, modelCallsAvailable: 1});
  assert.equal(planned.leads.length, 1);
  mode = 'vulnerable';
  const vulnerable = await runAccessBoundaries(planned.leads, scope,
    {requester, surface, env, modelCallsAvailable: 0});
  assert.equal(vulnerable.results[0].verdict, 'confirmed');
  assert.equal(vulnerable.findings[0].webProof.comparison, 'exact-body');
  assert.match(vulnerable.findings[0].rule, /exact-body-two-candidates/);
  mode = 'fixed';
  const fixed = await runAccessBoundaries(planned.leads, scope,
    {requester, surface, env, modelCallsAvailable: 0});
  assert.equal(fixed.results[0].verdict, 'not_reproduced');
  assert.equal(fixed.findings.length, 0);
});
