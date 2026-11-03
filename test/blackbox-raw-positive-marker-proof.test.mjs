import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import http from 'node:http';
import os from 'node:os';
import path from 'node:path';
import {randomBytes} from 'node:crypto';
import {createLedger} from '../src/blackbox/ledger.mjs';
import {proveFindings} from '../src/blackbox/poc.mjs';
import {rawBoundaryOutcome} from '../src/blackbox/poc-runtime.mjs';
import {validateResearchFlow, runResearchFlows} from '../src/blackbox/research-flow.mjs';
import {createRequester, loadScope} from '../src/blackbox/scope.mjs';
import {execFile} from '../src/util.mjs';

test('raw proof repeats an in-band marker when public and negative controls differ', async t => {
  const marker = `private_${randomBytes(10).toString('hex')}`;
  const route = `/preview-${randomBytes(4).toString('hex')}`;
  const internal = http.createServer((request, response) => {
    response.setHeader('cache-control', 'no-store');
    response.end(request.url === '/private' ? marker : 'internal path absent');
  });
  await new Promise(resolve => internal.listen(0, '127.0.0.1', resolve));
  t.after(() => new Promise(resolve => internal.close(resolve)));
  const internalOrigin = `http://127.0.0.1:${internal.address().port}`;
  let vulnerable = true;
  const app = http.createServer(async (request, response) => {
    response.setHeader('cache-control', 'no-store');
    if (request.url === '/public') return response.end('public information');
    if (request.url !== route || request.method !== 'POST') {
      response.statusCode = 404;
      return response.end('not found');
    }
    let body = '';
    for await (const chunk of request) body += chunk;
    const sourceUrl = JSON.parse(body).sourceUrl;
    if (!vulnerable && sourceUrl.startsWith(internalOrigin))
      return response.end('destination blocked');
    const fetched = await fetch(sourceUrl);
    response.end(await fetched.text());
  });
  await new Promise(resolve => app.listen(0, '127.0.0.1', resolve));
  t.after(() => new Promise(resolve => app.close(resolve)));
  const origin = `http://127.0.0.1:${app.address().port}`;
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'bypass-inband-proof-'));
  t.after(() => fs.rmSync(dir, {recursive: true, force: true}));
  const scope = loadScope({origin, overrides: {acceptLocal: true}}).scope;
  const raw = sourceUrl => ({method: 'POST', path: route,
    headers: [{name: 'Content-Type', value: 'application/json'}],
    body: JSON.stringify({sourceUrl})});
  const candidate = raw(`${internalOrigin}/private`);
  const proof = {baseline: [raw(`${origin}/public`)],
    negative: [raw(`${internalOrigin}/absent`)],
    closedText: 'internal path absent', openText: marker};
  const surface = {patterns: [{pattern: route, methods: ['POST'], params: {}}],
    focus: {findingId: 'fixture-source-finding', path: route, method: 'POST',
      sourceSnapshotMatches: true, category: 'Server-side request forgery',
      hypothesis: 'The server fetches an untrusted URL and returns its internal response.',
      source: {file: 'src/preview.ts', line: 1,
        quote: 'const response = await fetch(sourceUrl)'}}};
  const reviewed = validateResearchFlow({family: 'in-band fetched content',
    why: 'A URL input may return private content', priority: 8, as: 'anonymous',
    oracle: 'raw-proof', rawRequests: [candidate], rawProof: proof},
  surface, scope);
  assert.equal(reviewed.ok, true, JSON.stringify(reviewed.decision));
  const ledger = createLedger(dir);
  t.after(() => ledger.close());
  const run = await runResearchFlows([reviewed.lead], scope,
    {surface, ledger,
      requester: createRequester(scope, {ledger, allowLocal: true}),
      modelCallsAvailable: 0});
  assert.equal(run.results[0].verdict, 'confirmed', JSON.stringify(run.results[0]));
  assert.equal(run.findings[0]?.kind, 'model-raw-boundary');
  const proved = await proveFindings([{...run.findings[0], id: 'f-001'}], [],
    {runDir: dir, scope, surface: {}, env: {}, ledger, web: run});
  assert.equal(proved.length, 1);
  vulnerable = false;
  const fixed = await execFile(process.execPath, [proved[0].proof, '--expect-fixed'],
    {env: process.env, timeout: 20000});
  assert.equal(fixed.code, 0, fixed.stdout);
});

test('raw positive marker cannot be reflected from the submitted request', () => {
  const marker = `private_${randomBytes(8).toString('hex')}`;
  const route = `/preview-${randomBytes(4).toString('hex')}`;
  const request = [{method: 'POST', path: route, body: JSON.stringify({hint: marker})}];
  const proof = {baseline: [{path: route}], negative: [{path: route}],
    closedText: '', openText: marker};
  const response = body => ({status: 200, type: 'text/plain', body});
  const result = rawBoundaryOutcome([
    response('public'), response('missing'), response(marker),
    response(marker), response('missing'), response('public')], proof, request);
  assert.equal(result.verdict, 'inconclusive');
});

test('URL-encoded request reflection cannot seal a positive marker proof', () => {
  const marker = `private_${randomBytes(8).toString('hex')}`;
  const encoded = [...Buffer.from(marker)].map(byte =>
    `%${byte.toString(16).padStart(2, '0')}`).join('');
  const route = `/preview-${randomBytes(4).toString('hex')}`;
  const request = [{method: 'GET', path: `${route}?hint=${encoded}`}];
  const proof = {baseline: [{path: route}], negative: [{path: route}],
    openText: marker};
  const response = body => ({status: 200, type: 'text/plain', body});
  const result = rawBoundaryOutcome([
    response('public'), response('missing'), response(marker),
    response(marker), response('missing'), response('public')], proof, request);
  assert.equal(result.verdict, 'inconclusive');
});

test('standalone double-decoded reflection remains research, not a finding', async t => {
  const marker = `echo_${randomBytes(8).toString('hex')}`;
  const route = `/decode-${randomBytes(4).toString('hex')}`;
  const app = http.createServer((request, response) => {
    const url = new URL(request.url, 'http://fixture.invalid');
    response.setHeader('cache-control', 'no-store');
    response.setHeader('content-type', 'text/plain');
    response.end(decodeURIComponent(url.searchParams.get('value') ?? ''));
  });
  await new Promise(resolve => app.listen(0, '127.0.0.1', resolve));
  t.after(() => new Promise(resolve => app.close(resolve)));
  const origin = `http://127.0.0.1:${app.address().port}`;
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'bypass-reflected-marker-'));
  t.after(() => fs.rmSync(dir, {recursive: true, force: true}));
  const scope = loadScope({origin, overrides: {acceptLocal: true}}).scope;
  const raw = value => ({method: 'GET', path: `${route}?value=${value}`,
    headers: [], body: ''});
  const once = [...Buffer.from(marker)].map(byte =>
    `%${byte.toString(16).padStart(2, '0')}`).join('');
  const proposal = {family: 'decoded response', why: 'Inspect a visible transformation',
    priority: 5, as: 'anonymous', oracle: 'raw-proof',
    rawRequests: [raw(encodeURIComponent(once))],
    rawProof: {baseline: [raw('plain')], negative: [raw('other')],
      openText: marker}};
  const surface = {patterns: [{pattern: route, methods: ['GET'], params: {value: []}}]};
  const reviewed = validateResearchFlow(proposal, surface, scope);
  assert.equal(reviewed.ok, true, JSON.stringify(reviewed));
  const ledger = createLedger(dir);
  t.after(() => ledger.close());
  const run = await runResearchFlows([reviewed.lead], scope, {surface, ledger,
    requester: createRequester(scope, {ledger, allowLocal: true}),
    modelCallsAvailable: 0});
  assert.equal(run.results[0].verdict, 'inconclusive');
  assert.equal(run.findings.length, 0);
  assert.match(run.results[0].reason, /marker is ambiguous or supplied by the request/);
});
