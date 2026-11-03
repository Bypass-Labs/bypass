import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import http from 'node:http';
import os from 'node:os';
import path from 'node:path';
import {randomBytes} from 'node:crypto';
import {createLedger} from '../src/blackbox/ledger.mjs';
import {proveFindings, exportRun} from '../src/blackbox/poc.mjs';
import {rawBoundaryOutcome, responseMarkerFingerprint} from '../src/blackbox/poc-runtime.mjs';
import {planResearchFlows, validateResearchFlow,
  runResearchFlows} from '../src/blackbox/research-flow.mjs';
import {createRequester, loadScope} from '../src/blackbox/scope.mjs';
import {execFile} from '../src/util.mjs';

test('raw proof repeats an in-band marker when public and negative controls differ', async t => {
  const marker = `INTERNAL_SEAL_${randomBytes(16).toString('hex')}`;
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
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'bypass-inband-proof-'));
  const runId = `bx-20261103-${randomBytes(4).toString('hex')}`;
  const dir = path.join(root, '.bypass', 'runs', runId);
  fs.mkdirSync(dir, {recursive: true});
  t.after(() => fs.rmSync(root, {recursive: true, force: true}));
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
  const reviewed = validateResearchFlow({family: `in-band fetched content ${marker}`,
    why: `A URL input may return private content ${marker}`, priority: 8, as: 'anonymous',
    oracle: 'raw-proof', rawRequests: [candidate], rawProof: proof},
  surface, scope);
  assert.equal(reviewed.ok, true, JSON.stringify(reviewed.decision));
  assert.equal(reviewed.lead.rawProof.openText, undefined);
  assert.equal(reviewed.lead.rawProof.openTextLength, marker.length);
  assert.equal(JSON.stringify(reviewed.lead).includes(marker), false);
  const ledger = createLedger(dir);
  t.after(() => ledger.close());
  const checkpoint = path.join(dir, 'research-checkpoint.json');
  const run = await runResearchFlows([reviewed.lead], scope,
    {surface, ledger,
      requester: createRequester(scope, {ledger, allowLocal: true}),
      modelCallsAvailable: 0,
      onResearchCheckpoint: state => fs.writeFileSync(checkpoint, JSON.stringify(state))});
  assert.equal(run.results[0].verdict, 'confirmed', JSON.stringify(run.results[0]));
  assert.equal(run.findings[0]?.kind, 'model-raw-boundary');
  const proved = await proveFindings([{...run.findings[0], id: 'f-001'}], [],
    {runDir: dir, scope, surface: {}, env: {}, ledger, web: run});
  assert.equal(proved.length, 1);
  fs.writeFileSync(path.join(dir, 'run.json'), '{}');
  const exported = exportRun(root, runId, {out: path.join(root, 'exported')});
  assert.equal(exported.files.length, 1);
  const files = folder => fs.readdirSync(folder, {withFileTypes: true}).flatMap(entry => {
    const file = path.join(folder, entry.name);
    return entry.isDirectory() ? files(file) : [file];
  });
  for (const file of files(root))
    assert.equal(fs.readFileSync(file, 'utf8').includes(marker), false,
      `response marker leaked into ${path.relative(root, file)}`);
  vulnerable = false;
  const fixed = await execFile(process.execPath, [proved[0].proof, '--expect-fixed'],
    {env: process.env, timeout: 20000});
  assert.equal(fixed.code, 0, fixed.stdout);
});

test('response marker fingerprint scans a large body without saving marker text', () => {
  const marker = `INTERNAL_SEAL_${randomBytes(16).toString('hex')}`;
  const route = `/preview-${randomBytes(4).toString('hex')}`;
  const proof = {baseline: [{path: route}], negative: [{path: route}],
    ...responseMarkerFingerprint(marker)};
  const publicBody = 'ordinary public response';
  const candidateBody = `${'x'.repeat(1024 * 1024)}${marker}`;
  const response = body => ({status: 200, type: 'text/plain', body});
  const outcome = rawBoundaryOutcome([
    response(publicBody), response('missing'), response(candidateBody),
    response(candidateBody), response('missing'), response(publicBody)],
  proof, [{method: 'POST', path: route, body: 'sourceUrl=/private'}]);
  assert.equal(outcome.verdict, 'confirmed');
  assert.equal(outcome.proofMode, 'positive-marker');
  assert.equal(JSON.stringify(proof).includes(marker), false);
});

test('a missing route is inconclusive even when every response lacks the marker', () => {
  const route = '/missing-preview';
  const proof = {baseline: [{path: route}], negative: [{path: route}],
    ...responseMarkerFingerprint('internal-response-marker')};
  const response = body => ({status: 404, type: 'application/json', body});
  const request = [{method: 'POST', path: route, body: '{}'}];
  const uniform = Array.from({length: 6}, () => response('{"error":"Unknown route"}'));
  const varied = [response('baseline'), response('negative'), response('candidate'),
    response('candidate'), response('negative'), response('baseline')];
  assert.equal(rawBoundaryOutcome(uniform, proof, request).verdict, 'inconclusive');
  assert.equal(rawBoundaryOutcome(varied, proof, request).verdict, 'inconclusive');
});

test('planning metadata masks a long response marker before truncation', async () => {
  const marker = `INTERNAL_SEAL_${randomBytes(16).toString('hex')}${'x'.repeat(320)}`;
  const origin = 'http://127.0.0.1:4329';
  const scope = loadScope({origin, overrides: {acceptLocal: true}}).scope;
  const route = '/marker-metadata';
  const raw = () => ({method: 'GET', path: route, headers: [], body: ''});
  const proposal = {family: `source ${marker}`, why: `Response contained ${marker}`,
    priority: 8, as: 'anonymous', oracle: 'raw-proof',
    rawRequests: [raw()], rawProof: {baseline: [raw()], negative: [raw()],
      openText: marker}};
  const planned = await planResearchFlows({patterns: [{pattern: route,
    methods: ['GET'], params: {}}]}, scope, {model: 'fixture',
    budget: 1, modelCallsAvailable: 1,
    infer: async () => ({flows: [proposal]})});
  assert.equal(planned.leads.length, 1);
  assert.equal(planned.leads[0].rawProof.openTextLength, marker.length);
  assert.equal(JSON.stringify(planned.leads).includes(marker.slice(0, 40)), false);
  assert.equal(JSON.stringify(planned.decisions).includes(marker.slice(0, 40)), false);
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
