import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import http from 'node:http';
import path from 'node:path';
import {temp} from './helpers.mjs';
import {DEFAULT_SCOPE} from '../src/blackbox/scope.mjs';
import {createLedger} from '../src/blackbox/ledger.mjs';
import {reviewSource} from '../src/blackbox/source.mjs';
import {runWebProbes} from '../src/blackbox/web-probes.mjs';
import {proveFindings} from '../src/blackbox/poc.mjs';
import {renderReport} from '../src/blackbox/report.mjs';

test('source review preserves a bounded private-record lead without response values', async t => {
  const root = temp();
  t.after(() => fs.rmSync(root, {recursive: true, force: true}));
  fs.writeFileSync(path.join(root, 'server.js'),
    "app.get('/v2/api/user/:id', (req, res) => {\n" +
    "  const row = users[req.params.id];\n" +
    "  res.json({email: row.email, phone: row.phone, clearance: row.clearance});\n" +
    "});\n");
  const reviewed = await reviewSource(root);
  const lead = reviewed.securityLeads.find(item => item.path === '/v2/api/user/:id');
  assert.ok(lead, JSON.stringify(reviewed.securityLeads));
  assert.equal(lead.verdict, 'unproven');
  assert.deepEqual(lead.fields, ['email', 'phone', 'clearance']);
  assert.ok(!JSON.stringify(lead).includes('users[1]'));
});

test('source private-record verifier uses two anonymous IDs twice and stores no PII values', async t => {
  const root = temp();
  t.after(() => fs.rmSync(root, {recursive: true, force: true}));
  const ledger = createLedger(root);
  const scope = structuredClone(DEFAULT_SCOPE);
  const sourceLead = {id: 'source-private-user', title: 'Private user dossier is returned anonymously',
    category: 'sensitive-data', path: '/v2/api/user/:id', method: 'GET',
    hypothesis: 'Anonymous users may receive email, phone and clearance fields.',
    remediation: 'Require authentication and object authorization.',
    fields: ['email', 'phone', 'clearance'], verdict: 'unproven',
    source: {file: 'server.ts', line: 151, quote: 'email: target.email'}};
  const values = {1: {email: 'alpha@example.test', phone: '+15550000001', clearance: 'red'},
    2: {email: 'beta@example.test', phone: '+15550000002', clearance: 'blue'}};
  let sequence = 0;
  const checked = await runWebProbes({patterns: [], sourceReview: {securityLeads: [sourceLead]}},
    scope, {budget: 1, ledger, researchDeadline: Date.now() + 10_000,
      requester: async ({url}) => {
        const id = new URL(url, scope.target.origin).pathname.split('/').at(-1);
        return {status: 200, type: 'application/json', body: JSON.stringify(values[id]),
          headers: {'cache-control': 'no-store'}, evidenceId: ledger.append({step: 'task',
            request: {url}, response: {status: 200, hash: `response-${++sequence}`}})};
      }});
  assert.equal(checked.findings.length, 1, JSON.stringify(checked.results));
  assert.equal(checked.findings[0].sourceFinding.id, sourceLead.id);
  assert.equal(checked.results[0].verdict, 'confirmed');
  const stored = fs.readFileSync(ledger.file, 'utf8');
  for (const record of Object.values(values)) for (const value of Object.values(record))
    assert.ok(!stored.includes(value), `ledger stored ${value}`);
});

test('failed rate-limit proof matches its field lead and becomes an explained inconclusive signal', async t => {
  const root = temp();
  t.after(() => fs.rmSync(root, {recursive: true, force: true}));
  const server = http.createServer((_request, response) => {
    response.writeHead(429, {'content-type': 'application/json', 'retry-after': '60'});
    response.end('{"error":"throttled"}');
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  t.after(() => new Promise(resolve => server.close(resolve)));
  const origin = `http://127.0.0.1:${server.address().port}`;
  const scope = structuredClone(DEFAULT_SCOPE);
  scope.target.origin = origin;
  scope.credentialOrigins = [origin];
  const ledger = createLedger(root);
  const lead = {path: '/api/auth/login', parameter: 'password', field: 'password',
    userField: 'email', fields: ['email', 'password'], mode: 'login', placement: 'json',
    contentType: 'application/json', purpose: 'json-body'};
  const finding = {id: 'finding-rate', kind: 'rate-limit-auth-gate',
    title: 'No login throttling', severity: 'medium', pattern: lead.path,
    url: `${origin}${lead.path}`, verdict: 'confirmed', evidence: [], confirmation: [],
    webProof: {kind: 'rate-limit-auth-gate', request: {method: 'POST',
      url: `${origin}${lead.path}`, as: 'anonymous'}, mode: 'login', placement: 'json',
      field: 'password', userField: 'email', fields: ['email', 'password'],
      contentType: 'application/json', attemptCount: 20, minimumRps: 5}};
  const web = {results: [{lead, origin, kind: 'rate-limit-auth-gate',
    verdict: 'confirmed', reason: 'initial positive signal', evidence: []}]};
  const kept = await proveFindings([finding], [], {runDir: root,
    surface: {patterns: []}, scope, env: {}, ledger, web});
  assert.deepEqual(kept, []);
  assert.equal(web.results[0].initialVerdict, 'confirmed');
  assert.equal(web.results[0].verdict, 'inconclusive');
  assert.match(web.results[0].reason, /Positive signal found; final proof replay was inconclusive/);
  assert.equal(web.results[0].proofReplay.verdict, 'inconclusive');
});

test('combined report keeps source findings and labels each live-validation status', () => {
  const scope = structuredClone(DEFAULT_SCOPE);
  const leads = ['confirmed', 'negative', 'open', 'untested'].map((name, index) => ({
    id: `source-${name}`, title: `${name} source lead`, category: 'authorization',
    path: `/api/user/:id/${index}`, method: 'GET', hypothesis: `${name} hypothesis`,
    remediation: 'Enforce authorization.', fields: [], verdict: 'unproven',
    source: {file: 'server.ts', line: 10 + index, quote: 'route handler'}}));
  const finding = {id: 'finding-live', kind: 'model-anonymous-json-disclosure',
    title: 'confirmed source lead', severity: 'medium', pattern: leads[0].path,
    url: `${scope.target.origin}/api/user/1/0`, host: '127.0.0.1:4329', task: null,
    verdict: 'confirmed', rule: 'confirmed/live', evidence: [], confirmation: [],
    mirror: {result: 'unverified', evidence: []}, tags: [], reach: {observed: 2},
    dataClasses: [], remediation: leads[0].remediation, foundBy: 'source-assisted',
    status: 'open', sourceFinding: {id: leads[0].id}};
  const report = renderReport({run: 'bx-source-status', scope, scopeHash: 'test',
    surface: {patterns: [], sourceReview: {securityLeads: leads, files: [], notes: [],
      secretLeads: [], stats: {files: 1, skipped: 0, filesCut: 0, routesCut: 0}}},
    findings: [finding], results: [], web: {results: [
      {sourceLeadId: leads[1].id, verdict: 'not_reproduced', reason: 'anonymous reads denied', evidence: [], lead: {path: '/api/user/1/1'}},
      {sourceLeadId: leads[2].id, verdict: 'inconclusive', reason: 'response changed', evidence: [], lead: {path: '/api/user/1/2'}},
    ]}});
  assert.deepEqual(report.json.surface.application.sourceFindings.map(item => item.status),
    ['confirmed live', 'not reproduced', 'inconclusive', 'not tested']);
  assert.match(report.markdown, /Source findings and live validation/);
  assert.match(report.markdown, /source findings remain unproven unless the status is \*\*confirmed live\*\*/i);
});
