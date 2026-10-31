import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import {coverageFor} from '../src/blackbox/coverage.mjs';
import {countPendingResearchCheckpoints} from '../src/blackbox/index.mjs';

test('finished route paging still reports an accepted unexecuted HTTP lead', t => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'bypass-pending-page-'));
  t.after(() => fs.rmSync(dir, {recursive: true, force: true}));
  const file = path.join(dir, 'http-sequence-page-checkpoint.json');
  const page = {nextRouteOffset: 27, totalRoutes: 27,
    pendingLeads: [{proposalId: 'first'}, {proposalId: 'second'}],
    pendingCompletedIds: ['second']};
  fs.writeFileSync(file, JSON.stringify({pages: [page]}));
  assert.equal(countPendingResearchCheckpoints(dir), 1);
  page.pendingCompletedIds.push('first');
  fs.writeFileSync(file, JSON.stringify({pages: [page]}));
  assert.equal(countPendingResearchCheckpoints(dir), 0);
  page.nextRouteOffset = 26;
  fs.writeFileSync(file, JSON.stringify({pages: [page]}));
  assert.equal(countPendingResearchCheckpoints(dir), 1);
});

test('coverage keeps an attempted but blocked browser class untested and lists requested classes', () => {
  const scope = {target: {environment: 'local'}, discovery: {sensitivePaths: false},
    identities: {identityPath: null}};
  const blocked = coverageFor({scope, web: {results: [{kind: 'xss-reflected', verdict: 'blocked'}]}});
  assert.equal(blocked.rows.find(row => row.family === 'xss').status, 'not tested');
  assert.equal(blocked.requestedClasses.find(row => row.name === 'Reflected XSS').status, 'not tested');
  assert.equal(blocked.requestedClasses.find(row => row.name === 'Cloud Instance Credential Theft').status, 'not tested');
  assert.equal(new Set(blocked.requestedClasses.map(row => row.name)).size, blocked.requestedClasses.length);
  const checked = coverageFor({scope, web: {results: [{kind: 'xss-reflected', verdict: 'not_reproduced'}]}});
  assert.equal(checked.rows.find(row => row.family === 'xss').status, 'partial');
  assert.equal(checked.requestedClasses.find(row => row.name === 'Reflected XSS').status, 'partial');
});

test('one completed access-control kind does not claim blocked IDOR coverage', () => {
  const report = coverageFor({results: [
    {task: {kind: 'missing-auth'}, verdict: 'not_reproduced'},
    {task: {kind: 'idor'}, verdict: 'blocked'},
  ]});
  assert.equal(report.requestedClasses.find(row => row.name === 'Authentication Bypass').status, 'partial');
  assert.equal(report.requestedClasses.find(row => row.name === 'Insecure Direct Object Reference (IDOR)').status, 'not tested');
  assert.equal(report.requestedClasses.find(row => row.name === 'Broken Object Level Authorization (BOLA)').status, 'not tested');
  assert.equal(report.requestedClasses.find(row => row.name === 'Broken Access Control').status, 'partial');
});

test('a proved Muse login bypass counts as partial authentication coverage', () => {
  const report = coverageFor({web: {results: [{kind: 'model-auth-login', verdict: 'confirmed'}]}});
  for (const name of ['Authentication Bypass', 'API Authentication Bypass', 'Broken Access Control'])
    assert.equal(report.requestedClasses.find(row => row.name === name).status, 'partial');
  assert.equal(report.rows.find(row => row.family === 'session-account').status, 'partial');
  assert.equal(report.requestedClasses.find(row => row.name === 'Account Takeover (ATO)').status,
    'not tested');
});

test('local source credential scan is partial coverage, not a public leak finding', () => {
  const report = coverageFor({surface: {sourceReview: {stats: {files: 2},
    secretLeads: [{file: 'config.py', line: 4, name: 'stripe-secret-key'}]}}});
  const hardcoded = report.requestedClasses.find(row => row.name === 'Hardcoded Credentials');
  const leakage = report.requestedClasses.find(row => row.name === 'Secret Leakage');
  assert.equal(hardcoded.status, 'partial');
  assert.equal(hardcoded.attempts, 2);
  assert.equal(leakage.status, 'not tested');
});

test('executed Muse observations count as partial research, while queued plans do not', () => {
  const report = coverageFor({web: {results: [
    {kind: 'model-http-observation', verdict: 'inconclusive'},
    {kind: 'model-http-observation', verdict: 'not_reproduced'},
    {kind: 'model-json-observation', verdict: 'untested'},
  ]}});
  const row = report.rows.find(item => item.family === 'model-directed');
  assert.equal(row.status, 'partial');
  assert.equal(row.attempts, 2);
  assert.match(row.reason, /observations alone do not establish security impact/);
});

test('a confirmed model HTTP callback counts as partial SSRF coverage', () => {
  const report = coverageFor({web: {
    results: [{kind: 'model-http-sequence', verdict: 'confirmed'}],
    findings: [{kind: 'ssrf-loopback', verdict: 'confirmed',
      foundBy: 'muse-proposed-http-sequence'}],
  }});
  const ssrf = report.rows.find(row => row.family === 'ssrf');
  assert.equal(ssrf.status, 'partial');
  assert.equal(ssrf.attempts, 1);
  assert.equal(report.requestedClasses.find(row =>
    row.name === 'Server-Side Request Forgery (SSRF)').status, 'partial');
  assert.match(report.rows.find(row => row.family === 'model-directed').reason,
    /impact-specific HTTP sequence oracle/);
});

test('remote response-body use counts a narrow SSRF check without claiming RFI', () => {
  const report = coverageFor({web: {
    results: [{kind: 'model-http-sequence', verdict: 'confirmed'}],
    findings: [{kind: 'remote-content-use', verdict: 'confirmed',
      foundBy: 'muse-proposed-http-sequence'}],
  }});
  assert.equal(report.requestedClasses.find(row =>
    row.name === 'Server-Side Request Forgery (SSRF)').status, 'partial');
  assert.equal(report.requestedClasses.find(row =>
    row.name === 'Remote File Inclusion (RFI)').status, 'not tested');
  assert.equal(report.requestedClasses.find(row =>
    row.name === 'Remote Code Execution (RCE)').status, 'not tested');
});

test('a model sequence with owner-only content proof counts as partial access coverage', () => {
  const report = coverageFor({web: {
    results: [{kind: 'model-http-sequence', verdict: 'confirmed'}],
    findings: [{kind: 'model-access-boundary', verdict: 'confirmed',
      foundBy: 'muse-proposed-http-flow'}],
  }});
  assert.equal(report.requestedClasses.find(row =>
    row.name === 'Broken Access Control').status, 'partial');
  assert.equal(report.requestedClasses.find(row =>
    row.name === 'Broken Object Level Authorization (BOLA)').status, 'partial');
});

test('a confirmed model write sequence counts its exercised authorization class', () => {
  const report = coverageFor({web: {
    results: [{kind: 'model-state-change', verdict: 'confirmed'}],
    findings: [{kind: 'model-state-change', verdict: 'confirmed',
      foundBy: 'muse-proposed-http-sequence'}],
  }});
  assert.equal(report.requestedClasses.find(row =>
    row.name === 'Broken Function Level Authorization (BFLA)').status, 'partial');
  assert.equal(report.requestedClasses.find(row =>
    row.name === 'Broken Access Control').status, 'partial');
  assert.equal(report.requestedClasses.find(row =>
    row.name === 'Server-Side Request Forgery (SSRF)').status, 'not tested');
  assert.equal(report.requestedClasses.find(row =>
    row.name === 'Broken Object Level Authorization (BOLA)').status, 'not tested');
});

test('an outsider write to an owner-only record counts the cross-account object boundary', () => {
  const report = coverageFor({web: {
    results: [{kind: 'model-state-change', verdict: 'confirmed'}],
    findings: [{kind: 'model-state-change', verdict: 'confirmed',
      foundBy: 'muse-proposed-http-sequence', webProof: {as: 'outsider'}}],
  }});
  for (const name of ['Broken Object Level Authorization (BOLA)',
    'Horizontal Privilege Escalation'])
    assert.equal(report.requestedClasses.find(row => row.name === name).status, 'partial');
});
