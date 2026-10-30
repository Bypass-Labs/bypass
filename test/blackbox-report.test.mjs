// Tests for src/blackbox/report.mjs: findings (design 13), report rendering (13, 14) and exit codes (4.1).
// severityFor, classify and dataClasses are injected; these fakes follow the T4 contract,
// and the last test swaps in the real verdict.mjs functions when that sibling module exists.
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { temp } from './helpers.mjs';
import { buildFindings, consolidateBrowserXssProofs, renderReport, summaryText,
  exitCodeFor } from '../src/blackbox/report.mjs';

const ORIGIN = 'http://127.0.0.1:4329';
const OWNER_VALUE = 'owner-token-1';
const OTHER_VALUE = 'other-token-2';

test('report counts queued web checks separately from executed checks', () => {
  const report = renderReport({run: 'bx-20261029-00000000', scope,
    scopeHash: 'test', surface: surfaceFixture(), findings: [], results: [],
    web: {tested: 3, results: [{verdict: 'not_reproduced'},
      {verdict: 'untested'}, {verdict: 'untested'}]}});
  assert.match(report.json.summary.narrative, /1 task ran; 2 tasks remained queued/);
});

test('report preserves an audit deadline cut as coverage, not a model connection failure', () => {
  const message = 'Audit wall-clock deadline cut a Muse research call; remaining work is untested.';
  const report = renderReport({run: 'bx-deadline-cut', scope, scopeHash: 'test',
    surface: surfaceFixture(), findings: [], results: [],
    coverage: {researchDeadlineCut: true, statement: 'Partial coverage', rows: []},
    extraLimitations: [message]});
  assert.equal(report.json.coverage.researchDeadlineCut, true);
  assert.ok(report.json.limitations.includes(message));
  assert.match(report.markdown, /Audit wall-clock deadline cut a Muse research call/);
  assert.doesNotMatch(report.markdown, /Check the model connection/);
});

test('report labels a proved chain assessment as Muse interpretation', () => {
  const chain = {id: 'c-d-001', status: 'confirmed', template: 'derived-login-to-protected-impact',
    severity: 'high', selectedBy: 'baseline', findings: ['f-001', 'f-002'],
    proof: '/tmp/chain-proof.mjs', steps: [], reach: {observed: 1},
    assessment: {impact: 'A protected read follows the login bypass',
      preconditions: 'Observed invalid-password login',
      remediation: 'Reject invalid credentials and protect the read'}};
  const report = renderReport({run: 'bx-20261029-00000000', scope,
    scopeHash: 'test', surface: surfaceFixture(), findings: [], results: [], chains: [chain]});
  assert.match(report.markdown, /Muse chain assessment \(interpretation\)/);
  assert.match(report.markdown, /A protected read follows the login bypass/);
  assert.equal(report.json.chains[0].severity, 'high');
  assert.equal(report.json.chains[0].status, 'confirmed');
});

test('two confirmed browser proofs of the same reflected input form one finding with both proofs', t => {
  const root = temp();
  t.after(() => fs.rmSync(root, {recursive: true, force: true}));
  const ledgerFile = writeLedger(root, ['ev-0001', 'ev-0002']);
  const base = {title: 'Browser script execution', severity: 'medium',
    owasp: 'A03 Injection', cwe: 'CWE-79', pattern: '/view',
    url: `${ORIGIN}/view`, host: '127.0.0.1:4329', task: null,
    verdict: 'confirmed', rule: 'browser-proof', evidence: ['ev-0001'],
    confirmation: ['ev-0002'], mirror: {result: 'confirmed', evidence: []},
    tags: ['browser'], reach: {observed: 1, basis: 'script executed'},
    dataClasses: [], remediation: 'Escape HTML', foundBy: 'model', status: 'open',
    webSteps: [{identity: 'derived', method: 'GET', url: `${ORIGIN}/view`,
      status: 200, evidence: 'ev-0001'}]};
  const model = {...base, id: 'f-003', kind: 'model-browser-execution',
    proof: `${root}/poc/f-003/poc.mjs`,
    webProof: {as: 'derived', prelude: [], observe: [],
      subject: {method: 'GET', path: '/view', placement: 'query', key: 'q',
        fixedFields: [], headers: []}, assertion: {step: 'subject'}}};
  const xss = {...base, id: 'f-004', kind: 'xss-reflected',
    title: 'Reflected XSS', proof: `${root}/poc/f-004/poc.mjs`,
    evidence: ['ev-0002'], confirmation: ['ev-0001'],
    webProof: {request: {method: 'GET', url: '/view', as: 'derived'},
      parameter: 'q'}};
  const grouped = consolidateBrowserXssProofs([model, xss]);
  assert.equal(grouped.length, 1);
  assert.equal(grouped[0].id, 'f-004');
  assert.deepEqual(grouped[0].corroboratingProofs.map(item =>
    [item.id, item.proof]), [['f-003', model.proof]]);
  assert.deepEqual(grouped[0].evidence, ['ev-0002', 'ev-0001']);
  const report = renderReport({run: 'bx-20261029-00000000', scope,
    scopeHash: 'test', surface: surfaceFixture(), findings: grouped,
    results: [], ledgerFile});
  assert.equal(report.json.summary.findings.length, 1);
  assert.equal(report.json.summary.corroboratingProofs, 1);
  assert.equal(report.json.findings.length, 1);
  assert.match(report.markdown, /Corroborating independent proof f-003/);
  const terminal = summaryText({kind: 'blackbox-audit', run: 'bx-20261029-00000000',
    origin: ORIGIN, findings: grouped, runDir: root, projectRoot: root});
  assert.match(terminal, /Findings: 1 confirmed/);
  assert.match(terminal, /2 replayable proofs across 1 confirmed finding/);
  assert.equal(consolidateBrowserXssProofs([model, {...xss,
    webProof: {...xss.webProof, parameter: 'other'}}]).length, 2,
  'different inputs remain separate findings');
  assert.equal(consolidateBrowserXssProofs([model, {...xss,
    webProof: {...xss.webProof, request: {...xss.webProof.request,
      as: 'anonymous'}}}]).length, 2,
  'different identities remain separate findings');
});

const scope = {
  schemaVersion: 1,
  target: { origin: ORIGIN, environment: 'local', acknowledged: 'local-owner' },
  domains: [],
  credentialOrigins: [ORIGIN],
  include: ['/'],
  never: ['/api/billing/*', 'delete'],
  methods: ['GET', 'HEAD'],
  identities: { owner: { env: 'OWNER_TOKEN', role: 'member' }, outsider: { env: 'OTHER_TOKEN', role: 'member' }, auth: 'bearer', identityPath: null },
  limits: { rps: 50, hosts: 200, maxUrls: 200, tasks: 400, agents: 40, waves: 1, modelCalls: 60, minutes: 10 },
};

function surfaceFixture(identity = {}) {
  return {
    origin: ORIGIN,
    identity: {
      path: '/api/me', principals: { owner: 'u-1', outsider: 'u-2' }, aliases: { owner: ['u-1'], outsider: ['u-2'] },
      roles: { owner: { role: 'member' }, outsider: { role: 'member' } }, evidence: ['ev-0001', 'ev-0002'], verified: true, ...identity,
    },
    patterns: [
      {
        pattern: '/api/invoices/{id}', methods: ['GET'], source: ['harvest:/api/invoices'],
        ids: { format: 'prefixed', selector: 'id', samples: ['inv-101', 'inv-201'], sequential: 1, ownerIds: ['inv-101', 'inv-102'], outsiderIds: ['inv-201'], shared: [] },
        private: { 'inv-101': { by: 'ownership-field', field: 'ownerId' } }, label: { kind: 'item', by: 'code' },
        fingerprint: { owner: { status: 200 }, outsider: { status: 403 }, anonymous: { status: 401 }, notFound: { status: 404 } },
      },
      {
        pattern: '/api/invoices', methods: ['GET'], source: ['link'], ids: { ownerIds: [], outsiderIds: [], shared: [] },
        private: {}, label: { kind: 'list', by: 'code' },
        fingerprint: { owner: { status: 200 }, outsider: { status: 200 }, anonymous: { status: 401 }, notFound: null },
      },
    ],
    outOfScope: [{ url: '/static/app.js', reason: 'include' }],
    never: [{ url: '/api/invoices/inv-101/delete', match: 'delete' }],
    exposures: [
      { path: '/.env', severity: 'critical', signature: 'dotenv', evidenceId: 'ev-0009' },
      { path: '/openapi.json', severity: 'info', signature: 'openapi', evidenceId: 'ev-0010' },
    ],
    mined: null,
    stats: { urls: 12, requests: 40, patterns: 2 },
  };
}

function task(n, kind, url, as, extra = {}) {
  return {
    id: `t-${String(n).padStart(3, '0')}`, kind, pattern: extra.pattern ?? '/api/invoices/{id}',
    request: { method: 'GET', url, as }, control: { url: extra.control ?? url, as: 'owner' },
    expect: 'denied', why: '', priority: 5, origin: extra.origin ?? 'baseline', dependsOn: [],
    resourceId: extra.resourceId ?? null, ownerOnlyIds: [], sensitiveFields: [],
  };
}

function fp(status, evidenceId, extra = {}) {
  return { status, type: 'application/json', bytes: 64, hash: `sha256:${evidenceId}`, shape: { id: 'string', ownerId: 'string', total: 'number', email: 'string' }, ids: [], ownership: {}, headers: {}, evidenceId, items: null, ...extra };
}

function resultsFixture() {
  const idor = task(1, 'idor', '/api/invoices/inv-101', 'outsider', { resourceId: 'inv-101' });
  const leakAll = task(2, 'list-leak', '/api/invoices?all=1', 'outsider', { pattern: '/api/invoices', control: '/api/invoices' });
  const leakLimit = task(3, 'list-leak', '/api/invoices?limit=1000', 'outsider', { pattern: '/api/invoices', control: '/api/invoices' });
  const denied = task(4, 'idor', '/api/invoices/inv-102', 'outsider', { resourceId: 'inv-102' });
  const cached = task(5, 'missing-auth', '/api/invoices/inv-102', 'anonymous', { resourceId: 'inv-102' });
  const failed = task(6, 'idor', '/api/invoices/inv-999', 'outsider', { resourceId: 'inv-999' });
  const plans = task(7, 'idor', '/api/plans/p-1', 'outsider', { pattern: '/api/plans/{id}', resourceId: 'p-1' });
  return [
    {
      task: idor, verdict: 'confirmed', rule: 'idor/id-match', reason: '', evidence: ['ev-0011', 'ev-0012', 'ev-0013'],
      O: fp(200, 'ev-0011'), T: fp(200, 'ev-0012'), A: fp(401, 'ev-0013'), confirmation: ['ev-0031', 'ev-0032', 'ev-0033'],
      mirror: { result: 'both-open', url: '/api/invoices/inv-201', evidence: ['ev-0040'] }, tags: [],
    },
    {
      task: leakLimit, verdict: 'confirmed', rule: 'list-leak/owner-only-id', reason: '', evidence: ['ev-0017', 'ev-0018', 'ev-0019'],
      O: fp(200, 'ev-0017', { items: 2 }), T: fp(200, 'ev-0018', { items: 2 }), A: fp(401, 'ev-0019'), confirmation: ['ev-0035'],
      mirror: { result: 'unverified', evidence: [] }, tags: ['role-unverified'],
    },
    {
      task: leakAll, verdict: 'confirmed', rule: 'list-leak/owner-only-id', reason: '', evidence: ['ev-0014', 'ev-0015', 'ev-0016'],
      O: fp(200, 'ev-0014', { items: 2 }), A: fp(401, 'ev-0016'), confirmation: ['ev-0034'],
      // A list's shape stops at 'array' (T1 jsonShape); the record fields carry the data classes.
      T: fp(200, 'ev-0015', { items: 3, shape: { items: 'array' }, fields: { id: 'string', ownerId: 'string', email: 'string', total: 'number' } }),
      mirror: { result: 'unverified', evidence: [] }, tags: ['role-unverified'],
    },
    { task: denied, verdict: 'not_reproduced', rule: 'not_reproduced/denied', reason: '', evidence: ['ev-0020'], O: fp(200, 'ev-0020'), T: fp(403, 'ev-0021'), A: fp(401, 'ev-0022') },
    { task: cached, verdict: 'inconclusive', rule: 'inconclusive/cache', reason: 'Age header on a 200 response', evidence: ['ev-0023', 'ev-0024'], O: fp(200, 'ev-0023'), T: fp(200, 'ev-0024'), A: fp(200, 'ev-0024') },
    { task: failed, verdict: 'blocked', rule: 'blocked/control-failed', reason: 'owner control returned 404', evidence: ['ev-0025'], O: fp(404, 'ev-0025'), T: null, A: null },
    { task: plans, verdict: 'shared', rule: 'shared', reason: '', evidence: ['ev-0026'], O: fp(200, 'ev-0026'), T: fp(200, 'ev-0027'), A: fp(401, 'ev-0028') },
  ];
}

const CLASSIFICATION = {
  idor: { owasp: 'API1:2023 Broken Object Level Authorization', cwe: 'CWE-639' },
  'list-leak': { owasp: 'API1:2023 Broken Object Level Authorization', cwe: 'CWE-639' },
  exposure: { owasp: 'API8:2023 Security Misconfiguration', cwe: 'CWE-538' },
};
const fakes = {
  classify: kind => CLASSIFICATION[kind] ?? { owasp: null, cwe: null },
  severityFor: (kind, { pii = false, credentialLike = false } = {}) => {
    if (credentialLike) return 'critical';
    if (kind === 'list-leak') return pii ? 'high' : 'medium';
    return kind === 'idor' ? 'high' : 'low';
  },
  dataClasses: value => Object.keys(value?.shape ?? value ?? {}).flatMap(key => key === 'email' ? ['email'] : key === 'total' ? ['amount'] : key === 'apiKey' ? ['token-like'] : []),
};

function writeLedger(dir, ids) {
  const file = path.join(dir, 'evidence.jsonl');
  const lines = ids.map((id, index) => JSON.stringify({
    id, prev: index ? `sha256:${index}` : null, run: 'bx-20261028-ab12', task: 't-001', step: 'task', agent: 1, at: `2026-10-28T14:00:${String(index).padStart(2, '0')}.000Z`,
    identity: index % 3 === 0 ? 'owner' : index % 3 === 1 ? 'outsider' : 'anonymous',
    request: { method: 'GET', url: `${ORIGIN}/api/invoices/inv-101`, headers: ['accept', 'authorization'] },
    response: { status: 200, headers: { 'content-type': 'application/json' }, bytes: 64, hash: `sha256:${'ab'.repeat(32)}`, shape: {}, ownership: {}, ms: 3 },
  }));
  fs.writeFileSync(file, lines.join('\n') + '\n');
  return file;
}

function withTokensInEnv(t) {
  const before = { OWNER_TOKEN: process.env.OWNER_TOKEN, OTHER_TOKEN: process.env.OTHER_TOKEN };
  process.env.OWNER_TOKEN = OWNER_VALUE;
  process.env.OTHER_TOKEN = OTHER_VALUE;
  t.after(() => {
    for (const [name, value] of Object.entries(before)) {
      if (value === undefined) delete process.env[name];
      else process.env[name] = value;
    }
  });
}

test('exitCodeFor follows design 4.1', () => {
  const resolved = [{ verdict: 'not_reproduced' }, { verdict: 'shared' }, { verdict: 'public' }];
  const confirmed = [{ id: 'f-001', verdict: 'confirmed' }];
  assert.equal(exitCodeFor({ findings: confirmed, results: [...resolved, { verdict: 'confirmed' }], untested: [], blockedRun: false }), 1);
  assert.equal(exitCodeFor({ findings: confirmed, results: [{ verdict: 'inconclusive' }], untested: [{ id: 't-9' }], blockedRun: true }), 1, 'confirmed findings win over incomplete work');
  assert.equal(exitCodeFor({ findings: [], results: resolved, untested: [], blockedRun: false }), 0);
  assert.equal(exitCodeFor({ findings: [], results: [...resolved, { verdict: 'inconclusive' }], untested: [], blockedRun: false }), 3);
  assert.equal(exitCodeFor({ findings: [], results: [...resolved, { verdict: 'blocked' }], untested: [], blockedRun: false }), 3);
  assert.equal(exitCodeFor({ findings: [], results: resolved, untested: [{ id: 't-401' }], blockedRun: false }), 3);
  assert.equal(exitCodeFor({ findings: [], results: resolved, untested: [], blockedRun: true }), 3);
  assert.equal(exitCodeFor({ findings: [], results: [], untested: [], blockedRun: false }), 3, 'an audit that tested nothing is not clean');
  assert.equal(exitCodeFor({ findings: [], results: resolved }), 0, 'untested and blockedRun are optional');
  assert.equal(exitCodeFor({findings: [{kind: 'model-differential', verdict: 'confirmed'}],
    results: resolved}), 3, 'a reproduced transformation has no proven security impact');
  assert.equal(exitCodeFor({findings: [{kind: 'model-json-differential', verdict: 'confirmed'}],
    results: resolved}), 3, 'the JSON experiment uses the same impact standard');
});

test('buildFindings turns confirmed results and exposures into ranked, deduplicated findings', () => {
  const findings = buildFindings(resultsFixture(), { surface: surfaceFixture(), scope, ...fakes });
  assert.deepEqual(findings.map(f => [f.id, f.kind, f.pattern, f.severity]), [
    ['f-001', 'exposure', '/.env', 'critical'],
    ['f-002', 'idor', '/api/invoices/{id}', 'high'],
    ['f-003', 'list-leak', '/api/invoices', 'high'],
  ], 'info exposures and unconfirmed results are not findings; list-leak is deduplicated per (kind, pattern)');

  const idor = findings[1];
  assert.equal(idor.url, `${ORIGIN}/api/invoices/inv-101`);
  assert.equal(idor.host, '127.0.0.1:4329');
  assert.equal(idor.task, 't-001');
  assert.equal(idor.verdict, 'confirmed');
  assert.equal(idor.rule, 'idor/id-match');
  assert.equal(idor.owasp, CLASSIFICATION.idor.owasp);
  assert.equal(idor.cwe, 'CWE-639');
  assert.deepEqual(idor.evidence, ['ev-0011', 'ev-0012', 'ev-0013']);
  assert.deepEqual(idor.confirmation, ['ev-0031', 'ev-0032', 'ev-0033']);
  assert.equal(idor.mirror.result, 'both-open');
  assert.deepEqual(idor.reach.observed, 1);
  assert.match(idor.reach.basis, /ev-0012/);
  assert.deepEqual(idor.dataClasses, ['amount', 'email']);
  assert.match(idor.title, /\/api\/invoices\/\{id\}/);
  assert.match(idor.remediation, /ownership/i);
  assert.equal(idor.foundBy, 'baseline');
  assert.equal(idor.status, 'open');
  assert.deepEqual(idor.tags, []);

  const leak = findings[2];
  assert.equal(leak.task, 't-002', 'the representative with the larger observed reach is kept');
  assert.equal(leak.reach.observed, 3);
  assert.match(leak.title, /all=1/);
  assert.match(leak.remediation, /never by a parameter/);
  assert.deepEqual(leak.tags, ['role-unverified']);
  assert.deepEqual(leak.dataClasses, ['amount', 'email'], 'record fields of a list feed dataClasses');

  const exposure = findings[0];
  assert.equal(exposure.url, `${ORIGIN}/.env`);
  assert.equal(exposure.task, null);
  assert.deepEqual(exposure.evidence, ['ev-0009']);
  assert.equal(exposure.cwe, 'CWE-538');
  assert.match(exposure.remediation, /debug and management endpoints/);
});

test('buildFindings tags identity and role problems and escalates credential-like bodies', () => {
  const results = resultsFixture().slice(0, 1);
  results[0].T = fp(200, 'ev-0012', { shape: { id: 'string', apiKey: 'string' } });
  const calls = [];
  const severityFor = (kind, options) => { calls.push(options); return fakes.severityFor(kind, options); };
  const surface = surfaceFixture({ verified: false, roles: { owner: { role: 'member' }, outsider: { role: 'admin' } } });
  const [finding] = buildFindings(results, { surface: { ...surface, exposures: [] }, scope, ...fakes, severityFor });
  assert.equal(finding.severity, 'critical');
  assert.equal(calls[0].credentialLike, true);
  assert.equal(calls[0].list, false);
  assert.equal(calls[0].reach, 1);
  assert.deepEqual(finding.tags.sort(), ['credential-like', 'identity-unverified', 'role-mismatch']);
});

test('renderReport writes every design-13 section with numbered reproduction steps and placeholder curl lines', t => {
  withTokensInEnv(t);
  const dir = temp();
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  const surface = surfaceFixture();
  const results = resultsFixture();
  const findings = buildFindings(results, { surface, scope, ...fakes });
  const discovery = {stats: {hostsFound: 1, hostsLive: 1, dnsQueries: 2, cut: 0},
    hosts: [{host: 'api.example.test', depth: 1, foundBy: ['model:naming'], addresses: ['203.0.113.8'],
      origin: 'https://api.example.test', live: {https: 200}, title: 'API', stack: [], exposures: [], operations: [],
      audit: {tested: 1, cut: 0}, responseFollowup: {routesAvailable: 2, routesReviewed: 2,
        observations: 1, pagesAvailable: 1, pagesSent: 1, pathsAccepted: 1, pathsRejected: 1},
      certificate: {issuer: 'Fixture CA', sans: ['api.example.test', 'deep.api.example.test'], wildcardSans: [],
        expires: '2027-01-10T00:00:00.000Z', evidenceId: 'ev-0041'}}],
    modelNaming: {modelCalls: 2, pagesSent: 2, hostsSent: 2, hostsCut: 0,
      candidates: 3, accepted: 1, rejected: 2, newHosts: 1}};
  const cited = ['ev-0001', 'ev-0002', 'ev-0009', 'ev-0011', 'ev-0012', 'ev-0013', 'ev-0014', 'ev-0015', 'ev-0016', 'ev-0023', 'ev-0024', 'ev-0025', 'ev-0031', 'ev-0032', 'ev-0033', 'ev-0034', 'ev-0040'];
  const ledgerFile = writeLedger(dir, cited.filter(id => id !== 'ev-0040'));
  const { markdown, json } = renderReport({
    run: 'bx-20261028-ab12', scope, scopeHash: 'f'.repeat(64), surface, findings, results, chains: [], mined: null, discovery,
    stats: { startedAt: '2026-10-28T14:00:00.000Z', finishedAt: '2026-10-28T14:00:06.000Z', tasks: 7, requests: 19, cached: 4, elapsedMs: 6000, rps: 3.2, agents: 4 },
    ledgerFile, untested: [task(9, 'idor', '/api/invoices/inv-102', 'outsider')], integrity: { ok: true, records: 16, brokenAt: null },
  });

  // Header block (design 13)
  assert.match(markdown, /^# Black-box audit report/m);
  for (const text of [ORIGIN, 'local', 'bx-20261028-ab12', 'f'.repeat(64), 'ledger intact (16 records)', '$OWNER_TOKEN', '$OTHER_TOKEN', '2026-10-28T14:00:00.000Z']) {
    assert.ok(markdown.includes(text), `header contains ${text}`);
  }
  // Sections in order
  const headings = ['## 1. Executive summary', '## 2. Scope and method', '## 3. External attack surface', '## 4. Application attack surface',
    '## 5. Findings', '## 6. Chains', '## 7. Inconclusive and blocked', '## 8. Limitations', '## 9. Evidence appendix'];
  const positions = headings.map(heading => markdown.indexOf(heading));
  assert.ok(positions.every(position => position > 0), `all headings present: ${positions}`);
  assert.deepEqual([...positions].sort((a, b) => a - b), positions);
  assert.match(markdown, /Muse naming: 2 live host records reviewed in 2 pages; 1 scoped names queued, 1 resolved, 2 proposals rejected/);
  assert.equal(json.surface.external.modelNaming.newHosts, 1);
  assert.match(markdown, /TLS SAN names/);
  assert.match(markdown, /deep\.api\.example\.test/);
  assert.deepEqual(json.surface.external.discoveredHosts[0].certificate.sans,
    ['api.example.test', 'deep.api.example.test']);
  assert.equal(json.surface.external.discoveredHosts[0].responseFollowup.pathsAccepted, 1);
  assert.match(markdown, /response routes 2\/2/);
  // Summary table
  assert.match(markdown, /^\| ID \| Title \| Host \| Pattern \| Severity \| Verdict \| Kind \| Found by \|$/m);
  assert.match(markdown, /^\| f-002 \| Cross-account read: \/api\/invoices\/\{id\} \| 127\.0\.0\.1:4329 \| `\/api\/invoices\/\{id\}` \| high \| confirmed \| idor \| baseline \|$/m);
  // Numbered reproduction requests in reviewer order, then curl lines with env-var placeholders
  assert.match(markdown, /^1\. As owner, GET `http:\/\/127\.0\.0\.1:4329\/api\/invoices\/inv-101` → 200 \(ev-0011\)$/m);
  assert.match(markdown, /^2\. As outsider, GET `http:\/\/127\.0\.0\.1:4329\/api\/invoices\/inv-101` → 200 \(ev-0012\)$/m);
  assert.match(markdown, /^3\. As anonymous, GET `http:\/\/127\.0\.0\.1:4329\/api\/invoices\/inv-101` → 401 \(ev-0013\)$/m);
  assert.ok(markdown.includes(`curl -sS -i -H "Authorization: Bearer $OWNER_TOKEN" '${ORIGIN}/api/invoices/inv-101'`));
  assert.ok(markdown.includes(`curl -sS -i -H "Authorization: Bearer $OTHER_TOKEN" '${ORIGIN}/api/invoices/inv-101'`));
  assert.ok(markdown.includes(`curl -sS -i '${ORIGIN}/api/invoices/inv-101'`));
  assert.ok(markdown.includes(`curl -sS -i '${ORIGIN}/.env'`), 'exposure reproduction is one anonymous request');
  // Verdict rule, confirmation, mirror, remediation
  assert.match(markdown, /Verdict rule: `idor\/id-match`/);
  assert.match(markdown, /Confirmation \(re-verification\): ev-0031, ev-0032, ev-0033/);
  assert.match(markdown, /Mirror: both-open/);
  // Inconclusive and blocked items keep their reasons and evidence
  assert.match(markdown, /Age header on a 200 response/);
  assert.match(markdown, /owner control returned 404/);
  // Limitations and the appendix built from the ledger file
  assert.match(markdown, /a host or route without a finding was not shown to be safe/);
  assert.match(markdown, /^\| ev-0011 \| 2026-10-28T14:00:03\.000Z \| owner \| GET \| `http:\/\/127\.0\.0\.1:4329\/api\/invoices\/inv-101` \| 200 \| abababababab \|$/m);
  assert.match(markdown, /^\| ev-0040 \| not in ledger/m);
  // Credential values never appear, even when they sit in process.env
  for (const secret of [OWNER_VALUE, OTHER_VALUE]) {
    assert.ok(!markdown.includes(secret), 'markdown carries no credential value');
    assert.ok(!JSON.stringify(json).includes(secret), 'json carries no credential value');
  }

  assert.equal(json.kind, 'blackbox-report');
  assert.equal(json.header.run, 'bx-20261028-ab12');
  assert.equal(json.header.ledger, 'ledger intact (16 records)');
  assert.deepEqual(json.findings.map(f => f.id), ['f-001', 'f-002', 'f-003']);
  const idor = json.findings[1];
  assert.deepEqual(idor.reproduction.map(step => [step.identity, step.status, step.evidence]), [['owner', 200, 'ev-0011'], ['outsider', 200, 'ev-0012'], ['anonymous', 401, 'ev-0013']]);
  assert.equal(idor.curl.length, 3);
  assert.deepEqual(json.inconclusive.map(item => item.task), ['t-005', 't-006']);
  assert.deepEqual(json.surface.application.untested.map(item => item.id), ['t-009']);
  assert.ok(json.evidence.some(row => row.id === 'ev-0011' && row.status === 200));
  assert.deepEqual(json.chains, []);
});

test('renderReport uses the scope credential placement and reports missing ledger or integrity data', () => {
  const cookieScope = { ...scope, identities: { ...scope.identities, auth: 'cookie' } };
  const headerScope = { ...scope, identities: { ...scope.identities, auth: 'header:X-Api-Key' } };
  const base = { run: 'bx-1', scopeHash: 'abc', surface: surfaceFixture(), results: resultsFixture(), stats: {}, ledgerFile: path.join('/nonexistent', 'evidence.jsonl') };
  const cookie = renderReport({ ...base, scope: cookieScope, findings: buildFindings(base.results, { surface: base.surface, scope: cookieScope, ...fakes }) });
  assert.ok(cookie.markdown.includes(`-H "Cookie: $OWNER_TOKEN"`));
  assert.ok(cookie.markdown.includes(`-H "Cookie: $OTHER_TOKEN"`));
  assert.match(cookie.markdown, /ledger integrity not checked/);
  assert.match(cookie.markdown, /ledger file not found/);
  const header = renderReport({ ...base, scope: headerScope, findings: buildFindings(base.results, { surface: base.surface, scope: headerScope, ...fakes }), integrity: { ok: false, records: 9, brokenAt: 'ev-0004' } });
  assert.ok(header.markdown.includes(`-H "X-Api-Key: $OTHER_TOKEN"`));
  assert.match(header.markdown, /ledger broken at ev-0004/);
});

test('renderReport lists mined assets with masked secrets only', () => {
  const mined = {
    files: [{
      url: `${ORIGIN}/static/app.js`, bytes: 4096, hash: 'h', foundBy: 'page:/', sourceMap: 'exposed',
      sourceMapUrl: `${ORIGIN}/static/app.js.map`, sourcesCut: 2,
      endpoints: [{ path: '/api/invoices', method: 'GET', params: ['scope'], examples: {scope: ['global']},
        sources: ['webpack:///./src/api/invoices.js'],
        purpose: 'Lists invoices', parameterMeanings: [{name: 'scope', meaning: 'selects a list scope'}] },
      { path: '/api/invoices', method: 'POST' }],
      secrets: [{ name: 'aws-access-key', confidence: 'high', masked: 'AKIA…(20)', hash: 'x', line: 3, column: 9, public: false }],
      libraries: [{ name: 'jquery', version: '1.12.4', line: 1 }], hosts: [], env: [], comments: [],
    }],
    endpoints: [{ path: '/api/invoices', method: 'GET', params: [], files: [] }, { path: '/api/invoices', method: 'POST', params: [], files: [] }],
    hosts: [{ host: 'bucket.s3.amazonaws.com', kind: 'bucket' }], secrets: [], libraries: [], sourceMaps: [], stats: { files: 1, bytes: 4096 },
  };
  const surface = { ...surfaceFixture(), mined };
  const { markdown, json } = renderReport({ run: 'bx-1', scope, scopeHash: 'abc', surface, findings: [], results: [], mined, stats: {} });
  assert.match(markdown, /AKIA…\(20\)/);
  assert.match(markdown, /jquery 1\.12\.4/);
  assert.match(markdown, /bucket\.s3\.amazonaws\.com/);
  assert.match(markdown, /POST `\/api\/invoices`/);
  assert.match(markdown, /scope=global \(selects a list scope\)/);
  assert.match(markdown, /Lists invoices/);
  assert.match(markdown, /webpack:\/\/\/\.\/src\/api\/invoices\.js/);
  assert.equal(json.surface.external.files[0].sourceMap, 'exposed');
  assert.equal(json.surface.external.files[0].sourcesCut, 2);
  assert.match(markdown, /Map sources cut/);
  assert.equal(json.surface.external.files[0].operations[0].purpose, 'Lists invoices');
  assert.deepEqual(json.surface.external.files[0].operations[0].sourceFiles,
    ['webpack:///./src/api/invoices.js']);
  assert.match(markdown, /No confirmed findings/);
});

test('summaryText prints the findings table, counts and run folder', () => {
  const text = summaryText({
    kind: 'blackbox-audit', run: 'bx-20261028-ab12', runDir: '/tmp/project/.bypass/runs/bx-20261028-ab12', scopeHash: 'abc',
    stats: { tasks: 84, requests: 252, cached: 118, elapsedMs: 5100, rps: 49.4, confirmed: 2, notReproduced: 70, inconclusive: 1, blocked: 0 },
    findings: [
      { id: 'f-001', severity: 'critical', kind: 'missing-auth', title: 'Unauthenticated read: /api/reports/{id}', pattern: '/api/reports/{id}' },
      { id: 'f-002', severity: 'high', kind: 'idor', title: 'Cross-account read: /api/invoices/{id}', pattern: '/api/invoices/{id}' },
    ],
    untested: [], exitCode: 1, reportPath: '/tmp/project/.bypass/runs/bx-20261028-ab12/report.md',
  });
  assert.match(text, /bx-20261028-ab12/);
  assert.match(text, /discovery/i);
  assert.match(text, /f-001\s+critical\s+missing-auth\s+Unauthenticated read/);
  assert.match(text, /f-002\s+high\s+idor\s+Cross-account read/);
  assert.match(text, /84 executed/);
  assert.match(text, /252 requests/);
  assert.match(text, /118 cached/);
  assert.match(text, /70 no finding/);
  assert.match(text, /\/tmp\/project\/\.bypass\/runs\/bx-20261028-ab12/);
  assert.match(text, /Exit 1/);
  assert.match(text, /Muse model:\s+code-only/);
  const failedModel = summaryText({run: 'bx-model-failed', runDir: '/r', stats: {
    model: 'Muse session default', modelCalls: 2,
    modelWorkersConfigured: 12, modelWorkersPeak: 3},
    findings: [{id: 'f-001', severity: 'high', kind: 'idor', title: 'Cross-account read'}],
    modelOutput: {assetNotes: 0, assetPaths: 0, responsePaths: 0, webStrategies: 0},
    modelError: 'muse login required', incomplete: true, untested: [], exitCode: 1});
  assert.match(failedModel, /Muse model stage failed: muse login required/);
  assert.match(failedModel, /Muse agents\s+3 active at peak · 12 configured/);
  assert.match(failedModel, /Muse accepted:\s+0 route notes/);
  assert.match(failedModel, /Muse plans:\s+none accepted/);
  assert.match(failedModel, /Findings: 1 confirmed · partial coverage/);
  assert.match(failedModel, /Exit 1/);
  const deadlineCut = summaryText({run: 'bx-deadline', runDir: '/r', stats: {
    model: 'Muse session default', modelCalls: 74}, findings: [],
  modelError: null, researchDeadlineCut: true, incomplete: true,
  untested: [], exitCode: 3});
  assert.match(deadlineCut, /Research cutoff: Audit wall-clock deadline stopped a Muse call/);
  assert.doesNotMatch(deadlineCut, /Muse model stage failed|Check the model connection/);
  assert.match(summaryText({ run: 'bx-2', runDir: '/r', stats: {}, findings: [], untested: [], exitCode: 3 }), /Findings: none confirmed/);
  assert.match(summaryText({run: 'bx-3', runDir: '/r', stats: {}, findings: [], untested: [],
    advisories: {matches: 2}, exitCode: 3}), /Advisory leads:\s+2 version matches; unproved/);
});

test('terminal summary labels catalog coverage partial even when every queued task finished', () => {
  const output = summaryText({run: 'bx-bounded', runDir: '/tmp/bx-bounded',
    findings: [{id: 'f-001', kind: 'model-state-change', severity: 'medium',
      verdict: 'confirmed', title: 'Owner-only record changed', pattern: '/record'}],
    coverage: {complete: false, requestedClasses: [
      {name: 'Remote File Inclusion (RFI)', status: 'not tested'}]},
    stats: {tasks: 1}, exitCode: 1, incomplete: false});
  assert.match(output, /Findings: 1 confirmed · partial coverage/);
});

test('summaryText separates exposure findings from task outcomes', () => {
  const text = summaryText({run: 'bx-juice', runDir: '/tmp/bx-juice', exitCode: 1,
    stats: {tasks: 233, requests: 843, confirmed: 1, notReproduced: 189, inconclusive: 42, blocked: 1},
    findings: [
      {id: 'f-001', severity: 'high', kind: 'exposure', title: 'Sensitive path exposed', pattern: '/metrics'},
      {id: 'f-002', severity: 'high', kind: 'sql-boolean', title: 'SQL boolean condition changed search results', pattern: '/rest/products/search'},
    ]});
  assert.match(text, /Findings: 2 confirmed/);
  assert.match(text, /Proof sources\s+1 exposure check \+ 1 other probe = 2 confirmed findings/);
  assert.match(text, /Task verdicts\s+1 positive check · 189 no finding\n\s+42 inconclusive · 1 blocked/);
  assert.doesNotMatch(text, /Task verdicts: confirmed 1/);
});

test('summaryText explains repeated positive checks that support one finding', () => {
  const text = summaryText({run: 'bx-repeat', runDir: '/tmp/bx-repeat', exitCode: 1,
    stats: {tasks: 4, confirmed: 3, notReproduced: 1}, findings: [
      {id: 'f-001', severity: 'high', kind: 'sql-boolean', title: 'SQL injection', pattern: '/search'},
      {id: 'f-002', severity: 'low', kind: 'exposure', title: 'Directory index', pattern: '/files'},
    ]});
  assert.match(text, /Findings: 2 confirmed/);
  assert.match(text, /Proof sources\s+1 exposure check \+ 1 other probe = 2 confirmed findings/);
  assert.match(text, /Task verdicts\s+3 positive checks \(1 distinct non-exposure finding\) · 1 no finding/);
});

test('summaryText reconciles a proved Muse HTTP-sequence bug with task verdicts', () => {
  const proved = summaryText({run: 'bx-callback', runDir: '/tmp/bx-callback', exitCode: 1,
    stats: {tasks: 1, observed: 1}, findings: [
      {id: 'f-001', severity: 'medium', kind: 'ssrf-loopback',
        title: 'Loopback callback reached', pattern: '/preview',
        verdict: 'confirmed', foundBy: 'muse-proposed-http-sequence'},
    ]});
  assert.match(proved, /Findings: 1 confirmed/);
  assert.match(proved, /Task verdicts\s+1 positive check · 0 no finding/);
  assert.doesNotMatch(proved, /impact unverified|outcomes itemized/);
  const unproved = summaryText({run: 'bx-observation', runDir: '/tmp/bx-observation',
    stats: {tasks: 1, observed: 1}, findings: [], exitCode: 3});
  assert.match(unproved, /1 reproduced behavior \(impact unverified\)/);
});

test('summaryText distinguishes requested classes from broad report groups', () => {
  const output = summaryText({run: 'bx-coverage', runDir: '/tmp/bx-coverage', exitCode: 3,
    stats: {}, findings: [], coverage: {
      requestedClasses: [{name: 'SQL Injection (SQLi)', status: 'partial'},
        {name: 'Account Takeover (ATO)', status: 'not tested'},
        {name: 'Request Smuggling', status: 'not tested'}],
      rows: [{family: 'sql-nosql-injection', status: 'exercised'},
        {family: 'session-account', status: 'not tested'}],
    }});
  assert.match(output, /Class coverage\s+1 of 3 partly tested · 2 not tested/);
  assert.match(output, /Report groups\s+1 exercised · 0 partial · 1 not tested \(2 broad groups\)/);
});

test('summaryText separates executed checks, queued untested leads and budget cuts', () => {
  const text = summaryText({run: 'bx-cut', runDir: '/tmp/bx-cut', exitCode: 1,
    stats: {tasks: 189, queuedUntested: 8, beyondBudget: 7, requests: 723,
      confirmed: 2, notReproduced: 145, inconclusive: 34}, findings: []});
  assert.match(text, /Activity\s+181 executed · 8 queued untested · 7 beyond budget/);
  assert.match(text, /Task verdicts\s+2 positive checks · 145 no finding\n\s+34 inconclusive · 8 queued untested/);
  assert.doesNotMatch(text, /outcomes itemized/);
});

test('summaryText shows copied pending research queues separately from task verdicts', () => {
  const text = summaryText({run: 'bx-pending', runDir: '/tmp/bx-pending',
    projectRoot: '/tmp/bypass-project', exitCode: 3, incomplete: true, findings: [],
    stats: {tasks: 1, queuedUntested: 0, notReproduced: 1},
    coverage: {pendingResearchCheckpoints: 2}});
  assert.match(text, /Activity\s+1 executed/);
  assert.match(text, /Saved queues\s+2 research queues pending/);
  assert.match(text, /bypass blackbox resume 'bx-pending' --project '\/tmp\/bypass-project'/);
  assert.doesNotMatch(text, /queued untested|outcomes itemized/);
});

test('summaryText groups accepted Muse work without mixing probes and sequences', () => {
  const output = summaryText({run: 'bx-model-work', runDir: '/tmp/bx-model-work',
    stats: {model: 'muse-spark-1.3-contributor', modelCalls: 12}, findings: [],
    modelOutput: {assetNotes: 32, assetPaths: 4, responsePaths: 7,
      webStrategies: 2, webExperiments: 1, jsonExperiments: 1,
      httpSequences: 3, storedXssChecks: 1, sessionChains: 1,
      httpSequenceRejectedByReason: {'route-not-on-page': 8, 'binding-shape': 3}}, exitCode: 3});
  assert.match(output, /Muse accepted:\s+32 route notes · 4 asset paths · 7 response paths/);
  assert.match(output, /Muse plans:\s+2 web strategies · 1 GET experiment · 1 JSON POST experiment/);
  assert.match(output, /Muse sequences:\s+3 HTTP sequences · 1 stored XSS check · 1 session chain/);
  assert.match(output, /Bypass rejected\s+11 Muse HTTP plans · 8 route-not-on-page · 3 binding-shape/);
});

test('summaryText counts proposal and repair refusals and names concrete coverage gaps', () => {
  const output = summaryText({run: 'bx-partial', runDir: '/tmp/bx-partial',
    stats: {model: 'muse-spark-1.3-contributor', modelCalls: 119}, findings: [],
    incomplete: true,
    limitations: ['Source-map mining could not inspect 1533 originals on configured application origins because their maps omitted embedded source content.'],
    coverage: {requestedClasses: [{status: 'partial'}, {status: 'not tested'}],
      rows: [], derivedSessionRecon: {budgetCut: 35, sizeCut: 2}},
    modelOutput: {assetNotes: 0, assetPaths: 0,
      rejectedDecisionRecordsByReason: {'invalid-controls': 4, assertion: 2,
        'subject-or-controls': 4}}, exitCode: 3});
  assert.match(output, /Coverage gaps\s+35 authenticated recon URLs unvisited · 2 authenticated responses beyond capture limit · 1533 source-map originals without served source text · 1 class not tested/);
  assert.match(output, /Bypass rejected\s+10 Muse plan\/revision records · 4 invalid-controls · 4 subject-or-controls · 2 assertion/);
});

test('summaryText distinguishes missing source-map content from asset-budget cuts', () => {
  const output = summaryText({run: 'bx-maps', runDir: '/tmp/bx-maps',
    stats: {}, findings: [], incomplete: true,
    coverage: {requestedClasses: [], rows: [], sourceMaps: {
      originalsUnavailable: 1933, originalsBudgetCut: 2, mapCandidatesBudgetCut: 1}},
    exitCode: 3});
  assert.match(output, /1933 source-map originals without served source text/);
  assert.match(output, /2 source-map original URLs beyond asset budget/);
  assert.match(output, /1 source-map candidates beyond asset budget/);
  assert.doesNotMatch(output, /1935 source-map originals/);
});

test('summaryText labels virtual source names separately from failed public source fetches', () => {
  const output = summaryText({run: 'bx-map-names', runDir: '/tmp/bx-map-names',
    stats: {}, findings: [], incomplete: true,
    coverage: {requestedClasses: [], rows: [], sourceMaps: {
      originalsUnavailable: 1934, originalsUnresolvable: 1933,
      originalsFetchFailed: 1, originalsBudgetCut: 2,
      appLikelyUnavailable: 0, vendorUnavailable: 1550,
      bundleNamespaceUnavailable: 383, mapCandidatesBudgetCut: 0}},
    exitCode: 3});
  assert.match(output, /1933 source-map names without obtainable source text/);
  assert.match(output, /1 public source-map originals unavailable on replay/);
  assert.match(output, /2 source-map original URLs beyond asset budget/);
  assert.doesNotMatch(output, /1934 source-map originals without served source text/);
});

test('summaryText separates repeated Muse proposals from rejected request shapes', () => {
  const output = summaryText({run: 'bx-repeated', runDir: '/tmp/bx-repeated',
    stats: {model: 'muse-spark-1.3-contributor', modelCalls: 50}, findings: [],
    modelOutput: {rejectedDecisionRecordsByReason: {
      'duplicate-lead': 12, 'duplicate-payload': 1,
      'invalid-sql-baseline': 5, 'unobserved-read-step': 3}}, exitCode: 3});
  assert.match(output, /Muse duplicates\s+13 coalesced · 12 duplicate-lead · 1 duplicate-payload/);
  assert.match(output, /Bypass rejected\s+8 Muse plan\/revision records · 5 invalid-sql-baseline · 3 unobserved-read-step/);
});

test('generic canary behavior is shown as research, without a confirmed bug exit', () => {
  const finding = {id: 'f-001', kind: 'model-differential', severity: 'low',
    verdict: 'confirmed', title: 'Server transformed the submitted value', pattern: '/api/calculate'};
  const exitCode = exitCodeFor({findings: [finding],
    results: [{verdict: 'not_reproduced'}]});
  const output = summaryText({run: 'bx-research', runDir: '/tmp/bx-research',
    stats: {tasks: 1}, findings: [finding], exitCode});
  assert.equal(exitCode, 3);
  assert.match(output, /Findings: none confirmed/);
  assert.match(output, /Research\s+1 reproduced response transformation · impact unverified/);
  assert.match(output, /unrated\s+model-differential/);
  assert.match(output, /observed/);
});

const verdictModule = new URL('../src/blackbox/verdict.mjs', import.meta.url);
test('buildFindings works with the real verdict.mjs classifiers', { skip: !fs.existsSync(verdictModule) && 'src/blackbox/verdict.mjs (T4) not present yet' }, async () => {
  const { severityFor, classify, dataClasses } = await import(verdictModule);
  const findings = buildFindings(resultsFixture(), { surface: surfaceFixture(), scope, severityFor, classify, dataClasses });
  const idor = findings.find(f => f.kind === 'idor');
  assert.ok(['critical', 'high'].includes(idor.severity), `idor severity ${idor.severity}`);
  assert.equal(idor.cwe, 'CWE-639');
  assert.ok(findings.every(f => typeof f.owasp === 'string' && f.owasp.length));
});
