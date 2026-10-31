// Findings, the audit report (report.md and report.json), the terminal summary and the exit code.
// Implements design section 13 (report sections, classification, severity modifiers), 12.3 (remediation
// per kind), 14 (evidence appendix read from the ledger file) and 4.1 (exit codes). Credentials appear
// only as env-var placeholders such as $OWNER_TOKEN; this module never reads credential values.
import fs from 'node:fs';
import path from 'node:path';
import { VERSION } from '../util.mjs';
import {safeAssetHint} from './asset-interpret.mjs';

const SEVERITIES = ['critical', 'high', 'medium', 'low', 'info'];
const RESOLVED = new Set(['confirmed', 'not_reproduced', 'shared', 'public']);
const OPEN = new Set(['inconclusive', 'blocked']);
// The generic canary oracle proves a response transformation, not a security boundary.
const RESEARCH_BEHAVIOR = new Set(['model-differential', 'model-json-differential', 'model-http-sequence']);
const researchBehavior = item => RESEARCH_BEHAVIOR.has(item?.kind);
const PII_CLASSES = new Set(['email', 'phone', 'address', 'name', 'ssn', 'dob']);
const CREDENTIAL_LIKE = /token|secret|password|api.?key|credential/i;
const NOT_REQUESTED_METHODS = new Set(['GET', 'HEAD', 'UNKNOWN']);
const EXIT_MEANING = {
  0: 'every task resolved and nothing was cut',
  1: 'confirmed findings',
  2: 'usage error',
  3: 'incomplete or research observation needs impact assessment',
  130: 'cancelled',
};

const TITLES = {
  idor: 'Cross-account read',
  'graphql-bola': 'GraphQL object readable by another account',
  'nested-idor': 'Cross-account read through a nested route',
  'missing-auth': 'Unauthenticated read',
  bfla: 'Privileged route readable by an ordinary account',
  'list-leak': "List returns other accounts' records",
  'param-filter': "Query parameter exposes other accounts' data",
  enumeration: 'Predictable IDs reach other records',
  existence: 'Documented operation reachable',
  exposure: 'Sensitive path exposed',
};

const REMEDIATION = {
  idor: 'Compare ownership on the item handler: load the record, then return it only when its owner is the authenticated principal.',
  'graphql-bola': 'Check object ownership in the GraphQL item resolver for every caller, using the authenticated principal rather than a client supplied ID.',
  'nested-idor': 'Check the child against the parent on nested routes: the inner record must belong to the outer one, and the caller must be allowed to read both.',
  'missing-auth': 'Require authentication on this route and deny by default, then compare ownership on the item handler.',
  bfla: "Deny by default on privileged routes: check the caller's role on the server for every admin, internal or management route.",
  'list-leak': 'Filter lists by the authenticated principal, never by a parameter.',
  'param-filter': 'Filter lists by the authenticated principal, never by a parameter, and return only the properties the caller may see.',
  enumeration: 'Non-sequential IDs do not replace authorization checks: enforce ownership on every item and answer missing and forbidden records alike.',
  existence: 'Confirm the documented operation should be reachable and give it the same authorization as its sibling routes.',
  exposure: 'Remove debug and management endpoints from public hosts or put them behind authentication and network restrictions.',
  secret: 'Rotate every leaked secret and remove it from the bundle, since removing it from the current build does not revoke it.',
  'vulnerable-library': 'Upgrade or remove the vulnerable library.',
  'source-map': 'Stop serving source maps in production.',
};

const unique = values => [...new Set(values)];
const rank = severity => (SEVERITIES.includes(severity) ? SEVERITIES.indexOf(severity) : SEVERITIES.length);
const principalValue = principal => (principal !== null && typeof principal === 'object' ? principal.value ?? null : principal ?? null);
const evidenceNumber = id => Number(String(id).replace(/\D/g, '')) || 0;
const hashPrefix = value => (value ? String(value).replace(/^sha256:/, '').slice(0, 12) : '');
const plural = (count, word) => `${count} ${word}${count === 1 ? '' : 's'}`;

/**
 * Turn confirmed results and signature-checked exposures into findings (design 13).
 * Keeps one finding per (kind, pattern): the most severe representative, then the widest reach.
 * Info-level exposures stay in the report's surface section and are not findings.
 * @returns {object[]} findings with ids 'f-001'… in severity order
 */
export function buildFindings(results, { surface, scope, originSurfaces = {}, severityFor, classify, dataClasses, webFindings = [] }) {
  const context = { origin: scope.target.origin, identityTags: identityTags(surface?.identity), severityFor, classify, dataClasses };
  const candidates = [
    ...results.filter(result => result.verdict === 'confirmed').map(result => {
      const origin = result.origin ?? scope.target.origin;
      const appSurface = originSurfaces[origin] ?? surface;
      return findingFromResult(result, {...context, origin, identityTags: identityTags(appSurface?.identity)});
    }),
    ...(surface?.exposures ?? []).filter(exposure => exposure.severity !== 'info').map(exposure => findingFromExposure(exposure, context)),
    ...webFindings,
  ];
  const kept = new Map();
  for (const candidate of candidates) {
    const key = `${candidate.kind} ${candidate.host} ${candidate.pattern}`;
    const current = kept.get(key);
    if (!current || outranks(candidate, current)) kept.set(key, candidate);
  }
  return [...kept.values()]
    .sort((a, b) => rank(a.severity) - rank(b.severity))
    .map((finding, index) => ({ id: `f-${String(index + 1).padStart(3, '0')}`, ...finding }));
}

function simpleReflectedXssInput(finding) {
  if (finding?.verdict !== 'confirmed' || !finding.proof || !finding.webProof) return null;
  const proof = finding.webProof;
  let method, path, parameter, identity;
  if (finding.kind === 'xss-reflected') {
    ({method, url: path, as: identity} = proof.request ?? {});
    parameter = proof.parameter;
  } else if (finding.kind === 'model-browser-execution' &&
      proof.assertion?.step === 'subject' &&
      proof.subject?.placement === 'query' &&
      !(proof.prelude?.length || proof.observe?.length || proof.binding ||
        proof.subject?.fixedFields?.length || proof.subject?.headers?.length)) {
    method = proof.subject.method;
    path = proof.subject.path;
    parameter = proof.subject.key;
    identity = proof.as;
  } else return null;
  if (method !== 'GET' || typeof path !== 'string' ||
      typeof parameter !== 'string' || !parameter ||
      typeof identity !== 'string') return null;
  let url;
  try {url = new URL(path, finding.url);} catch {return null;}
  return JSON.stringify([url.origin, url.pathname, method, parameter, identity]);
}

/** Keep every sealed proof while reporting the same browser-executed XSS input once. */
export function consolidateBrowserXssProofs(findings) {
  const reflected = new Map(findings.filter(item => item.kind === 'xss-reflected')
    .map(item => [simpleReflectedXssInput(item), item]).filter(([key]) => key));
  const corroborating = new Set();
  for (const finding of findings) {
    if (finding.kind !== 'model-browser-execution') continue;
    const primary = reflected.get(simpleReflectedXssInput(finding));
    if (!primary || primary.id === finding.id) continue;
    if (primary.corroboratingProofs?.some(item => item.id === finding.id)) {
      corroborating.add(finding.id);
      continue;
    }
    primary.corroboratingProofs = [...(primary.corroboratingProofs ?? []), {
      id: finding.id, kind: finding.kind, proof: finding.proof,
      rule: finding.rule, evidence: finding.evidence ?? [],
      confirmation: finding.confirmation ?? []}];
    primary.evidence = unique([...(primary.evidence ?? []), ...(finding.evidence ?? [])]);
    primary.confirmation = unique([...(primary.confirmation ?? []),
      ...(finding.confirmation ?? [])]);
    primary.tags = unique([...(primary.tags ?? []), ...(finding.tags ?? [])]);
    corroborating.add(finding.id);
  }
  return findings.filter(item => !corroborating.has(item.id));
}

// A proved access recipe can open several pages through the same gate. Keep
// every sealed route proof, but count the shared boundary failure once.
function rawBoundaryKey(finding) {
  if (finding.kind !== 'model-raw-boundary' || finding.verdict !== 'confirmed' ||
      !finding.proof) return null;
  const {rawRequests, rawProof, as} = finding.webProof ?? {};
  if (!rawRequests?.length || !rawProof?.baseline?.length ||
      !rawProof.closedText || !rawProof.openText) return null;
  try {
    const origin = new URL(finding.url).origin;
    const withoutFinalRoute = steps => steps.map((step, index) => {
      if (index !== steps.length - 1) return step;
      const url = new URL(step.path, finding.url);
      return {...step, path: `${url.origin}${url.search}`};
    });
    return JSON.stringify([origin, finding.cwe, finding.severity, as,
      rawProof.closedText, rawProof.openText,
      withoutFinalRoute(rawRequests), withoutFinalRoute(rawProof.baseline)]);
  } catch { return null; }
}

export function consolidateRawBoundaryProofs(findings) {
  const primaryByKey = new Map();
  const corroborating = new Set();
  for (const finding of findings) {
    const key = rawBoundaryKey(finding);
    if (!key) continue;
    const primary = primaryByKey.get(key);
    if (!primary) {
      primaryByKey.set(key, finding);
      const gate = safeAssetHint(finding.webProof.rawProof.closedText);
      finding.title = gate && gate !== '[redacted]' ?
        `Access gate bypass: ${gate.replace(/\|/g, '/')}` : 'Access gate bypass';
      continue;
    }
    primary.corroboratingProofs = [...(primary.corroboratingProofs ?? []), {
      id: finding.id, kind: finding.kind, pattern: finding.pattern,
      proof: finding.proof, rule: finding.rule,
      evidence: finding.evidence ?? [], confirmation: finding.confirmation ?? []}];
    primary.evidence = unique([...(primary.evidence ?? []), ...(finding.evidence ?? [])]);
    primary.confirmation = unique([...(primary.confirmation ?? []),
      ...(finding.confirmation ?? [])]);
    primary.tags = unique([...(primary.tags ?? []), ...(finding.tags ?? [])]);
    corroborating.add(finding.id);
  }
  return findings.filter(item => !corroborating.has(item.id));
}

function outranks(candidate, current) {
  if (rank(candidate.severity) !== rank(current.severity)) return rank(candidate.severity) < rank(current.severity);
  return candidate.reach.observed > current.reach.observed;
}

function findingFromResult(result, { origin, identityTags: tags, severityFor, classify, dataClasses }) {
  const { task } = result;
  const leaked = result.T ?? {};
  // A list's shape stops at 'array'; the field types of its records are what carry the data classes.
  const classes = unique(dataClasses(leaked.fields ? { ...leaked, shape: { ...leaked.shape, ...leaked.fields } } : leaked) ?? []).sort();
  const list = Number.isInteger(leaked.items);
  const observed = list ? leaked.items : 1;
  const credentialLike = classes.some(name => CREDENTIAL_LIKE.test(name));
  const pii = classes.some(name => PII_CLASSES.has(name));
  const severity = severityFor(task.kind, { dataClasses: classes, reach: observed, list, pii, credentialLike, chain: false });
  const { owasp = null, cwe = null } = classify(task.kind) ?? {};
  const url = new URL(task.request.url, origin);
  const where = `${url.pathname}${url.search}`;
  return {
    kind: task.kind,
    title: task.kind === 'graphql-bola' ?
      `${TITLES[task.kind]}: ${task.graphql.itemField} at ${task.pattern}` :
      `${TITLES[task.kind] ?? task.kind}: ${task.pattern}${url.search ? ` with ${url.search}` : ''}`,
    severity, owasp, cwe, pattern: task.pattern, url: url.href, host: url.host, task: task.id,
    verdict: 'confirmed', rule: result.rule, evidence: result.evidence ?? [], confirmation: result.confirmation ?? [],
    mirror: result.mirror ?? { result: 'unverified', evidence: [], reason: 'mirror not run' },
    tags: unique([...(result.tags ?? []), ...tags, ...(credentialLike ? ['credential-like'] : [])]),
    reach: {
      observed,
      basis: list
        ? `${observed} items returned to the ${task.request.as} by ${where} (${leaked.evidenceId})`
        : `one record read by the ${task.request.as} (${leaked.evidenceId})`,
    },
    dataClasses: classes, remediation: REMEDIATION[task.kind] ?? '', foundBy: task.origin ?? 'baseline', status: 'open',
  };
}

function findingFromExposure(exposure, { origin, classify }) {
  const url = new URL(exposure.url ?? exposure.path, origin);
  const { owasp = null, cwe = null } = classify('exposure') ?? {};
  return {
    kind: 'exposure', title: `${TITLES.exposure}: ${exposure.path}`, severity: exposure.severity, owasp, cwe,
    pattern: exposure.path, url: url.href, host: url.host, task: null, verdict: 'confirmed', rule: 'exposure/signature',
    evidence: [exposure.evidenceId].filter(Boolean), confirmation: [exposure.confirmationEvidence].filter(Boolean),
    exposureHash: exposure.hash ?? null,
    mirror: { result: 'unverified', evidence: [], reason: 'not a cross-account finding' }, tags: [],
    reach: { observed: 1, basis: `body matched the ${exposure.signature} signature (${exposure.evidenceId})` },
    dataClasses: [], remediation: REMEDIATION.exposure,
    foundBy: exposure.source ?? 'wordlist', status: 'open',
  };
}

// Design 6.5 and 9.4: no identity endpoint tags every finding; differing role fields tag it too.
function identityTags(identity) {
  const tags = identity?.verified ? [] : identity?.ownerVerified ? ['owner-identity-only'] : ['identity-unverified'];
  const owner = identity?.roles?.owner ?? {};
  const outsider = identity?.roles?.outsider ?? {};
  const keys = unique([...Object.keys(owner), ...Object.keys(outsider)]);
  if (identity?.principals?.outsider != null &&
      keys.some(key => JSON.stringify(owner[key]) !== JSON.stringify(outsider[key]))) tags.push('role-mismatch');
  return tags;
}

/**
 * Exit code for an audit run (design 4.1): 1 when a security finding is confirmed; 0 only when every
 * result is resolved and nothing is untested or blocked; 3 for open work or an unclassified behavior.
 * A run with no results tested nothing, so it exits 3 rather than reading as clean.
 */
export function exitCodeFor({ findings = [], results = [], untested = [], blockedRun = false }) {
  if (findings.some(finding => finding.verdict === 'confirmed' && !researchBehavior(finding)) ||
      results.some(result => result.verdict === 'confirmed' && !researchBehavior(result))) return 1;
  if (findings.some(researchBehavior) || results.some(result =>
      researchBehavior(result) && result.verdict === 'confirmed')) return 3;
  if (blockedRun || untested.length || !results.length) return 3;
  return results.every(result => RESOLVED.has(result.verdict)) ? 0 : 3;
}

/**
 * Render report.md and report.json (design 13). Optional inputs: `untested` and `dropped` from the
 * planner, `integrity` from verifyLedger(), `recheck` from identityRecheck(). `stats` may carry
 * startedAt, finishedAt, tasks, requests, cached, elapsedMs, rps, agents, model and modelCalls.
 * @returns {{markdown: string, json: object}} json is the report object with the same sections
 */
export function renderReport({
  run, scope, scopeHash, surface, findings, results, chains = [], mined = null, discovery = null, web = null, coverage = null, advisories = null, stats = {}, ledgerFile,
  credentialAudits = [], untested = [], dropped = [], integrity = null, recheck = null, extraLimitations = [],
}) {
  const ledger = readLedger(ledgerFile);
  const byTask = new Map(results.map(result => [result.task?.id, result]));
  const assets = mined ?? surface?.mined ?? null;
  const report = {
    schemaVersion: 1,
    kind: 'blackbox-report',
    header: headerSection({ run, scope, scopeHash, stats, integrity }),
    summary: summarySection(findings, results, web),
    scope: scopeSection(scope, surface, stats, dropped, recheck),
    surface: surfaceSection(surface, assets, results, untested, discovery, credentialAudits, scope.target.origin, advisories),
    findings: findings.map(finding => findingSection(finding, finding.task ? byTask.get(finding.task) : null, scope, ledger)),
    chains,
    inconclusive: [
      ...results.filter(result => OPEN.has(result.verdict)).map(openItem),
      ...(web?.results ?? []).filter(result => OPEN.has(result.verdict)).map(result => ({
        task: result.lead.parameter ? `${result.origin ?? scope.target.origin}${result.lead.path}?${result.lead.parameter}` :
          `${result.origin ?? scope.target.origin}${result.lead.path}`,
        kind: result.kind ?? 'open-redirect', pattern: result.lead.path,
        as: result.kind === 'cors-reflection' ? 'owner' : result.lead.as ?? 'anonymous',
        method: result.kind === 'xss-dom-fragment' ? 'BROWSER' :
          result.kind === 'xxe-body-hosts' ? 'POST' : result.lead.method ?? 'GET',
        url: new URL(result.lead.path, result.origin ?? scope.target.origin).href,
        verdict: result.verdict, rule: result.kind === 'cors-reflection' ? 'cors-probe' :
          result.kind === 'ssrf-loopback' ? 'ssrf-loopback-probe' :
          result.kind === 'http-parameter-pollution' ? 'duplicate-query-redirect-probe' :
          result.kind === 'host-header-redirect' ? 'host-header-redirect-probe' :
          result.kind === 'jwt-unsigned' ? 'jwt-unsigned-probe' :
          result.kind === 'crlf-header' ? 'crlf-response-header-probe' :
          result.kind === 'xss-dom-fragment' ? 'browser-dom-fragment-probe' :
          result.kind === 'xss-reflected' ? 'browser-xss-probe' :
          result.kind === 'ssti-arithmetic' ? 'ssti-arithmetic-probe' :
          result.kind === 'sql-boolean' ? 'sql-boolean-probe' :
          result.kind === 'nosql-operator-bypass' ? 'nosql-operator-probe' :
          result.kind === 'command-output' ? 'command-output-probe' :
          result.kind === 'path-traversal-hosts' ? 'path-traversal-probe' :
          ['public-private-key', 'public-api-credential'].includes(result.kind) ? 'public-secret-probe' :
          ['xxe-hosts', 'xxe-body-hosts'].includes(result.kind) ? 'xml-entity-probe' : 'redirect-probe',
        reason: result.reason, evidence: result.evidence ?? [], tags: [],
      })),
      ...chains.filter(chain => chain.status !== 'confirmed').map(openChain),
    ],
    limitations: limitations({ scope, surface, assets, untested, stats, discovery, advisories, extraLimitations }),
    coverage,
    ledgerFile: { found: ledger.found, unreadableLines: ledger.unreadable },
    evidence: [],
  };
  report.evidence = citedIds(report).map(id => evidenceRow(id, ledger));
  return { markdown: toMarkdown(report), json: report };
}

function readLedger(file) {
  const records = new Map();
  if (!file || !fs.existsSync(file)) return { found: false, records, unreadable: 0 };
  let unreadable = 0;
  // Read whole: one run's ledger is a few MB at most; streaming would buy nothing at this size.
  for (const line of fs.readFileSync(file, 'utf8').split('\n')) {
    if (!line.trim()) continue;
    const record = parseLedgerLine(line);
    if (record?.id) records.set(record.id, record);
    else unreadable += 1;
  }
  return { found: true, records, unreadable };
}

// A torn or corrupt line is counted and printed in the appendix; verifyLedger() reports where the chain broke.
function parseLedgerLine(line) {
  try {
    return JSON.parse(line);
  } catch {
    return null;
  }
}

function headerSection({ run, scope, scopeHash, stats, integrity }) {
  return {
    origin: scope.target.origin, environment: scope.target.environment, domains: scope.domains ?? [], run,
    startedAt: stats.startedAt ?? null, finishedAt: stats.finishedAt ?? null, version: VERSION,
    model: stats.model ?? null, modelCalls: stats.modelCalls ?? 0, modelCallCap: scope.limits?.modelCalls ?? null,
    scopeHash, ledger: integrityLine(integrity),
    accounts: { owner: account(scope, 'owner'), outsider: account(scope, 'outsider'), auth: scope.identities?.auth ?? 'bearer' },
  };
}

function account(scope, name) {
  return { env: scope.identities?.[name]?.env ?? null, role: scope.identities?.[name]?.role ?? null };
}

function integrityLine(integrity) {
  if (!integrity) return 'ledger integrity not checked';
  const count = plural(Number(integrity.records ?? 0), 'record').replace(/^\d+/, n => Number(n).toLocaleString('en-US'));
  return integrity.ok ? `ledger intact (${count})` : `ledger broken at ${integrity.brokenAt} (${count})`;
}

function summarySection(findings, results, web) {
  const confirmed = findings.filter(finding => !researchBehavior(finding));
  const observations = findings.filter(researchBehavior);
  const corroboratingProofs = confirmed.reduce((count, finding) =>
    count + (finding.corroboratingProofs?.length ?? 0), 0);
  const counts = Object.fromEntries(SEVERITIES.map(severity =>
    [severity, confirmed.filter(f => f.severity === severity).length]));
  const open = results.filter(result => OPEN.has(result.verdict)).length +
    (web?.results ?? []).filter(result => OPEN.has(result.verdict)).length;
  const allChecks = [...results, ...(web?.results ?? [])];
  const executed = allChecks.filter(result => result.verdict !== 'untested').length;
  const queued = allChecks.length - executed;
  const bySeverity = SEVERITIES.filter(severity => counts[severity]).map(severity => `${counts[severity]} ${severity}`).join(', ');
  const found = confirmed.length ? `${plural(confirmed.length, 'confirmed finding')} (${bySeverity})${corroboratingProofs ?
    ` with ${plural(corroboratingProofs, 'additional independent proof')}` : ''}` : 'No confirmed findings';
  const observed = observations.length ? ` ${plural(observations.length, 'verified response transformation')} requires security impact assessment.` : '';
  const listed = `${plural(open, 'inconclusive or blocked item')} ${open === 1 ? 'is' : 'are'} listed in section 7`;
  return {
    narrative: `${found}.${observed} ${plural(executed, 'task')} ran${queued ? `; ${plural(queued, 'task')} remained queued` : ''}; ${listed}.`,
    counts,
    corroboratingProofs,
    researchObservations: observations.length,
    findings: findings.map(({ id, title, host, pattern, severity, status, kind, foundBy, tags,
      corroboratingProofs }) => (
      { id, title, host, pattern, severity: RESEARCH_BEHAVIOR.has(kind) ? 'unrated' : severity,
        status, kind, foundBy, tags,
        ...(corroboratingProofs?.length ?
          {corroboratingProofIds: corroboratingProofs.map(item => item.id)} : {}),
        verdict: RESEARCH_BEHAVIOR.has(kind) ? 'observed' : 'confirmed' }
    )),
  };
}

function scopeSection(scope, surface, stats, dropped, recheck) {
  const identity = surface?.identity ?? {};
  return {
    domains: scope.domains ?? [], auditDomains: scope.discovery?.auditDomains ?? [],
    include: scope.include ?? [], never: scope.never ?? [], limits: scope.limits ?? {},
    credentialOrigins: scope.credentialOrigins ?? [scope.target.origin],
    excluded: {
      outOfScope: surface?.outOfScope ?? [],
      never: surface?.never ?? [],
      dropped: dropped.map(item => ({ task: item.task?.id ?? null, reason: item.reason })),
    },
    identities: {
      owner: account(scope, 'owner'), outsider: account(scope, 'outsider'), auth: scope.identities?.auth ?? 'bearer',
      identityPath: identity.path ?? scope.identities?.identityPath ?? null,
    },
    execution: {
      agents: stats.agents ?? null, waves: scope.limits?.waves ?? 1, tasks: stats.tasks ?? null, requests: stats.requests ?? null,
      museAgentsConfigured: stats.modelWorkersConfigured ?? scope.limits?.modelConcurrency ?? null,
      museAgentsPeak: stats.modelWorkersPeak ?? 0,
      httpWorkersConfigured: stats.webWorkersConfigured ?? scope.limits?.agents ?? null,
      httpWorkersPeak: stats.webWorkersPeak ?? stats.agents ?? 0,
      cached: stats.cached ?? null, elapsedMs: stats.elapsedMs ?? null, rps: stats.rps ?? null,
    },
    control: {
      verified: !!identity.verified,
      ownerVerified: !!identity.ownerVerified,
      principals: { owner: principalValue(identity.principals?.owner), outsider: principalValue(identity.principals?.outsider) },
      roles: identity.roles ?? {}, evidence: identity.evidence ?? [],
      recheck: recheck ? { ok: recheck.ok, reason: recheck.reason, evidence: recheck.evidence ?? [] } : null,
      statement: controlStatement(identity, recheck),
    },
    model: { calls: stats.modelCalls ?? 0, note: stats.model ? `model ${stats.model}` : 'code-only run: no model calls and no model proposals' },
  };
}

function controlStatement(identity, recheck) {
  const owner = principalValue(identity.principals?.owner);
  const outsider = principalValue(identity.principals?.outsider);
  const evidence = (identity.evidence ?? []).join(', ') || 'no evidence IDs';
  const parts = [identity.verified
    ? `The identity endpoint ${identity.path} returned principal ${owner} for the owner and ${outsider} for the outsider (${evidence}).`
    : identity.ownerVerified ?
      `The identity endpoint ${identity.path} returned owner principal ${owner} and denied an anonymous read (${evidence}); the outsider account boundary was not verified. Findings are tagged owner-identity-only.` :
      'No identity endpoint proved the two accounts; every finding is tagged identity-unverified.'];
  if (identityTags(identity).includes('role-mismatch')) {
    parts.push('Role-looking fields differ between the accounts; every finding is tagged role-mismatch.');
  }
  if (recheck) parts.push(recheck.ok ? 'Re-checked at the end of the wave: unchanged.' : `Re-check at the end of the wave failed: ${recheck.reason}.`);
  return parts.join(' ');
}

function surfaceSection(surface, assets, results, untested, discovery, credentialAudits = [], primaryOrigin, advisories = null) {
  const files = [...new Map([...(assets?.files ?? []), ...(discovery?.hosts ?? []).flatMap(host => host.assets?.files ?? []),
    ...credentialAudits.flatMap(audit => audit.mined?.files ?? [])]
    .map(file => [file.url, file])).values()];
  const publicShared = new Map();
  for (const result of results.filter(r => (!r.origin || r.origin === primaryOrigin) &&
      (r.verdict === 'public' || r.verdict === 'shared'))) {
    publicShared.set(`${result.task.pattern} ${result.verdict}`, { pattern: result.task.pattern, verdict: result.verdict, task: result.task.id });
  }
  const taskOrigins = new Map(credentialAudits.flatMap(audit =>
    [...audit.plan.tasks, ...audit.plan.untested].map(task => [task.id, audit.origin])));
  return {
    external: {
      discovery: discovery ? `${discovery.stats.hostsFound} resolved hosts; ${discovery.stats.hostsLive} live; ${discovery.stats.dnsQueries} DNS queries; ${discovery.stats.tlsHandshakes ?? 0} TLS certificate lookups; ${discovery.stats.cut} incomplete discovery checks.` :
        `External discovery did not run; ${1 + credentialAudits.length} explicitly configured application origin${credentialAudits.length ? 's were' : ' was'} analyzed.`,
      discoveredHosts: discovery?.hosts?.map(host => ({host: host.host, depth: host.depth, foundBy: host.foundBy,
        addresses: host.addresses, origin: host.origin ?? null, live: host.live, title: host.title,
        stack: host.stack, certificate: host.certificate ?? null, exposures: host.exposures,
        assets: host.assets?.files?.length ?? 0, alias: host.alias ?? null, audit: host.audit ?? null,
        graphql: host.graphql ?? null, responseFollowup: host.responseFollowup ?? null,
        role: host.analysis?.role ?? null, roleReason: host.analysis?.why ?? null,
        operations: host.operations ?? [], operationCut: host.operationCut ?? 0})) ?? [],
      modelAnalysis: discovery?.modelAnalysis ?? null,
      modelNaming: discovery?.modelNaming ?? null,
      assetModelAnalysis: assets?.modelAnalysis ?? discovery?.assetModelAnalysis ?? null,
      advisories,
      files: files.map(file => ({
        url: file.url, bytes: file.bytes ?? null, endpoints: file.endpoints?.length ?? 0, secrets: file.secrets?.length ?? 0,
        libraries: (file.libraries ?? []).map(library => `${library.name} ${library.version ?? ''}`.trim()),
        sourceMap: file.sourceMap ?? null, sourcesCut: file.sourcesCut ?? 0,
        analysis: file.analysis ?? null,
        operations: (file.endpoints ?? []).slice(0, 16).map(item => ({method: item.method, path: item.path,
          params: item.params ?? [], examples: item.examples ?? {}, purpose: item.purpose ?? null,
          parameterMeanings: item.parameterMeanings ?? [],
          sourceFiles: (item.sources ?? (item.source ? [item.source] : [])).slice(0, 8).map(safeAssetHint)})),
        operationsCut: Math.max(0, (file.endpoints?.length ?? 0) - 16),
      })),
      secrets: files.flatMap(file => (file.secrets ?? []).map(secret => ({
        name: secret.name, masked: secret.masked, confidence: secret.confidence, public: !!secret.public,
        location: `${file.url}:${secret.line}:${secret.column}`,
      }))),
      hosts: assets?.hosts ?? [],
    },
    exposures: surface?.exposures ?? [],
    application: {
      patterns: (surface?.patterns ?? []).map(patternRow),
      routeRecon: surface?.routeRecon ?? null,
      exposureSelection: surface?.exposureSelection ?? null,
      modelNotes: surface?.modelNotes ?? [],
      modelFollowup: surface?.modelFollowup ?? [],
      anonymousResponseFollowup: surface?.anonymousResponseFollowup ?? null,
      accessFollowup: surface?.accessFollowup ?? null,
      graphql: surface?.graphql ?? null,
      sourceReview: surface?.sourceReview ?? null,
      publicShared: [...publicShared.values()],
      otherOrigins: credentialAudits.map(audit => ({origin: audit.origin,
        identityVerified: !!audit.surface.identity?.verified,
        identityEvidence: audit.surface.identity?.evidence ?? [],
        patterns: (audit.surface.patterns ?? []).map(patternRow),
        publicShared: audit.results.filter(result => result.verdict === 'public' || result.verdict === 'shared')
          .map(result => ({pattern: result.task.pattern, verdict: result.verdict, task: result.task.id})),
        tasks: audit.plan.tasks.length, tested: audit.results.length,
        webTested: audit.web?.tested ?? 0, webCut: audit.web?.cut ?? 0,
        assets: audit.mined?.files?.length ?? 0, modelNotes: audit.surface.modelNotes ?? [],
        anonymousResponseFollowup: audit.surface.anonymousResponseFollowup ?? null,
        accessFollowup: audit.surface.accessFollowup ?? null,
        graphql: audit.surface.graphql ?? null,
        nonGet: nonGetOperations(audit.mined)})),
      untested: untested.map(item => ({
        id: item.id, kind: item.kind, pattern: item.pattern,
        url: item.request?.url ? new URL(item.request.url, taskOrigins.get(item.id) ?? primaryOrigin).href : null,
        as: item.request?.as ?? null, priority: item.priority ?? null,
      })),
      nonGet: nonGetOperations(assets),
    },
  };
}

// Non-GET operations named in mined assets. Exact reviewed POST routes may be tested separately.
function nonGetOperations(assets) {
  return (assets?.endpoints ?? [])
    .filter(endpoint => !NOT_REQUESTED_METHODS.has(endpoint.method))
    .map(endpoint => ({ method: endpoint.method, path: endpoint.path }));
}

function patternRow(pattern) {
  const fingerprint = pattern.fingerprint ?? {};
  return {
    pattern: pattern.pattern, label: pattern.label?.kind ?? 'unknown', source: pattern.source ?? [],
    statuses: {
      owner: fingerprint.owner?.status ?? null, outsider: fingerprint.outsider?.status ?? null,
      anonymous: fingerprint.anonymous?.status ?? null, notFound: fingerprint.notFound?.status ?? null,
    },
    private: Object.keys(pattern.private ?? {}).length > 0,
    ids: { owner: pattern.ids?.ownerIds?.length ?? 0, outsider: pattern.ids?.outsiderIds?.length ?? 0 },
  };
}

function findingSection(finding, result, scope, ledger) {
  const steps = result ? resultSteps(result, result.origin ?? scope.target.origin) :
    finding.webSteps ?? [exposureStep(finding, ledger)];
  const evidenceIds = unique([...finding.evidence, ...finding.confirmation, ...(finding.mirror?.evidence ?? [])]);
  const classes = finding.dataClasses.length ? `data classes: ${finding.dataClasses.join(', ')}` : 'no sensitive data classes recorded';
  return {
    ...finding,
    verdict: researchBehavior(finding) ? 'observed' : finding.verdict,
    severity: researchBehavior(finding) ? 'unrated' : finding.severity,
    rationale: `${classes} · ${finding.reach.basis}`,
    reproduction: steps,
    curl: (['xss-dom-fragment', 'jwt-unsigned', 'model-json-differential', 'model-http-sequence',
      'model-cookie-access', 'model-raw-boundary',
      'model-browser-execution',
      'model-access-boundary', 'xss-stored'].includes(finding.kind) ||
      steps.some(step => step.identity === 'derived' || !['GET', 'HEAD'].includes(step.method))) && finding.proof ?
      [`node '${finding.proof.replaceAll("'", "'\\''")}'`] :
      steps.map(step => curlLine(step, scope.identities ?? {})),
    evidenceTable: evidenceIds.map(id => evidenceRow(id, ledger)),
    proof: finding.proof ?? 'not generated',
  };
}

// Reviewer order (design 11): the owner control first, then the task identity, then anonymous.
function resultSteps({ task, O, T, A }, origin) {
  const method = task.request.method ?? 'GET';
  const step = (identity, verb, url, response) => (
    { identity, method: verb, url: new URL(url, origin).href, status: response?.status ?? null, evidence: response?.evidenceId ?? null }
  );
  const steps = [step(task.control.as ?? 'owner', 'GET', task.control.url, O), step(task.request.as, method, task.request.url, T)];
  if (task.request.as !== 'anonymous') steps.push(step('anonymous', method, task.request.url, A));
  return steps;
}

function exposureStep(finding, ledger) {
  const evidence = finding.evidence[0] ?? null;
  return { identity: 'anonymous', method: 'GET', url: finding.url, status: ledger.records.get(evidence)?.response?.status ?? null, evidence };
}

function curlLine({ identity, method, url, origin, hostHeader }, identities) {
  const parts = ['curl -sS', method === 'HEAD' ? '-I' : '-i'];
  const header = credentialHeader(identity, identities);
  if (header) parts.push(`-H "${header}"`);
  if (origin) parts.push(`-H 'Origin: ${origin}'`);
  if (['bypass-audit.invalid', 'bypass-audit-two.invalid'].includes(hostHeader))
    parts.push(`-H 'Host: ${hostHeader}'`);
  parts.push(`'${url.replaceAll("'", "'\\''")}'`);
  return parts.join(' ');
}

// A placeholder, never a value: the reviewer's shell expands $NAME from their own environment.
function credentialHeader(identity, identities) {
  if (identity === 'anonymous') return null;
  if (identity === 'public-token') return 'Authorization: Bearer $PUBLIC_SESSION_TOKEN';
  if (identity === 'invalid-token') return 'Authorization: Bearer $INVALID_TEST_TOKEN';
  const placeholder = `$${identities[identity]?.env}`;
  const auth = identities.auth ?? 'bearer';
  if (auth === 'cookie') return `Cookie: ${placeholder}`;
  if (auth.startsWith('header:')) return `${auth.slice('header:'.length)}: ${placeholder}`;
  return `Authorization: Bearer ${placeholder}`;
}

function evidenceRow(id, ledger) {
  const record = ledger.records.get(id);
  if (!record) return { id, missing: true };
  return {
    id, at: record.at ?? null, step: record.step ?? null, identity: record.identity ?? null,
    method: record.request?.method ?? null, url: record.request?.url ?? null, status: record.response?.status ?? null,
    type: record.response?.headers?.['content-type'] ?? null, bytes: record.response?.bytes ?? null,
    hash: hashPrefix(record.response?.hash), refused: record.refused ?? null, blocked: record.blocked ?? null,
  };
}

function openItem(result) {
  const { task } = result;
  return {
    task: task.id, kind: task.kind, pattern: task.pattern, as: task.request.as, method: task.request.method ?? 'GET',
    url: result.origin ? new URL(task.request.url, result.origin).href : task.request.url,
    verdict: result.verdict, rule: result.rule, reason: result.reason ?? '', evidence: result.evidence ?? [], tags: result.tags ?? [],
  };
}

function openChain(chain) {
  return {
    task: chain.id, kind: `chain:${chain.template}`, pattern: null, as: null, method: null, url: null, verdict: chain.status,
    rule: chain.template, reason: 'a chain link did not hold', evidence: (chain.steps ?? []).flatMap(step => step.evidence ?? []), tags: [],
  };
}

function limitations({ scope, surface, assets, untested, stats, discovery, advisories, extraLimitations }) {
  const nonGet = nonGetOperations(assets).length;
  const methods = (scope.methods ?? ['GET', 'HEAD']).join(' and ');
  const observed = `${plural(nonGet, 'non-GET operation')} seen in assets; observed contracts for any authorized method may be investigated and replayed`;
  const never = plural(surface?.never?.length ?? 0, 'path');
  const skippedRecon = plural(surface?.outOfScope?.length ?? 0, 'recon candidate');
  const roles = `owner ${scope.identities?.owner?.role ?? 'undeclared'}, outsider ${scope.identities?.outsider?.role ?? 'undeclared'}`;
  const identity = surface?.identity?.verified ? 'the identity endpoint proved two distinct principals' : 'no identity endpoint proved the accounts';
  const elapsed = stats.elapsedMs == null ? '' : ` (${(stats.elapsedMs / 1000).toFixed(1)} s of task execution)`;
  return [
    `Methods selected for this audit: ${methods}. ${observed}.`,
    `Skipped during discovery or planning: ${never} matched by never, ${skippedRecon} refused by method, scope or budget, ${plural(untested.length, 'task')} beyond the task budget. Reviewed operations may still be tested later.`,
    discovery ? `Discovery reached ${discovery.stats.hostsFound} hosts and left ${discovery.stats.cut} checks incomplete; ${discovery.stats.tlsFailures ?? 0} TLS certificate lookups failed; Wayback lookups were not run.` :
      'External host discovery did not run.',
    advisories?.status === 'checked' ?
      `OSV checked ${advisories.stats.checked} of ${advisories.stats.available} detected client-library versions. Advisory matches are version leads, not proof that vulnerable code is reachable.` :
      advisories?.status === 'offline' ? 'OSV lookups were skipped by --offline.' :
      advisories?.status === 'no-libraries' ? 'OSV was enabled, but no eligible client-library version was detected.' :
      'OSV lookups were disabled in the scope; libraries are listed without advisory checks.',
    `Roles are as declared in the scope (${roles}) and not otherwise attested; ${identity}.`,
    `Time window: ${stats.startedAt ?? 'unknown'} to ${stats.finishedAt ?? 'unknown'}${elapsed}.`,
    ...extraLimitations,
    `Model calls: ${stats.modelCalls ?? 0}${stats.model ? ` (${stats.model})` : ' (code-only run)'}.`,
    'Silence is not safety: a host or route without a finding was not shown to be safe.',
  ];
}

function citedIds(report) {
  const ids = [
    ...report.scope.control.evidence,
    ...(report.surface.application.otherOrigins ?? []).flatMap(origin => origin.identityEvidence ?? []),
    ...(report.surface.application.graphql?.attempts ?? []).map(attempt => attempt.evidenceId),
    ...(report.surface.application.graphql?.bola?.typeAttempts ?? []).map(attempt => attempt.evidenceId),
    ...(report.surface.application.graphql?.bola?.listAttempts ?? []).flatMap(attempt => attempt.evidence ?? []),
    ...(report.surface.application.otherOrigins ?? []).flatMap(origin =>
      (origin.graphql?.attempts ?? []).map(attempt => attempt.evidenceId)),
    ...(report.surface.application.otherOrigins ?? []).flatMap(origin => [
      ...(origin.graphql?.bola?.typeAttempts ?? []).map(attempt => attempt.evidenceId),
      ...(origin.graphql?.bola?.listAttempts ?? []).flatMap(attempt => attempt.evidence ?? []),
    ]),
    ...(report.surface.external.discoveredHosts ?? []).flatMap(host =>
      (host.graphql?.attempts ?? []).map(attempt => attempt.evidenceId)),
    ...(report.surface.external.advisories?.records ?? []).flatMap(record => record.evidence ?? []),
    ...(report.scope.control.recheck?.evidence ?? []),
    ...report.surface.exposures.map(exposure => exposure.evidenceId),
    ...report.findings.flatMap(finding => [...finding.evidence, ...finding.confirmation, ...(finding.mirror?.evidence ?? [])]),
    ...report.chains.flatMap(chain => (chain.steps ?? []).flatMap(step => step.evidence ?? [])),
    ...report.inconclusive.flatMap(item => item.evidence),
  ];
  return unique(ids.filter(Boolean)).sort((a, b) => evidenceNumber(a) - evidenceNumber(b));
}

// ---- Markdown rendering: every section is drawn from the report object, so report.md and report.json agree.

const cell = value => String(value ?? '').replace(/\|/g, '\\|').replace(/\r?\n/g, ' ');
const code = value => `\`${String(value ?? '').replace(/`/g, "'").replace(/\r?\n/g, ' ')}\``;
const list = (values, render = code) => (values.length ? values.map(render).join(', ') : 'none');

function table(headers, rows) {
  return [`| ${headers.join(' | ')} |`, `|${headers.map(() => '---').join('|')}|`, ...rows.map(row => `| ${row.map(cell).join(' | ')} |`)];
}

function toMarkdown(report) {
  return [
    ...markdownHeader(report.header), '',
    ...markdownSummary(report.summary), '',
    ...markdownScope(report.scope), '',
    ...markdownExternal(report.surface), '',
    ...markdownApplication(report.surface.application), '',
    ...markdownFindings(report.findings), '',
    ...markdownChains(report.chains), '',
    ...markdownOpen(report.inconclusive), '',
    '## 8. Limitations', '', ...report.limitations.map((line, index) => `${index + 1}. ${line}`), '',
    ...(report.coverage ? ['### Family coverage', '', report.coverage.statement, '',
      ...table(['Family', 'Status', 'Attempts', 'Reason'], report.coverage.rows.map(row =>
        [row.description, row.status, row.attempts, row.reason ?? 'Bounded probes ran; see the task and evidence sections.'])), '',
      '### Requested vulnerability classes', '',
      ...table(['Category', 'Class', 'Status', 'Attempts'], (report.coverage.requestedClasses ?? []).map(row =>
        [row.category, row.name, row.status, row.attempts])), ''] : []),
    ...markdownAppendix(report.evidence, report.ledgerFile), '',
  ].join('\n');
}

// Accounts are named by env-var placeholder and declared role, never by credential value.
function accountsText({ owner, outsider }, separator) {
  const one = (label, account) => `${label} ${code(`$${account.env}`)} (${account.role ?? 'role undeclared'})`;
  return `${one('owner', owner)}${separator}${one('outsider', outsider)}`;
}

function markdownHeader(header) {
  const model = header.model ? `${header.model}` : 'none (code-only)';
  return [
    '# Black-box audit report', '',
    ...table(['Field', 'Value'], [
      ['Target', `${code(header.origin)} (${header.environment})`],
      ['Domains', list(header.domains)],
      ['Run', header.run],
      ['Started', header.startedAt ?? 'unknown'],
      ['Finished', header.finishedAt ?? 'unknown'],
      ['Bypass version', header.version],
      ['Model', `${model} · ${header.modelCalls} of ${header.modelCallCap ?? '?'} calls`],
      ['Scope hash', code(header.scopeHash)],
      ['Ledger', header.ledger],
      ['Configured account variables', `${accountsText(header.accounts, ' · ')} · ${header.accounts.auth}`],
    ]),
  ];
}

function markdownSummary(summary) {
  const lines = ['## 1. Executive summary', '', summary.narrative];
  if (!summary.findings.length) return lines;
  return [...lines, '', ...table(['ID', 'Title', 'Host', 'Pattern', 'Severity', 'Verdict', 'Kind', 'Found by'],
    summary.findings.map(f => [f.id, f.title, f.host, code(f.pattern), f.severity, f.verdict, f.kind, f.foundBy]))];
}

function markdownScope(scope) {
  const { auth, identityPath } = scope.identities;
  const run = scope.execution;
  const seconds = run.elapsedMs == null ? '?' : (run.elapsedMs / 1000).toFixed(1);
  const execution = [`Muse agents ${run.museAgentsConfigured ?? scope.limits?.modelConcurrency ?? '?'} configured (peak ${run.museAgentsPeak ?? 0})`,
    `HTTP workers ${run.httpWorkersConfigured ?? scope.limits?.agents ?? '?'} configured (peak ${run.httpWorkersPeak ?? run.agents ?? 0})`,
    `${run.waves} wave`, `${run.tasks ?? '?'} tasks`, `${run.requests ?? '?'} requests`,
    `${run.cached ?? 0} served from cache`, `${seconds} s`, `${run.rps ?? '?'} rps`];
  const excluded = [
    ...scope.excluded.outOfScope.map(item => [code(`${item.method ? `${item.method} ` : ''}${item.url}`),
      item.reason === 'method' ? 'general recon method refused; a reviewed operation may be tested later' :
        item.reason === 'budget' ? 'recon URL budget' :
          item.reason === 'include' ? 'outside include' : `recon skipped: ${item.reason ?? 'scope'}`]),
    ...scope.excluded.never.map(item => [code(item.url), `matched never: ${item.match}`]),
    ...scope.excluded.dropped.map(item => [item.task ?? 'proposal', `dropped by validation: ${item.reason}`]),
  ];
  return [
    '## 2. Scope and method', '',
    `- Domains: ${list(scope.domains)}`,
    `- Active descendant audit domains: ${list(scope.auditDomains)}`,
    `- Include: ${list(scope.include)}`,
    `- Never: ${list(scope.never)}`,
    `- Limits: ${Object.entries(scope.limits).map(([name, value]) => `${name} ${value}`).join(' · ') || 'defaults'}`,
    `- Credential origins: ${list(scope.credentialOrigins)}`,
    `- Account configuration: ${accountsText(scope.identities, ', ')}, ${auth}, identity path ${identityPath ? code(identityPath) : 'not found'}`,
    `- Execution: ${execution.join(' · ')}`,
    `- Control validity and role parity: ${scope.control.statement}`,
    `- Model contribution: ${scope.model.note}`,
    '',
    ...(excluded.length ? ['Scope exclusions and baseline planning drops:', '',
      ...table(['Candidate', 'Reason'], excluded)] : []),
  ];
}

function markdownExternal(surface) {
  const { external, exposures } = surface;
  const lines = ['## 3. External attack surface', '', external.discovery];
  if (external.modelNaming?.modelCalls) lines.push('',
    `Muse naming: ${external.modelNaming.hostsSent} live host records reviewed in ${external.modelNaming.pagesSent} pages; ` +
    `${external.modelNaming.accepted} scoped names queued, ${external.modelNaming.newHosts} resolved, ` +
    `${external.modelNaming.rejected} proposals rejected, ${external.modelNaming.hostsCut} host records not reviewed.`);
  if (external.assetModelAnalysis?.modelCalls) lines.push('',
    `Muse asset interpretation: ${external.assetModelAnalysis.coverage.filesSent} of ` +
    `${external.assetModelAnalysis.coverage.filesAvailable} mined files and ` +
    `${external.assetModelAnalysis.coverage.routesSent} of ` +
    `${external.assetModelAnalysis.coverage.routesAvailable} extracted route facts sent in ` +
    `${external.assetModelAnalysis.coverage.pagesSent} completed pages; ` +
    `${external.assetModelAnalysis.notesAccepted ?? 0} accepted route notes and ` +
    `${external.assetModelAnalysis.proposalsAccepted ?? 0} accepted path proposals.`);
  if (external.files.length) {
    const rows = external.files.map(file => [
      code(file.url), file.bytes ?? '?', file.analysis?.role ?? 'unclassified', file.endpoints, file.secrets,
      file.libraries.join(', ') || 'none', file.sourceMap ?? 'unknown', file.sourcesCut || '-',
    ]);
    lines.push('', 'Assets analyzed:', '', ...table(['File', 'Bytes', 'Muse role', 'Endpoints', 'Secrets', 'Libraries', 'Source map', 'Map sources cut'], rows));
    const calls = external.files.flatMap(file => file.operations.map(operation => ({file: file.url, ...operation})));
    if (calls.length) lines.push('',
      `API calls extracted from client files (${Math.min(calls.length, 100)} shown${calls.length > 100 ? `; ${calls.length - 100} more in report.json` : ''}):`,
      '', ...table(['File', 'Original source', 'Method', 'Path', 'Parameters and examples', 'Muse purpose'], calls.slice(0, 100).map(item => [
        code(item.file), (item.sourceFiles ?? []).map(source => code(source)).join(', ') || '-', item.method, code(item.path), item.params.map(name => {
          const examples = (item.examples[name] ?? []).slice(0, 4);
          const meaning = item.parameterMeanings.find(note => note.name === name)?.meaning;
          return `${name}${examples.length ? `=${examples.join('|')}` : ''}${meaning ? ` (${meaning})` : ''}`;
        }).join(', ') || '-', item.purpose ?? 'not interpreted'])));
  } else {
    lines.push('', 'No script assets were analyzed.');
  }
  const advisories = external.advisories;
  if (advisories?.status === 'checked') {
    const matches = advisories.records.flatMap(record => record.advisories.map(item =>
      ({...item, package: record.name, version: record.version, files: record.files,
        evidence: record.evidence})));
    lines.push('', `OSV advisory lookup: ${advisories.stats.checked} of ${advisories.stats.available} detected package versions checked; ${matches.length} version-match lead(s), ${advisories.stats.cut} cut, ${advisories.stats.errors} failed. Matches are not exploit proofs.`);
    if (matches.length) lines.push('', `Known advisory leads (${Math.min(matches.length, 50)} shown${matches.length > 50 ? `; ${matches.length - 50} more in report.json` : ''}):`, '',
      ...table(['Package', 'Version', 'Advisory', 'Rating', 'Summary', 'Fixed versions', 'Asset', 'Evidence'],
        matches.slice(0, 50).map(item => [code(item.package), item.version, code(item.id),
          item.rating ?? 'unknown', item.summary || '-', item.fixedVersions.join(', ') || 'not specified',
          code(item.files[0] ?? '-'), item.evidence.join(', ')])));
  }
  if (external.secrets.length) {
    const rows = external.secrets.map(secret => [
      secret.name, code(secret.masked), secret.public ? `${secret.confidence} (public by design)` : secret.confidence, code(secret.location),
    ]);
    lines.push('', 'Secrets found (masked, never used):', '', ...table(['Name', 'Masked', 'Confidence', 'Location'], rows));
  }
  if (external.discoveredHosts.length) {
    lines.push('', 'Resolved in-scope hosts:', '', ...table(['Host', 'Depth', 'Source', 'Live', 'Role', 'Stack', 'TLS SAN names', 'Assets', 'API ops', 'GraphQL fields', 'Active probes', 'Exposures'],
      external.discoveredHosts.map(host => [code(host.host), host.depth, host.foundBy.join(', '),
        host.live ? `${host.live.https != null ? 'HTTPS' : 'HTTP'} ${host.live.https ?? host.live.http}` : 'no',
        host.role ?? 'unclassified',
        host.stack.map(item => `${item.product} ${item.version ?? ''}`.trim()).join(', ') || 'unknown',
        host.certificate ? [
          ...(host.certificate.sans ?? []).slice(0, 3),
          ...(host.certificate.wildcardSans ?? []).slice(0, 2).map(name => `*.${name}`),
        ].join(', ') + ((host.certificate.sans?.length ?? 0) > 3 ||
          (host.certificate.wildcardSans?.length ?? 0) > 2 ? ' (more in report.json)' : '') : '-',
        host.assets,
        host.operations.length, host.graphql?.operations?.length ?? 0,
        host.audit ? `${host.audit.tested} tested, ${host.audit.cut} cut` +
          (host.responseFollowup ? `; response routes ${host.responseFollowup.routesReviewed}/${host.responseFollowup.routesAvailable}` : '') :
          'inventory only',
        host.exposures.length])));
    const operations = external.discoveredHosts.flatMap(host => host.operations.map(operation => ({host: host.host, ...operation})));
    if (operations.length) {
      lines.push('', `Observed API operations on discovered hosts (${Math.min(operations.length, 100)} shown${operations.length > 100 ? `; ${operations.length - 100} more in report.json` : ''}):`, '',
        ...table(['Host', 'Method', 'Path', 'Parameters', 'Purpose', 'Source'], operations.slice(0, 100).map(item => [
          code(item.host), item.method, code(item.path), item.params.map(param => {
            const meaning = item.parameterMeanings?.find(note => note.name === param.name)?.meaning;
            return meaning ? `${param.name} (${meaning})` : param.name;
          }).join(', ') || '-', item.purpose ?? 'not interpreted', item.source.join(', ')])));
    }
    if (external.modelAnalysis) lines.push('', `Muse host interpretation: ${external.modelAnalysis.hostsSent} live hosts and ${external.modelAnalysis.operationsSent} of ${external.modelAnalysis.operationsAvailable} recorded operations sent; ${external.modelAnalysis.operationsCut ?? 0} not sent within budget.`);
  }
  if (external.hosts.length) {
    lines.push('', `Hosts named in assets (recorded, not contacted): ${external.hosts.map(host => `${code(host.host)} (${host.kind})`).join(', ')}`);
  }
  if (exposures.length) {
    const rows = exposures.map(exposure => [code(exposure.url ?? exposure.path), exposure.severity,
      exposure.signature, exposure.evidenceId, exposure.confirmationEvidence ?? '-']);
    lines.push('', 'Exposures (body signature checked):', '',
      ...table(['URL or path', 'Severity', 'Signature', 'Evidence', 'Confirmation'], rows));
  } else {
    lines.push('', 'No sensitive path answered with its signature.');
  }
  return lines;
}

function markdownApplication(application) {
  const lines = ['## 4. Application attack surface', ''];
  if (application.routeRecon) {
    const routeRecon = application.routeRecon;
    const cut = Object.values(routeRecon.stats?.cuts ?? {}).reduce((sum, count) => sum + count, 0);
    lines.push(`Observed route crawl: ${routeRecon.stats.routes} paths, ${routeRecon.stats.requested} guarded requests, ` +
      `${routeRecon.stats.listings} independently rechecked directory indexes, ` +
      `${routeRecon.stats.filesChecked} candidate files checked, ${routeRecon.stats.filesUnfetched ?? 0} files recorded without fetching; ${cut} leads cut. ` +
      'Robots directives are discovery hints, not findings.');
    const routes = routeRecon.routes.filter(item => item.sources.some(source =>
      /robots|sitemap|directory/.test(source.source)));
    if (routes.length) lines.push('', `Robots, sitemap and directory leads (${Math.min(100, routes.length)} shown):`, '',
      ...table(['Path', 'Source', 'HTTP', 'Listing', 'Evidence'], routes.slice(0, 100).map(item => [
        code(item.path), item.sources.map(source => source.from ? `${source.source} ${source.from}` : source.source).join(', '),
        item.status ?? 'unfetched', item.listing ? 'confirmed index' : '-', item.evidenceId ?? '-'])));
    if (routes.length > 100) lines.push(`${routes.length - 100} more leads are in observed-routes.json.`);
    lines.push('');
  }
  if (application.exposureSelection) lines.push(`Sensitive-path selection: ${application.exposureSelection.selected} of ` +
    `${application.exposureSelection.available} catalog paths chosen from observed routes and stack evidence; ` +
    `${application.exposureSelection.skipped.length} unselected. Fingerprints: ` +
    `${application.exposureSelection.fingerprints.join(', ') || 'none'}.`);
  lines.push(...(application.patterns.length
    ? table(['Pattern', 'Label', 'Source', 'Owner', 'Outsider', 'Anonymous', 'Not found', 'Private', 'IDs owner/outsider'],
      application.patterns.map(p => [code(p.pattern), p.label, p.source.join(', '), p.statuses.owner ?? '-', p.statuses.outsider ?? '-',
        p.statuses.anonymous ?? '-', p.statuses.notFound ?? '-', p.private ? 'yes' : 'no', `${p.ids.owner}/${p.ids.outsider}`]))
    : ['No patterns were mapped.']));
  lines.push('', `Public and shared routes: ${list(application.publicShared, item => `${code(item.pattern)} (${item.verdict}, ${item.task})`)}`);
  if (application.graphql) {
    const graphql = application.graphql;
    lines.push('', `GraphQL read-only schema inventory: ${graphql.attempts?.filter(item => item.result === 'schema').length ?? 0} schema endpoints, ${graphql.operations?.length ?? 0} root fields. Public introspection is context, not a confirmed vulnerability.`);
    if (graphql.bola) lines.push(`GraphQL object authorization: ${graphql.bola.planned} planned task(s) from ${graphql.bola.candidates} observed list/item query pair(s); ${graphql.bola.cut} pair(s) beyond budget. Muse ranked ${graphql.bola.modelCoverage?.candidatesSent ?? 0} pair(s) in ${graphql.bola.modelCoverage?.pagesSent ?? 0} page(s). Findings still require owner, outsider, anonymous and replay controls.`);
    if (graphql.operations?.length) lines.push('', ...table(['Endpoint', 'Kind', 'Field', 'Arguments', 'Returns', 'Evidence'],
      graphql.operations.slice(0, 50).map(item => [code(item.endpoint), item.kind, code(item.name),
        item.args.map(arg => `${arg.name}: ${arg.type ?? '?'}`).join(', ') || '-', item.returns ?? '?', item.evidenceId ?? '-'])));
    if (graphql.operations?.length > 50) lines.push(`More GraphQL root fields are in report.json: ${graphql.operations.length - 50}.`);
  }
  lines.push('', 'Surface inventory and queued work:', '');
  const untested = list(application.untested, item => `${item.id} ${item.kind} ${item.as ?? ''} ${code(item.url ?? item.pattern)}`);
  lines.push(`- Tasks beyond the budget: ${untested}`);
  lines.push(`- Non-GET operations seen in assets (exact reviewed POSTs may have been tested; see task ledger): ${list(application.nonGet, item => `${item.method} ${code(item.path)}`)}`);
  if (application.modelFollowup?.length) lines.push(`- Muse recon follow-up: ${application.modelFollowup.length} guarded response page(s) reviewed; ${application.modelFollowup.reduce((count, page) => count + page.accepted.length, 0)} scope-checked path proposals accepted. The resulting routes still required HTTP proof.`);
  if (application.anonymousResponseFollowup?.routesReviewed) lines.push(`- Muse anonymous recon follow-up: ${application.anonymousResponseFollowup.routesReviewed} guarded public GET response(s) reviewed; ${application.anonymousResponseFollowup.pathsAccepted} scope-checked path proposals accepted. The resulting routes still required HTTP proof.`);
  if (application.accessFollowup?.coverage?.tasksAvailable) lines.push(`- Muse access-control follow-up: ${application.accessFollowup.coverage.tasksSent} of ${application.accessFollowup.coverage.tasksAvailable} inconclusive tasks reviewed; ${application.accessFollowup.selected.length} observed query variants executed as regular tasks; ${application.accessFollowup.coverage.variantsCut} variants cut by the per-task limit. Findings still required fresh verification and an executed proof.`);
  if (application.sourceReview) {
    const source = application.sourceReview;
    lines.push(`- Source-assisted context: ${source.stats.files} local files read; ${source.stats.skipped} skipped by size budget; ${source.stats.filesCut ?? 0} beyond file limit; ${source.stats.routesCut ?? 0} route facts beyond route limit. Source alone did not confirm a finding.`);
    if (source.modelCoverage) lines.push(`- Muse source interpretation: ${source.modelCoverage.snippetsSent} of ${source.modelCoverage.snippetsAvailable} route excerpts in ${source.modelCoverage.pagesSent} of ${source.modelCoverage.pagesAvailable} pages.`);
    if (source.secretLeads?.length) {
      lines.push(`- Local source credential leads: ${source.secretLeads.length} credential-shaped value(s). These are review leads; validity and public exposure were not tested. No matched value is saved in this report.`);
      lines.push('', ...table(['File', 'Line', 'Pattern', 'Confidence'], source.secretLeads.slice(0, 20)
        .map(lead => [code(lead.file), lead.line, lead.name, lead.confidence])));
      if (source.secretLeads.length > 20) lines.push(`${source.secretLeads.length - 20} more lead(s) are in report.json.`);
    }
  }
  if (application.modelNotes?.length) lines.push('', 'Muse route interpretations (hypotheses):', '',
    ...application.modelNotes.map(note => `- ${code(note.path)}: ${note.purpose}; methods ${note.methods.join(', ') || 'unknown'}; parameters ${note.parameters.join(', ') || 'unknown'}. ${note.why}`));
  if (application.otherOrigins?.length) {
    lines.push('', 'Other credential origins:', '', ...table(
      ['Origin', 'Identity control', 'Patterns', 'GraphQL fields', 'GraphQL object tasks', 'Access tasks', 'Web probes', 'Assets'],
      application.otherOrigins.map(origin => [code(origin.origin), origin.identityVerified ? 'verified' : 'unverified',
        origin.patterns.length, origin.graphql?.operations?.length ?? 0,
        origin.graphql?.bola?.planned ?? 0, `${origin.tested}/${origin.tasks}`,
        `${origin.webTested} tested, ${origin.webCut} cut`, origin.assets])));
    for (const origin of application.otherOrigins) if (origin.patterns.length)
      lines.push('', `${code(origin.origin)} observed patterns:`, '', ...table(['Pattern', 'Label', 'Source'],
        origin.patterns.slice(0, 50).map(item => [code(item.pattern), item.label, item.source.join(', ')])));
    for (const origin of application.otherOrigins) if (origin.publicShared?.length)
      lines.push('', `${code(origin.origin)} public and shared routes: ${list(origin.publicShared,
        item => `${code(item.pattern)} (${item.verdict}, ${item.task})`)}`);
  }
  return lines;
}

function markdownFindings(findings) {
  const confirmed = findings.filter(finding => !researchBehavior(finding));
  const observations = findings.filter(researchBehavior);
  return ['## 5. Findings',
    ...(!confirmed.length ? ['', 'No confirmed security findings.'] :
      confirmed.flatMap(markdownFinding)),
    ...(observations.length ? ['', 'Research observations (security impact unverified):',
      ...observations.flatMap(markdownFinding)] : [])];
}

function markdownFinding(finding) {
  const mirror = finding.mirror ?? { result: 'unverified', evidence: [] };
  const mirrorText = [mirror.result, mirror.url && `owner GET ${code(mirror.url)}`, mirror.reason, mirror.evidence?.join(', ')].filter(Boolean).join(' · ');
  return [
    '', `### ${finding.id} · ${finding.title}`, '',
    `- Host: ${finding.host}`,
    `- Verdict: ${researchBehavior(finding) ? 'Observed response transformation; security impact unverified' : 'Confirmed security finding'}`,
    `- Severity: ${researchBehavior(finding) ? 'unrated' : finding.severity} · ${researchBehavior(finding) ? 'Security impact has not been established' : finding.rationale}`,
    `- Classification: ${finding.owasp ?? 'none'} · ${finding.cwe ?? 'none'}`,
    `- Pattern: ${code(finding.pattern)} · URL: ${code(finding.url)}`,
    `- Found by: ${finding.foundBy} · task ${finding.task ?? 'none'} · status ${finding.status}`,
    `- Tags: ${finding.tags.length ? finding.tags.join(', ') : 'none'}`,
    ...(finding.modelHypothesis ? [`- Muse hypothesis: ${code(finding.modelHypothesis.family)} · ${code(finding.modelHypothesis.why ?? 'no rationale supplied')}. ${finding.kind === 'public-session-token' ? 'The public owner-token replay is proved; the broader family label remains a hypothesis.' : finding.kind === 'model-access-boundary' ? 'The owner-only record disclosure is independently proved; the proposed mechanism remains a hypothesis.' : finding.kind === 'model-cookie-access' ? 'Fresh arbitrary cookie values crossed the measured page gate; the broader family label remains a hypothesis.' : finding.kind === 'model-raw-boundary' ? 'The exact model-authored request crossed the measured access boundary under fresh controls; the broader mechanism remains a hypothesis.' : 'The response behavior below is observed; this hypothesis and its security impact are not established by the generic canary check.'}`] : []),
    ...(finding.kind === 'model-differential' && finding.webProof?.prelude?.length ?
      [`- Muse-selected read-only prelude: ${finding.webProof.prelude.map(code).join(', ')}. The proof repeats these requests before each control and probe.`] : []),
    ...(finding.kind === 'public-session-token' ? [`- Replay input: extract ${code(finding.webProof.tokenPointer)} from the public JSON response into ${code('$PUBLIC_SESSION_TOKEN')}; the proof does this in memory and stores no token value.`] : []),
    ...(finding.tags.includes('credential-like') ? ['- A credential-like value was observed and was not used; manual follow-up required.'] : []),
    '', 'Reproduction:', '',
    ...finding.reproduction.map(stepLine),
    '', '```sh', ...finding.curl, '```',
    '', 'Evidence:', '',
    ...table(['Identity', 'Request', 'Status', 'Type', 'Bytes', 'Hash', 'Evidence'], finding.evidenceTable.map(evidenceCells)),
    '',
    `- Verdict rule: ${code(finding.rule)}`,
    `- Confirmation (re-verification): ${finding.confirmation.length ? finding.confirmation.join(', ') : 'none'}`,
    `- Mirror: ${mirrorText}`,
    `- Proof of concept and regression test: ${finding.proof}`,
    ...((finding.corroboratingProofs ?? []).map(item =>
      `- Corroborating independent proof ${item.id} (${item.kind}${item.pattern ? `, ${code(item.pattern)}` : ''}): ${item.proof}`)),
    ...(finding.assessment ? [`- Muse assessment (interpretation): ${finding.assessment.impact} Preconditions: ${finding.assessment.preconditions} Suggested remediation: ${finding.assessment.remediation}`] : []),
    `- Remediation: ${finding.remediation}`,
  ];
}

function stepLine(step, index) {
  const outcome = `${step.status ?? 'status not recorded'} (${step.evidence ?? 'no evidence'})`;
  return `${index + 1}. As ${step.identity}, ${step.method} ${code(step.url)}${step.origin ? ` with Origin ${code(step.origin)}` : ''}${step.hostHeader ? ` with Host ${code(step.hostHeader)}` : ''} → ${outcome}`;
}

function evidenceCells(row) {
  if (row.missing) return ['-', '-', '-', '-', '-', '-', `${row.id} (not in ledger)`];
  return [row.identity ?? '-', `${row.method ?? '-'} ${code(row.url)}`, statusText(row), row.type ?? '-', row.bytes ?? '-', row.hash || '-', row.id];
}

function statusText(row) {
  if (row.refused) return `refused (${row.refused.rule}: ${row.refused.match ?? ''})`;
  if (row.blocked) return `blocked (${row.blocked.reason ?? ''})`;
  return row.status ?? '-';
}

function markdownChains(chains) {
  const confirmed = chains.filter(chain => chain.status === 'confirmed');
  if (!confirmed.length) return ['## 6. Chains', '', 'No chains were confirmed in this run.'];
  return ['## 6. Chains', ...confirmed.flatMap(chain => [
    '', `### ${chain.id} · ${chain.template} · ${chain.severity}`, '',
    `Selected by: ${chain.selectedBy === 'model' ? 'Muse proposal, independently replayed' : 'code template'}`,
    `Findings: ${(chain.findings ?? []).join(', ')}`,
    ...(chain.steps ?? []).map((step, index) => `${index + 1}. ${step.use} (${(step.evidence ?? []).join(', ')})`),
    `Reach observed: ${chain.reach?.observed ?? 'unknown'}${chain.reach?.basis ? ` (${chain.reach.basis})` : ''}`,
    ...(chain.proof ? [`Proof: ${code(chain.proof)}`] : []),
    ...(chain.assessment ? [
      `Muse chain assessment (interpretation): ${code(chain.assessment.impact)}`,
      `Preconditions: ${code(chain.assessment.preconditions)}`,
      `Suggested remediation: ${code(chain.assessment.remediation)}`,
    ] : []),
    ...(chain.reach?.estimated ? [`Reach estimated: ${chain.reach.estimated} (estimated from the ID range, not verified)`] : []),
  ])];
}

function markdownOpen(items) {
  if (!items.length) return ['## 7. Inconclusive and blocked', '', 'None: every task reached a definite verdict.'];
  const rows = items.map(item => {
    const request = item.url ? `${item.as} ${item.method} ${code(item.url)}` : '-';
    return [item.task, item.kind, request, item.verdict, code(item.rule), item.reason || '-', item.evidence.join(', ') || '-'];
  });
  return ['## 7. Inconclusive and blocked', '', ...table(['Task', 'Kind', 'Request', 'Verdict', 'Rule', 'Reason', 'Evidence'], rows)];
}

function markdownAppendix(rows, ledgerFile) {
  const lines = ['## 9. Evidence appendix', ''];
  if (!ledgerFile.found) lines.push('Evidence details unavailable: ledger file not found.', '');
  if (ledgerFile.unreadableLines) {
    lines.push(`${plural(ledgerFile.unreadableLines, 'ledger line')} could not be parsed; see the ledger integrity line in the header.`, '');
  }
  if (!rows.length) return [...lines, 'No evidence was cited.'];
  const cells = row => (row.missing
    ? [row.id, 'not in ledger', '', '', '', '', '']
    : [row.id, row.at ?? '-', row.identity ?? '-', row.method ?? '-', code(row.url), statusText(row), row.hash || '-']);
  return [...lines, ...table(['Evidence', 'Time', 'Identity', 'Method', 'URL', 'Status', 'Hash'], rows.map(cells))];
}

/** Compact terminal result. Probe verdict counts exclude separately confirmed exposure scans. */
export function summaryText(result, {color = false} = {}) {
  const stats = result.stats ?? {};
  const findings = result.findings ?? [];
  const confirmedFindings = findings.filter(finding => !researchBehavior(finding));
  const observations = findings.filter(researchBehavior);
  const corroboratingProofs = confirmedFindings.reduce((count, finding) =>
    count + (finding.corroboratingProofs?.length ?? 0), 0);
  const paint = (code, value) => color ? `\x1b[${code}m${value}\x1b[0m` : value;
  const heading = value => paint('1;36', value);
  const dim = value => paint('90', value);
  const displayPath = value => {
    const relative = path.relative(process.cwd(), value);
    return relative === '' ? '.' : relative.startsWith('..') || path.isAbsolute(relative) ? value :
      relative.startsWith('.') ? relative : `./${relative}`;
  };
  const incomplete = Boolean(result.incomplete ?? result.limitations?.length) ||
    result.coverage?.complete === false;
  const applicationOrigins = Math.max(1, result.credentialOrigins?.length ?? 0);
  const scope = result.discovery ?
    `${result.discovery.hostsLive} live of ${result.discovery.hostsFound} resolved hosts · ${result.discovery.dnsQueries} DNS queries` :
    `${applicationOrigins} application origin${applicationOrigins === 1 ? '' : 's'} · external discovery did not run`;
  const lines = ['', `${heading('BYPASS')} ${dim('/')} blackbox ${dim('·')} ${result.run}`];
  if (result.origin ?? result.credentialOrigins?.[0])
    lines.push(`Target           ${result.origin ?? result.credentialOrigins[0]}`);
  lines.push(`Scope            ${scope}`);
  lines.push('', heading((confirmedFindings.length ? `Findings: ${confirmedFindings.length} confirmed` : 'Findings: none confirmed') +
    (incomplete ? ' · partial coverage' : '')));
  if (observations.length) lines.push(`Research          ${observations.length} reproduced response transformation${observations.length === 1 ? '' : 's'} · impact unverified`);
  if (findings.length) {
    const widths = ['id', 'severity', 'kind'].map(key => Math.max(...findings.map(finding =>
      String(key === 'severity' && researchBehavior(finding) ? 'unrated' : finding[key]).length)));
    for (const finding of findings) {
      const columns = [finding.id, researchBehavior(finding) ? 'unrated' : finding.severity,
        finding.kind].map((value, index) => String(value).padEnd(widths[index]));
      const tone = finding.severity === 'critical' ? '1;31' : finding.severity === 'high' ? '33' : '0';
      const suffix = finding.pattern ? `: ${finding.pattern}` : '';
      const title = suffix && String(finding.title).endsWith(suffix) ?
        String(finding.title).slice(0, -suffix.length) : finding.title;
      lines.push(`  ${columns[0]}  ${paint(tone, columns[1])}  ${columns[2]}  ${title}${researchBehavior(finding) ? ' · observed' : ''}`);
      if (finding.pattern) lines.push(`         ${dim(finding.pattern)}`);
      if (finding.corroboratingProofs?.length)
        lines.push(`         ${dim(`Corroborated by ${finding.corroboratingProofs.map(item =>
          `${item.id} ${item.pattern ?? item.kind}`).join(', ')}`)}`);
    }
    if (corroboratingProofs)
      lines.push('', `Proof sources    ${plural(confirmedFindings.length + corroboratingProofs, 'replayable proof')} across ${plural(confirmedFindings.length, 'confirmed finding')}`);
    const exposureFindings = findings.filter(finding => finding.kind === 'exposure').length;
    if (exposureFindings && !corroboratingProofs) {
      const probeFindings = confirmedFindings.length - exposureFindings;
      lines.push('', `Proof sources    ${exposureFindings} exposure check${exposureFindings === 1 ? '' : 's'}` +
        (probeFindings ? ` + ${probeFindings} other probe${probeFindings === 1 ? '' : 's'}` : '') +
        ` = ${confirmedFindings.length} confirmed findings`);
    }
  }

  lines.push('', heading('Run'));
  const elapsedSeconds = Math.max(0, Math.round((stats.elapsedMs ?? 0) / 1000));
  const duration = elapsedSeconds >= 60 ? `${Math.floor(elapsedSeconds / 60)}m ${elapsedSeconds % 60}s` : `${elapsedSeconds}s`;
  const queuedUntested = stats.queuedUntested ?? 0;
  const executed = Math.max(0, (stats.tasks ?? 0) - queuedUntested);
  lines.push(`Activity         ${executed} executed${queuedUntested ? ` · ${queuedUntested} queued untested` : ''}${stats.beyondBudget ? ` · ${stats.beyondBudget} beyond budget` : ''} · ${stats.requests ?? 0} requests · ${stats.cached ?? 0} cached · ${duration} · ${stats.rps ?? 0} rps`);
  if (stats.webWorkersPeak > 0)
    lines.push(`Web workers      ${stats.webWorkersPeak} active at peak · ${stats.webWorkersConfigured ?? '?'} configured`);
  const pendingQueues = result.coverage?.pendingResearchCheckpoints;
  if (Number.isInteger(pendingQueues) && pendingQueues > 0)
    lines.push(`Saved queues     ${plural(pendingQueues, 'research queue')} pending · resume to continue`);
  // The generic Muse HTTP-sequence result is tallied as `observed` while its
  // impact oracle emits a separate finding. Once that finding survives fresh
  // PoC replay, the executed sequence is a positive task, not unrated research.
  const provedSequenceChecks = Math.min(stats.observed ?? 0,
    confirmedFindings.filter(finding => finding.verdict === 'confirmed' &&
      ['muse-proposed-http-sequence', 'muse-proposed-http-flow'].includes(finding.foundBy)).length);
  const positiveChecks = (stats.confirmed ?? 0) + provedSequenceChecks;
  const unprovedObservations = Math.max(0, (stats.observed ?? 0) - provedSequenceChecks);
  const nonExposureFindings = confirmedFindings.filter(finding => finding.kind !== 'exposure').length;
  const deduplicated = positiveChecks > nonExposureFindings && nonExposureFindings > 0 ?
    ` (${nonExposureFindings} distinct non-exposure finding${nonExposureFindings === 1 ? '' : 's'})` : '';
  const resolved = [`${positiveChecks} positive check${positiveChecks === 1 ? '' : 's'}${deduplicated}`, `${stats.notReproduced ?? 0} no finding`];
  const remaining = [`${stats.inconclusive ?? 0} inconclusive`];
  if (unprovedObservations) remaining.push(`${unprovedObservations} reproduced behavior${unprovedObservations === 1 ? '' : 's'} (impact unverified)`);
  if (stats.blocked) remaining.push(`${stats.blocked} blocked`);
  if (stats.public) remaining.push(`${stats.public} public`);
  if (stats.shared) remaining.push(`${stats.shared} shared`);
  if (queuedUntested) remaining.push(`${queuedUntested} queued untested`);
  const counted = (stats.confirmed ?? 0) + (stats.notReproduced ?? 0) +
    (stats.inconclusive ?? 0) + (stats.observed ?? 0) + (stats.blocked ?? 0) +
    (stats.public ?? 0) + (stats.shared ?? 0) + queuedUntested;
  lines.push(`Task verdicts    ${resolved.join(' · ')}`);
  lines.push(`                 ${remaining.join(' · ')}${counted !== (stats.tasks ?? 0) ? ` · ${counted} of ${stats.tasks ?? 0} outcomes itemized` : ''}`);
  if (result.untested?.length) lines.push(`Queued work      ${result.untested.length} not tested`);
  if (result.coverage) {
    const classes = result.coverage.requestedClasses ?? [];
    const classCounts = Object.groupBy(classes, row => row.status);
    const families = result.coverage.rows ?? [];
    const familyCounts = Object.groupBy(families, row => row.status);
    if (classes.length) lines.push(`Class coverage   ${classCounts.partial?.length ?? 0} of ${classes.length} partly tested · ${classCounts['not tested']?.length ?? 0} not tested`);
    lines.push(`Report groups    ${familyCounts.exercised?.length ?? 0} exercised · ${familyCounts.partial?.length ?? 0} partial · ${familyCounts['not tested']?.length ?? 0} not tested (${families.length} broad groups)`);
    if (incomplete) {
      const gaps = [];
      if (result.coverage.derivedSessionRecon?.budgetCut)
        gaps.push(`${result.coverage.derivedSessionRecon.budgetCut} authenticated recon URLs unvisited`);
      if (result.coverage.derivedSessionRecon?.sizeCut)
        gaps.push(`${result.coverage.derivedSessionRecon.sizeCut} authenticated responses beyond capture limit`);
      const mapCoverage = result.coverage.sourceMaps;
      if (mapCoverage) {
        if (mapCoverage.originalsUnresolvable)
          gaps.push(`${mapCoverage.originalsUnresolvable} source-map names without obtainable source text`);
        if (mapCoverage.originalsFetchFailed)
          gaps.push(`${mapCoverage.originalsFetchFailed} public source-map originals unavailable on replay`);
        if (mapCoverage.originalsUnavailable && !mapCoverage.originalsUnresolvable &&
            !mapCoverage.originalsFetchFailed)
          gaps.push(`${mapCoverage.originalsUnavailable} source-map originals without served source text`);
        if (mapCoverage.originalsBudgetCut)
          gaps.push(`${mapCoverage.originalsBudgetCut} source-map original URLs beyond asset budget`);
        if (mapCoverage.mapCandidatesBudgetCut)
          gaps.push(`${mapCoverage.mapCandidatesBudgetCut} source-map candidates beyond asset budget`);
      } else {
        // Older reports have only a prose limitation, without source-map counters.
        const sourceMapCut = result.limitations?.find(item =>
          item.startsWith('Source-map mining could not inspect ') ||
          item.startsWith('Source-map mining found '));
        const count = /Source-map mining (?:could not inspect|found) (\d+)/.exec(sourceMapCut ?? '')?.[1];
        if (count) gaps.push(`${count} source-map originals without served source text`);
      }
      if (classCounts['not tested']?.length)
        gaps.push(`${classCounts['not tested'].length} ${classCounts['not tested'].length === 1 ? 'class' : 'classes'} not tested`);
      lines.push(`Coverage gaps    ${gaps.join(' · ') || 'see report.md limitations'}`);
    }
    lines.push(dim('  Full class list and limits: coverage.json'));
  }
  if (result.modelError) lines.push(`Muse model stage failed: ${result.modelError}`);
  else if (stats.model) lines.push(`Muse model:      ${stats.model} · ${stats.modelCalls ?? 0} calls`);
  else lines.push('Muse model:      code-only');
  if (stats.model)
    lines.push(`Muse agents      ${stats.modelWorkersPeak ?? 0} active at peak · ${stats.modelWorkersConfigured ?? '?'} configured`);
  if (result.researchDeadlineCut)
    lines.push('Research cutoff: Audit wall-clock deadline stopped a Muse call; remaining work is untested.');
  if (result.modelOutput) {
    const accepted = result.modelOutput;
    const label = (count, singular, pluralWord = `${singular}s`) =>
      `${count} ${count === 1 ? singular : pluralWord}`;
    lines.push(`Muse accepted:   ${plural(accepted.assetNotes ?? 0, 'route note')} · ${plural(accepted.assetPaths ?? 0, 'asset path')}${accepted.responsePaths == null ? '' : ` · ${plural(accepted.responsePaths, 'response path')}`}`);
    const planned = [
      [accepted.webStrategies, 'web strategy', 'web strategies'],
      [accepted.webExperiments, 'GET experiment'],
      [accepted.jsonExperiments, 'JSON POST experiment'],
    ].filter(([count]) => count > 0).map(([count, singular, many]) => label(count, singular, many));
    const sequences = [
      [accepted.httpSequences, 'HTTP sequence'], [accepted.storedXssChecks, 'stored XSS check'],
      [accepted.sessionChains, 'session chain'],
    ].filter(([count]) => count > 0).map(([count, singular]) => label(count, singular));
    lines.push(`Muse plans:      ${planned.join(' · ') || 'none accepted'}`);
    if (accepted.accessBoundaries) lines.push(`Muse boundaries: ${label(accepted.accessBoundaries, 'access-control hypothesis', 'access-control hypotheses')}`);
    if (accepted.httpSamples) lines.push(`Muse sampled:    ${label(accepted.httpSamples, 'reviewed POST request')}`);
    if (sequences.length) lines.push(`Muse sequences:  ${sequences.join(' · ')}`);
    const rejectionRecords = accepted.rejectedDecisionRecordsByReason;
    const decisions = Object.entries(rejectionRecords ?? accepted.httpSequenceRejectedByReason ?? {})
      .filter(([, count]) => Number.isFinite(count) && count > 0)
      .sort((a, b) => b[1] - a[1]);
    const duplicateReasons = new Set(['duplicate-lead', 'duplicate-payload']);
    const coalesced = decisions.filter(([reason]) => duplicateReasons.has(reason));
    const rejected = decisions.filter(([reason]) => !duplicateReasons.has(reason));
    if (coalesced.length) lines.push(`Muse duplicates  ${coalesced.reduce((sum, [, count]) => sum + count, 0)} coalesced · ` +
      coalesced.map(([reason, count]) => `${count} ${reason}`).join(' · '));
    if (rejected.length) lines.push(`Bypass rejected  ${rejected.reduce((sum, [, count]) => sum + count, 0)} ` +
      (rejectionRecords ? 'Muse plan/revision records' : 'Muse HTTP plans') + ' · ' +
      rejected.slice(0, 3).map(([reason, count]) => `${count} ${reason}`).join(' · '));
  }
  if (result.advisories?.matches)
    lines.push(`Advisory leads:  ${result.advisories.matches} version matches; unproved; see report`);

  lines.push('', heading('Evidence'));
  lines.push(`Run folder: ${displayPath(result.runDir)}`);
  lines.push(dim(`  report.md  coverage.json  evidence.jsonl${findings.length ? '  poc/' : ''}`));
  if (result.projectRoot && (findings.length || pendingQueues > 0)) {
    const quote = value => `'${String(value).replaceAll("'", "'\\''")}'`;
    const project = ` --project ${quote(displayPath(result.projectRoot))}`;
    lines.push('', heading('Next'));
    if (pendingQueues > 0)
      lines.push(`  bypass blackbox resume ${quote(result.run)}${project}`);
    if (findings.length) {
      lines.push(`  bypass blackbox verify ${quote(result.run)}${project}`);
      lines.push(`  bypass blackbox export ${quote(result.run)}${project}`);
    }
  }
  lines.push('', `Exit ${result.exitCode} · ${EXIT_MEANING[result.exitCode] ?? 'see the report'}`);
  return lines.join('\n');
}
