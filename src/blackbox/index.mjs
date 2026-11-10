import fs from 'node:fs';
import path from 'node:path';
import { randomBytes } from 'node:crypto';
import {loopback} from '../network.mjs';
import { atomic, rootFrom } from '../store.mjs';
import { hash, id, need, now, Fault, abortFault } from '../util.mjs';
import { modelProfile } from '../models.mjs';
import { infer as modelInfer, withStructuredRepair } from '../inference.mjs';
import { loadScope, taskAllowance, createLimiter, createRequester, validateUrl } from './scope.mjs';
import { createLedger, verifyLedger, scrub, maskExcerpt } from './ledger.mjs';
import { mineOrigin, maskSecrets } from './assets.mjs';
import {interpretAssets, applyAssetProposals} from './asset-interpret.mjs';
import {discover} from './discovery.mjs';
import {interpretDiscovery} from './discovery-interpret.mjs';
import { establishIdentities, credentialNames } from './auth.mjs';
import { recon, sensitivePathMatches, scanSensitivePaths } from './recon.mjs';
import {anonymousSurface, deriveLocalPostScope} from './anonymous.mjs';
import {reconObservedRoutes, observedExposureMatches} from './robots-directory.mjs';
import { planTasks, oneAccountMissingAuthCandidate } from './planner.mjs';
import { decide, severityFor, classify, dataClasses } from './verdict.mjs';
import { runSwarm, reverify, mirror, identityRecheck } from './swarm.mjs';
import { buildFindings, consolidateBrowserXssProofs, consolidateRawBoundaryProofs,
  consolidateInjectionProofs,
  renderReport, exitCodeFor } from './report.mjs';
import { proveFindings } from './poc.mjs';
import {reviewSource} from './source.mjs';
import {runWebProbes, runSourceDisclosureProbes, runSourceHeaderProbes,
  runSourceFetchProbes} from './web-probes.mjs';
import {reconDerivedSession, derivedAnonymousSurface, reconConfirmedAccess} from './derived-session-recon.mjs';
import {checkDerivedAnonymousAccess} from './derived-access.mjs';
import {auditDiscoveredHosts, followupResponseHints, mergeResponsePatterns} from './host-audit.mjs';
import {auditCredentialOrigins} from './credential-origins.mjs';
import {coverageFor} from './coverage.mjs';
import {buildChains, buildDerivedPrerequisiteChains} from './chain.mjs';
import {assessFindings} from './assessment.mjs';
import {inspectGraphql} from './graphql.mjs';
import {planGraphqlBola} from './graphql-bola.mjs';
import {followupInconclusive} from './followup.mjs';
import {auditPublicPrivateKeys, auditPublicCredentials} from './secret-exposure.mjs';
import {lookupAdvisories} from './advisories.mjs';
import {sourceFindingFocus, checkLiveRevision} from './focus.mjs';

const RESEARCH_KINDS = new Set(['model-differential', 'model-json-differential', 'model-http-sequence']);
const ACCEPTED_RESEARCH_CHECKPOINT = /^(?:json-experiment|access-boundary)(?:-derived-[0-9a-f]{12})?(?:-queue-[0-9a-f]{12})?-checkpoint\.json$/;
const HTTP_SEQUENCE_CHECKPOINT = /^http-sequence(?:-derived-[0-9a-f]{12})?(?:-page-[0-9a-f]{12})?(?:-queue-[0-9a-f]{12})?-checkpoint\.json$/;
const AUDIT_MODEL_DEADLINE_MESSAGE = 'Audit wall-clock deadline cut a Muse research call; remaining work is untested.';

function observedSearchBaseline(response, sourceLead) {
  if (response.status !== 200 || !/json|\+json/i.test(response.type ?? '') ||
      !(response.ids?.length) || typeof response.body !== 'string') return null;
  const column = /\b([A-Za-z_][A-Za-z0-9_]*)\s+LIKE\b/i.exec(
    sourceLead?.source?.quote ?? '')?.[1];
  if (!column || /(?:email|token|secret|password|credential|key|phone|address|name|birth|ssn|social|tax|card|account)/i.test(column))
    return null;
  let document;
  try { document = JSON.parse(response.body); } catch { return null; }
  const records = Array.isArray(document) ? document :
    Array.isArray(document?.items) ? document.items : null;
  if (!records) return null;
  for (const record of records.slice(0, 5)) {
    const value = record?.[column];
    if (typeof value !== 'string' || value.length > 256) continue;
    for (const token of value.match(/[A-Za-z0-9_.-]{2,32}/g) ?? [])
      if (maskSecrets(token) === token) return token;
  }
  return null;
}

export function describeModelActivity(messages = []) {
  const instruction=messages.find(message=>message?.role==='system')?.content ?? '';
  if(/source route excerpts|source-grounded/i.test(instruction))return 'Reviewing source-grounded routes';
  if(/public (?:JS|assets?)|mined files|asset/i.test(instruction))return 'Interpreting routes from public assets';
  if(/HTTP sequence|workflow|multi-step/i.test(instruction))return 'Planning an HTTP-sequence check';
  if(/access-control|access boundary|access-boundary|object authorization|account boundary/i.test(instruction))return 'Planning an access-boundary check';
  if(/authentication|login|session/i.test(instruction))return 'Planning an authentication check';
  if(/web-test candidates|observed (?:GET|read-only)|rank only the supplied/i.test(instruction))return 'Ranking observed web checks';
  if(/response facts|follow-up|revise|repair|experiment|investigat/i.test(instruction))return 'Assessing a bounded research result';
  if(/independently proved|impact|remediation|assess/i.test(instruction))return 'Writing impact and remediation';
  if(/hostnames|DNS/i.test(instruction))return 'Interpreting discovered hosts';
  return 'Analyzing observed security evidence';
}

const hasPendingPageLeads = page => Array.isArray(page?.pendingLeads) &&
  page.pendingLeads.some(lead =>
    !page.pendingCompletedIds?.includes(lead.proposalId));
const pendingRoutePage = page => Number.isInteger(page?.nextRouteOffset) &&
  Number.isInteger(page?.totalRoutes) && page.nextRouteOffset >= 0 &&
  (page.nextRouteOffset < page.totalRoutes || hasPendingPageLeads(page));

export function countPendingResearchCheckpoints(runDir) {
  return fs.readdirSync(runDir)
    .filter(name => ACCEPTED_RESEARCH_CHECKPOINT.test(name) ||
      HTTP_SEQUENCE_CHECKPOINT.test(name) ||
      ['research-checkpoint.json', 'http-sequence-page-checkpoint.json'].includes(name))
    .reduce((count, name) => {
      const state = JSON.parse(fs.readFileSync(path.join(runDir, name), 'utf8'));
      return count + (Array.isArray(state.leads) && Number.isInteger(state.cursor) &&
        state.cursor < state.leads.length ? 1 : 0) +
        (Array.isArray(state.pages) ? state.pages.filter(pendingRoutePage).length : 0);
    }, 0);
}

/** Identify a timeout imposed by this audit, leaving genuine provider timeouts untouched. */
export function classifyAuditModelDeadline(error, {auditLimited, deadline, nowMs = Date.now()}) {
  if (auditLimited && error?.details?.reason === 'model_timeout' && nowMs >= deadline - 250)
    return new Fault(AUDIT_MODEL_DEADLINE_MESSAGE, 3, {reason: 'research_deadline'});
  return error;
}

/** Preserve exact executable bytes or mark this research checkpoint unavailable. */
export function sanitizeJsonCheckpoint(payload, secrets = []) {
  const safe = scrub(payload, secrets);
  const safeLead = lead => lead && ({...lead,
    why: maskSecrets(lead.why ?? ''),
    family: maskSecrets(lead.family ?? '')});
  if (Array.isArray(safe.leads)) safe.leads = safe.leads.map(safeLead);
  if (safe.active) safe.active = {...safe.active,
    initial: safeLead(safe.active.initial),
    currentLead: safeLead(safe.active.currentLead),
    lastPayloads: safeLead(safe.active.lastPayloads)};
  const requestShape = lead => lead && ({path: lead.path,
    parameter: lead.parameter, as: lead.as, oracle: lead.oracle,
    controlValue: lead.controlValue, firstValue: lead.firstValue,
    secondValue: lead.secondValue, marker: lead.marker,
    secondMarker: lead.secondMarker, fixedFields: lead.fixedFields,
    observedFields: lead.observedFields, prelude: lead.prelude,
    observePath: lead.observePath, observeAs: lead.observeAs});
  const executable = item => JSON.stringify(item ?? null);
  const requests = leads => (leads ?? []).map(requestShape);
  const originalRequests = executable(requests(payload.leads));
  const originalLastPayloads = executable(requestShape(payload.active?.lastPayloads));
  if (executable(requests(safe.leads)) !== originalRequests ||
      executable(requestShape(safe.active?.currentLead)) !==
        executable(requestShape(payload.active?.currentLead)) ||
      executable(requestShape(safe.active?.lastPayloads)) !== originalLastPayloads ||
      maskSecrets(originalRequests) !== originalRequests ||
      maskSecrets(originalLastPayloads) !== originalLastPayloads)
    return {...safe, leads: [], cursor: 0, active: null,
      redactedExecutableLeads: payload.leads?.length ?? 0};
  return safe;
}

/** Preserve an accepted access request, or record a redaction cut. */
export function sanitizeAccessCheckpoint(payload, secrets = []) {
  const safe = scrub(payload, secrets);
  if (Array.isArray(safe.leads)) safe.leads = safe.leads.map(lead => ({...lead,
    family: maskSecrets(lead.family ?? ''), why: maskSecrets(lead.why ?? '')}));
  const executable = lead => lead && ({protectedAs: lead.protectedAs,
    protectedPath: lead.protectedPath, subject: lead.subject,
    controlValue: lead.controlValue, firstValue: lead.firstValue,
    secondValue: lead.secondValue, comparison: lead.comparison,
    ownerPointer: lead.ownerPointer, candidatePointer: lead.candidatePointer,
    identityField: lead.identityField, matchFields: lead.matchFields});
  const original = JSON.stringify((payload.leads ?? []).map(executable));
  const stored = JSON.stringify((safe.leads ?? []).map(executable));
  if (original !== stored || maskSecrets(original) !== original)
    return {...safe, leads: [], cursor: 0, active: null,
      redactedExecutableLeads: payload.leads?.length ?? 0};
  return safe;
}

function authorizedDescendantFeedback(scope, hint) {
  if (!hint || typeof hint.origin !== 'string' || typeof hint.path !== 'string' ||
      !hint.path.startsWith('/') || hint.path.startsWith('//') ||
      hint.path.length > 300 || maskSecrets(hint.path) !== hint.path) return false;
  try {
    const origin = new URL(hint.origin);
    if (origin.origin !== hint.origin || origin.origin === scope.target.origin ||
        !['http:', 'https:'].includes(origin.protocol) ||
        !scope.discovery.auditDomains.some(domain =>
          origin.hostname === domain || origin.hostname.endsWith(`.${domain}`))) return false;
    const hostScope = {...scope, target: {...scope.target, origin: hint.origin}};
    const checked = validateUrl(hostScope, hint.path,
      {identity: 'anonymous', method: 'GET'});
    return checked.ok && new URL(checked.url).origin === hint.origin;
  } catch {return false;}
}

/** Read only origin/path hints from the exact prior run and reviewed discovery scope. */
export function loadDescendantFeedbackCheckpoint(file, {run, scopeHash, scope}) {
  const feedback = JSON.parse(fs.readFileSync(file, 'utf8'));
  need(feedback.version === 1 && feedback.kind === 'descendant-test-feedback' &&
    feedback.run === run && feedback.scopeHash === scopeHash &&
    feedback.origin === scope.target.origin && Array.isArray(feedback.pending) &&
    feedback.pending.every(item => item && Object.keys(item).sort().join(',') === 'origin,path' &&
      authorizedDescendantFeedback(scope, item)),
  `Run ${run} has an invalid descendant test-feedback checkpoint.`);
  return [...new Map(feedback.pending.map(item =>
    [`${item.origin}\0${item.path}`, {origin: item.origin, path: item.path}])).values()];
}

/** Keep an early budget cut unless the same lead was completed or counted as cut later. */
export function remainingDeferredCut(early, later) {
  const laterKeys = new Map();
  for (const key of [...(later?.completedLeadKeys ?? []),
    ...(later?.cutLeadKeys ?? []),
    ...(later?.results ?? []).filter(item => item.verdict === 'untested')
      .map(item => item.proposalId ? `proposal:${item.proposalId}` : item.leadKey)
      .filter(Boolean)])
    laterKeys.set(key, (laterKeys.get(key) ?? 0) + 1);
  let accounted = 0;
  for (const key of early?.cutLeadKeys ?? []) {
    const available = laterKeys.get(key) ?? 0;
    if (!available) continue;
    laterKeys.set(key, available - 1);
    accounted++;
  }
  return Math.max(0, (early?.cut ?? 0) - accounted);
}

/** A later pass replaces the earlier untested record for the same accepted plan. */
export function reconciledPassResults(run, laterProposalIds = new Set()) {
  return (run?.results ?? []).filter(item => !(item.verdict === 'untested' &&
    ((item.proposalId && laterProposalIds.has(item.proposalId)) ||
      (item.leadKey && laterProposalIds.has(item.leadKey)))));
}

function executedWebTasks(run) {
  return (run?.results ?? []).filter(item => item.verdict !== 'untested').length;
}

/** An early derived planning page is deferred when a later pass reviews the same inventory. */
export function unresolvedWebModelCuts(coverage = []) {
  const resolvedLater = (item, index, available, sent) =>
    item.discoveredVia === 'derived-session' && coverage.slice(index + 1).some(later =>
      later.origin === item.origin && later.discoveredVia === item.discoveredVia &&
      later[available] === item[available] && later[sent] >= item[available]);
  return {
    candidates: coverage.filter((item, index) =>
      item.candidatesSent < item.candidatesAvailable &&
      !resolvedLater(item, index, 'candidatesAvailable', 'candidatesSent')),
    prelude: coverage.filter((item, index) =>
      (item.candidatesAvailable ?? 0) > 0 &&
      (item.preludeRoutesSent ?? 0) < (item.preludeRoutesAvailable ?? 0) &&
      !resolvedLater(item, index, 'preludeRoutesAvailable', 'preludeRoutesSent')),
    sequences: coverage.filter((item, index) =>
      (item.httpSequenceSent ?? 0) < (item.httpSequenceAvailable ?? 0) &&
      !resolvedLater(item, index, 'httpSequenceAvailable', 'httpSequenceSent')),
  };
}

/** Keep a post-recon planning window open while reserving later research time. */
export function protectedPlanningDeadline(now, originalEarlyDeadline, researchDeadline) {
  if (now < originalEarlyDeadline) return originalEarlyDeadline;
  const remaining = researchDeadline - now;
  return remaining > 0 ? now + Math.max(1, Math.floor(remaining / 4)) : now;
}

/** Keep time for proof replay while letting user-budgeted research use the run. */
export function researchReportReserveMs(totalMs) {
  return Math.min(90_000, Math.max(30_000, Math.floor(totalMs * 0.1)));
}

function earlyRunFailure(error, ledger, firstRecord, secrets, redactFields) {
  const name = String(error?.name ?? 'Error').replace(/[^A-Za-z0-9]/g, '').slice(0, 40) || 'Error';
  const code = /^[A-Z][A-Z0-9_]{0,39}$/.test(error?.code ?? '') ? error.code : null;
  const message = scrub(maskExcerpt(String(error?.message ?? 'unknown runner error')
    .replace(/\s+/g, ' '), redactFields), secrets)
    .replace(/\b[A-Za-z0-9._-]{24,}\b/g, '[value]').slice(0, 240);
  const partial = {firstEvidence: firstRecord <= ledger.count() ? `ev-${String(firstRecord).padStart(4, '0')}` : null,
    lastEvidence: firstRecord <= ledger.count() ? `ev-${String(ledger.count()).padStart(4, '0')}` : null,
    acceptedPlans: 0, acceptedRevisions: 0, attempts: []};
  try {
    const rows = fs.readFileSync(ledger.file, 'utf8').trim().split('\n').slice(firstRecord - 1);
    for (const line of rows) {
      const item = JSON.parse(line);
      if (item.kind === 'model-http-sequence-plan-summary') partial.acceptedPlans += item.accepted ?? 0;
      if (item.kind === 'model-http-sequence-decision' && item.accepted) partial.acceptedRevisions++;
      if (['model-http-sequence-attempt', 'model-protected-body-attempt'].includes(item.kind))
        partial.attempts.push({evidenceId: item.id, kind: item.kind,
          path: item.path, verdict: item.verdict});
    }
  } catch { /* The intact ledger range remains the authoritative partial evidence. */ }
  return {name, code, message, partial};
}

function selectedModel(root, name, env = process.env) {
  let state;
  try { state = JSON.parse(fs.readFileSync(path.join(root, '.bypass/state.json'), 'utf8')); } catch { /* an uninitialized folder is valid */ }
  const profile = state?.models?.find(item => item.name === (name ?? state.activeModel));
  need(!name || profile, `Model profile '${name}' was not found. Add it with bypass model add, or omit --model to use the Meta API default.`);
  return profile ?? modelProfile('meta-blackbox', {provider: 'meta',
    'secret-env': env.META_API_KEY ? 'META_API_KEY' : env.LLM_KEY ? 'LLM_KEY' : 'MODEL_API_KEY'});
}

/** Run a bounded audit, writing every intermediate artifact under one run folder. */
export async function runAudit({url, root = process.cwd(), scopeFile = null, overrides = {}, env = process.env,
  noModel = false, dryRun = false, noDiscovery = false, offline = false, modelName = null, infer = modelInfer,
  modelProfileOverride = null,
  resolve = null, ct = null, connectTls = null, osvQuery = null, sourcePath = null,
  sourceContext = null, combinedReviewId = null,
  findingId = null, focusPath = null, revisionPath = null, revisionField = null,
  log = () => {}, out = null,
  signal = null,
  resumeFrom = null} = {}) {
  need(url, 'Provide a target origin URL: bypass blackbox <url>.');
  const projectRoot = rootFrom(root, false);
  let registeredTargets = [];
  try {registeredTargets = JSON.parse(fs.readFileSync(path.join(projectRoot,'.bypass/state.json'),'utf8')).targets ?? [];} catch { /* local uninitialized folder */ }
  if (resumeFrom) {
    need(/^bx-\d{8}-[0-9a-f]{8}$/.test(resumeFrom), 'Resume needs a saved black-box run ID.');
    need(!noModel && !dryRun, 'Research resume needs a model-enabled audit.');
  }
  const priorDir = resumeFrom ? path.join(projectRoot, '.bypass/runs', resumeFrom) : null;
  const metadataFile = priorDir && (fs.existsSync(path.join(priorDir, 'run.json')) ?
    path.join(priorDir, 'run.json') : path.join(priorDir, 'run-start.json'));
  const prior = metadataFile && fs.existsSync(metadataFile) ?
    JSON.parse(fs.readFileSync(metadataFile, 'utf8')) : null;
  const focus = findingId || prior?.focus?.findingId ?
    await sourceFindingFocus(projectRoot, findingId ?? prior.focus.findingId,
      focusPath ?? prior?.focus?.path ?? null) : null;
  const effectiveRevisionPath = revisionPath ?? prior?.revisionPath ?? null;
  const effectiveRevisionField = revisionField ?? prior?.revisionField ?? 'revision';
  const effectiveOverrides = {...overrides, testResolver: !!resolve};
  const savedLimits = prior?.effectiveLimits ?? prior?.scope?.limits;
  for (const [flag, limit] of [['rps', 'rps'],
    ['waves', 'waves'], ['modelCalls', 'modelCalls'], ['minutes', 'minutes'],
    ['maxUrls', 'maxUrls'], ['maxTasks', 'tasks'],
    ['domScriptBytes', 'domScriptBytes']]) {
    if (effectiveOverrides[flag] == null && savedLimits?.[limit] != null)
      effectiveOverrides[flag] = savedLimits[limit];
  }
  if (effectiveOverrides.httpWorkers == null && effectiveOverrides.agents == null &&
      savedLimits?.agents != null)
    effectiveOverrides.httpWorkers = savedLimits.agents;
  if (effectiveOverrides.modelAgents == null && savedLimits?.modelConcurrency != null)
    effectiveOverrides.modelAgents = savedLimits.modelConcurrency;
  const defaultScope = path.join(projectRoot, 'blackbox.scope.json');
  const file = scopeFile ?? (fs.existsSync(defaultScope) ? defaultScope : null);
  const {scope, hash: scopeHash} = loadScope({file, origin: url,
    overrides: effectiveOverrides, targets: registeredTargets});
  // Resume may change execution budgets without changing the reviewed target,
  // paths, methods or authorization. Rebuild the prior effective scope with
  // its saved budgets to detect any actual scope-file change.
  const priorScopeHash = resumeFrom && savedLimits ? loadScope({file, origin: url,
    overrides: {...effectiveOverrides,
      ...Object.fromEntries([['rps', 'rps'], ['httpWorkers', 'agents'],
        ['modelAgents', 'modelConcurrency'],
        ['waves', 'waves'], ['modelCalls', 'modelCalls'], ['minutes', 'minutes'],
        ['maxUrls', 'maxUrls'], ['maxTasks', 'tasks'],
        ['domScriptBytes', 'domScriptBytes']]
        .filter(([, limit]) => savedLimits[limit] != null)
        .map(([flag, limit]) => [flag, savedLimits[limit]]))},
    targets: registeredTargets}).hash : scopeHash;
  const taskLimit = taskAllowance(scope);
  let resumeResearch = null, resumeResearchFile = null;
  let resumePageFile = null, resumePageIdentity = null;
  let resumeAcceptedQueues = [];
  let resumeFeedback = [], resumeDescendantFeedback = [];
  let resumeCheckpointBacklog = [];
  if (resumeFrom) {
    const flowCheckpointFiles = fs.readdirSync(priorDir)
      .filter(name => HTTP_SEQUENCE_CHECKPOINT.test(name));
    const jsonCheckpointFiles = fs.readdirSync(priorDir)
      .filter(name => name.startsWith('json-experiment-') &&
        ACCEPTED_RESEARCH_CHECKPOINT.test(name));
    const accessCheckpointFiles = fs.readdirSync(priorDir)
      .filter(name => name.startsWith('access-boundary-') &&
        ACCEPTED_RESEARCH_CHECKPOINT.test(name));
    const checkpointFiles = [...flowCheckpointFiles,
      ...jsonCheckpointFiles, ...accessCheckpointFiles, 'research-checkpoint.json',
      'http-sequence-page-checkpoint.json']
      .map(name => path.join(priorDir, name)).filter(name => fs.existsSync(name));
    const feedbackFile = path.join(priorDir, 'test-feedback-checkpoint.json');
    const descendantFeedbackFile = path.join(priorDir, 'descendant-test-feedback-checkpoint.json');
    need(prior && (checkpointFiles.length || fs.existsSync(feedbackFile) ||
      fs.existsSync(descendantFeedbackFile)),
      `Run ${resumeFrom} has no recoverable Muse research checkpoint.`);
    need(prior.scopeHash === priorScopeHash &&
      (prior.origin ?? prior.scope?.target?.origin) === scope.target.origin,
    `Run ${resumeFrom} has a different scope or target. Resume with its original reviewed scope.`);
    need(verifyLedger(path.join(priorDir, 'evidence.jsonl')).ok,
      `Run ${resumeFrom} has a damaged evidence ledger.`);
    if (fs.existsSync(feedbackFile)) {
      const feedback = JSON.parse(fs.readFileSync(feedbackFile, 'utf8'));
      need(feedback.version === 1 && feedback.kind === 'test-feedback' &&
        feedback.run === resumeFrom && feedback.scopeHash === prior.scopeHash &&
        feedback.origin === scope.target.origin && Array.isArray(feedback.pending) &&
        feedback.pending.every(value => typeof value === 'string' &&
          value.startsWith('/') && !value.startsWith('//') &&
          validateUrl(scope, value, {identity: 'anonymous', method: 'GET'}).ok),
      `Run ${resumeFrom} has an invalid test-feedback checkpoint.`);
      resumeFeedback = [...new Set(feedback.pending)];
    }
    if (fs.existsSync(descendantFeedbackFile)) {
      resumeDescendantFeedback = loadDescendantFeedbackCheckpoint(descendantFeedbackFile,
        {run: resumeFrom, scopeHash: prior.scopeHash, scope});
    }
    const checkpointEntries = checkpointFiles.map(file => ({file,
      state: JSON.parse(fs.readFileSync(file, 'utf8'))}));
    resumeCheckpointBacklog = checkpointEntries.filter(({state}) =>
      (Array.isArray(state.leads) && Number.isInteger(state.cursor) &&
        state.cursor >= 0 && state.cursor < state.leads.length) ||
      (Array.isArray(state.pages) && state.pages.some(pendingRoutePage)));
    need(resumeCheckpointBacklog.every(({state}) => state.version === 1 &&
      state.run === resumeFrom && state.scopeHash === prior.scopeHash &&
      state.origin === scope.target.origin),
    `Run ${resumeFrom} has an invalid research checkpoint.`);
    const pendingPageEntry = checkpointEntries.flatMap(({file, state}) =>
      (state.pages ?? []).map(page => ({file,
        page: {...state, ...page, pages: undefined, kind: 'http-sequence-page'}})))
      .filter(({page}) => pendingRoutePage(page) &&
        page.origin === scope.target.origin)
      .sort((a, b) => String(b.page.updatedAt).localeCompare(String(a.page.updatedAt)))[0];
    const pendingPage = pendingPageEntry?.page;
    const pendingQueues = checkpointEntries.filter(({state}) =>
      Array.isArray(state.leads) && Number.isInteger(state.cursor) &&
      state.cursor >= 0 && state.cursor < state.leads.length);
    // Resume the oldest accepted unfinished work first, regardless of runner
    // kind. File-group order otherwise keeps HTTP feedback ahead of an older
    // access hypothesis that Muse already selected.
    const queueAge = ({state}) => {
      const timestamp = Date.parse(state.updatedAt ?? '');
      return Number.isFinite(timestamp) ? timestamp : Number.MAX_SAFE_INTEGER;
    };
    resumeAcceptedQueues = pendingQueues
      .filter(({file}) => ACCEPTED_RESEARCH_CHECKPOINT.test(path.basename(file)) ||
        HTTP_SEQUENCE_CHECKPOINT.test(path.basename(file)))
      .sort((a, b) => queueAge(a) - queueAge(b));
    const genericQueue = pendingQueues.find(({file}) =>
      path.basename(file) === 'research-checkpoint.json');
    resumeResearch = genericQueue?.state ?? pendingPage ?? null;
    resumeResearchFile = genericQueue?.file ?? null;
    resumePageFile = genericQueue ? null : pendingPageEntry?.file;
    resumePageIdentity = genericQueue ? null : pendingPage;
    if (resumeResearch) need(resumeResearch.version === 1 &&
      resumeResearch.scopeHash === prior.scopeHash &&
      resumeResearch.origin === scope.target.origin && resumeResearch.run === resumeFrom,
    `Run ${resumeFrom} has an invalid research checkpoint.`);
    need(resumeResearch || resumeAcceptedQueues.length ||
      resumeFeedback.length || resumeDescendantFeedback.length,
    `Run ${resumeFrom} has no pending Muse ${resumeResearch?.kind === 'http-sequence' ?
      'HTTP sequence' : resumeResearch?.kind === 'json-experiment' ?
      'JSON POST' : resumeResearch?.kind === 'access-boundary' ?
      'access-boundary' : 'GET'} investigation to resume.`);
  }
  const allowLocal = loopback(new URL(scope.target.origin).hostname);
  const run = `bx-${new Date().toISOString().slice(0, 10).replaceAll('-', '')}-${randomBytes(4).toString('hex')}`;
  const runDir = out ? path.resolve(projectRoot, out) : path.join(projectRoot, '.bypass/runs', run);
  need(!fs.existsSync(runDir) || fs.readdirSync(runDir).length === 0,
    `Run folder must be new or empty: ${runDir}.`);
  fs.mkdirSync(runDir, {recursive: true, mode: 0o700});
  const startedAt = now(), started = Date.now();
  atomic(path.join(runDir, 'run-start.json'), {run, status: 'running', scopeHash,
    ...(combinedReviewId?{combinedReviewId}:{}),
    origin: scope.target.origin, scopeFile: file ? path.resolve(file) : null,
    rps: scope.limits.rps, effectiveLimits: scope.limits,
    startedAt, resumedFrom: resumeFrom,
    ...(focus ? {focus, revisionPath: effectiveRevisionPath,
      revisionField: effectiveRevisionField} : {})});
  const deadline = started + scope.limits.minutes * 60000;
  // Reserve enough time to execute and replay accepted work after Muse planning.
  const researchReserve = researchReportReserveMs(deadline - started);
  const researchDeadline = deadline - researchReserve;
  // A confirmed session gets an early planning window, and the primary pass
  // then leaves time for the complete protected-route follow-up.
  const protectedEarlyDeadline = started + Math.floor((researchDeadline - started) * 0.4);
  const primaryAfterSessionDeadline = started + Math.floor((researchDeadline - started) * 0.7);
  const secrets = [scope.identities.owner.env, scope.identities.outsider.env,
    ...['owner', 'outsider'].flatMap(identity =>
      Object.values(credentialNames(scope, identity)))]
    .filter(Boolean).map(name => env[name]).filter(Boolean);
  // Copy every accepted queue into the new ledger before executing any of
  // them. A deadline or interruption leaves the unstarted work resumable.
  for (const {file, state} of resumeCheckpointBacklog) {
    const copied = {...state, run, scopeHash,
      origin: scope.target.origin, resumedFrom: resumeFrom};
    const saved = path.basename(file).startsWith('json-experiment-') ?
      sanitizeJsonCheckpoint(copied, secrets) :
      path.basename(file).startsWith('access-boundary-') ?
        sanitizeAccessCheckpoint(copied, secrets) : scrub(copied, secrets);
    const copiedFile = path.join(runDir, path.basename(file));
    atomic(copiedFile, saved);
    // The executor must use the same redacted state that was persisted. A
    // newly supplied credential can invalidate an old executable request.
    if (file === resumeResearchFile) resumeResearch = saved;
    if (file === resumePageFile) {
      const page = saved.pages?.find(item => item.pass === resumePageIdentity.pass &&
        item.derivedLoginPath === resumePageIdentity.derivedLoginPath &&
        (item.principalFingerprint ?? null) ===
          (resumePageIdentity.principalFingerprint ?? null));
      if (page) resumeResearch = {...saved, ...page,
        pages: undefined, kind: 'http-sequence-page'};
    }
    const accepted = resumeAcceptedQueues.find(item => item.file === file);
    if (accepted) {
      accepted.file = copiedFile;
      accepted.state = saved;
    }
  }
  const ledger = createLedger(runDir, {run, redactFields: scope.harvest.redactFields, secrets});
  if (focus) ledger.append({step: 'recon', kind: 'source-finding-handoff',
    findingId: focus.findingId, path: focus.path, method: focus.method,
    source: focus.source, sourceSnapshotMatches: focus.sourceSnapshotMatches,
    sourceRevision: focus.sourceRevision});
  const events = [];
  const say = item => { events.push({at: now(), ...item}); log(item); };
  let liveRequests = 0, liveModelCalls = 0;
  let currentPhase = {step: 0, title: 'Starting', since: Date.now()};
  const stopRecord = (status, extra = {}) => ({run, status,
    phase: {step: currentPhase.step, title: currentPhase.title},
    evidenceEntries: ledger.count(), requests: liveRequests, modelCalls: liveModelCalls,
    startedAt, finishedAt: now(), ...extra});
  const onSignal = signal => {
    try {atomic(path.join(runDir, 'run-stop.json'), stopRecord('interrupted', {signal}));}
    catch { /* Preserve normal signal handling even if the disk is unavailable. */ }
    process.removeListener(signal, signalHandlers[signal]);
    process.kill(process.pid, signal);
  };
  const signalHandlers = {
    SIGINT: () => onSignal('SIGINT'),
    SIGTERM: () => onSignal('SIGTERM'),
  };
  for (const [signal, handler] of Object.entries(signalHandlers)) process.once(signal, handler);
  const phase = (state, step, title) => {
    if (signal?.aborted) throw abortFault(signal);
    const phaseDurationMs=state === 'done' && currentPhase.step === step ?
      Math.max(0,Date.now()-currentPhase.since) : null;
    if (state === 'doing') currentPhase = {step, title, since: Date.now()};
    log({stage: 'progress', type: 'phase', state, step,
      total: 6, title, requests: liveRequests, modelCalls: liveModelCalls,
      ...(phaseDurationMs!=null?{durationMs:phaseDurationMs}:{})});
  };
  const appendEvidence = ledger.append;
  ledger.append = entry => {
    const evidenceId = appendEvidence(entry);
    if (entry?.request && (entry.response || entry.blocked)) {
      liveRequests++;
      log({stage: 'progress', type: 'request', requests: liveRequests});
    }
    return evidenceId;
  };
  let surface = null, mined = null, discovery = null, sourceReview = null, assetAnalysis = null, advisories = null,
    observedRoutes = null,
    plan = null, results = [], findings = [], chains = [], chainPlanning = [], recheck = null,
    modelError = null;
  let researchDeadlineCut = false;
  let credentialAudits = [];
  const derivedSessions = [];
  const derivedWeb = [];
  const resumedWeb = [];
  const derivedPending = [];
  const provedAccessQueue = [];
  const provedAccessRecon = [];
  const provedAccessSurfaces = [];
  const provedAccessScopes = [];
  const derivedScopedRequesters = [];
  const derivedSessionKeys = new Map();
  let derivedSessionsReused = 0;
  const webProgress = {run, updatedAt: startedAt, current: null, passes: {}};
  const onWebProgress = pass => snapshot => {
    webProgress.updatedAt = now();
    webProgress.current = pass;
    webProgress.passes[pass] = scrub(snapshot, secrets);
    atomic(path.join(runDir, 'web-progress.json'), webProgress);
  };
  let web = {findings: [], results: [], cut: 0, tested: 0, strategyDecisions: []};
  let earlySource = {findings: [], results: [], tested: 0, keys: [], plan: []};
  let assessment = null;
  let stats = {startedAt, model: null, modelCalls: 0, requests: 0, cached: 0, tasks: 0, agents: 0};
  try {
    const testMuse = !noModel && infer === modelInfer && !modelProfileOverride && !modelName &&
      env.BYPASS_TEST_LEGACY_MUSE === '1' &&
      fs.existsSync(path.join(env.PATH?.split(path.delimiter)[0] ?? '', 'muse'));
    const model = noModel ? null : modelProfileOverride ??
      (testMuse ? {name: 'muse', provider: 'muse-code',
        model: 'Muse session default', effort: 'minimal'} : selectedModel(projectRoot, modelName, env));
    const activeInfer = testMuse ?
      (await import('../../test/legacy-muse-infer.mjs')).infer : infer;
    stats.model = model?.model ?? null;
    let modelInvocations = 0;
    const modelParallelism = Math.max(1,
      Math.floor(Number(scope.limits.modelConcurrency) || 4));
    stats.modelWorkersConfigured = modelParallelism;
    let modelInFlight = 0;
    const modelWaiters = [];
    const acquireModelSlot = async () => {
      if (modelInFlight < modelParallelism) { modelInFlight++; return; }
      await new Promise(resolve => modelWaiters.push(resolve));
    };
    const releaseModelSlot = () => {
      const next = modelWaiters.shift();
      if (next) next();
      else modelInFlight--;
    };
    const invokeModelOnce = async (profile, messages, options = {}) => {
      await acquireModelSlot();
      let call=null,callStarted=null,activity='Analyzing observed security evidence';
      try {
        need(modelInvocations < scope.limits.modelCalls, 'Muse model-call budget was exhausted.', 3);
        if (Date.now() >= deadline) {
          researchDeadlineCut = true;
          throw new Fault(AUDIT_MODEL_DEADLINE_MESSAGE, 3, {reason: 'research_deadline'});
        }
        modelInvocations++;
        call=modelInvocations;
        callStarted=Date.now();
        activity=describeModelActivity(messages);
        liveModelCalls = modelInvocations;
        stats.modelWorkersPeak = Math.max(stats.modelWorkersPeak ?? 0, modelInFlight);
        log({stage: 'progress', type: 'model', modelCalls: liveModelCalls});
        log({stage:'progress',type:'model-start',call,activity,active:modelInFlight,
          configured:modelParallelism});
        const remainingMs = deadline - Date.now();
        const timeoutMs = Math.max(1, Math.min(model.provider === 'muse-host' ? 300000 : 60000, remainingMs));
        try {
          const answer=await activeInfer(profile, messages, {...options, signal, timeoutMs,
            onProgress: progress => {if (progress.kind === 'model') stats.model = progress.model;}});
          log({stage:'progress',type:'model-finish',call,activity,status:'completed',
            durationMs:Date.now()-callStarted,active:Math.max(0,modelInFlight-1),
            configured:modelParallelism});
          return answer;
        } catch (error) {
          const classified = classifyAuditModelDeadline(error,
            {auditLimited: remainingMs <= 60000, deadline});
          if (classified !== error) researchDeadlineCut = true;
          log({stage:'progress',type:'model-finish',call,activity,
            status:/timed out|deadline/i.test(classified.message)?'timed out':'failed',
            durationMs:Date.now()-callStarted,active:Math.max(0,modelInFlight-1),
            configured:modelParallelism});
          throw classified;
        }
      } finally { releaseModelSlot(); }
    };
    const invokeModel = (profile, messages, options = {}) => withStructuredRepair(
      repairMessages=>invokeModelOnce(profile,repairMessages,options),messages,{
        canRetry:()=>!signal?.aborted&&modelInvocations<scope.limits.modelCalls&&Date.now()<deadline,
        onRetry:()=>log({stage:'progress',type:'activity',message:
          'Model returned an invalid structured response; retrying this decision once with the same evidence'})
      });
    phase('doing', 1, 'Scope and host discovery');
    const auditLimiter = createLimiter(scope.limits.rps);
    const anonymousRequester = createRequester(scope, {ledger, limiter: auditLimiter,
      env: {}, allowLocal, log: say, run, signal, deadline});
    if (scope.domains.length && !noDiscovery && !focus) {
      discovery = await discover(scope, {requester: anonymousRequester, ledger, ...(resolve ? {resolve} : {}),
        ...(ct ? {ct} : {}), ...(connectTls ? {connectTls} : {}),
        infer: model ? invokeModel : null, model, offline, log: say});
      const interpretation = await interpretDiscovery(discovery, {infer: model ? invokeModel : null, model,
        maxCalls: Math.max(1, Math.min(20, Math.floor(scope.limits.modelCalls / 3))), log: say});
      modelError = modelError ?? discovery.modelNaming?.modelError ?? interpretation.modelError;
      atomic(path.join(runDir, 'discovery.json'), discovery);
    }
    phase('done', 1, 'Scope and host discovery');
    phase('doing', 2, 'Recon: assets and source');
    if (focus) {
      const readMethod = ['GET', 'HEAD'].includes(focus.method) ? focus.method :
        focus.method === 'UNKNOWN' && scope.methods.includes('GET') ? 'GET' : null;
      const response = readMethod ? await anonymousRequester({url: focus.path,
        identity: 'anonymous', method: readMethod, step: 'recon', purpose: 'task',
        omitExcerpt: true}) : null;
      const observedRead = response && (focus.method !== 'UNKNOWN' ||
        response.status >= 200 && response.status < 400);
      observedRoutes = {routes: observedRead ? [{path: new URL(focus.path, scope.target.origin).pathname,
        method: readMethod, sources: [{source: 'source-finding', findingId: focus.findingId}],
        status: response.status ?? null, type: response.type ?? null,
        hash: response.hash ?? null, evidenceId: response.evidenceId ?? null,
        links: 0, listing: false}] : [], exposures: [],
        assetPages: observedRead && readMethod === 'GET' && /html/i.test(response.type ?? '') ? [focus.path] : [],
        stats: {routes: observedRead ? 1 : 0, requested: response ? 1 : 0,
          listings: 0, filesChecked: 0,
          filesUnfetched: 0, exposures: 0, queued: 0, cuts: {}}};
      say({stage: 'recon', message: `Focused source finding ${focus.findingId}: ${focus.path}`});
    } else observedRoutes = await reconObservedRoutes(scope, anonymousRequester,
      {deadline, log: say});
    const miningPages = [...new Set([...observedRoutes.assetPages,
      ...scope.discover.filter(item => item === '/' || /html?|docs/i.test(item))])];
    observedRoutes.stats.cuts.minedPages = Math.max(0, miningPages.length - 30);
    atomic(path.join(runDir, 'observed-routes.json'), observedRoutes);
    let assetPages = miningPages.slice(0, 30);
    if (focus) {
      assetPages = observedRoutes.routes[0]?.method === 'GET' ? [focus.path] : [];
      if (!assetPages.length && validateUrl(scope, '/',
        {purpose: 'task', identity: 'anonymous', method: 'GET'}).ok) assetPages = ['/'];
    }
    mined = await mineOrigin(scope.target.origin, {requester: anonymousRequester, assetHosts: scope.discovery.assetHosts,
      workers: scope.limits.agents,
      crawlPaths: focus ? [] : scope.include,
      pages: assetPages,
      ...(focus ? {maxPages: 1} : {}), log: say});
    if (focus) {
      const focusedPathname = new URL(focus.path, scope.target.origin).pathname;
      mined.endpoints = mined.endpoints.filter(item => {
        try {return new URL(item.path, scope.target.origin).pathname === focusedPathname;}
        catch {return false;}
      });
    }
    if (focus && !mined.endpoints.some(item => item.path === focus.path))
      mined.endpoints.push({path: focus.path, method: focus.method, params: [],
        source: 'source-finding', evidenceId: observedRoutes.routes[0]?.evidenceId ?? null});
    const knownEndpoints = new Set(mined.endpoints.map(item => `${item.method} ${item.path}`));
    for (const item of observedRoutes.routes.filter(item =>
      (item.status === 200 && (/html|json|xml/i.test(item.type ?? '') || item.listing)) ||
      [301, 302, 307, 308, 401, 403].includes(item.status))) {
      if (knownEndpoints.has(`${item.method} ${item.path}`)) continue;
      knownEndpoints.add(`${item.method} ${item.path}`);
      mined.endpoints.push({path: item.path, method: item.method, params: [],
        source: item.sources.map(source => source.source).join(', '),
        observedStatus: item.status, evidenceId: item.evidenceId});
    }
    // Scale early interpretation with the operator's model allowance while
    // leaving most calls for route analysis, tests, revisions and assessment.
    const reconModelPages = reserve => {
      const available = Math.max(0, scope.limits.modelCalls - modelInvocations - reserve);
      return Math.min(available, Math.ceil(available / 4));
    };
    if (sourceContext) sourceReview = await sourceContext;
    if (sourcePath || focus && fs.existsSync(path.join(projectRoot, focus.source.file))) {
      const reviewed = await reviewSource(sourcePath ?? projectRoot, {
        infer: !focus && model ? invokeModel : null, model,
        origin: scope.target.origin,
        maxModelPages: scope.limits.modelCalls <= 10 ?
          Math.min(1, Math.max(0, scope.limits.modelCalls - modelInvocations)) :
          reconModelPages(10),
        modelConcurrency: scope.limits.modelConcurrency,
        log: say});
      sourceReview = sourceReview ? {
        ...reviewed,
        files: [...sourceReview.files, ...reviewed.files],
        endpoints: [...sourceReview.endpoints, ...reviewed.endpoints],
        notes: [...sourceReview.notes, ...reviewed.notes],
        proposals: [...sourceReview.proposals, ...reviewed.proposals],
        secretLeads: [...sourceReview.secretLeads, ...reviewed.secretLeads],
        securityLeads: [...sourceReview.securityLeads, ...reviewed.securityLeads],
        stats: Object.fromEntries(Object.keys(reviewed.stats).map(key => [key,
          Number(sourceReview.stats?.[key] ?? 0) + Number(reviewed.stats[key] ?? 0)])),
        modelCalls: Number(sourceReview.modelCalls ?? 0) + reviewed.modelCalls,
        modelError: sourceReview.modelError ?? reviewed.modelError,
      } : reviewed;
    }
    if (sourceReview) {
      stats.modelCalls += sourceReview.modelCalls ?? 0;
      modelError = modelError ?? sourceReview.modelError;
      mined.endpoints.push(...(focus ? sourceReview.endpoints.filter(item =>
        item.file === focus.source.file || item.path === focus.path) :
        sourceReview.endpoints),
      ...(!focus ? sourceReview.proposals.map(path => ({path, method: 'GET',
        params: [], source: 'model:source'})) : []));
      atomic(path.join(runDir, 'source.json'), sourceReview);
    }
    if (!dryRun && sourceReview?.securityLeads?.length) {
      say({stage: 'progress', type: 'activity',
        message: 'Checking cited private-record routes with fresh anonymous reads'});
      earlySource = await runSourceDisclosureProbes({sourceReview}, scope,
        {requester: anonymousRequester, budget: Math.min(3, taskLimit)});
      atomic(path.join(runDir, 'source-live-probes.json'), earlySource);
      for (const result of earlySource.results)
        say({stage: 'progress', type: 'task-done', confirmed: result.verdict === 'confirmed'});
      if (earlySource.tested) say({stage: 'source-proof', message:
        `${earlySource.tested} cited route${earlySource.tested === 1 ? '' : 's'} checked early · ` +
        `${earlySource.findings.length} positive signal${earlySource.findings.length === 1 ? '' : 's'} queued for replay`});
    }
    if (model && !focus) {
      const assetHosts = (discovery?.hosts ?? []).filter(host => host.assets?.files?.length);
      assetAnalysis = await interpretAssets([mined, ...assetHosts.map(host => host.assets)],
        {infer: invokeModel, model,
          maxPages: reconModelPages(8), log: say});
      modelError = modelError ?? assetAnalysis.modelError;
      applyAssetProposals(mined, assetHosts, assetAnalysis.proposals);
      mined.modelAnalysis = {coverage: assetAnalysis.coverage, modelCalls: assetAnalysis.modelCalls,
        modelError: assetAnalysis.modelError, notesAccepted: assetAnalysis.notes.length,
        proposalsAccepted: assetAnalysis.proposals.length};
      ledger.append({step: 'recon', kind: 'asset-model-analysis', coverage: assetAnalysis.coverage,
        acceptedNotes: assetAnalysis.notes.length,
        evidence: [...new Set(assetAnalysis.notes.map(note => note.evidenceId).filter(Boolean))]});
      atomic(path.join(runDir, 'asset-analysis.json'), assetAnalysis);
      if (discovery) {
        discovery.assetModelAnalysis = mined.modelAnalysis;
        for (const [index, host] of assetHosts.entries()) for (const note of assetAnalysis.notes)
          if (note.summaryIndexes.includes(index + 1)) {
            const operation = host.operations.find(item => item.path === note.path && item.method === note.method);
            if (!operation) continue;
            operation.purpose ??= note.purpose;
            operation.parameterMeanings ??= note.parameterMeanings.filter(item =>
              operation.params.some(param => param.name === item.name));
          }
        atomic(path.join(runDir, 'discovery.json'), discovery);
      }
    }
    atomic(path.join(runDir, 'assets.json'), mined);
    phase('done', 2, 'Recon: assets and source');
    phase('doing', 3, 'Recon: routes and responses');
    const localPosts = await deriveLocalPostScope(focus ? {...scope, discover: []} : scope,
      mined, anonymousRequester);
    if (localPosts.admitted.length || localPosts.authAdmitted.length || localPosts.skipped.length) {
      atomic(path.join(runDir, 'local-post-contracts.json'), {admitted: localPosts.admitted,
        authAdmitted: localPosts.authAdmitted, skipped: localPosts.skipped});
      say({stage: 'recon', message: `Observed POST contracts: ${localPosts.admitted.length} JSON/form + ${localPosts.authAdmitted.length} login admitted from public evidence; ${localPosts.skipped.length} skipped`});
    }
    const sessions = await establishIdentities(localPosts.scope, {mined, requester: anonymousRequester,
      env, ledger, allowLocal, log: say});
    // Keep configured login values available only in the audit's private
    // execution environment; plans and proofs refer to their env names.
    for (const identity of ['owner', 'outsider'])
      for (const name of Object.values(credentialNames(sessions.scope, identity)))
        if (typeof env[name] === 'string' && env[name]) sessions.env[name] = env[name];
    const requester = createRequester(sessions.scope, {ledger, limiter: auditLimiter,
      env: sessions.env, allowLocal, log: say, run, signal, deadline});
    const ownerSecret = sessions.env[sessions.scope.identities.owner.env];
    const outsiderSecret = sessions.env[sessions.scope.identities.outsider.env];
    const ownerReady = !!(sessions.identities.owner.ok && ownerSecret);
    const outsiderReady = !!(sessions.identities.outsider.ok && outsiderSecret);
    let principalParityFailed = false;
    let credentialsReady = !!(ownerReady && outsiderReady && ownerSecret !== outsiderSecret &&
      sessions.scope.identities.owner.role === sessions.scope.identities.outsider.role);
    if (ownerReady) {
      surface = await recon(sessions.scope, {requester, env: sessions.env, mined,
        infer: model ? invokeModel : null, model,
        maxModelPages: Math.max(0, Math.min(8, scope.limits.modelCalls - modelInvocations - 2)), log: say});
      if (credentialsReady && surface.identity.ownerVerified && !surface.identity.verified) {
        credentialsReady = false;
        principalParityFailed = true;
        say({stage: 'identity', message: 'The supplied credentials did not establish distinct account principals; cross-account tasks are withheld.'});
      }
      if (sourceReview) surface.sourceReview = {files: sourceReview.files, notes: sourceReview.notes,
        secretLeads: sourceReview.secretLeads, securityLeads: sourceReview.securityLeads,
        stats: sourceReview.stats, modelCoverage: model ? sourceReview.modelCoverage : null};
      if (sourceReview?.notes?.length) surface.modelNotes.push(...sourceReview.notes.map(note => ({...note, by: 'source-assisted'})));
      if (assetAnalysis?.notes?.length) surface.modelNotes.push(...assetAnalysis.notes
        .filter(note => note.summaryIndexes.includes(0)));
      surface.assetSignals = (assetAnalysis?.signals ?? [])
        .filter(signal => signal.summaryIndexes.includes(0));
      stats.modelCalls += surface.modelCalls ?? 0;
      modelError = modelError ?? surface.modelError;
      atomic(path.join(runDir, 'surface.json'), surface);
      const credentialOriginCount = sessions.scope.credentialOrigins.filter(origin =>
        origin !== sessions.scope.target.origin).length;
      const planQuota = Math.ceil(taskLimit / (credentialOriginCount + 1));
      const planScope = credentialOriginCount ? {...sessions.scope,
        limits: {...sessions.scope.limits, tasks: planQuota}} : sessions.scope;
      plan = await planTasks(surface, planScope, {infer: model ? invokeModel : null, model, discovery,
        maxModelPages: Math.max(0, Math.min(8, scope.limits.modelCalls - modelInvocations - 2)), log: say});
      if (!credentialsReady) {
        const supported = task => oneAccountMissingAuthCandidate(task, surface, sessions.scope);
        const unsupported = plan.tasks.filter(task => !supported(task));
        plan.dropped.push(...unsupported.map(task => ({task, reason: task.request.as === 'anonymous' ?
          'requires-verified-owner-bound-sensitive-item' : 'requires-distinct-same-role-account'})));
        plan.tasks = plan.tasks.filter(supported);
        say({stage: 'plan', message: `${plan.tasks.length} bounded anonymous missing-authentication tasks kept; ${unsupported.length} tasks need more controls`});
      }
      stats.modelCalls += plan.modelCalls;
      modelError = modelError ?? plan.modelError;
      atomic(path.join(runDir, 'tasks.json'), plan);
      if (!dryRun) {
        const swarm = await runSwarm(plan.tasks, {requester, surface, scope: sessions.scope, decide, log: say, run});
        results = swarm.results;
        stats = {...stats, ...swarm.stats};
        const followup = await followupInconclusive(results, plan.tasks, surface, sessions.scope,
          {requester, decide, infer: model ? invokeModel : null, model,
            budget: Math.max(0, taskAllowance(planScope) - plan.tasks.length),
            maxModelPages: Math.max(0, Math.min(8, scope.limits.modelCalls - modelInvocations - 2)),
            log: say, run});
        surface.accessFollowup = {coverage: followup.coverage, selected: followup.selected,
          rejected: followup.rejected, cut: followup.cut,
          modelCalls: followup.modelCalls, modelError: followup.modelError};
        plan.tasks.push(...followup.tasks);
        results.push(...followup.results);
        modelError ??= followup.modelError;
        if (followup.stats) {
          for (const field of ['tasks', 'confirmed', 'notReproduced', 'inconclusive', 'blocked', 'public', 'shared'])
            stats[field] = (stats[field] ?? 0) + (followup.stats[field] ?? 0);
          stats.agents = Math.max(stats.agents ?? 0, followup.stats.agents ?? 0);
        }
        if (surface.identity.verified) {
          recheck = await identityRecheck(surface, {requester, scope: sessions.scope, results, log: say});
        }
        await reverify(results, {requester, surface, scope: sessions.scope, decide, log: say});
        if (credentialsReady) await mirror(results, {requester, surface, scope: sessions.scope, log: say});
      }
    } else {
      say({stage: 'identity', message: 'Two distinct, usable credentials with the same declared role are needed for the current account-boundary runner.'});
      const [mappedResult, exposureResult] = await Promise.allSettled([
        anonymousSurface(sessions.scope, requester, mined),
        focus ? Promise.resolve({exposures: [], stats: {}, selection: null}) :
          scanSensitivePaths(sessions.scope, requester,
            {mined, routes: observedRoutes.routes, modelNotes: assetAnalysis?.notes ?? []}),
      ]);
      if (mappedResult.status === 'rejected') throw mappedResult.reason;
      if (exposureResult.status === 'rejected') throw exposureResult.reason;
      const mapped = mappedResult.value, exposureScan = exposureResult.value;
      say({stage: 'recon', message: `Mapped ${mapped.patterns.length} public GET route candidates`});
      surface = {origin: scope.target.origin, identity: {verified: false},
        patterns: mapped.patterns, xmlBodyOperations: mapped.xmlBodyOperations,
        jsonBodyOperations: mapped.jsonBodyOperations,
        formBodyOperations: mapped.formBodyOperations,
        methodOperations: mapped.methodOperations,
        authBodyOperations: mapped.authBodyOperations,
        apiSchemaCuts: mapped.apiSchemaCuts,
        skippedReadActions: mapped.skippedReadActions ?? [],
        exposures: exposureScan.exposures, exposureStats: exposureScan.stats,
        exposureSelection: exposureScan.selection,
        outOfScope: [], never: [], mined,
        modelNotes: [...(sourceReview?.notes ?? []), ...(assetAnalysis?.notes ?? [])
          .filter(note => note.summaryIndexes.includes(0))],
        assetSignals: (assetAnalysis?.signals ?? [])
          .filter(signal => signal.summaryIndexes.includes(0)),
        sourceReview: sourceReview ?
          {files: sourceReview.files, notes: sourceReview.notes, secretLeads: sourceReview.secretLeads,
            securityLeads: sourceReview.securityLeads,
            stats: sourceReview.stats,
            modelCoverage: model ? sourceReview.modelCoverage : null} : null};
      const followup = focus ? {patterns: [], coverage: {routesAvailable: 0,
        routesReviewed: 0, pagesAvailable: 0, pagesSent: 0}, modelCalls: 0,
        modelError: null} : await followupResponseHints(scope.target.origin, sessions.scope, surface.patterns,
        {requester, infer: model ? invokeModel : null, model,
          // Leave at least half of the remaining calls for hypothesis planning,
          // execution feedback and proof assessment after recursive recon.
          maxModelPages: Math.max(0, Math.min(
            scope.limits.minutes <= 10 ? 1 : 8,
            Math.floor((scope.limits.modelCalls - modelInvocations - 2) / 2))),
          kind: 'primary', log: say});
      mergeResponsePatterns(surface.patterns, followup.patterns);
      surface.anonymousResponseFollowup = {...followup.coverage,
        modelCalls: followup.modelCalls, modelError: followup.modelError};
      modelError ??= followup.modelError;
      plan = {tasks: [], dropped: [], untested: [], modelCalls: 0, modelError: null};
      atomic(path.join(runDir, 'surface.json'), surface);
      atomic(path.join(runDir, 'tasks.json'), plan);
    }
    surface.routeRecon = observedRoutes;
    if (focus) {
      surface.focus = {...focus,
        revision: await checkLiveRevision(focus, requester,
          effectiveRevisionPath, effectiveRevisionField)};
      surface.modelNotes ??= [];
      surface.modelNotes.unshift({path: focus.path, methods: [focus.method],
        parameters: [], purpose: focus.title, why: focus.hypothesis});
      atomic(path.join(runDir, 'focus.json'), surface.focus);
    }
    surface.exposures.push(...observedRoutes.exposures);
    for (const record of surface.patterns ?? []) {
      const observed = observedRoutes.routes.find(item => item.path === record.pattern);
      if (observed?.status != null && !record.responseFacts)
        record.responseFacts = {status: observed.status, type: observed.type,
          hash: observed.hash ?? null, evidenceId: observed.evidenceId, shape: null};
    }
    surface.authBodyOperations ??= Object.values(sessions.scope.localAuthPostContracts ?? {});
    surface.graphql = focus ? {attempts: [], operations: [], modelCalls: 0,
      coverage: {pagesAvailable: 0, pagesSent: 0, fieldsCut: 0, pathsCut: 0}} :
      await inspectGraphql(sessions.scope, {requester,
      observed: [...(mined.endpoints ?? []), ...(surface.patterns ?? []), ...(surface.exposures ?? [])],
      allowOwner: ownerReady,
      infer: model ? invokeModel : null, model,
      maxModelPages: Math.max(0, Math.min(8, scope.limits.modelCalls - modelInvocations - 2)), log: say});
    stats.modelCalls += surface.graphql.modelCalls;
    modelError ??= surface.graphql.modelError;
    if (credentialsReady && !dryRun) {
      const graphqlPlan = await planGraphqlBola(sessions.scope, {inventory: surface.graphql,
        surface, requester, budget: Math.max(0, taskLimit - plan.tasks.length),
        infer: model ? invokeModel : null, model,
        maxModelPages: Math.max(0, Math.min(8, scope.limits.modelCalls - modelInvocations - 2)), log: say});
      surface.graphql.bola = {typeAttempts: graphqlPlan.typeAttempts,
        listAttempts: graphqlPlan.listAttempts, candidates: graphqlPlan.candidates,
        planned: graphqlPlan.tasks.length, cut: graphqlPlan.cut, selected: graphqlPlan.selected,
        modelCoverage: graphqlPlan.modelCoverage, modelCalls: graphqlPlan.modelCalls,
        modelError: graphqlPlan.modelError};
      modelError ??= graphqlPlan.modelError;
      plan.tasks.push(...graphqlPlan.tasks);
      if (graphqlPlan.tasks.length) {
        const graphqlSwarm = await runSwarm(graphqlPlan.tasks,
          {requester, surface, scope: sessions.scope, decide, log: say, run});
        results.push(...graphqlSwarm.results);
        for (const field of ['tasks', 'confirmed', 'notReproduced', 'inconclusive', 'blocked', 'public', 'shared'])
          stats[field] = (stats[field] ?? 0) + (graphqlSwarm.stats[field] ?? 0);
        stats.agents = Math.max(stats.agents ?? 0, graphqlSwarm.stats.agents ?? 0);
        await reverify(graphqlSwarm.results, {requester, surface, scope: sessions.scope, decide, log: say});
        await mirror(graphqlSwarm.results, {requester, surface, scope: sessions.scope, log: say});
        recheck = await identityRecheck(surface, {requester, scope: sessions.scope, results, log: say});
      }
      atomic(path.join(runDir, 'tasks.json'), plan);
    }
    atomic(path.join(runDir, 'graphql.json'), surface.graphql);
    atomic(path.join(runDir, 'surface.json'), surface);
    credentialAudits = focus ? [] : await auditCredentialOrigins(scope, {discovery, env, primary: sessions, ledger,
      infer: model ? invokeModel : null, model, dryRun, run, deadline,
      taskBudget: Math.max(0, taskLimit - plan.tasks.length),
      remainingModelCalls: () => scope.limits.modelCalls - modelInvocations - 2, log: say});
    for (const audit of credentialAudits) {
      results.push(...audit.results);
      plan.tasks.push(...audit.plan.tasks);
      plan.dropped.push(...audit.plan.dropped);
      plan.untested.push(...audit.plan.untested);
      surface.exposures.push(...(audit.surface.exposures ?? []).map(exposure =>
        ({...exposure, url: new URL(exposure.url ?? exposure.path, audit.origin).href})));
      if (audit.stats) for (const field of ['tasks', 'confirmed', 'notReproduced', 'inconclusive', 'blocked', 'public', 'shared'])
        stats[field] = (stats[field] ?? 0) + (audit.stats[field] ?? 0);
      stats.agents = Math.max(stats.agents ?? 0, audit.stats?.agents ?? 0);
      modelError ??= audit.modelError;
    }
    if (credentialAudits.length) {
      atomic(path.join(runDir, 'credential-origins.json'), credentialAudits.map(audit => ({origin: audit.origin,
        mined: audit.mined, surface: audit.surface, plan: audit.plan, results: audit.results,
        recheck: audit.recheck, usable: audit.usable, stats: audit.stats, modelError: audit.modelError})));
      atomic(path.join(runDir, 'tasks.json'), plan);
    }
    if (discovery) for (const host of discovery.hosts) for (const exposure of host.exposures) {
      const address = `${host.origin ?? `https://${host.host}`}${exposure.path}`;
      const fresh = await anonymousRequester({url: address, identity: 'anonymous', method: 'GET', step: 'reverify',
        purpose: 'sensitive', noCache: true, maxBytes: 65536, omitExcerpt: true,
        headers: {'cache-control': 'no-cache'}});
      if (sensitivePathMatches(exposure.path, fresh)) surface.exposures.push({...exposure, url: address,
        confirmationEvidence: fresh.evidenceId, hash: fresh.hash});
    }
    if (!dryRun && scope.limits.modelCalls <= 10 &&
        surface.sourceReview?.securityLeads?.length) {
      const citedReads = [...new Set(surface.sourceReview.securityLeads
        .filter(item => item.method === 'GET' &&
          ['authentication-trust', 'injection'].includes(item.category) &&
          typeof item.path === 'string' && !/[{}:]/.test(item.path))
        .map(item => item.path))].slice(0, 4);
      for (const path of citedReads) {
        const record = (surface.patterns ?? []).find(item => item.pattern === path &&
          (item.methods ?? []).includes('GET') && !Number.isInteger(item.responseFacts?.status));
        if (!record || Date.now() >= deadline ||
            !validateUrl(sessions.scope, path,
              {identity: 'anonymous', method: 'GET'}).ok) continue;
        const response = await requester({url: path, identity: 'anonymous',
          method: 'GET', step: 'recon', purpose: 'task', noCache: true,
          omitExcerpt: true});
        record.responseFacts = {status: response.status ?? null,
          type: response.type ?? null, hash: response.hash ?? null,
          shape: response.shape ?? null, evidenceId: response.evidenceId ?? null};
        const searchLead = surface.sourceReview.securityLeads.find(item =>
          item.category === 'injection' && item.method === 'GET' &&
          item.path === path && item.fields?.some(field =>
            /^(?:q|query|search|term|keyword)$/i.test(field) &&
            Object.hasOwn(record.params ?? {}, field)));
        const baseline = observedSearchBaseline(response, searchLead);
        if (baseline) for (const field of searchLead.fields) {
          if (!/^(?:q|query|search|term|keyword)$/i.test(field) ||
              !Object.hasOwn(record.params ?? {}, field)) continue;
          record.params[field] = [baseline, ...(record.params[field] ?? [])
            .filter(value => value !== baseline)].slice(0, 3);
        }
        say({stage: 'recon', message: `Checked cited ${path} before planning more routes`});
      }
      atomic(path.join(runDir, 'surface.json'), surface);
    }
    if (!dryRun && surface.sourceReview?.securityLeads?.length &&
        taskLimit > earlySource.tested) {
      const header = await runSourceHeaderProbes(surface, sessions.scope,
        {requester, ledger, budget: Math.min(2, taskLimit - earlySource.tested), log: say});
      if (header.tested) {
        earlySource = {...earlySource,
          findings: [...earlySource.findings, ...header.findings],
          results: [...earlySource.results, ...header.results],
          plan: [...earlySource.plan, ...header.plan],
          tested: earlySource.tested + header.tested};
        atomic(path.join(runDir, 'source-header-probes.json'), header);
        for (const result of header.results)
          say({stage: 'progress', type: 'task-done', confirmed: result.verdict === 'confirmed'});
      }
      if (taskLimit > earlySource.tested) {
        const fetch = await runSourceFetchProbes(surface, sessions.scope,
          {requester, ledger, budget: Math.min(1, taskLimit - earlySource.tested),
            log: say});
        if (fetch.tested) {
          earlySource = {...earlySource,
            findings: [...earlySource.findings, ...fetch.findings],
            results: [...earlySource.results, ...fetch.results],
            plan: [...earlySource.plan, ...fetch.plan],
            tested: earlySource.tested + fetch.tested};
          atomic(path.join(runDir, 'source-fetch-probes.json'), fetch);
          for (const result of fetch.results)
            say({stage: 'progress', type: 'task-done', confirmed: result.verdict === 'confirmed'});
        }
      }
    }
    phase('done', 3, 'Recon: routes and responses');
    if (!dryRun) {
      phase('doing', 4, 'Plan and test observed leads');
      const verifiedExposures = [];
      for (const exposure of surface.exposures) {
        const range = exposure.source === 'observed-file' ? 'bytes=0-63' :
          exposure.rangeHeader ?? (exposure.ranged === true ? 'bytes=0-63' : null);
        const fresh = await requester({url: exposure.url ?? exposure.path, identity: 'anonymous', method: 'GET', step: 'reverify',
          purpose: 'sensitive', noCache: true, omitExcerpt: true,
          maxBytes: range === 'bytes=0-63' ? 128 : range ? 8192 : 65536,
          headers: range ? {'cache-control': 'no-cache', range} :
            {'cache-control': 'no-cache', ...(exposure.acceptHtml ? {accept: 'text/html'} : {})}});
        if (sensitivePathMatches(exposure.path, fresh) ||
            observedExposureMatches(exposure, fresh, sessions.scope))
          verifiedExposures.push({...exposure, confirmationEvidence: fresh.evidenceId, hash: fresh.hash});
      }
      surface.exposures = verifiedExposures;
      const availableWebTasks = Math.max(0, taskLimit - (plan.tasks?.length ?? 0) - earlySource.tested);
      const secretSummaries = [mined,
        ...credentialAudits.map(audit => audit.mined),
        ...(discovery?.hosts ?? []).map(host => host.assets)];
      const keyAudit = await auditPublicPrivateKeys(secretSummaries, sessions.scope,
        {requester, budget: Math.min(4, availableWebTasks), log: say});
      const credentialAudit = await auditPublicCredentials(secretSummaries, sessions.scope,
        {requester, budget: Math.min(4, Math.max(0, availableWebTasks - keyAudit.tested)), log: say});
      const webBudget = Math.max(0, availableWebTasks - keyAudit.tested - credentialAudit.tested);
      const activeHosts = (discovery?.hosts ?? []).filter(host => host.origin && !host.alias &&
        host.origin !== sessions.scope.target.origin && !sessions.scope.credentialOrigins.includes(host.origin) &&
        sessions.scope.discovery.auditDomains.some(domain =>
          host.host === domain || host.host.endsWith(`.${domain}`))).length;
      const remainingWebModelCalls = () => Math.max(0, scope.limits.modelCalls - modelInvocations - 2);
      const webModelShare = origins => model ?
        Math.floor(remainingWebModelCalls() / Math.max(1, origins)) : 0;
      // A confirmed login may reveal routes unavailable to anonymous recon.
      // A finite task pool is shared between the early authenticated pass and
      // the primary pass. With tasks=0 both may queue all observed work; their
      // separate research deadlines and the shared model/rate limits still
      // bound execution.
      const unlimitedTasks = scope.limits.tasks === 0;
      const derivedPriorityBudget = model && surface.authBodyOperations?.length ?
        (unlimitedTasks ? webBudget : Math.ceil(webBudget / 8)) : 0;
      const primaryBudget = Math.ceil((unlimitedTasks ? webBudget :
        Math.max(0, webBudget - derivedPriorityBudget)) /
        (activeHosts + credentialAudits.length + 1));
      const derivedLateModelReserve = derivedPriorityBudget ?
        Math.max(1, Math.ceil(webModelShare(activeHosts + credentialAudits.length + 1) / 4)) : 0;
      const primaryModelCallsLeft = () => Math.max(0,
        scope.limits.modelCalls - modelInvocations - 1 -
        (derivedPending.length ? derivedLateModelReserve : 0));
      const resumeFlowDerived = ['http-sequence', 'http-sequence-page',
        'json-experiment', 'access-boundary'].includes(resumeResearch?.kind) &&
        (Boolean(resumeResearch.derivedLoginPath) ||
          resumeResearch.active?.currentLead?.as === 'derived');
      // Older derived flow/page checkpoints do not identify which proved
      // principal created them. Retain them as pending instead of attaching
      // their requests to the first account using the same login route.
      const unboundDerivedFlow = ['http-sequence', 'http-sequence-page']
        .includes(resumeResearch?.kind) && !resumeResearch.principalFingerprint &&
        (resumeFlowDerived || resumeResearch.leads?.some(lead => lead.as === 'derived'));
      let resumeFlowUsed = false;
      const freshCheckpointName = base => {
        let name = base;
        while (fs.existsSync(path.join(runDir, name)))
          name = base.replace(/-checkpoint\.json$/,
            `-queue-${randomBytes(6).toString('hex')}-checkpoint.json`);
        return name;
      };
      const selectedCheckpointName = (kind, pass, derivedLoginPath,
        principalFingerprint) =>
        resumeResearch?.kind === kind &&
        (resumeResearch.pass ?? 'primary') === pass &&
        (resumeResearch.derivedLoginPath ?? null) === derivedLoginPath &&
        (!resumeResearch.principalFingerprint ||
          resumeResearch.principalFingerprint === principalFingerprint) &&
        resumeResearchFile ? path.basename(resumeResearchFile) : null;
      const onFlowCheckpointFor = (pass, derivedLoginPath = null,
        principalFingerprint = null, resume = false) => {
        const names = new Map();
        let selected = resume ? selectedCheckpointName('http-sequence', pass,
          derivedLoginPath, principalFingerprint) : null;
        return state => {
          const leadIds = (state.leads ?? []).map(lead =>
            lead.proposalId ?? hash(JSON.stringify(lead))).sort();
          const pageKey = hash(JSON.stringify(leadIds)).slice(0, 12);
          let name = names.get(pageKey);
          if (!name) {
            const base = derivedLoginPath ?
              `http-sequence-derived-${hash(derivedLoginPath + pass +
                (principalFingerprint ?? '')).slice(0, 12)}-page-${pageKey}-checkpoint.json` :
              `http-sequence-page-${pageKey}-checkpoint.json`;
            name = selected ?? freshCheckpointName(base);
            selected = null;
            names.set(pageKey, name);
          }
          atomic(path.join(runDir, name), scrub({version: 1, run, scopeHash,
            origin: scope.target.origin, resumedFrom: resumeFrom, ...state,
            pass, derivedLoginPath, principalFingerprint,
            updatedAt: now()}, secrets));
        };
      };
      const onJsonCheckpointFor = (pass, derivedLoginPath = null,
        principalFingerprint = null, resume = false) => {
        const base = derivedLoginPath ?
          `json-experiment-derived-${hash(derivedLoginPath + pass +
            (principalFingerprint ?? '')).slice(0, 12)}-checkpoint.json` :
          'json-experiment-checkpoint.json';
        const name = resume ? selectedCheckpointName('json-experiment', pass,
          derivedLoginPath, principalFingerprint) : freshCheckpointName(base);
        return state => {
          if (!name) return;
          const payload = {version: 1, run, scopeHash,
            origin: scope.target.origin, pass, derivedLoginPath,
            principalFingerprint, resumedFrom: resumeFrom, updatedAt: now(),
            ...state};
          atomic(path.join(runDir, name), sanitizeJsonCheckpoint(payload, secrets));
        };
      };
      const onAccessCheckpointFor = (pass, derivedLoginPath = null,
        principalFingerprint = null, resume = false) => {
        const base = derivedLoginPath ?
          `access-boundary-derived-${hash(derivedLoginPath + pass +
            (principalFingerprint ?? '')).slice(0, 12)}-checkpoint.json` :
          'access-boundary-checkpoint.json';
        const name = resume ? selectedCheckpointName('access-boundary', pass,
          derivedLoginPath, principalFingerprint) : freshCheckpointName(base);
        return state => {
          if (!name) return;
          const payload = {version: 1, run, scopeHash,
            origin: scope.target.origin, pass, derivedLoginPath,
            principalFingerprint, resumedFrom: resumeFrom, updatedAt: now(),
            ...state};
          atomic(path.join(runDir, name), sanitizeAccessCheckpoint(payload, secrets));
        };
      };
      const flowPageFile = path.join(runDir, 'http-sequence-page-checkpoint.json');
      const onFlowPageCheckpoint = (pass, derivedLoginPath = null,
        principalFingerprint = null) => state => {
        let previous = [];
        try {previous = JSON.parse(fs.readFileSync(flowPageFile, 'utf8')).pages ?? [];}
        catch { /* The first page has no earlier checkpoint. */ }
        const samePass = item => item.pass === pass &&
          item.derivedLoginPath === derivedLoginPath &&
          (item.principalFingerprint ?? null) === principalFingerprint;
        const supersededEarly = item => pass === 'derived-late' &&
          item.pass === 'derived-early' && item.derivedLoginPath === derivedLoginPath &&
          (item.principalFingerprint ?? null) === principalFingerprint;
        const pages = previous.filter(item => !samePass(item) && !supersededEarly(item));
        pages.push({pass, derivedLoginPath, principalFingerprint, ...state,
          updatedAt: now()});
        atomic(flowPageFile, scrub({version: 1, run, scopeHash,
          origin: scope.target.origin, pages}, secrets));
      };
      let derivedEarlyTested = 0;
      const resumedLeadKeys = new Set();
      const resumedLeadKey = (state, lead) => {
        const request = {...lead};
        for (const name of ['proposalId', 'why', 'basis', 'family', 'priority'])
          delete request[name];
        return hash(JSON.stringify([state.kind, state.derivedLoginPath ?? null,
          state.principalFingerprint ?? null, request]));
      };
      const runAcceptedQueues = async ({pass, loginPath = null,
        principalFingerprint = null, currentSurface, currentScope,
        currentRequester, derivedSession = null, budget,
        modelCallsLeft, sessionIndex = null,
        queueDeadline = researchDeadline}) => {
        let used = 0;
        const stalled = new Set();
        const matches = queue => {
          const state = queue.state;
          if ((state.pass ?? 'primary') !== pass) return false;
          if (pass === 'primary') return !state.derivedLoginPath;
          // A login route is not a principal. Retain older unbound queues
          // rather than replaying their requests under another account.
          return state.derivedLoginPath === loginPath &&
            Boolean(state.principalFingerprint) &&
            state.principalFingerprint === principalFingerprint;
        };
        const queues = resumeAcceptedQueues.filter(matches);
        const width = Math.max(1, Math.floor(currentScope.limits.modelConcurrency ?? 1));
        const activeFiles = new Set(), activeKeys = new Set();
        const waiters = [];
        let scanAt = 0, callsReserved = 0, failure = null;
        const wake = () => {
          for (const resolve of waiters.splice(0)) resolve();
        };
        const takeNext = () => {
          while (Date.now() < queueDeadline) {
            let coalesced = false;
            for (let offset = 0; offset < queues.length; offset++) {
              const index = (scanAt + offset) % queues.length;
              const queue = queues[index];
              if (queue.state.cursor >= queue.state.leads.length ||
                  stalled.has(queue.file) || activeFiles.has(queue.file)) continue;
              const initial = queue.state.leads[queue.state.cursor];
              const key = resumedLeadKey(queue.state, initial);
              if (resumedLeadKeys.has(key)) {
                const copied = {...queue.state, cursor: queue.state.cursor + 1,
                  active: null, updatedAt: now()};
                const saved = copied.kind === 'json-experiment' ?
                  sanitizeJsonCheckpoint(copied, secrets) :
                  copied.kind === 'access-boundary' ?
                    sanitizeAccessCheckpoint(copied, secrets) : scrub(copied, secrets);
                atomic(queue.file, saved);
                queue.state = saved;
                ledger.append({step: 'investigation', kind: 'resumed-duplicate-coalesced',
                  queue: path.basename(queue.file)});
                scanAt = (index + 1) % queues.length;
                coalesced = true;
                break;
              }
              // A duplicate waits for the in-flight copy's evidence before
              // it can be coalesced or independently replayed.
              if (activeKeys.has(key) || used + activeFiles.size >= budget)
                continue;
              const pending = queues.filter(item => item.state.cursor <
                item.state.leads.length && !stalled.has(item.file)).length;
              const maxModelPages = Math.ceil(Math.max(0,
                modelCallsLeft() - callsReserved) / Math.max(1, pending));
              callsReserved += maxModelPages;
              activeFiles.add(queue.file);
              activeKeys.add(key);
              scanAt = (index + 1) % queues.length;
              return {queue, key, before: queue.state.cursor, maxModelPages};
            }
            if (!coalesced) return null;
          }
          return null;
        };
        const runOne = async ({queue, key, before, maxModelPages}) => {
          try {
            const checked = await runWebProbes(currentSurface, currentScope, {
              requester: currentRequester, ledger, budget: 1,
              env: sessions.env, infer: model ? invokeModel : null, model,
              derivedSession, resumeOnly: true,
              resumeResearch: queue.state,
              onResumeCheckpoint: state => {
                const copied = {...queue.state, ...state, run, scopeHash,
                  origin: scope.target.origin, updatedAt: now()};
                const saved = copied.kind === 'json-experiment' ?
                  sanitizeJsonCheckpoint(copied, secrets) :
                  copied.kind === 'access-boundary' ?
                    sanitizeAccessCheckpoint(copied, secrets) : scrub(copied, secrets);
                atomic(queue.file, saved);
                queue.state = saved;
              },
              maxModelPages,
              remainingModelCalls: modelCallsLeft,
              researchDeadline: queueDeadline, log: say});
            if (checked.results.length || checked.findings.length) {
              checked.discoveredVia = 'resumed-research';
              if (sessionIndex != null) checked.sessionIndex = sessionIndex;
              resumedWeb.push(checked);
            }
            used += executedWebTasks(checked);
            if (queue.state.cursor > before &&
                checked.results.some(item => item.evidence?.length))
              resumedLeadKeys.add(key);
            if (queue.state.cursor <= before) stalled.add(queue.file);
          } catch (error) {
            stalled.add(queue.file);
            failure ??= error;
          } finally {
            callsReserved -= maxModelPages;
            activeFiles.delete(queue.file);
            activeKeys.delete(key);
            wake();
          }
        };
        const worker = async () => {
          while (!failure && Date.now() < queueDeadline) {
            const next = takeNext();
            if (next) {await runOne(next); continue;}
            if (!activeFiles.size) break;
            await new Promise(resolve => waiters.push(resolve));
          }
        };
        // A freed slot starts the next ready file immediately. Workers still
        // finish in-flight requests before an error can close the ledger.
        await Promise.all(Array.from({length: Math.min(width, queues.length)}, worker));
        if (failure) throw failure;
        return used;
      };
      const captureProvedAccess = item => provedAccessQueue.push(item);
      if (!focus) Object.defineProperty(surface, 'onConfirmedAccess',
        {value: captureProvedAccess, configurable: true});
      const onConfirmedSession = async ({lead, loginProof, principalFingerprint,
        requestAuthenticated, derivedBearer, derivedCookie}) => {
        const derivedCookieName = derivedCookie?.split('=', 1)[0] ?? null;
        const contractKey = `${lead.loginPath}\n${lead.userField}\n${lead.passwordField}`;
        const seenPrincipals = derivedSessionKeys.get(contractKey);
        const fingerprint = typeof principalFingerprint === 'string' &&
          /^[0-9a-f]{64}$/.test(principalFingerprint) ? principalFingerprint :
          // A protected-status proof has no readable principal ID. Its
          // independently proved login recipe still identifies the same
          // synthetic session across restart without persisting a token.
          hash(JSON.stringify(['proved-login-recipe', lead.loginPath,
            lead.userField, lead.passwordField, loginProof.proofMode,
            loginProof.userPayloads, lead.privatePath]));
        if (seenPrincipals && (!fingerprint || seenPrincipals.has(fingerprint) ||
            seenPrincipals.has('unknown'))) {
          if (fingerprint && seenPrincipals.has('unknown')) {
            seenPrincipals.delete('unknown');
            seenPrincipals.add(fingerprint);
          }
          derivedSessionsReused++;
          say({stage: 'derived-recon', message:
            'Previously mapped login session; reusing its protected-route coverage.'});
          return;
        }
        try {
          const mapped = await reconDerivedSession(sessions.scope, {
            requestAuthenticated,
            observedRoutes: [lead.privatePath,
              ...(surface.patterns ?? []).map(record => ({
                path: record.representative ?? record.pattern,
                method: record.methods?.includes('GET') ? 'GET' : 'UNKNOWN',
                params: Object.keys(record.params ?? {})})),
              ...(mined.endpoints ?? []).map(item => ({path: item.path,
                method: item.method, params: item.params, headers: item.headers,
                bodyEncoding: item.bodyEncoding, bodyFields: item.bodyFields,
                bodyStringFields: item.bodyStringFields,
                contentType: item.contentType, rootElement: item.rootElement}))],
            infer: model ? invokeModel : null, model,
            maxRequests: sessions.scope.limits.maxUrls,
            remainingModelCalls: () => Math.max(0, scope.limits.modelCalls - modelInvocations - 1),
            deadline,
          });
          say({stage: 'derived-recon', message:
            `Authenticated recon: ${mapped.coverage.requested} requests · ` +
            `${mapped.routes.length} GET responses · ${mapped.assets.length} assets` +
            (mapped.coverage.budgetCut ?
              ` · ${mapped.coverage.budgetCut} queued URLs unvisited (` +
              (mapped.coverage.cutReason === 'url-count-cap' ?
                `URL cap ${sessions.scope.limits.maxUrls}` : mapped.coverage.cutReason) + ')' : '')});
          // The newly proved session may use a different placement from
          // operator-supplied identities. Keep that placement in this protected
          // pass only; the primary scope and its operator credentials stay as is.
          let sessionScope = sessions.scope;
          let sessionRequester = requester;
          let sessionAuthenticated = requestAuthenticated;
          const useSessionScope = nextScope => {
            sessionScope = nextScope;
            sessionRequester = createRequester(sessionScope, {ledger,
              limiter: auditLimiter, env: sessions.env, allowLocal, log: say,
              run, signal, deadline});
            derivedScopedRequesters.push(sessionRequester);
            sessionAuthenticated = ({url, method = 'GET', body, maxBytes,
              headers = {}, step = 'control', purpose = 'task', auditCallback = null}) =>
              sessionRequester({url, identity: 'anonymous', method, body, step,
                task: 'derived-session-recon', agent: 'derived-session-authenticated',
                purpose, noCache: true, omitExcerpt: true, maxBytes, headers,
                auditCallback,
                ...(derivedCookie ? {derivedCookie} : {derivedBearer})});
          };
          if (derivedCookie && sessionScope.identities.auth !== 'cookie') {
            const cookieScope = structuredClone(sessionScope);
            cookieScope.identities.auth = 'cookie';
            for (const identity of ['owner', 'outsider'])
              cookieScope.identities[identity].env =
                `BX_DERIVED_COOKIE_${identity.toUpperCase()}_${randomBytes(6).toString('hex')}`;
            useSessionScope(cookieScope);
          }
          // Local targets can admit exact method contracts discovered after login.
          // The expanded scope and session credential remain in memory.
          if (sessions.scope.target.environment === 'local' &&
              (derivedBearer || derivedCookie) && mapped.contracts.length) {
            const admitted = await deriveLocalPostScope(sessionScope,
              {endpoints: mapped.contracts}, requester);
            if (admitted.scope !== sessionScope) useSessionScope(admitted.scope);
            mapped.coverage.methodContractsAdmitted = admitted.admitted.length +
              admitted.methodAdmitted.length;
            mapped.coverage.methodContractsSkipped = admitted.skipped.length;
          }
          const nextSurface = derivedAnonymousSurface(mapped, surface);
          Object.defineProperty(nextSurface, 'onConfirmedAccess',
            {value: captureProvedAccess});
          mapped.coverage.anonymousRoutesAvailable = nextSurface.patterns.length;
          mapped.coverage.anonymousChecks = 0;
          mapped.coverage.anonymousConfirmed = 0;
          mapped.coverage.anonymousCut = nextSurface.patterns.length;
          const sessionIndex = derivedSessions.length;
          derivedSessions.push(scrub({loginPath: lead.loginPath, privatePath: lead.privatePath,
            ...mapped}, secrets));
          const pending = {mapped, nextSurface, requestAuthenticated: sessionAuthenticated,
            requester: sessionRequester, scope: sessionScope, loginProof,
            loginPath: lead.loginPath, privatePath: lead.privatePath, sessionIndex,
            derivedCookieName, principalFingerprint: fingerprint,
            earlyResults: []};
          derivedPending.push(pending);
          const principals = derivedSessionKeys.get(contractKey) ?? new Set();
          principals.add(fingerprint ?? 'unknown');
          derivedSessionKeys.set(contractKey, principals);
          const firstEvidence = ledger.count() + 1;
          const resumeThisSession = resumeFlowDerived && !unboundDerivedFlow &&
            !resumeFlowUsed &&
            (!['http-sequence', 'http-sequence-page', 'json-experiment',
              'access-boundary'].includes(resumeResearch.kind) ||
              resumeResearch.pass === 'derived-early') &&
            (!resumeResearch.derivedLoginPath ||
              resumeResearch.derivedLoginPath === lead.loginPath) &&
            (!resumeResearch.principalFingerprint ||
              resumeResearch.principalFingerprint === fingerprint);
          const resumeLatePage = resumeFlowDerived && !unboundDerivedFlow &&
            ['http-sequence', 'http-sequence-page', 'json-experiment',
              'access-boundary'].includes(resumeResearch?.kind) &&
            resumeResearch.pass === 'derived-late' &&
            resumeResearch.derivedLoginPath === lead.loginPath &&
            (!resumeResearch.principalFingerprint ||
              resumeResearch.principalFingerprint === fingerprint);
          // Full authenticated mapping may finish after the original early
          // window. Give the discovered surface part of the remaining research
          // time now, leaving the rest for primary and later protected work.
          const earlyResearchDeadline = protectedPlanningDeadline(
            Date.now(), protectedEarlyDeadline, researchDeadline);
          const resumedEarly = await runAcceptedQueues({pass: 'derived-early',
            loginPath: lead.loginPath, principalFingerprint: fingerprint,
            currentSurface: nextSurface, currentScope: sessionScope,
            currentRequester: request => sessionRequester({...request,
              omitExcerpt: true}),
            derivedSession: {requestAuthenticated: sessionAuthenticated,
              loginProof,
              ...(derivedCookieName ? {cookieName: derivedCookieName} : {})},
            budget: Math.max(0, webBudget - derivedEarlyTested),
            modelCallsLeft: remainingWebModelCalls,
            sessionIndex, queueDeadline: earlyResearchDeadline});
          derivedEarlyTested += resumedEarly;
          mapped.coverage.earlyResumedChecks = resumedEarly;
          if ((nextSurface.patterns.length || nextSurface.methodOperations?.length ||
              nextSurface.jsonBodyOperations?.length || nextSurface.formBodyOperations?.length) &&
              (derivedEarlyTested < derivedPriorityBudget || resumeThisSession) &&
              !resumeLatePage &&
              Date.now() < earlyResearchDeadline) try {
            const early = await runWebProbes(nextSurface, sessionScope, {
              requester: request => sessionRequester({...request, omitExcerpt: true}),
              ledger, budget: Math.max(0, derivedPriorityBudget - derivedEarlyTested,
                resumeThisSession && webBudget > derivedEarlyTested ? 1 : 0),
              onProgressCheckpoint: onWebProgress(`derived-${sessionIndex}-early`),
              ...(resumeThisSession ? {resumeResearch} : {}),
              onJsonCheckpoint: onJsonCheckpointFor('derived-early', lead.loginPath,
                fingerprint),
              onAccessCheckpoint: onAccessCheckpointFor('derived-early', lead.loginPath,
                fingerprint),
              onJsonResumeCheckpoint: onJsonCheckpointFor('derived-early',
                lead.loginPath, fingerprint, true),
              onAccessResumeCheckpoint: onAccessCheckpointFor('derived-early',
                lead.loginPath, fingerprint, true),
              onFlowCheckpoint: onFlowCheckpointFor('derived-early',
                lead.loginPath, fingerprint, resumeThisSession),
              onFlowPageCheckpoint: onFlowPageCheckpoint('derived-early',
                lead.loginPath, fingerprint),
              flowPagePass: 'derived-early',
              env: sessions.env, infer: model ? invokeModel : null, model,
              derivedSession: {requestAuthenticated: sessionAuthenticated, loginProof,
                ...(derivedCookieName ? {cookieName: derivedCookieName} : {})},
              deferOverflow: true,
              prioritizeWebTurn: true,
              // Leave room for a reviewed method sample and its Muse follow-up
              // when the first protected-session route page yields no plan.
              maxModelPages: Math.min(
                Math.ceil(remainingWebModelCalls() / 3), remainingWebModelCalls()),
              remainingModelCalls: () => Math.max(0,
                scope.limits.modelCalls - modelInvocations - 1),
              researchDeadline: earlyResearchDeadline, log: say});
            derivedWeb.push(early);
            if (resumeThisSession) resumeFlowUsed = true;
            pending.earlyWeb = early;
            pending.earlyResults = early.results;
            derivedEarlyTested += executedWebTasks(early);
            mapped.coverage.earlyWebChecks = resumedEarly + executedWebTasks(early);
            mapped.coverage.earlyWebUntested = early.results.filter(item =>
              item.verdict === 'untested').length;
            mapped.coverage.earlyModelCalls = early.modelCalls;
            mapped.coverage.earlyWebCut = early.cut;
            for (const finding of early.findings) finding.tags = [...new Set([
              ...(finding.tags ?? []), 'discovered-via-derived-session'])];
          } catch (error) {
            mapped.coverage.earlyWebError = 'runner-error';
            mapped.coverage.earlyWebFailure = earlyRunFailure(error, ledger, firstEvidence,
              secrets, sessions.scope.harvest.redactFields);
            derivedSessions[sessionIndex] = scrub({loginPath: lead.loginPath,
              privatePath: lead.privatePath, ...mapped}, secrets);
            say({stage: 'derived-recon', message:
              `Protected-route planning failed (${mapped.coverage.earlyWebFailure.name}); ` +
              'later anonymous follow-up remains available.'});
          }
        } catch {
          // Protected discovery is optional and cannot invalidate the independently proved login finding.
          derivedSessions.push({origin: sessions.scope.target.origin, loginPath: lead.loginPath,
            privatePath: lead.privatePath, status: 'failed', reason: 'derived-recon-error'});
          say({stage: 'derived-recon', message: 'Derived session mapping failed; the login proof remains separate.'});
        }
        atomic(path.join(runDir, 'derived-session-recon.json'), {sessions: derivedSessions});
      };
      const resumedPrimary = await runAcceptedQueues({pass: 'primary',
        currentSurface: surface, currentScope: sessions.scope,
        currentRequester: requester, budget: primaryBudget,
        modelCallsLeft: primaryModelCallsLeft});
      const primaryWeb = await runWebProbes(surface, sessions.scope, {requester, ledger,
        budget: Math.max(0, primaryBudget - resumedPrimary),
        skipLeadKeys: earlySource.keys,
        onProgressCheckpoint: onWebProgress('primary'),
        env: sessions.env,
        infer: model ? invokeModel : null, model,
        researchDeadline,
        // A short combined review can finish Muse planning at the research
        // cutoff and still run already selected checks in the proof reserve.
        ...(combinedReviewId && scope.limits.minutes <= 10 ?
          {executionDeadline: deadline - 5_000} : {}),
        researchDeadlineAfterAuth: () => derivedPending.length ?
          protectedPlanningDeadline(Date.now(), primaryAfterSessionDeadline,
            researchDeadline) : researchDeadline,
        maxModelPages: webModelShare(activeHosts + credentialAudits.length + 1),
        remainingModelCalls: primaryModelCallsLeft,
        onConfirmedSession: focus ? null : onConfirmedSession,
        onFlowPageCheckpoint: onFlowPageCheckpoint('primary'),
        flowPagePass: 'primary',
        resumeResearch: resumeFlowDerived ? null : resumeResearch,
        onFlowCheckpoint: onFlowCheckpointFor('primary', null, null,
          !resumeFlowDerived && resumeResearch?.kind === 'http-sequence'),
        onResearchCheckpoint: state => atomic(path.join(runDir, 'research-checkpoint.json'),
          scrub({version: 1, run, scopeHash, origin: scope.target.origin,
            resumedFrom: resumeFrom, ...state}, secrets)),
        onJsonCheckpoint: onJsonCheckpointFor('primary'),
        onAccessCheckpoint: onAccessCheckpointFor('primary'),
        onJsonResumeCheckpoint: onJsonCheckpointFor('primary', null, null, true),
        onAccessResumeCheckpoint: onAccessCheckpointFor('primary', null, null, true),
        priorVerifierResults: resumedWeb.flatMap(item => item.results),
        log: say});
      let remainingWebBudget = Math.max(0,
        webBudget - resumedPrimary - executedWebTasks(primaryWeb) - derivedEarlyTested);
      const seenAccessContexts = new Set();
      const drainProvedAccess = async () => {
        while (provedAccessQueue.length && remainingWebBudget > 0 &&
            Date.now() < researchDeadline) {
          const {context, finding} = provedAccessQueue.shift();
          const witness = context.requests.at(-1);
          const contextKey = hash(JSON.stringify([witness.headers,
            new URL(witness.path, scope.target.origin).search, context.setCookies]));
          if (seenAccessContexts.has(contextKey)) continue;
          seenAccessContexts.add(contextKey);
          const row = {sourceEvidence: finding.evidence,
            sourcePath: new URL(finding.pattern, scope.target.origin).pathname,
            status: 'mapping'};
          provedAccessRecon.push(row);
          try {
            const observed = [witness.path,
              ...(surface.patterns ?? []).map(item => ({path: item.representative ?? item.pattern,
                method: item.methods?.includes('GET') ? 'GET' : 'UNKNOWN',
                params: Object.keys(item.params ?? {})})),
              ...(mined.endpoints ?? []).map(item => ({path: item.path,
                method: item.method, params: item.params, headers: item.headers,
                bodyEncoding: item.bodyEncoding, bodyFields: item.bodyFields,
                bodyStringFields: item.bodyStringFields,
                contentType: item.contentType, rootElement: item.rootElement}))];
            const {mapped, nextSurface} = await reconConfirmedAccess(sessions.scope,
              {context, requester, observedRoutes: observed, publicSurface: surface,
                infer: model ? invokeModel : null, model,
                maxRequests: sessions.scope.limits.maxUrls,
                remainingModelCalls: remainingWebModelCalls, deadline: researchDeadline});
            Object.defineProperty(nextSurface, 'onConfirmedAccess',
              {value: captureProvedAccess});
            let accessScope = sessions.scope;
            let accessRequester = requester;
            if (accessScope.target.environment === 'local' && mapped.contracts.length) {
              const admitted = await deriveLocalPostScope(accessScope,
                {endpoints: mapped.contracts}, requester);
              accessScope = admitted.scope;
              if (accessScope !== sessions.scope) {
                provedAccessScopes.push(accessScope);
                accessRequester = createRequester(accessScope, {ledger,
                  limiter: auditLimiter, env: sessions.env, allowLocal, log: say,
                  run, signal, deadline});
              }
            }
            const knownPaths = new Set((surface.patterns ?? []).map(item => item.pattern));
            const knownContracts = new Set((mined.endpoints ?? []).map(item =>
              `${item.method} ${new URL(item.path, scope.target.origin).pathname}`));
            Object.assign(row, {status: 'mapped', requested: mapped.coverage.requested,
              routes: mapped.routes.length, assets: mapped.assets.length,
              contracts: mapped.contracts.length,
              externalContracts: mapped.externalContracts,
              unresolvedContracts: mapped.unresolvedContracts,
              newRoutes: nextSurface.patterns.filter(item =>
                !knownPaths.has(item.pattern)).length,
              changedRoutes: nextSurface.patterns.filter(item =>
                item.responseFacts?.hash && item.responseFacts?.anonymousHash &&
                item.responseFacts.hash !== item.responseFacts.anonymousHash).length,
              newContracts: mapped.contracts.filter(item =>
                !knownContracts.has(`${item.method} ${new URL(item.path, scope.target.origin).pathname}`)).length,
              coverage: mapped.coverage});
            provedAccessSurfaces.push(nextSurface);
            say({stage: 'derived-recon', message:
              `Proved-access recon: ${row.requested} requests · ${row.assets} assets · ` +
              `${row.newRoutes} new routes · ${row.newContracts} new contracts`});
            const checked = await runWebProbes(nextSurface, accessScope, {
              requester: accessRequester, ledger, budget: remainingWebBudget,
              env: sessions.env, infer: model ? invokeModel : null, model,
              maxModelPages: remainingWebModelCalls(),
              remainingModelCalls: remainingWebModelCalls, researchDeadline,
              onProgressCheckpoint: onWebProgress(`proved-access-${provedAccessRecon.length}`),
              log: say});
            checked.discoveredVia = 'confirmed-access';
            derivedWeb.push(checked);
            row.checksExecuted = executedWebTasks(checked);
            row.checksUntested = checked.results.filter(item =>
              item.verdict === 'untested').length;
            row.modelCalls = checked.modelCalls + mapped.coverage.modelCalls;
            remainingWebBudget = Math.max(0, remainingWebBudget - row.checksExecuted);
          } catch (error) {
            row.status = 'recon-error';
            row.error = error?.name ?? 'Error';
            say({stage: 'derived-recon', message:
              `Proved-access recon failed (${row.error}); the original proof remains valid.`});
          }
          atomic(path.join(runDir, 'confirmed-access-recon.json'),
            {contexts: provedAccessRecon, pending: provedAccessQueue.length});
        }
      };
      await drainProvedAccess();
      const derivedCheckedPaths = new Set();
      const deferredEarlyCuts = new Map();
      const supersededDeferredResults = new Map();
      for (const pending of derivedPending) {
        const {mapped, nextSurface, requestAuthenticated, requester: sessionRequester,
          scope: sessionScope, loginProof, sessionIndex, derivedCookieName} = pending;
        try {
          // Execute accepted Muse work while its research window remains open.
          // The broader anonymous JSON sweep can continue afterward using the
          // audit deadline, without starving protected sequence attempts.
          let lateCut = 0;
          const inputKey = (method, path, placement, field) =>
            JSON.stringify([method, new URL(path, sessions.scope.target.origin).pathname,
              placement, field]);
          const loginPathname = new URL(pending.loginPath,
            sessions.scope.target.origin).pathname;
          const actionableInputs = new Set([
            ...nextSurface.patterns.flatMap(route => Object.keys(route.params ?? {})
              .map(field => inputKey('GET', route.pattern, 'query', field))),
            ...['jsonBodyOperations', 'formBodyOperations', 'xmlBodyOperations',
              'methodOperations'].flatMap(property => (nextSurface[property] ?? [])
              .filter(operation => new URL(operation.path,
                sessions.scope.target.origin).pathname !== loginPathname)
              .flatMap(operation => (operation.fields ?? []).map(field =>
                inputKey(operation.method, operation.path,
                  operation.placement ?? property.replace('BodyOperations', '').toLowerCase(), field)))),
          ]);
          const earlyDerivedInputs = new Set((pending.earlyResults ?? [])
            .filter(result => result.lead?.as === 'derived' &&
              result.kind?.startsWith('model-') &&
              ['confirmed', 'observed'].includes(result.verdict) &&
              result.lead?.path && result.lead?.parameter)
            .map(result => inputKey(result.lead.method ?? 'GET', result.lead.path,
              result.lead.placement ?? 'query', result.lead.parameter)));
          const untestedDerivedInputs = [...actionableInputs]
            .filter(key => !earlyDerivedInputs.has(key)).length;
          const resumeThisSession = resumeFlowDerived && !unboundDerivedFlow &&
            !resumeFlowUsed &&
            (!['http-sequence', 'http-sequence-page', 'json-experiment',
              'access-boundary'].includes(resumeResearch.kind) ||
              resumeResearch.pass === 'derived-late') &&
            (!resumeResearch.derivedLoginPath ||
              resumeResearch.derivedLoginPath === pending.loginPath) &&
            (!resumeResearch.principalFingerprint ||
              resumeResearch.principalFingerprint === pending.principalFingerprint);
          mapped.coverage.protectedInputsAvailable = actionableInputs.size;
          mapped.coverage.protectedInputsUntestedAfterEarly = untestedDerivedInputs;
          const resumedEarlyTail = await runAcceptedQueues({pass: 'derived-early',
            loginPath: pending.loginPath,
            principalFingerprint: pending.principalFingerprint,
            currentSurface: nextSurface, currentScope: sessionScope,
            currentRequester: request => sessionRequester({...request,
              omitExcerpt: true}),
            derivedSession: {requestAuthenticated, loginProof,
              ...(derivedCookieName ? {cookieName: derivedCookieName} : {})},
            budget: remainingWebBudget,
            modelCallsLeft: remainingWebModelCalls,
            sessionIndex});
          remainingWebBudget = Math.max(0,
            remainingWebBudget - resumedEarlyTail);
          mapped.coverage.anonymousChecks += resumedEarlyTail;
          const resumedLate = await runAcceptedQueues({pass: 'derived-late',
            loginPath: pending.loginPath,
            principalFingerprint: pending.principalFingerprint,
            currentSurface: nextSurface, currentScope: sessionScope,
            currentRequester: request => sessionRequester({...request,
              omitExcerpt: true}),
            derivedSession: {requestAuthenticated, loginProof,
              ...(derivedCookieName ? {cookieName: derivedCookieName} : {})},
            budget: remainingWebBudget,
            modelCallsLeft: remainingWebModelCalls,
            sessionIndex});
          remainingWebBudget = Math.max(0, remainingWebBudget - resumedLate);
          mapped.coverage.anonymousChecks += resumedLate;
          mapped.coverage.lateResumedChecks = resumedLate;
          if ((untestedDerivedInputs || pending.earlyWeb?.deferredLeads?.length ||
              resumeThisSession) &&
              remainingWebBudget > 0 &&
              Date.now() < researchDeadline) {
            const checked = await runWebProbes(nextSurface, sessionScope, {
              // Derived credentials stay in memory while Muse reviews protected
              // route and method facts; the requester enforces the scoped contracts.
              requester: request => sessionRequester({...request, omitExcerpt: true}),
              ledger, budget: remainingWebBudget, env: sessions.env,
              onProgressCheckpoint: onWebProgress(`derived-${sessionIndex}-late`),
              onJsonCheckpoint: onJsonCheckpointFor('derived-late', pending.loginPath,
                pending.principalFingerprint),
              onAccessCheckpoint: onAccessCheckpointFor('derived-late', pending.loginPath,
                pending.principalFingerprint),
              onJsonResumeCheckpoint: onJsonCheckpointFor('derived-late',
                pending.loginPath, pending.principalFingerprint, true),
              onAccessResumeCheckpoint: onAccessCheckpointFor('derived-late',
                pending.loginPath, pending.principalFingerprint, true),
              infer: model ? invokeModel : null, model,
              ...(loginProof ? {derivedSession: {requestAuthenticated, loginProof,
                ...(derivedCookieName ? {cookieName: derivedCookieName} : {})}} : {}),
              carryForward: pending.earlyWeb?.deferredLeads ?? [],
              priorVerifierResults: pending.earlyWeb?.results ?? [],
              ...(resumeThisSession ? {resumeResearch} : {}),
              onFlowCheckpoint: onFlowCheckpointFor('derived-late',
                pending.loginPath, pending.principalFingerprint, resumeThisSession),
              onFlowPageCheckpoint: onFlowPageCheckpoint('derived-late',
                pending.loginPath, pending.principalFingerprint),
              flowPagePass: 'derived-late',
              skipLeadKeys: pending.earlyWeb?.completedLeadKeys ?? [],
              maxModelPages: remainingWebModelCalls(),
              remainingModelCalls: () => Math.max(0, scope.limits.modelCalls - modelInvocations - 1),
              researchDeadline, log: say});
            for (const finding of checked.findings) finding.tags = [...new Set([
              ...(finding.tags ?? []), 'discovered-via-derived-session'])];
            derivedWeb.push(checked);
            pending.lateWeb = checked;
            if (resumeThisSession) resumeFlowUsed = true;
            // The early pass's cut describes deferred leads. A lead seen again
            // in this pass is counted here; retain any early-only cut.
            if (pending.earlyWeb) deferredEarlyCuts.set(pending.earlyWeb,
              remainingDeferredCut(pending.earlyWeb, checked));
            if (pending.earlyWeb) supersededDeferredResults.set(pending.earlyWeb,
              new Set(checked.results.filter(item => item.verdict !== 'untested')
                .flatMap(item => [item.proposalId, item.leadKey]).filter(Boolean)));
            remainingWebBudget = Math.max(0, remainingWebBudget - executedWebTasks(checked));
            mapped.coverage.anonymousChecks += executedWebTasks(checked);
            mapped.coverage.anonymousConfirmed += checked.findings.filter(item =>
              item.verdict === 'confirmed').length;
            lateCut = checked.cut;
          }
          const access = await checkDerivedAnonymousAccess(mapped, nextSurface, sessionScope, {
            requester: request => sessionRequester({...request, omitExcerpt: true}),
            requestAuthenticated, budget: remainingWebBudget, deadline,
            seen: derivedCheckedPaths, log: say});
          derivedWeb.push(access);
          remainingWebBudget = Math.max(0, remainingWebBudget - access.tested);
          mapped.coverage.anonymousChecks += access.tested;
          mapped.coverage.anonymousConfirmed += access.findings.length;
          mapped.coverage.anonymousCut = lateCut + access.cut;
          mapped.coverage.anonymousAlreadyMeasured = access.alreadyMeasured ?? 0;
          say({stage: 'derived-recon', message:
            `Protected-session leads: ${nextSurface.patterns.length} GET routes, ` +
            `${nextSurface.methodOperations?.length ?? 0} method contracts; ` +
            `${mapped.coverage.anonymousChecks} anonymous checks; ` +
            `${mapped.coverage.anonymousConfirmed} independently proved findings.`});
        } catch {
          mapped.coverage.anonymousTestError = 'runner-error';
          mapped.coverage.anonymousCut = Math.max(0,
            nextSurface.patterns.length - (mapped.coverage.anonymousChecks ?? 0));
          say({stage: 'derived-recon', message:
            'Protected routes were mapped, but the anonymous follow-up runner failed.'});
        }
        derivedSessions[sessionIndex] = scrub({loginPath: pending.loginPath,
          privatePath: pending.privatePath, ...mapped}, secrets);
        atomic(path.join(runDir, 'derived-session-recon.json'), {sessions: derivedSessions});
      }
      // A protected test response can disclose a second route that was not
      // visible when the login session was first mapped. Reopen only that
      // session's scoped GET inventory, keeping its bearer in memory.
      const derivedFeedbackCoverage = {sessions: 0, hintsAvailable: 0,
        routesChecked: 0, routesAdded: 0, checksExecuted: 0,
        modelCalls: 0, hintsUntested: 0};
      for (const pending of derivedPending) {
        const known = new Set((pending.nextSurface.patterns ?? []).map(item => item.pattern));
        const seen = new Set(known);
        const hints = [...(pending.earlyWeb?.derivedResponsePathHints ?? []),
          ...(pending.lateWeb?.derivedResponsePathHints ?? [])];
        let queued = [...new Map(hints.filter(item => !seen.has(item.path))
          .map(item => [item.path, item])).values()];
        if (!queued.length) continue;
        derivedFeedbackCoverage.sessions++;
        const sessionCoverage = {sessionIndex: pending.sessionIndex,
          principalFingerprint: pending.principalFingerprint,
          hintsAvailable: queued.length, routesChecked: 0,
          routesAdded: 0, checksExecuted: 0, modelCalls: 0, hintsUntested: 0};
        derivedFeedbackCoverage.hintsAvailable += queued.length;
        while (model && queued.length && remainingWebBudget > 0 &&
            remainingWebModelCalls() > 0 && Date.now() < researchDeadline) {
          const pageSeen = new Set();
          const seeds = queued.filter(item => !seen.has(item.path) &&
            !pageSeen.has(item.path) && pageSeen.add(item.path))
            .map(item => ({pattern: item.path, methods: ['GET'],
              source: ['derived-test-response'], params: {}, label: {kind: 'unknown'},
              responseHintEvidence: item.evidenceId}));
          queued = [];
          if (!seeds.length) break;
          for (const item of seeds) seen.add(item.pattern);
          const followup = await followupResponseHints(scope.target.origin,
            pending.scope, seeds, {requester: request =>
              pending.requestAuthenticated({...request, omitExcerpt: true}),
            infer: invokeModel, model,
            maxModelPages: Math.min(remainingWebModelCalls(),
              Math.ceil(seeds.length / 6)), deadline: researchDeadline,
            kind: 'derived-test-feedback', responseIdentity: 'derived-session', log: say});
          sessionCoverage.routesChecked += followup.coverage.routesReviewed;
          sessionCoverage.modelCalls += followup.modelCalls;
          modelError ??= followup.modelError;
          mergeResponsePatterns(seeds, followup.patterns);
          const fresh = seeds.filter(item => !known.has(item.pattern));
          if (!fresh.length) continue;
          for (const record of fresh) {
            try {
              const anonymous = await pending.requester({url: record.pattern,
                identity: 'anonymous', method: 'GET', step: 'control',
                purpose: 'task', noCache: true, omitExcerpt: true});
              record.responseFacts ??= {};
              record.responseFacts.anonymousStatus = anonymous.status ?? null;
            } catch { /* Missing anonymous control stays unknown to Muse. */ }
          }
          mergeResponsePatterns(pending.nextSurface.patterns, fresh);
          for (const record of fresh) known.add(record.pattern);
          sessionCoverage.routesAdded += fresh.length;
          const checked = await runWebProbes({origin: scope.target.origin,
            identity: pending.nextSurface.identity, patterns: fresh,
            modelNotes: fresh.map(record => ({path: record.pattern,
              method: 'GET', purpose: 'Discovered in a protected test response; ' +
                'the authenticated and anonymous statuses require fresh verification.'}))},
          pending.scope, {requester: request =>
            pending.requester({...request, omitExcerpt: true}),
            ledger, budget: remainingWebBudget, env: sessions.env,
            infer: remainingWebModelCalls() > 0 ? invokeModel : null,
            model: remainingWebModelCalls() > 0 ? model : null,
            derivedSession: {requestAuthenticated: pending.requestAuthenticated,
              loginProof: pending.loginProof,
              ...(pending.derivedCookieName ?
                {cookieName: pending.derivedCookieName} : {})},
            researchDeadline, maxModelPages: remainingWebModelCalls(),
            remainingModelCalls: remainingWebModelCalls,
            onProgressCheckpoint: onWebProgress('derived-test-response'), log: say});
          checked.discoveredVia = 'derived-test-response';
          checked.sessionIndex = pending.sessionIndex;
          for (const finding of checked.findings) finding.tags = [...new Set([
            ...(finding.tags ?? []), 'discovered-via-derived-session',
            'discovered-via-test-response'])];
          derivedWeb.push(checked);
          remainingWebBudget = Math.max(0, remainingWebBudget - executedWebTasks(checked));
          sessionCoverage.checksExecuted += executedWebTasks(checked);
          sessionCoverage.modelCalls += checked.modelCalls;
          queued.push(...(checked.derivedResponsePathHints ?? []).filter(item =>
            !seen.has(item.path)));
        }
        sessionCoverage.hintsUntested = new Set(queued.filter(item =>
          !seen.has(item.path)).map(item => item.path)).size;
        if (sessionCoverage.hintsUntested) sessionCoverage.stopReason =
          !model ? 'model-unavailable' : remainingWebBudget < 1 ? 'task-budget' :
            remainingWebModelCalls() < 1 ? 'model-budget' :
              Date.now() >= researchDeadline ? 'research-deadline' : 'no-novel-path';
        Object.assign(derivedFeedbackCoverage, {
          routesChecked: derivedFeedbackCoverage.routesChecked + sessionCoverage.routesChecked,
          routesAdded: derivedFeedbackCoverage.routesAdded + sessionCoverage.routesAdded,
          checksExecuted: derivedFeedbackCoverage.checksExecuted + sessionCoverage.checksExecuted,
          modelCalls: derivedFeedbackCoverage.modelCalls + sessionCoverage.modelCalls,
          hintsUntested: derivedFeedbackCoverage.hintsUntested + sessionCoverage.hintsUntested});
        pending.mapped.coverage.testResponseFollowup = sessionCoverage;
        derivedSessions[pending.sessionIndex] = scrub({loginPath: pending.loginPath,
          privatePath: pending.privatePath, ...pending.mapped}, secrets);
      }
      if (derivedFeedbackCoverage.sessions) {
        surface.derivedTestResponseFollowup = derivedFeedbackCoverage;
        atomic(path.join(runDir, 'derived-session-recon.json'), {sessions: derivedSessions});
      }
      const credentialWeb = [];
      for (const [index, audit] of credentialAudits.entries()) {
        const share = Math.ceil(remainingWebBudget / (credentialAudits.length - index + activeHosts));
        const checked = await runWebProbes(audit.surface, audit.scope, {requester: audit.requester,
          ledger, budget: share, env: audit.env, infer: model ? invokeModel : null, model,
          onProgressCheckpoint: onWebProgress(`credential-${index + 1}`),
          researchDeadline,
          maxModelPages: webModelShare(credentialAudits.length - index + activeHosts),
          remainingModelCalls: () => Math.max(0, scope.limits.modelCalls - modelInvocations - 1), log: say});
        audit.web = checked;
        remainingWebBudget -= executedWebTasks(checked);
        credentialWeb.push(checked);
        const host = discovery?.hosts?.find(item => item.origin === audit.origin);
        if (host) host.audit = {status: 'credential-origin', leads: audit.surface.patterns.length,
          tested: checked.tested, cut: checked.cut,
          confirmed: checked.findings.filter(item => item.verdict === 'confirmed').length};
      }
      const descendantFeedbackCheckpointFile = path.join(runDir,
        'descendant-test-feedback-checkpoint.json');
      const checkpointDescendantFeedback = pending => {
        const safe = [...new Map(pending.filter(item =>
          authorizedDescendantFeedback(sessions.scope, item) &&
          !secrets.some(secret => item.path.includes(secret)))
          .map(({origin, path}) => [`${origin}\0${path}`, {origin, path}])).values()];
        atomic(descendantFeedbackCheckpointFile, {version: 1,
          kind: 'descendant-test-feedback', run, scopeHash,
          origin: scope.target.origin, resumedFrom: resumeFrom, pending: safe});
      };
      checkpointDescendantFeedback(resumeDescendantFeedback);
      const descendantWeb = await auditDiscoveredHosts(discovery, sessions.scope, {requester, ledger,
        budget: remainingWebBudget, infer: model ? invokeModel : null, model,
        researchDeadline,
        remainingModelCalls: remainingWebModelCalls, log: say,
        resumeHints: resumeDescendantFeedback,
        onFeedbackCheckpoint: checkpointDescendantFeedback});
      await drainProvedAccess();
      derivedWeb.push(...resumedWeb);
      const derivedResultRows = derivedWeb.flatMap(run =>
        reconciledPassResults(run, supersededDeferredResults.get(run))
        .map(item => ({...item, origin: sessions.scope.target.origin,
          discoveredVia: run.discoveredVia ?? 'derived-session',
          ...(run.sessionIndex != null ? {sessionIndex: run.sessionIndex} : {})})));
      web = {descendantFeedbackPending: descendantWeb.responsePathHints.map(({origin, path}) =>
          ({origin, path})),
        findings: [...earlySource.findings, ...keyAudit.findings, ...credentialAudit.findings, ...primaryWeb.findings,
          ...derivedWeb.flatMap(item => item.findings),
          ...credentialWeb.flatMap(item => item.findings), ...descendantWeb.findings],
        results: [...earlySource.results.map(item => ({...item, origin: sessions.scope.target.origin})),
          ...keyAudit.results, ...credentialAudit.results,
          ...primaryWeb.results.map(item => ({...item, origin: sessions.scope.target.origin})),
          ...derivedResultRows,
          ...credentialWeb.flatMap((item, index) => item.results.map(result =>
            ({...result, origin: credentialAudits[index].origin}))), ...descendantWeb.results],
        cut: keyAudit.cut + credentialAudit.cut + primaryWeb.cut +
          derivedWeb.reduce((count, item) => count +
            (deferredEarlyCuts.get(item) ?? item.cut), 0) +
          credentialWeb.reduce((count, item) => count + item.cut, 0) + descendantWeb.cut,
        tested: earlySource.tested + keyAudit.tested + credentialAudit.tested + primaryWeb.tested +
          derivedResultRows.length + credentialWeb.reduce((count, item) => count + item.tested, 0) +
          descendantWeb.tested,
        plan: [...earlySource.plan.map(item => ({...item, origin: sessions.scope.target.origin})),
          ...keyAudit.plan, ...credentialAudit.plan,
          ...primaryWeb.plan.map(item => ({...item, origin: sessions.scope.target.origin})),
          ...derivedWeb.flatMap(run => run.plan.map(item => ({...item,
            origin: sessions.scope.target.origin,
            discoveredVia: run.discoveredVia ?? 'derived-session',
            ...(run.sessionIndex != null ? {sessionIndex: run.sessionIndex} : {})}))),
          ...credentialWeb.flatMap((item, index) => item.plan.map(lead =>
            ({...lead, origin: credentialAudits[index].origin}))), ...descendantWeb.plan],
        strategyDecisions: [...primaryWeb.strategyDecisions.map(item =>
          ({...item, origin: sessions.scope.target.origin})),
          ...derivedWeb.flatMap(run => run.strategyDecisions.map(item => ({...item,
            origin: sessions.scope.target.origin,
            discoveredVia: run.discoveredVia ?? 'derived-session',
            ...(run.sessionIndex != null ? {sessionIndex: run.sessionIndex} : {})}))),
          ...credentialWeb.flatMap((item, index) => item.strategyDecisions.map(decision =>
            ({...decision, origin: credentialAudits[index].origin}))),
          ...descendantWeb.strategyDecisions],
        investigations: [...(primaryWeb.investigations ?? []).map(item =>
          ({...item, origin: sessions.scope.target.origin})),
          ...derivedWeb.flatMap(run => (run.investigations ?? []).map(item => ({...item,
            origin: sessions.scope.target.origin,
            discoveredVia: run.discoveredVia ?? 'derived-session',
            ...(run.sessionIndex != null ? {sessionIndex: run.sessionIndex} : {})}))),
          ...credentialWeb.flatMap((item, index) => (item.investigations ?? []).map(investigation =>
            ({...investigation, origin: credentialAudits[index].origin}))),
          ...(descendantWeb.investigations ?? [])],
        modelCalls: primaryWeb.modelCalls + derivedWeb.reduce((count, item) => count + item.modelCalls, 0) +
          derivedFeedbackCoverage.modelCalls +
          credentialWeb.reduce((count, item) => count + item.modelCalls, 0) + descendantWeb.modelCalls,
        modelError: primaryWeb.modelError ?? derivedWeb.find(item => item.modelError)?.modelError ??
          credentialWeb.find(item => item.modelError)?.modelError ?? descendantWeb.modelError,
        modelCoverage: [{origin: sessions.scope.target.origin, ...primaryWeb.modelCoverage},
          ...derivedWeb.map(item => ({origin: sessions.scope.target.origin,
            discoveredVia: item.discoveredVia ?? 'derived-session',
            ...(item.sessionIndex != null ? {sessionIndex: item.sessionIndex} : {}),
            ...item.modelCoverage})),
          ...credentialWeb.map((item, index) => ({origin: credentialAudits[index].origin, ...item.modelCoverage})),
          ...descendantWeb.modelCoverage]};
      // A test response may reveal a route that initial recon could not see.
      // Feed only scoped, anonymous JSON route hints into the existing guarded
      // response-followup and web runner after protected and host work has had
      // its turn. Global task, model and time budgets stop this loop naturally.
      const feedbackSeen = new Set((surface.patterns ?? []).map(item => item.pattern));
      const feedbackCheckpointFile = path.join(runDir, 'test-feedback-checkpoint.json');
      const checkpointFeedback = pending => {
        const paths = [...new Set(pending.map(item => typeof item === 'string' ? item :
          item?.path ?? item?.pattern)
          .filter(value => typeof value === 'string' &&
            !secrets.some(secret => value.includes(secret)) &&
            validateUrl(sessions.scope, value,
              {identity: 'anonymous', method: 'GET'}).ok))];
        atomic(feedbackCheckpointFile, {version: 1, kind: 'test-feedback', run,
          scopeHash, origin: scope.target.origin, resumedFrom: resumeFrom,
          updatedAt: now(), pending: paths});
      };
      let feedbackPending = focus ? [] : [...resumeFeedback.map(path => ({path, evidenceId: null})),
        ...[primaryWeb, ...derivedWeb].flatMap(item => item.responsePathHints ?? [])]
        .filter(item => !feedbackSeen.has(item.path));
      checkpointFeedback(feedbackPending);
      let feedbackTasksLeft = Math.max(0, remainingWebBudget - descendantWeb.tested);
      const feedbackCoverage = {hintsAvailable: new Set(feedbackPending.map(item => item.path)).size,
        routesChecked: 0, routesAdded: 0, checksExecuted: 0, modelCalls: 0,
        hintsUntested: 0};
      while (model && feedbackPending.length && feedbackTasksLeft > 0 &&
          remainingWebModelCalls() > 0 && Date.now() < researchDeadline) {
        const pageSeen = new Set();
        const seeds = feedbackPending.filter(item => !feedbackSeen.has(item.path) &&
          !pageSeen.has(item.path) && pageSeen.add(item.path))
          .map(item => ({pattern: item.path, methods: ['GET'],
            source: ['test-response'], params: {}, label: {kind: 'unknown'},
            responseHintEvidence: item.evidenceId}));
        feedbackPending = [];
        if (!seeds.length) {checkpointFeedback([]); break;}
        for (const item of seeds) feedbackSeen.add(item.pattern);
        checkpointFeedback(seeds);
        const followup = await followupResponseHints(scope.target.origin, sessions.scope,
          seeds, {requester, infer: invokeModel, model,
            maxModelPages: Math.min(remainingWebModelCalls(),
              Math.ceil(seeds.length / 6)), kind: 'test-feedback', log: say});
        feedbackCoverage.routesChecked += followup.coverage.routesReviewed;
        feedbackCoverage.modelCalls += followup.modelCalls;
        modelError ??= followup.modelError;
        mergeResponsePatterns(seeds, followup.patterns);
        const fresh = seeds.filter(item => !(surface.patterns ?? [])
          .some(known => known.pattern === item.pattern));
        if (!fresh.length) {checkpointFeedback(feedbackPending); continue;}
        mergeResponsePatterns(surface.patterns, fresh);
        feedbackCoverage.routesAdded += fresh.length;
        const checked = await runWebProbes({origin: scope.target.origin,
          identity: surface.identity, patterns: fresh}, sessions.scope,
        {requester, ledger, budget: feedbackTasksLeft, env: sessions.env,
          infer: remainingWebModelCalls() > 0 ? invokeModel : null,
          model: remainingWebModelCalls() > 0 ? model : null, researchDeadline,
          maxModelPages: remainingWebModelCalls(),
          remainingModelCalls: remainingWebModelCalls,
          onProgressCheckpoint: onWebProgress('test-response'), log: say});
        feedbackTasksLeft = Math.max(0, feedbackTasksLeft - executedWebTasks(checked));
        feedbackCoverage.checksExecuted += executedWebTasks(checked);
        feedbackCoverage.modelCalls += checked.modelCalls;
        feedbackPending.push(...(checked.responsePathHints ?? []));
        checkpointFeedback(feedbackPending.filter(item => !feedbackSeen.has(item.path)));
        web.findings.push(...checked.findings);
        web.results.push(...checked.results.map(item => ({...item,
          origin: sessions.scope.target.origin, discoveredVia: 'test-response'})));
        web.cut += checked.cut;
        web.tested += checked.tested;
        web.plan.push(...checked.plan.map(item => ({...item,
          origin: sessions.scope.target.origin, discoveredVia: 'test-response'})));
        web.strategyDecisions.push(...checked.strategyDecisions.map(item => ({...item,
          origin: sessions.scope.target.origin, discoveredVia: 'test-response'})));
        web.investigations.push(...checked.investigations.map(item => ({...item,
          origin: sessions.scope.target.origin, discoveredVia: 'test-response'})));
        web.modelCalls += followup.modelCalls + checked.modelCalls;
        web.modelError ??= followup.modelError ?? checked.modelError;
        web.modelCoverage.push({origin: sessions.scope.target.origin,
          discoveredVia: 'test-response', ...checked.modelCoverage});
      }
      feedbackCoverage.hintsUntested = new Set(feedbackPending.filter(item =>
        !feedbackSeen.has(item.path)).map(item => item.path)).size;
      checkpointFeedback(feedbackPending.filter(item => !feedbackSeen.has(item.path)));
      if (feedbackCoverage.hintsUntested) feedbackCoverage.stopReason =
        !model ? 'model-unavailable' : feedbackTasksLeft < 1 ? 'task-budget' :
          remainingWebModelCalls() < 1 ? 'model-budget' :
            Date.now() >= researchDeadline ? 'research-deadline' : 'no-novel-path';
      surface.testResponseFollowup = feedbackCoverage;
      if (credentialAudits.length) atomic(path.join(runDir, 'credential-origins.json'), credentialAudits.map(audit =>
        ({origin: audit.origin, mined: audit.mined, surface: audit.surface, plan: audit.plan,
          results: audit.results, web: audit.web, recheck: audit.recheck, usable: audit.usable,
          stats: audit.stats, modelError: audit.modelError})));
      if (discovery) atomic(path.join(runDir, 'discovery.json'), discovery);
      modelError = modelError ?? web.modelError;
      stats.tasks += web.tested;
      stats.webWorkersConfigured = sessions.scope.limits.agents;
      stats.webWorkersPeak = Math.max(0, ...(web.modelCoverage ?? [])
        .map(item => item.webWorkersPeak ?? 0));
      stats.agents = Math.max(stats.agents ?? 0, stats.webWorkersPeak);
      stats.queuedUntested = (stats.queuedUntested ?? 0) +
        web.results.filter(item => item.verdict === 'untested').length;
      stats.beyondBudget = (stats.beyondBudget ?? 0) + web.cut + plan.untested.length;
      const webVerdictCounts = () => ({
        confirmed: web.results.filter(item =>
          item.verdict === 'confirmed' && !RESEARCH_KINDS.has(item.kind)).length,
        observed: web.results.filter(item =>
          RESEARCH_KINDS.has(item.kind) && ['confirmed', 'observed'].includes(item.verdict)).length,
        inconclusive: web.results.filter(item => item.verdict === 'inconclusive').length,
        blocked: web.results.filter(item => item.verdict === 'blocked').length,
        notReproduced: web.results.filter(item => item.verdict === 'not_reproduced').length,
      });
      const countedWebVerdicts = webVerdictCounts();
      stats.confirmed = (stats.confirmed ?? 0) + web.results.filter(item =>
        item.verdict === 'confirmed' && !RESEARCH_KINDS.has(item.kind)).length;
      stats.observed = (stats.observed ?? 0) + web.results.filter(item =>
        RESEARCH_KINDS.has(item.kind) && ['confirmed', 'observed'].includes(item.verdict)).length;
      stats.inconclusive = (stats.inconclusive ?? 0) + web.results.filter(item => item.verdict === 'inconclusive').length;
      stats.blocked = (stats.blocked ?? 0) + web.results.filter(item => item.verdict === 'blocked').length;
      stats.notReproduced = (stats.notReproduced ?? 0) + web.results.filter(item => item.verdict === 'not_reproduced').length;
      const originSurfaces = Object.fromEntries(credentialAudits.map(audit => [audit.origin, audit.surface]));
      findings = buildFindings(results, {surface, scope: sessions.scope, originSurfaces,
        severityFor, classify, dataClasses, webFindings: web.findings});
      if (ownerReady && !credentialsReady) for (const finding of findings.filter(item =>
        item.kind === 'missing-auth' && new URL(item.url).origin === sessions.scope.target.origin)) {
        finding.tags = [...new Set([...finding.tags, 'single-account'])];
      }
      for (const audit of credentialAudits.filter(item => !item.usable))
        for (const finding of findings.filter(item => item.kind === 'missing-auth' &&
          new URL(item.url).origin === audit.origin))
          finding.tags = [...new Set([...finding.tags, 'single-account'])];
      log({stage: 'progress', type: 'task-reconcile', total: stats.tasks,
        done: stats.tasks - (stats.queuedUntested ?? 0),
        untested: stats.queuedUntested ?? 0});
      phase('done', 4, 'Plan and test observed leads');
      phase('doing', 5, 'Replay and assess');
      const proofSurface = derivedPending.length || provedAccessSurfaces.length ? {...surface,
        patterns: [...(surface.patterns ?? []),
          ...derivedPending.flatMap(item => item.nextSurface.patterns ?? []),
          ...provedAccessSurfaces.flatMap(item => item.patterns ?? [])],
        methodOperations: [...(surface.methodOperations ?? []),
          ...derivedPending.flatMap(item => item.nextSurface.methodOperations ?? []),
          ...provedAccessSurfaces.flatMap(item => item.methodOperations ?? [])],
      } : surface;
      // The PoC receives only exact local contracts observed during this run.
      // It obtains a fresh login; no derived bearer is written to disk.
      const proofScope = [...derivedPending, ...provedAccessScopes.map(scope => ({scope}))]
        .reduce((effective, item) => {
        if (item.scope === sessions.scope || item.scope.target.environment !== 'local') return effective;
        const merged = structuredClone(effective);
        for (const name of ['jsonPostPaths', 'formPostPaths', 'writeOperations'])
          merged.probes[name] = [...new Map([...merged.probes[name], ...item.scope.probes[name]]
            .map(value => [typeof value === 'string' ? value : JSON.stringify(value), value])).values()];
        merged.localAutoPostContracts = {...merged.localAutoPostContracts,
          ...item.scope.localAutoPostContracts};
        merged.localAutoMethodContracts = {...merged.localAutoMethodContracts,
          ...item.scope.localAutoMethodContracts};
        return merged;
        }, sessions.scope);
      findings = await proveFindings(findings, results, {runDir, surface: proofSurface,
        scope: proofScope,
        originSurfaces, originContexts: Object.fromEntries(credentialAudits.map(audit =>
          [audit.origin, {scope: audit.scope, env: audit.env, loginSpecs: audit.loginSpecs}])),
        env: sessions.env, loginSpecs: sessions.loginSpecs, ledger, web, log: say});
      const finalWebVerdicts = webVerdictCounts();
      for (const [field, statsField] of [['confirmed', 'confirmed'], ['observed', 'observed'],
        ['inconclusive', 'inconclusive'], ['blocked', 'blocked'],
        ['notReproduced', 'notReproduced']])
        stats[statsField] = Math.max(0, (stats[statsField] ?? 0) +
          finalWebVerdicts[field] - countedWebVerdicts[field]);
      if (credentialsReady) {
        const primaryResults = results.filter(item => !item.origin || item.origin === sessions.scope.target.origin);
        const built = await buildChains(primaryResults, findings, {requester, surface, scope: sessions.scope,
          runDir, env: sessions.env, loginSpecs: sessions.loginSpecs, ledger,
          infer: model ? invokeModel : null, model,
          maxModelCalls: scope.limits.modelCalls - modelInvocations, log: say});
        chains = built.chains;
        chainPlanning.push({origin: sessions.scope.target.origin, ...built.modelCoverage,
          modelCalls: built.modelCalls, modelError: built.modelError});
        modelError = modelError ?? built.modelError;
      }
      for (const [index, audit] of credentialAudits.entries()) if (audit.usable) {
        const built = await buildChains(audit.results, findings, {requester: audit.requester,
          surface: audit.surface, scope: audit.scope, runDir, env: audit.env, ledger,
          loginSpecs: audit.loginSpecs, idPrefix: `c-o${index + 1}`,
          infer: model ? invokeModel : null, model,
          maxModelCalls: scope.limits.modelCalls - modelInvocations, log: say});
        chains.push(...built.chains);
        chainPlanning.push({origin: audit.origin, ...built.modelCoverage,
          modelCalls: built.modelCalls, modelError: built.modelError});
        modelError = modelError ?? built.modelError;
      }
      chains.push(...await buildDerivedPrerequisiteChains(findings,
        {runDir, env: sessions.env, ledger, log: say}));
      assessment = await assessFindings(findings, chains, {infer: model ? invokeModel : null, model,
        maxModelPages: Math.max(0, Math.min(8, scope.limits.modelCalls - modelInvocations)),
        maxConcurrency: modelParallelism, log: say});
      modelError = modelError ?? assessment.modelError;
      atomic(path.join(runDir, 'assessment.json'), assessment);
      atomic(path.join(runDir, 'chains.json'), chains);
      atomic(path.join(runDir, 'chain-planning.json'), chainPlanning);
      atomic(path.join(runDir, 'web-probes.json'), web);
      phase('done', 5, 'Replay and assess');
    } else {
      phase('skipped', 4, 'Plan and test observed leads');
      phase('skipped', 5, 'Replay and assess');
    }
    phase('doing', 6, 'Report and coverage');
    findings = consolidateInjectionProofs(consolidateRawBoundaryProofs(
      consolidateBrowserXssProofs(findings)));
    atomic(path.join(runDir, 'surface.json'), surface);
    atomic(path.join(runDir, 'results.json'), results);
    atomic(path.join(runDir, 'findings.json'), findings);
    advisories = await lookupAdvisories([mined, ...(discovery?.hosts ?? []).map(host => host.assets),
      ...credentialAudits.map(audit => audit.mined)], {enabled: scope.discovery.external.osv,
      offline, ledger, deadline, ...(osvQuery ? {query: osvQuery} : {}), log: say});
    atomic(path.join(runDir, 'advisories.json'), advisories);
    stats = {...stats, modelCalls: modelInvocations, finishedAt: now(), elapsedMs: Date.now() - started,
      requests: anonymousRequester.stats.sent + requester.stats.sent +
        derivedScopedRequesters.reduce((count, item) => count + item.stats.sent, 0),
      cached: anonymousRequester.stats.cached + requester.stats.cached +
        derivedScopedRequesters.reduce((count, item) => count + item.stats.cached, 0)};
    stats.requests += credentialAudits.reduce((count, audit) => count + audit.requester.stats.sent, 0);
    stats.cached += credentialAudits.reduce((count, audit) => count + audit.requester.stats.cached, 0);
    stats.rps = Math.round((stats.requests * 10000) / Math.max(stats.elapsedMs, 1)) / 10;
    const integrity = verifyLedger(ledger.file);
    const planModelCut = !!model && plan.modelCoverage?.pagesSent < plan.modelCoverage?.pagesAvailable;
    const reconModelCuts = model ? [
      {origin: sessions.scope.target.origin, coverage: surface.modelCoverage},
      ...credentialAudits.map(audit => ({origin: audit.origin, coverage: audit.surface.modelCoverage})),
    ].filter(item => item.coverage && (item.coverage.routesSent < item.coverage.routesAvailable ||
      item.coverage.followupPathsSent < item.coverage.followupPathsAvailable)) : [];
    const credentialPlanCuts = model ? credentialAudits.filter(audit =>
      audit.plan.modelCoverage?.pagesSent < audit.plan.modelCoverage?.pagesAvailable) : [];
    const pageCuts = (mined?.stats.pagesCut ?? 0) + credentialAudits.reduce((count, audit) =>
      count + (audit.mined?.stats.pagesCut ?? 0), 0);
    const assetStats = [mined?.stats, ...credentialAudits.map(audit => audit.mined?.stats),
      ...(discovery?.hosts ?? []).filter(host => host.origin !== sessions.scope.target.origin &&
        !sessions.scope.credentialOrigins.includes(host.origin)).map(host => host.assets?.stats)];
    const sourceMapCount = field => assetStats.reduce((count, stats) =>
      count + (stats?.[field] ?? 0), 0);
    const sourceMapSourcesCut = sourceMapCount('sourceMapSourcesCut');
    const sourceMapOriginalsBudgetCut = sourceMapCount('sourceMapOriginalsBudgetCut');
    const sourceMapOriginalsUnresolvable = sourceMapCount('sourceMapOriginalsUnresolvable');
    const sourceMapOriginalsFetchFailed = sourceMapCount('sourceMapOriginalsFetchFailed');
    const sourceMapAppSourcesUnavailable = sourceMapCount('sourceMapAppSourcesUnavailable');
    const sourceMapVendorSourcesUnavailable = sourceMapCount('sourceMapVendorSourcesUnavailable');
    const sourceMapNamespacedSourcesUnavailable = sourceMapCount('sourceMapNamespacedSourcesUnavailable');
    const sourceMapOriginalsUnavailable = Math.max(0,
      sourceMapSourcesCut - sourceMapOriginalsBudgetCut);
    const derivedSourceMapSourcesCut = derivedSessions.reduce((count, session) =>
      count + (session.coverage?.sourceMapSourcesCut ?? 0), 0);
    const testFeedbackCut = surface.testResponseFollowup?.hintsUntested ?? 0;
    const derivedTestFeedbackCut = surface.derivedTestResponseFollowup?.hintsUntested ?? 0;
    const sourceMapBudgetCut = assetStats.reduce((count, stats) =>
      count + (stats?.sourceMapBudgetCut ?? 0), 0);
    const assetHintsCut = assetStats.reduce((count, stats) => count + (stats?.routeHintsCut ?? 0), 0);
    const inferredRoutesCut = assetStats.reduce((count, stats) => count + (stats?.inferredRoutesCut ?? 0), 0);
    const inferredClassesCut = assetStats.reduce((count, stats) => count + (stats?.inferredClassesCut ?? 0), 0);
    const modelNamingCut = !!model && !!scope.discovery.recurse && (discovery?.modelNaming?.hostsCut ?? 0) > 0;
    const webReviewCuts = model ? unresolvedWebModelCuts(web.modelCoverage) :
      {candidates: [], prelude: [], sequences: []};
    const webModelCuts = webReviewCuts.candidates;
    const preludeModelCuts = webReviewCuts.prelude;
    const sessionModelCuts = model ? (web.modelCoverage ?? []).filter(item =>
      (item.sessionPublicAvailable ?? 0) > 0 && (item.sessionPrivateAvailable ?? 0) > 0 &&
      ((item.sessionPublicSent ?? 0) < item.sessionPublicAvailable ||
        (item.sessionPrivateSent ?? 0) < item.sessionPrivateAvailable)) : [];
    const jsonModelCuts = model ? (web.modelCoverage ?? []).filter(item =>
      (item.jsonPostSent ?? 0) < (item.jsonPostAvailable ?? 0) ||
      (item.jsonReadSent ?? 0) < (item.jsonReadAvailable ?? 0) ||
      (item.jsonFieldsCut ?? 0) > 0) : [];
    const httpSequenceModelCuts = webReviewCuts.sequences;
    const storedXssModelCuts = model ? (web.modelCoverage ?? []).filter(item =>
      (item.storedXssPostsSent ?? 0) < (item.storedXssPostsAvailable ?? 0) ||
      (item.storedXssViewsSent ?? 0) < (item.storedXssViewsAvailable ?? 0)) : [];
    const hostResponseModelCuts = model ? (web.modelCoverage ?? []).filter(item =>
      (item.responseRoutesReviewed ?? 0) < (item.responseRoutesAvailable ?? 0) ||
      (item.responsePagesSent ?? 0) < (item.responsePagesAvailable ?? 0)) : [];
    const anonymousResponseModelCuts = model ? [
      {origin: surface.origin, coverage: surface.anonymousResponseFollowup},
      ...credentialAudits.map(audit => ({origin: audit.origin,
        coverage: audit.surface.anonymousResponseFollowup})),
    ].filter(item => item.coverage &&
      (item.coverage.routesReviewed < item.coverage.routesAvailable ||
        item.coverage.pagesSent < item.coverage.pagesAvailable)) : [];
    const chainModelCuts = model ? chainPlanning.filter(item =>
      item.candidatesSent < item.candidatesAvailable) : [];
    const assessmentModelCut = !!model && !!assessment?.modelCoverage &&
      assessment.modelCoverage.findingsSent < assessment.modelCoverage.findingsAvailable;
    const sourceModelCut = !!model && !!sourceReview?.modelCoverage &&
      sourceReview.modelCoverage.snippetsSent < sourceReview.modelCoverage.snippetsAvailable;
    const assetModelCut = !!model && !!assetAnalysis?.coverage &&
      (assetAnalysis.coverage.filesSent < assetAnalysis.coverage.filesAvailable ||
        assetAnalysis.coverage.routesSent < assetAnalysis.coverage.routesAvailable ||
        assetAnalysis.coverage.hintsSent < assetAnalysis.coverage.hintsAvailable ||
        assetAnalysis.coverage.sourceChunksSent < assetAnalysis.coverage.sourceChunksAvailable);
    const graphqlModelCuts = model ? [
      {origin: sessions.scope.target.origin, coverage: surface.graphql?.coverage},
      ...credentialAudits.map(audit => ({origin: audit.origin, coverage: audit.surface.graphql?.coverage})),
      ...(discovery?.hosts ?? []).filter(host => host.graphql?.coverage)
        .map(host => ({origin: host.origin, coverage: host.graphql.coverage})),
    ].filter(item => item.coverage.pagesSent < item.coverage.pagesAvailable) : [];
    const graphqlFieldsCut = (surface.graphql?.coverage?.fieldsCut ?? 0) +
      credentialAudits.reduce((count, audit) => count + (audit.surface.graphql?.coverage?.fieldsCut ?? 0), 0) +
      (discovery?.hosts ?? []).reduce((count, host) => count + (host.graphql?.coverage?.fieldsCut ?? 0), 0);
    const graphqlPathsCut = (surface.graphql?.coverage?.pathsCut ?? 0) +
      credentialAudits.reduce((count, audit) => count + (audit.surface.graphql?.coverage?.pathsCut ?? 0), 0) +
      (discovery?.hosts ?? []).reduce((count, host) => count + (host.graphql?.coverage?.pathsCut ?? 0), 0);
    const graphqlBolaCut = (surface.graphql?.bola?.cut ?? 0) +
      credentialAudits.reduce((count, audit) => count + (audit.surface.graphql?.bola?.cut ?? 0), 0);
    const apiSchemaCuts = (surface.apiSchemaCuts ?? 0) +
      credentialAudits.reduce((count, audit) => count + (audit.surface.apiSchemaCuts ?? 0), 0);
    const graphqlBolaModelCuts = model ? [
      {origin: sessions.scope.target.origin, coverage: surface.graphql?.bola?.modelCoverage},
      ...credentialAudits.map(audit => ({origin: audit.origin,
        coverage: audit.surface.graphql?.bola?.modelCoverage})),
    ].filter(item => item.coverage && item.coverage.candidatesSent < item.coverage.candidatesAvailable) : [];
    const accessFollowupCuts = model ? [
      {origin: sessions.scope.target.origin, coverage: surface.accessFollowup?.coverage},
      ...credentialAudits.map(audit => ({origin: audit.origin,
        coverage: audit.surface.accessFollowup?.coverage})),
    ].filter(item => item.coverage && item.coverage.tasksSent < item.coverage.tasksAvailable) : [];
    const accessFollowupBudgetCut = (surface.accessFollowup?.cut ?? 0) +
      credentialAudits.reduce((count, audit) => count + (audit.surface.accessFollowup?.cut ?? 0), 0);
    const accessFollowupVariantCut = (surface.accessFollowup?.coverage?.variantsCut ?? 0) +
      credentialAudits.reduce((count, audit) => count +
        (audit.surface.accessFollowup?.coverage?.variantsCut ?? 0), 0);
    const sourceFilesCut = !!sourceReview && (sourceReview.stats.skipped > 0 ||
      sourceReview.stats.filesCut > 0 || sourceReview.stats.routesCut > 0 ||
      sourceReview.stats.unresolvedRoutesCut > 0 || sourceReview.stats.secretLeadsCut > 0 ||
      sourceReview.stats.traversalCut);
    const sourceUnresolved = (sourceReview?.stats.unresolvedRoutes ?? 0) > 0;
    const discoveryModelCut = !!model && (discovery?.modelAnalysis?.operationsCut ?? 0) > 0;
    const pendingResearchCheckpoints = countPendingResearchCheckpoints(runDir);
    const redactedResearchLeads = fs.readdirSync(runDir)
      .filter(name => ACCEPTED_RESEARCH_CHECKPOINT.test(name))
      .reduce((count, name) => count +
        (JSON.parse(fs.readFileSync(path.join(runDir, name), 'utf8'))
          .redactedExecutableLeads ?? 0), 0);
    const provedAccessCut = provedAccessQueue.length + provedAccessRecon.reduce((count, item) =>
      count + (item.coverage?.budgetCut ?? 0) + (item.status === 'recon-error' ? 1 : 0), 0);
    const externalScriptContracts = provedAccessRecon.reduce((count, item) =>
      count + (item.externalContracts?.length ?? 0), 0);
    const unresolvedScriptContracts = provedAccessRecon.reduce((count, item) =>
      count + (item.unresolvedContracts?.length ?? 0), 0);
    if (researchDeadlineCut && modelError === AUDIT_MODEL_DEADLINE_MESSAGE) modelError = null;
    const incomplete = dryRun || researchDeadlineCut || !credentialsReady || credentialAudits.some(audit => !audit.usable) ||
      planModelCut || credentialPlanCuts.length > 0 || reconModelCuts.length > 0 ||
      webModelCuts.length > 0 || preludeModelCuts.length > 0 || sessionModelCuts.length > 0 ||
      jsonModelCuts.length > 0 || httpSequenceModelCuts.length > 0 ||
      hostResponseModelCuts.length > 0 || anonymousResponseModelCuts.length > 0 ||
      chainModelCuts.length > 0 || assessmentModelCut ||
      sourceModelCut || assetModelCut || sourceFilesCut ||
      sourceUnresolved ||
      discoveryModelCut || graphqlModelCuts.length > 0 || graphqlFieldsCut > 0 ||
      graphqlPathsCut > 0 || graphqlBolaCut > 0 || graphqlBolaModelCuts.length > 0 ||
      apiSchemaCuts > 0 ||
      accessFollowupCuts.length > 0 || accessFollowupBudgetCut > 0 ||
      accessFollowupVariantCut > 0 ||
      pageCuts > 0 || sourceMapSourcesCut > 0 || derivedSourceMapSourcesCut > 0 ||
      testFeedbackCut > 0 || (web.descendantFeedbackPending?.length ?? 0) > 0 ||
      sourceMapBudgetCut > 0 || assetHintsCut > 0 ||
      inferredRoutesCut > 0 || inferredClassesCut > 0 || modelNamingCut ||
      !!modelError || !integrity.ok || web.cut > 0 ||
      pendingResearchCheckpoints > 0 || redactedResearchLeads > 0 || provedAccessCut > 0 ||
      unresolvedScriptContracts > 0 ||
      advisories.incomplete ||
      chains.some(chain => chain.status !== 'confirmed') ||
      (scope.domains.length > 0 && (!discovery || discovery.incomplete));
    const oneAccountChecks = results.filter(item => item.task?.kind === 'missing-auth' &&
      item.task.request?.as === 'anonymous').length;
    const oneAccountStatus = oneAccountChecks ? `${oneAccountChecks} bounded anonymous missing-authentication checks ran` :
      'no one-account access-control check ran because no configured identity route or verified owner-bound sensitive item was reached';
    const limitations = [
        ...(focus ? [`Focused validation of source finding ${focus.findingId}; routes outside this finding were not independently audited.`,
          ...(focus.sourceSnapshotMatches === false ?
            ['The source checkout changed after this finding was recorded; its cited source hypothesis may be stale.'] : []),
          ...(surface.focus?.revision?.status !== 'matched' ?
            [`Source and live build revision ${surface.focus?.revision?.status ?? 'unverified'}; a live proof establishes behavior on the target, not that this checkout produced it.`] : [])] : []),
        ...(assessmentModelCut ? ['Muse assessed ' + assessment.modelCoverage.findingsSent +
          ' of ' + assessment.modelCoverage.findingsAvailable + ' independently proved findings in ' +
          assessment.modelCoverage.pagesSent + ' of ' + assessment.modelCoverage.pagesAvailable +
          ' pages.'] : []),
        ...reconModelCuts.filter(item => item.coverage.routesSent < item.coverage.routesAvailable)
          .map(item => 'Muse reviewed ' + item.coverage.routesSent +
          ' of ' + item.coverage.routesAvailable + ' observed reconnaissance routes on ' +
          item.origin + ' in ' + item.coverage.pagesSent + ' of ' +
          item.coverage.pagesAvailable + ' pages.'),
        ...reconModelCuts.filter(item => item.coverage.followupPathsSent < item.coverage.followupPathsAvailable)
          .map(item => 'Muse reviewed ' + item.coverage.followupPathsSent + ' of ' +
          item.coverage.followupPathsAvailable + ' guarded reconnaissance GET responses on ' +
          item.origin + ' in ' + item.coverage.followupPagesSent + ' of ' +
          item.coverage.followupPagesAvailable + ' follow-up pages.'),
        ...(scope.domains.length && !discovery ? ['External subdomain discovery was skipped.'] : []),
        ...(discovery?.incomplete ? [`Discovery left ${discovery.stats.cut} host, query, page, certificate or source-map checks incomplete.`] : []),
        ...(pageCuts ? [`HTML crawl cut ${pageCuts} linked pages on configured application origins by its page or byte budget.`] : []),
        ...(sourceMapOriginalsUnresolvable ? [`Source-map mining found ${sourceMapOriginalsUnresolvable} original names without embedded source text or an authorized public source URL (${sourceMapAppSourcesUnavailable} app-likely, ${sourceMapVendorSourcesUnavailable} vendor, ${sourceMapNamespacedSourcesUnavailable} bundle-namespace originals overall). Virtual source names are metadata, not inspected code.`] : []),
        ...(sourceMapOriginalsFetchFailed ? [`Source-map mining requested ${sourceMapOriginalsFetchFailed} public original URLs, but they did not return inspectable source text.`] : []),
        ...(sourceMapOriginalsUnavailable && !sourceMapOriginalsUnresolvable && !sourceMapOriginalsFetchFailed ? [`Source-map mining found ${sourceMapOriginalsUnavailable} originals without inspectable source text; see assets.json for their source-map metadata.`] : []),
        ...(sourceMapOriginalsBudgetCut ? [`Asset budget prevented checking ${sourceMapOriginalsBudgetCut} source-map original URLs.`] : []),
        ...(derivedSourceMapSourcesCut ? [`Authenticated source-map reconnaissance left ${derivedSourceMapSourcesCut} originals uninspected after checking reachable same-origin files; see derived-session-recon.json.`] : []),
        ...(testFeedbackCut ? [`Test responses revealed ${testFeedbackCut} new scoped route hints that were not followed up (${surface.testResponseFollowup.stopReason ?? 'unknown stop reason'}); see coverage.json.`] : []),
        ...(derivedTestFeedbackCut ? [`Protected test responses revealed ${derivedTestFeedbackCut} new scoped route hints that were not followed up; see coverage.json.`] : []),
        ...(web.descendantFeedbackPending?.length ?
          [`${web.descendantFeedbackPending.length} authorized descendant route hints remain pending; see coverage.json.`] : []),
        ...(sourceMapBudgetCut ? [`Asset budget prevented checking ${sourceMapBudgetCut} source-map candidates.`] : []),
        ...(assetHintsCut ? [`Asset mining did not retain ${assetHintsCut} indirect HTTP call hints beyond per-file limits.`] : []),
        ...(inferredRoutesCut ? [`Asset mining cut ${inferredRoutesCut} inferred client call routes beyond per-file limits.`] : []),
        ...(inferredClassesCut ? [`Asset mining did not inspect ${inferredClassesCut} JavaScript classes beyond per-file limits.`] : []),
        ...(discovery?.modelAnalysis?.operationsCut && model ?
          [`Muse did not interpret ${discovery.modelAnalysis.operationsCut} observed API operations within its discovery call budget.`] : []),
        ...(modelNamingCut ? [`Muse did not review ${discovery.modelNaming.hostsCut} live host records for additional DNS name proposals within its naming-call budget.`] : []),
        ...(planModelCut ? [`Muse received ${plan.modelCoverage.pagesSent} of ${plan.modelCoverage.pagesAvailable} access-control planning pages; some routes and assets were not model-reviewed.`] : []),
        ...credentialPlanCuts.map(audit => `Muse received ${audit.plan.modelCoverage.pagesSent} of ${audit.plan.modelCoverage.pagesAvailable} access-control planning pages on ${audit.origin}; some routes and assets were not model-reviewed.`),
        ...accessFollowupCuts.map(item => `Muse reviewed ${item.coverage.tasksSent} of ${item.coverage.tasksAvailable} inconclusive access-control tasks on ${item.origin} for observed-query follow-ups in ${item.coverage.pagesSent} of ${item.coverage.pagesAvailable} pages.`),
        ...(accessFollowupBudgetCut ? [`${accessFollowupBudgetCut} selected access-control follow-ups were cut by the task budget.`] : []),
        ...(accessFollowupVariantCut ? [`${accessFollowupVariantCut} observed access-control query variants were cut by the per-task follow-up limit.`] : []),
        ...webModelCuts.map(item => `Muse reviewed ${item.candidatesSent} of ${item.candidatesAvailable} web-probe candidates on ${item.origin} in ${item.pagesSent} of ${item.pagesAvailable} pages.`),
        ...preludeModelCuts.map(item => `Muse web-strategy pages included ${item.preludeRoutesSent ?? 0} of ${item.preludeRoutesAvailable ?? 0} observed GET routes on ${item.origin} as possible prelude steps; the separate HTTP-sequence planner reviewed ${item.httpSequenceObservedReadsSent ?? 0} of ${item.httpSequenceObservedReadsAvailable ?? 0} observed GET routes.`),
        ...sessionModelCuts.map(item => `Muse reviewed ${item.sessionPublicSent ?? 0} of ${item.sessionPublicAvailable} public and ${item.sessionPrivateSent ?? 0} of ${item.sessionPrivateAvailable} private GET routes on ${item.origin} for owner-session chains.`),
        ...jsonModelCuts.map(item => `Muse reviewed ${item.jsonPostSent ?? 0} of ${item.jsonPostAvailable ?? 0} exact reviewed JSON POST routes and ${item.jsonReadSent ?? 0} of ${item.jsonReadAvailable ?? 0} observed GET sequence routes on ${item.origin}; ${item.jsonFieldsCut ?? 0} eligible body fields were beyond the per-route model page.`),
        ...httpSequenceModelCuts.map(item => `Muse reviewed ${item.httpSequenceSent ?? 0} of ${item.httpSequenceAvailable ?? 0} observed HTTP sequence routes on ${item.origin}; the remaining routes were not reviewed in this run.`),
        ...storedXssModelCuts.map(item => `Muse reviewed ${item.storedXssPostsSent ?? 0} of ${item.storedXssPostsAvailable ?? 0} reviewed JSON POST routes and ${item.storedXssViewsSent ?? 0} of ${item.storedXssViewsAvailable ?? 0} observed GET views for stored XSS on ${item.origin}.`),
        ...hostResponseModelCuts.map(item => `Muse reviewed ${item.responseRoutesReviewed ?? 0} of ${item.responseRoutesAvailable ?? 0} guarded descendant GET responses on ${item.origin}, and sent ${item.responsePagesSent ?? 0} of ${item.responsePagesAvailable ?? 0} response-fact pages.`),
        ...anonymousResponseModelCuts.map(item => `Muse reviewed ${item.coverage.routesReviewed} of ${item.coverage.routesAvailable} guarded anonymous GET responses on ${item.origin}, and sent ${item.coverage.pagesSent} of ${item.coverage.pagesAvailable} response-fact pages.`),
        ...chainModelCuts.map(item => `Muse reviewed ${item.candidatesSent} of ${item.candidatesAvailable} independently proved cross-path chain candidates on ${item.origin}.`),
        ...(discovery?.hosts?.some(host => host.origin && host.origin !== scope.target.origin &&
          !scope.discovery.auditDomains.some(domain => host.host === domain || host.host.endsWith(`.${domain}`))) ?
          ['Discovered descendant hosts outside discovery.auditDomains received inventory and sensitive-path checks only.'] : []),
        ...(discovery?.hosts?.some(host => host.audit) ?
          ['Descendants outside explicit credentialOrigins received anonymous web probes only; authenticated recon ran on credential origins.'] : []),
        ...credentialAudits.filter(audit => !audit.usable).map(audit =>
          `Credential origin ${audit.origin} did not establish two distinct identities; its cross-account tasks did not run.`),
        ...(!credentialsReady ? [ownerReady ?
          outsiderReady && ownerSecret === outsiderSecret ?
            `Both account names resolved to the same credential; ${oneAccountStatus}.` :
          principalParityFailed ?
            `Both credentials resolved to the same account principal; ${oneAccountStatus}. Cross-account tests did not run.` :
          outsiderReady ?
            `The accounts have different declared roles; ${oneAccountStatus}. Vertical tests are not implemented.` :
            `Only the owner account was usable; ${oneAccountStatus}. Cross-account tests did not run.` :
          'Two distinct, usable same-role account credentials were unavailable; account-boundary tests were not run.'] : []),
        ...(sourceReview?.stats.skipped ? [`Source review skipped ${sourceReview.stats.skipped} files by its size budget.`] : []),
        ...(sourceReview?.stats.filesCut ? [`Source review did not read ${sourceReview.stats.filesCut} eligible files beyond its file limit.`] : []),
        ...(sourceReview?.stats.routesCut ? [`Source review did not retain ${sourceReview.stats.routesCut} route facts beyond its route limit.`] : []),
        ...(sourceReview?.stats.unresolvedRoutes ? [`Source review saw ${sourceReview.stats.unresolvedRoutes} route declarations with paths it could not parse statically; Muse proposals and HTTP checks do not prove all of them were covered.`] : []),
        ...(sourceReview?.stats.unresolvedRoutesCut ? [`Source review did not send ${sourceReview.stats.unresolvedRoutesCut} unresolved route excerpts beyond its source-hint limit.`] : []),
        ...(sourceReview?.stats.secretLeadsCut ? [`Source review did not retain ${sourceReview.stats.secretLeadsCut} credential-shaped leads beyond its per-file or total limit.`] : []),
        ...(sourceReview?.stats.traversalCut ? ['Source review stopped enumerating files at its directory-entry budget.'] : []),
        ...(sourceModelCut ? [`Muse received ${sourceReview.modelCoverage.snippetsSent} of ${sourceReview.modelCoverage.snippetsAvailable} source route excerpts in ${sourceReview.modelCoverage.pagesSent} of ${sourceReview.modelCoverage.pagesAvailable} pages.`] : []),
        ...(assetModelCut ? [`Muse reviewed ${assetAnalysis.coverage.filesSent} of ${assetAnalysis.coverage.filesAvailable} mined files, ${assetAnalysis.coverage.routesSent} of ${assetAnalysis.coverage.routesAvailable} route facts, ${assetAnalysis.coverage.hintsSent} of ${assetAnalysis.coverage.hintsAvailable} indirect call hints and ${assetAnalysis.coverage.sourceChunksSent} of ${assetAnalysis.coverage.sourceChunksAvailable} redacted source chunks in ${assetAnalysis.coverage.pagesSent} of ${assetAnalysis.coverage.pagesAvailable} asset-analysis pages.`] : []),
        ...graphqlModelCuts.map(item => `Muse reviewed ${item.coverage.operationsSent} of ${item.coverage.operationsAvailable} GraphQL root signatures on ${item.origin} in ${item.coverage.pagesSent} of ${item.coverage.pagesAvailable} pages.`),
        ...(graphqlFieldsCut ? [`GraphQL schema inventory omitted ${graphqlFieldsCut} root fields beyond its per-endpoint limits.`] : []),
        ...(graphqlPathsCut ? [`GraphQL schema inventory did not request ${graphqlPathsCut} eligible endpoints beyond its per-origin path limit.`] : []),
        ...(graphqlBolaCut ? [`${graphqlBolaCut} GraphQL object-query pairs were not tested within the task and pair budget.`] : []),
        ...(apiSchemaCuts ? [`${apiSchemaCuts} OpenAPI request-schema references were unresolved or beyond the local reference limit; related body fields may be incomplete.`] : []),
        ...(observedRoutes && Object.values(observedRoutes.stats.cuts).some(Boolean) ?
          [`Observed route crawling left ${Object.values(observedRoutes.stats.cuts).reduce((a, b) => a + b, 0)} scoped, depth, link, time or request leads unvisited; see observed-routes.json.`] : []),
        ...(surface.skippedReadActions?.length ?
          [`Anonymous route mapping skipped ${surface.skippedReadActions.length} observed GET action routes that require operator review; see coverage.json.`] : []),
        ...derivedSessions.filter(session => session.coverage?.anonymousTestError)
          .map(session => `Protected-session anonymous follow-up failed after mapping ${session.coverage.anonymousRoutesAvailable ?? 0} new routes.`),
        ...derivedSessions.filter(session => session.coverage?.budgetCut > 0)
          .map(session => `Authenticated reconnaissance left ${session.coverage.budgetCut} queued scoped URLs unrequested (` +
            (session.coverage.cutReason === 'url-count-cap' ?
              `maxUrls ${scope.limits.maxUrls} per-session cap` : session.coverage.cutReason ?? 'unknown stop reason') + ').'),
        ...derivedSessions.filter(session => session.coverage?.sizeCut > 0)
          .map(session => `Authenticated reconnaissance could not capture ${session.coverage.sizeCut} responses beyond the 16 MiB response limit; see derived-session-recon.json for paths.`),
        ...derivedSessions.filter(session => session.coverage?.anonymousRoutesAvailable &&
          !session.coverage?.anonymousChecks && !session.coverage?.anonymousTestError)
          .map(session => `For one derived session, recon mapped ${session.coverage.anonymousRoutesAvailable} new routes, but no anonymous follow-up checks ran for that session within the reserved budget or deadline.`),
        ...(provedAccessCut ? [`Proved-access reconnaissance left ${provedAccessCut} context or scoped URL leads unvisited; see confirmed-access-recon.json.`] : []),
        ...(externalScriptContracts ? [`Post-access JavaScript suggested ${externalScriptContracts} request contracts on other origins; none were sent. See confirmed-access-recon.json for their source evidence.`] : []),
        ...(unresolvedScriptContracts ? [`Post-access JavaScript left ${unresolvedScriptContracts} request destinations unresolved or beyond the Muse budget; see confirmed-access-recon.json.`] : []),
        ...graphqlBolaModelCuts.map(item => `Muse ranked ${item.coverage.candidatesSent} of ${item.coverage.candidatesAvailable} observed GraphQL object-query pairs on ${item.origin} in ${item.coverage.pagesSent} of ${item.coverage.pagesAvailable} pages.`),
        ...(researchDeadlineCut ? [AUDIT_MODEL_DEADLINE_MESSAGE] : []),
        ...(modelError ? [`A Muse model stage failed: ${modelError}`] : []),
        ...(web.cut ? [`${web.cut} web-probe leads were not executed within ` +
          (scope.limits.tasks === 0 ? 'the time and model budgets.' : 'the task, time and model budgets.')] : []),
        ...(pendingResearchCheckpoints ?
          [`${pendingResearchCheckpoints} saved Muse research checkpoint${pendingResearchCheckpoints === 1 ? '' : 's'} remain pending; resume this run to continue them.`] : []),
        ...(redactedResearchLeads ?
          [`${redactedResearchLeads} accepted JSON experiment${redactedResearchLeads === 1 ? '' : 's'} could not be saved for exact resume because executable values required credential redaction.`] : []),
        ...(advisories.incomplete ? [`OSV checked ${advisories.stats.checked} of ${advisories.stats.available} detected client-library versions; ${advisories.stats.cut} lookups or results were cut and ${advisories.stats.errors} failed.`] : []),
        'The probe catalog is partial. See coverage.json for exact exercised and untested variants; general account recovery, remote file inclusion, raw HTTP request smuggling and broad write workflows are not implemented.',
      ];
    const coverage = coverageFor({results, surface, web, ownerReady, credentialsReady,
      discovery, applications: credentialAudits.map(audit => audit.surface), scope: sessions.scope,
      advisories});
    coverage.observedRoutes = observedRoutes?.stats ?? null;
    coverage.pendingResearchCheckpoints = pendingResearchCheckpoints;
    coverage.researchDeadlineCut = researchDeadlineCut;
    coverage.redactedResearchLeads = redactedResearchLeads;
    coverage.confirmedAccessRecon = {contexts: provedAccessRecon.length,
      pendingContexts: provedAccessQueue.length,
      requests: provedAccessRecon.reduce((count, item) => count + (item.requested ?? 0), 0),
      routes: provedAccessRecon.reduce((count, item) => count + (item.routes ?? 0), 0),
      assets: provedAccessRecon.reduce((count, item) => count + (item.assets ?? 0), 0),
      newRoutes: provedAccessRecon.reduce((count, item) => count + (item.newRoutes ?? 0), 0),
      changedRoutes: provedAccessRecon.reduce((count, item) => count + (item.changedRoutes ?? 0), 0),
      newContracts: provedAccessRecon.reduce((count, item) => count + (item.newContracts ?? 0), 0),
      externalContracts: externalScriptContracts,
      unresolvedContracts: unresolvedScriptContracts,
      checksExecuted: provedAccessRecon.reduce((count, item) => count + (item.checksExecuted ?? 0), 0),
      budgetCut: provedAccessCut};
    coverage.testResponseFollowup = surface.testResponseFollowup ?? null;
    coverage.derivedTestResponseFollowup = surface.derivedTestResponseFollowup ?? null;
    coverage.descendantFeedbackPending = web.descendantFeedbackPending ?? [];
    coverage.skippedReadActions = surface.skippedReadActions ?? [];
    coverage.sensitivePaths = surface.exposureSelection ? {
      available: surface.exposureSelection.available,
      selected: surface.exposureSelection.selected,
      cut: surface.exposureSelection.skipped.length,
      fingerprints: surface.exposureSelection.fingerprints} : null;
    coverage.sourceMaps = {originalsUnavailable: sourceMapOriginalsUnavailable,
      originalsUnresolvable: sourceMapOriginalsUnresolvable,
      originalsFetchFailed: sourceMapOriginalsFetchFailed,
      appLikelyUnavailable: sourceMapAppSourcesUnavailable,
      vendorUnavailable: sourceMapVendorSourcesUnavailable,
      bundleNamespaceUnavailable: sourceMapNamespacedSourcesUnavailable,
      originalsBudgetCut: sourceMapOriginalsBudgetCut,
      mapCandidatesBudgetCut: sourceMapBudgetCut};
    coverage.derivedSessionRecon = {sessions: derivedSessions.length,
      reused: derivedSessionsReused,
      failed: derivedSessions.filter(session => session.status === 'failed').length,
      routes: derivedSessions.reduce((count, session) => count + (session.routes?.length ?? 0), 0),
      assets: derivedSessions.reduce((count, session) => count + (session.assets?.length ?? 0), 0),
      requests: derivedSessions.reduce((count, session) => count + (session.coverage?.requested ?? 0), 0),
      budgetCut: derivedSessions.reduce((count, session) => count + (session.coverage?.budgetCut ?? 0), 0),
      sizeCut: derivedSessions.reduce((count, session) => count + (session.coverage?.sizeCut ?? 0), 0),
      sourceMapSourcesCut: derivedSourceMapSourcesCut,
      sourceMapOriginalsRecovered: derivedSessions.reduce((count, session) =>
        count + (session.coverage?.sourceMapOriginalsRecovered ?? 0), 0),
      modelPathsAccepted: derivedSessions.reduce((count, session) =>
        count + (session.coverage?.modelPathsAccepted ?? 0), 0),
      anonymousRoutesAvailable: derivedSessions.reduce((count, session) =>
        count + (session.coverage?.anonymousRoutesAvailable ?? 0), 0),
      anonymousChecks: derivedSessions.reduce((count, session) =>
        count + (session.coverage?.anonymousChecks ?? 0), 0),
      anonymousConfirmed: derivedSessions.reduce((count, session) =>
        count + (session.coverage?.anonymousConfirmed ?? 0), 0),
      anonymousCut: derivedSessions.reduce((count, session) =>
        count + (session.coverage?.anonymousCut ?? 0), 0)};
    atomic(path.join(runDir, 'coverage.json'), coverage);
    const report = renderReport({run, scope: sessions.scope, scopeHash, surface, findings, results, chains, mined, stats, web, coverage,
      discovery, credentialAudits, ledgerFile: ledger.file, untested: plan.untested, dropped: plan.dropped, integrity, recheck,
      advisories, extraLimitations: limitations});
    const exitCode = exitCodeFor({findings, results, untested: plan.untested, blockedRun: incomplete});
    atomic(path.join(runDir, 'report.md'), report.markdown);
    atomic(path.join(runDir, 'report.json'), report.json);
    const modelOutput = model ? {
      assetNotes: assetAnalysis?.notes.length ?? 0,
      assetPaths: assetAnalysis?.proposals.length ?? 0,
      responsePaths: surface.anonymousResponseFollowup?.pathsAccepted ?? null,
      webStrategies: web.strategyDecisions.filter(item => item.accepted &&
        !['experiment', 'experiment-revision', 'session-chain', 'json-experiment',
          'stored-xss', 'access-boundary', 'access-boundary-revision',
          'http-sequence', 'http-sequence-sample',
          'http-sequence-sample-followup'].includes(item.mode)).length,
      webExperiments: web.strategyDecisions.filter(item => item.accepted &&
        ['experiment', 'experiment-revision'].includes(item.mode)).length,
      sessionChains: web.strategyDecisions.filter(item => item.accepted && item.mode === 'session-chain').length,
      jsonExperiments: web.strategyDecisions.filter(item => item.accepted && item.mode === 'json-experiment').length,
      httpSequences: web.strategyDecisions.filter(item => item.accepted &&
        ['http-sequence', 'http-sequence-sample-followup'].includes(item.mode)).length,
      httpSamples: web.strategyDecisions.filter(item => item.accepted &&
        item.mode === 'http-sequence-sample').length,
      httpSequenceRejectedByReason: Object.fromEntries(web.strategyDecisions
        .filter(item => !item.accepted && item.reason &&
          ['http-sequence', 'http-sequence-sample', 'http-sequence-sample-followup'].includes(item.mode))
        .reduce((counts, item) => counts.set(item.reason, (counts.get(item.reason) ?? 0) + 1), new Map())),
      rejectedDecisionRecordsByReason: Object.fromEntries(web.strategyDecisions
        .filter(item => !item.accepted && item.reason && item.reason !== 'model-stopped')
        .reduce((counts, item) => counts.set(item.reason,
          (counts.get(item.reason) ?? 0) + 1), new Map())),
      accessBoundaries: web.strategyDecisions.filter(item => item.accepted &&
        ['access-boundary', 'access-boundary-revision'].includes(item.mode)).length,
      storedXssChecks: web.strategyDecisions.filter(item => item.accepted && item.mode === 'stored-xss').length,
    } : null;
    const runState = {run, status: dryRun ? 'dry-run' : exitCode === 3 ? 'incomplete' : 'partial', scopeHash,
      ...(combinedReviewId?{combinedReviewId}:{}),
      resumedFrom: resumeFrom, scopeFile: file ? path.resolve(file) : null,
      ...(focus ? {focus, revisionPath: effectiveRevisionPath,
        revisionField: effectiveRevisionField} : {}),
      rps: scope.limits.rps,
      scope: sessions.scope, effectiveScopeHash: hash(JSON.stringify(sessions.scope)),
      localPostContracts: localPosts.admitted.length,
      localAuthContracts: localPosts.authAdmitted.length,
      startedAt, finishedAt: stats.finishedAt, stats, integrity, modelError, researchDeadlineCut,
      modelOutput, limitations, coverage,
      chains: chains.length, exitCode};
    atomic(path.join(runDir, 'run.json'), runState);
    phase('done', 6, 'Report and coverage');
    return {kind: 'blackbox-audit', run, runDir, projectRoot, origin: sessions.scope.target.origin,
      ...(combinedReviewId?{combinedReviewId}:{}),
      reportPath: path.join(runDir, 'report.md'),
      scopeHash, findings, stats, untested: plan.untested, dropped: plan.dropped, patterns: surface.patterns.length,
      tasks: plan.tasks.length + web.tested, chains: chains.length, discovery: discovery?.stats ?? null, integrity, coverage,
      replayInconclusive: web.results.filter(item => item.proofReplay?.verdict === 'inconclusive')
        .map(item => ({kind: item.kind, path: item.lead?.path ?? null, reason: item.reason})),
      sourceFindings: report.json.surface.application.sourceFindings,
      credentialOrigins: sessions.scope.credentialOrigins,
      advisories: {status: advisories.status, ...advisories.stats},
      modelOutput,
      modelError, researchDeadlineCut, incomplete, limitations: runState.limitations, exitCode};
  } catch (error) {
    const failure = earlyRunFailure(error, ledger, ledger.count() + 1,
      secrets, scope.harvest.redactFields);
    try {atomic(path.join(runDir, 'run-stop.json'), stopRecord(error.code === 130 ? 'interrupted' : 'failed', {
      error: {name: failure.name, code: failure.code, message: failure.message}}));}
    catch { /* The original failure remains the CLI error. */ }
    throw error;
  } finally {
    for (const [signal, handler] of Object.entries(signalHandlers))
      process.removeListener(signal, handler);
    ledger.close();
  }
}
