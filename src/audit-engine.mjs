import path from 'node:path';
import {read, change, event} from './store.mjs';
import {executeSourceReview, realPlan} from './real-engine.mjs';
import {prepareScopeTemplate} from './blackbox/setup.mjs';
import {projectIdentityBridge, projectBlackboxEnvironment} from './blackbox/project-scope.mjs';
import {runAudit} from './blackbox/index.mjs';
import {rememberBlackboxFindings} from './project-memory.mjs';
import {hash, id, need, now, redact} from './util.mjs';

const RESEARCH_BEHAVIOR = new Set(['model-differential', 'model-json-differential',
  'model-http-sequence']);

const leadCategory = finding => finding.privateFields?.length ? 'sensitive-data' :
  /auth|access|idor|bola|permission|account/i.test(finding.category) ?
    'authorization' : /inject/i.test(finding.category) ? 'injection' :
      /sensitive|disclos/i.test(finding.category) ? 'sensitive-data' : 'other';

function sourceContext(root, sourceResult) {
  const state = read(root);
  const routeLocations = sourceResult.inventory?.routeLocations ?? [];
  const methodFor = finding => finding.method ?? routeLocations.find(route =>
    route.path === finding.resourcePath)?.method ?? 'UNKNOWN';
  const findings = (sourceResult.findings ?? []).map(findingId =>
    state.findings.find(finding => finding.id === findingId)).filter(Boolean);
  const files = [...new Map(findings.filter(finding => finding.sourceEvidence?.file)
    .map(finding => [finding.sourceEvidence.file, {path: finding.sourceEvidence.file,
      bytes: null, hash: null, routes: finding.resourcePath ? 1 : 0}])).values()];
  const endpoints = findings.filter(finding => finding.resourcePath).map(finding => ({
    path: finding.resourcePath, method: methodFor(finding), params: [],
    file: finding.sourceEvidence.file, line: finding.sourceEvidence.line,
    source: 'white-box'}));
  const securityLeads = findings.filter(finding => finding.resourcePath).map(finding => ({
    id: finding.id, title: finding.title, category: leadCategory(finding),
    path: finding.resourcePath, method: methodFor(finding), hypothesis: finding.hypothesis,
    remediation: finding.recommendation, fields: finding.privateFields ?? [], source: {
      file: finding.sourceEvidence.file, line: finding.sourceEvidence.line,
      quote: finding.sourceEvidence.quote}, verdict: 'unproven'}));
  return {root, files, endpoints, notes: securityLeads.map(lead => ({path: lead.path,
    purpose: lead.hypothesis, methods: [lead.method], parameters: [],
    why: `${lead.title}: ${lead.hypothesis}`, sourceFindingId: lead.id})),
  proposals: [], secretLeads: [], securityLeads,
  stats: {files: files.length, bytes: 0, skipped: 0, filesCut: 0, routesCut: 0,
    unresolvedRoutes: 0, unresolvedRoutesCut: 0, secretLeadsCut: 0, traversalCut: 0,
    importedFindings: securityLeads.length}, unresolved: [],
  modelCoverage: {pagesAvailable: 0, pagesSent: 0, snippetsAvailable: 0,
    snippetsSent: 0, importedFindings: securityLeads.length}, modelCalls: 0,
  modelError: null, provenance: {kind: 'white-box-run', findings: findings.map(f => f.id)}};
}

function scopeOptions(target, options, bridge, runId) {
  const authorization = target.authorization;
  return {out: path.join('.bypass', 'runs', `${runId}.blackbox.scope.json`), force: true,
    environment: target.environment, include: authorization.paths.join(','),
    methods: authorization.methods.join(','), rps: authorization.maxRequestsPerSecond,
    ...(bridge?.options ?? {}),
    ...(options.modelCalls != null ? {'model-calls': options.modelCalls} : {}),
    ...(options.minutes != null ? {minutes: options.minutes} : {}),
    ...(options.maxUrls != null ? {'max-urls': options.maxUrls} : {}),
    ...(options.maxTasks != null ? {'max-tasks': options.maxTasks} : {}),
    ...(options.modelAgents != null ? {agents: options.modelAgents} : {}),
    ...(options.httpWorkers != null ? {'http-workers': options.httpWorkers} : {})};
}

async function reconcile(root, parentRunId, sourceResult, blackbox) {
  const state = read(root), target = state.targets.find(item => item.url === blackbox.origin);
  const sourceOutcomes = new Map((blackbox.sourceFindings ?? []).map(item => [item.id, item]));
  const sourceIds = sourceResult?.findings ?? [];
  await change(root, current => {
    for (const findingId of sourceIds) {
      const finding = current.findings.find(item => item.id === findingId);
      const outcome = sourceOutcomes.get(findingId);
      if (!finding || !outcome) continue;
      finding.lastRunId = parentRunId;
      finding.liveValidation = {runId: blackbox.run, status: outcome.status,
        reason: outcome.liveReason, evidence: outcome.evidence ?? [], at: now()};
      if (outcome.status === 'confirmed live') finding.status = 'confirmed';
      else if (outcome.status === 'not reproduced') finding.status = 'not_reproduced';
      else if (['blocked', 'inconclusive'].includes(outcome.status)) finding.status = 'blocked';
    }
    for (const finding of (blackbox.findings ?? []).filter(item =>
      item.verdict === 'confirmed' && !RESEARCH_BEHAVIOR.has(item.kind))) {
      const linked = finding.sourceFinding?.id ?
        current.findings.find(item => item.id === finding.sourceFinding.id) : null;
      const proofId = finding.proof ? path.basename(path.dirname(finding.proof)) : null;
      if (linked) {
        linked.status = 'confirmed';
        linked.lastRunId = parentRunId;
        linked.severity = finding.severity ?? linked.severity ?? 'unknown';
        linked.engine = 'blackbox';
        linked.recommendation = finding.assessment?.remediation ?? finding.remediation ??
          linked.recommendation;
        linked.verification = {status: 'confirmed', at: now(), origin: blackbox.origin,
          blackboxRun: blackbox.run, blackboxFindingId: finding.id, proofId,
          evidence: finding.evidence ?? [], confirmation: finding.confirmation ?? []};
        linked.history.push({action: 'blackbox-confirm', ...linked.verification});
        continue;
      }
      const fingerprint = hash({kind: 'blackbox', origin: blackbox.origin,
        type: finding.kind, pattern: finding.pattern ?? finding.url ?? finding.title});
      let saved = current.findings.find(item => item.fingerprint === fingerprint);
      if (!saved) {saved = {id: id('finding'), fingerprint, createdAt: now(), history: []};
        current.findings.push(saved);}
      Object.assign(saved, redact({title: finding.title, category: finding.kind,
        severity: finding.severity ?? 'unknown', status: 'confirmed', simulation: false,
        engine: 'blackbox', fixture: false, target: target?.name ?? null,
        targetOrigin: blackbox.origin, resourcePath: finding.pattern ?? null,
        sourceEvidence: finding.sourceFinding?.source ? {kind: 'source',
          ...finding.sourceFinding.source} : {kind: 'http', runId: blackbox.run,
          evidence: finding.evidence ?? []},
        hypothesis: finding.rationale ?? finding.sourceFinding?.hypothesis ?? finding.title,
        recommendation: finding.assessment?.remediation ?? finding.remediation ?? null,
        lastRunId: parentRunId, verification: {status: 'confirmed', at: now(),
          origin: blackbox.origin, blackboxRun: blackbox.run,
          blackboxFindingId: finding.id, proofId, evidence: finding.evidence ?? [],
          confirmation: finding.confirmation ?? []}}));
      saved.history.push({action: 'blackbox-confirm', ...saved.verification});
    }
    const combined=Boolean(sourceResult);
    event(current, combined?'combined-audit':'live-audit',
      `${combined?'Combined':'Live'} audit ${parentRunId}: ${combined?'source review and ':''}live proof reconciled.`,
      {runId: parentRunId, blackboxRunId: blackbox.run});
  });
  await rememberBlackboxFindings(root, blackbox);
  const latest = read(root);
  const findings = latest.findings.filter(item => item.lastRunId === parentRunId).map(item => item.id);
  const confirmed = findings.filter(findingId => latest.findings.find(item =>
    item.id === findingId)?.status === 'confirmed');
  return {findings, confirmed};
}

export async function executeStandaloneAudit(root, runId, options,
  {signal, report, runtime = {}} = {}) {
  const initial = read(root), plan = realPlan(initial, options);
  // Keep executeRun's established runtime-injection contract while allowing the
  // combined runner to receive separate source and black-box test doubles.
  const sourceRuntime = runtime.source ?? (runtime.prepareAgents || runtime.runContainer ||
    runtime.infer || runtime.testModel ? runtime : null);
  need(!plan.blockers.length, plan.blockers.join(' '), 3, {stage: 'setup', next: 'status'});
  if (plan.mode === 'code')
    return executeSourceReview(root, runId, options, {signal, report,
      ...(sourceRuntime ? {runtime: sourceRuntime} : {})});

  const target = initial.targets.find(item => item.name === plan.target);
  need(target?.authorization, 'Authorize the app testing scope before live testing.', 3);
  const bridge = projectIdentityBridge(initial, target);
  const prepared = prepareScopeTemplate(root, target.url,
    scopeOptions(target, options, bridge, runId), {reuse: false});
  const env = await projectBlackboxEnvironment(initial, target, bridge,
    {signal, env: runtime.env ?? process.env});

  let progressQueue = Promise.resolve();
  const sourcePromise = plan.mode === 'combined' ? executeSourceReview(root, runId,
    {...options, mode: 'code', target: plan.target}, {signal, report,
      ...(sourceRuntime ? {runtime: sourceRuntime} : {})})
    .then(result => ({result, context: sourceContext(root, result)}))
    .catch(error => {const failure=redact({message: error.message, details: error.details});
      report('white-box', 'Source review could not finish; the independent live audit is continuing.').catch(() => {});
      return {result: {findings: [], confirmed: [], executionFailures: [{stage: 'white-box',
        reason: failure.message}]}, context: null};}) : Promise.resolve({result: null, context: null});

  const blackbox = await (runtime.runBlackbox ?? runAudit)({url: target.url, root,
    scopeFile: prepared.file, sourceContext: sourcePromise.then(value => value.context),
    signal, env, infer: runtime.blackboxInfer, modelProfileOverride: runtime.modelProfile,
    log: event => {progressQueue=progressQueue.then(()=>report(
      `blackbox:${event.stage ?? 'progress'}`, event.message ??
      `${event.type ?? 'progress'}`, {blackbox: event})).catch(()=>{});
      runtime.onBlackboxProgress?.(event);}});
  await progressQueue;
  const source = await sourcePromise;
  const reconciled = await reconcile(root, runId, source.result, blackbox);
  const executionFailures = [...(source.result?.executionFailures ?? []),
    ...(blackbox.modelError ? [{stage: 'blackbox-model', reason: blackbox.modelError}] : [])];
  return {plan, engine: plan.mode, simulation: false, source: source.result,
    blackbox: {kind: blackbox.kind, run: blackbox.run, runDir: blackbox.runDir,
      projectRoot: blackbox.projectRoot, origin: blackbox.origin, exitCode: blackbox.exitCode,
      reportPath: blackbox.reportPath,
      stats: blackbox.stats, coverage: blackbox.coverage, findings: blackbox.findings,
      sourceFindings: blackbox.sourceFindings, incomplete: blackbox.incomplete},
    findings: reconciled.findings, confirmed: reconciled.confirmed,
    modelCalls: (source.result?.modelCalls ?? 0) + (blackbox.stats?.modelCalls ?? 0),
    executionFailures, coverageComplete: false,
    exitCode: reconciled.confirmed.length ? 1 : 3,
    message: reconciled.confirmed.length ?
      `${reconciled.confirmed.length} confirmed finding(s) across the ${plan.mode} security audit.` :
      `${plan.mode[0].toUpperCase()+plan.mode.slice(1)} security audit finished without a confirmed finding; review explicit coverage gaps.`};
}
