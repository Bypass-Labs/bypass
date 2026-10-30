// Application-level, anonymous probes on discovered hosts explicitly authorized by an apex audit scope.
import {runWebProbes} from './web-probes.mjs';
import {inspectGraphql} from './graphql.mjs';
import {credentialQueryKey} from './private-query.mjs';
import {validateUrl} from './scope.mjs';
import {baselineResponseHints} from './recon.mjs';
import {maskSecrets} from './assets.mjs';

const under = (host, domain) => host === domain || host.endsWith(`.${domain}`);
const HOST_RESPONSE_LIMIT = 6;
const HOST_RESPONSE_MAX_BYTES = 12000;
const safePath = value => typeof value === 'string' && value.startsWith('/') &&
  !value.startsWith('//') && value.length <= 300 && maskSecrets(value) === value;
const safePublicId = value => typeof value === 'string' &&
  /^[A-Za-z0-9_.-]{1,64}$/.test(value) && maskSecrets(value) === value;

/** Ask Muse for guarded GET follow-ups grounded in short, redacted facts from observed responses. */
export async function followupResponseHints(origin, scope, patterns, {requester, infer, model,
  maxModelPages = 0, deadline = Infinity, kind = 'descendant',
  responseIdentity = 'anonymous', log = () => {}}) {
  const stage = kind === 'descendant' ? 'descendant-recon' : 'recon';
  const eligible = patterns.filter(record => safePath(record.pattern) &&
    !record.pattern.includes('{') &&
    validateUrl(scope, record.pattern, {identity: 'anonymous', method: 'GET'}).ok);
  const coverage = {routesAvailable: eligible.length, routesReviewed: 0, observations: 0,
    pagesAvailable: Math.ceil(eligible.length / HOST_RESPONSE_LIMIT), pagesSent: 0,
    pathsProposed: 0, pathsAccepted: 0, pathsRejected: 0,
    pathsRejectedByReason: {}, responsesQueued: 0,
    responsesWithoutHints: 0};
  const rejectPath = reason => {
    coverage.pathsRejected++;
    coverage.pathsRejectedByReason[reason] = (coverage.pathsRejectedByReason[reason] ?? 0) + 1;
  };
  const result = {patterns: [], coverage, modelCalls: 0, modelError: null,
    modelReviewedPaths: []};
  const pageLimit = Math.max(0, Math.floor(maxModelPages));
  if (!infer || !model || pageLimit < 1) return result;
  log({stage: 'progress', type: 'recon-total', routesAvailable: eligible.length});
  const proposedPaths = new Set();
  // Accepted requests have already been fetched. Reuse their responses as the
  // next recon page so a newly revealed route can inform another Muse decision.
  const queued = eligible.map(record => ({record, url: record.pattern, response: null}));
  const queuedUrls = new Set(queued.map(item => new URL(item.url, origin).href));
  const requestWidth = Math.max(1, Math.min(HOST_RESPONSE_LIMIT,
    scope.limits?.agents ?? 1));
  while (queued.length && result.modelCalls < pageLimit && Date.now() < deadline) {
    const batch = queued.splice(0, HOST_RESPONSE_LIMIT);
    const responses = new Array(batch.length);
    for (let at = 0; at < batch.length; at += requestWidth) {
      const settled = await Promise.allSettled(batch.slice(at, at + requestWidth).map(async (item, offset) => {
        if (item.response) {responses[at + offset] = item.response; return;}
        try {
          responses[at + offset] = await requester({url: item.url,
            identity: 'anonymous', method: 'GET', step: 'recon',
            purpose: 'task', omitExcerpt: true});
        } catch (error) {
          log({stage, message: `Guarded ${kind} GET failed on ${origin}: ${error.message}`});
        }
      }));
      const failure = settled.find(item => item.status === 'rejected');
      if (failure) throw failure.reason;
    }
    const observations = [];
    for (const [index, item] of batch.entries()) {
      const {record} = item;
      const response = responses[index];
      if (!response) continue;
      coverage.routesReviewed++;
      const hints = baselineResponseHints(response);
      record.responseFacts = {status: Number.isInteger(response.status) ? response.status : null,
        ...(responseIdentity === 'derived-session' ? {identity: responseIdentity} : {}),
        type: maskSecrets(String(response.type ?? '').replace(/[\x00-\x1f\x7f]/g, ' ')).slice(0, 80),
        shape: response.status === 200 && /json|\+json/i.test(response.type ?? '') &&
          response.shape && typeof response.shape === 'object' ? response.shape : null,
        evidenceId: response.evidenceId ?? null};
      const publicIds = response.status === 200 && /json|\+json/i.test(response.type ?? '') ?
        (response.ids ?? []).filter(safePublicId).slice(0, 8) : [];
      if (publicIds.length) record.publicIds = [...new Set([
        ...(record.publicIds ?? []), ...publicIds])].slice(0, 20);
      observations.push({path: record.pattern, status: response.status ?? null,
        type: maskSecrets(String(response.type ?? '').replace(/[\x00-\x1f\x7f]/g, ' ')).slice(0, 80), hints,
        publicIds,
        parameters: Object.keys(record.params ?? {}).filter(name => !credentialQueryKey(name)).slice(0, 16),
        evidenceId: response.evidenceId ?? null});
    }
    coverage.observations += observations.length;
    if (!observations.length) continue;
    const context = {origin, page: coverage.pagesSent + 1,
      ...(responseIdentity === 'derived-session' ? {identity: responseIdentity} : {}),
      pages: coverage.pagesAvailable, observations};
    if (Buffer.byteLength(JSON.stringify(context)) > HOST_RESPONSE_MAX_BYTES) {
      result.modelError = `Response facts exceed ${HOST_RESPONSE_MAX_BYTES} bytes on ${origin}.`;
      break;
    }
    try {
      result.modelCalls++;
      const answer = await infer(model, [{role: 'system', content:
        `Continue mapping this authorized ${kind} application from the supplied guarded GET facts only. ` +
        (responseIdentity === 'derived-session' ?
          'These facts came from a transient confirmed session; choose scoped paths for the same session and do not infer anonymous access. ' : '') +
        'Propose at most eight same-origin, read-only GET paths or documented query variations worth checking. ' +
        'Use route-shaped hints to infer purpose and accepted values. Do not include credentials, ' +
        'state-changing routes or off-origin URLs. Code validates each path and confirms it over HTTP before testing. Return JSON only.'},
      {role: 'user', content: JSON.stringify(context)}], {schema: {type: 'object', properties: {
        paths: {type: 'array', maxItems: 8, items: {type: 'string'}}}, required: ['paths'], additionalProperties: false}});
      coverage.pagesSent++;
      if (Array.isArray(answer?.paths))
        result.modelReviewedPaths.push(...observations.map(item => item.path));
      for (const candidate of (Array.isArray(answer?.paths) ? answer.paths : []).slice(0, 8)) {
        coverage.pathsProposed++;
        if (!safePath(candidate)) {
          const offOrigin = typeof candidate === 'string' && /^https?:\/\//i.test(candidate) &&
            URL.canParse(candidate) && new URL(candidate).origin !== origin;
          rejectPath(offOrigin ? 'off-origin' : 'unsafe-path');
          continue;
        }
        const checked = validateUrl(scope, candidate, {identity: 'anonymous', method: 'GET'});
        if (!checked.ok) {rejectPath('scope'); continue;}
        const proposed = new URL(checked.url);
        if (proposed.origin !== origin) {rejectPath('off-origin'); continue;}
        if (proposedPaths.has(proposed.href)) {rejectPath('duplicate'); continue;}
        if ([...proposed.searchParams.keys()].some(credentialQueryKey)) {
          rejectPath('credential-query'); continue;
        }
        proposedPaths.add(proposed.href);
        let response;
        try {response = await requester({url: proposed.href, identity: 'anonymous', method: 'GET',
          step: 'recon', purpose: 'task', omitExcerpt: true});} catch {
          rejectPath('request-error');
          continue;
        }
        if (!Number.isInteger(response?.status)) {rejectPath('unanswered'); continue;}
        if (response.status >= 500) {rejectPath('http-5xx'); continue;}
        if (response.status >= 400) {rejectPath('http-4xx'); continue;}
        const operation = {method: 'GET', path: proposed.pathname,
          params: [...proposed.searchParams].map(([name, example]) => ({name, in: 'query', example})),
          source: [`model:${kind}-response`]};
        const [pattern] = patternsFromOperations({operations: [operation]});
        if (!pattern) {rejectPath('unmapped'); continue;}
        pattern.responseFacts = {status: response.status,
          ...(responseIdentity === 'derived-session' ? {identity: responseIdentity} : {}),
          type: maskSecrets(String(response.type ?? '').replace(/[\x00-\x1f\x7f]/g, ' ')).slice(0, 80),
          shape: /json|\+json/i.test(response.type ?? '') && response.shape &&
            typeof response.shape === 'object' ? response.shape : null,
          evidenceId: response.evidenceId ?? null};
        result.patterns.push(pattern);
        coverage.pathsAccepted++;
        if (!baselineResponseHints(response).length) coverage.responsesWithoutHints++;
        else if (!queuedUrls.has(proposed.href)) {
          queuedUrls.add(proposed.href);
          queued.push({record: pattern, url: proposed.href, response});
          coverage.responsesQueued++;
          coverage.routesAvailable++;
          coverage.pagesAvailable = Math.max(coverage.pagesAvailable,
            coverage.pagesSent + Math.ceil(queued.length / HOST_RESPONSE_LIMIT));
        }
      }
    } catch (error) {
      result.modelError = error.message;
      log({stage, message: `Muse ${kind} response follow-up failed on ${origin}: ${error.message}`});
      break;
    }
    log({stage: 'progress', type: 'recon', routesReviewed: coverage.routesReviewed,
      routesAvailable: coverage.routesAvailable, pathsAccepted: coverage.pathsAccepted});
  }
  return result;
}

export function mergeResponsePatterns(patterns, proposals) {
  for (const proposal of proposals) {
    const known = patterns.find(record => record.pattern === proposal.pattern);
    if (!known) {patterns.push(proposal); continue;}
    known.source.push(...proposal.source);
    if (proposal.responseFacts) known.responseFacts = proposal.responseFacts;
    for (const [name, examples] of Object.entries(proposal.params))
      known.params[name] = [...new Set([...(known.params[name] ?? []), ...examples])];
  }
  return patterns;
}

/** Turn observed GET operation parameters into web leads without inventing a route or parameter. */
export function patternsFromOperations(host) {
  const patterns = new Map();
  for (const operation of host.operations ?? []) {
    if (!['GET', 'UNKNOWN'].includes(operation.method) || typeof operation.path !== 'string' ||
        !operation.path.startsWith('/') || operation.path.startsWith('//') || operation.path.includes('{')) continue;
    const query = (operation.params ?? []).filter(param => (param.in === 'query' ||
      (param.in == null && (operation.source ?? []).includes('client-asset'))) &&
      typeof param.name === 'string' && /^[A-Za-z_][A-Za-z0-9_.-]{0,79}$/.test(param.name) &&
      !credentialQueryKey(param.name));
    if (!query.length && (operation.params ?? []).length) continue;
    const row = patterns.get(operation.path) ?? {pattern: operation.path, methods: ['GET'],
      source: [], params: {}, label: {kind: 'unknown'}};
    row.source.push(...(operation.source ?? []));
    for (const param of query) {
      const values = row.params[param.name] ?? [];
      if (typeof param.example === 'string' && /^[A-Za-z0-9_.-]{1,64}$/.test(param.example) &&
          !values.includes(param.example)) values.push(param.example);
      row.params[param.name] = values;
    }
    patterns.set(operation.path, row);
  }
  return [...patterns.values()];
}

/** Execute the existing deterministic web oracles on each in-scope, authorized descendant host. */
export async function auditDiscoveredHosts(discovery, scope, {requester, ledger, budget = 0,
  infer = null, model = null, remainingModelCalls = () => Infinity,
  researchDeadline = Infinity, log = () => {}, resumeHints = [],
  onFeedbackCheckpoint = () => {}} = {}) {
  const hosts = (discovery?.hosts ?? []).filter(host => host.origin && !host.alias &&
    host.origin !== scope.target.origin && !scope.credentialOrigins.includes(host.origin) &&
    scope.discovery.auditDomains.some(domain => under(host.host, domain)));
  const aggregate = {findings: [], results: [], cut: 0, tested: 0, plan: [], strategyDecisions: [],
    investigations: [], responsePathHints: [], modelCalls: 0,
    modelError: null, modelCoverage: []};
  // Keep pending hints for hosts that fresh discovery does not rediscover.
  // A hint is used only on an exactly matching, explicitly authorized host.
  const pending = new Map(resumeHints.filter(item => item?.origin && safePath(item.path))
    .map(item => [`${item.origin}\0${item.path}`,
      {origin: item.origin, path: item.path, evidenceId: null}]));
  const checkpoint = () => onFeedbackCheckpoint([...pending.values()]);
  checkpoint();
  let remaining = Math.max(0, budget);
  for (const [index, host] of hosts.entries()) {
    const share = Math.ceil(remaining / (hosts.length - index));
    const loopback = ['localhost', '127.0.0.1', '::1'].includes(new URL(host.origin).hostname);
    const hostScope = {...scope, target: {...scope.target, origin: host.origin,
      environment: loopback ? 'local' : scope.target.environment === 'local' ? 'staging' : scope.target.environment}};
    const hostRequester = options => requester({...options, url: new URL(options.url, host.origin).href});
    const surface = {origin: host.origin, patterns: patternsFromOperations(host), mined: host.assets,
      operationNotes: (host.operations ?? []).filter(item => item.purpose || item.parameterMeanings?.length)
        .map(item => ({method: item.method, path: item.path, purpose: item.purpose ?? null,
          parameters: item.parameterMeanings ?? []})),
      modelNotes: [], identity: {verified: false}};
    host.graphql = await inspectGraphql(hostScope, {requester: hostRequester,
      observed: host.operations ?? [], infer, model,
      maxModelPages: model ? Math.floor(Math.max(0, remainingModelCalls()) /
        (hosts.length - index + 1)) : 0, log});
    aggregate.modelCalls += host.graphql.modelCalls;
    aggregate.modelError ??= host.graphql.modelError;
    const responseModelSlots = Math.max(0, remainingModelCalls());
    const responsePages = model && share > 0 && responseModelSlots > 0 ?
      Math.max(1, Math.floor(responseModelSlots / (2 * (hosts.length - index)))) : 0;
    const followup = await followupResponseHints(host.origin, hostScope, surface.patterns,
      {requester: hostRequester, infer, model,
        maxModelPages: responsePages, deadline: researchDeadline, log});
    host.responseFollowup = followup.coverage;
    aggregate.modelCalls += followup.modelCalls;
    aggregate.modelError ??= followup.modelError;
    mergeResponsePatterns(surface.patterns, followup.patterns);
    const maxModelPages = model ? Math.ceil(Math.max(0, remainingModelCalls()) /
      (hosts.length - index)) : 0;
    const checked = await runWebProbes(surface, hostScope, {requester: hostRequester, ledger, budget: share,
      infer, model, maxModelPages, researchDeadline, log});
    const passes = [{run: checked, response: followup.coverage, pass: 'descendant'}];
    const resumedPaths = [...pending.values()].filter(item => item.origin === host.origin &&
      validateUrl(hostScope, item.path, {identity: 'anonymous', method: 'GET'}).ok)
      .map(item => item.path);
    const feedbackSeen = new Set(surface.patterns.map(item => item.pattern)
      .filter(path => !resumedPaths.includes(path)));
    const feedbackUnreviewed = new Map();
    const checkedHints = (checked.responsePathHints ?? [])
      .filter(item => !feedbackSeen.has(item.path));
    let feedbackPending = [...resumedPaths.map(path => ({path, evidenceId: null})),
      ...checkedHints];
    for (const item of checkedHints)
      if (safePath(item.path) &&
          validateUrl(hostScope, item.path, {identity: 'anonymous', method: 'GET'}).ok)
        pending.set(`${host.origin}\0${item.path}`,
          {origin: host.origin, path: item.path, evidenceId: item.evidenceId ?? null});
    checkpoint();
    const feedbackAll = new Set(feedbackPending.map(item => item.path));
    const feedbackCoverage = {hintsAvailable: feedbackAll.size, routesChecked: 0,
      routesAdded: 0, checksExecuted: 0, modelCalls: 0, hintsUntested: 0};
    let hostBudget = Math.max(0, share - checked.tested);
    while (model && feedbackPending.length && hostBudget > 0 &&
        remainingModelCalls() > 0 && Date.now() < researchDeadline) {
      const nextPaths = new Map(feedbackPending.filter(item =>
        !feedbackSeen.has(item.path) &&
        validateUrl(hostScope, item.path, {identity: 'anonymous', method: 'GET'}).ok)
        .map(item => [item.path, item]));
      feedbackPending = [];
      if (!nextPaths.size) break;
      const seeds = [...nextPaths.values()].map(item => ({pattern: item.path,
        methods: ['GET'], source: ['test-response'], params: {},
        label: {kind: 'unknown'}, responseHintEvidence: item.evidenceId}));
      for (const seed of seeds) feedbackSeen.add(seed.pattern);
      const reviewed = await followupResponseHints(host.origin, hostScope, seeds,
        {requester: hostRequester, infer, model, maxModelPages: remainingModelCalls(),
          deadline: researchDeadline, log});
      feedbackCoverage.routesChecked += reviewed.coverage.routesReviewed;
      feedbackCoverage.modelCalls += reviewed.modelCalls;
      aggregate.modelCalls += reviewed.modelCalls;
      aggregate.modelError ??= reviewed.modelError;
      const modelReviewed = new Set(reviewed.modelReviewedPaths);
      for (const seed of seeds) {
        if (!seed.responseFacts || !modelReviewed.has(seed.pattern))
          feedbackUnreviewed.set(seed.pattern,
            {path: seed.pattern, evidenceId: seed.responseHintEvidence});
        else feedbackUnreviewed.delete(seed.pattern);
      }
      mergeResponsePatterns(seeds, reviewed.patterns);
      const fresh = seeds.filter(item => !surface.patterns.some(known =>
        known.pattern === item.pattern));
      mergeResponsePatterns(surface.patterns, fresh);
      feedbackCoverage.routesAdded += fresh.length;
      for (const route of fresh) feedbackSeen.add(route.pattern);
      if (!fresh.length) {
        for (const seed of seeds) if (!feedbackUnreviewed.has(seed.pattern))
          pending.delete(`${host.origin}\0${seed.pattern}`);
        checkpoint();
        continue;
      }
      const next = await runWebProbes({origin: host.origin, identity: surface.identity,
        patterns: fresh}, hostScope, {requester: hostRequester, ledger,
          budget: hostBudget, infer, model, maxModelPages: remainingModelCalls(),
          researchDeadline, log});
      passes.push({run: next, response: reviewed.coverage,
        pass: 'descendant-test-response'});
      hostBudget = Math.max(0, hostBudget - next.tested);
      feedbackCoverage.checksExecuted += next.tested;
      feedbackCoverage.modelCalls += next.modelCalls;
      const nextHints = (next.responsePathHints ?? [])
        .filter(item => !feedbackSeen.has(item.path));
      feedbackPending.push(...nextHints);
      for (const hint of nextHints) feedbackAll.add(hint.path);
      for (const seed of seeds) if (!feedbackUnreviewed.has(seed.pattern))
        pending.delete(`${host.origin}\0${seed.pattern}`);
      for (const item of nextHints)
        if (safePath(item.path) &&
            validateUrl(hostScope, item.path, {identity: 'anonymous', method: 'GET'}).ok)
          pending.set(`${host.origin}\0${item.path}`,
            {origin: host.origin, path: item.path, evidenceId: item.evidenceId ?? null});
      checkpoint();
      feedbackCoverage.hintsAvailable = feedbackAll.size;
    }
    feedbackCoverage.hintsUntested = [...pending.values()]
      .filter(item => item.origin === host.origin).length;
    if (feedbackCoverage.hintsUntested) feedbackCoverage.stopReason =
      !model ? 'model-unavailable' : hostBudget < 1 ? 'task-budget' :
        remainingModelCalls() < 1 ? 'model-budget' :
          Date.now() >= researchDeadline ? 'research-deadline' : 'no-novel-path';
    host.testResponseFollowup = feedbackCoverage;
    const hostTested = passes.reduce((count, item) => count + item.run.tested, 0);
    const hostCut = passes.reduce((count, item) => count + item.run.cut, 0);
    const hostConfirmed = passes.reduce((count, item) => count +
      item.run.findings.filter(finding => finding.verdict === 'confirmed').length, 0);
    host.audit = {status: surface.patterns.length === 0 ? 'no-eligible-leads' :
      share > 0 ? 'active-probes' : 'budget-exhausted',
      leads: surface.patterns.length, tested: hostTested, cut: hostCut,
      confirmed: hostConfirmed};
    remaining -= hostTested;
    for (const {run, response, pass} of passes) {
      aggregate.findings.push(...run.findings);
      aggregate.results.push(...run.results.map(result => ({...result, origin: host.origin})));
      aggregate.plan.push(...run.plan.map(item => ({...item, origin: host.origin})));
      aggregate.strategyDecisions.push(...run.strategyDecisions.map(item =>
        ({...item, origin: host.origin})));
      aggregate.investigations.push(...(run.investigations ?? []).map(item =>
        ({...item, origin: host.origin})));
      aggregate.cut += run.cut;
      aggregate.tested += run.tested;
      aggregate.modelCalls += run.modelCalls;
      aggregate.modelError ??= run.modelError;
      aggregate.modelCoverage.push({origin: host.origin, discoveredVia: pass,
        ...run.modelCoverage,
        responseRoutesAvailable: response.routesAvailable,
        responseRoutesReviewed: response.routesReviewed,
        responsePagesAvailable: response.pagesAvailable,
        responsePagesSent: response.pagesSent,
        responsePathsProposed: response.pathsProposed,
        responsePathsAccepted: response.pathsAccepted,
        responsePathsRejected: response.pathsRejected,
        responsePathsRejectedByReason: response.pathsRejectedByReason});
    }
  }
  aggregate.responsePathHints = [...pending.values()];
  checkpoint();
  return aggregate;
}
