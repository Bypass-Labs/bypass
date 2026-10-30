// Reuse the application recon, planner and swarm on each exact origin the operator allowed credentials to reach.
import {loopback} from '../network.mjs';
import {createRequester} from './scope.mjs';
import {mineOrigin} from './assets.mjs';
import {anonymousPatterns} from './anonymous.mjs';
import {followupResponseHints, mergeResponsePatterns} from './host-audit.mjs';
import {recon, scanSensitivePaths} from './recon.mjs';
import {planTasks, oneAccountMissingAuthCandidate} from './planner.mjs';
import {decide} from './verdict.mjs';
import {runSwarm, reverify, mirror, identityRecheck} from './swarm.mjs';
import {inspectGraphql} from './graphql.mjs';
import {planGraphqlBola} from './graphql-bola.mjs';
import {followupInconclusive} from './followup.mjs';
import {establishIdentities} from './auth.mjs';

export async function auditCredentialOrigins(scope, {discovery = null, env = {}, primary = null, ledger,
  infer = null, model = null, dryRun = false, run = null,
  deadline = Infinity, taskBudget = 0, remainingModelCalls = () => 8, log = () => {}} = {}) {
  const origins = scope.credentialOrigins.filter(origin => origin !== scope.target.origin);
  const records = [];
  let remaining = Math.max(0, taskBudget);
  for (const [index, origin] of origins.entries()) {
    let originScope = structuredClone(scope);
    originScope.target.origin = origin;
    originScope.target.environment = scope.authorizedOrigins?.[origin]?.environment ??
      (loopback(new URL(origin).hostname) ? 'local' : scope.target.environment);
    const allowLocal = loopback(new URL(origin).hostname);
    const anonymousRequester = createRequester(originScope, {ledger, env: {}, allowLocal, run, deadline, log});
    const host = discovery?.hosts?.find(item => item.origin === origin);
    const mined = host?.assets ?? await mineOrigin(origin, {requester: anonymousRequester, assetHosts: originScope.discovery.assetHosts,
      crawlPaths: originScope.include,
      pages: originScope.discover.filter(item => item === '/' || /html?|docs/i.test(item)).slice(0, 5), log});
    const sessions = await establishIdentities(originScope, {mined, requester: anonymousRequester,
      env, ledger, allowLocal, log});
    let sessionEnv = sessions.env, loginSpecs = sessions.loginSpecs;
    originScope = sessions.scope;
    const usable = current => {
      const owner = current.env[current.scope.identities.owner.env];
      const outsider = current.env[current.scope.identities.outsider.env];
      return !!(owner && outsider && owner !== outsider &&
        current.scope.identities.owner.role === current.scope.identities.outsider.role);
    };
    if (!sessionEnv[originScope.identities.owner.env] && primary && usable(primary)) {
      // Shared sessions are useful for SSO-style origins; explicit credentialOrigins permits this reuse.
      originScope = structuredClone(primary.scope);
      originScope.target.origin = origin;
      originScope.target.environment = scope.authorizedOrigins?.[origin]?.environment ??
        (allowLocal ? 'local' : scope.target.environment);
      sessionEnv = primary.env;
      loginSpecs = primary.loginSpecs;
    }
    const requester = createRequester(originScope, {ledger, env: sessionEnv, allowLocal, run, deadline, log});
    let surface, plan, results = [], recheck = null, swarmStats = null;
    const hasOwner = !!sessionEnv[originScope.identities.owner.env];
    const ownerSecret = sessionEnv[originScope.identities.owner.env];
    const outsiderSecret = sessionEnv[originScope.identities.outsider.env];
    const credentialsReady = !!(ownerSecret && outsiderSecret && ownerSecret !== outsiderSecret &&
      originScope.identities.owner.role === originScope.identities.outsider.role);
    if (hasOwner) {
      surface = await recon(originScope, {requester, env: sessionEnv, mined, infer, model,
        maxModelPages: model ? Math.max(0, Math.min(8,
          Math.ceil(remainingModelCalls() / (origins.length - index)))) : 0, log});
      const quota = Math.min(remaining, Math.ceil(taskBudget / Math.max(1, origins.length)));
      const planScope = {...originScope, limits: {...originScope.limits, tasks: quota}};
      plan = await planTasks(surface, planScope, {infer, model, discovery,
        maxModelPages: Math.max(0, Math.min(8, remainingModelCalls())), log});
      if (!credentialsReady || !surface.identity.verified) {
        const supported = task => oneAccountMissingAuthCandidate(task, surface, originScope);
        const unsupported = plan.tasks.filter(task => !supported(task));
        plan.dropped.push(...unsupported.map(task => ({task, reason: !credentialsReady ?
          'requires-distinct-same-role-account' : 'identity-not-verified-on-origin'})));
        plan.tasks = plan.tasks.filter(supported);
      }
    } else {
      const patterns = await anonymousPatterns(originScope, requester, mined);
      const exposureScan = await scanSensitivePaths(originScope, requester, {mined, routes: patterns});
      surface = {origin, identity: {verified: false, ownerVerified: false}, patterns, mined,
        exposures: exposureScan.exposures, exposureStats: exposureScan.stats,
        outOfScope: [], never: [], modelNotes: [], modelCalls: 0, modelError: null};
      const followup = await followupResponseHints(origin, originScope, surface.patterns,
        {requester, infer, model, maxModelPages: model ? Math.max(0, Math.min(3,
          Math.floor(remainingModelCalls() / (origins.length - index + 1)))) : 0,
          kind: 'credential-origin', log});
      mergeResponsePatterns(surface.patterns, followup.patterns);
      surface.anonymousResponseFollowup = {...followup.coverage,
        modelCalls: followup.modelCalls, modelError: followup.modelError};
      surface.modelCalls += followup.modelCalls;
      surface.modelError ??= followup.modelError;
      plan = {tasks: [], dropped: [], untested: [], modelCalls: 0, modelError: null};
    }
    surface.graphql = await inspectGraphql(originScope, {requester,
      observed: [...(mined.endpoints ?? []), ...(surface.patterns ?? []), ...(surface.exposures ?? [])],
      allowOwner: hasOwner,
      infer, model, maxModelPages: model ? Math.max(0, Math.min(4,
        Math.floor(remainingModelCalls() / (origins.length - index + 1)))) : 0, log});
    if (credentialsReady && surface.identity.verified && !dryRun) {
      const graphqlPlan = await planGraphqlBola(originScope, {inventory: surface.graphql,
        surface, requester, budget: Math.max(0, remaining - plan.tasks.length), infer, model,
        maxModelPages: model ? Math.max(0, Math.min(8,
          Math.floor(remainingModelCalls() / (origins.length - index + 1)))) : 0, log});
      surface.graphql.bola = {typeAttempts: graphqlPlan.typeAttempts,
        listAttempts: graphqlPlan.listAttempts, candidates: graphqlPlan.candidates,
        planned: graphqlPlan.tasks.length, cut: graphqlPlan.cut, selected: graphqlPlan.selected,
        modelCoverage: graphqlPlan.modelCoverage, modelCalls: graphqlPlan.modelCalls,
        modelError: graphqlPlan.modelError};
      plan.tasks.push(...graphqlPlan.tasks);
    }
    for (const task of [...plan.tasks, ...plan.untested]) task.id = `t-o${index + 1}-${task.id}`;
    remaining -= plan.tasks.length;
    if (!dryRun && plan.tasks.length) {
      const swarm = await runSwarm(plan.tasks, {requester, surface, scope: originScope, decide, log, run});
      results = swarm.results;
      swarmStats = swarm.stats;
      const followup = await followupInconclusive(results, plan.tasks, surface, originScope,
        {requester, decide, infer, model, budget: Math.max(0, remaining),
          maxModelPages: model ? Math.max(0, Math.min(8,
            Math.floor(remainingModelCalls() / (origins.length - index + 1)))) : 0, log, run});
      surface.accessFollowup = {coverage: followup.coverage, selected: followup.selected,
        rejected: followup.rejected, cut: followup.cut,
        modelCalls: followup.modelCalls, modelError: followup.modelError};
      plan.tasks.push(...followup.tasks);
      results.push(...followup.results);
      remaining -= followup.tasks.length;
      if (followup.stats) {
        for (const field of ['tasks', 'confirmed', 'notReproduced', 'inconclusive', 'blocked', 'public', 'shared'])
          swarmStats[field] = (swarmStats[field] ?? 0) + (followup.stats[field] ?? 0);
        swarmStats.agents = Math.max(swarmStats.agents ?? 0, followup.stats.agents ?? 0);
      }
      if (surface.identity.verified) recheck = await identityRecheck(surface,
        {requester, scope: originScope, results, log});
      await reverify(results, {requester, surface, scope: originScope, decide, log});
      if (credentialsReady && surface.identity.verified) await mirror(results, {requester, surface,
        scope: originScope, log});
      for (const result of results) result.origin = origin;
    }
    if (host) host.authAudit = {identityVerified: !!surface.identity.verified,
      ownerVerified: !!surface.identity.ownerVerified,
      patterns: surface.patterns.length, tasks: plan.tasks.length, tested: results.length};
    records.push({origin, scope: originScope, env: sessionEnv, loginSpecs, requester, mined, surface, plan, results,
      recheck, stats: swarmStats, usable: credentialsReady && !!surface.identity.verified,
      modelError: surface.modelError ?? plan.modelError ?? surface.accessFollowup?.modelError ?? surface.graphql.modelError ??
        surface.graphql.bola?.modelError});
  }
  return records;
}
