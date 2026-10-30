import fs from 'node:fs';
import path from 'node:path';
import {atomic} from '../store.mjs';
import {execFile, need, hash} from '../util.mjs';
import {verifyLedger} from './ledger.mjs';
import {blackboxEnvironment} from './accounts.mjs';

// Capture the proof runtime with the audit process's code version. Reading these
// files only at proof time can mix versions if the CLI is edited during a run.
const PROOF_SOURCES = Object.freeze({
  runtime: fs.readFileSync(new URL('./poc-runtime.mjs', import.meta.url), 'utf8'),
  boundary: fs.readFileSync(new URL('./boundary-oracle.mjs', import.meta.url), 'utf8'),
  content: fs.readFileSync(new URL('./content-boundary.mjs', import.meta.url), 'utf8'),
});

const WEB_PROOF_KINDS = new Set(['open-redirect', 'host-header-redirect', 'jwt-unsigned',
  'anonymous-credential-data', 'derived-private-read',
  'http-parameter-pollution', 'cors-reflection', 'ssrf-loopback', 'remote-content-use',
  'xss-reflected', 'html-injection',
  'xss-dom-fragment', 'ssti-arithmetic', 'sql-boolean', 'nosql-operator-bypass',
  'command-output', 'path-traversal-hosts', 'xxe-hosts', 'xxe-body-hosts',
  'crlf-header', 'public-private-key', 'public-api-credential', 'model-differential',
  'model-json-differential', 'model-http-sequence', 'model-browser-execution', 'model-access-boundary',
  'model-state-change', 'xss-stored',
  'public-session-token', 'model-auth-login']);
const PARAMETER_PROOF_KINDS = new Set(['host-header-redirect', 'jwt-unsigned',
  'anonymous-credential-data',
  'http-parameter-pollution', 'ssrf-loopback', 'remote-content-use', 'xss-reflected',
  'html-injection', 'xss-dom-fragment',
  'ssti-arithmetic', 'sql-boolean', 'nosql-operator-bypass', 'command-output',
  'path-traversal-hosts', 'xxe-hosts', 'xxe-body-hosts', 'crlf-header', 'public-private-key',
  'public-api-credential', 'model-differential', 'model-json-differential',
  'xss-stored', 'public-session-token']);

function reviewedReadInputs(surface, subject, origin) {
  if (!['GET', 'HEAD'].includes(subject?.method) || subject.placement !== 'query')
    return [];
  const parameters = new Set();
  let routeSeen = false;
  const add = (raw, methods, names) => {
    let url;
    try {url = new URL(raw, origin);} catch {return;}
    if (url.origin !== origin || url.pathname !== subject.path ||
        !methods.includes(subject.method)) return;
    routeSeen = true;
    for (const name of [...names, ...url.searchParams.keys()])
      if (typeof name === 'string') parameters.add(name);
  };
  for (const item of surface?.patterns ?? []) {
    const path = item.pattern?.includes('{') ? item.representative : item.pattern;
    if (typeof path === 'string') add(path,
      item.methods?.length ? item.methods : ['GET'], Object.keys(item.params ?? {}));
  }
  for (const item of surface?.mined?.endpoints ?? []) if (typeof item.path === 'string')
    add(item.path, [item.method === 'UNKNOWN' ? 'GET' : item.method],
      (item.params ?? []).map(entry => typeof entry === 'string' ? entry : entry?.name));
  return routeSeen ? [{path: subject.path, methods: [subject.method],
    parameters: [...parameters]}] : [];
}

function specFor(finding, result, surface, scope) {
  const pattern = surface.patterns.find(item => item.pattern === finding.pattern);
  const outsider = new Set(pattern?.ids?.outsiderIds ?? []);
  const ownerOnlyIds = (pattern?.ids?.ownerIds ?? []).filter(id => !outsider.has(id));
  const baseline = pattern?.fingerprint?.outsider;
  const before = new Set(Object.keys({...baseline?.shape, ...baseline?.fields}));
  const after = Object.keys({...result.T?.shape, ...result.T?.fields});
  const extraFields = after.filter(field => !before.has(field) && /email|phone|address|ssn|dob|token|secret|password|salary|balance/i.test(field));
  const principal = value => value && typeof value === 'object' ? value.value : value;
  const owner = principal(surface.identity?.principals?.owner);
  const other = principal(surface.identity?.principals?.outsider);
  const ownerHash = owner == null ? null : hash(owner);
  const outsiderHash = other == null ? null : hash(other);
  const boundaryField = finding.kind === 'missing-auth' && result.task.request.as === 'outsider' &&
    ownerHash && outsiderHash && Object.keys(result.O?.ownership ?? {}).find(field =>
      result.O.ownership[field] === ownerHash && result.T?.ownership?.[field] === outsiderHash);
  const sensitiveFields = Object.keys(result.O?.shape ?? {}).filter(field =>
    /^(email|phone|address|ssn|dob|iban|card|token|secret|password|salary|balance)$/i.test(field));
  const accountBoundary = boundaryField && sensitiveFields.length ?
    {field: boundaryField, ownerHash, outsiderHash, sensitiveFields} : null;
  const oneAccountPrivateFields = finding.kind === 'missing-auth' && result.task.request.as === 'anonymous' &&
    result.task.resourceId && surface.identity?.ownerVerified && !surface.identity?.verified ?
    Object.keys(result.O?.shape ?? {}).filter(field =>
      /^(ssn|dob|iban|card|token|secret|password|salary|balance)$/i.test(field)) : [];
  const oneAccountOwnerField = oneAccountPrivateFields.length &&
    pattern?.private?.[result.task.resourceId]?.by === 'ownership-field' ?
    pattern.private[result.task.resourceId].field : null;
  const oneAccountBoundary = oneAccountOwnerField && result.O?.ownership?.[oneAccountOwnerField] ?
    {field: oneAccountOwnerField, ownerHash: result.O.ownership[oneAccountOwnerField]} : null;
  return {schemaVersion: 1, id: finding.id, kind: finding.kind, origin: scope.target.origin,
    include: scope.include, never: scope.never, rps: scope.limits.rps,
    expiresAt: scope.target.environment === 'local' ? null : scope.expiresAt,
    identities: {owner: scope.identities.owner.env, outsider: scope.identities.outsider.env}, auth: scope.identities.auth,
    identityPath: scope.identities.identityPath, identityCookieName: scope.identities.identityCookieName,
    control: result.task.control, request: result.task.request, ownerOnlyIds, extraFields,
    accountBoundary, oneAccountPrivateFields, oneAccountBoundary,
    graphql: result.task.graphql ?? null, rule: result.rule};
}

/** Generate and execute one reviewable Node proof per confirmed access-control finding. */
export async function proveFindings(findings, results, {runDir, surface, scope, originSurfaces = {}, originContexts = {},
  env, loginSpecs = {}, ledger, web = null, log = () => {}}) {
  const dir = path.join(runDir, 'poc');
  fs.mkdirSync(dir, {recursive: true, mode: 0o700});
  const runtime = path.join(dir, 'runtime.mjs');
  const boundaryOracle = path.join(dir, 'boundary-oracle.mjs');
  const contentOracle = path.join(dir, 'content-boundary.mjs');
  atomic(runtime, PROOF_SOURCES.runtime);
  atomic(boundaryOracle, PROOF_SOURCES.boundary);
  atomic(contentOracle, PROOF_SOURCES.content);
  const kept = [];
  let activeProofs = 0, proofWorkerPeak = 0, parallelProofs = 0;
  const runProof = async ({proofPath, context}) => {
    activeProofs++;
    proofWorkerPeak = Math.max(proofWorkerPeak, activeProofs);
    try {
      const completed = await execFile(process.execPath, [proofPath],
        {env: context.env, timeout: 20000});
      if (!completed.stdout?.trim()) throw Error(/ERR_MODULE_NOT_FOUND/.test(completed.stderr ?? '') ?
        'Generated proof runtime is missing a module.' :
        `Generated proof process exited ${completed.code} without a JSON result.`);
      return {exitCode: completed.code, result: JSON.parse(completed.stdout)};
    } catch (error) {
      return {exitCode: 3, result: {verdict: 'inconclusive', reason: error.message}};
    } finally {activeProofs--;}
  };
  const commitProof = ({finding, result, webOrigin, proofDir, specPath, proofPath}, proof) => {
    const evidenceId = ledger.append({step: 'poc', task: result?.task?.id ?? null, proof: {path: proofPath,
      specHash: hash(fs.readFileSync(specPath)), scriptHash: hash(fs.readFileSync(proofPath)),
      runtimeHash: hash(fs.readFileSync(runtime)),
      oracleHash: hash(fs.readFileSync(boundaryOracle)),
      contentOracleHash: hash(fs.readFileSync(contentOracle)),
      verdict: proof.result.verdict, exitCode: proof.exitCode}});
    if (proof.exitCode === 1 && proof.result.verdict ===
        (finding.kind === 'model-http-sequence' ? 'observed' : 'confirmed')) {
      finding.proof = proofPath;
      finding.confirmation = [...finding.confirmation, evidenceId];
      kept.push(finding);
    } else {
      fs.rmSync(proofDir, {recursive: true, force: true});
      if (result) {
        result.verdict = 'inconclusive';
        result.rule = 'inconclusive/poc';
        result.reason = `Generated proof did not reproduce: ${proof.result.reason ?? proof.result.verdict}`;
        result.evidence.push(evidenceId);
        log({stage: 'poc', message: `${finding.id} downgraded: ${result.reason}`});
      } else {
        if (WEB_PROOF_KINDS.has(finding.kind)) {
          const lead = web?.results?.find(item => item.lead.path === finding.pattern &&
            item.origin === webOrigin &&
            (['model-http-sequence', 'model-browser-execution'].includes(finding.kind) ?
              item.kind === finding.kind && item.lead.path === finding.pattern :
            finding.kind === 'model-access-boundary' ?
              item.kind === finding.kind &&
                item.lead.path === finding.webProof.subject?.path :
            PARAMETER_PROOF_KINDS.has(finding.kind) ?
              item.kind === finding.kind && item.lead.parameter === finding.webProof.parameter :
              finding.kind === 'cors-reflection' ? item.kind === 'cors-reflection' :
              item.lead.parameter === new URL(finding.url).searchParams.keys().next().value));
          if (lead) Object.assign(lead, {verdict: 'inconclusive',
            reason: `Generated proof did not reproduce: ${proof.result.reason ?? proof.result.verdict}`});
        }
        log({stage: 'poc', message: `${finding.id} proof did not reproduce: ${proof.result.reason ?? proof.result.verdict}`});
      }
    }
  };
  let pendingReads = [];
  const flushReads = async () => {
    if (!pendingReads.length) return;
    const agentLimit = Number(scope.limits?.agents) || 1;
    const minimumRps = Math.min(...pendingReads.map(item => Number(item.spec.rps) || 1));
    const width = Math.min(pendingReads.length, agentLimit >= 2 && minimumRps >= 2 ? 2 : 1);
    if (width === 2) {
      const perProofRps = Math.max(0.5, minimumRps / 4);
      for (const item of pendingReads) {
        item.spec.rps = perProofRps;
        atomic(item.specPath, item.spec);
      }
      parallelProofs += pendingReads.length;
    }
    for (let index = 0; index < pendingReads.length; index += width) {
      const batch = pendingReads.slice(index, index + width);
      const proofs = await Promise.all(batch.map(runProof));
      batch.forEach((item, offset) => commitProof(item, proofs[offset]));
    }
    pendingReads = [];
  };
  for (const finding of findings) {
    const result = results.find(item => item.task?.id === finding.task);
    const webOrigin = new URL(finding.url).origin;
    const webHost = new URL(finding.url).hostname;
    const remoteHttp = new URL(finding.url).protocol === 'http:' && scope.domains.some(domain =>
      webHost === domain || webHost.endsWith(`.${domain}`));
    const context = originContexts[result?.origin ?? webOrigin] ?? {scope, env, loginSpecs};
    const proofScope = result ? context.scope.target.origin === (result.origin ?? scope.target.origin) ?
      context.scope : {...scope, target: {...scope.target, origin: result.origin ?? scope.target.origin}} : context.scope;
    const proofSurface = result ? originSurfaces[result.origin] ?? surface : surface;
    const spec = result ? specFor(finding, result, proofSurface, proofScope) : WEB_PROOF_KINDS.has(finding.kind) ?
      {schemaVersion: 1, id: finding.id, kind: finding.kind, origin: webOrigin,
        include: ['public-private-key', 'public-api-credential'].includes(finding.kind) ? ['/'] : context.scope.include,
        never: context.scope.never, rps: context.scope.limits.rps,
        expiresAt: context.scope.target.environment === 'local' ? null : context.scope.expiresAt,
        allowRemoteHttp: remoteHttp && (['public-private-key', 'public-api-credential'].includes(finding.kind) ||
          scope.discovery.auditDomains.some(domain => webHost === domain || webHost.endsWith(`.${domain}`))),
        identities: {owner: context.scope.identities.owner.env, outsider: context.scope.identities.outsider.env},
        auth: finding.webProof?.auth ?? finding.webProof?.derivedLogin?.auth ??
          context.scope.identities.auth,
        identityPath: context.scope.identities.identityPath,
        identityCookieName: context.scope.identities.identityCookieName,
        ...finding.webProof,
        ...(finding.kind === 'xss-dom-fragment' ? {
          domScriptBytes: context.scope.limits.domScriptBytes,
        } : {}),
        ...(finding.kind === 'model-access-boundary' ? {
          reviewedPostFields: (proofSurface?.jsonBodyOperations ?? [])
            .find(item => item.path === finding.webProof.subject?.path)?.fields ?? [],
          reviewedGetInputs: (proofSurface?.patterns ?? []).filter(item =>
            (item.fingerprint?.anonymous?.status === 200 ||
              item.responseFacts?.anonymousStatus === 200 ||
              item.responseFacts?.identity !== 'derived-session' &&
                item.responseFacts?.status === 200) &&
            (!Array.isArray(item.methods) || !item.methods.length || item.methods.includes('GET')))
            .map(item => ({path: item.pattern?.includes('{') ? item.representative : item.pattern,
              parameters: Object.keys(item.params ?? {})}))
            .filter(item => item.path === finding.webProof.subject?.path),
        } : {}),
        ...(finding.kind === 'model-auth-login' ? {
          reviewedAuthPosts: (proofSurface?.authBodyOperations ?? [])
            .filter(item => item.path === finding.webProof.loginPath &&
              item.method === 'POST' && item.contentType === 'application/json' &&
              item.usernameField === finding.webProof.userField &&
              item.passwordField === finding.webProof.passwordField)
            .map(item => ({path: item.path, usernameField: item.usernameField,
              passwordField: item.passwordField})),
        } : {}),
        ...(['model-http-sequence', 'model-browser-execution', 'model-access-boundary',
          'model-state-change'].includes(finding.kind) ||
          ['ssrf-loopback', 'remote-content-use'].includes(finding.kind) &&
            finding.webProof?.subject ? {
          reviewedCallbackFields: ['jsonBodyOperations', 'formBodyOperations',
            'xmlBodyOperations', 'methodOperations'].flatMap(property =>
              (proofSurface?.[property] ?? []).filter(item =>
                item.method === finding.webProof.subject.method &&
                item.path === finding.webProof.subject.path &&
                (item.placement ?? ({jsonBodyOperations: 'json',
                  formBodyOperations: 'form', xmlBodyOperations: 'xml'})[property]) ===
                  finding.webProof.subject.placement)
                .map(item => item.fields ?? [])).flat(),
        } : {}),
        ...((['model-http-sequence', 'model-browser-execution', 'model-access-boundary',
          'model-state-change'].includes(finding.kind) &&
            (finding.kind !== 'model-access-boundary' ||
              ['sequence-exact-body', 'sequence-json-field']
                .includes(finding.webProof.comparison)) ||
          ['ssrf-loopback', 'remote-content-use'].includes(finding.kind) &&
            finding.webProof?.subject) ? {
          reviewedReadInputs: reviewedReadInputs(proofSurface,
            finding.webProof.subject, webOrigin),
          reviewedOperations: (proofSurface?.methodOperations ?? [])
            .filter(item => ['POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'].includes(item.method) &&
              ((context.scope.probes?.writeOperations ?? []).some(review =>
                review.method === item.method && review.path === item.path &&
                review.placement === item.placement) ||
              context.scope.localAutoMethodContracts?.[
                `${item.method} ${item.placement} ${item.path}`] != null))
            .map(item => ({method: item.method, path: item.path,
              placement: item.placement, fields: item.fields ?? [],
              requiredFields: item.requiredFields ?? [],
              contentType: item.contentType ?? null,
              rootElement: item.rootElement ?? null})),
        } : {}),
        ...(['model-http-sequence', 'model-browser-execution', 'model-access-boundary', 'model-state-change',
          'model-auth-login',
          'ssrf-loopback', 'remote-content-use',
          'model-json-differential', 'xss-stored'].includes(finding.kind) ? {
          reviewedPostPaths: {
            json: [...(context.scope.probes?.jsonPostPaths ?? [])],
            xml: [...(context.scope.probes?.xmlPostPaths ?? [])],
            form: [...(context.scope.probes?.formPostPaths ?? [])]},
          targetEnvironment: context.scope.target.environment,
          xmlExternalEntity: context.scope.probes?.xmlExternalEntity === true,
        } : {}),
        ...(finding.webProof?.derivedLogin ? {
          targetEnvironment: context.scope.target.environment,
          reviewedAuthPosts: (proofSurface?.authBodyOperations ?? [])
            .filter(item => item.path === finding.webProof.derivedLogin.loginPath &&
              item.method === 'POST' && item.contentType === 'application/json')
            .map(item => ({path: item.path,
              usernameField: item.usernameField,
              passwordField: item.passwordField})),
        } : {})} : finding.kind === 'exposure' ?
      {schemaVersion: 1, id: finding.id, kind: 'exposure', origin: webOrigin, include: ['/'], never: scope.never,
        rps: scope.limits.rps, expiresAt: scope.target.environment === 'local' ? null : scope.expiresAt,
        allowRemoteHttp: remoteHttp,
        identities: {}, auth: scope.identities.auth,
        request: {url: finding.url, as: 'anonymous', method: 'GET'},
        signature: surface?.exposures?.find(item => item.path === finding.pattern)?.signature ?? null,
        ranged: surface?.exposures?.find(item => item.path === finding.pattern)?.ranged === true,
        rangeHeader: surface?.exposures?.find(item => item.path === finding.pattern)?.rangeHeader ?? null,
        acceptHtml: surface?.exposures?.find(item => item.path === finding.pattern)?.acceptHtml === true,
        expectedHash: finding.exposureHash} : null;
    if (!spec) continue;
    if (['model-http-sequence', 'model-browser-execution', 'model-state-change'].includes(finding.kind) ||
        Object.keys(context.loginSpecs).length)
      spec.credentialOrigins = context.scope.credentialOrigins;
    if (Object.keys(context.loginSpecs).length) {
      spec.authBootstrap = context.loginSpecs;
    }
    const proofDir = path.join(dir, finding.id);
    const specPath = path.join(proofDir, 'spec.json');
    const proofPath = path.join(proofDir, 'poc.mjs');
    atomic(specPath, spec);
    atomic(proofPath, `import fs from 'node:fs';\nimport {check} from '../runtime.mjs';\nconst spec=JSON.parse(fs.readFileSync(new URL('./spec.json',import.meta.url),'utf8'));\nconst result=await check(spec,process.env);\nconsole.log(JSON.stringify(result));\nconst reproduced=spec.kind==='model-http-sequence'?result.verdict==='observed':result.verdict==='confirmed';\nprocess.exitCode=process.argv.includes('--expect-fixed')?(result.verdict==='not_reproduced'?0:3):reproduced?1:result.verdict==='not_reproduced'?0:3;\n`);
    const job = {finding, result, webOrigin, proofDir, specPath, proofPath, context,
      spec};
    if (spec.kind === 'exposure' && spec.request?.method === 'GET' &&
        spec.request.as === 'anonymous' && !spec.authBootstrap) {
      pendingReads.push(job);
      continue;
    }
    await flushReads();
    commitProof(job, await runProof(job));
  }
  await flushReads();
  ledger.append({step: 'poc', kind: 'proof-schedule', workerPeak: proofWorkerPeak,
    parallelProofs, total: findings.length});
  return kept;
}

function recordedRun(root, run) {
  need(/^bx-\d{8}-[0-9a-f]{8}$/.test(run), 'Use a recorded black-box run ID.');
  const runDir = path.join(root, '.bypass/runs', run);
  const stateFile = path.join(runDir, 'run.json');
  need(fs.existsSync(stateFile), `Black-box run not found: ${run}.`);
  const state = JSON.parse(fs.readFileSync(stateFile, 'utf8'));
  const integrity = verifyLedger(path.join(runDir, 'evidence.jsonl'));
  need(integrity.ok, `Evidence ledger is broken at ${integrity.brokenAt}.`, 3);
  const proofs = fs.readFileSync(path.join(runDir, 'evidence.jsonl'), 'utf8').split('\n').filter(Boolean)
    .map(line => JSON.parse(line)).filter(record => record.step === 'poc' && record.proof?.path);
  const canonical = value => {
    try { return fs.realpathSync(value); } catch { return path.resolve(value); }
  };
  const proofByPath = new Map(proofs.map(record => [canonical(record.proof.path), record.proof]));
  const pocDir = path.join(runDir, 'poc');
  for (const entry of fs.existsSync(pocDir) ? fs.readdirSync(pocDir, {withFileTypes: true}).filter(item => item.isDirectory()) : []) {
    const dir = path.join(pocDir, entry.name);
    const script = path.join(dir, 'poc.mjs');
    const record = proofByPath.get(canonical(script));
    need(record && fs.existsSync(script) && fs.existsSync(path.join(dir, 'spec.json')) &&
      record.specHash === hash(fs.readFileSync(path.join(dir, 'spec.json'))) &&
      record.scriptHash === hash(fs.readFileSync(script)) &&
      record.runtimeHash === hash(fs.readFileSync(path.join(pocDir, 'runtime.mjs'))),
    `Recorded proof ${entry.name} differs from the sealed ledger artifact.`, 3);
    if (record.oracleHash) need(fs.existsSync(path.join(pocDir, 'boundary-oracle.mjs')) &&
      record.oracleHash === hash(fs.readFileSync(path.join(pocDir, 'boundary-oracle.mjs'))),
    `Recorded proof ${entry.name} has a modified boundary oracle.`, 3);
    if (record.contentOracleHash) need(fs.existsSync(path.join(pocDir, 'content-boundary.mjs')) &&
      record.contentOracleHash === hash(fs.readFileSync(path.join(pocDir, 'content-boundary.mjs'))),
    `Recorded proof ${entry.name} has a modified content oracle.`, 3);
  }
  return {runDir, state, integrity};
}

function reportedProofGroups(runDir) {
  const file = path.join(runDir, 'findings.json');
  if (!fs.existsSync(file)) return {findings: null, corroborates: new Map()};
  let findings;
  try {findings = JSON.parse(fs.readFileSync(file, 'utf8'));} catch {return {findings: null, corroborates: new Map()};}
  if (!Array.isArray(findings)) return {findings: null, corroborates: new Map()};
  const corroborates = new Map(findings.flatMap(finding =>
    (finding.corroboratingProofs ?? []).map(proof => [proof.id, finding.id])));
  return {findings: findings.length, corroborates};
}

/** Re-execute every saved proof after a fix. The retest artifact never contains credential values. */
export async function verifyRun(root, run, {env = process.env} = {}) {
  const {runDir, integrity} = recordedRun(root, run);
  const groups = reportedProofGroups(runDir);
  const pocDir = path.join(runDir, 'poc');
  const entries = fs.existsSync(pocDir) ? fs.readdirSync(pocDir, {withFileTypes: true}).filter(item => item.isDirectory()) : [];
  need(entries.length > 0, `Run ${run} has no generated proofs.`, 3);
  const proofs = [];
  for (const entry of entries) {
    const file = path.join(pocDir, entry.name, 'poc.mjs');
    const spec = JSON.parse(fs.readFileSync(path.join(pocDir, entry.name, 'spec.json'), 'utf8'));
    // Historical sealed runtimes may still endorse this unsupported oracle.
    // Keep the artifact intact, but do not treat it as a confirmed bug today.
    if (spec.kind === 'derived-private-read') {
      proofs.push({id: entry.name, kind: spec.kind, verdict: 'inconclusive',
        exitCode: 3, controls: [],
        reason: 'A self-declared private field does not establish an independent access policy or denial control'});
      continue;
    }
    let completed;
    try {
      const proofEnv = await blackboxEnvironment(root, {target: {origin: spec.origin},
        identities: {owner: {env: spec.identities?.owner}, outsider: {env: spec.identities?.outsider},
          auth: spec.auth, identityPath: spec.identityPath}}, {env});
      completed = await execFile(process.execPath, [file], {env: proofEnv, timeout: 20000});
    }
    catch {
      proofs.push({id: entry.name, kind: spec.kind, verdict: 'inconclusive',
        exitCode: 3, controls: [], reason: 'Proof execution failed or exceeded its time/output limit.'});
      continue;
    }
    let response;
    try { response = JSON.parse(completed.stdout); } catch { response = {verdict: 'inconclusive', reason: 'proof output was not JSON'}; }
    const observation = spec.kind === 'model-http-sequence';
    const reproducedBehavior = observation && ['observed', 'confirmed'].includes(response.verdict);
    proofs.push({id: entry.name, kind: spec.kind,
      ...(groups.corroborates.has(entry.name) ?
        {corroborates: groups.corroborates.get(entry.name)} : {}),
      verdict: reproducedBehavior ? completed.code === 1 ? 'observed' : 'inconclusive' : response.verdict,
      ...(observation ? {impact: 'unverified'} : {}),
      exitCode: completed.code, controls: response.controls ?? [], reason: response.reason ?? null});
  }
  const retest = {run, at: new Date().toISOString(), integrity, proofs};
  atomic(path.join(runDir, 'retest.json'), retest);
  const exitCode = proofs.some(item => item.verdict === 'confirmed' ||
    item.kind === 'model-http-sequence' && item.verdict === 'observed' && item.exitCode === 1) ? 1 :
    proofs.every(item => item.verdict === 'not_reproduced') ? 0 : 3;
  return {kind: 'blackbox-verify', run, runDir, integrity, proofs,
    reportedFindings: groups.findings ?? proofs.length, exitCode};
}

/** Export ordinary Node tests whose safe behavior passes after the application is fixed. */
export function exportRun(root, run, {out = null} = {}) {
  const {runDir, integrity} = recordedRun(root, run);
  const groups = reportedProofGroups(runDir);
  const pocDir = path.join(runDir, 'poc');
  const entries = fs.existsSync(pocDir) ? fs.readdirSync(pocDir, {withFileTypes: true}).filter(item => item.isDirectory()) : [];
  need(entries.length > 0, `Run ${run} has no generated proofs.`, 3);
  const output = out ? path.resolve(root, out) : path.join(root, 'tests/security/blackbox');
  fs.mkdirSync(output, {recursive: true});
  const runtime = path.join(output, 'blackbox-runtime.mjs');
  const source = fs.readFileSync(path.join(pocDir, 'runtime.mjs'), 'utf8');
  need(!fs.existsSync(runtime) || fs.readFileSync(runtime, 'utf8') === source,
    `${runtime} differs from this run's proof runtime; choose another --out directory.`);
  atomic(runtime, source);
  const boundarySource = path.join(pocDir, 'boundary-oracle.mjs');
  if (fs.existsSync(boundarySource)) {
    const oracle = path.join(output, 'boundary-oracle.mjs');
    const source = fs.readFileSync(boundarySource, 'utf8');
    need(!fs.existsSync(oracle) || fs.readFileSync(oracle, 'utf8') === source,
      `${oracle} differs from this run's proof oracle; choose another --out directory.`);
    atomic(oracle, source);
  }
  const contentSource = path.join(pocDir, 'content-boundary.mjs');
  if (fs.existsSync(contentSource)) {
    const oracle = path.join(output, 'content-boundary.mjs');
    const source = fs.readFileSync(contentSource, 'utf8');
    need(!fs.existsSync(oracle) || fs.readFileSync(oracle, 'utf8') === source,
      `${oracle} differs from this run's content oracle; choose another --out directory.`);
    atomic(oracle, source);
  }
  const files = [], skippedProofs = [];
  for (const entry of entries) {
    const spec = JSON.parse(fs.readFileSync(path.join(pocDir, entry.name, 'spec.json'), 'utf8'));
    if (spec.kind === 'derived-private-read') {
      skippedProofs.push({id: entry.name, reason: 'independent access policy or denial control is missing'});
      continue;
    }
    const file = path.join(output, `${run}-${entry.name}.test.mjs`);
    need(!fs.existsSync(file), `Regression test already exists: ${file}.`);
    const testSource = `import test from 'node:test';\nimport assert from 'node:assert/strict';\nimport {check} from './blackbox-runtime.mjs';\nconst spec=${JSON.stringify(spec)};\ntest(${JSON.stringify(`${entry.name} ${spec.kind} is fixed`)},async()=>{\n  const result=await check(spec,process.env);\n  assert.equal(result.verdict,'not_reproduced',JSON.stringify(result));\n});\n`;
    atomic(file, testSource);
    files.push(file);
  }
  return {kind: 'blackbox-export', run, output, files, skippedProofs, integrity,
    reportedFindings: groups.findings ?? files.length,
    corroboratingTests: files.filter(file => groups.corroborates.has(
      path.basename(file).match(/-(f-\d+)\.test\.mjs$/)?.[1])).length,
    exitCode: files.length ? 0 : 3};
}
