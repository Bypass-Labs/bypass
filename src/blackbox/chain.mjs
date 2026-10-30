import fs from 'node:fs';
import path from 'node:path';
import {atomic} from '../store.mjs';
import {execFile, hash} from '../util.mjs';
import {decide} from './verdict.mjs';
import {responseCached} from './poc-runtime.mjs';

const unique = values => [...new Set(values.filter(Boolean))];
const CHAIN_MODEL_CANDIDATES = 24;
const CHAIN_MODEL_BYTES = 20000;
const SEVERITIES = ['info', 'low', 'medium', 'high', 'critical'];
const denied = response => [401, 403, 404].includes(response?.status) &&
  response.headers?.['retry-after'] == null && response.headers?.['x-ratelimit-remaining'] !== '0';

function candidatePairs(results, findings) {
  const proved = new Set(findings.filter(finding => finding.proof).map(finding => finding.task));
  const confirmed = results.filter(item => item.verdict === 'confirmed' &&
    proved.has(item.task.id));
  const lists = confirmed.filter(item => ['list-leak', 'param-filter'].includes(item.task.kind));
  const items = confirmed.filter(item => item.task.kind === 'idor');
  const pairs = [], anonymous = [];
  for (const list of lists) for (const item of items) {
    const itemId = item.task.resourceId;
    if (!itemId || !list.T?.ids?.includes(itemId)) continue;
    pairs.push({list, item, itemId, mode: 'cross-account'});
  }
  const anonymousLists = confirmed.filter(item => item.task.kind === 'missing-auth' &&
    item.task.resourceId == null && item.A?.items != null);
  const anonymousItems = confirmed.filter(item => item.task.kind === 'missing-auth' &&
    item.task.resourceId != null);
  for (const list of anonymousLists) for (const item of anonymousItems) {
    const itemId = item.task.resourceId;
    if (!list.A?.ids?.includes(itemId)) continue;
    anonymous.push({list, item, itemId, mode: 'anonymous'});
  }
  const nested = pair => pair.item.task.pattern.startsWith(
    `${pair.list.task.pattern.replace(/\/$/, '')}/`);
  const baseline = [...pairs.filter(nested).slice(0, 3), ...anonymous.filter(nested).slice(0, 3)]
    .map(pair => ({...pair, by: 'baseline'}));
  const candidates = [...pairs, ...anonymous].filter(pair => !nested(pair));
  return {baseline, candidates};
}

/** Muse may select only already proved, ID-overlapping list/item pairs that the path rule missed. */
export async function proposeChainPairs(candidates, findings, {infer = null, model = null,
  maxModelCalls = 1, log = () => {}} = {}) {
  const coverage = {candidatesAvailable: candidates.length, candidatesSent: 0,
    proposalsReceived: 0, accepted: 0, rejected: 0};
  if (!infer || !model || !candidates.length || maxModelCalls < 1)
    return {pairs: [], modelCalls: 0, modelError: null, coverage};
  const byTask = new Map(findings.filter(item => item.proof && item.task)
    .map(item => [item.task, item.id]));
  const prepared = candidates.slice(0, CHAIN_MODEL_CANDIDATES).map(pair => ({pair, row: {
    yields: byTask.get(pair.list.task.id), reads: pair.item.task.pattern,
    as: pair.mode === 'anonymous' ? 'anonymous' : 'outsider',
    listPath: pair.list.task.pattern, itemPath: pair.item.task.pattern,
    observedSharedIds: 1,
  }})).filter(item => item.row.yields);
  const context = () => ({candidates: prepared.map(item => item.row)});
  while (prepared.length && Buffer.byteLength(JSON.stringify(context())) > CHAIN_MODEL_BYTES)
    prepared.pop();
  if (!prepared.length)
    return {pairs: [], modelCalls: 0,
      modelError: `Chain candidate page exceeds the ${CHAIN_MODEL_BYTES}-byte model context limit.`, coverage};
  coverage.candidatesSent = prepared.length;
  const keyed = new Map();
  for (const {pair, row} of prepared) {
    const listId = row.yields;
    const key = `${listId}\n${pair.item.task.pattern}\n${pair.mode === 'anonymous' ? 'anonymous' : 'outsider'}`;
    if (!keyed.has(key)) keyed.set(key, pair);
  }
  try {
    const response = await infer(model, [{role: 'system', content: 'Select at most three useful list-to-item chains only from the supplied independently proved, overlapping candidates. Return yields as a supplied finding ID, reads as its supplied item pattern, and as as the supplied identity. Do not invent findings, paths, IDs, requests, impact or proof. Code will independently replay every step before reporting a chain.'},
      {role: 'user', content: JSON.stringify(context())}], {schema: {type: 'object', properties: {
      proposals: {type: 'array', maxItems: 3, items: {type: 'object', properties: {
        yields: {type: 'string'}, reads: {type: 'string'},
        as: {type: 'string', enum: ['outsider', 'anonymous']},
        why: {type: 'string', maxLength: 200}},
      required: ['yields', 'reads', 'as', 'why'], additionalProperties: false}}},
    required: ['proposals'], additionalProperties: false}});
    const selected = [], seen = new Set();
    for (const proposal of Array.isArray(response?.proposals) ? response.proposals.slice(0, 3) : []) {
      coverage.proposalsReceived++;
      const key = `${proposal.yields}\n${proposal.reads}\n${proposal.as}`;
      const pair = keyed.get(key);
      if (!pair || seen.has(key)) {coverage.rejected++; continue;}
      selected.push({...pair, by: 'model'});
      seen.add(key);
      coverage.accepted++;
    }
    log({stage: 'chain-plan', message: `Muse selected ${coverage.accepted} of ${coverage.candidatesSent} observed cross-path chain candidates; ${coverage.rejected} proposals were rejected`});
    return {pairs: selected, modelCalls: 1, modelError: null, coverage};
  } catch (error) {
    log({stage: 'chain-plan', message: `Muse chain selection failed: ${error.message}`});
    return {pairs: [], modelCalls: 1, modelError: error.message, coverage};
  }
}

function proofSpec({list, item, itemId, mode}, scope, chainId, loginSpecs) {
  return {schemaVersion: 1, id: chainId,
    kind: mode === 'anonymous' ? 'chain-anonymous-list-item' : 'chain-list-item',
    origin: scope.target.origin,
    include: scope.include, never: scope.never, rps: scope.limits.rps,
    expiresAt: scope.target.environment === 'local' ? null : scope.expiresAt,
    identities: {owner: scope.identities.owner.env, outsider: scope.identities.outsider.env}, auth: scope.identities.auth,
    ...(Object.keys(loginSpecs).length ? {credentialOrigins: scope.credentialOrigins, authBootstrap: loginSpecs} : {}),
    listUrl: list.task.request.url, itemUrl: item.task.request.url, itemId};
}

function writeProof(runDir, spec) {
  const dir = path.join(runDir, 'poc', spec.id);
  fs.mkdirSync(dir, {recursive: true, mode: 0o700});
  atomic(path.join(dir, 'spec.json'), spec);
  const proof = path.join(dir, 'poc.mjs');
  atomic(proof, `import fs from 'node:fs';\nimport {check} from '../runtime.mjs';\nconst spec=JSON.parse(fs.readFileSync(new URL('./spec.json',import.meta.url),'utf8'));\nconst result=await check(spec,process.env);\nconsole.log(JSON.stringify(result));\nprocess.exitCode=process.argv.includes('--expect-fixed')?(result.verdict==='not_reproduced'?0:3):result.verdict==='confirmed'?1:result.verdict==='not_reproduced'?0:3;\n`);
  return proof;
}

/** Replays only confirmed list-to-item edges, then executes a saved compound proof. */
export async function buildChains(results, findings, {requester, surface, scope, runDir, env, ledger,
  loginSpecs = {}, idPrefix = 'c', infer = null, model = null, maxModelCalls = 1,
  log = () => {}}) {
  const chains = [];
  const {baseline, candidates} = candidatePairs(results, findings);
  const selection = await proposeChainPairs(candidates, findings,
    {infer, model, maxModelCalls, log});
  for (const pair of [...baseline, ...selection.pairs]) {
    const id = `${idPrefix}-${String(chains.length + 1).padStart(3, '0')}`;
    const anonymous = pair.mode === 'anonymous';
    const template = anonymous ? 'anonymous-list-to-item-read' : 'list-id-to-item-read';
    const parentFindings = [pair.list.task.id, pair.item.task.id]
      .map(task => findings.find(finding => finding.task === task)).filter(Boolean);
    const baseRank = Math.max(0, ...parentFindings.map(finding => SEVERITIES.indexOf(finding.severity)));
    const baseSeverity = SEVERITIES[baseRank];
    const severity = SEVERITIES[Math.min(baseRank + 1, SEVERITIES.length - 1)];
    const call = (url, identity) => requester({url, identity, method: 'GET', step: 'chain', noCache: true,
      headers: {'cache-control': 'no-cache'}, task: id});
    const listOwner = anonymous ? await call(pair.list.task.control.url, 'owner') : null;
    const list = await call(pair.list.task.request.url, anonymous ? 'anonymous' : 'outsider');
    const O = await call(pair.item.task.control.url, 'owner');
    const T = await call(pair.item.task.request.url, anonymous ? 'anonymous' : 'outsider');
    const A = anonymous ? T : await call(pair.item.task.request.url, 'anonymous');
    const outsider = anonymous ? await call(pair.item.task.request.url, 'outsider') : null;
    const listed = list.status === 200 && /json|\+json/i.test(list.type ?? '') &&
      !responseCached(list) && list.ids?.includes(pair.itemId);
    const listVerdict = anonymous ? decide(pair.list.task,
      {O: listOwner, T: list, A: list, surface, scope}) : null;
    const itemVerdict = decide(pair.item.task, {O, T, A, surface, scope});
    const evidence = unique([listOwner?.evidenceId, list.evidenceId, O.evidenceId,
      T.evidenceId, A.evidenceId, outsider?.evidenceId]);
    const valid = listed && itemVerdict.verdict === 'confirmed' && (anonymous ?
      listVerdict?.verdict === 'confirmed' && denied(outsider) : denied(A));
    if (!valid) {
      chains.push({id, template, selectedBy: pair.by, status: 'inconclusive', severity, baseSeverity,
        findings: [], steps: [{use: 'Fresh list and item replay did not preserve both links', evidence}],
        reach: {observed: 0}});
      continue;
    }
    const spec = proofSpec(pair, scope, id, loginSpecs);
    const proof = writeProof(runDir, spec);
    let completed;
    try {completed = await execFile(process.execPath, [proof], {env, timeout: 20000});}
    catch (error) {completed = {code: 3, stdout: JSON.stringify({verdict: 'inconclusive', reason: error.message})};}
    let replay;
    try {replay = JSON.parse(completed.stdout);} catch {replay = {verdict: 'inconclusive'};}
    const proofEvidence = ledger.append({step: 'poc', task: id, proof: {path: proof,
      specHash: hash(fs.readFileSync(path.join(path.dirname(proof), 'spec.json'))),
      scriptHash: hash(fs.readFileSync(proof)),
      runtimeHash: hash(fs.readFileSync(path.join(runDir, 'poc', 'runtime.mjs'))),
      verdict: replay.verdict, exitCode: completed.code}});
    const proved = completed.code === 1 && replay.verdict === 'confirmed';
    if (!proved) fs.rmSync(path.dirname(proof), {recursive: true, force: true});
    const parentIds = parentFindings.map(finding => finding.id);
    chains.push({id, template, selectedBy: pair.by, status: proved ? 'confirmed' : 'inconclusive',
      severity, baseSeverity,
      findings: parentIds, proof: proved ? proof : null,
      steps: [{use: `Read ${pair.itemId} from the ${anonymous ? 'anonymous' : 'outsider'}-visible list`,
        evidence: unique([listOwner?.evidenceId, list.evidenceId])},
        {use: anonymous ? 'Read that owner item anonymously; another account was denied' :
          'Read that owner item as the outsider; anonymous was denied',
        evidence: unique([O.evidenceId, T.evidenceId, A.evidenceId, outsider?.evidenceId])},
        {use: 'Execute the generated compound proof', evidence: [proofEvidence]}],
      reach: {observed: proved ? 1 : 0, basis: 'one owner item was actually read; no population size was inferred'}});
    if (proved) log({stage: 'chain', message: `${id} confirmed: ${anonymous ? 'anonymous' : 'outsider'} list ID to owner item read`, evidenceId: proofEvidence});
  }
  return {chains, modelCalls: selection.modelCalls, modelError: selection.modelError,
    modelCoverage: selection.coverage};
}

/** A protected proof can itself replay the login bypass that made it reachable. */
export async function buildDerivedPrerequisiteChains(findings, {runDir, env, ledger,
  log = () => {}}) {
  const chains = [];
  const logins = findings.filter(item => item.kind === 'model-auth-login' &&
    item.verdict === 'confirmed' && item.proof && item.webProof);
  for (const sink of findings) {
    if (sink.verdict !== 'confirmed' || !sink.proof || !sink.webProof?.derivedLogin)
      continue;
    const login = logins.find(item => new URL(item.url).origin === new URL(sink.url).origin &&
      JSON.stringify(item.webProof) === JSON.stringify(sink.webProof.derivedLogin));
    if (!login) continue;
    const id = `c-d-${String(chains.length + 1).padStart(3, '0')}`;
    const original = path.join(path.dirname(sink.proof), 'spec.json');
    const spec = {...JSON.parse(fs.readFileSync(original, 'utf8')), id};
    const proof = writeProof(runDir, spec);
    let completed, replay;
    try {
      completed = await execFile(process.execPath, [proof], {env, timeout: 20000});
      replay = JSON.parse(completed.stdout);
    } catch (error) {
      completed = {code: 3};
      replay = {verdict: 'inconclusive', reason: error.message};
    }
    const controls = Array.isArray(replay.controls) ? replay.controls : [];
    const freshLogin = controls.some(item => item.label === 'fresh-login-boundary' &&
      item.verdict === 'confirmed');
    const protectedBoundary = controls.some(item => item.label === 'protected-route-boundary' &&
      denied({status: item.anonymousStatus}) && denied({status: item.invalidBearerStatus}));
    const proved = completed.code === 1 && replay.verdict === 'confirmed' &&
      freshLogin && protectedBoundary;
    if (!proved) fs.rmSync(path.dirname(proof), {recursive: true, force: true});
    const event = ledger.append({step: proved ? 'poc' : 'chain', task: id,
      template: 'derived-login-to-protected-impact',
      parents: [login.id, sink.id], verdict: proved ? 'confirmed' : 'inconclusive',
      ...(proved ? {proof: {path: proof,
        specHash: hash(fs.readFileSync(path.join(path.dirname(proof), 'spec.json'))),
        scriptHash: hash(fs.readFileSync(proof)),
        runtimeHash: hash(fs.readFileSync(path.join(runDir, 'poc', 'runtime.mjs'))),
        verdict: replay.verdict, exitCode: completed.code}} :
        {reason: replay.reason ?? 'The fresh compound proof lacked a login or denied-route control'})});
    const baseRank = Math.max(0, SEVERITIES.indexOf(login.severity), SEVERITIES.indexOf(sink.severity));
    chains.push({id, template: 'derived-login-to-protected-impact', selectedBy: 'baseline',
      status: proved ? 'confirmed' : 'inconclusive',
      severity: SEVERITIES[baseRank], baseSeverity: SEVERITIES[baseRank],
      findings: proved ? [login.id, sink.id] : [], proof: proved ? proof : null,
      steps: [
        {use: 'Fresh invalid-password login established a session',
          evidence: unique([...(login.evidence ?? []), ...(login.confirmation ?? [])])},
        {use: 'That session reached a protected route and reproduced its independent impact oracle; anonymous and invalid sessions were denied',
          evidence: unique([...(sink.evidence ?? []), ...(sink.confirmation ?? [])])},
        {use: proved ? 'Execute the generated compound proof' :
          'Fresh compound proof did not preserve every required control', evidence: [event]},
      ], reach: {observed: proved ? 1 : 0,
        basis: 'one protected finding was replayed through the proved login bypass; no wider reach was inferred'}});
    if (proved) log({stage: 'chain', message: `${id} confirmed: derived login to protected impact`,
      evidenceId: event});
  }
  return chains;
}
