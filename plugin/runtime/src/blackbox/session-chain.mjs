// A Muse-selected, read-only account sequence: a public JSON field must expose the
// operator's own bearer token, which then reproduces the owner's private response.
import {randomBytes} from 'node:crypto';
import {MODEL_RESPONSE_BYTES, requestFailureVerdict, responseSizeReason} from './response-size.mjs';
import {validateUrl} from './scope.mjs';
import {modelJsonPointer, responseCached, validModelJsonPointer} from './poc-runtime.mjs';

const unique = values => [...new Set(values.filter(Boolean))];
const brief = (value, limit = 300) => String(value ?? '').replace(/[\x00-\x1f\x7f]/g, ' ').slice(0, limit);
const exactGet = record => typeof record?.pattern === 'string' &&
  record.pattern.startsWith('/') && !/[{}?#%]/.test(record.pattern) &&
  (!Array.isArray(record.methods) || !record.methods.length || record.methods.includes('GET'));
const denied = response => [401, 403, 404].includes(response?.status) &&
  response.headers?.['retry-after'] == null && response.headers?.['x-ratelimit-remaining'] !== '0';
const unstable = response => response?.status == null || response.status === 429 ||
  response.status >= 500 || responseCached(response);

export async function planSessionChains(surface, scope, {infer, model, env = {}, budget = 1,
  modelCallsAvailable = 0, log = () => {}} = {}) {
  const result = {leads: [], decisions: [], modelCalls: 0, modelError: null,
    coverage: {publicAvailable: 0, publicSent: 0, privateAvailable: 0, privateSent: 0}};
  if (!infer || !model || scope.target.environment !== 'local' || !env[scope.identities.owner.env] ||
      scope.identities.auth !== 'bearer') return result;
  const records = (surface?.patterns ?? []).filter(exactGet);
  const publicRoutes = records.filter(record => record.fingerprint?.anonymous?.status === 200);
  const privateRoutes = records.filter(record => record.fingerprint?.owner?.status === 200 &&
    [401, 403, 404].includes(record.fingerprint?.anonymous?.status));
  result.coverage.publicAvailable = publicRoutes.length;
  result.coverage.privateAvailable = privateRoutes.length;
  if (!publicRoutes.length || !privateRoutes.length || budget < 1 || modelCallsAvailable < 1)
    return result;
  const publicSent = publicRoutes.slice(0, 32);
  const privateSent = privateRoutes.slice(0, 16);
  const routeFact = record => ({path: record.pattern,
    fields: record.fingerprint?.anonymous?.shape ?? null,
    ownerStatus: record.fingerprint?.owner?.status ?? null,
    anonymousStatus: record.fingerprint?.anonymous?.status ?? null,
    purpose: brief((surface?.modelNotes ?? []).find(note => note.path === record.pattern)?.purpose, 160)});
  const context = {origin: scope.target.origin,
    publicRoutes: publicSent.map(routeFact), privateRoutes: privateSent.map(routeFact)};
  if (Buffer.byteLength(JSON.stringify(context)) > 16000) {
    result.modelError = 'Public-session planning context exceeded 16 KB.';
    return result;
  }
  try {
    result.modelCalls++;
    const reply = await infer(model, [{role: 'system', content:
      'Identify at most one read-only public-session-token sequence from these observed routes. ' +
      'Choose an anonymous JSON source route, the exact JSON Pointer to a bearer token in its response, ' +
      'and a private GET route that an owner can read but anonymous callers cannot. ' +
      'The runner will test only whether the public field equals the operator-supplied owner test token, ' +
      'then replay that token on the private route with anonymous and invalid-token controls. ' +
      'Never propose another user’s token, writes, guessed routes or off-origin requests. ' +
      'Name the hypothesis freely. Return an empty chains array if the evidence is weak.'},
      {role: 'user', content: JSON.stringify(context)}], {schema: {type: 'object',
      properties: {chains: {type: 'array', maxItems: 1, items: {type: 'object', properties: {
        family: {type: 'string', maxLength: 60}, sourcePath: {type: 'string', maxLength: 300},
        tokenPointer: {type: 'string', maxLength: 200}, privatePath: {type: 'string', maxLength: 300},
        why: {type: 'string', maxLength: 300}, priority: {type: 'integer'}},
      required: ['family', 'sourcePath', 'tokenPointer', 'privatePath', 'why', 'priority'],
      additionalProperties: false}}}, required: ['chains'], additionalProperties: false}});
    result.coverage.publicSent = publicSent.length;
    result.coverage.privateSent = privateSent.length;
    for (const proposal of Array.isArray(reply?.chains) ? reply.chains.slice(0, 1) : []) {
      const decision = {mode: 'session-chain', family: brief(proposal?.family, 60),
        sourcePath: brief(proposal?.sourcePath, 300), privatePath: brief(proposal?.privatePath, 300),
        tokenPointer: brief(proposal?.tokenPointer, 200), hypothesis: brief(proposal?.why, 300),
        accepted: false};
      if (!publicSent.some(record => record.pattern === proposal.sourcePath) ||
          !privateSent.some(record => record.pattern === proposal.privatePath) ||
          proposal.sourcePath === proposal.privatePath) decision.reason = 'unobserved-route-pair';
      else if (!validModelJsonPointer(proposal.tokenPointer) ||
          !/^[a-z][a-z0-9-]{2,59}$/.test(proposal.family ?? '') ||
          !Number.isInteger(proposal.priority)) decision.reason = 'invalid-plan';
      else if (!validateUrl(scope, proposal.sourcePath, {identity: 'anonymous'}).ok ||
          !validateUrl(scope, proposal.privatePath, {identity: 'owner'}).ok)
        decision.reason = 'scope';
      else {
        decision.accepted = true;
        result.leads.push({path: proposal.sourcePath, sourcePath: proposal.sourcePath,
          privatePath: proposal.privatePath, tokenPointer: proposal.tokenPointer,
          family: proposal.family, why: decision.hypothesis, priority: Math.max(0, Math.min(10, proposal.priority)),
          as: 'anonymous', parameter: null, basis: 'model-session-chain'});
      }
      result.decisions.push(decision);
    }
  } catch (error) {
    result.modelError = error.message;
    log({stage: 'session-chain', message: `Muse session-chain planning failed: ${error.message}`});
  }
  return result;
}

function publicSessionFinding(lead, scope, controls) {
  const sourceUrl = new URL(lead.sourcePath, scope.target.origin);
  const privateUrl = new URL(lead.privatePath, scope.target.origin);
  const [owner, anonymous, invalid, sourceOne, replayOne, sourceTwo, replayTwo] = controls;
  return {kind: 'public-session-token',
    title: `Public response grants the owner test session: ${lead.sourcePath}`,
    severity: 'high', owasp: 'A07 Identification and Authentication Failures', cwe: 'CWE-200',
    pattern: lead.sourcePath, url: sourceUrl.href, host: sourceUrl.host, task: null,
    verdict: 'confirmed', rule: 'confirmed/public-session-token/two-owner-token-replays',
    evidence: unique([owner.evidenceId, anonymous.evidenceId, invalid.evidenceId,
      sourceOne.evidenceId, replayOne.evidenceId]),
    confirmation: unique([sourceTwo.evidenceId, replayTwo.evidenceId]),
    mirror: {result: 'unverified', evidence: [], reason: 'only the operator-supplied owner token was tested'},
    tags: ['model-proposed', 'operator-test-account', 'local-target-only'],
    reach: {observed: 1, basis: `two anonymous reads exposed the exact owner test bearer; replayed private JSON matched the owner response twice, while anonymous and invalid-token controls were denied (${replayOne.evidenceId}, ${replayTwo.evidenceId})`},
    dataClasses: ['session token'],
    remediation: 'Remove session credentials from public responses and revoke exposed sessions. Require authentication and ownership checks before returning account material.',
    foundBy: 'muse-proposed-account-sequence', status: 'open',
    modelHypothesis: {family: lead.family, why: lead.why},
    webProof: {kind: 'public-session-token', request: {method: 'GET', url: lead.sourcePath, as: 'anonymous'},
      sourcePath: lead.sourcePath, privatePath: lead.privatePath, tokenPointer: lead.tokenPointer,
      parameter: null},
    webSteps: [
      {identity: 'owner', method: 'GET', url: privateUrl.href, status: owner.status, evidence: owner.evidenceId},
      {identity: 'anonymous', method: 'GET', url: privateUrl.href, status: anonymous.status, evidence: anonymous.evidenceId},
      {identity: 'invalid-token', method: 'GET', url: privateUrl.href, status: invalid.status, evidence: invalid.evidenceId},
      {identity: 'anonymous', method: 'GET', url: sourceUrl.href, status: sourceOne.status, evidence: sourceOne.evidenceId},
      {identity: 'public-token', method: 'GET', url: privateUrl.href, status: replayOne.status, evidence: replayOne.evidenceId},
      {identity: 'anonymous', method: 'GET', url: sourceUrl.href, status: sourceTwo.status, evidence: sourceTwo.evidenceId},
      {identity: 'public-token', method: 'GET', url: privateUrl.href, status: replayTwo.status, evidence: replayTwo.evidenceId},
    ]};
}

export async function runSessionChains(leads, scope, {requester, env = {}} = {}) {
  const findings = [], results = [];
  for (const lead of leads) {
    const evidence = [], controls = [];
    const send = async (path, identity, step, extras = {}) => {
      const response = await requester({url: path, identity, method: 'GET', step,
        noCache: true, maxBytes: MODEL_RESPONSE_BYTES,
        headers: {'cache-control': 'no-cache'}, ...extras});
      if (response.evidenceId) evidence.push(response.evidenceId);
      controls.push(response);
      return response;
    };
    const owner = await send(lead.privatePath, 'owner', 'control');
    const anonymous = await send(lead.privatePath, 'anonymous', 'control');
    const invalid = await send(lead.privatePath, 'anonymous', 'control',
      {derivedBearer: `bx-invalid-${randomBytes(12).toString('hex')}`});
    let verdict = 'inconclusive', reason = 'private-route controls were unavailable';
    if ([owner, anonymous, invalid].some(item => item.blocked || item.refused)) {
      verdict = requestFailureVerdict([owner, anonymous, invalid]);
      reason = [owner, anonymous, invalid].map(responseSizeReason).find(Boolean) ??
        'a private-route control was refused';
    } else if (owner.status === 200 && /json|\+json/i.test(owner.type ?? '') &&
        denied(anonymous) && denied(invalid) && ![owner, anonymous, invalid].some(unstable)) {
      const ownerToken = env[scope.identities.owner.env];
      for (let index = 0; index < 2; index++) {
        const source = await send(lead.sourcePath, 'anonymous', index ? 'reverify' : 'task',
          {omitExcerpt: true, rawForSessionChain: true});
        if (source.blocked || source.refused) {
          verdict = requestFailureVerdict([source]);
          reason = responseSizeReason(source) ?? 'public source was refused'; break;
        }
        if (unstable(source)) {reason = 'public source was unavailable or cached'; break;}
        const token = source.status === 200 && /json|\+json/i.test(source.type ?? '') ?
          modelJsonPointer(source.rawBody, lead.tokenPointer) : null;
        if (token !== ownerToken) {
          verdict = index ? 'inconclusive' : 'not_reproduced';
          reason = 'the public field did not contain the operator owner token';
          break;
        }
        const replay = await send(lead.privatePath, 'anonymous', index ? 'reverify' : 'task',
          {derivedBearer: token, omitExcerpt: true});
        if (replay.blocked || replay.refused) {
          verdict = requestFailureVerdict([replay]);
          reason = responseSizeReason(replay) ?? 'public token replay was refused'; break;
        }
        if (unstable(replay)) {reason = 'public token replay was unavailable or cached'; break;}
        if (replay.status !== 200 || replay.hash !== owner.hash ||
            !/json|\+json/i.test(replay.type ?? '')) {
          verdict = index ? 'inconclusive' : 'not_reproduced';
          reason = 'the public token did not reproduce the owner private response';
          break;
        }
        if (index === 1) {verdict = 'confirmed'; reason = 'two public owner-token reads replayed the private owner response';}
      }
    }
    results.push({lead: {path: lead.path, parameter: null, family: lead.family,
      basis: lead.basis}, kind: 'public-session-token', verdict, reason, evidence: unique(evidence)});
    if (verdict === 'confirmed') findings.push(publicSessionFinding(lead, scope, controls));
  }
  return {findings, results, tested: results.length};
}
