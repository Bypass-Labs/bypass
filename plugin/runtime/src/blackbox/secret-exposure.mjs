// Validate publicly served private-key material without recording the key or sending it to a model.
import {validateUrl} from './scope.mjs';
import {publicPrivateKeyFingerprints, publicCredentialFingerprints, responseCached} from './poc-runtime.mjs';
import {MODEL_RESPONSE_BYTES, requestFailureVerdict, responseSizeReason} from './response-size.mjs';

const CREDENTIAL_KINDS = new Set(['github-token', 'stripe-secret-key', 'stripe-restricted-key', 'sendgrid-key']);

function proofable(scope, url) {
  const parsed = new URL(url);
  if (parsed.protocol === 'https:') return true;
  if (parsed.protocol !== 'http:') return false;
  const host = parsed.hostname.replace(/^\[|\]$/g, '').toLowerCase();
  return ['localhost', '127.0.0.1', '::1'].includes(host) ||
    scope.domains.some(domain => host === domain || host.endsWith(`.${domain}`));
}

export function publicPrivateKeyCandidates(summaries) {
  const seen = new Set(), candidates = [];
  for (const summary of summaries) for (const file of summary?.files ?? []) {
    if (!file?.secrets?.some(secret => secret.name === 'private-key' && secret.public === false) ||
        typeof file.url !== 'string' || !URL.canParse(file.url) || seen.has(file.url)) continue;
    seen.add(file.url);
    candidates.push({url: file.url, path: new URL(file.url).pathname,
      sourceEvidence: file.evidenceId ?? null, source: file.foundBy ?? 'public-asset'});
  }
  return candidates;
}

/** Re-fetch an observed public asset twice; only a parseable private key can become a finding. */
export async function auditPublicPrivateKeys(summaries, scope, {requester, budget = 4, log = () => {}} = {}) {
  const candidates = publicPrivateKeyCandidates(summaries);
  const selected = candidates.slice(0, Math.max(0, budget));
  const findings = [], results = [];
  for (const lead of selected) {
    const origin = new URL(lead.url).origin;
    const result = {kind: 'public-private-key', lead, origin, verdict: 'not_reproduced', evidence: []};
    const check = validateUrl(scope, lead.url, {purpose: 'asset', identity: 'anonymous'});
    if (!check.ok || !proofable(scope, lead.url)) {
      results.push({...result, verdict: 'blocked',
        reason: check.reason ?? 'asset transport cannot be replayed by a guarded proof'});
      continue;
    }
    const request = step => requester({url: lead.url, identity: 'anonymous', method: 'GET',
      purpose: 'asset', step, noCache: true, maxBytes: MODEL_RESPONSE_BYTES,
      headers: {'cache-control': 'no-cache'}});
    const first = await request('task');
    if (first.evidenceId) result.evidence.push(first.evidenceId);
    if (first.blocked || first.refused || first.status == null || first.status >= 500 || first.status === 429 ||
        responseCached(first)) {
      results.push({...result, verdict: requestFailureVerdict([first]),
        reason: responseSizeReason(first) ?? first.reason ?? 'first public asset read was unavailable'});
      continue;
    }
    if (first.status !== 200) {results.push(result); continue;}
    const fingerprint = publicPrivateKeyFingerprints(first.body)[0];
    if (!fingerprint) {results.push(result); continue;}
    const second = await request('reverify');
    if (second.evidenceId) result.evidence.push(second.evidenceId);
    const confirmed = second.status === 200 && !responseCached(second) &&
      publicPrivateKeyFingerprints(second.body).includes(fingerprint);
    results.push({...result, verdict: confirmed ? 'confirmed' : 'inconclusive',
      reason: confirmed ? 'same parseable private key remained publicly readable' :
        responseSizeReason(second) ?? second.reason ?? 'key was not reproduced by the second public read',
      publicKeyFingerprint: fingerprint});
    if (!confirmed) continue;
    const url = new URL(lead.url);
    findings.push({kind: 'public-private-key', title: `Parseable private key in a public asset: ${lead.path}`,
      severity: 'high', owasp: 'API8 Security Misconfiguration', cwe: 'CWE-321',
      pattern: lead.path, url: url.href, host: url.host, task: null, verdict: 'confirmed',
      rule: 'confirmed/public-private-key/two-anonymous-reads',
      evidence: [lead.sourceEvidence, first.evidenceId].filter(Boolean),
      confirmation: [second.evidenceId].filter(Boolean),
      mirror: {result: 'unverified', evidence: [], reason: 'key use and privileges were not tested'},
      tags: ['public-asset', 'parseable-private-key', 'key-use-unverified'],
      reach: {observed: 1, basis: `a parseable key with public-key fingerprint ${fingerprint} appeared in two anonymous reads (${first.evidenceId}, ${second.evidenceId})`},
      dataClasses: ['private-key'],
      remediation: 'Remove the private key from public assets, rotate it and revoke credentials or signatures that trust it.',
      foundBy: 'public-asset-validation', status: 'open',
      webProof: {kind: 'public-private-key', request: {method: 'GET', url: url.href, as: 'anonymous'},
        publicKeyFingerprint: fingerprint}});
  }
  log({stage: 'secret-exposure', message: `${results.length} public private-key candidates checked; ${findings.length} confirmed; ${Math.max(0, candidates.length - selected.length)} beyond budget`});
  return {findings, results, tested: selected.length,
    cut: Math.max(0, candidates.length - selected.length),
    plan: selected.map(lead => ({kind: 'public-private-key', path: lead.path, origin: new URL(lead.url).origin,
      parameter: null, by: 'asset-signature', basis: 'observed-private-key-pattern'}))};
}

export function publicCredentialCandidates(summaries) {
  const seen = new Set(), candidates = [];
  for (const summary of summaries) for (const file of summary?.files ?? []) {
    if (typeof file?.url !== 'string' || !URL.canParse(file.url)) continue;
    for (const secret of file.secrets ?? []) {
      if (!CREDENTIAL_KINDS.has(secret.name) || secret.public !== false ||
          secret.confidence !== 'high') continue;
      const key = `${file.url} ${secret.name}`;
      if (seen.has(key)) continue;
      seen.add(key);
      candidates.push({url: file.url, path: new URL(file.url).pathname,
        credentialKind: secret.name, sourceEvidence: file.evidenceId ?? null,
        source: file.foundBy ?? 'public-asset'});
    }
  }
  return candidates;
}

/** Re-fetch high-confidence credential leads; validity and privileges remain untested. */
export async function auditPublicCredentials(summaries, scope, {requester, budget = 4, log = () => {}} = {}) {
  const candidates = publicCredentialCandidates(summaries);
  const selected = candidates.slice(0, Math.max(0, budget));
  const findings = [], results = [];
  for (const lead of selected) {
    const origin = new URL(lead.url).origin;
    const result = {kind: 'public-api-credential', lead, origin, verdict: 'not_reproduced', evidence: []};
    const check = validateUrl(scope, lead.url, {purpose: 'asset', identity: 'anonymous'});
    if (!check.ok || !proofable(scope, lead.url)) {
      results.push({...result, verdict: 'blocked',
        reason: check.reason ?? 'asset transport cannot be replayed by a guarded proof'});
      continue;
    }
    const request = step => requester({url: lead.url, identity: 'anonymous', method: 'GET',
      purpose: 'asset', step, noCache: true, maxBytes: MODEL_RESPONSE_BYTES,
      headers: {'cache-control': 'no-cache'}});
    const first = await request('task');
    if (first.evidenceId) result.evidence.push(first.evidenceId);
    if (first.blocked || first.refused || first.status == null || first.status >= 500 || first.status === 429 ||
        responseCached(first)) {
      results.push({...result, verdict: requestFailureVerdict([first]),
        reason: responseSizeReason(first) ?? first.reason ?? 'first public asset read was unavailable'});
      continue;
    }
    if (first.status !== 200) {results.push(result); continue;}
    const firstKeys = publicCredentialFingerprints(first.body)
      .filter(item => item.name === lead.credentialKind);
    if (!firstKeys.length) {results.push(result); continue;}
    const second = await request('reverify');
    if (second.evidenceId) result.evidence.push(second.evidenceId);
    if (second.blocked || second.refused || second.status == null || second.status >= 500 || second.status === 429 ||
        second.status !== 200 || responseCached(second)) {
      results.push({...result, verdict: requestFailureVerdict([second]),
        reason: responseSizeReason(second) ?? second.reason ?? 'second public asset read was unavailable'});
      continue;
    }
    const secondKeys = new Set(publicCredentialFingerprints(second.body)
      .filter(item => item.name === lead.credentialKind).map(item => item.fingerprint));
    const confirmed = firstKeys.find(item => secondKeys.has(item.fingerprint));
    results.push({...result, verdict: confirmed ? 'confirmed' : 'inconclusive',
      reason: confirmed ? 'same credential-shaped value remained publicly readable' :
        'credential-shaped value was not reproduced by the second public read',
      credentialFingerprint: confirmed?.fingerprint ?? null});
    if (!confirmed) continue;
    const url = new URL(lead.url);
    findings.push({kind: 'public-api-credential',
      title: `Credential-shaped ${lead.credentialKind} value in a public asset: ${lead.path}`,
      severity: 'medium', owasp: 'API8 Security Misconfiguration', cwe: 'CWE-200',
      pattern: lead.path, url: url.href, host: url.host, task: null, verdict: 'confirmed',
      rule: 'confirmed/public-api-credential/two-anonymous-reads',
      evidence: [lead.sourceEvidence, first.evidenceId].filter(Boolean),
      confirmation: [second.evidenceId].filter(Boolean),
      mirror: {result: 'unverified', evidence: [], reason: 'credential validity and privileges were not tested'},
      tags: ['public-asset', 'credential-shaped', 'key-use-unverified'],
      reach: {observed: 1, basis: `a ${lead.credentialKind} value with fingerprint ${confirmed.fingerprint} appeared in two anonymous reads (${first.evidenceId}, ${second.evidenceId})`},
      dataClasses: ['api-credential'],
      remediation: 'Remove the credential from public assets and rotate or revoke it if active.',
      foundBy: 'public-asset-validation', status: 'open',
      webProof: {kind: 'public-api-credential', request: {method: 'GET', url: url.href, as: 'anonymous'},
        credentialKind: lead.credentialKind, credentialFingerprint: confirmed.fingerprint}});
  }
  log({stage: 'secret-exposure', message: `${results.length} public credential candidates checked; ${findings.length} confirmed; ${Math.max(0, candidates.length - selected.length)} beyond budget`});
  return {findings, results, tested: selected.length,
    cut: Math.max(0, candidates.length - selected.length),
    plan: selected.map(lead => ({kind: 'public-api-credential', path: lead.path,
      origin: new URL(lead.url).origin, parameter: null, credentialKind: lead.credentialKind,
      by: 'asset-signature', basis: 'observed-credential-pattern'}))};
}
