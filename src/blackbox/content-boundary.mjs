// A reusable oracle for a Muse-chosen public input that returns the exact body
// of a protected read. It keeps private response bytes in memory and records
// only status, length and hashes. This proves disclosure, not its mechanism.
import {createHash} from 'node:crypto';

const digest = body => `sha256:${createHash('sha256').update(body).digest('hex')}`;
// This module is copied beside standalone proofs, so keep the capture ceiling local.
export const PRIVATE_JSON_BYTES = 16 * 1024 * 1024;
const MODEL_RESPONSE_BYTES = PRIVATE_JSON_BYTES;
const cached = response => {
  const headers = response?.headers ?? {};
  const value = name => headers[name] ?? headers[name.toLowerCase()] ?? '';
  return response?.cached === true || /\bHIT\b/i.test(String(value('x-cache'))) ||
    value('age') !== '';
};
const clean = response => response && !response.blocked && !response.refused &&
  response.status != null && response.status !== 429 && response.status < 500 &&
  !cached(response) && typeof response.body === 'string';
const denied = response => [401, 403, 404].includes(response?.status);
const safePath = value => typeof value === 'string' && value.startsWith('/') &&
  !value.startsWith('//') && value.length <= 300 &&
  !/[\\;%?#{}]/.test(value) && !/[^\x21-\x7e]/.test(value) &&
  !value.split('/').some(part => part === '.' || part === '..');
const safeField = value => typeof value === 'string' &&
  /^[A-Za-z_][A-Za-z0-9_.-]{0,63}$/.test(value);
const safeValue = value => typeof value === 'string' && value.length > 0 &&
  value.length <= 256 &&
  /^[\x20-\x7e]*$/.test(value) && !/[;`$<>|&\\]/.test(value) &&
  !/(?:https?:|file:|ftp:|gopher:|data:|bearer\s|password\s*=|api[_-]?key\s*=|secret\s*=|token\s*=)/i.test(value);

/** A self-declared private account document. Only field names leave this oracle. */
export function privateDeclarationSignal(body, type = '') {
  if (typeof body !== 'string' || Buffer.byteLength(body) < 32 ||
      Buffer.byteLength(body) > PRIVATE_JSON_BYTES || !/(?:json|\+json)/i.test(type)) return null;
  let parsed;
  try { parsed = JSON.parse(body); } catch { return null; }
  if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) return null;
  const scopes = [['', parsed], ...['data', 'record'].map(name => [name, parsed[name]])];
  for (const [prefix, item] of scopes) {
    if (!item || typeof item !== 'object' || Array.isArray(item)) continue;
    const marker = item.private === true ? 'private' :
      item.confidential === true ? 'confidential' :
      item.visibility === 'private' ? 'visibility' :
      item.access === 'private' ? 'access' : null;
    if (!marker) continue;
    const keys = Object.keys(item);
    const owner = keys.some(key => /^(?:owner|ownerId|account|accountId|user|userId)$/i.test(key) &&
      item[key] != null && item[key] !== '');
    const material = keys.find(key => /^(?:email|phone|address|balance|salary|ssn|dob|note|message|document|content|secret|token|apiKey)$/i.test(key) &&
      item[key] != null && item[key] !== '' &&
      (typeof item[key] !== 'object' || Object.keys(item[key]).length > 0));
    if (!material || !owner && !/^(?:secret|token|apiKey|ssn|dob|salary|balance)$/i.test(material)) continue;
    return {markerKey: `${prefix ? `${prefix}.` : ''}${marker}`,
      materialField: `${prefix ? `${prefix}.` : ''}${material}`};
  }
  return null;
}

/** Strict inputs for an exact-content disclosure hypothesis. */
export function contentBoundaryShapeReason(plan) {
  if (!safePath(plan?.protectedPath) || !safePath(plan?.subject?.path) ||
      plan.protectedPath === plan.subject.path) return 'paths';
  const post = plan.subject.method === 'POST' && plan.subject.placement === 'json';
  const get = plan.subject.method === 'GET' && plan.subject.placement === 'query';
  if (!(post || get) || !safeField(plan.subject.key)) return 'subject';
  const fixed = plan.subject.fixedFields;
  if (!Array.isArray(fixed) || fixed.length > (get ? 0 : 3) ||
      fixed.some(item => !safeField(item?.field) ||
        item.field === plan.subject.key || !safeValue(item.value)) ||
      new Set(fixed.map(item => item.field)).size !== fixed.length)
    return 'fixed-fields';
  const values = [plan.controlValue, plan.firstValue, plan.secondValue];
  if (!values.every(safeValue)) return 'values';
  if (new Set(values).size !== values.length) return 'duplicate-values';
  return null;
}

/** Exact-body equality is intentionally strict: a similar page is no proof. */
export function protectedContentMatch(owner, candidate, {minBytes = 64,
  maxBytes = MODEL_RESPONSE_BYTES} = {}) {
  if (!clean(owner) || owner.status !== 200 || !clean(candidate) ||
      candidate.status !== 200) return false;
  const ownerBytes = Buffer.byteLength(owner.body);
  return ownerBytes >= minBytes && ownerBytes <= maxBytes &&
    Buffer.byteLength(candidate.body) === ownerBytes &&
    owner.body === candidate.body;
}

// A private JSON field can survive a different public response wrapper. Keep
// its value only in memory; evidence records hashes of complete responses.
function privateMaterial(response) {
  const type = response?.type ?? response?.headers?.['content-type'] ?? '';
  const signal = privateDeclarationSignal(response?.body, type);
  if (!signal) return null;
  let parsed;
  try {parsed = JSON.parse(response.body);} catch {return null;}
  const path = signal.materialField.split('.');
  const value = path.reduce((item, key) => item?.[key], parsed);
  const container = path.slice(0, -1).reduce((item, key) => item?.[key], parsed);
  const ownerKey = Object.keys(container ?? {}).find(key =>
    /^(?:owner|ownerId|account|accountId|user|userId)$/i.test(key) &&
    ['string', 'number'].includes(typeof container[key]) && container[key] !== '');
  const randomToken = typeof value === 'string' &&
    ((value.match(/[a-f0-9]{24,}/ig) ?? []).some(part =>
      new Set(part.toLowerCase()).size >= 8) ||
    value.length >= 32 && !/\s/.test(value) &&
      /[A-Z]/.test(value) && /[a-z]/.test(value) && /\d/.test(value) &&
      new Set(value).size >= 12);
  return typeof value === 'string' && Buffer.byteLength(value) >= 12 &&
    Buffer.byteLength(value) <= 4096 ? {key: path.at(-1), path: signal.materialField,
      value, strong: randomToken,
      ...(ownerKey ? {ownerKey, ownerValue: container[ownerKey]} : {})} : null;
}

function containsPrivateField(body, material, {requireOwnerLink = true} = {}) {
  let parsed;
  try {parsed = JSON.parse(body);} catch {return false;}
  let visited = 0;
  const walk = (item, depth, ownerLinked = false) => {
    if (!item || typeof item !== 'object' || depth > 6 || ++visited > 128)
      return false;
    ownerLinked ||= material.ownerKey !== undefined &&
      item[material.ownerKey] === material.ownerValue;
    for (const [key, value] of Object.entries(item)) {
      if (key === material.key && value === material.value &&
          (material.strong || ownerLinked || !requireOwnerLink)) return true;
      if (walk(value, depth + 1, ownerLinked)) return true;
    }
    return false;
  };
  return walk(parsed, 0);
}

/** Check only client-supplied bytes, never response bodies. Keep the private value in memory. */
export function requestSuppliesPrivateMaterial(request, materialValue) {
  if (!request || typeof materialValue !== 'string' || !materialValue) return false;
  const supplied = [request.url, request.body,
    ...Object.values(request.headers ?? {})].filter(value =>
    typeof value === 'string');
  return supplied.some(value => {
    if (value.includes(materialValue)) return true;
    try {return decodeURIComponent(value).includes(materialValue);} catch {return false;}
  });
}

/** Bounded JSON key/type structure for model feedback; never include field values. */
function responseJsonShape(response) {
  if (!/(?:json|\+json)/i.test(response?.type ??
      response?.headers?.['content-type'] ?? '') ||
      typeof response?.body !== 'string') return null;
  let parsed;
  try {parsed = JSON.parse(response.body);} catch {return null;}
  let remaining = 32;
  const shape = (value, depth) => {
    if (value === null) return 'null';
    if (Array.isArray(value)) return 'array';
    if (typeof value !== 'object') return typeof value;
    if (depth >= 3 || remaining <= 0) return 'object';
    return Object.entries(value).slice(0, 16).flatMap(([key, item]) => {
      if (remaining-- <= 0) return [];
      return [[/^[A-Za-z_][A-Za-z0-9_.-]{0,63}$/.test(key) ? key : '[other]',
        shape(item, depth + 1)]];
    });
  };
  return shape(parsed, 0);
}

/**
 * The caller provides already scope-validated request descriptors. The oracle
 * establishes fresh owner and anonymous controls around an ordinary input and
 * two distinct Muse-proposed inputs. A single positive must repeat uncached.
 */
export async function verifyContentBoundary({requester, protectedRequest,
  makeCandidate, runCandidate = null, controlValue, firstValue, secondValue,
  comparison = 'exact-body', minBytes = 64,
  maxBytes = MODEL_RESPONSE_BYTES} = {}) {
  if (typeof requester !== 'function' ||
      typeof makeCandidate !== 'function' && typeof runCandidate !== 'function' ||
      !protectedRequest || [controlValue, firstValue, secondValue]
        .some(value => typeof value !== 'string') ||
      new Set([controlValue, firstValue, secondValue]).size !== 3)
    return {verdict: 'inconclusive', reason: 'content-boundary inputs are invalid',
      evidence: [], controls: []};
  const evidence = [], controls = [];
  let unprovenBinding = false;
  let unprovenPrelude = false;
  let submittedPrivateMaterial = false;
  const issue = async (request, label) => {
    const response = await requester({...request, noCache: true,
      omitExcerpt: true, maxBytes,
      headers: {...request.headers, 'cache-control': 'no-cache'},
      step: label === 'candidate-one' ? 'task' :
        label.endsWith('recheck') || label.endsWith('final') ||
        label === 'candidate-two' ? 'reverify' : 'control'});
    if (response.evidenceId) evidence.push(response.evidenceId);
    const shape = responseJsonShape(response);
    controls.push({label, status: response.status,
      evidence: response.evidenceId ?? null, cached: cached(response),
      ...(shape ? {shape} : {}),
      ...(typeof response.body === 'string' ?
        {bytes: Buffer.byteLength(response.body), hash: digest(response.body)} : {})});
    return response;
  };
  const issueCandidate = async (value, label) => {
    if (typeof runCandidate !== 'function') {
      const request = makeCandidate(value);
      if (material && requestSuppliesPrivateMaterial(request, material.value)) {
        submittedPrivateMaterial = true;
        request.redactValues = [material.value];
      }
      return issue(request, label);
    }
    const phase = await runCandidate(value, {label, noCache: true,
      omitExcerpt: true, maxBytes, privateMaterialValue: material?.value});
    if (phase?.publicBinding === false) unprovenBinding = true;
    if (phase?.credentialedPrelude === true) unprovenPrelude = true;
    if (phase?.submittedPrivateMaterial === true) submittedPrivateMaterial = true;
    for (const [index, step] of (phase?.steps ?? []).entries()) {
      const response = step?.response ?? step;
      if (response?.evidenceId) evidence.push(response.evidenceId);
      const shape = responseJsonShape(response);
      controls.push({label: `${label}-${step?.label ?? index}`,
        status: response?.status ?? null, evidence: response?.evidenceId ?? null,
        cached: cached(response),
        ...(shape ? {shape} : {}),
        ...(step?.method ? {method: step.method, path: step.path,
          identity: step.identity} : {}),
        ...(typeof response?.body === 'string' ?
          {bytes: Buffer.byteLength(response.body), hash: digest(response.body)} : {})});
    }
    const response = phase?.complete === false ?
      {...phase?.response, status: null, blocked: true} :
      phase?.response ?? {status: null, blocked: true};
    if (response.evidenceId) evidence.push(response.evidenceId);
    const shape = responseJsonShape(response);
    controls.push({label, status: response.status, evidence: response.evidenceId ?? null,
      cached: cached(response),
      ...(shape ? {shape} : {}),
      ...(typeof response.body === 'string' ?
        {bytes: Buffer.byteLength(response.body), hash: digest(response.body)} : {})});
    return response;
  };
  const protectedAs = as => ({...protectedRequest, identity: as});
  const ownerOne = await issue(protectedAs('owner'), 'owner-control');
  const anonymousOne = await issue(protectedAs('anonymous'), 'anonymous-denial');
  if (!clean(ownerOne) || ownerOne.status !== 200 ||
      Buffer.byteLength(ownerOne.body) < minBytes ||
      Buffer.byteLength(ownerOne.body) > maxBytes ||
      !clean(anonymousOne) || !denied(anonymousOne))
    return {verdict: 'inconclusive', reason: 'protected owner and anonymous controls unavailable',
      evidence, controls};
  const material = comparison === 'json-field' ? privateMaterial(ownerOne) : null;
  if (comparison === 'json-field' && (!material ||
      [controlValue, firstValue, secondValue].includes(material.value)))
    return {verdict: 'inconclusive',
      reason: 'private JSON material is unavailable or was submitted as input',
      evidence, controls};
  const matches = (owner, candidate) => comparison === 'json-field' ?
    clean(candidate) && candidate.status === 200 &&
      Buffer.byteLength(candidate.body) <= maxBytes &&
      /(?:json|\+json)/i.test(candidate.type ??
        candidate.headers?.['content-type'] ?? '') &&
      containsPrivateField(candidate.body, material) :
    protectedContentMatch(owner, candidate, {minBytes, maxBytes});
  const control = await issueCandidate(controlValue, 'public-control');
  const first = await issueCandidate(firstValue, 'candidate-one');
  const resetBetween = typeof runCandidate === 'function' ?
    await issueCandidate(controlValue, 'public-reset-between') : null;
  const second = await issueCandidate(secondValue, 'candidate-two');
  const resetAfter = typeof runCandidate === 'function' ?
    await issueCandidate(controlValue, 'public-reset-after') : null;
  const ownerTwo = await issue(protectedAs('owner'), 'owner-recheck');
  const anonymousTwo = await issue(protectedAs('anonymous'), 'anonymous-recheck');
  if (unprovenPrelude) return {verdict: 'inconclusive',
    reason: 'credentialed prelude may have published the asserted content',
    evidence, controls};
  if (unprovenBinding) return {verdict: 'inconclusive',
    reason: 'credentialed bound value was not independently available anonymously',
    evidence, controls};
  if (submittedPrivateMaterial) return {verdict: 'inconclusive',
    reason: 'private JSON material was supplied by the client request',
    evidence, controls};
  if (resetBetween && resetAfter &&
      (![resetBetween, resetAfter].every(item => clean(item) && item.status === 200) ||
        matches(ownerOne, resetBetween) || matches(ownerOne, resetAfter)))
    return {verdict: 'inconclusive',
      reason: 'sequence ordinary control did not restore a non-owner baseline',
      evidence, controls};
  const freshMaterial = comparison === 'json-field' ? privateMaterial(ownerTwo) : null;
  if ([control, first, second, ownerTwo, anonymousTwo].some(item => !clean(item)) ||
      ownerTwo.status !== 200 || !denied(anonymousTwo) ||
      control.status !== 200 || first.status !== 200 || second.status !== 200 ||
      (comparison === 'json-field' ?
        freshMaterial?.value !== material.value ||
          freshMaterial?.ownerKey !== material.ownerKey ||
          freshMaterial?.ownerValue !== material.ownerValue :
        !matches(ownerOne, ownerTwo)))
    return {verdict: 'inconclusive', reason: 'candidate or fresh controls unavailable or unstable',
      evidence, controls};
  const ordinaryExcludes = !matches(ownerOne, control);
  const firstMatches = matches(ownerOne, first);
  const secondMatches = matches(ownerOne, second);
  if (comparison === 'json-field' && !material.strong &&
      [first, second].some(item => containsPrivateField(item.body, material,
        {requireOwnerLink: false}) && !containsPrivateField(item.body, material)))
    return {verdict: 'inconclusive',
      reason: 'matching private JSON material lacked an owner link',
      evidence, controls};
  const comparisonFact = {label: 'content-boundary', mode: comparison,
    ownerStable: true,
    anonymousDenied: true, ordinaryExcludes, firstMatches, secondMatches};
  if (!ordinaryExcludes) {
    controls.push(comparisonFact);
    return {verdict: 'inconclusive', reason: 'ordinary public input also returned protected content',
      evidence, controls};
  }
  if (firstMatches !== secondMatches) {
    const positive = firstMatches ? firstValue : secondValue;
    const repeated = await issueCandidate(positive, 'candidate-recheck');
    const baselineFinal = await issueCandidate(controlValue, 'public-recheck');
    const ownerFinal = await issue(protectedAs('owner'), 'owner-final');
    const anonymousFinal = await issue(protectedAs('anonymous'), 'anonymous-final');
    Object.assign(comparisonFact, {positive: firstMatches ? 'first' : 'second',
      repeated: matches(ownerTwo, repeated),
      baselineExcluded: clean(baselineFinal) && baselineFinal.status === 200 &&
        !matches(ownerTwo, baselineFinal),
      ownerFinalStable: comparison === 'json-field' ?
        privateMaterial(ownerFinal)?.value === material.value &&
          privateMaterial(ownerFinal)?.ownerValue === material.ownerValue :
        matches(ownerTwo, ownerFinal),
      anonymousFinalDenied: clean(anonymousFinal) && denied(anonymousFinal)});
  }
  controls.push(comparisonFact);
  const confirmed = firstMatches && secondMatches || comparisonFact.repeated &&
    comparisonFact.baselineExcluded && comparisonFact.ownerFinalStable &&
    comparisonFact.anonymousFinalDenied;
  return {verdict: confirmed ? 'confirmed' :
    !firstMatches && !secondMatches ? 'not_reproduced' : 'inconclusive',
  reason: confirmed ? comparison === 'json-field' ?
    'anonymous input reproduced a declared private owner JSON field under fresh controls' :
    'anonymous input reproduced the exact owner-only response under fresh controls' :
    !firstMatches && !secondMatches ? 'candidate inputs did not return protected content' :
      'single positive candidate or fresh controls did not reproduce',
  evidence, controls};
}
