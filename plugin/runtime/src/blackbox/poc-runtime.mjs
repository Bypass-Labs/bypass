// Copied beside generated proofs and tests. Node built-ins only; no credential values are stored.
import {createHash, createPrivateKey, createPublicKey, randomBytes} from 'node:crypto';
import {execFile as childExecFile} from 'node:child_process';
import {AsyncLocalStorage} from 'node:async_hooks';
import {setTimeout as wait} from 'node:timers/promises';
import dns from 'node:dns/promises';
import fs from 'node:fs';
import http from 'node:http';
import https from 'node:https';
import net from 'node:net';
import os from 'node:os';
import path from 'node:path';
import {boundaryMatch, validBoundaryShape} from './boundary-oracle.mjs';
import {contentBoundaryShapeReason, requestSuppliesPrivateMaterial,
  verifyContentBoundary} from './content-boundary.mjs';

const sha = text => createHash('sha256').update(text).digest('hex');
const denied = status => [401, 403, 404].includes(status);
const cleanDenied = response => denied(response?.status) &&
  response.headers?.['retry-after'] == null && response.headers?.['x-ratelimit-remaining'] !== '0';
const object = value => value !== null && typeof value === 'object' && !Array.isArray(value);
let nextRequestAt = 0;
const localHost = host => ['localhost', '127.0.0.1', '::1'].includes(host.toLowerCase());
const XSS_STYLES = new Set(['html-double', 'html-single', 'script-close']);
const DOM_SCRIPT_BYTES = 2 * 1024 * 1024;
// Keep proof replay's ordinary response ceiling aligned with the scanner.
// Byte-range file proofs retain their smaller limits.
const MODEL_RESPONSE_BYTES = 16 * 1024 * 1024;
const DERIVED_SESSION_REPLAY = Symbol('derived-session-replay');
const replayBudget = new AsyncLocalStorage();
export const MAX_SEQUENCE_STEPS = 8;
const MAX_PROOF_REQUESTS = 128;
const MAX_PROOF_MS = 60000;
const domScriptLimit = value => Number.isSafeInteger(value) && value > 0 &&
  value <= 16 * 1024 * 1024 ? value : DOM_SCRIPT_BYTES;
export const HTML_INJECTION_STYLES = Object.freeze(['plain', 'double-quote', 'single-quote',
  'textarea-close', 'script-close']);
export const HOST_HEADER_CANARIES = Object.freeze(['bypass-audit.invalid', 'bypass-audit-two.invalid']);
export const validQueryParameter = value => typeof value === 'string' && value.length > 0 &&
  value.length <= 80 && value.trim() === value && !/[\x00-\x1f\x7f]/.test(value);
const safeProbeParameter = value => typeof value === 'string' &&
  /^[A-Za-z_][A-Za-z0-9_.-]{0,79}$/.test(value);
const modelValueReason = (value, markers = []) => {
  if (typeof value !== 'string') return 'value-shape';
  if (markers.some(marker => value.toLowerCase().includes(marker.toLowerCase())))
    return 'literal-marker';
  return null;
};
const harmlessModelValue = (value, markers = []) =>
  modelValueReason(value, markers) === null;
export function validModelHeaders(headers, markers = []) {
  if (!Array.isArray(headers)) return false;
  const seen = new Set();
  for (const header of headers) {
    const name = String(header?.name ?? '').toLowerCase();
    if (!/^[!#$%&'*+.^_`|~0-9a-z-]+$/.test(name) || seen.has(name) ||
        typeof header?.value !== 'string' || /[\r\n\x00]/.test(header.value)) return false;
    seen.add(name);
  }
  return true;
}
/** Return a reason category only; proposal values must not enter saved decisions. */
export function modelExperimentReason(spec) {
  const observation = spec?.oracle === 'observation';
  const markers = observation ? [] : [spec?.marker, spec?.secondMarker];
  if (!safeProbeParameter(spec?.parameter)) return 'parameter';
  if (!observation && (markers.some(marker => !/^bx[0-9a-f]{12}$/.test(marker ?? '')) ||
      markers[0] === markers[1])) return 'markers';
  const values = [spec.controlValue, spec.firstValue, spec.secondValue];
  for (const value of values) {
    const reason = modelValueReason(value, markers);
    if (reason) return reason;
  }
  if (!validModelHeaders(spec?.headers ?? [], markers)) return 'headers';
  if ((spec?.headers ?? []).some(header => markers.some(marker =>
    header.value.toLowerCase().includes(marker.toLowerCase())))) return 'literal-marker';
  if (new Set(values).size !== values.length) return 'duplicate-values';
  return null;
}
/** Validate a model-proposed read-only differential without naming a vulnerability family. */
export const validModelExperiment = spec => modelExperimentReason(spec) === null;
/** Preserve a Muse-supplied JSON value's bytes inside one reviewed outer body field. */
export function sequenceJsonBody(fields, key, value, valueEncoding = 'string') {
  if (valueEncoding !== 'json') return JSON.stringify({...fields, [key]: value});
  if (typeof value !== 'string') throw Error('A typed JSON sequence value must be text.');
  JSON.parse(value);
  const fixed = JSON.stringify(fields);
  return `${fixed.slice(0, -1)}${fixed === '{}' ? '' : ','}${JSON.stringify(key)}:${value}}`;
}
/** Preserve Muse's values unless one happens to equal the transient owner baseline. */
export function stateChangeCanaries(original, firstValue, secondValue) {
  const values = [firstValue, secondValue];
  let adjusted = false;
  for (let index = 0; index < values.length; index++) {
    if (values[index] !== original) continue;
    adjusted = true;
    let canary;
    do {canary = `bxstate${randomBytes(6).toString('hex')}`;}
    while (canary === original || values.includes(canary));
    values[index] = canary;
  }
  return {firstValue: values[0], secondValue: values[1], adjusted};
}
/** Companion JSON fields satisfy an observed request schema; none is a probe field. */
export function validModelFixedFields(fields, parameter, markers = [], observedFields = null) {
  if (!Array.isArray(fields) ||
      observedFields != null && (!Array.isArray(observedFields) ||
        !observedFields.includes(parameter))) return false;
  const names = new Set();
  for (const item of fields) {
    if (!item || !safeProbeParameter(item.field) || item.field === parameter ||
        names.has(item.field) || observedFields != null && !observedFields.includes(item.field) ||
        !harmlessModelValue(item.value, markers)) return false;
    names.add(item.field);
  }
  return true;
}
const SEQUENCE_POINTER = /^(?:\/[A-Za-z_][A-Za-z0-9_-]{0,63}){1,3}$/;
const SEQUENCE_SECRET_FIELD = /(?:auth|bearer|cookie|credential|csrf|key|otp|pass|pin|secret|session|token)/i;
const SEQUENCE_VALUE = /^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$/;
export const validSequencePointer = pointer => typeof pointer === 'string' &&
  SEQUENCE_POINTER.test(pointer) &&
  !pointer.slice(1).split('/').some(name => SEQUENCE_SECRET_FIELD.test(name));
/** A binding reads only a short, non-credential JSON scalar; its value is never in a proof spec. */
export function sequencePointerType(shape, pointer) {
  if (!validSequencePointer(pointer)) return null;
  let current = shape;
  for (const name of pointer.slice(1).split('/')) {
    if (!object(current) || !Object.hasOwn(current, name)) return null;
    current = current[name];
  }
  return ['string', 'number'].includes(current) ? current : null;
}
export function captureSequenceScalar(body, pointer) {
  if (typeof body !== 'string' || Buffer.byteLength(body) > MODEL_RESPONSE_BYTES ||
      !validSequencePointer(pointer)) return null;
  let current;
  try {current = JSON.parse(body);} catch {return null;}
  for (const name of pointer.slice(1).split('/')) {
    if (!object(current) || !Object.hasOwn(current, name)) return null;
    current = current[name];
  }
  const value = typeof current === 'number' && Number.isSafeInteger(current) && current >= 0 ?
    String(current) : typeof current === 'string' ? current : null;
  if (!value || !SEQUENCE_VALUE.test(value) ||
      value.length >= 24 && !/^\d{1,18}$/.test(value) &&
      !/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(value))
    return null;
  return value;
}
/** Find one string field in a bounded JSON read. Its value stays in memory for restoration. */
export function uniqueJsonStringField(body, key) {
  if (typeof body !== 'string' || Buffer.byteLength(body) > MODEL_RESPONSE_BYTES ||
      !safeProbeParameter(key)) return null;
  let document;
  try {document = JSON.parse(body);} catch {return null;}
  let nodes = 0;
  const found = [];
  const visit = (value, depth) => {
    if (++nodes > 256 || depth > 6 || value == null || typeof value !== 'object') return;
    if (Array.isArray(value)) {
      for (const item of value.slice(0, 64)) visit(item, depth + 1);
      return;
    }
    for (const [name, item] of Object.entries(value).slice(0, 64)) {
      if (name === key && typeof item === 'string') found.push(item);
      visit(item, depth + 1);
    }
  };
  visit(document, 0);
  return nodes <= 256 && found.length === 1 ? found[0] : null;
}
/** Substitute one reviewed concrete path slot after a fresh JSON capture. */
export function boundSequencePath(path, binding, captured) {
  if (binding?.placement !== 'path') return path;
  if (typeof path !== 'string' || !Number.isInteger(binding.segment) ||
      binding.segment < 0 || typeof captured !== 'string' ||
      !SEQUENCE_VALUE.test(captured)) return null;
  let url;
  try {url = new URL(path, 'http://placeholder.invalid');} catch {return null;}
  const parts = url.pathname.split('/').slice(1);
  if (!parts[binding.segment]) return null;
  parts[binding.segment] = captured;
  return `/${parts.join('/')}${url.search}`;
}
export const validModelJsonPointer = pointer => typeof pointer === 'string' &&
  /^(?:\/[A-Za-z_][A-Za-z0-9_-]{0,63}){1,3}$/.test(pointer);
/** Read a small, exact JSON field path without evaluating model-supplied code. */
export function modelJsonPointer(body, pointer) {
  if (!validModelJsonPointer(pointer)) return null;
  let value;
  try {value = JSON.parse(body);} catch {return null;}
  for (const key of pointer.slice(1).split('/')) {
    if (!object(value) || !Object.hasOwn(value, key)) return null;
    value = value[key];
  }
  return typeof value === 'string' && /^[\x21-\x7e]{16,4096}$/.test(value) ? value : null;
}
const PEM_PRIVATE_KEY = /-----BEGIN ((?:RSA |EC |DSA )?PRIVATE KEY)-----[\s\S]{1,8192}?-----END \1-----/g;

/** Return only the field name and count when a public JSON list exposes distinct account credentials. */
export function anonymousCredentialExposure(body) {
  if (typeof body !== 'string' || Buffer.byteLength(body) > MODEL_RESPONSE_BYTES) return null;
  let json;
  try {json = JSON.parse(body);} catch {return null;}
  const rows = Array.isArray(json) ? json :
    ['users', 'accounts', 'members', 'data', 'items', 'results', 'records'].map(key => json?.[key])
      .find(Array.isArray);
  if (!Array.isArray(rows) || rows.length < 2) return null;
  const names = new Set(['passwordhash', 'password_hash', 'passwdhash', 'passwd_hash',
    'password', 'passwd', 'apikey', 'api_key', 'accesstoken', 'access_token',
    'sessiontoken', 'session_token']);
  const matches = new Map();
  for (const row of rows) {
    if (!object(row)) continue;
    const id = ['id', '_id', 'uid', 'uuid', 'userId', 'user_id'].map(key => row[key])
      .find(value => (typeof value === 'string' || typeof value === 'number') &&
        /^[A-Za-z0-9_.:-]{1,128}$/.test(String(value)));
    if (id === undefined) continue;
    for (const [field, value] of Object.entries(row)) {
      const lower = field.toLowerCase();
      if (!names.has(lower) || typeof value !== 'string' || /example|dummy|sample|placeholder|redacted|fake/i.test(value))
        continue;
      const hash = /^(?:passwordhash|password_hash|passwdhash|passwd_hash)$/.test(lower) &&
        (/^\$2[aby]\$\d\d\$[./A-Za-z0-9]{53}$/.test(value) ||
          /^\$argon2(?:id|i|d)\$(?:v=\d+\$)?m=\d+,t=\d+,p=\d+\$[A-Za-z0-9+/]{8,}\$[A-Za-z0-9+/]{16,}$/.test(value));
      const token = /^(?:apikey|api_key|accesstoken|access_token|sessiontoken|session_token)$/.test(lower) &&
        /^[\x21-\x7e]{20,512}$/.test(value) && /[a-zA-Z]/.test(value) && /\d/.test(value);
      const password = /^(?:password|passwd)$/.test(lower) && /^[\x21-\x7e]{8,128}$/.test(value) &&
        /[a-zA-Z]/.test(value) && /\d/.test(value);
      if (!(hash || token || password)) continue;
      const group = matches.get(field) ?? new Map();
      group.set(String(id), value);
      matches.set(field, group);
    }
  }
  for (const [field, records] of matches) if (records.size >= 2 && new Set(records.values()).size >= 2)
    return {field, records: records.size};
  return null;
}

/** Return only public-key fingerprints for complete, parseable private-key blocks. */
export function publicPrivateKeyFingerprints(body) {
  if (typeof body !== 'string' || Buffer.byteLength(body) > MODEL_RESPONSE_BYTES) return [];
  const fingerprints = new Set();
  const texts = [body];
  try {
    const map = JSON.parse(body);
    if (Array.isArray(map?.sourcesContent))
      for (const value of map.sourcesContent) if (typeof value === 'string') texts.push(value);
  } catch { /* ordinary JavaScript is not a source map */ }
  for (const text of texts) for (const match of text.matchAll(PEM_PRIVATE_KEY)) {
    try {
      const publicKey = createPublicKey(createPrivateKey(match[0])).export({type: 'spki', format: 'der'});
      fingerprints.add(`sha256:${sha(publicKey)}`);
    } catch { /* a header or malformed block is not a valid exposed key */ }
  }
  return [...fingerprints];
}

const PUBLIC_CREDENTIAL_PATTERNS = Object.freeze([
  ['github-token', /\b(?:gh[po]_[0-9A-Za-z]{36}|github_pat_[A-Za-z0-9_]{22,255})\b/g],
  ['stripe-secret-key', /\bsk_live_[0-9A-Za-z]{20,247}\b/g],
  ['stripe-restricted-key', /\brk_live_[0-9A-Za-z]{20,247}\b/g],
  ['sendgrid-key', /\bSG\.[\w-]{22}\.[\w-]{43}\b/g],
]);

/** High-confidence credential-shaped values in a public asset; return only kind and digest. */
export function publicCredentialFingerprints(body) {
  if (typeof body !== 'string' || Buffer.byteLength(body) > MODEL_RESPONSE_BYTES) return [];
  const found = new Map();
  for (const [name, pattern] of PUBLIC_CREDENTIAL_PATTERNS) for (const match of body.matchAll(pattern)) {
    const token = match[0];
    const suffix = token.replace(/^(?:gh[po]_|github_pat_|[sr]k_live_|SG\.)/, '');
    if (/(?:example|dummy|sample|placeholder|redacted|fake)/i.test(suffix)) continue;
    let ascending = 1, syntheticSequence = false;
    for (let index = 1; index < suffix.length; index++) {
      ascending = suffix.charCodeAt(index) === suffix.charCodeAt(index - 1) + 1 ? ascending + 1 : 1;
      if (ascending >= 8) {syntheticSequence = true; break;}
    }
    if (syntheticSequence) continue;
    const counts = new Map();
    for (const char of suffix) counts.set(char, (counts.get(char) ?? 0) + 1);
    const entropy = [...counts.values()].reduce((sum, count) => {
      const probability = count / suffix.length;
      return sum - probability * Math.log2(probability);
    }, 0);
    if (counts.size < 8 || entropy < 3.2) continue;
    const fingerprint = `sha256:${sha(token)}`;
    found.set(`${name} ${fingerprint}`, {name, fingerprint});
  }
  return [...found.values()];
}

/** Preserve an operator-supplied JWT payload while changing only its signature or algorithm header. */
export function jwtUnsignedCanaries(token) {
  if (typeof token !== 'string' || token.length > 8192) return null;
  const parts = token.split('.');
  if (parts.length !== 3 || parts.some(part => !/^[A-Za-z0-9_-]+$/.test(part))) return null;
  let header, payload;
  try {
    header = JSON.parse(Buffer.from(parts[0], 'base64url').toString('utf8'));
    payload = JSON.parse(Buffer.from(parts[1], 'base64url').toString('utf8'));
  } catch {return null;}
  if (!object(header) || !object(payload) || !Object.keys(payload).length ||
      typeof header.alg !== 'string' || !header.alg || header.alg.toLowerCase() === 'none') return null;
  const encode = value => Buffer.from(JSON.stringify(value)).toString('base64url');
  let invalidSignature = randomBytes(18).toString('base64url');
  if (invalidSignature === parts[2]) invalidSignature = randomBytes(18).toString('base64url');
  return {invalidSignature: `${parts[0]}.${parts[1]}.${invalidSignature}`,
    first: `${encode({alg: 'none', typ: 'JWT'})}.${parts[1]}.`,
    second: `${encode({typ: 'JWT', alg: 'none'})}.${parts[1]}.`};
}

/** An invalid signature and an anonymous request must fail before two unsigned tokens can count. */
export function jwtUnsignedOracle(owner, anonymous, invalidSignature, first, second) {
  const responses = [owner, anonymous, invalidSignature, first, second];
  return responses.every(item => item?.status != null && item.status !== 429 && item.status < 500 &&
      !responseCached(item)) && owner.status === 200 && !!owner.hash &&
    (owner.json === true || /json|\+json/i.test(owner.type ?? '')) &&
    cleanDenied(anonymous) && cleanDenied(invalidSignature) &&
    first.status === 200 && first.hash === owner.hash &&
    second.status === 200 && second.hash === owner.hash;
}
const ISOLATION_CSP = "default-src 'none'; base-uri 'none'; form-action 'none'; frame-src 'none'; object-src 'none'; connect-src 'none'; img-src 'none'; style-src 'none'; font-src 'none'; media-src 'none'; worker-src 'none'; script-src 'self' 'unsafe-inline'; navigate-to 'none'";
export function xssPayload(style, marker) {
  if (!XSS_STYLES.has(style) || !/^[0-9a-f]{24}$/.test(marker)) throw Error('Invalid reflected-XSS canary.');
  const script = `<script>document.documentElement.dataset.bypassXss="${marker}"</script>`;
  return style === 'html-single' ? `'>${script}` : style === 'script-close' ? `</script>${script}` : `">${script}`;
}

/** Markup only: the canary has no script, event handler, network URL or state change. */
export function htmlInjectionPayload(style, marker) {
  if (!HTML_INJECTION_STYLES.includes(style) || !/^[0-9a-f]{24}$/.test(marker))
    throw Error('Invalid HTML-injection canary.');
  const element = `<b id="bx-html-${marker}" data-bypass-audit="html"></b>`;
  return style === 'double-quote' ? `">${element}` :
    style === 'single-quote' ? `'>${element}` :
    style === 'textarea-close' ? `</textarea>${element}` :
    style === 'script-close' ? `</script>${element}` : element;
}

export function domXssPayload(marker) {
  if (!/^[0-9a-f]{24}$/.test(marker)) throw Error('Invalid DOM-XSS canary.');
  return `<img src=bx-${marker} onerror="document.documentElement.dataset.bypassXss='${marker}'">`;
}

export const domXssFragment = marker => encodeURIComponent(domXssPayload(marker)).replaceAll("'", '%27');

export function crlfCanary(marker) {
  if (!/^[0-9a-f]{24}$/.test(marker)) throw Error('Invalid response-header canary.');
  return `bx-${marker}\r\nX-Bypass-Audit: ${marker}`;
}

export function crlfControl(marker) {
  if (!/^[0-9a-f]{24}$/.test(marker)) throw Error('Invalid response-header control.');
  return `bx-${marker} X-Bypass-Audit: ${marker}`;
}

export function sstiCanary() {
  const a = 1000 + randomBytes(2).readUInt16BE(0) % 8000;
  const b = 1000 + randomBytes(2).readUInt16BE(0) % 8000;
  return {input: `{{${a}*${b}}}`, result: String(a * b)};
}

/** Read-only boolean pairs. The search form closes a quoted expression and tests a wider result set. */
export function sqlBooleanCanary(base, style) {
  if (typeof base !== 'string' || !/^[A-Za-z0-9_.@-]{1,64}$/.test(base) ||
      !['quoted', 'numeric', 'search-quote-close-or'].includes(style) ||
      style === 'numeric' && !/^\d{1,12}$/.test(base))
    throw Error('Invalid SQL boolean probe value.');
  const number = 1000 + randomBytes(2).readUInt16BE(0) % 8000;
  if (style === 'search-quote-close-or') return {number,
    yes: `${base}')) OR ${number}=${number}--`,
    no: `${base}')) OR ${number}=${number + 1}--`};
  return style === 'quoted' ? {number,
    yes: `${base}' AND '${number}'='${number}`,
    no: `${base}' AND '${number}'='${number + 1}`} : {number,
    yes: `${base} AND ${number}=${number}`,
    no: `${base} AND ${number}=${number + 1}`};
}

export function sqlBooleanOracle(baseline, yes, no, style = 'quoted') {
  const json = value => /json|\+json/i.test(value?.type ?? '');
  const baselineIds = new Set((baseline?.ids ?? []).map(String));
  const validBaseline = baseline?.status === 200 && json(baseline) && baselineIds.size > 0 && !responseCached(baseline);
  if (style === 'search-quote-close-or') {
    const yesIds = new Set((yes?.ids ?? []).map(String));
    return validBaseline && yes?.status === 200 && json(yes) && !responseCached(yes) &&
      yesIds.size > baselineIds.size && [...baselineIds].every(id => yesIds.has(id)) &&
      no?.status === 200 && json(no) && !responseCached(no) && (no.ids ?? []).length === 0 &&
      yes.hash !== baseline.hash && no.hash !== baseline.hash;
  }
  const trueMatch = yes?.status === 200 && json(yes) && !responseCached(yes) && yes.hash === baseline?.hash;
  const falseMatch = no?.status === 404 || no?.status === 200 && json(no) && no.hash !== baseline?.hash &&
    !(no.ids ?? []).some(id => baselineIds.has(String(id)));
  return validBaseline && trueMatch && falseMatch && !responseCached(no);
}

/** Read-only equality operator shape; never sends $ne, $where, JavaScript or a write operator. */
export function nosqlEqUrl(raw, origin, parameter, value) {
  if (!safeProbeParameter(parameter) ||
      typeof value !== 'string' || !/^[A-Za-z0-9_.@-]{1,96}$/.test(value))
    throw Error('Invalid equality-operator probe.');
  const url = new URL(raw, origin);
  url.searchParams.delete(parameter);
  url.searchParams.set(`${parameter}[$eq]`, value);
  return url.href;
}

/** The operator must expose an owner record that a plain outsider lookup cannot read. */
export function nosqlOperatorOracle(owner, plain, yes, no, recordId) {
  const has = response => (response?.ids ?? []).some(id => String(id) === recordId);
  const json = response => response?.json === true || /json|\+json/i.test(response?.type ?? '');
  const stable = response => response?.status != null && !responseCached(response);
  const plainDenied = denied(plain?.status) || plain?.status === 200 && json(plain) && !has(plain);
  const negativeAbsent = [400, 401, 403, 404].includes(no?.status) ||
    no?.status === 200 && json(no) && !has(no);
  return stable(owner) && stable(plain) && stable(yes) && stable(no) &&
    owner.status === 200 && json(owner) && has(owner) && plainDenied &&
    yes.status === 200 && json(yes) && has(yes) && yes.hash === owner.hash && negativeAbsent;
}

/** A duplicate query parameter can test a validation/parser mismatch without following the redirect. */
export function redirectPollutionUrl(raw, origin, parameter, destination, variant) {
  if (!validQueryParameter(parameter) ||
      !/^https:\/\/bypass-audit\.invalid\/[0-9a-f]{16}-[ab]$/.test(destination) ||
      !['safe', 'external', 'safe-first', 'external-first'].includes(variant))
    throw Error('Invalid duplicate-parameter redirect probe.');
  const url = new URL(raw, origin);
  url.searchParams.delete(parameter);
  for (const value of variant === 'safe' ? ['/safe'] : variant === 'external' ? [destination] :
    variant === 'safe-first' ? ['/safe', destination] : [destination, '/safe'])
    url.searchParams.append(parameter, value);
  return url.href;
}

export function redirectPollutionOracle(safe, scalar, duplicate, destination, origin) {
  const location = response => response?.location ?? response?.headers?.location;
  const pointsTo = (response, target) => {
    const raw = location(response);
    return [301, 302, 303, 307, 308].includes(response?.status) && raw && URL.canParse(raw, origin) &&
      new URL(raw, origin).href === target;
  };
  return [safe, scalar, duplicate].every(response => response?.status != null &&
      response.status !== 429 && response.status < 500 && !responseCached(response)) &&
    pointsTo(safe, new URL('/safe', origin).href) && !pointsTo(scalar, destination) &&
    pointsTo(duplicate, destination);
}

/** Match one fixed Host against the same observed redirect path and query. */
export function hostHeaderRedirectMatch(control, changed, origin, index) {
  if (![0, 1].includes(index) || [control, changed].some(response =>
      ![301, 302, 303, 307, 308].includes(response?.status) ||
      response.status !== control?.status || responseCached(response))) return false;
  const location = response => {
    const raw = response?.location ?? response?.headers?.location;
    return typeof raw === 'string' && URL.canParse(raw, origin) ? new URL(raw, origin) : null;
  };
  const base = location(control);
  if (!base || base.origin !== origin || base.username || base.password) return false;
  const actual = location(changed);
  const expected = new URL(base.href);
  expected.hostname = HOST_HEADER_CANARIES[index];
  expected.port = '';
  return actual?.href === expected.href;
}

/** The destination must change only with two fixed Host values on one observed redirect. */
export function hostHeaderRedirectOracle(control, first, second, origin) {
  return hostHeaderRedirectMatch(control, first, origin, 0) &&
    hostHeaderRedirectMatch(control, second, origin, 1);
}

export function responseCached(value) {
  return value?.headers?.age != null || /HIT/i.test(value?.headers?.['x-cache'] ?? '');
}

/** An arbitrary value for one named cookie must repeatedly cross the same access boundary. */
export function cookieAccessOutcome(responses) {
  if (!Array.isArray(responses) || responses.length !== 8)
    return {verdict: 'inconclusive', reason: 'cookie access controls are incomplete'};
  if (responses.some(item => item?.blocked || item?.refused ||
      !Number.isInteger(item?.status) || item.status === 429 ||
      item.status >= 500 || responseCached(item)))
    return {verdict: 'inconclusive', reason: 'a cookie access control was unavailable or cached'};
  const signature = item => JSON.stringify([item.status, item.type, item.hash]);
  const [noCookieA, wrongNameA, namedA, namedB,
    noCookieB, wrongNameB, namedC, namedD] = responses;
  const closed = signature(noCookieA), opened = signature(namedA);
  if ([wrongNameA, noCookieB, wrongNameB].some(item => signature(item) !== closed) ||
      [namedB, namedC, namedD].some(item => signature(item) !== opened))
    return {verdict: 'inconclusive', reason: 'cookie controls did not produce stable responses'};
  if (closed === opened)
    return {verdict: 'not_reproduced', reason: 'the named cookie did not change access'};
  if ([namedA, namedB, namedC, namedD].some(item =>
    item.status < 200 || item.status >= 300 ||
    !(item.bytes > 0 || typeof item.body === 'string' && item.body.length > 0)))
    return {verdict: 'inconclusive', reason: 'the changed response did not serve a successful body'};
  return {verdict: 'confirmed',
    reason: 'fresh arbitrary values for the named cookie repeatedly opened a distinct response; missing and wrong-name controls stayed closed'};
}

/** Replay model-authored requests and compare an access boundary, never a label alone. */
export function rawBoundaryOutcome(responses, proof, candidateRequests = []) {
  if (!Array.isArray(responses) || responses.length !== 6)
    return {verdict: 'inconclusive', reason: 'raw proof controls are incomplete'};
  const pathOf = requests => {
    try {return new URL(requests.at(-1).path, 'https://proof.invalid').pathname;}
    catch {return null;}
  };
  const paths = [proof?.baseline, proof?.negative, candidateRequests].map(pathOf);
  if (!paths[0] || paths.some(path => path !== paths[0]))
    return {verdict: 'inconclusive',
      reason: 'raw proof controls did not address the same final route'};
  if (responses.some(item => !item || item.blocked || item.refused ||
      !Number.isInteger(item.status) || item.status === 429 ||
      item.status >= 500 || responseCached(item)))
    return {verdict: 'inconclusive', reason: 'a raw proof response was unavailable or cached'};
  const [baselineA, negativeA, candidateA, candidateB, negativeB, baselineB] = responses;
  const controls = [baselineA, negativeA, negativeB, baselineB];
  const candidates = [candidateA, candidateB];
  const closedText = proof?.closedText ?? '';
  const openText = proof?.openText ?? '';
  const signature = item => JSON.stringify([item.status, item.type,
    item.hash ?? `sha256:${sha(item.body ?? '')}`]);
  if (controls.every(item => signature(item) === signature(candidateA)) &&
      signature(candidateA) === signature(candidateB))
    return {verdict: 'not_reproduced', reason: 'candidate and controls returned the same response'};
  if (closedText && openText) {
    if (closedText === openText || JSON.stringify(candidateRequests).includes(openText))
      return {verdict: 'inconclusive',
        reason: 'the positive marker is ambiguous or supplied by the request itself'};
    const closed = item => String(item.body ?? '').includes(closedText) &&
      !String(item.body ?? '').includes(openText);
    const opened = item => item.status >= 200 && item.status < 300 &&
      String(item.body ?? '').includes(openText) &&
      !String(item.body ?? '').includes(closedText);
    if (controls.every(closed) && candidates.every(opened))
      return {verdict: 'confirmed',
        reason: 'two fresh candidate replays crossed the recorded page boundary while both negative controls stayed closed'};
    if (controls.every(closed) && candidates.every(closed))
      return {verdict: 'not_reproduced', reason: 'candidate stayed on the same gated page as the controls'};
    return {verdict: 'inconclusive', reason: 'page boundary markers were unstable across controls'};
  }
  if (closedText || openText)
    return {verdict: 'inconclusive', reason: 'both closed and open response markers are needed'};
  const denied = item => [401, 403, 404].includes(item.status);
  const opened = item => item.status >= 200 && item.status < 300 &&
    String(item.body ?? '').length > 0;
  if (controls.every(denied) && candidates.every(opened))
    return {verdict: 'confirmed',
      reason: 'two fresh candidate replays returned content from a route denied to both controls'};
  return {verdict: 'inconclusive',
    reason: 'the candidate did not establish a stable denied-to-allowed boundary'};
}

/** Encode the marker as octal escapes so a plain reflection cannot satisfy the output oracle. */
export function commandOutputCanary(marker) {
  if (!/^bx[0-9a-f]{24}$/.test(marker)) throw Error('Invalid command-output marker.');
  const octal = [...Buffer.from(marker, 'ascii')].map(byte => `\\${byte.toString(8).padStart(3, '0')}`).join('');
  return {marker, control: `bx-${octal}`, payload: `bx;printf '${octal}'`};
}

export function commandOutputOracle(control, executed, marker) {
  return control?.status === 200 && executed?.status === 200 && !responseCached(control) && !responseCached(executed) &&
    !control.body?.includes(marker) && executed.body?.includes(marker);
}

const HOSTS_LINE = /^127\.0\.0\.1[\t ]+localhost(?:[\t \r]|$)/m;

export function hostsTraversalCanary() {
  const prefix = '../'.repeat(12);
  return {control: `bx-${randomBytes(12).toString('hex')}.txt`,
    first: `${prefix}etc/hosts`, second: `../${prefix}etc/hosts`};
}

export function hostsTraversalOracle(control, first, second) {
  return [first, second].every(item => item?.status === 200 && !responseCached(item) &&
      typeof item.body === 'string' && item.body.length >= 20 &&
      Buffer.byteLength(item.body) <= MODEL_RESPONSE_BYTES &&
      HOSTS_LINE.test(item.body) && !/<html\b/i.test(item.body)) &&
    control?.status != null && control.status < 500 && control.status !== 429 &&
    !responseCached(control) && !HOSTS_LINE.test(control.body ?? '') &&
    first.hash === second.hash && first.hash !== control.hash;
}

/** A literal entity checks XML handling; two distinct external entities request only /etc/hosts. */
export function xxeHostsCanaries() {
  const marker = `bx${randomBytes(10).toString('hex')}`;
  const xml = (entity, declaration) =>
    `<?xml version="1.0"?><!DOCTYPE audit [<!ENTITY ${entity} ${declaration}>]><audit>&${entity};</audit>`;
  const firstName = `bx${randomBytes(6).toString('hex')}`;
  const secondName = `bx${randomBytes(6).toString('hex')}`;
  return {marker,
    control: xml('bxcontrol', `"${marker}"`),
    first: xml(firstName, 'SYSTEM "file:///etc/hosts"'),
    second: xml(secondName, 'SYSTEM "file:///etc/hosts"')};
}

export function xxeLiteralControl(control, marker) {
  return control?.status === 200 && !responseCached(control) &&
    control.body?.includes(marker) && !HOSTS_LINE.test(control.body);
}

export function xxeHostsOracle(control, first, second, marker) {
  return xxeLiteralControl(control, marker) &&
    [first, second].every(item => item?.status === 200 && !responseCached(item) &&
      typeof item.body === 'string' && item.body.length >= 20 &&
      Buffer.byteLength(item.body) <= MODEL_RESPONSE_BYTES &&
      HOSTS_LINE.test(item.body) && !/<html\b/i.test(item.body));
}

/** Check serialized browser tags, ignoring marker text inside attributes and raw-text elements. */
function hasHtmlCanary(markup, marker) {
  const expected = `bx-html-${marker}`;
  const lower = markup.toLowerCase();
  let at = 0, raw = null;
  while (at < markup.length) {
    if (raw) {
      const close = lower.indexOf(`</${raw}`, at);
      if (close < 0) return false;
      at = close;
      raw = null;
    }
    const start = markup.indexOf('<', at);
    if (start < 0) return false;
    if (markup.startsWith('<!--', start)) {
      const end = markup.indexOf('-->', start + 4);
      if (end < 0) return false;
      at = end + 3;
      continue;
    }
    let quote = null, end = start + 1;
    for (; end < markup.length; end++) {
      const char = markup[end];
      if (quote) {if (char === quote) quote = null;}
      else if (char === '"' || char === "'") quote = char;
      else if (char === '>') break;
    }
    if (end >= markup.length) return false;
    const tag = markup.slice(start, end + 1);
    at = end + 1;
    const match = /^<\s*(\/)?\s*([a-z][a-z0-9:-]*)\b/i.exec(tag);
    if (!match || match[1]) continue;
    const name = match[2].toLowerCase();
    if (name === 'b') {
      const id = /(?:^|\s)id\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s>]+))/i.exec(tag);
      if ((id?.[1] ?? id?.[2] ?? id?.[3]) === expected) return true;
    }
    if (['script', 'style', 'textarea', 'title'].includes(name)) raw = name;
  }
  return false;
}

/** Execute captured HTML and explicitly captured scripts through a deny-all local proxy. */
export async function renderCapturedHtml(body, originalCsp, marker,
  {sourceUrl = null, fragment = '', scripts = [], detectHtml = false,
    maxScriptBytes = DOM_SCRIPT_BYTES} = {}) {
  const scriptLimit = domScriptLimit(maxScriptBytes);
  if (!/^[0-9a-f]{24}$/.test(marker) || typeof body !== 'string' ||
      Buffer.byteLength(body) > MODEL_RESPONSE_BYTES)
    return {executed: false, blocked: true, reason: 'Captured HTML or marker is invalid.'};
  if (typeof fragment !== 'string' || fragment.length > 4096 || !Array.isArray(scripts) || scripts.length > 8 ||
      scripts.some(item => typeof item?.url !== 'string' || typeof item.body !== 'string' ||
        Buffer.byteLength(item.body) > scriptLimit || (item.type != null && typeof item.type !== 'string')))
    return {executed: false, blocked: true, reason: 'Captured fragment or scripts exceed the browser budget.'};
  const profile = fs.mkdtempSync(path.join(os.tmpdir(), 'bx-xss-'));
  const fakeOrigin = 'http://bypass-audit.invalid';
  const source = sourceUrl ? new URL(sourceUrl) : new URL('/', fakeOrigin);
  const pageUrl = new URL(`${source.pathname}${source.search}`, fakeOrigin);
  const pageRequestUrl = pageUrl.href;
  const captureTag = `data-bypass-captured="${marker}"`;
  pageUrl.hash = fragment;
  const captured = new Map(scripts.map(item => {
    const original = new URL(item.url, source);
    const fake = new URL(`${original.pathname}${original.search}`, fakeOrigin);
    return [fake.href, {original: original.href, body: item.body, type: item.type,
      nosniff: item.nosniff === true}];
  }));
  const rewritten = sourceUrl ? body.replace(/<script\b[^>]*>/gi, tag =>
    tag.replace(/(\s)src\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s>]+))/i, (attribute, space, double, single, bare) => {
      const raw = (double ?? single ?? bare).replaceAll('&amp;', '&');
      if (!URL.canParse(raw, source)) return attribute;
      const original = new URL(raw, source).href;
      const script = [...captured].find(([, value]) => value.original === original);
      return script ? `${space}src="${script[0]}"` : attribute;
    })) : body;
  const capturedHtml = /<html\b/i.test(rewritten) ?
    rewritten.replace(/<html\b/i, `<html ${captureTag}`) :
    `<meta ${captureTag}>${rewritten}`;
  const server = http.createServer((request, response) => {
    let requested;
    try {requested = new URL(request.url, fakeOrigin);} catch { /* Deny malformed proxy requests. */ }
    const authorized = requested?.origin === fakeOrigin &&
      (!request.url.startsWith('/') || /^bypass-audit\.invalid(?::80)?$/i.test(request.headers.host ?? ''));
    if (request.method !== 'GET') {
      response.writeHead(403, {'content-type': 'text/plain', 'cache-control': 'no-store'});
      response.end('Blocked by audit browser proxy.');
      return;
    }
    if (authorized && requested.href === pageRequestUrl) {
      const policies = (Array.isArray(originalCsp) ? originalCsp : [originalCsp])
        .filter(policy => typeof policy === 'string' && policy);
      const csp = [...policies, ISOLATION_CSP];
      response.writeHead(200, {'content-type': 'text/html; charset=utf-8', 'content-security-policy': csp,
        'cache-control': 'no-store'});
      response.end(capturedHtml);
      return;
    }
    if (authorized && captured.has(requested.href)) {
      const script = captured.get(requested.href);
      response.writeHead(200, {'content-type': script.type ?? 'application/javascript; charset=utf-8',
        ...(script.nosniff ? {'x-content-type-options': 'nosniff'} : {}), 'cache-control': 'no-store'});
      response.end(script.body);
      return;
    }
    response.writeHead(403, {'content-type': 'text/plain', 'cache-control': 'no-store'});
    response.end('Blocked by audit browser proxy.');
  });
  server.on('connect', (_request, socket) => {
    socket.on('error', () => {});
    socket.end('HTTP/1.1 403 Forbidden\r\nConnection: close\r\n\r\n');
  });
  server.on('clientError', (_error, socket) => {
    socket.on('error', () => {});
    socket.destroy();
  });
  try {
    await new Promise((resolve, reject) => {server.once('error', reject);server.listen(0, '127.0.0.1', resolve);});
    const args = ['--headless=new', '--no-sandbox', '--disable-gpu', '--disable-background-networking',
      '--disable-extensions', '--disable-sync', '--disable-component-update', '--no-first-run',
      '--no-default-browser-check', '--disable-dev-shm-usage', '--virtual-time-budget=2000',
      `--proxy-server=127.0.0.1:${server.address().port}`,
      '--proxy-bypass-list=<-loopback>',
      `--user-data-dir=${profile}`, '--dump-dom', pageUrl.href];
    const candidates = process.env.BYPASS_CHROME ? [process.env.BYPASS_CHROME] :
      process.platform === 'win32' ? ['chrome.exe'] : process.platform === 'darwin' ?
        ['/Applications/Google Chrome.app/Contents/MacOS/Google Chrome',
          path.join(os.homedir(), 'Applications/Google Chrome.app/Contents/MacOS/Google Chrome'),
          'google-chrome', 'chromium', 'chromium-browser'] : ['google-chrome', 'chromium', 'chromium-browser'];
    for (const command of candidates) {
      for (let attempt = 0; attempt < 2; attempt++) {
        try {
          const runArgs = attempt ? args.map(arg => arg === `--user-data-dir=${profile}` ?
            `--user-data-dir=${profile}-retry` : arg) : args;
          const output = await new Promise((resolve, reject) => childExecFile(command, runArgs,
            {timeout: 12000, maxBuffer: 1_000_000}, (error, stdout) => error ? reject(error) : resolve(stdout)));
          if (!output.includes(captureTag)) {
            if (!attempt) continue;
            return {executed: false, blocked: true, reason: 'Chrome did not render the captured page.'};
          }
          return {executed: new RegExp(`<html\\b[^>]*\\bdata-bypass-xss="${marker}"`, 'i').test(output),
            elementInserted: detectHtml ? hasHtmlCanary(output, marker) : false};
        } catch (error) {
          if (error.code === 'ENOENT') break;
          if (!attempt) continue;
          return {executed: false, blocked: true, reason: `Chrome did not complete (${error.code ?? 'error'}).`};
        }
      }
    }
    return {executed: false, blocked: true, reason: 'Chrome is not available.'};
  } finally {
    await new Promise(resolve => server.close(resolve));
    fs.rmSync(profile, {recursive: true, force: true});
    fs.rmSync(`${profile}-retry`, {recursive: true, force: true});
  }
}
function publicIp(address) {
  if (net.isIP(address) === 4) {
    const [a, b, c] = address.split('.').map(Number);
    return !(a === 0 || a === 10 || a === 127 || a >= 224 || (a === 100 && b >= 64 && b <= 127) ||
      (a === 169 && b === 254) || (a === 172 && b >= 16 && b <= 31) ||
      (a === 192 && (b === 168 || b === 0 || (b === 88 && c === 99))) ||
      (a === 198 && (b === 18 || b === 19 || (b === 51 && c === 100))) ||
      (a === 203 && b === 0 && c === 113));
  }
  return net.isIP(address) === 6 && /^[23][0-9a-f]{3}:/i.test(address) && !/^(2001:(db8|0|10|20):|2002:)/i.test(address);
}
async function guardedRequest(url, {method = 'GET', headers = {}, body = null,
  allowRemoteHttp = false, maxBodyBytes = MODEL_RESPONSE_BYTES} = {}) {
  const budget = replayBudget.getStore();
  if (budget) {
    if (budget.signal.aborted || budget.requests >= MAX_PROOF_REQUESTS)
      throw Error('Proof replay exceeded its request or time budget.');
    budget.requests++;
  }
  const host = url.hostname.replace(/^\[|\]$/g, '');
  const local = localHost(host);
  if (!local && url.protocol !== 'https:' && !(allowRemoteHttp && url.protocol === 'http:'))
    throw Error('Remote proof requests require HTTPS unless the sealed scope explicitly allows anonymous HTTP.');
  const addresses = net.isIP(host) ? [{address: host, family: net.isIP(host)}] : await dns.lookup(host, {all: true});
  if (!addresses.length || !addresses.every(item => local ? localHost(item.address) : publicIp(item.address)))
    throw Error('Proof destination resolves outside the permitted public or loopback network.');
  const chosen = addresses[0];
  return new Promise((resolve, reject) => {
    const client = url.protocol === 'https:' ? https : http;
    const request = client.request(url, {method, headers: {accept: 'application/json', ...headers}, agent: false,
      signal: budget?.signal,
      family: chosen.family, servername: net.isIP(host) ? undefined : host,
      lookup: (_name, options, callback) => options?.all ? callback(null, [chosen]) :
        callback(null, chosen.address, chosen.family)}, response => {
      const chunks = [];
      let bytes = 0;
      response.on('data', chunk => {
        bytes += chunk.length;
        if (bytes > maxBodyBytes) request.destroy(Error('Proof response exceeds its byte limit.'));
        else chunks.push(chunk);
      });
      response.on('end', () => {
        const data = Buffer.concat(chunks);
        resolve({status: response.statusCode, body: data.toString('utf8'),
          prefixHex: data.subarray(0, 16).toString('hex'), headers: response.headers});
      });
      response.on('error', reject);
    });
    request.setTimeout(8000, () => request.destroy(Error('Proof request timed out.')));
    request.on('error', reject);
    request.end(body);
  });
}

const guardedGet = (url, headers, allowRemoteHttp = false, maxBodyBytes = MODEL_RESPONSE_BYTES) =>
  guardedRequest(url, {headers, allowRemoteHttp, maxBodyBytes});

async function pace(spec) {
  const budget = replayBudget.getStore();
  if (budget?.signal.aborted) throw Error('Proof replay exceeded its time budget.');
  const spacing = 1000 / Math.max(0.5, Math.min(100, Number(spec.rps) || 2));
  const at = Math.max(Date.now(), nextRequestAt);
  nextRequestAt = at + spacing;
  if (at > Date.now()) await wait(at - Date.now(), undefined, {signal: budget?.signal});
}

function neverMatches(spec, path, search, {pathOnly = false} = {}) {
  const words = [...path.split('/'), ...new URLSearchParams(search).keys(), ...new URLSearchParams(search).values()];
  return spec.never.some(entry => {
    const lower = entry.toLowerCase();
    if (lower.startsWith('/')) {
      const expression = lower.split('*').map(part => part.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')).join('.*');
      return new RegExp(`^${expression}$`).test(path.toLowerCase());
    }
    if (pathOnly) return false;
    return words.some(word => {const value = String(word).toLowerCase();
      return value.startsWith(lower) && !/[a-z]/.test(value[lower.length] ?? '');});
  });
}

function reviewedPostOrigin(spec) {
  if (!URL.canParse(spec?.origin)) return false;
  const origin = new URL(spec.origin);
  return spec.targetEnvironment === 'local' ? localHost(origin.hostname) :
    ['preview', 'staging', 'production'].includes(spec.targetEnvironment) &&
    origin.protocol === 'https:' && !localHost(origin.hostname);
}

function checkedUrl(spec, raw, {reviewedJsonPost = false, reviewedFlowPost = false,
  reviewedFlowStep = null, reviewedBoundaryPost = false} = {}) {
  const url = new URL(raw, spec.origin);
  const pathOnly = (reviewedJsonPost &&
    ['model-json-differential', 'xss-stored'].includes(spec.kind) &&
    reviewedPostOrigin(spec) && url.pathname === spec.jsonPostPath &&
    !url.search) || (reviewedFlowPost && ['model-http-sequence', 'model-access-boundary',
      'model-state-change'].includes(spec.kind) &&
    reviewedPostOrigin(spec) && !url.search &&
    (['json', 'form'].some(placement =>
      spec.reviewedPostPaths?.[placement]?.includes(url.pathname)) ||
    reviewedFlowStep?.path === url.pathname &&
      reviewedSequenceOperation(spec, reviewedFlowStep))) ||
    (reviewedBoundaryPost && spec.kind === 'model-access-boundary' &&
      reviewedPostOrigin(spec) && !url.search &&
      spec.reviewedPostPaths?.json?.includes(url.pathname));
  const included = spec.include.some(prefix => prefix === '/' || url.pathname === prefix ||
    url.pathname.startsWith(`${prefix.replace(/\/$/, '')}/`)) ||
    spec.kind === 'xss-dom-fragment' && Array.isArray(spec.assetUrls) && spec.assetUrls.includes(url.href);
  if (url.origin !== spec.origin || url.username || url.password || url.hash || url.pathname.includes('%') ||
      /[\\;]/.test(url.pathname) || url.pathname.split('/').some(part => part === '.' || part === '..') ||
      !included ||
      neverMatches(spec, url.pathname, url.search, {pathOnly}) || url.searchParams.size > 8)
    throw Error('Proof request is outside its recorded scope.');
  return url;
}

async function checkModelCookieAccess(spec) {
  const subject = spec.subject;
  if (spec.kind !== 'model-cookie-access' || spec.as !== 'anonymous' ||
      !['GET', 'HEAD'].includes(subject?.method) ||
      subject.placement !== 'cookie' ||
      !/^[A-Za-z0-9._~-]{1,128}$/.test(subject.key ?? ''))
    return {verdict: 'inconclusive', reason: 'cookie proof request is incomplete'};
  const url = checkedUrl(spec, subject.path);
  if (url.search || url.pathname !== subject.path)
    return {verdict: 'inconclusive', reason: 'cookie proof path changed'};
  const wrongName = `bxw_${randomBytes(8).toString('hex')}`;
  const values = Array.from({length: 4}, () => `bx${randomBytes(12).toString('hex')}`);
  const variants = [null, `${wrongName}=${values[0]}`,
    `${subject.key}=${values[0]}`, `${subject.key}=${values[1]}`,
    null, `${wrongName}=${values[2]}`,
    `${subject.key}=${values[2]}`, `${subject.key}=${values[3]}`];
  const labels = ['missing-a', 'wrong-name-a', 'named-a', 'named-b',
    'missing-b', 'wrong-name-b', 'named-c', 'named-d'];
  const responses = [], controls = [];
  for (const [index, cookie] of variants.entries()) {
    await pace(spec);
    const response = await guardedRequest(url, {method: subject.method,
      headers: {'cache-control': 'no-cache', ...(cookie ? {cookie} : {})},
      allowRemoteHttp: spec.allowRemoteHttp === true,
      maxBodyBytes: MODEL_RESPONSE_BYTES});
    const fact = {status: response.status,
      type: response.headers['content-type'] ?? '',
      hash: `sha256:${sha(response.body)}`,
      bytes: Buffer.byteLength(response.body), headers: response.headers};
    responses.push(fact);
    controls.push({label: labels[index], status: fact.status,
      hash: fact.hash, cached: responseCached(fact)});
  }
  return {...cookieAccessOutcome(responses), controls};
}

async function checkModelRawBoundary(spec, env) {
  if (!Array.isArray(spec.rawRequests) || !spec.rawRequests.length ||
      !Array.isArray(spec.rawProof?.baseline) || !spec.rawProof.baseline.length ||
      !Array.isArray(spec.rawProof?.negative) || !spec.rawProof.negative.length)
    return {verdict: 'inconclusive', reason: 'raw proof requests are incomplete'};
  const phases = [
    ['baseline-a', spec.rawProof.baseline],
    ['negative-a', spec.rawProof.negative],
    ['candidate-a', spec.rawRequests],
    ['candidate-b', spec.rawRequests],
    ['negative-b', spec.rawProof.negative],
    ['baseline-b', spec.rawProof.baseline],
  ];
  const allowedEnv = new Set([spec.identities?.owner, spec.identities?.outsider,
    spec.derivedLogin?.usernameEnv, spec.derivedLogin?.passwordEnv]
    .filter(value => typeof value === 'string'));
  const expand = value => String(value).replace(/\{\{env:([A-Za-z_][A-Za-z0-9_]*)\}\}/g,
    (whole, name) => allowedEnv.has(name) && typeof env[name] === 'string' ?
      env[name] : whole);
  const controls = [], responses = [];
  let derivedSession = null;
  for (const [index, [label, requests]] of phases.entries()) {
    if ((index === 0 || index === 3) && phases.some(([, steps]) =>
      steps.some(step => (step.as ?? spec.as) === 'derived'))) {
      const loginSpec = {...spec, ...spec.derivedLogin, kind: 'model-auth-login',
        origin: spec.origin, include: spec.include, never: spec.never,
        targetEnvironment: spec.targetEnvironment, auth: spec.auth};
      const login = await checkModelAuthLogin(loginSpec, env,
        session => {derivedSession = session;});
      if (login.verdict !== 'confirmed' || !derivedSession)
        return {verdict: 'inconclusive',
          reason: 'fresh derived session was unavailable for raw proof', controls};
    }
    let last = null;
    for (const [stepIndex, request] of requests.entries()) {
      const url = checkedUrl(spec, expand(request.path));
      if (Array.isArray(spec.methods) && !spec.methods.includes(request.method))
        return {verdict: 'inconclusive', reason: 'request method is outside the recorded scope', controls};
      const as = request.as ?? spec.as;
      const identity = as === 'derived' ? sessionHeaders(spec.auth, derivedSession) :
        await headerFor(spec, as, env, url);
      const headers = {...identity, ...Object.fromEntries((request.headers ?? [])
        .map(header => [header.name, expand(header.value)]))};
      await pace(spec);
      last = await guardedRequest(url, {method: request.method, headers,
        body: expand(request.body ?? ''),
        allowRemoteHttp: spec.allowRemoteHttp === true && as === 'anonymous',
        maxBodyBytes: MODEL_RESPONSE_BYTES});
      controls.push({label: `${label}-${stepIndex + 1}`, method: request.method,
        path: url.pathname, status: last.status,
        hash: `sha256:${sha(last.body)}`});
    }
    responses.push({...last, type: last.headers?.['content-type'] ?? '',
      hash: `sha256:${sha(last.body)}`});
  }
  return {...rawBoundaryOutcome(responses, spec.rawProof, spec.rawRequests), controls};
}

const LOGIN_TOKEN = /^[\x21-\x7e]{1,8192}$/;
const LOGIN_JWT = /^eyJ[\w-]*\.eyJ[\w-]*\.[\w-]*$/;
const LOGIN_FIELDS = [['token'], ['accessToken'], ['access_token'], ['id_token'], ['jwt'],
  ['authentication', 'token'], ['data', 'token']];

function loginCookie(headers) {
  const candidates = [];
  for (const line of [headers?.['set-cookie'] ?? []].flat()) {
    const [pair, ...attributes] = String(line).split(';');
    const at = pair.indexOf('=');
    if (at < 1) continue;
    const name = pair.slice(0, at).trim(), value = pair.slice(at + 1).trim();
    const deleted = attributes.some(attribute => {
      const [key, ...parts] = attribute.split('=');
      const data = parts.join('=').trim();
      return key.trim().toLowerCase() === 'max-age' && Number(data) <= 0 ||
        key.trim().toLowerCase() === 'expires' && Date.parse(data) <= Date.now();
    });
    if (!/^[A-Za-z0-9._~-]{1,128}$/.test(name) ||
        !/^[\x21-\x7e]{1,4096}$/.test(value) || /[;,]/.test(value) ||
        /csrf|xsrf/i.test(name) || deleted) continue;
    candidates.push({name, value,
      httpOnly: attributes.some(attribute => attribute.trim().toLowerCase() === 'httponly')});
  }
  const selected = candidates.find(item => /(session|sid|token|auth|jwt)/i.test(item.name)) ??
    (candidates.filter(item => item.httpOnly && item.value.length >= 16).length === 1 ?
      candidates.find(item => item.httpOnly && item.value.length >= 16) : null);
  return selected ? {placement: 'cookie', value: `${selected.name}=${selected.value}`} : null;
}

function loginToken(response, preferred = null) {
  if (preferred === 'cookie') {
    const cookie = loginCookie(response.headers);
    if (cookie) return cookie;
  }
  let json;
  try {json = JSON.parse(response.body);} catch { /* cookie-based login may have a non-JSON body */ }
  for (const keys of LOGIN_FIELDS) {
    const value = keys.reduce((node, key) => object(node) ? node[key] : undefined, json);
    if (typeof value === 'string' && LOGIN_TOKEN.test(value)) return {placement: 'bearer', value};
  }
  const jwt = (value, depth) => {
    if (typeof value === 'string') return LOGIN_JWT.test(value) && LOGIN_TOKEN.test(value) ? value : null;
    if (!value || typeof value !== 'object' || depth === 0) return null;
    for (const child of Object.values(value)) {const found = jwt(child, depth - 1); if (found) return found;}
    return null;
  };
  const nested = jwt(json, 3);
  if (nested) return {placement: 'bearer', value: nested};
  return loginCookie(response.headers);
}

const sessionHeaders = (auth, session) => auth === 'cookie' ? {cookie: session} :
  {authorization: `Bearer ${session}`};
const invalidSession = (auth, session = null) => {
  const random = `bx-invalid-${randomBytes(12).toString('hex')}`;
  return auth === 'cookie' ? `${String(session ?? 'session=').split('=')[0]}=${random}` : random;
};

/** Read a bearer token transiently from an explicit pointer or a small login JSON. */
export function modelAuthBearer(body, pointer) {
  const exact = modelJsonPointer(body, pointer);
  if (exact) return exact;
  if (typeof body !== 'string' || Buffer.byteLength(body) > MODEL_RESPONSE_BYTES) return null;
  const found = loginToken({body, headers: {}});
  return found?.placement === 'bearer' && /^[\x21-\x7e]{16,4096}$/.test(found.value) ?
    found.value : null;
}

async function bootstrapCredential(spec, as, env) {
  const name = spec.identities?.[as];
  const login = spec.authBootstrap?.[as];
  if (!login || !name) throw Error(`Missing credential environment variable ${name}.`);
  if (!Array.isArray(spec.credentialOrigins) || !spec.credentialOrigins.includes(login.origin))
    throw Error('Saved login origin is outside the credential scope.');
  if (typeof login.path !== 'string' || !login.path.startsWith('/') ||
      login.path.includes('%') || /[\\;#?]/.test(login.path) ||
      login.path.split('/').some(part => part === '.' || part === '..'))
    throw Error('Saved login path is invalid.');
  const url = new URL(login.path, login.origin);
  if (url.origin !== login.origin || url.pathname !== login.path || url.search || url.hash ||
      neverMatches(spec, url.pathname, ''))
    throw Error('Saved login path is outside the recorded scope.');
  if (typeof login.usernameField !== 'string' || typeof login.passwordField !== 'string' ||
      !/^[A-Za-z_][A-Za-z0-9_.-]{0,79}$/.test(login.usernameField) ||
      !/^[A-Za-z_][A-Za-z0-9_.-]{0,79}$/.test(login.passwordField) ||
      login.usernameField === login.passwordField ||
      !['json', 'form'].includes(login.encoding))
    throw Error('Saved login field description is invalid.');
  const username = env[login.usernameEnv], password = env[login.passwordEnv];
  if (!username || !password) throw Error(`Missing login environment variables for ${as}.`);
  const fields = {[login.usernameField]: username, [login.passwordField]: password};
  const form = login.encoding === 'form';
  await pace(spec);
  const response = await guardedRequest(url, {method: 'POST',
    headers: {'content-type': form ? 'application/x-www-form-urlencoded' : 'application/json'},
    body: form ? new URLSearchParams(fields).toString() : JSON.stringify(fields), maxBodyBytes: MODEL_RESPONSE_BYTES});
  if (response.status < 200 || response.status >= 300) throw Error(`${as} login returned HTTP ${response.status}.`);
  const token = loginToken(response, spec.auth);
  if (!token || token.placement !== spec.auth) throw Error(`${as} login did not return the expected session type.`);
  env[name] = token.value;
}

async function headerFor(spec, as, env, url = null) {
  if (as === 'anonymous') return {};
  const name = spec.identities[as];
  if (!env[name]) await bootstrapCredential(spec, as, env);
  const token = env[name];
  if (!token) throw Error(`Missing credential environment variable ${name}.`);
  if (spec.identityCookieName && url && spec.auth === 'bearer' &&
      url.origin === spec.origin && url.pathname === spec.identityPath && !url.search) {
    if (!/^[A-Za-z0-9._~-]{1,4096}$/.test(token)) throw Error('Identity cookie needs a safe bearer token.');
    return {cookie: `${spec.identityCookieName}=${token}`};
  }
  if (spec.auth === 'bearer') return {authorization: `Bearer ${token}`};
  if (spec.auth === 'cookie') return {cookie: token};
  if (spec.auth.startsWith('header:')) return {[spec.auth.slice(7)]: token};
  throw Error('Unsupported credential placement.');
}

async function read(spec, raw, as, env, extraHeaders = {}, maxBodyBytes = MODEL_RESPONSE_BYTES) {
  const url = checkedUrl(spec, raw);
  const headers = {...await headerFor(spec, as, env, url), ...extraHeaders};
  await pace(spec);
  const response = await guardedGet(url, headers,
    spec.allowRemoteHttp === true && as === 'anonymous', maxBodyBytes);
  const body = response.body;
  let json = null;
  try {json = JSON.parse(body);} catch { /* non-JSON is inconclusive for API findings */ }
  const values = new Set();
  const visit = (value, depth = 0) => {
    if (depth > 2) return;
    if (Array.isArray(value)) { for (const item of value) visit(item, depth); return; }
    if (!object(value)) return;
    for (const [key, field] of Object.entries(value)) {
      if (/^(id|_id|uid|uuid|slug|key)$|Id$|_id$|_uid$/.test(key) && ['string', 'number'].includes(typeof field)) values.add(String(field));
      else if (object(field) || Array.isArray(field)) visit(field, depth + 1);
    }
  };
  visit(json);
  const submittedMarkers = new Set([...url.searchParams.values()]
    .flatMap(value => value.match(/\b[0-9a-f]{24}\b/g) ?? []));
  const auditHeader = response.headers['x-bypass-audit'];
  return {status: response.status, hash: `sha256:${sha(body)}`, prefixHex: response.prefixHex, ids: [...values],
    fields: object(json) ? Object.keys(json) : Array.isArray(json) && object(json[0]) ? Object.keys(json[0]) : [],
    json: json !== null, type: response.headers['content-type'] ?? '', location: response.headers.location ?? null,
    corsOrigin: response.headers['access-control-allow-origin'] ?? null,
    corsCredentials: response.headers['access-control-allow-credentials'] ?? null,
    auditHeader: typeof auditHeader === 'string' && submittedMarkers.has(auditHeader) ? auditHeader : null,
    csp: response.headers['content-security-policy'] ?? null,
    headers: {age: response.headers.age ?? null, 'x-cache': response.headers['x-cache'] ?? null,
      'content-range': response.headers['content-range'] ?? null,
      'retry-after': response.headers['retry-after'] ?? null,
      'x-ratelimit-remaining': response.headers['x-ratelimit-remaining'] ?? null},
    nosniff: String(response.headers['x-content-type-options']).toLowerCase() === 'nosniff', body};
}

async function checkCrlfHeader(spec, env) {
  if (!safeProbeParameter(spec.parameter) ||
      !['anonymous', 'owner', 'outsider', 'derived'].includes(spec.request?.as))
    return {verdict: 'inconclusive', reason: 'response-header proof prerequisites are missing'};
  const withValue = value => {
    const url = new URL(spec.request.url, spec.origin);
    url.searchParams.set(spec.parameter, value);
    return url.href;
  };
  const controlMarker = randomBytes(12).toString('hex');
  const control = await read(spec, withValue(crlfControl(controlMarker)), spec.request.as, env);
  const controls = [{label: 'header-shaped-control', status: control.status,
    auditHeader: control.auditHeader === controlMarker}];
  if (control.status >= 500 || control.status === 429 || control.auditHeader === controlMarker)
    return {verdict: 'inconclusive', controls};
  const firstMarker = randomBytes(12).toString('hex');
  const first = await read(spec, withValue(crlfCanary(firstMarker)), spec.request.as, env);
  const firstHit = first.status >= 200 && first.status < 400 && first.auditHeader === firstMarker;
  controls.push({label: 'first-canary', status: first.status, injectedHeader: firstHit});
  if (!firstHit) return {verdict: first.status >= 500 || first.status === 429 ? 'inconclusive' :
    'not_reproduced', controls};
  const secondMarker = randomBytes(12).toString('hex');
  const second = await read(spec, withValue(crlfCanary(secondMarker)), spec.request.as, env,
    {'cache-control': 'no-cache'});
  const secondHit = second.status >= 200 && second.status < 400 && second.auditHeader === secondMarker;
  controls.push({label: 'second-canary', status: second.status, injectedHeader: secondHit});
  return {verdict: secondHit ? 'confirmed' : 'inconclusive', controls};
}

function linkedScripts(body, pageUrl) {
  const urls = [];
  for (const match of body.matchAll(/<script\b[^>]*>/gi)) {
    const source = /(?:^|\s)src\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s>]+))/i.exec(match[0]);
    const raw = (source?.[1] ?? source?.[2] ?? source?.[3] ?? '').replaceAll('&amp;', '&');
    if (raw && URL.canParse(raw, pageUrl)) urls.push(new URL(raw, pageUrl).href);
  }
  return [...new Set(urls)];
}

async function checkDomXss(spec, env) {
  if (spec.request?.as !== 'anonymous' || !Array.isArray(spec.assetUrls) ||
      !Array.isArray(spec.scriptUrls) || spec.assetUrls.length > 9 || spec.scriptUrls.length > 8 ||
      !spec.assetUrls.includes(new URL(spec.request.url, spec.origin).href))
    return {verdict: 'inconclusive', reason: 'DOM-XSS proof prerequisites are missing'};
  const pageUrl = new URL(spec.request.url, spec.origin).href;
  const scriptLimit = domScriptLimit(spec.domScriptBytes);
  const capture = async label => {
    const page = await read(spec, pageUrl, 'anonymous', env, {accept: 'text/html, */*;q=0.8',
      'cache-control': 'no-cache'});
    if (page.status !== 200 || !/html/i.test(page.type) ||
        Buffer.byteLength(page.body) > MODEL_RESPONSE_BYTES)
      return {page, scripts: [], blocked: true, reason: `${label} HTML page unavailable`};
    const allowed = new Set(spec.scriptUrls);
    const scripts = [];
    for (const url of linkedScripts(page.body, pageUrl).filter(url => allowed.has(url))) {
      if (new URL(url).origin !== spec.origin) continue;
      const script = await read(spec, url, 'anonymous', env,
        {accept: 'application/javascript, text/javascript;q=0.9, */*;q=0.8', 'cache-control': 'no-cache'},
        scriptLimit);
      if (script.status !== 200 || Buffer.byteLength(script.body) > scriptLimit)
        return {page, scripts, blocked: true, reason: `${label} observed script unavailable`};
      scripts.push({url, body: script.body, type: script.type, nosniff: script.nosniff});
    }
    return {page, scripts, blocked: false};
  };
  const first = await capture('first');
  if (first.blocked) return {verdict: first.page.status === 404 ? 'not_reproduced' : 'inconclusive',
    reason: first.reason, controls: [{label: 'page', status: first.page.status}]};
  const controlMarker = randomBytes(12).toString('hex');
  const options = (snapshot, fragment) => ({sourceUrl: pageUrl, fragment,
    scripts: snapshot.scripts, maxScriptBytes: scriptLimit});
  const control = await renderCapturedHtml(first.page.body, first.page.csp, controlMarker,
    options(first, controlMarker));
  const controls = [{label: 'plain-fragment', executed: control.executed, status: first.page.status}];
  if (control.blocked || control.executed) return {verdict: 'inconclusive',
    reason: control.reason ?? 'plain fragment changed the proof marker', controls};
  const marker1 = randomBytes(12).toString('hex');
  const one = await renderCapturedHtml(first.page.body, first.page.csp, marker1,
    options(first, domXssFragment(marker1)));
  controls.push({label: 'first-fragment', executed: one.executed, status: first.page.status});
  if (one.blocked || first.page.body.includes(marker1)) return {verdict: 'inconclusive',
    reason: one.reason ?? 'marker appeared in the raw page', controls};
  if (!one.executed) return {verdict: 'not_reproduced', controls};
  const second = await capture('second');
  if (second.blocked) return {verdict: 'inconclusive', reason: second.reason, controls};
  const marker2 = randomBytes(12).toString('hex');
  const two = await renderCapturedHtml(second.page.body, second.page.csp, marker2,
    options(second, domXssFragment(marker2)));
  controls.push({label: 'second-fragment', executed: two.executed, status: second.page.status});
  return {verdict: two.executed && !second.page.body.includes(marker2) ? 'confirmed' : 'inconclusive',
    reason: two.reason ?? null, controls};
}

async function checkReflectedXss(spec, env) {
  if (!XSS_STYLES.has(spec.style) || !safeProbeParameter(spec.parameter) ||
      !['anonymous', 'owner', 'outsider', 'derived'].includes(spec.request?.as))
    return {verdict: 'inconclusive', reason: 'reflected-XSS proof prerequisites are missing'};
  const controls = [];
  for (let at = 0; at < 2; at++) {
    const marker = randomBytes(12).toString('hex');
    const url = new URL(spec.request.url, spec.origin);
    url.searchParams.set(spec.parameter, xssPayload(spec.style, marker));
    const response = await read(spec, url.href, spec.request.as, env,
      at ? {'cache-control': 'no-cache'} : {});
    if (response.status !== 200 || !/html/i.test(response.type) || !response.body.includes(marker)) {
      controls.push({label: `browser-canary-${at + 1}`, status: response.status, executed: false});
      return {verdict: response.status >= 500 || response.status === 429 ? 'inconclusive' :
        at ? 'inconclusive' : 'not_reproduced', controls};
    }
    const browser = await renderCapturedHtml(response.body, response.csp, marker);
    controls.push({label: `browser-canary-${at + 1}`, status: response.status, executed: browser.executed});
    if (browser.blocked) return {verdict: 'inconclusive', reason: browser.reason, controls};
    if (!browser.executed) return {verdict: at ? 'inconclusive' : 'not_reproduced', controls};
  }
  return {verdict: 'confirmed', controls};
}

async function checkStoredXss(spec, env) {
  if (!reviewedPostOrigin(spec) || spec.request?.method !== 'POST' ||
      !['anonymous', 'owner'].includes(spec.request?.as) ||
      !['anonymous', 'owner'].includes(spec.viewAs) ||
      !XSS_STYLES.has(spec.style) || !safeProbeParameter(spec.parameter) ||
      !validModelFixedFields(spec.fixedFields ?? [], spec.parameter, [],
        spec.observedFields ?? null))
    return {verdict: 'inconclusive', reason: 'stored-XSS proof prerequisites are missing'};
  const postUrl = checkedUrl(spec, spec.request.url, {reviewedJsonPost: true});
  const viewUrl = checkedUrl(spec, spec.viewPath);
  if (postUrl.pathname !== spec.jsonPostPath || postUrl.search || viewUrl.search ||
      postUrl.pathname === viewUrl.pathname)
    return {verdict: 'inconclusive', reason: 'stored-XSS routes are outside reviewed scope'};
  const controls = [];
  const view = async () => read(spec, viewUrl, spec.viewAs, env,
    {'cache-control': 'no-cache'}, MODEL_RESPONSE_BYTES);
  const post = async value => {
    const headers = {...await headerFor(spec, spec.request.as, env, postUrl),
      'content-type': 'application/json', 'cache-control': 'no-cache'};
    await pace(spec);
    return guardedRequest(postUrl, {method: 'POST', headers,
      body: JSON.stringify({...Object.fromEntries((spec.fixedFields ?? []).map(item =>
        [item.field, item.value])), [spec.parameter]: value}), maxBodyBytes: MODEL_RESPONSE_BYTES});
  };
  const usablePage = page => page.status === 200 && /html/i.test(page.type ?? '') &&
    !responseCached(page);
  const usablePost = response => response.status >= 200 && response.status < 300 &&
    !responseCached(response);
  const baseline = await view();
  controls.push({label: 'baseline-view', status: baseline.status});
  if (!usablePage(baseline)) return {verdict: 'inconclusive',
    reason: 'baseline HTML view was unavailable', controls};
  const plainMarker = randomBytes(12).toString('hex');
  const plainPost = await post(plainMarker);
  controls.push({label: 'plain-post', status: plainPost.status});
  if (!usablePost(plainPost)) return {verdict: 'inconclusive',
    reason: 'plain POST control was unavailable', controls};
  const plainView = await view();
  if (!usablePage(plainView) || !plainView.body.includes(plainMarker))
    return {verdict: 'inconclusive',
      reason: 'plain text was not stored in the HTML view', controls};
  const plainBrowser = await renderCapturedHtml(plainView.body, plainView.csp,
    plainMarker, {sourceUrl: viewUrl.href});
  controls.push({label: 'plain-browser', executed: plainBrowser.executed});
  if (plainBrowser.blocked || plainBrowser.executed)
    return {verdict: 'inconclusive', reason: plainBrowser.reason ??
      'plain text unexpectedly executed', controls};
  for (let index = 0; index < 2; index++) {
    const marker = randomBytes(12).toString('hex');
    if (baseline.body.includes(marker)) return {verdict: 'inconclusive',
      reason: 'fresh marker appeared before the POST', controls};
    const sent = await post(xssPayload(spec.style, marker));
    controls.push({label: `canary-post-${index + 1}`, status: sent.status});
    if (!usablePost(sent)) return {verdict: 'inconclusive',
      reason: 'stored-XSS POST was unavailable', controls};
    const page = await view();
    if (!usablePage(page) || !page.body.includes(marker)) return {verdict: 'inconclusive',
      reason: 'canary did not appear in the stored HTML view', controls};
    const browser = await renderCapturedHtml(page.body, page.csp, marker,
      {sourceUrl: viewUrl.href});
    controls.push({label: `stored-browser-${index + 1}`, status: page.status,
      executed: browser.executed});
    if (browser.blocked) return {verdict: 'inconclusive', reason: browser.reason, controls};
    if (!browser.executed) return {verdict: index ? 'inconclusive' : 'not_reproduced',
      reason: 'stored canary did not execute in isolated Chrome', controls};
  }
  return {verdict: 'confirmed', controls};
}

async function checkHtmlInjection(spec, env) {
  if (!HTML_INJECTION_STYLES.includes(spec.style) ||
      !safeProbeParameter(spec.parameter) ||
      !['anonymous', 'owner', 'outsider', 'derived'].includes(spec.request?.as))
    return {verdict: 'inconclusive', reason: 'HTML-injection proof prerequisites are missing'};
  const withValue = value => {
    const url = new URL(spec.request.url, spec.origin);
    url.searchParams.set(spec.parameter, value);
    return url.href;
  };
  const controlMarker = randomBytes(12).toString('hex');
  const control = await read(spec, withValue(`bx-control-${controlMarker}`), spec.request.as, env);
  const controls = [{label: 'plain-text-control', status: control.status, elementInserted: false}];
  if (control.status !== 200 || !/html/i.test(control.type) || responseCached(control))
    return {verdict: 'inconclusive', reason: 'uncached HTML control was unavailable', controls};
  const controlBrowser = await renderCapturedHtml(control.body, control.csp, controlMarker,
    {detectHtml: true});
  if (controlBrowser.blocked || controlBrowser.elementInserted)
    return {verdict: 'inconclusive',
      reason: controlBrowser.reason ?? 'plain text created the audit element', controls};
  for (let at = 0; at < 2; at++) {
    const marker = randomBytes(12).toString('hex');
    const response = await read(spec, withValue(htmlInjectionPayload(spec.style, marker)),
      spec.request.as, env, at ? {'cache-control': 'no-cache'} : {});
    const html = response.status === 200 && /html/i.test(response.type) &&
      response.body.includes(marker) && !responseCached(response);
    if (!html) {
      controls.push({label: `markup-canary-${at + 1}`, status: response.status, elementInserted: false});
      return {verdict: response.status >= 500 || response.status === 429 || at ? 'inconclusive' :
        'not_reproduced', controls};
    }
    const browser = await renderCapturedHtml(response.body, response.csp, marker, {detectHtml: true});
    controls.push({label: `markup-canary-${at + 1}`, status: response.status,
      elementInserted: browser.elementInserted});
    if (browser.blocked) return {verdict: 'inconclusive', reason: browser.reason, controls};
    if (!browser.elementInserted)
      return {verdict: at ? 'inconclusive' : 'not_reproduced', controls};
  }
  return {verdict: 'confirmed', controls};
}

async function checkSstiArithmetic(spec, env) {
  if (!safeProbeParameter(spec.parameter) ||
      !['anonymous', 'owner', 'outsider', 'derived'].includes(spec.request?.as))
    return {verdict: 'inconclusive', reason: 'template proof prerequisites are missing'};
  const samples = [sstiCanary(), sstiCanary()];
  while (samples[1].result === samples[0].result) samples[1] = sstiCanary();
  const withValue = value => {
    const url = new URL(spec.request.url, spec.origin);
    url.searchParams.set(spec.parameter, value);
    return url.href;
  };
  const control = await read(spec, withValue(`bx-control-${randomBytes(8).toString('hex')}`), spec.request.as, env);
  const controls = [{label: 'plain-control', status: control.status, hash: control.hash}];
  if (control.status !== 200 || samples.some(sample => control.body.includes(sample.result)))
    return {verdict: 'inconclusive', reason: 'plain control did not establish a stable baseline', controls};
  for (let at = 0; at < samples.length; at++) {
    const sample = samples[at];
    const response = await read(spec, withValue(sample.input), spec.request.as, env,
      at ? {'cache-control': 'no-cache'} : {});
    const evaluated = response.status === 200 && response.body.includes(sample.result) &&
      !response.body.includes(sample.input);
    controls.push({label: `arithmetic-${at + 1}`, status: response.status, evaluated});
    if (!evaluated) return {verdict: response.status >= 500 || response.status === 429 || at ?
      'inconclusive' : 'not_reproduced', controls};
  }
  return {verdict: 'confirmed', controls};
}

async function checkModelDifferential(spec, env) {
  if (spec.oracle === 'observation')
    return {verdict: 'inconclusive', reason: 'An unclassified observation has no impact oracle'};
  if (!validModelExperiment(spec) || spec.request?.method !== 'GET' ||
      !['anonymous', 'owner', 'outsider', 'derived'].includes(spec.request?.as) ||
      !Array.isArray(spec.prelude ?? []) ||
      (spec.prelude ?? []).some(path => typeof path !== 'string' ||
        !path.startsWith('/') || path.includes('?') || path.includes('#')))
    return {verdict: 'inconclusive', reason: 'Model experiment proof prerequisites are missing'};
  const headers = Object.fromEntries((spec.headers ?? []).map(item =>
    [item.name.toLowerCase(), item.value]));
  const withValue = value => {
    const url = new URL(spec.request.url, spec.origin);
    url.searchParams.set(spec.parameter, value);
    return url.href;
  };
  const responses = [];
  const controls = [];
  for (const value of [spec.controlValue, spec.firstValue, spec.secondValue]) {
    for (const path of spec.prelude ?? []) {
      const prior = await read(spec, path, spec.request.as, env,
        {...headers, 'cache-control': 'no-cache'}, MODEL_RESPONSE_BYTES);
      controls.push({label: 'prelude', status: prior.status, hash: prior.hash});
      if (prior.status == null || prior.status === 429 || prior.status >= 500 || responseCached(prior))
        return {verdict: 'inconclusive', reason: 'Model prelude was unavailable or cached', controls};
    }
    responses.push(await read(spec, withValue(value), spec.request.as, env,
      {...headers, 'cache-control': 'no-cache'}, MODEL_RESPONSE_BYTES));
  }
  controls.push(...responses.map((response, index) => ({label: ['control', 'probe-one', 'probe-two'][index],
    status: response.status, firstMarkerPresent: response.body.includes(spec.marker),
    secondMarkerPresent: response.body.includes(spec.secondMarker), hash: response.hash})));
  if (responses.some(response => response.status == null || response.status === 429 ||
      response.status >= 500 || responseCached(response)))
    return {verdict: 'inconclusive', reason: 'Model experiment response was unavailable or cached', controls};
  if (responses[0].status !== 200 ||
      [spec.marker, spec.secondMarker].some(marker => responses[0].body.includes(marker)))
    return {verdict: 'inconclusive', reason: 'Control response did not establish a clean baseline', controls};
  const matched = responses.slice(1).map((response, index) => response.status === 200 &&
    response.body.includes(index ? spec.secondMarker : spec.marker) &&
    !response.body.includes(index ? spec.marker : spec.secondMarker));
  return {verdict: matched.every(Boolean) ? 'confirmed' : matched.some(Boolean) ? 'inconclusive' :
    'not_reproduced', controls};
}

async function checkModelJsonDifferential(spec, env) {
  if (!validModelExperiment(spec) || spec.request?.method !== 'POST' ||
      !['anonymous', 'owner'].includes(spec.request?.as) ||
      !reviewedPostOrigin(spec) ||
      !validModelFixedFields(spec.fixedFields ?? [], spec.parameter,
        [spec.marker, spec.secondMarker], spec.observedFields ?? null))
    return {verdict: 'inconclusive', reason: 'JSON POST proof prerequisites are missing'};
  const url = checkedUrl(spec, spec.request.url, {reviewedJsonPost: true});
  if (url.pathname !== spec.jsonPostPath || url.search || url.hash)
    return {verdict: 'inconclusive', reason: 'JSON POST is outside its reviewed exact path'};
  const prelude = spec.prelude ?? [];
  const observeAs = spec.observeAs ?? spec.request.as;
  const observePath = spec.observePath ?? '';
  if (!Array.isArray(prelude) ||
      new Set(prelude).size !== prelude.length ||
      !['anonymous', 'owner'].includes(observeAs) ||
      typeof observePath !== 'string' || !observePath && observeAs !== spec.request.as)
    return {verdict: 'inconclusive', reason: 'JSON POST sequence prerequisites are missing'};
  const preludeUrls = prelude.map(path => checkedUrl(spec, path));
  const observeUrl = observePath ? checkedUrl(spec, observePath) : null;
  if (preludeUrls.some(item => item.search || item.hash) ||
      observeUrl && (observeUrl.search || observeUrl.hash))
    return {verdict: 'inconclusive', reason: 'JSON POST sequence contains an unreviewed query'};
  const controls = [], responses = [];
  for (const [index, value] of [spec.controlValue, spec.firstValue, spec.secondValue].entries()) {
    for (const preludeUrl of preludeUrls) {
      const before = await read(spec, preludeUrl, spec.request.as, env,
        {'cache-control': 'no-cache'}, MODEL_RESPONSE_BYTES);
      controls.push({label: `prelude-${index + 1}`, path: preludeUrl.pathname,
        status: before.status});
      if (before.status !== 200 || responseCached(before))
        return {verdict: 'inconclusive', reason: 'JSON POST prelude was unavailable', controls};
    }
    const headers = {...await headerFor(spec, spec.request.as, env, url),
      'content-type': 'application/json', 'cache-control': 'no-cache'};
    await pace(spec);
    const post = await guardedRequest(url, {method: 'POST', headers,
      body: JSON.stringify({...Object.fromEntries((spec.fixedFields ?? []).map(item =>
        [item.field, item.value])), [spec.parameter]: value}), maxBodyBytes: MODEL_RESPONSE_BYTES});
    controls.push({label: `post-${index + 1}`, status: post.status});
    if (post.status < 200 || post.status >= 300 || responseCached(post))
      return {verdict: 'inconclusive', reason: 'JSON POST did not complete', controls};
    const response = observeUrl ? await read(spec, observeUrl, observeAs, env,
      {'cache-control': 'no-cache'}, MODEL_RESPONSE_BYTES) : post;
    responses.push(response);
    controls.push({label: ['control', 'probe-one', 'probe-two'][index],
      status: response.status, hash: `sha256:${sha(response.body)}`,
      firstMarkerPresent: response.body.includes(spec.marker),
      secondMarkerPresent: response.body.includes(spec.secondMarker)});
  }
  if (responses.some(response => response.status == null || response.status === 429 ||
      response.status >= 500 || responseCached(response)))
    return {verdict: 'inconclusive', reason: 'JSON POST response was unavailable or cached', controls};
  if (responses[0].status !== 200 ||
      [spec.marker, spec.secondMarker].some(marker => responses[0].body.includes(marker)))
    return {verdict: 'inconclusive', reason: 'JSON POST control did not establish a clean baseline', controls};
  const matched = responses.slice(1).map((response, index) => response.status === 200 &&
    response.body.includes(index ? spec.secondMarker : spec.marker) &&
    !response.body.includes(index ? spec.marker : spec.secondMarker));
  return {verdict: matched.every(Boolean) ? 'confirmed' : matched.some(Boolean) ? 'inconclusive' :
    'not_reproduced', controls};
}

const sequenceBindings = spec => spec.bindings == null ?
  spec.binding == null ? [] : [spec.binding] : spec.bindings;
const sequenceBindingReviews = spec => spec.bindings == null ?
  spec.binding == null ? [] : [spec.bindingReview] : spec.bindingReviews;
const sequenceBindingTarget = (spec, binding) => binding.to === 'prelude' ?
  spec.prelude[binding.index] : binding.to === 'subject' ?
    spec.subject : spec.observe[binding.index];
const sequenceTargetBindings = (spec, to, index, captures) =>
  (Array.isArray(sequenceBindings(spec)) ? sequenceBindings(spec) : [])
    .flatMap((binding, at) =>
    binding.to === to && binding.index === index ?
      [{binding, value: captures.get(at)}] : []);
const sequenceSuppliesField = (spec, to, index, key) =>
  Array.isArray(sequenceBindings(spec)) &&
  sequenceBindings(spec).some(binding => binding.to === to &&
    binding.index === index && binding.key === key);

/** A sealed, model-directed sequence may prove a response transformation, not its impact. */
function validSequenceBinding(spec) {
  const bindings = sequenceBindings(spec);
  const reviews = sequenceBindingReviews(spec);
  if (!Array.isArray(bindings) || !Array.isArray(reviews) ||
      bindings.length !== reviews.length) return false;
  return bindings.every((binding, at) => validOneSequenceBinding(spec, binding, reviews[at]));
}

function validOneSequenceBinding(spec, binding, review) {
  if (!object(binding) || !object(review) ||
      !Number.isInteger(binding.from) || binding.from < 0 ||
      binding.from >= spec.prelude.length ||
      !['prelude', 'subject', 'observe'].includes(binding.to) ||
      !Number.isInteger(binding.index) || binding.index < 0 ||
      binding.to === 'prelude' && (binding.index <= binding.from ||
        binding.index >= spec.prelude.length) ||
      !safeProbeParameter(binding.key) ||
      !SEQUENCE_POINTER.test(binding.pointer ?? '') ||
      binding.pointer.slice(1).split('/').some(name => SEQUENCE_SECRET_FIELD.test(name)))
    return false;
  const source = spec.prelude[binding.from];
  const writeSource = !['GET', 'HEAD'].includes(source.method) &&
    reviewedSequenceOperation(spec, source);
  if (source.method !== 'GET' && !writeSource || source.path.includes('?') ||
      review.sourcePath !== source.path ||
      review.sourceAs !== (source.as ?? spec.as) ||
      review.sourcePointer !== binding.pointer ||
      (writeSource && (review.sourceMethod !== source.method ||
        review.sourcePlacement !== source.placement ||
        !Array.isArray(review.sourceFields) ||
        !review.sourceFields.includes(source.key))) ||
      !['string', 'number'].includes(review.sourceType) ||
      (writeSource ? ![200, '2xx'].includes(review.sourceStatus) :
        review.sourceStatus !== 200)) return false;
  const target = sequenceBindingTarget(spec, binding);
  if (!target || binding.to === 'subject' && binding.index !== 0 ||
      binding.to === 'observe' && !['GET', 'HEAD'].includes(target.method)) return false;
  const placement = binding.placement === 'path' ? 'path' :
    binding.to === 'subject' ? target.placement : target.placement ?? 'query';
  if (placement === 'path') {
    if (!['GET', 'HEAD'].includes(target.method) ||
        !Number.isInteger(binding.segment) || binding.segment < 0 ||
        review.targetPath !== target.path || review.targetPlacement !== 'path' ||
        !Array.isArray(review.targetFields) ||
        !review.targetFields.includes(binding.key) ||
        typeof review.targetPathTemplate !== 'string') return false;
    const template = review.targetPathTemplate.split('/').slice(1);
    const concrete = new URL(target.path, 'http://placeholder.invalid')
      .pathname.split('/').slice(1);
    return template.length === concrete.length &&
      template[binding.segment] === `{${binding.key}}` &&
      template.every((part, index) =>
        /^\{[A-Za-z_][A-Za-z0-9_.-]{0,79}\}$/.test(part) ?
          Boolean(concrete[index]) : part === concrete[index]);
  }
  const queryTarget = placement === 'query' ?
    new URL(target.path, 'http://placeholder.invalid') : null;
  const queryBindingConflict = queryTarget?.search &&
    queryTarget.searchParams.getAll(binding.key).length !== 1;
  if (!['query', 'json', 'form'].includes(placement) ||
      binding.to !== 'prelude' && binding.key === target.key ||
      queryBindingConflict ||
      review.targetPath !== target.path ||
      review.targetPlacement !== placement ||
      !Array.isArray(review.targetFields) ||
      !review.targetFields.includes(binding.key) ||
      placement !== 'query' && (target.fixedFields ?? []).some(item =>
        item.field === binding.key)) return false;
  return true;
}

const SEQUENCE_WRITE_METHODS = new Set(['PUT', 'PATCH', 'DELETE', 'OPTIONS']);
const SEQUENCE_BODY_PLACEMENTS = new Set(['json', 'form', 'xml']);
const sequenceContentType = placement => placement === 'json' ?
  /^application\/(?:json|[a-z0-9.-]+\+json)(?:\s*;|$)/i :
  placement === 'form' ? /^application\/x-www-form-urlencoded(?:\s*;|$)/i :
  /^(?:application|text)\/xml(?:\s*;|$)/i;

/** A write proof must match the exact method, path, body shape and input from recon and scope. */
function reviewedSequenceOperation(spec, subject) {
  if (subject.method !== 'POST' && !SEQUENCE_WRITE_METHODS.has(subject.method) ||
      subject.method === 'OPTIONS' &&
        !['query', 'header'].includes(subject.placement) ||
      !Array.isArray(spec.reviewedOperations)) return null;
  return spec.reviewedOperations.find(item => object(item) &&
    item.method === subject.method && item.path === subject.path &&
    item.placement === subject.placement &&
    Array.isArray(item.fields) && item.fields.includes(subject.key) &&
    Array.isArray(item.requiredFields) &&
    (SEQUENCE_BODY_PLACEMENTS.has(item.placement) ?
      typeof item.contentType === 'string' &&
      sequenceContentType(item.placement).test(item.contentType) :
      ['query', 'header'].includes(item.placement) &&
      (item.contentType == null || item.contentType === '')));
}

function reviewedSequenceXmlTemplate(subject, operation) {
  const template = subject.bodyTemplate;
  const root = operation.rootElement;
  if (typeof root !== 'string' || !/^[A-Za-z_][A-Za-z0-9_.-]{0,79}$/.test(root) ||
      !template.startsWith(`<${root}>`) || !template.endsWith(`</${root}>`) ||
      !template.includes(`<${subject.key}>{{input}}</${subject.key}>`)) return false;
  const tags = [...template.matchAll(/<\/?([A-Za-z_][A-Za-z0-9_.-]{0,79})>/g)];
  if (tags.length < 4 || template.replaceAll('{{input}}', '')
    .replaceAll(/<\/?[A-Za-z_][A-Za-z0-9_.-]{0,79}>/g, '').trim()) return false;
  const allowed = new Set([root, ...operation.fields]);
  const stack = [];
  for (const tag of tags) {
    if (!allowed.has(tag[1])) return false;
    if (tag[0].startsWith('</')) {if (stack.pop() !== tag[1]) return false;}
    else stack.push(tag[1]);
  }
  return !stack.length;
}

export function validModelHttpSequence(spec) {
  const subject = spec?.subject;
  const assertion = spec?.assertion;
  const browserSequence = spec?.kind === 'model-browser-execution';
  const contentSequence = spec?.kind === 'model-access-boundary' &&
    ['sequence-exact-body', 'sequence-json-field'].includes(spec.comparison);
  const markers = contentSequence || browserSequence ? [] : [spec?.marker, spec?.secondMarker];
  const safePath = value => typeof value === 'string' && value.startsWith('/') &&
    !value.startsWith('//') && value.length <= 512 &&
    !/[\\;%#{}]/.test(value.split('?')[0]) &&
    !/(?:^|\/)\.{1,2}(?:\/|$)/.test(value.split('?')[0]);
  if (spec?.kind !== 'model-http-sequence' && !contentSequence && !browserSequence ||
      !['anonymous', 'owner', 'outsider', 'derived'].includes(spec.as) ||
      !object(subject) || !object(assertion) ||
      !Array.isArray(spec.prelude) || !Array.isArray(spec.observe) ||
      spec.prelude.length > MAX_SEQUENCE_STEPS || spec.observe.length > MAX_SEQUENCE_STEPS ||
      !['GET', 'HEAD', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'].includes(subject.method) ||
      !['query', 'header', 'json', 'xml', 'form'].includes(subject.placement) ||
      !['subject', 'observe'].includes(assertion.step) ||
      !['body', 'header'].includes(assertion.location) ||
      assertion.step === 'observe' && (!Number.isInteger(assertion.index) ||
        assertion.index < 0 || assertion.index >= spec.observe.length) ||
      assertion.step === 'subject' && assertion.index != null && assertion.index !== 0 ||
      assertion.location === 'header' && !['location', 'content-type', 'link',
        'www-authenticate'].includes(assertion.name?.toLowerCase()) ||
      assertion.location === 'body' && assertion.name != null && assertion.name !== '')
    return false;
  const derivedStep = step => (step.as ?? spec.as) === 'derived';
  const stepValid = (step, to, index) => {
    if (!object(step) ||
        step.as !== undefined && !['anonymous', 'owner', 'outsider', 'derived'].includes(step.as) ||
        !safePath(step.path) ||
        !validModelHeaders(step.headers ?? [], markers) ||
        (step.headers ?? []).some(item => item.name.toLowerCase() === 'content-type'))
      return false;
    if (['GET', 'HEAD'].includes(step.method))
      return step.placement == null && step.key == null && step.value == null;
    const operation = (step.method === 'POST' || SEQUENCE_WRITE_METHODS.has(step.method)) ?
      reviewedSequenceOperation(spec, step) : null;
    let typedScalar = step.valueEncoding == null || step.valueEncoding === 'string';
    if (step.valueEncoding === 'json' && step.placement === 'json') {
      try {
        const parsed = JSON.parse(step.value);
        typedScalar = typeof parsed === 'string' ?
          harmlessModelValue(parsed, markers, 128) :
          parsed === null || typeof parsed === 'boolean' ||
          typeof parsed === 'number' && Number.isFinite(parsed);
      } catch { typedScalar = false; }
    }
    if (!operation || !reviewedPostOrigin(spec) ||
        !['query', 'header', 'json', 'form', 'xml'].includes(step.placement) ||
        !safeProbeParameter(step.key) ||
        !harmlessModelValue(step.value, markers, 128) ||
        !typedScalar ||
        !validModelFixedFields(step.fixedFields ?? [], step.key,
          markers, operation.fields) ||
        operation.requiredFields.some(name => name !== step.key &&
          !(step.fixedFields ?? []).some(item => item.field === name) &&
          !sequenceSuppliesField(spec, to, index, name))) return false;
    if (['query', 'header'].includes(step.placement))
      return !step.bodyTemplate && !(step.fixedFields ?? []).length &&
        (step.placement !== 'header' ||
          validModelHeaders([{name: step.key, value: step.value}], markers));
    if (step.path.includes('?')) return false;
    return step.placement === 'xml' ?
      reviewedSequenceXmlTemplate(step, operation) : !step.bodyTemplate;
  };
  if (spec.prelude.some((step, index) => !stepValid(step, 'prelude', index)) ||
      spec.observe.some((step, index) => !stepValid(step, 'observe', index)) ||
      !safePath(subject.path) ||
      !validModelHeaders(subject.headers ?? [], markers) ||
      (subject.headers ?? []).some(item => item.name.toLowerCase() === 'content-type')) return false;
  const usesDerived = spec.as === 'derived' ||
    [...spec.prelude, ...spec.observe].some(derivedStep);
  if (usesDerived && (!['bearer', 'cookie'].includes(spec.auth) || !spec.derivedLogin ||
      !validModelAuthLogin({...spec, ...spec.derivedLogin,
        kind: 'model-auth-login', origin: spec.origin, include: spec.include,
        never: spec.never, targetEnvironment: spec.targetEnvironment,
        auth: spec.auth}))) return false;
  if (!(browserSequence ? true : contentSequence ? !contentBoundaryShapeReason(spec) :
      validModelExperiment({...spec, parameter: subject.key})) ||
      !validSequenceBinding(spec)) return false;
  const staticRequests = JSON.stringify({prelude: spec.prelude, subject, observe: spec.observe});
  if (markers.some(marker =>
    staticRequests.toLowerCase().includes(marker.toLowerCase()))) return false;
  const reviewedWrite = reviewedSequenceOperation(spec, subject);
  if (SEQUENCE_WRITE_METHODS.has(subject.method) && !reviewedWrite) return false;
  if (['query', 'header'].includes(subject.placement)) {
    const read = ['GET', 'HEAD'].includes(subject.method);
    if (!read && !reviewedWrite || (subject.bodyTemplate ?? '') !== '') return false;
    if (subject.placement === 'query' && read && (subject.fixedFields ?? []).length) {
      const reviewedRead = spec.reviewedReadInputs?.find(item =>
        item?.path === subject.path && item.methods?.includes(subject.method));
      if (!reviewedRead || !validModelFixedFields(subject.fixedFields,
        subject.key, markers) ||
        subject.fixedFields.some(item => !reviewedRead.parameters?.includes(item.field)))
        return false;
    } else if ((subject.fixedFields ?? []).length) return false;
    if (reviewedWrite && reviewedWrite.requiredFields.some(name =>
      name !== subject.key && !sequenceSuppliesField(spec, 'subject', 0, name))) return false;
    if (subject.placement === 'header' &&
        (!validModelHeaders([{name: subject.key, value: spec.controlValue}],
          markers) ||
          (subject.headers ?? []).some(item => item.name.toLowerCase() === subject.key.toLowerCase())))
      return false;
  } else {
    if (subject.method !== 'POST' && !reviewedWrite ||
        (subject.headers ?? []).length ||
        subject.method === 'POST' &&
        !spec.reviewedPostPaths?.[subject.placement]?.includes(subject.path) &&
        !reviewedWrite ||
        subject.path.includes('?') || subject.path.includes('#')) return false;
    if (subject.placement === 'xml') {
      if (spec.xmlExternalEntity !== true || (subject.fixedFields ?? []).length ||
          typeof subject.bodyTemplate !== 'string' ||
          subject.bodyTemplate.length > 2048 ||
          subject.bodyTemplate.split('{{input}}').length !== 2 ||
          /<!|<\?|&|[\x00-\x1f\x7f]|(?:https?|file|ftp|gopher|data):/i
            .test(subject.bodyTemplate)) return false;
      if (reviewedWrite && !reviewedSequenceXmlTemplate(subject, reviewedWrite))
        return false;
    } else if (!validModelFixedFields(subject.fixedFields ?? [], subject.key,
      markers, reviewedWrite?.fields ?? null)) return false;
    if (reviewedWrite && reviewedWrite.requiredFields.some(name =>
      name !== subject.key && !(subject.fixedFields ?? []).some(item => item.field === name) &&
      !sequenceSuppliesField(spec, 'subject', 0, name))) return false;
    if (['json', 'form'].includes(subject.placement) && !reviewedPostOrigin(spec))
      return false;
  }
  return true;
}

async function checkModelHttpSequence(spec, env) {
  if (!validModelHttpSequence(spec)) return {verdict: 'inconclusive',
    reason: 'Model HTTP sequence proof prerequisites are missing'};
  if (spec.kind === 'model-browser-execution' &&
      !['GET', 'HEAD'].includes(spec.subject.method) &&
      (spec.targetEnvironment !== 'local' ||
        !['POST', 'PUT', 'PATCH'].includes(spec.subject.method)))
    return {verdict: 'inconclusive',
      reason: 'browser write requires a reviewed non-destructive local contract'};
  const controls = [];
  let derivedSession = null;
  if (spec.as === 'derived' || [...spec.prelude, ...spec.observe].some(step =>
      (step.as ?? spec.as) === 'derived')) {
    const loginSpec = {...spec, ...spec.derivedLogin, kind: 'model-auth-login',
      origin: spec.origin, include: spec.include, never: spec.never,
      targetEnvironment: spec.targetEnvironment, auth: spec.auth};
    const login = await checkModelAuthLogin(loginSpec, env,
      session => { derivedSession = session; });
    controls.push({label: 'fresh-login-boundary', verdict: login.verdict,
      checks: login.controls});
    if (login.verdict !== 'confirmed' || !derivedSession)
      return {verdict: login.verdict === 'not_reproduced' ? 'not_reproduced' : 'inconclusive',
        reason: 'Fresh derived login did not establish a private session', controls};
    const boundaryStep = spec.as === 'derived' ? spec.subject :
      [...spec.prelude, ...spec.observe].find(step => step.as === 'derived');
    // A reviewed write cannot establish a read boundary by requesting its
    // path with GET. Reuse the login proof's protected GET contract instead.
    const boundaryPath = boundaryStep === spec.subject &&
      !['GET', 'HEAD'].includes(spec.subject.method) ?
      spec.derivedLogin.privatePath : boundaryStep.path;
    const boundaryUrl = checkedUrl(spec, boundaryPath);
    if (boundaryStep === spec.subject && ['GET', 'HEAD'].includes(spec.subject.method) &&
        spec.subject.placement === 'query')
      boundaryUrl.searchParams.set(spec.subject.key, spec.controlValue);
    checkedUrl(spec, boundaryUrl.href);
    await pace(spec);
    const boundaryMethod = ['GET', 'HEAD'].includes(boundaryStep.method) ?
      boundaryStep.method : 'GET';
    const anonymous = await guardedRequest(boundaryUrl,
      {method: boundaryMethod, headers: {'cache-control': 'no-cache'},
        allowRemoteHttp: spec.allowRemoteHttp === true, maxBodyBytes: MODEL_RESPONSE_BYTES});
    await pace(spec);
    const invalid = await guardedRequest(boundaryUrl,
      {method: boundaryMethod, headers: {'cache-control': 'no-cache',
        ...sessionHeaders(spec.auth, invalidSession(spec.auth, derivedSession))},
      allowRemoteHttp: spec.allowRemoteHttp === true, maxBodyBytes: MODEL_RESPONSE_BYTES});
    controls.push({label: 'protected-route-boundary', anonymousStatus: anonymous.status,
      invalidBearerStatus: invalid.status});
    if (!denied(anonymous.status) || !denied(invalid.status) ||
        responseCached(anonymous) || responseCached(invalid))
      return {verdict: 'inconclusive',
        reason: 'Anonymous and invalid-bearer controls did not establish the protected route', controls};
  }
  const browserSequence = spec.kind === 'model-browser-execution';
  const browserStyle = value => XSS_STYLES.has(value) ? value :
    /script-close|<\/script/i.test(String(value)) ? 'script-close' :
      /html-single|^'/.test(String(value)) ? 'html-single' : 'html-double';
  const browserMarkers = browserSequence ?
    [randomBytes(12).toString('hex'), randomBytes(12).toString('hex')] : [];
  const values = browserSequence ? [spec.controlValue,
    xssPayload(browserStyle(spec.firstValue), browserMarkers[0]),
    xssPayload(browserStyle(spec.secondValue), browserMarkers[1])] :
    [spec.controlValue, spec.firstValue, spec.secondValue];
  const labels = ['control', 'probe-one', 'probe-two'];
  const fixedHeaders = step => Object.fromEntries((step.headers ?? []).map(item =>
    [item.name.toLowerCase(), item.value]));
  const issue = async (step, value, label, index, captures, to) => {
    const write = step.method === 'POST' || SEQUENCE_WRITE_METHODS.has(step.method);
    const bodyWrite = write && SEQUENCE_BODY_PLACEMENTS.has(step.placement);
    const legacyPost = write && step.method === 'POST';
    const bound = sequenceTargetBindings(spec, to, index, captures);
    if (bound.some(item => item.value == null))
      throw Error('Model sequence binding was unavailable.');
    const submittedValue = bound.find(item => item.binding.placement !== 'path' &&
      item.binding.key === step.key)?.value ??
      (step === spec.subject ? value : step.value);
    const identity = step === spec.subject ? spec.as : step.as ?? spec.as;
    const selectedPath = bound.filter(item => item.binding.placement === 'path')
      .reduce((path, item) => path && boundSequencePath(path,
        item.binding, item.value), step.path);
    if (!selectedPath) throw Error('Model sequence path binding was unavailable.');
    const url = checkedUrl(spec, selectedPath, {reviewedFlowPost: legacyPost,
      reviewedFlowStep: step});
    if (write && (url.pathname !== step.path || url.search || url.hash))
      throw Error('Model sequence write is outside its reviewed exact path.');
    if (step.placement === 'query' && step.key) {
      for (const item of step.fixedFields ?? [])
        url.searchParams.set(item.field, item.value);
      url.searchParams.set(step.key, submittedValue);
    }
    if (!bodyWrite) for (const item of bound) {
      if (item.binding.placement !== 'path')
        url.searchParams.set(item.binding.key, item.value);
    }
    checkedUrl(spec, url.href, {reviewedFlowPost: legacyPost,
      reviewedFlowStep: step});
    if (identity !== 'anonymous' && Array.isArray(spec.credentialOrigins) &&
        !spec.credentialOrigins.includes(url.origin))
      throw Error('Model sequence credential origin is outside its recorded scope.');
    const headers = {...(identity === 'derived' ?
      sessionHeaders(spec.auth, derivedSession) :
      await headerFor(spec, identity, env, url)),
      ...fixedHeaders(step), 'cache-control': 'no-cache'};
    if (step.placement === 'header' && step.key)
      headers[step.key.toLowerCase()] = submittedValue;
    let body = null;
    if (bodyWrite) {
      const writeContentType = legacyPost ? null :
        reviewedSequenceOperation(spec, step)?.contentType;
      if (step.placement === 'json') {
        headers['content-type'] = writeContentType ?? 'application/json';
        body = sequenceJsonBody({...Object.fromEntries((step.fixedFields ?? []).map(item =>
          [item.field, item.value])), ...Object.fromEntries(bound
          .filter(item => item.binding.placement !== 'path')
          .map(item => [item.binding.key, item.value]))},
        step.key, submittedValue, step.valueEncoding);
      } else if (step.placement === 'form') {
        headers['content-type'] = writeContentType ?? 'application/x-www-form-urlencoded';
        body = new URLSearchParams(Object.fromEntries([
          ...((step.fixedFields ?? []).map(item => [item.field, item.value])),
          ...bound.filter(item => item.binding.placement !== 'path')
            .map(item => [item.binding.key, item.value]),
          [step.key, submittedValue]])).toString();
      } else {
        headers['content-type'] = writeContentType ?? 'application/xml';
        body = step.bodyTemplate.replace('{{input}}', submittedValue);
      }
      if (Buffer.byteLength(body) > 4096)
        throw Error('Model sequence request body exceeds its byte limit.');
    }
    await pace(spec);
    const response = await guardedRequest(url, {method: step.method, headers, body,
      allowRemoteHttp: spec.allowRemoteHttp === true && identity === 'anonymous',
      maxBodyBytes: MODEL_RESPONSE_BYTES});
    controls.push({label: `${label}-${index}`, status: response.status,
      hash: `sha256:${sha(response.body)}`, cached: responseCached(response)});
    return response;
  };
  const observed = [];
  for (const [variant, value] of values.entries()) {
    const label = labels[variant];
    const captures = new Map();
    for (const [index, step] of spec.prelude.entries()) {
      const response = await issue(step, value, `${label}-prelude`, index,
        captures, 'prelude');
      const setupSucceeded = ['GET', 'HEAD'].includes(step.method) ?
        response.status === 200 : response.status >= 200 && response.status < 300;
      if (!setupSucceeded || responseCached(response))
        return {verdict: 'inconclusive', reason: 'Model sequence prelude was unavailable or cached', controls};
      for (const [at, binding] of sequenceBindings(spec).entries()) {
        if (binding.from !== index) continue;
        if (!/(?:json|\+json)/i.test(response.headers?.['content-type'] ?? ''))
          return {verdict: 'inconclusive', reason: 'Model sequence capture was not JSON', controls};
        const captured = captureSequenceScalar(response.body, binding.pointer);
        controls.push({label: `${label}-capture-${at}`, pointer: binding.pointer,
          source: step.path, present: captured !== null, length: captured?.length ?? 0});
        if (captured === null) return {verdict: 'inconclusive',
          reason: 'Model sequence capture was unavailable or unsafe', controls};
        captures.set(at, captured);
      }
    }
    const subject = await issue(spec.subject, value, `${label}-subject`, 0,
      captures, 'subject');
    if (subject.status == null || subject.status === 429 || subject.status >= 500 ||
        responseCached(subject)) return {verdict: 'inconclusive',
      reason: 'Model sequence subject was unavailable or cached', controls};
    const followups = [];
    for (const [index, step] of spec.observe.entries()) {
      const response = await issue(step, value, `${label}-observe`, index,
        captures, 'observe');
      if (response.status == null || response.status === 429 || response.status >= 500 ||
          responseCached(response)) return {verdict: 'inconclusive',
        reason: 'Model sequence observation was unavailable or cached', controls};
      followups.push(response);
    }
    observed.push(spec.assertion.step === 'subject' ? subject :
      followups[spec.assertion.index]);
  }
  const extract = response => spec.assertion.location === 'body' ? response.body :
    String(response.headers[spec.assertion.name.toLowerCase()] ?? '');
  const outputs = observed.map(extract);
  if (browserSequence) {
    const path = spec.assertion.step === 'subject' ? spec.subject.path :
      spec.observe[spec.assertion.index]?.path;
    const sourceUrl = checkedUrl(spec, path).href;
    const browser = [];
    for (const [index, response] of observed.entries()) {
      if (response.status !== 200 ||
          !/(?:^|\/)html\b/i.test(response.headers?.['content-type'] ?? ''))
        return {verdict: 'not_reproduced',
          reason: 'selected response was not an HTML page', controls};
      const marker = browserMarkers[index === 2 ? 1 : 0];
      const result = await renderCapturedHtml(response.body,
        response.headers?.['content-security-policy'], marker, {sourceUrl});
      controls.push({label: `${labels[index]}-browser`, executed: result.executed,
        status: response.status});
      if (result.blocked) return {verdict: 'inconclusive',
        reason: result.reason, controls};
      browser.push(result.executed);
    }
    if (browser[0]) return {verdict: 'inconclusive',
      reason: 'plain control executed before browser probes', controls};
    return {verdict: browser[1] && browser[2] ? 'confirmed' :
      !browser[1] && !browser[2] ? 'not_reproduced' : 'inconclusive',
    reason: browser[1] && browser[2] ?
      'two fresh script canaries executed in isolated Chrome' :
      'the browser canaries did not both execute', controls};
  }
  controls.push(...observed.map((response, index) => ({label: `${labels[index]}-assertion`,
    status: response.status, marker: outputs[index].includes(spec.marker),
    secondMarker: outputs[index].includes(spec.secondMarker)})));
  if (outputs[0].includes(spec.marker) || outputs[0].includes(spec.secondMarker))
    return {verdict: 'inconclusive', reason: 'Model sequence control or probe response was unstable',
      impact: 'unverified', controls};
  const first = outputs[1].includes(spec.marker) &&
    !outputs[1].includes(spec.secondMarker);
  const second = outputs[2].includes(spec.secondMarker) &&
    !outputs[2].includes(spec.marker);
  return {verdict: first && second ? 'observed' : !first && !second &&
    !outputs[1].includes(spec.secondMarker) && !outputs[2].includes(spec.marker) ?
    'not_reproduced' : 'inconclusive', impact: 'unverified', controls};
}

/** Freshly prove a reversible non-owner write to an owner-only local test record. */
async function checkModelStateChange(spec, env) {
  if (spec.targetEnvironment !== 'local' ||
      !['anonymous', 'outsider'].includes(spec.as) ||
      !['POST', 'PUT', 'PATCH'].includes(spec.subject?.method) ||
      !['json', 'form'].includes(spec.subject?.placement) ||
      !spec.protectedPath || spec.prelude?.length || spec.observe?.length ||
      spec.binding ||
      !validModelHttpSequence({...spec, kind: 'model-http-sequence'}))
    return {verdict: 'inconclusive', reason: 'State-change proof prerequisites are missing'};
  const readUrl = checkedUrl(spec, spec.protectedPath);
  const writeUrl = checkedUrl(spec, spec.subject.path,
    {reviewedFlowPost: spec.subject.method === 'POST',
      reviewedFlowStep: spec.subject});
  if (writeUrl.search || writeUrl.hash || writeUrl.pathname !== spec.subject.path)
    return {verdict: 'inconclusive', reason: 'State-change write left its reviewed path'};
  const controls = [];
  const get = async (as, label) => {
    let result;
    try {result = await read(spec, readUrl.href, as, env,
      {'cache-control': 'no-cache'});} catch {result = {status: null, json: false};}
    controls.push({label, status: result.status, hash: result.hash,
      cached: responseCached(result)});
    return result;
  };
  const valueOf = result => result?.status === 200 && result.json &&
    !responseCached(result) ?
    uniqueJsonStringField(result.body, spec.subject.key) : null;
  const write = async (value, label, as = spec.as) => {
    // The reviewed write may require harmless companion fields. Replay the
    // exact accepted body shape for each canary and for restoration.
    const fields = Object.fromEntries((spec.subject.fixedFields ?? [])
      .map(item => [item.field, item.value]));
    fields[spec.subject.key] = value;
    const body = spec.subject.placement === 'json' ?
      JSON.stringify(fields) : new URLSearchParams(fields).toString();
    const type = spec.subject.method === 'POST' ?
      (spec.subject.contentType ?? (spec.subject.placement === 'json' ?
        'application/json' : 'application/x-www-form-urlencoded')) :
      reviewedSequenceOperation(spec, spec.subject)?.contentType;
    if (!type || Buffer.byteLength(body) > 4096) throw Error('State-change proof body is not reviewed.');
    let response;
    try {
      const identityHeaders = await headerFor(spec, as, env, writeUrl);
      await pace(spec);
      response = await guardedRequest(writeUrl, {method: spec.subject.method,
        headers: {...identityHeaders, 'content-type': type,
          'cache-control': 'no-cache'}, body,
        maxBodyBytes: MODEL_RESPONSE_BYTES});
    } catch {response = {status: null, body: ''};}
    controls.push({label, status: response.status,
      hash: `sha256:${sha(response.body)}`, cached: responseCached(response)});
    return response;
  };
  const anonymous = await get('anonymous', 'anonymous-denial');
  if (!cleanDenied(anonymous) || responseCached(anonymous))
    return {verdict: 'inconclusive', reason: 'Owner-only read boundary was unavailable', controls};
  if (spec.as === 'outsider') {
    const outsider = await get('outsider', 'outsider-denial');
    if (!cleanDenied(outsider) || responseCached(outsider))
      return {verdict: 'inconclusive', reason: 'Cross-account read boundary was unavailable', controls};
  }
  const before = await get('owner', 'owner-before');
  const original = valueOf(before);
  const stable = await get('owner', 'owner-repeat');
  controls.at(-1).fieldMatches = valueOf(stable) === original;
  if (original === null)
    return {verdict: 'inconclusive',
      reason: 'Owner-only JSON field was unavailable', controls};
  if (valueOf(stable) !== original)
    return {verdict: 'inconclusive',
      reason: 'Owner-only JSON field changed between control reads', controls};
  const effectiveValues = stateChangeCanaries(original, spec.firstValue,
    spec.secondValue);
  const preflightReason = modelExperimentReason({...spec,
    parameter: spec.subject.key, controlValue: original,
    firstValue: effectiveValues.firstValue,
    secondValue: effectiveValues.secondValue});
  if (preflightReason)
    return {verdict: 'inconclusive',
      reason: `Owner field cannot be safely restored: ${preflightReason}`, controls};
  let writeStarted = false, outcome;
  const investigate = async () => {
    writeStarted = true;
    await write(original, 'same-value-control-write');
    const plain = await get('owner', 'same-value-control-read');
    controls.at(-1).fieldMatches = valueOf(plain) === original;
    if (valueOf(plain) !== original)
      return {verdict: 'inconclusive', reason: 'Same-value control changed the owner field'};
    await write(effectiveValues.firstValue, 'first-write');
    const firstRead = await get('owner', 'first-owner-read');
    controls.at(-1).fieldMatches = valueOf(firstRead) === effectiveValues.firstValue;
    await write(effectiveValues.secondValue, 'second-write');
    const secondRead = await get('owner', 'second-owner-read');
    controls.at(-1).fieldMatches = valueOf(secondRead) === effectiveValues.secondValue;
    const first = valueOf(firstRead) === effectiveValues.firstValue;
    const second = valueOf(secondRead) === effectiveValues.secondValue;
    if (first && second) return {verdict: 'confirmed',
      reason: `Two ${spec.as} writes changed an owner-only field`};
    if (!first && !second && valueOf(firstRead) === original &&
        valueOf(secondRead) === original) return {verdict: 'not_reproduced',
      reason: `Owner-only field stayed unchanged after both ${spec.as} writes`};
    return {verdict: 'inconclusive',
      reason: 'Write or owner-read behavior changed between independent canaries'};
  };
  try {outcome = await investigate();}
  finally {
    if (writeStarted) {
      await write(original, 'restore-write');
      let restored = await get('owner', 'restore-owner-read');
      let restoredValue = valueOf(restored) === original;
      controls.at(-1).fieldMatches = restoredValue;
      if (!restoredValue) {
        await write(original, 'restore-owner-write', 'owner');
        restored = await get('owner', 'restore-owner-read-after-fallback');
        restoredValue = valueOf(restored) === original;
        controls.at(-1).fieldMatches = restoredValue;
      }
      const anon = await get('anonymous', 'anonymous-recheck');
      const outsider = spec.as === 'outsider' ?
        await get('outsider', 'outsider-recheck') : null;
      if (!restoredValue || !cleanDenied(anon) ||
          outsider && !cleanDenied(outsider))
        outcome = {verdict: 'inconclusive',
          reason: 'Test record did not return to its owner-only baseline'};
    }
  }
  return {...outcome, controls,
    ...(effectiveValues.adjusted ? {canaryAdjustment: 'baseline-collision'} : {})};
}

/** Replay a Muse-selected sequence against a fresh owner-only content boundary. */
async function checkModelContentSequence(spec, env) {
  if (spec.kind !== 'model-access-boundary' ||
      !['sequence-exact-body', 'sequence-json-field'].includes(spec.comparison) ||
      spec.as !== 'anonymous' ||
      !validModelHttpSequence(spec) || !reviewedPostOrigin(spec) ||
      !spec.identities?.owner)
    return {verdict: 'inconclusive',
      reason: 'Sequence content proof prerequisites are missing'};
  const controls = [];
  let derivedSession = null;
  if ([...spec.prelude, ...spec.observe].some(step => step.as === 'derived')) {
    const loginSpec = {...spec, ...spec.derivedLogin, kind: 'model-auth-login',
      origin: spec.origin, include: spec.include, never: spec.never,
      targetEnvironment: spec.targetEnvironment, auth: spec.auth};
    const login = await checkModelAuthLogin(loginSpec, env,
      session => { derivedSession = session; });
    controls.push({label: 'fresh-login-boundary', verdict: login.verdict,
      checks: login.controls});
    if (login.verdict !== 'confirmed' || !derivedSession)
      return {verdict: login.verdict === 'not_reproduced' ? 'not_reproduced' :
        'inconclusive', reason: 'Fresh derived login did not establish a session', controls};
  }
  const protectedUrl = checkedUrl(spec, spec.protectedPath);
  const issue = async (step, value, captures, to, index, onRequest = null) => {
    const subject = step === spec.subject;
    const write = step.method === 'POST' || SEQUENCE_WRITE_METHODS.has(step.method);
    const bodyWrite = write && SEQUENCE_BODY_PLACEMENTS.has(step.placement);
    const legacyPost = step.method === 'POST';
    const bound = to ? sequenceTargetBindings(spec, to, index, captures) : [];
    if (bound.some(item => item.value == null))
      throw Error('Model sequence binding was unavailable.');
    const submittedValue = bound.find(item => item.binding.placement !== 'path' &&
      item.binding.key === step.key)?.value ?? (subject ? value : step.value);
    const identity = subject ? spec.as : step.as ?? spec.as;
    const selectedPath = bound.filter(item => item.binding.placement === 'path')
      .reduce((path, item) => path && boundSequencePath(path,
        item.binding, item.value), step.path);
    if (!selectedPath) throw Error('Model sequence path binding was unavailable.');
    const url = checkedUrl(spec, selectedPath, {reviewedFlowPost: legacyPost,
      reviewedFlowStep: step});
    if (write && (url.pathname !== step.path || url.search || url.hash))
      throw Error('Model sequence write is outside its reviewed exact path.');
    if (subject && step.method === 'GET') url.searchParams.set(step.key, submittedValue);
    if (step.placement === 'query' && step.key && write) {
      for (const item of step.fixedFields ?? [])
        url.searchParams.set(item.field, item.value);
      url.searchParams.set(step.key, submittedValue);
    }
    if (!bodyWrite) for (const item of bound) {
      if (item.binding.placement !== 'path')
        url.searchParams.set(item.binding.key, item.value);
    }
    checkedUrl(spec, url.href, {reviewedFlowPost: legacyPost,
      reviewedFlowStep: step});
    if (identity !== 'anonymous' && Array.isArray(spec.credentialOrigins) &&
        !spec.credentialOrigins.includes(url.origin))
      throw Error('Model sequence credential origin is outside its recorded scope.');
    const headers = {...(identity === 'derived' ?
      sessionHeaders(spec.auth, derivedSession) :
      await headerFor(spec, identity, env, url)),
      ...Object.fromEntries((step.headers ?? []).map(item =>
        [item.name.toLowerCase(), item.value])), 'cache-control': 'no-cache'};
    if (step.placement === 'header' && step.key && write)
      headers[step.key.toLowerCase()] = submittedValue;
    let body = null;
    if (bodyWrite) {
      headers['content-type'] = reviewedSequenceOperation(spec, step)?.contentType ??
        (step.placement === 'form' ? 'application/x-www-form-urlencoded' :
          step.placement === 'xml' ? 'application/xml' : 'application/json');
      const fixed = {...Object.fromEntries((step.fixedFields ?? [])
        .map(item => [item.field, item.value])),
      ...Object.fromEntries(bound.filter(item => item.binding.placement !== 'path')
        .map(item => [item.binding.key, item.value]))};
      body = step.placement === 'json' ?
        sequenceJsonBody(fixed, step.key, submittedValue,
          step.valueEncoding) :
        step.placement === 'form' ? new URLSearchParams({...fixed,
          [step.key]: submittedValue}).toString() :
          step.bodyTemplate.replace('{{input}}', submittedValue);
      if (Buffer.byteLength(body) > 4096)
        throw Error('Model sequence request body exceeds its byte limit.');
    }
    onRequest?.({url: url.href, headers, body});
    await pace(spec);
    return guardedRequest(url, {method: step.method, headers, body,
      allowRemoteHttp: spec.allowRemoteHttp === true && identity === 'anonymous',
      maxBodyBytes: MODEL_RESPONSE_BYTES});
  };
  const runCandidate = async (value, options = {}) => {
    const steps = [];
    let submittedPrivateMaterial = false;
    const trackRequest = request => {
      submittedPrivateMaterial ||= requestSuppliesPrivateMaterial(request,
        options.privateMaterialValue);
    };
    const incomplete = () => ({steps, complete: false, submittedPrivateMaterial});
    const record = (step, response, label) => {
      steps.push({response, label, method: step.method, path: step.path,
        identity: step === spec.subject ? spec.as : step.as ?? spec.as});
      return response;
    };
    const captures = new Map();
    for (const [index, step] of spec.prelude.entries()) {
      const response = record(step,
        await issue(step, value, captures, 'prelude', index, trackRequest),
        `prelude-${index}`);
      const setupSucceeded = ['GET', 'HEAD'].includes(step.method) ?
        response.status === 200 : response.status >= 200 && response.status < 300;
      if (!setupSucceeded || responseCached(response))
        return incomplete();
      for (const [at, binding] of sequenceBindings(spec).entries()) {
        if (binding.from !== index) continue;
        if (!/(?:json|\+json)/i.test(response.headers?.['content-type'] ?? ''))
          return incomplete();
        const captured = captureSequenceScalar(response.body, binding.pointer);
        if (captured === null) return incomplete();
        captures.set(at, captured);
      }
    }
    const subject = record(spec.subject,
      await issue(spec.subject, value, captures, 'subject', 0, trackRequest),
      'subject');
    if (subject.status == null || subject.status === 429 || subject.status >= 500 ||
        responseCached(subject)) return incomplete();
    const observations = [];
    for (const [index, step] of spec.observe.entries()) {
      const response = record(step,
        await issue(step, value, captures, 'observe', index, trackRequest),
        `observe-${index}`);
      observations.push(response);
      if (response.status == null || response.status === 429 ||
          response.status >= 500 || responseCached(response))
        return incomplete();
    }
    const selected = spec.assertion.step === 'subject' ? subject :
      observations[spec.assertion.index];
    const selectedAs = spec.assertion.step === 'subject' ? spec.as :
      spec.observe[spec.assertion.index]?.as ?? spec.as;
    let publicBinding = true;
    for (const [at, binding] of sequenceBindings(spec).entries()) {
      const boundSource = spec.prelude[binding.from];
      const bindingAffectsAssertion = binding.to === 'prelude' ||
        binding.to === 'subject' ||
        binding.to === 'observe' && spec.assertion.step === 'observe' &&
          binding.index <= spec.assertion.index;
      if (!bindingAffectsAssertion ||
          (boundSource.as ?? spec.as) === 'anonymous') continue;
      // Do not send an earlier protected capture into an anonymous control.
      if (sequenceBindings(spec).some(item => item.to === 'prelude' &&
          item.index === binding.from)) {publicBinding = false; break;}
      const captured = captures.get(at);
      publicBinding = captured != null;
      for (let check = 0; check < 2 && publicBinding; check++) {
        const publicStep = {...boundSource, as: 'anonymous', headers: []};
        let response;
        try {response = await issue(publicStep, value, new Map(), null, 0,
          trackRequest);} catch {
          response = {status: null, body: '', headers: {}, refused: true};
        }
        record(publicStep, response, `public-binding-control-${at}-${check}`);
        publicBinding = response.status >= 200 && response.status < 300 &&
          !response.blocked && !response.refused && !responseCached(response) &&
          /(?:json|\+json)/i.test(response.headers?.['content-type'] ?? '') &&
          captureSequenceScalar(response.body, binding.pointer) === captured;
      }
      if (!publicBinding) break;
    }
    return {response: selected, steps, publicBinding,
      submittedPrivateMaterial,
      credentialedPrelude: spec.prelude.some(step =>
        (step.as ?? spec.as) !== 'anonymous'),
      complete: selectedAs === 'anonymous' &&
      steps.every(item => item.response.status != null &&
        item.response.status !== 429 && item.response.status < 500 &&
        !responseCached(item.response))};
  };
  const result = await verifyContentBoundary({requester: async request => {
    const url = checkedUrl(spec, request.url);
    return read(spec, url.href, request.identity, env,
      {'cache-control': 'no-cache'}, MODEL_RESPONSE_BYTES);
  }, protectedRequest: {url: protectedUrl.href, method: 'GET'}, runCandidate,
  comparison: spec.comparison === 'sequence-json-field' ? 'json-field' :
    'exact-body',
  controlValue: spec.controlValue, firstValue: spec.firstValue,
  secondValue: spec.secondValue});
  return {...result, controls: [...controls, ...(result.controls ?? [])]};
}

/** Recheck an observed anonymous input against exact owner-only response bytes. */
async function checkModelContentBoundary(spec, env) {
  const post = spec.subject?.method === 'POST' && spec.subject?.placement === 'json';
  const get = spec.subject?.method === 'GET' && spec.subject?.placement === 'query';
  if (spec.kind !== 'model-access-boundary' ||
      !['exact-body', 'json-field'].includes(spec.comparison) ||
      contentBoundaryShapeReason(spec) ||
      !reviewedPostOrigin(spec) ||
      !(post && spec.reviewedPostPaths?.json?.includes(spec.subject.path) &&
        Array.isArray(spec.reviewedPostFields) &&
        [spec.subject.key, ...spec.subject.fixedFields.map(item => item.field)]
          .every(name => spec.reviewedPostFields.includes(name)) ||
      get && Array.isArray(spec.reviewedGetInputs) &&
        spec.reviewedGetInputs.some(item => item.path === spec.subject.path)) ||
      !spec.identities?.owner)
    return {verdict: 'inconclusive',
      reason: 'Exact-content proof prerequisites are missing'};
  const protectedUrl = checkedUrl(spec, spec.protectedPath);
  const subjectUrl = checkedUrl(spec, spec.subject.path,
    {reviewedBoundaryPost: post});
  if (subjectUrl.search || subjectUrl.pathname !== spec.subject.path)
    return {verdict: 'inconclusive', reason: 'Input is outside its reviewed exact path'};
  const makeCandidate = value => {
    if (get) {
      const url = new URL(subjectUrl);
      url.searchParams.set(spec.subject.key, value);
      return {url: url.href, method: 'GET', identity: 'anonymous'};
    }
    return {url: subjectUrl.href, method: 'POST', identity: 'anonymous',
      body: sequenceJsonBody(Object.fromEntries(spec.subject.fixedFields.map(item =>
        [item.field, item.value])), spec.subject.key, value,
      spec.subject.valueEncoding)};
  };
  const requester = async request => {
    const url = checkedUrl(spec, request.url, {reviewedBoundaryPost: post &&
      request.method === 'POST'});
    if (request.method === 'POST') {
      if (url.pathname !== spec.subject.path || url.search ||
          Buffer.byteLength(request.body ?? '') > 4096)
        throw Error('Exact-content POST is outside its reviewed shape.');
      await pace(spec);
      return guardedRequest(url, {method: 'POST',
        headers: {'content-type': 'application/json', 'cache-control': 'no-cache'},
        body: request.body, maxBodyBytes: MODEL_RESPONSE_BYTES});
    }
    if (request.method !== 'GET') throw Error('Exact-content proof supports GET reads only.');
    return read(spec, url.href, request.identity, env,
      {'cache-control': 'no-cache'}, MODEL_RESPONSE_BYTES);
  };
  return verifyContentBoundary({requester,
    protectedRequest: {url: protectedUrl.href, method: 'GET'},
    comparison: spec.comparison,
    makeCandidate, controlValue: spec.controlValue,
    firstValue: spec.firstValue, secondValue: spec.secondValue});
}

/** Recheck an observed anonymous input against a protected owner item. */
async function checkModelAccessBoundary(spec, env) {
  if (['sequence-exact-body', 'sequence-json-field'].includes(spec.comparison))
    return checkModelContentSequence(spec, env);
  if (['exact-body', 'json-field'].includes(spec.comparison))
    return checkModelContentBoundary(spec, env);
  const post = spec.subject?.method === 'POST' && spec.subject?.placement === 'json';
  const get = spec.subject?.method === 'GET' && spec.subject?.placement === 'query';
  if (spec.kind !== 'model-access-boundary' || !validBoundaryShape(spec) ||
      !reviewedPostOrigin(spec) ||
      !(post && spec.reviewedPostPaths?.json?.includes(spec.subject.path) &&
        Array.isArray(spec.reviewedPostFields) &&
        [spec.subject.key, ...spec.subject.fixedFields.map(item => item.field)]
          .every(name => spec.reviewedPostFields.includes(name)) ||
      get && Array.isArray(spec.reviewedGetInputs) &&
        spec.reviewedGetInputs.some(item => item.path === spec.subject.path)) ||
      !spec.identities?.owner)
    return {verdict: 'inconclusive', reason: 'Access-boundary proof prerequisites are missing'};
  const protectedUrl = checkedUrl(spec, spec.protectedPath);
  const subjectUrl = checkedUrl(spec, spec.subject.path, {reviewedBoundaryPost: post});
  if (subjectUrl.search || subjectUrl.pathname !== spec.subject.path)
    return {verdict: 'inconclusive', reason: 'Input is outside its reviewed exact path'};
  const probe = async value => {
    if (get) {
      const url = new URL(subjectUrl);
      url.searchParams.set(spec.subject.key, value);
      const response = await read(spec, url.href, 'anonymous', env,
        {'cache-control': 'no-cache'}, MODEL_RESPONSE_BYTES);
      return {...response, headers: {...response.headers, 'content-type': response.type}};
    }
    const body = sequenceJsonBody(Object.fromEntries(spec.subject.fixedFields.map(item =>
      [item.field, item.value])), spec.subject.key, value,
      spec.subject.valueEncoding);
    if (Buffer.byteLength(body) > 4096) throw Error('Proof request body exceeds its byte limit.');
    await pace(spec);
    return guardedRequest(subjectUrl, {method: 'POST',
      headers: {'content-type': 'application/json', 'cache-control': 'no-cache'},
      body, maxBodyBytes: MODEL_RESPONSE_BYTES});
  };
  const controls = [];
  const ownerOne = await read(spec, protectedUrl.href, 'owner', env,
    {'cache-control': 'no-cache'}, MODEL_RESPONSE_BYTES);
  const anonymousOne = await read(spec, protectedUrl.href, 'anonymous', env,
    {'cache-control': 'no-cache'}, MODEL_RESPONSE_BYTES);
  const ownerTwo = await read(spec, protectedUrl.href, 'owner', env,
    {'cache-control': 'no-cache'}, MODEL_RESPONSE_BYTES);
  const anonymousTwo = await read(spec, protectedUrl.href, 'anonymous', env,
    {'cache-control': 'no-cache'}, MODEL_RESPONSE_BYTES);
  controls.push({label: 'owner-one', status: ownerOne.status, hash: ownerOne.hash},
    {label: 'anonymous-one', status: anonymousOne.status},
    {label: 'owner-two', status: ownerTwo.status, hash: ownerTwo.hash},
    {label: 'anonymous-two', status: anonymousTwo.status});
  const ownerComparison = {...spec, candidatePointer: spec.ownerPointer};
  if (ownerOne.status !== 200 || ownerTwo.status !== 200 ||
      !ownerOne.json || !ownerTwo.json ||
      !boundaryMatch(ownerOne.body, ownerTwo.body, ownerComparison).match ||
      !boundaryMatch(ownerTwo.body, ownerOne.body, ownerComparison).match ||
      !cleanDenied(anonymousOne) || !cleanDenied(anonymousTwo) ||
      [ownerOne, ownerTwo, anonymousOne, anonymousTwo].some(response =>
        responseCached(response) || response.status === 429 || response.status >= 500))
    return {verdict: 'inconclusive',
      reason: 'Protected owner and anonymous controls were unavailable or unstable', controls};
  const baselineOne = await probe(spec.controlValue);
  const attackOne = await probe(spec.firstValue);
  const baselineTwo = await probe(spec.controlValue);
  const attackTwo = await probe(spec.secondValue);
  const responses = [baselineOne, attackOne, baselineTwo, attackTwo];
  const labels = ['baseline-one', 'attack-one', 'baseline-two', 'attack-two'];
  const matched = responses.map(response => boundaryMatch(ownerOne.body, response.body, spec).match);
  controls.push(...responses.map((response, index) => ({label: labels[index],
    status: response.status, hash: `sha256:${sha(response.body)}`,
    ownerObjectMatched: matched[index]})));
  if (responses.some(response => response.status !== 200 || responseCached(response) ||
      !/(?:json|\+json)/i.test(response.headers?.['content-type'] ?? '')))
    return {verdict: 'inconclusive', reason: 'JSON input controls were unavailable or cached', controls};
  if (matched[0] || matched[2]) return {verdict: 'inconclusive',
    reason: 'A baseline input already returned the protected object', controls};
  if (matched[1] && matched[3]) return {verdict: 'confirmed', controls};
  if (matched[1] !== matched[3]) {
    const positive = matched[1] ? 'first' : 'second';
    const repeated = await probe(matched[1] ? spec.firstValue : spec.secondValue);
    const baselineFinal = await probe(spec.controlValue);
    const ownerFinal = await read(spec, protectedUrl.href, 'owner', env,
      {'cache-control': 'no-cache'}, MODEL_RESPONSE_BYTES);
    const anonymousFinal = await read(spec, protectedUrl.href, 'anonymous', env,
      {'cache-control': 'no-cache'}, MODEL_RESPONSE_BYTES);
    const repeatMatch = repeated.status === 200 && !responseCached(repeated) &&
      /(?:json|\+json)/i.test(repeated.headers?.['content-type'] ?? '') &&
      boundaryMatch(ownerTwo.body, repeated.body, spec).match;
    const baselineFinalExcluded = baselineFinal.status === 200 &&
      !responseCached(baselineFinal) &&
      /(?:json|\+json)/i.test(baselineFinal.headers?.['content-type'] ?? '') &&
      !boundaryMatch(ownerTwo.body, baselineFinal.body, spec).match;
    const ownerStable = ownerFinal.status === 200 && ownerFinal.json &&
      !responseCached(ownerFinal) &&
      boundaryMatch(ownerFinal.body, ownerTwo.body, ownerComparison).match &&
      boundaryMatch(ownerTwo.body, ownerFinal.body, ownerComparison).match;
    const anonymousDenied = cleanDenied(anonymousFinal) &&
      !responseCached(anonymousFinal);
    controls.push({label: 'positive-repeat', positive, status: repeated.status,
      hash: typeof repeated.body === 'string' ? `sha256:${sha(repeated.body)}` : null,
      ownerObjectMatched: repeatMatch},
    {label: 'baseline-final', status: baselineFinal.status,
      excludesOwnerObject: baselineFinalExcluded},
    {label: 'owner-final', status: ownerFinal.status, ownerStable},
    {label: 'anonymous-final', status: anonymousFinal.status,
      denied: anonymousDenied});
    return {verdict: repeatMatch && baselineFinalExcluded && ownerStable && anonymousDenied ?
      'confirmed' : 'inconclusive',
    reason: repeatMatch && baselineFinalExcluded && ownerStable && anonymousDenied ?
      'One candidate repeated the owner-only object with fresh owner and anonymous controls' :
      'The single positive candidate or fresh controls did not reproduce', controls};
  }
  return {verdict: !matched[1] && !matched[3] ? 'not_reproduced' :
    'inconclusive', controls};
}

async function checkPublicSessionToken(spec, env) {
  if (!localHost(new URL(spec.origin).hostname) || spec.request?.method !== 'GET' ||
      spec.request?.as !== 'anonymous' || !validModelJsonPointer(spec.tokenPointer))
    return {verdict: 'inconclusive', reason: 'Public-session proof prerequisites are missing'};
  const privateUrl = checkedUrl(spec, spec.privatePath).href;
  const sourceUrl = checkedUrl(spec, spec.sourcePath).href;
  if (privateUrl === sourceUrl) return {verdict: 'inconclusive', reason: 'Source and private route are identical'};
  const headers = {'cache-control': 'no-cache'};
  const owner = await read(spec, privateUrl, 'owner', env, headers);
  const anonymous = await read(spec, privateUrl, 'anonymous', env, headers);
  const invalid = await read(spec, privateUrl, 'anonymous', env,
    {...headers, authorization: `Bearer bx-invalid-${randomBytes(12).toString('hex')}`});
  const controls = [{label: 'owner', status: owner.status, hash: owner.hash},
    {label: 'anonymous', status: anonymous.status},
    {label: 'invalid-token', status: invalid.status}];
  if (owner.status !== 200 || !owner.json || !cleanDenied(anonymous) || !cleanDenied(invalid) ||
      [owner, anonymous, invalid].some(item => responseCached(item) || item.status === 429 || item.status >= 500))
    return {verdict: 'inconclusive', reason: 'The owner/private controls were unavailable', controls};
  const ownerToken = env[spec.identities?.owner];
  if (!ownerToken) return {verdict: 'inconclusive', reason: 'Owner test token is unavailable', controls};
  for (let index = 0; index < 2; index++) {
    const source = await read(spec, sourceUrl, 'anonymous', env, headers);
    const token = source.status === 200 && source.json ?
      modelJsonPointer(source.body, spec.tokenPointer) : null;
    controls.push({label: `public-source-${index + 1}`, status: source.status,
      ownerTokenExposed: token === ownerToken});
    if (source.status === 429 || source.status >= 500 || responseCached(source))
      return {verdict: 'inconclusive', reason: 'Public source was unavailable or cached', controls};
    if (token !== ownerToken) return {verdict: index ? 'inconclusive' : 'not_reproduced', controls};
    const replay = await read(spec, privateUrl, 'anonymous', env,
      {...headers, authorization: `Bearer ${token}`});
    const matched = replay.status === 200 && replay.json && replay.hash === owner.hash;
    controls.push({label: `public-token-replay-${index + 1}`, status: replay.status,
      ownerResponseMatched: matched});
    if (replay.status === 429 || replay.status >= 500 || responseCached(replay))
      return {verdict: 'inconclusive', reason: 'Token replay was unavailable or cached', controls};
    if (!matched) return {verdict: index ? 'inconclusive' : 'not_reproduced', controls};
  }
  return {verdict: 'confirmed', controls};
}

const AUTH_FIELD = /^[A-Za-z_][A-Za-z0-9_.-]{0,79}$/;
const PRINCIPAL_FIELD = /^(?:id|_id|uid|sub|userId|accountId|principalId|username|email)$/i;
export const safeAuthUserPayload = value => typeof value === 'string' &&
  !/[\r\n\x00]/.test(value);

/** Return only the failed proof prerequisite; never include candidate inputs. */
export function modelAuthLoginRejection(spec) {
  const statusMode = spec?.proofMode === 'protected-status';
  if (spec?.kind !== 'model-auth-login') return 'kind';
  if (!reviewedPostOrigin(spec)) return 'origin';
  if (![undefined, 'principal', 'protected-status'].includes(spec.proofMode)) return 'mode';
  if (!['bearer', 'cookie'].includes(spec.auth)) return 'auth';
  if (spec.request?.method !== 'POST' || spec.request?.as !== 'anonymous' ||
      spec.request?.url !== spec.loginPath) return 'request';
  if (!AUTH_FIELD.test(spec.userField ?? '') || !AUTH_FIELD.test(spec.passwordField ?? '') ||
      spec.userField === spec.passwordField) return 'fields';
  if (!Array.isArray(spec.userPayloads) ||
      spec.userPayloads.length !== (statusMode ? 1 : 2)) return 'payload-count';
  if (!spec.userPayloads.every(safeAuthUserPayload)) return 'payload-shape';
  if (!statusMode && spec.userPayloads[0] === spec.userPayloads[1]) return 'duplicate-payload';
  if (spec.auth === 'bearer' && !validModelJsonPointer(spec.tokenPointer) &&
      !(statusMode && spec.tokenPointer == null)) return 'token-pointer';
  if (!statusMode) {
    if (!validModelJsonPointer(spec.principalPointer)) return 'principal-pointer';
    if (!PRINCIPAL_FIELD.test(spec.principalPointer.split('/').at(-1))) return 'principal-field';
    if (spec.principalPointer.slice(1).split('/').some(name =>
      SEQUENCE_SECRET_FIELD.test(name))) return 'principal-secret-field';
  }
  if (typeof spec.loginPath !== 'string' || typeof spec.privatePath !== 'string' ||
      spec.loginPath === spec.privatePath) return 'paths';
  if (!Array.isArray(spec.reviewedAuthPosts) ||
      !spec.reviewedAuthPosts.some(item => item.path === spec.loginPath &&
        item.usernameField === spec.userField &&
        item.passwordField === spec.passwordField)) return 'reviewed-contract';
  return null;
}

/** A login proof stores synthetic usernames only; passwords and tokens are regenerated. */
export function validModelAuthLogin(spec) {
  return modelAuthLoginRejection(spec) === null;
}

function authPrincipal(body, pointer) {
  if (!validModelJsonPointer(pointer)) return null;
  let current;
  try {current = JSON.parse(body);} catch {return null;}
  for (const name of pointer.slice(1).split('/')) {
    if (!object(current) || !Object.hasOwn(current, name)) return null;
    current = current[name];
  }
  if (typeof current === 'number' && Number.isSafeInteger(current) && current >= 0)
    return String(current);
  return typeof current === 'string' && /^[\x21-\x7e]{1,128}$/.test(current) ?
    current : null;
}

async function checkModelAuthLogin(spec, env, onConfirmedSession = null) {
  if (!validModelAuthLogin(spec)) return {verdict: 'inconclusive',
    reason: 'Auth-login proof prerequisites are missing'};
  const loginUrl = checkedUrl(spec, spec.loginPath);
  const privateUrl = checkedUrl(spec, spec.privatePath);
  if (loginUrl.pathname !== spec.loginPath || loginUrl.search ||
      privateUrl.pathname !== spec.privatePath || privateUrl.search)
    return {verdict: 'inconclusive', reason: 'Auth-login paths are outside reviewed exact routes'};
  const controls = [];
  const statusMode = spec.proofMode === 'protected-status';
  const healthy = response => response?.status != null && response.status !== 429 &&
    response.status < 500 && !responseCached(response);
  const post = async (username, password, label) => {
    const body = JSON.stringify({[spec.userField]: username,
      [spec.passwordField]: password});
    if (Buffer.byteLength(body) > 4096) throw Error('Auth-login proof body exceeds its byte limit.');
    await pace(spec);
    const response = await guardedRequest(loginUrl, {method: 'POST',
      headers: {'content-type': 'application/json', 'cache-control': 'no-cache'},
      body, maxBodyBytes: MODEL_RESPONSE_BYTES});
    const found = spec.auth === 'cookie' ? loginToken(response, 'cookie') : null;
    const token = response.status >= 200 && response.status < 300 ?
      spec.auth === 'cookie' ? found?.placement === 'cookie' ? found.value : null :
      /(?:json|\+json)/i.test(response.headers['content-type'] ?? '') ?
        modelAuthBearer(response.body, spec.tokenPointer) : null : null;
    controls.push({label, status: response.status,
      cached: responseCached(response), tokenPresent: token !== null});
    return {response, token};
  };
  const get = async (session, label) => {
    await pace(spec);
    const response = await guardedRequest(privateUrl, {method: 'GET',
      headers: {'cache-control': 'no-cache',
        ...(session ? sessionHeaders(spec.auth, session) : {})},
      maxBodyBytes: MODEL_RESPONSE_BYTES});
    const principal = !statusMode && response.status === 200 &&
      /(?:json|\+json)/i.test(response.headers['content-type'] ?? '') ?
        authPrincipal(response.body, spec.principalPointer) : null;
    controls.push({label, status: response.status,
      cached: responseCached(response), principalPresent: principal !== null});
    return {response, principal};
  };
  let stablePrincipal = null, successful = 0, replaySession = null;
  for (let round = 0; round < 2; round++) {
    const password = `bx-invalid-${randomBytes(12).toString('hex')}`;
    const nonexistent = `bx-user-${randomBytes(10).toString('hex')}@invalid`;
    const baseline = await post(nonexistent, password, `invalid-login-${round + 1}`);
    const anonymous = await get(null, `anonymous-private-${round + 1}`);
    const invalid = spec.auth === 'cookie' ? null :
      await get(invalidSession(spec.auth), `invalid-bearer-${round + 1}`);
    const unavailable = [baseline.response, anonymous.response, invalid?.response]
      .filter(Boolean)
      .some(response => !healthy(response));
    const noPrincipal = item => denied(item.response.status) ||
      item.response.status === 200 && item.principal === null;
    if (unavailable || baseline.token !== null ||
        statusMode && !denied(baseline.response.status) ||
        !(statusMode ? denied(anonymous.response.status) &&
          (!invalid || denied(invalid.response.status)) :
          noPrincipal(anonymous) && (!invalid || noPrincipal(invalid))))
      return {verdict: 'inconclusive',
        reason: 'Invalid-credential or anonymous controls did not establish a private boundary',
        controls};
    for (const [index, username] of spec.userPayloads.entries()) {
      const login = await post(username, password, `candidate-login-${round + 1}-${index + 1}`);
      if (!healthy(login.response)) return {verdict: 'inconclusive',
        reason: 'Candidate login was unavailable or cached', controls};
      if (!login.token) continue;
      if (spec.auth === 'cookie') {
        const invalidCookie = await get(invalidSession('cookie', login.token),
          `invalid-cookie-${round + 1}-${index + 1}`);
        if (!healthy(invalidCookie.response) ||
            !(statusMode ? denied(invalidCookie.response.status) :
              noPrincipal(invalidCookie))) return {verdict: 'inconclusive',
          reason: 'Invalid-cookie control did not establish the protected route',
          controls};
      }
      const access = await get(login.token, `candidate-private-${round + 1}-${index + 1}`);
      if (!healthy(access.response)) return {verdict: 'inconclusive',
        reason: 'Candidate private read was unavailable or cached', controls};
      if (statusMode) {
        if (access.response.status >= 200 && access.response.status < 300) {
          successful++;
          replaySession = login.token;
        }
        continue;
      }
      if (access.principal === null) continue;
      successful++;
      replaySession = login.token;
      if (stablePrincipal !== null && stablePrincipal !== access.principal)
        return {verdict: 'inconclusive',
          reason: 'Candidate logins reached different principals', controls};
      stablePrincipal = access.principal;
    }
  }
  const expected = statusMode ? 2 : 4;
  const verdict = successful === expected ? 'confirmed' : successful === 0 ?
    'not_reproduced' : 'inconclusive';
  if (verdict === 'confirmed' && onConfirmedSession && replaySession)
    onConfirmedSession(replaySession);
  return {verdict,
  reason: successful === expected ? statusMode ?
    'One synthetic username input twice reached a protected GET under fresh invalid passwords and denial controls' :
    'Two synthetic username inputs authenticated to one stable principal under two fresh invalid passwords' :
    successful === 0 ? 'Synthetic username inputs did not authenticate under invalid passwords' :
      'Only some candidate logins authenticated under invalid passwords', controls};
}

async function checkSqlBoolean(spec, env) {
  if (!safeProbeParameter(spec.parameter) ||
      !['anonymous', 'owner', 'outsider', 'derived'].includes(spec.request?.as) ||
      !/^[A-Za-z0-9_.@-]{1,64}$/.test(spec.base ?? '') ||
      !['quoted', 'numeric', 'search-quote-close-or'].includes(spec.style))
    return {verdict: 'inconclusive', reason: 'SQL boolean proof prerequisites are missing'};
  const withValue = value => {
    const url = new URL(spec.request.url, spec.origin);
    url.searchParams.set(spec.parameter, value);
    return url.href;
  };
  const controls = [];
  let derivedSession = null;
  if (spec.request.as === 'derived') {
    if (!spec.derivedLogin || !['bearer', 'cookie'].includes(spec.auth) ||
        !['local', 'preview', 'staging', 'production'].includes(spec.targetEnvironment))
      return {verdict: 'inconclusive', reason: 'Derived session proof prerequisites are missing'};
    const loginSpec = {...spec, ...spec.derivedLogin, kind: 'model-auth-login',
      origin: spec.origin, include: spec.include, never: spec.never,
      targetEnvironment: spec.targetEnvironment, auth: spec.auth};
    const login = await checkModelAuthLogin(loginSpec, env,
      session => { derivedSession = session; });
    controls.push({label: 'fresh-login-boundary', verdict: login.verdict,
      checks: login.controls});
    if (login.verdict !== 'confirmed' || !derivedSession)
      return {verdict: login.verdict === 'not_reproduced' ? 'not_reproduced' : 'inconclusive',
        reason: 'Fresh derived login did not establish a private session', controls};
    const boundaryUrl = withValue(spec.base);
    const anonymous = await read(spec, boundaryUrl, 'anonymous', env);
    const invalid = await read(spec, boundaryUrl, 'anonymous', env,
      sessionHeaders(spec.auth, invalidSession(spec.auth, derivedSession)));
    controls.push({label: 'protected-route-boundary', anonymousStatus: anonymous.status,
      invalidBearerStatus: invalid.status});
    if (!denied(anonymous.status) || !denied(invalid.status) ||
        responseCached(anonymous) || responseCached(invalid))
      return {verdict: 'inconclusive',
        reason: 'Anonymous and invalid-bearer controls did not establish the protected route', controls};
  }
  const sqlRead = (url, headers) => spec.request.as === 'derived' ?
    read(spec, url, 'anonymous', env,
      {...headers, ...sessionHeaders(spec.auth, derivedSession)}) :
    read(spec, url, spec.request.as, env, headers);
  const first = sqlBooleanCanary(spec.base, spec.style);
  let second = sqlBooleanCanary(spec.base, spec.style);
  while (second.number === first.number) second = sqlBooleanCanary(spec.base, spec.style);
  let baselineHash = null, searchHashes = null;
  for (const [index, sample] of [first, second].entries()) {
    const headers = index ? {'cache-control': 'no-cache'} : {};
    const baseline = await sqlRead(withValue(spec.base), headers);
    if (baseline.status !== 200 || !baseline.json || !baseline.ids.length || responseCached(baseline)) {
      controls.push({label: `record-control-${index + 1}`, status: baseline.status, identifiable: false});
      return {verdict: 'inconclusive', reason: 'known value no longer returns an identifiable JSON record', controls};
    }
    const yes = await sqlRead(withValue(sample.yes), headers);
    const no = await sqlRead(withValue(sample.no), headers);
    const matched = sqlBooleanOracle(baseline, yes, no, spec.style);
    controls.push({label: `boolean-pair-${index + 1}`, baseline: baseline.status,
      trueStatus: yes.status, falseStatus: no.status, matched});
    if (baselineHash && baseline.hash !== baselineHash)
      return {verdict: 'inconclusive', reason: 'baseline changed between proof pairs', controls};
    baselineHash = baseline.hash;
    if (spec.style === 'search-quote-close-or') {
      if (searchHashes && (yes.hash !== searchHashes.yes || no.hash !== searchHashes.no))
        return {verdict: 'inconclusive', reason: 'search differential changed between proof pairs', controls};
      searchHashes = {yes: yes.hash, no: no.hash};
    }
    if ([yes, no].some(responseCached))
      return {verdict: 'inconclusive', reason: 'SQL boolean response was cached', controls};
    if ([yes, no].some(item => item.status == null || [400, 401, 403, 429].includes(item.status) ||
        item.status >= 500 || item.status >= 300 && item.status < 400))
      return {verdict: 'inconclusive', reason: 'SQL boolean response was an error, throttle or redirect', controls};
    if (!matched) return {verdict: index ? 'inconclusive' : 'not_reproduced', controls};
  }
  return {verdict: 'confirmed', controls};
}

async function checkNosqlOperator(spec, env) {
  if (!safeProbeParameter(spec.parameter) ||
      !/^[A-Za-z0-9_.@-]{1,64}$/.test(spec.base ?? '') || spec.request?.as !== 'outsider')
    return {verdict: 'inconclusive', reason: 'operator proof prerequisites are missing'};
  const plainUrl = new URL(spec.request.url, spec.origin);
  plainUrl.searchParams.set(spec.parameter, spec.base);
  const controls = [];
  let firstOwnerHash = null;
  for (let index = 0; index < 2; index++) {
    const headers = index ? {'cache-control': 'no-cache'} : {};
    const negative = `${spec.base}-bx-${randomBytes(8).toString('hex')}`;
    const owner = await read(spec, plainUrl.href, 'owner', env, headers);
    const plain = await read(spec, plainUrl.href, 'outsider', env, headers);
    const yes = await read(spec, nosqlEqUrl(spec.request.url, spec.origin, spec.parameter, spec.base),
      'outsider', env, headers);
    const no = await read(spec, nosqlEqUrl(spec.request.url, spec.origin, spec.parameter, negative),
      'outsider', env, headers);
    const matched = nosqlOperatorOracle(owner, plain, yes, no, spec.base);
    controls.push({label: `operator-pair-${index + 1}`, ownerStatus: owner.status,
      plainStatus: plain.status, positiveStatus: yes.status, negativeStatus: no.status, matched});
    if (firstOwnerHash && owner.hash !== firstOwnerHash)
      return {verdict: 'inconclusive', reason: 'owner lookup changed between operator pairs', controls};
    firstOwnerHash = owner.hash;
    if (owner.status !== 200 || !owner.json || !owner.ids.includes(spec.base) ||
        [owner, plain, yes, no].some(responseCached))
      return {verdict: 'inconclusive', reason: 'operator controls were unavailable or cached', controls};
    if ([plain, yes, no].some(item => item.status == null || item.status === 429 ||
        item.status >= 500 || item.status >= 300 && item.status < 400))
      return {verdict: 'inconclusive', reason: 'operator response was an error, throttle or redirect', controls};
    if (!matched) return {verdict: index ? 'inconclusive' : 'not_reproduced', controls};
  }
  return {verdict: 'confirmed', controls};
}

async function checkRedirectPollution(spec, env) {
  if (!validQueryParameter(spec.parameter) ||
      !['anonymous', 'owner', 'outsider'].includes(spec.request?.as) ||
      !['safe-first', 'external-first'].includes(spec.order))
    return {verdict: 'inconclusive', reason: 'duplicate-parameter proof prerequisites are missing'};
  const controls = [];
  for (let index = 0; index < 2; index++) {
    const destination = `https://bypass-audit.invalid/${randomBytes(8).toString('hex')}-${index ? 'b' : 'a'}`;
    const headers = index ? {'cache-control': 'no-cache'} : {};
    const request = variant => read(spec, redirectPollutionUrl(spec.request.url, spec.origin,
      spec.parameter, destination, variant), spec.request.as, env, headers);
    const safe = await request('safe');
    const scalar = await request('external');
    const duplicate = await request(spec.order);
    const matched = redirectPollutionOracle(safe, scalar, duplicate, destination, spec.origin);
    controls.push({label: `duplicate-pair-${index + 1}`, safeStatus: safe.status,
      scalarStatus: scalar.status, duplicateStatus: duplicate.status, matched});
    if ([safe, scalar, duplicate].some(item => item.status == null || item.status === 429 ||
        item.status >= 500 || responseCached(item)))
      return {verdict: 'inconclusive', reason: 'redirect controls were unavailable or cached', controls};
    if (!matched) return {verdict: index ? 'inconclusive' : 'not_reproduced', controls};
  }
  return {verdict: 'confirmed', controls};
}

async function checkHostHeaderRedirect(spec, env) {
  if (spec.enabled !== true || spec.request?.as !== 'anonymous' || spec.request?.method !== 'GET')
    return {verdict: 'inconclusive', reason: 'Host-header proof prerequisites are missing'};
  const url = checkedUrl(spec, spec.request.url);
  const headers = {'cache-control': 'no-cache'};
  const control = await read(spec, url.href, 'anonymous', env, headers);
  const controls = [{label: 'normal-host', status: control.status, location: control.location}];
  if (control.status == null || control.status === 429 || control.status >= 500 || responseCached(control))
    return {verdict: 'inconclusive', reason: 'Host-header control was unavailable or cached', controls};
  if (![301, 302, 303, 307, 308].includes(control.status) ||
      !control.location || !URL.canParse(control.location, spec.origin) ||
      new URL(control.location, spec.origin).origin !== spec.origin)
    return {verdict: 'not_reproduced', controls};
  const first = await read(spec, url.href, 'anonymous', env,
    {...headers, host: HOST_HEADER_CANARIES[0]});
  controls.push({label: 'host-one', status: first.status, location: first.location});
  if (first.status == null || first.status === 429 || first.status >= 500 || responseCached(first))
    return {verdict: 'inconclusive', reason: 'First Host-header response was unavailable or cached', controls};
  if (!hostHeaderRedirectMatch(control, first, spec.origin, 0))
    return {verdict: 'not_reproduced', controls};
  const second = await read(spec, url.href, 'anonymous', env,
    {...headers, host: HOST_HEADER_CANARIES[1]});
  controls.push({label: 'host-two', status: second.status, location: second.location});
  if (second.status == null || second.status === 429 || second.status >= 500 || responseCached(second))
    return {verdict: 'inconclusive', reason: 'Second Host-header response was unavailable or cached', controls};
  return {verdict: hostHeaderRedirectOracle(control, first, second, spec.origin) ?
    'confirmed' : 'inconclusive', controls};
}

async function checkJwtUnsigned(spec, env) {
  if (spec.enabled !== true || spec.auth !== 'bearer' || spec.request?.as !== 'owner' ||
      spec.request?.method !== 'GET')
    return {verdict: 'inconclusive', reason: 'Unsigned-JWT proof prerequisites are missing'};
  const url = checkedUrl(spec, spec.request.url).href;
  if (!env[spec.identities?.owner]) await bootstrapCredential(spec, 'owner', env);
  const canaries = jwtUnsignedCanaries(env[spec.identities?.owner]);
  if (!canaries) return {verdict: 'inconclusive', reason: 'The owner credential is not a signed JWT'};
  const headers = {'cache-control': 'no-cache'};
  const owner = await read(spec, url, 'owner', env, headers);
  const anonymous = await read(spec, url, 'anonymous', env, headers);
  const controls = [{label: 'owner', status: owner.status, hash: owner.hash},
    {label: 'anonymous', status: anonymous.status, hash: anonymous.hash}];
  if (owner.status !== 200 || !(owner.json === true || /json|\+json/i.test(owner.type ?? '')) ||
      !cleanDenied(anonymous) || [owner, anonymous].some(item => responseCached(item) ||
        item.status === 429 || item.status >= 500))
    return {verdict: 'inconclusive', reason: 'The private JSON control changed', controls};
  const invalid = await read(spec, url, 'anonymous', env,
    {...headers, authorization: `Bearer ${canaries.invalidSignature}`});
  controls.push({label: 'invalid-signature', status: invalid.status, hash: invalid.hash});
  if (!cleanDenied(invalid) || responseCached(invalid))
    return {verdict: 'inconclusive', reason: 'The invalid-signature control was not denied', controls};
  const first = await read(spec, url, 'anonymous', env,
    {...headers, authorization: `Bearer ${canaries.first}`});
  controls.push({label: 'unsigned-one', status: first.status, hash: first.hash});
  if (first.status === 429 || first.status >= 500 || responseCached(first))
    return {verdict: 'inconclusive', reason: 'First unsigned-JWT response was unavailable or cached', controls};
  if (first.status !== 200 || first.hash !== owner.hash)
    return {verdict: 'not_reproduced', controls};
  const second = await read(spec, url, 'anonymous', env,
    {...headers, authorization: `Bearer ${canaries.second}`});
  controls.push({label: 'unsigned-two', status: second.status, hash: second.hash});
  if (second.status === 429 || second.status >= 500 || responseCached(second))
    return {verdict: 'inconclusive', reason: 'Second unsigned-JWT response was unavailable or cached', controls};
  return {verdict: jwtUnsignedOracle(owner, anonymous, invalid, first, second) ?
    'confirmed' : 'inconclusive', controls};
}

async function checkCommandOutput(spec, env) {
  if (!safeProbeParameter(spec.parameter) ||
      !['anonymous', 'owner', 'outsider', 'derived'].includes(spec.request?.as) ||
      spec.style !== 'semicolon-printf' || spec.enabled !== true)
    return {verdict: 'inconclusive', reason: 'command-output proof prerequisites are missing'};
  const withValue = value => {
    const url = new URL(spec.request.url, spec.origin);
    url.searchParams.set(spec.parameter, value);
    return url.href;
  };
  const controls = [];
  for (let index = 0; index < 2; index++) {
    const sample = commandOutputCanary(`bx${randomBytes(12).toString('hex')}`);
    const headers = index ? {'cache-control': 'no-cache'} : {};
    const control = await read(spec, withValue(sample.control), spec.request.as, env, headers);
    const executed = await read(spec, withValue(sample.payload), spec.request.as, env, headers);
    const matched = commandOutputOracle(control, executed, sample.marker);
    controls.push({label: `printf-pair-${index + 1}`, control: control.status,
      payload: executed.status, markerSeenInControl: control.body.includes(sample.marker), matched});
    if (control.status !== 200 || control.body.includes(sample.marker) ||
        [400, 401, 403, 429].includes(executed.status) || executed.status >= 500 ||
        executed.status >= 300 && executed.status < 400)
      return {verdict: 'inconclusive', reason: 'command-output control was unstable', controls};
    if ([control, executed].some(responseCached))
      return {verdict: 'inconclusive', reason: 'command-output response was cached', controls};
    if (!matched) return {verdict: index ? 'inconclusive' : 'not_reproduced', controls};
  }
  return {verdict: 'confirmed', controls};
}

async function checkHostsTraversal(spec, env) {
  if (!safeProbeParameter(spec.parameter) ||
      !['anonymous', 'owner', 'outsider', 'derived'].includes(spec.request?.as) ||
      spec.style !== 'etc-hosts-relative' || spec.enabled !== true)
    return {verdict: 'inconclusive', reason: 'file traversal proof prerequisites are missing'};
  const withValue = value => {
    const url = new URL(spec.request.url, spec.origin);
    url.searchParams.set(spec.parameter, value);
    return url.href;
  };
  const sample = hostsTraversalCanary();
  const control = await read(spec, withValue(sample.control), spec.request.as, env, {}, MODEL_RESPONSE_BYTES);
  const first = await read(spec, withValue(sample.first), spec.request.as, env,
    {'cache-control': 'no-cache'}, MODEL_RESPONSE_BYTES);
  const second = await read(spec, withValue(sample.second), spec.request.as, env,
    {'cache-control': 'no-cache'}, MODEL_RESPONSE_BYTES);
  const matched = hostsTraversalOracle(control, first, second);
  const controls = [{label: 'missing-file-control', status: control.status},
    {label: 'first-etc-hosts-read', status: first.status, signature: HOSTS_LINE.test(first.body)},
    {label: 'second-etc-hosts-read', status: second.status, signature: HOSTS_LINE.test(second.body),
      sameBody: first.hash === second.hash}];
  if ([control, first, second].some(item => item.status == null || item.status >= 500 ||
      item.status === 429 || responseCached(item)))
    return {verdict: 'inconclusive', reason: 'file traversal response was unavailable or cached', controls};
  return {verdict: matched ? 'confirmed' : 'not_reproduced', controls};
}

async function checkXxeHosts(spec, env) {
  const post = spec.kind === 'xxe-body-hosts';
  if ((!post && !safeProbeParameter(spec.parameter)) ||
      !['anonymous', 'owner', 'derived'].includes(spec.request?.as) ||
      spec.request?.method !== (post ? 'POST' : 'GET') ||
      post && (spec.request.as !== 'anonymous' ||
        spec.postPath !== new URL(spec.request.url, spec.origin).pathname ||
        new URL(spec.request.url, spec.origin).search) ||
      spec.style !== 'xml-entity-etc-hosts' || spec.enabled !== true)
    return {verdict: 'inconclusive', reason: 'XML entity proof prerequisites are missing'};
  const withValue = value => {
    if (post) return spec.request.url;
    const url = new URL(spec.request.url, spec.origin);
    url.searchParams.set(spec.parameter, value);
    return url.href;
  };
  const sample = xxeHostsCanaries();
  const controls = [];
  const readXml = async (value, label) => {
    let response;
    if (post) {
      const url = checkedUrl(spec, spec.request.url);
      const headers = {...await headerFor(spec, spec.request.as, env),
        'content-type': 'application/xml', 'cache-control': 'no-cache'};
      await pace(spec);
      response = await guardedRequest(url, {method: 'POST', headers, body: value,
        allowRemoteHttp: spec.allowRemoteHttp === true && spec.request.as === 'anonymous',
        maxBodyBytes: MODEL_RESPONSE_BYTES});
    } else response = await read(spec, withValue(value), spec.request.as, env,
      {'cache-control': 'no-cache'}, MODEL_RESPONSE_BYTES);
    controls.push({label, status: response.status, hostsLine: HOSTS_LINE.test(response.body ?? ''),
      cached: responseCached(response)});
    return response;
  };
  const control = await readXml(sample.control, 'literal-entity-control');
  if ([400, 422].includes(control.status) && !responseCached(control))
    return {verdict: 'not_reproduced', reason: 'XML DTDs were rejected', controls};
  if (control.status == null || control.status === 429 || control.status >= 500 ||
      responseCached(control) || control.status !== 200 ||
      !xxeLiteralControl(control, sample.marker))
    return {verdict: 'inconclusive', reason: 'XML literal-entity control was unavailable or unstable', controls};
  const first = await readXml(sample.first, 'first-external-entity');
  if ([400, 422].includes(first.status) && !responseCached(first))
    return {verdict: 'not_reproduced', reason: 'External entity input was rejected', controls};
  if (first.status == null || first.status === 429 || first.status >= 500 || responseCached(first))
    return {verdict: 'inconclusive', reason: 'First XML external-entity response was unavailable or cached', controls};
  if (first.status !== 200)
    return {verdict: 'inconclusive', reason: 'First XML external-entity response was not a successful parse', controls};
  if (!HOSTS_LINE.test(first.body ?? '')) return {verdict: 'not_reproduced', controls};
  const second = await readXml(sample.second, 'second-external-entity');
  if (second.status == null || second.status === 429 || second.status >= 500 || responseCached(second))
    return {verdict: 'inconclusive', reason: 'Second XML external-entity response was unavailable or cached', controls};
  return {verdict: xxeHostsOracle(control, first, second, sample.marker) ? 'confirmed' : 'inconclusive', controls};
}

async function checkSsrfLoopback(spec, env) {
  const target = new URL(spec.origin);
  const contentUse = spec.kind === 'remote-content-use';
  if (!localHost(target.hostname.replace(/^\[|\]$/g, '')) ||
      !validQueryParameter(spec.parameter))
    return {verdict: 'inconclusive', reason: 'loopback proof prerequisites are missing'};
  if (contentUse && (!spec.subject ||
      !['subject', 'observe'].includes(spec.assertion?.step) ||
      !['body', 'header'].includes(spec.assertion?.location) ||
      spec.assertion.step === 'observe' &&
        (!Array.isArray(spec.observe) ||
          !spec.observe[spec.assertion.index])))
    return {verdict: 'inconclusive', reason: 'selected content-use response is unavailable'};
  if (spec.subject && spec.targetEnvironment !== 'local')
    return {verdict: 'inconclusive', reason: 'audit-owned callback requires an authorized local target'};
  const subject = spec.subject;
  if (subject) {
    const read = ['GET', 'HEAD'].includes(subject.method);
    const write = ['POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'].includes(subject.method);
    const operation = (spec.reviewedOperations ?? []).find(item =>
      item.method === subject.method && item.path === subject.path &&
      item.placement === subject.placement);
    const postPath = subject.method === 'POST' &&
      spec.reviewedPostPaths?.[subject.placement]?.includes(subject.path);
    const observedRead = (spec.reviewedReadInputs ?? []).some(item =>
      item.path === subject.path && item.methods?.includes(subject.method));
    if (subject.path !== spec.request?.url || subject.key !== spec.parameter ||
        !['anonymous', 'owner', 'derived'].includes(spec.request?.as) ||
        !['query', 'header', 'json', 'form', 'xml'].includes(subject.placement) ||
        !Array.isArray(subject.fixedFields) || subject.fixedFields.length > 3 ||
        !subject.fixedFields.every(item => typeof item.field === 'string' &&
          typeof item.value === 'string' && item.field !== subject.key) ||
        !validModelHeaders(subject.headers ?? [], []) ||
        !((read && ['query', 'header'].includes(subject.placement) && observedRead) ||
          write && (postPath || operation) &&
          (spec.reviewedCallbackFields ?? operation?.fields ?? []).includes(subject.key)))
      return {verdict: 'inconclusive', reason: 'reviewed callback request is unavailable'};
  }
  const allowed = new Map(), hits = new Set(), waiting = new Map();
  const server = http.createServer((request, response) => {
    const token = /^\/bx-ssrf\/([0-9a-f]{24})$/.exec(new URL(request.url, 'http://127.0.0.1').pathname)?.[1];
    if (request.method === 'GET' && allowed.has(token)) {
      hits.add(token);
      waiting.get(token)?.();
      waiting.delete(token);
      response.writeHead(contentUse ? 200 : 204, contentUse ?
        {'content-type': 'text/plain; charset=utf-8',
          'cache-control': 'no-store'} : {});
    } else response.writeHead(404);
    response.end(request.method === 'GET' && allowed.has(token) && contentUse ?
      allowed.get(token) : undefined);
  });
  await new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(0, '127.0.0.1', resolve);
  });
  const port = server.address().port;
  const canary = () => {
    const token = randomBytes(12).toString('hex');
    const marker = contentUse ? `bxremote${randomBytes(16).toString('hex')}` : null;
    allowed.set(token, marker);
    const url = new URL(spec.request.url, spec.origin);
    const callbackUrl = `http://127.0.0.1:${port}/bx-ssrf/${token}`;
    if (!subject) url.searchParams.set(spec.parameter, callbackUrl);
    return {token, marker, url: url.href, callbackUrl};
  };
  const seen = token => hits.has(token) ? Promise.resolve(true) : new Promise(resolve => {
    const timer = setTimeout(() => {waiting.delete(token); resolve(false);}, 1200);
    waiting.set(token, () => {clearTimeout(timer); resolve(true);});
  });
  try {
    if (subject) {
      const prelude = spec.prelude ?? [];
      const observe = spec.observe ?? [];
      let derivedSession = null;
      const controls = [];
      const usesDerived = [subject, ...prelude, ...observe].some(step =>
        (step === subject ? spec.request.as : step.as ?? spec.request.as) === 'derived');
      if (usesDerived) {
        if (!spec.derivedLogin || !['bearer', 'cookie'].includes(spec.auth))
          return {verdict: 'inconclusive', reason: 'fresh derived login recipe is unavailable'};
        const loginSpec = {...spec, ...spec.derivedLogin, kind: 'model-auth-login',
          origin: spec.origin, include: spec.include, never: spec.never,
          targetEnvironment: spec.targetEnvironment, auth: spec.auth};
        const login = await checkModelAuthLogin(loginSpec, env,
          session => {derivedSession = session;});
        controls.push({label: 'fresh-login-boundary', verdict: login.verdict});
        if (login.verdict !== 'confirmed' || !derivedSession)
          return {verdict: login.verdict === 'not_reproduced' ?
            'not_reproduced' : 'inconclusive',
          reason: 'fresh derived login failed', controls};
      }
      const issue = async (step, value, label, captures, to, index) => {
        if (step !== subject && !['GET', 'HEAD'].includes(step.method) &&
            !reviewedSequenceOperation(spec, step)) return null;
        const bound = sequenceTargetBindings(spec, to, index, captures);
        if (bound.some(item => item.value == null)) return null;
        const path = bound.filter(item => item.binding.placement === 'path')
          .reduce((current, item) => current && boundSequencePath(current,
            item.binding, item.value), step.path);
        if (!path) return null;
        const url = checkedUrl(spec, path);
        const identity = step === subject ? spec.request.as : step.as ?? spec.request.as;
        const headers = {...(identity === 'derived' ?
          sessionHeaders(spec.auth, derivedSession) :
          await headerFor(spec, identity, env, url)),
          ...Object.fromEntries((step.headers ?? []).map(item => [item.name, item.value])),
          'cache-control': 'no-cache'};
        let body;
        const write = !['GET', 'HEAD'].includes(step.method);
        const submittedValue = bound.find(item => item.binding.placement !== 'path' &&
          item.binding.key === step.key)?.value ??
          (step === subject ? value : step.value);
        if (step === subject || write) {
          if (step.placement === 'query') {
            for (const item of step.fixedFields ?? []) url.searchParams.set(item.field, item.value);
            url.searchParams.set(step.key, submittedValue);
            for (const item of bound) if (item.binding.placement !== 'path')
              url.searchParams.set(item.binding.key, item.value);
          } else if (step.placement === 'header') headers[step.key] = submittedValue;
          else {
            const fields = {...Object.fromEntries((step.fixedFields ?? []).map(item =>
              [item.field, item.value])), ...Object.fromEntries(bound
              .filter(item => item.binding.placement !== 'path')
              .map(item => [item.binding.key, item.value]))};
            if (step.placement === 'json') {
              headers['content-type'] = step.contentType ?? 'application/json';
              body = sequenceJsonBody(fields, step.key, submittedValue,
                step.valueEncoding);
            } else if (step.placement === 'form') {
              headers['content-type'] = step.contentType ?? 'application/x-www-form-urlencoded';
              body = new URLSearchParams({...fields, [step.key]: submittedValue}).toString();
            } else {
              headers['content-type'] = step.contentType ?? 'application/xml';
              body = step.bodyTemplate.replace('{{input}}', submittedValue);
            }
          }
        } else for (const item of bound) {
          if (item.binding.placement !== 'path')
            url.searchParams.set(item.binding.key, item.value);
        }
        checkedUrl(spec, url.href);
        await pace(spec);
        const response = await guardedRequest(url, {method: step.method, headers, body,
          maxBodyBytes: MODEL_RESPONSE_BYTES});
        const record = {label, status: response.status, cached: responseCached(response)};
        controls.push(record);
        return {response, record};
      };
      const plain = spec.controlValue ?? 'audit-control';
      const phase = async (value, label, token = null) => {
        const captures = new Map();
        for (const [index, step] of prelude.entries()) {
          const read = await issue(step, value, `${label}-prelude-${index}`,
            captures, 'prelude', index);
          const setupSucceeded = ['GET', 'HEAD'].includes(step.method) ?
            read?.record.status === 200 : read?.record.status >= 200 &&
              read?.record.status < 300;
          if (!read || !setupSucceeded || read.record.cached)
            return {ok: false, reason: 'callback prelude was unavailable or cached'};
          for (const [at, binding] of sequenceBindings(spec).entries()) {
            if (binding.from !== index) continue;
            const captured = captureSequenceScalar(read.response.body, binding.pointer);
            controls.push({label: `${label}-capture-${at}`, pointer: binding.pointer,
              present: captured !== null, length: captured?.length ?? 0});
            if (captured === null)
              return {ok: false, reason: 'callback binding was unavailable'};
            captures.set(at, captured);
          }
        }
        const sent = await issue(subject, value, label, captures, 'subject', 0);
        if (!sent || sent.record.status == null || sent.record.status === 429 ||
            sent.record.status >= 500 || sent.record.cached)
          return {ok: false, reason: 'callback subject response was unavailable or cached'};
        const observed = [];
        for (const [index, step] of observe.entries()) {
          const read = await issue(step, value, `${label}-observe-${index}`,
            captures, 'observe', index);
          if (!read || read.record.status == null || read.record.status === 429 ||
              read.record.status >= 500 || read.record.cached)
            return {ok: false, reason: 'callback observe response was unavailable or cached'};
          observed.push(read);
        }
        if (token) sent.record.callback = await seen(token);
        const selected = contentUse ? spec.assertion.step === 'subject' ?
          sent.response : observed[spec.assertion.index]?.response : null;
        const selectedText = contentUse ? spec.assertion.location === 'body' ?
          String(selected?.body ?? '') :
          String(selected?.headers?.[String(spec.assertion.name ?? '').toLowerCase()] ?? '') : '';
        return {ok: true, hit: sent.record.callback ?? false, selectedText};
      };
      const baseline = await phase(plain, 'plain-control');
      if (!baseline.ok) return {verdict: 'inconclusive', reason: baseline.reason, controls};
      const first = canary();
      const firstResult = await phase(first.callbackUrl, 'first-callback', first.token);
      if (!firstResult.ok) return {verdict: 'inconclusive', reason: firstResult.reason, controls};
      const repeat = await phase(plain, 'repeat-control');
      if (!repeat.ok) return {verdict: 'inconclusive', reason: repeat.reason, controls};
      const second = canary();
      const secondResult = await phase(second.callbackUrl, 'second-callback', second.token);
      if (!secondResult.ok) return {verdict: 'inconclusive', reason: secondResult.reason, controls};
      const contentIsolated = !contentUse ||
        !baseline.selectedText.includes(first.marker) &&
        !baseline.selectedText.includes(second.marker) &&
        firstResult.selectedText.includes(first.marker) &&
        !firstResult.selectedText.includes(second.marker) &&
        !repeat.selectedText.includes(first.marker) &&
        !repeat.selectedText.includes(second.marker) &&
        secondResult.selectedText.includes(second.marker) &&
        !secondResult.selectedText.includes(first.marker);
      if (contentUse) {
        const firstRecord = controls.find(item => item.label === 'first-callback');
        const secondRecord = controls.find(item => item.label === 'second-callback');
        firstRecord.contentUsed = firstResult.selectedText.includes(first.marker);
        secondRecord.contentUsed = secondResult.selectedText.includes(second.marker);
      }
      return {verdict: firstResult.hit && secondResult.hit && contentIsolated ?
        'confirmed' : 'not_reproduced', controls};
    }
    const firstCanary = canary();
    const first = await read(spec, firstCanary.url, 'anonymous', env);
    const firstHit = await seen(firstCanary.token);
    const controls = [{label: 'first-canary', status: first.status, callback: firstHit}];
    if (!firstHit) return {verdict: first.status >= 500 || first.status === 429 ? 'inconclusive' : 'not_reproduced', controls};
    const secondCanary = canary();
    const second = await read(spec, secondCanary.url, 'anonymous', env, {'cache-control': 'no-cache'});
    const secondHit = await seen(secondCanary.token);
    controls.push({label: 'second-canary', status: second.status, callback: secondHit});
    return {verdict: secondHit ? 'confirmed' : 'inconclusive', controls};
  } finally {await new Promise(resolve => server.close(resolve));}
}

async function checkPublicPrivateKey(spec, env) {
  if (spec.request?.method !== 'GET' || spec.request?.as !== 'anonymous' ||
      !/^sha256:[0-9a-f]{64}$/.test(spec.publicKeyFingerprint))
    return {verdict: 'inconclusive', reason: 'public private-key proof prerequisites are missing'};
  const controls = [];
  for (let index = 0; index < 2; index++) {
    const response = await read(spec, spec.request.url, 'anonymous', env,
      index ? {'cache-control': 'no-cache'} : {}, MODEL_RESPONSE_BYTES);
    controls.push({label: index ? 'second-anonymous-read' : 'first-anonymous-read',
      status: response.status, keyPresent: publicPrivateKeyFingerprints(response.body)
        .includes(spec.publicKeyFingerprint), cached: responseCached(response)});
  }
  if (controls.some(item => item.status == null || item.status >= 500 || item.status === 429 || item.cached) ||
      controls[0].status !== controls[1].status)
    return {verdict: 'inconclusive', reason: 'public asset responses were unavailable or unstable', controls};
  if (controls.every(item => item.status === 200 && item.keyPresent)) return {verdict: 'confirmed', controls};
  if (controls.every(item => !item.keyPresent)) return {verdict: 'not_reproduced', controls};
  return {verdict: 'inconclusive', reason: 'key presence changed between reads', controls};
}

async function checkPublicCredential(spec, env) {
  if (spec.request?.method !== 'GET' || spec.request?.as !== 'anonymous' ||
      !PUBLIC_CREDENTIAL_PATTERNS.some(([name]) => name === spec.credentialKind) ||
      !/^sha256:[0-9a-f]{64}$/.test(spec.credentialFingerprint))
    return {verdict: 'inconclusive', reason: 'public credential proof prerequisites are missing'};
  const controls = [];
  for (let index = 0; index < 2; index++) {
    const response = await read(spec, spec.request.url, 'anonymous', env,
      {'cache-control': 'no-cache'}, MODEL_RESPONSE_BYTES);
    const present = publicCredentialFingerprints(response.body).some(item =>
      item.name === spec.credentialKind && item.fingerprint === spec.credentialFingerprint);
    controls.push({label: index ? 'second-anonymous-read' : 'first-anonymous-read',
      status: response.status, credentialPresent: present, cached: responseCached(response)});
  }
  if (controls.some(item => item.status == null || item.status >= 500 || item.status === 429 || item.cached) ||
      controls[0].status !== controls[1].status)
    return {verdict: 'inconclusive', reason: 'public asset responses were unavailable or unstable', controls};
  if (controls.every(item => item.status === 200 && item.credentialPresent)) return {verdict: 'confirmed', controls};
  if (controls.every(item => !item.credentialPresent)) return {verdict: 'not_reproduced', controls};
  return {verdict: 'inconclusive', reason: 'credential presence changed between reads', controls};
}

function graphqlData(response, field) {
  if (response?.status !== 200 || !response.json) return null;
  try {return JSON.parse(response.body)?.data?.[field] ?? null;} catch {return null;}
}

function graphqlRows(response, field) {
  const value = graphqlData(response, field);
  return Array.isArray(value) && value.every(object) ? value : null;
}

function graphqlObject(response, field, id, ownerField, ownerPrincipal) {
  const value = graphqlData(response, field);
  return object(value) && String(value.id) === id && String(value[ownerField]) === ownerPrincipal;
}

function graphqlDenied(response, field) {
  if (denied(response?.status)) return true;
  if (response?.status !== 200 || !response.json) return false;
  try {
    const body = JSON.parse(response.body);
    return body?.data?.[field] == null && (!Array.isArray(body.errors) || body.errors.length === 0 ||
      body.errors.every(error => ['FORBIDDEN', 'UNAUTHENTICATED', 'NOT_FOUND'].includes(error?.extensions?.code)));
  } catch {return false;}
}

async function checkGraphqlBola(spec, env) {
  const info = spec.graphql;
  const field = /^[_A-Za-z][_A-Za-z0-9]{0,79}$/;
  if (!info || !field.test(info.listField) || !field.test(info.itemField) ||
      !['ownerId', 'userId', 'owner_uid'].includes(info.ownerField) ||
      !/^[A-Za-z0-9_.@-]{1,96}$/.test(info.recordId) ||
      typeof info.ownerPrincipal !== 'string' ||
      spec.control?.as !== 'owner' || spec.request?.as !== 'outsider' ||
      spec.control.url !== spec.request.url)
    return {verdict: 'inconclusive', reason: 'GraphQL object proof prerequisites are missing'};
  const ownerList = await read(spec, info.listUrl, 'owner', env);
  const outsiderList = await read(spec, info.listUrl, 'outsider', env);
  const anonymousList = await read(spec, info.listUrl, 'anonymous', env);
  const O = await read(spec, spec.control.url, 'owner', env);
  const T = await read(spec, spec.request.url, 'outsider', env);
  const A = await read(spec, spec.request.url, 'anonymous', env);
  const controls = [
    {label: 'owner-list', status: ownerList.status, hash: ownerList.hash},
    {label: 'outsider-list', status: outsiderList.status, hash: outsiderList.hash},
    {label: 'anonymous-list', status: anonymousList.status, hash: anonymousList.hash},
    {label: 'owner-item', status: O.status, hash: O.hash},
    {label: 'outsider-item', status: T.status, hash: T.hash},
    {label: 'anonymous-item', status: A.status, hash: A.hash},
  ];
  if ([ownerList, outsiderList, anonymousList, O, T, A].some(item => item.status === 429 ||
      item.status >= 500 || item.status >= 300 && item.status < 400 || item.headers?.age != null ||
      /HIT/i.test(item.headers?.['x-cache'] ?? '')))
    return {verdict: 'inconclusive', reason: 'A GraphQL proof control was unstable or cached', controls};
  const ownerListed = graphqlRows(ownerList, info.listField)?.some(row =>
    String(row.id) === info.recordId && String(row[info.ownerField]) === info.ownerPrincipal);
  const outsiderListed = graphqlRows(outsiderList, info.listField)?.some(row => String(row.id) === info.recordId);
  const anonymousListed = graphqlRows(anonymousList, info.listField)?.some(row => String(row.id) === info.recordId);
  if (!ownerListed || outsiderListed || anonymousListed ||
      !graphqlObject(O, info.itemField, info.recordId, info.ownerField, info.ownerPrincipal))
    return {verdict: 'inconclusive', reason: 'The owner-only object control changed', controls};
  if (graphqlObject(A, info.itemField, info.recordId, info.ownerField, info.ownerPrincipal))
    return {verdict: 'inconclusive', reason: 'The object is anonymously readable', controls};
  if (graphqlObject(T, info.itemField, info.recordId, info.ownerField, info.ownerPrincipal))
    return {verdict: 'confirmed', controls};
  return {verdict: graphqlDenied(T, info.itemField) ? 'not_reproduced' : 'inconclusive', controls};
}

/** Replay the recorded requests. Only statuses, hashes and the deterministic verdict leave this function. */
export async function check(spec, env = process.env, replay = null) {
  if (replayBudget.getStore()) return checkWithinBudget(spec, env, replay);
  return replayBudget.run({requests: 0, signal: AbortSignal.timeout(MAX_PROOF_MS)},
    () => checkWithinBudget(spec, env, replay));
}

async function checkWithinBudget(spec, env, replay) {
  try {
    env = {...env};
    if (spec.expiresAt && Date.parse(spec.expiresAt) <= Date.now()) throw Error('Proof scope has expired.');
    const derivedAccess = spec.kind === 'model-access-boundary' &&
      spec.protectedAs === 'derived';
    if (replay !== DERIVED_SESSION_REPLAY && (derivedAccess ||
        spec.request?.as === 'derived' &&
        ['xss-reflected', 'html-injection', 'ssti-arithmetic', 'crlf-header',
          'command-output', 'path-traversal-hosts', 'xxe-hosts',
          'model-differential'].includes(spec.kind))) {
      if (!spec.derivedLogin || !['bearer', 'cookie'].includes(spec.auth))
        return {verdict: 'inconclusive',
        reason: 'Fresh derived login recipe is unavailable'};
      let session = null;
      const loginSpec = {...spec, ...spec.derivedLogin, kind: 'model-auth-login',
        origin: spec.origin, include: spec.include, never: spec.never,
        targetEnvironment: spec.targetEnvironment, auth: spec.auth};
      const login = await checkModelAuthLogin(loginSpec, env,
        value => { session = value; });
      const loginControl = {label: 'fresh-login-boundary', verdict: login.verdict,
        checks: login.controls};
      if (login.verdict !== 'confirmed' || !session) return {
        verdict: login.verdict === 'not_reproduced' ? 'not_reproduced' : 'inconclusive',
        reason: 'Fresh derived login did not establish a session', controls: [loginControl]};
      const tokenEnv = `BX_DERIVED_${randomBytes(8).toString('hex')}`;
      const result = await check({...spec, derivedLogin: null,
        identities: {...spec.identities, [derivedAccess ? 'owner' : 'derived']: tokenEnv}},
      {...env, [tokenEnv]: session}, DERIVED_SESSION_REPLAY);
      return {...result, controls: [loginControl, ...(result.controls ?? [])]};
    }
    if (spec.kind === 'exposure') {
      const rangedFile = spec.ranged === true || ['KeePass KDBX header', 'SQLite database header', 'ZIP archive header',
        'PEM private key', 'SQL dump statements', 'environment key-value lines'].includes(spec.signature);
      const rangeHeader = spec.rangeHeader ?? 'bytes=0-63';
      const rangeBytes = rangeHeader === 'bytes=0-4095' ? 8192 : 128;
      const response = await read(spec, spec.request.url, 'anonymous', env,
        rangedFile ? {range: rangeHeader} : spec.acceptHtml ? {accept: 'text/html'} : {},
        rangedFile ? rangeBytes : MODEL_RESPONSE_BYTES);
      if (['directory index', 'KeePass KDBX header', 'SQLite database header',
        'ZIP archive header', 'PEM private key', 'SQL dump statements',
        'environment key-value lines'].includes(spec.signature)) {
        const fresh = await read(spec, spec.request.url, 'anonymous', env,
          rangedFile ? {'cache-control': 'no-cache', range: rangeHeader} :
            {'cache-control': 'no-cache', ...(spec.acceptHtml ? {accept: 'text/html'} : {})},
          rangedFile ? rangeBytes : MODEL_RESPONSE_BYTES);
        const path = new URL(spec.request.url).pathname;
        const links = item => {
          if (item.status !== 200) return [];
          if (/json/i.test(item.type)) {
            let names;
            try {names = JSON.parse(item.body);} catch {return [];}
            if (!Array.isArray(names) || names.length < 3 || names.length > 200 ||
                !names.every(name => typeof name === 'string' && /^[A-Za-z0-9_.-]{1,120}$/.test(name)) ||
                names.filter(name => /\.[A-Za-z0-9]{1,10}$/.test(name)).length < 2) return [];
            return names.map(name => new URL(name,
              new URL(path.endsWith('/') ? path : `${path}/`, spec.origin)).pathname);
          }
          if (!/html/i.test(item.type) ||
              !/<title>\s*(?:index of|listing directory)\b/i.test(item.body)) return [];
          return [...item.body.matchAll(/<a\b[^>]*\bhref\s*=\s*["']([^"']+)["']/gi)]
            .map(match => {try {return new URL(match[1],
              new URL(path.endsWith('/') ? path : `${path}/`, spec.origin));} catch {return null;}})
            .filter(url => url && url.origin === spec.origin &&
              url.pathname.startsWith(path.endsWith('/') ? path : `${path}/`) &&
              url.pathname !== path && !url.search).map(url => url.pathname);
        };
        const matches = item => (rangedFile ? item.status === 200 || item.status === 206 &&
          /^bytes 0-\d{1,4}\/\d+$/i.test(item.headers?.['content-range'] ?? '') :
          item.status === 200) && (
          spec.signature === 'directory index' ? links(item).length > 0 :
          spec.signature === 'KeePass KDBX header' ? /^03d9a29a67fb4bb5/i.test(item.prefixHex ?? '') :
          spec.signature === 'SQLite database header' ? /^53514c69746520666f726d6174203300/i.test(item.prefixHex ?? '') :
          spec.signature === 'ZIP archive header' ? /^504b0304/i.test(item.prefixHex ?? '') :
          spec.signature === 'PEM private key' ? /^-----BEGIN (?:[A-Z]+ )*PRIVATE KEY-----/m.test(item.body) :
          spec.signature === 'SQL dump statements' ? /(?:^|\n)\s*(?:CREATE TABLE|INSERT INTO)\s+/i.test(item.body) :
          !/html/i.test(item.type) && /(?:^|\n)\s*[A-Za-z_][A-Za-z0-9_]*\s*=\s*\S+/m.test(item.body));
        const stableLinks = spec.signature !== 'directory index' ||
          links(response).some(link => links(fresh).includes(link));
        const control = spec.signature === 'directory index' ?
          await read(spec, new URL(`__bypass_absent_${randomBytes(6).toString('hex')}`,
            new URL(path.endsWith('/') ? path : `${path}/`, spec.origin)).href,
          'anonymous', env, spec.acceptHtml ? {accept: 'text/html'} : {}) : null;
        const distinctControl = !control || control.status < 500 &&
          control.hash !== response.hash && !matches(control);
        return {verdict: matches(response) && matches(fresh) && stableLinks && distinctControl ? 'confirmed' :
          denied(response.status) && denied(fresh.status) ? 'not_reproduced' : 'inconclusive',
          controls: [response, fresh, ...(control ? [control] : [])].map((item, index) => ({label: index === 2 ? 'missing-child' : index ? 'fresh' : 'anonymous',
            status: item.status, signatureMatched: matches(item), hash: item.hash}))};
      }
      if (spec.signature === 'metrics exposition') {
        const fresh = await read(spec, spec.request.url, 'anonymous', env, {'cache-control': 'no-cache'});
        const matches = item => {
          if (item.status !== 200 || !/^(?:text\/plain|application\/(?:openmetrics-text|json))/i.test(item.type)) return false;
          if (item.json) {
            try {return Array.isArray(JSON.parse(item.body)?.names);} catch {return false;}
          }
          const help = new Set([...item.body.matchAll(/^# HELP ([A-Za-z_:][A-Za-z0-9_:]*)\b/gm)].map(match => match[1]));
          return [...item.body.matchAll(/^# TYPE ([A-Za-z_:][A-Za-z0-9_:]*)\b/gm)]
            .some(match => help.has(match[1]));
        };
        return {verdict: matches(response) && matches(fresh) ? 'confirmed' :
          denied(response.status) && denied(fresh.status) ? 'not_reproduced' : 'inconclusive',
          controls: [response, fresh].map((item, index) => ({label: index ? 'fresh' : 'anonymous',
            status: item.status, signatureMatched: matches(item), hash: item.hash}))};
      }
      if (rangedFile) {
        const fresh = await read(spec, spec.request.url, 'anonymous', env,
          {'cache-control': 'no-cache', range: rangeHeader}, rangeBytes);
        const valid = item => item.status === 200 || item.status === 206 &&
          /^bytes 0-\d{1,4}\/\d+$/i.test(item.headers?.['content-range'] ?? '');
        return {verdict: valid(response) && valid(fresh) &&
          response.hash === spec.expectedHash && fresh.hash === spec.expectedHash ? 'confirmed' :
          denied(response.status) && denied(fresh.status) ? 'not_reproduced' : 'inconclusive',
          controls: [response, fresh].map((item, index) => ({label: index ? 'fresh' : 'anonymous',
            status: item.status, signatureMatched: valid(item) && item.hash === spec.expectedHash,
            hash: item.hash}))};
      }
      return {verdict: response.status === 200 && response.hash === spec.expectedHash ? 'confirmed' :
        denied(response.status) ? 'not_reproduced' : 'inconclusive',
        controls: [{label: 'anonymous', status: response.status, hash: response.hash}]};
    }
    if (spec.kind === 'anonymous-credential-data') {
      if (spec.request?.as !== 'anonymous' || spec.request?.method !== 'GET' ||
          typeof spec.field !== 'string')
        return {verdict: 'inconclusive', reason: 'Anonymous credential proof controls are missing'};
      const first = await read(spec, spec.request.url, 'anonymous', env,
        {'cache-control': 'no-cache'});
      const second = await read(spec, spec.request.url, 'anonymous', env,
        {'cache-control': 'no-cache'});
      const controls = [{label: 'anonymous-one', status: first.status, hash: first.hash},
        {label: 'anonymous-two', status: second.status, hash: second.hash}];
      if ([first, second].some(item => item.status == null || item.status >= 500 || item.status === 429 ||
          responseCached(item) || item.status >= 300 && item.status < 400))
        return {verdict: 'inconclusive', reason: 'Anonymous JSON controls were unavailable or cached', controls};
      if ([first, second].every(item => denied(item.status))) return {verdict: 'not_reproduced', controls};
      if (first.status !== second.status || first.status !== 200 || !first.json || !second.json)
        return {verdict: 'inconclusive', reason: 'Anonymous JSON controls changed', controls};
      const one = anonymousCredentialExposure(first.body), two = anonymousCredentialExposure(second.body);
      return {verdict: one?.field === spec.field && two?.field === spec.field ? 'confirmed' :
        !one && !two ? 'not_reproduced' : 'inconclusive', controls};
    }
    if (spec.kind === 'derived-private-read') {
      return {verdict: 'inconclusive',
        reason: 'A self-declared private field does not establish an independent access policy or denial control'};
    }
    if (spec.kind === 'open-redirect') {
      const as = spec.request?.as ?? 'anonymous';
      if (!['anonymous', 'owner'].includes(as)) return {verdict: 'inconclusive',
        reason: 'redirect proof identity is invalid'};
      const response = await read(spec, spec.request.url, as, env);
      const confirmed = [301, 302, 303, 307, 308].includes(response.status) &&
        response.location && new URL(response.location, spec.origin).href === spec.expectedLocation;
      return {verdict: confirmed ? 'confirmed' : response.status < 500 && response.status !== 429 ? 'not_reproduced' : 'inconclusive',
        controls: [{label: as, status: response.status, location: response.location}]};
    }
    if (spec.kind === 'cors-reflection') {
      if (spec.auth !== 'cookie' || spec.origins?.length !== 2) return {verdict: 'inconclusive', reason: 'cookie controls missing'};
      const O = await read(spec, spec.request.url, 'owner', env);
      const A = await read(spec, spec.request.url, 'anonymous', env);
      const C1 = await read(spec, spec.request.url, 'owner', env, {origin: spec.origins[0]});
      const C2 = await read(spec, spec.request.url, 'owner', env, {origin: spec.origins[1]});
      const controls = [{label: 'owner', status: O.status, hash: O.hash},
        {label: 'anonymous', status: A.status},
        {label: 'origin-one', status: C1.status, corsOrigin: C1.corsOrigin, corsCredentials: C1.corsCredentials},
        {label: 'origin-two', status: C2.status, corsOrigin: C2.corsOrigin, corsCredentials: C2.corsCredentials}];
      if (O.status !== 200 || !denied(A.status) || [O, A, C1, C2].some(item => item.status >= 500 || item.status === 429))
        return {verdict: 'inconclusive', controls};
      const valid = (item, origin) => item.status === 200 && item.hash === O.hash &&
        item.corsOrigin === origin && String(item.corsCredentials).toLowerCase() === 'true';
      return {verdict: valid(C1, spec.origins[0]) && valid(C2, spec.origins[1]) ? 'confirmed' : 'not_reproduced', controls};
    }
    if (['ssrf-loopback', 'remote-content-use'].includes(spec.kind))
      return await checkSsrfLoopback(spec, env);
    if (spec.kind === 'public-private-key') return await checkPublicPrivateKey(spec, env);
    if (spec.kind === 'public-api-credential') return await checkPublicCredential(spec, env);
    if (spec.kind === 'host-header-redirect') return await checkHostHeaderRedirect(spec, env);
    if (spec.kind === 'jwt-unsigned') return await checkJwtUnsigned(spec, env);
    if (spec.kind === 'crlf-header') return await checkCrlfHeader(spec, env);
    if (spec.kind === 'xss-dom-fragment') return await checkDomXss(spec, env);
    if (spec.kind === 'xss-reflected') return await checkReflectedXss(spec, env);
    if (spec.kind === 'xss-stored') return await checkStoredXss(spec, env);
    if (spec.kind === 'html-injection') return await checkHtmlInjection(spec, env);
    if (spec.kind === 'ssti-arithmetic') return await checkSstiArithmetic(spec, env);
    if (spec.kind === 'model-differential') return await checkModelDifferential(spec, env);
    if (spec.kind === 'model-json-differential') return await checkModelJsonDifferential(spec, env);
    if (spec.kind === 'model-cookie-access') return await checkModelCookieAccess(spec);
    if (spec.kind === 'model-raw-boundary') return await checkModelRawBoundary(spec, env);
    if (['model-http-sequence', 'model-browser-execution'].includes(spec.kind))
      return await checkModelHttpSequence(spec, env);
    if (spec.kind === 'model-state-change') return await checkModelStateChange(spec, env);
    if (spec.kind === 'model-access-boundary') return await checkModelAccessBoundary(spec, env);
    if (spec.kind === 'public-session-token') return await checkPublicSessionToken(spec, env);
    if (spec.kind === 'model-auth-login') return await checkModelAuthLogin(spec, env);
    if (spec.kind === 'sql-boolean') return await checkSqlBoolean(spec, env);
    if (spec.kind === 'nosql-operator-bypass') return await checkNosqlOperator(spec, env);
    if (spec.kind === 'http-parameter-pollution') return await checkRedirectPollution(spec, env);
    if (spec.kind === 'command-output') return await checkCommandOutput(spec, env);
    if (spec.kind === 'path-traversal-hosts') return await checkHostsTraversal(spec, env);
    if (spec.kind === 'xxe-hosts' || spec.kind === 'xxe-body-hosts')
      return await checkXxeHosts(spec, env);
    if (spec.kind === 'graphql-bola') return await checkGraphqlBola(spec, env);
    if (spec.kind === 'chain-anonymous-list-item') {
      const ownerList = await read(spec, spec.listUrl, 'owner', env);
      const anonymousList = await read(spec, spec.listUrl, 'anonymous', env);
      const ownerItem = await read(spec, spec.itemUrl, 'owner', env);
      const anonymousItem = await read(spec, spec.itemUrl, 'anonymous', env);
      const outsiderItem = await read(spec, spec.itemUrl, 'outsider', env);
      const controls = [{label: 'owner-list', status: ownerList.status, hash: ownerList.hash},
        {label: 'anonymous-list', status: anonymousList.status, hash: anonymousList.hash},
        {label: 'owner-item', status: ownerItem.status, hash: ownerItem.hash},
        {label: 'anonymous-item', status: anonymousItem.status, hash: anonymousItem.hash},
        {label: 'outsider-item', status: outsiderItem.status}];
      if ([ownerList, anonymousList, ownerItem, anonymousItem, outsiderItem].some(item =>
        item.status >= 500 || item.status === 429 || item.status >= 300 && item.status < 400 ||
        responseCached(item)) || ownerList.status !== 200 || ownerItem.status !== 200 ||
        !ownerList.json || !ownerItem.json || !ownerList.ids.includes(spec.itemId) ||
        !ownerItem.ids.includes(spec.itemId))
        return {verdict: 'inconclusive', controls};
      const listed = anonymousList.status === 200 && anonymousList.json &&
        anonymousList.ids.includes(spec.itemId);
      const item = anonymousItem.status === 200 && anonymousItem.json &&
        anonymousItem.ids.includes(spec.itemId) &&
        (anonymousItem.hash === ownerItem.hash ||
          anonymousItem.fields.join(',') === ownerItem.fields.join(','));
      const confirmed = listed && item && cleanDenied(outsiderItem);
      const fixed = cleanDenied(anonymousList) || cleanDenied(anonymousItem) ||
        anonymousList.status === 200 && !listed;
      return {verdict: confirmed ? 'confirmed' : fixed ? 'not_reproduced' : 'inconclusive', controls};
    }
    if (spec.kind === 'chain-list-item') {
      const list = await read(spec, spec.listUrl, 'outsider', env);
      const O = await read(spec, spec.itemUrl, 'owner', env);
      const T = await read(spec, spec.itemUrl, 'outsider', env);
      const A = await read(spec, spec.itemUrl, 'anonymous', env);
      const controls = [{label: 'outsider-list', status: list.status, hash: list.hash},
        {label: 'owner-item', status: O.status, hash: O.hash},
        {label: 'outsider-item', status: T.status, hash: T.hash},
        {label: 'anonymous-item', status: A.status, hash: A.hash}];
      if ([list, O, T, A].some(item => item.status >= 500 || item.status === 429 ||
        (item.status >= 300 && item.status < 400) || responseCached(item)) ||
        O.status !== 200 || !O.json)
        return {verdict: 'inconclusive', controls};
      const listed = list.status === 200 && list.json && list.ids.includes(spec.itemId);
      const item = T.status === 200 && T.json && T.ids.includes(spec.itemId) &&
        (T.hash === O.hash || T.fields.join(',') === O.fields.join(','));
      const confirmed = listed && item && cleanDenied(A);
      const fixed = list.status === 200 && !listed || cleanDenied(list) || cleanDenied(T);
      return {verdict: confirmed ? 'confirmed' : fixed ? 'not_reproduced' : 'inconclusive', controls};
    }
    const O = await read(spec, spec.control.url, spec.control.as, env);
    const T = await read(spec, spec.request.url, spec.request.as, env);
    const A = spec.request.as === 'anonymous' ? T : await read(spec, spec.request.url, 'anonymous', env);
    const controls = [{label: spec.control.as, status: O.status, hash: O.hash},
      {label: spec.request.as, status: T.status, hash: T.hash}, {label: 'anonymous', status: A.status, hash: A.hash}];
    if (O.status !== 200 || !O.json || [O, T, A].some(item => item.status >= 500 || item.status === 429 ||
      (item.status >= 300 && item.status < 400))) return {verdict: 'inconclusive', controls};
    const owner = new Set(spec.ownerOnlyIds ?? []);
    const hasOwner = item => item.ids.some(id => owner.has(id));
    const sameResource = item => item.status === 200 && item.json && (item.hash === O.hash ||
      (hasOwner(item) && hasOwner(O) && item.fields.join(',') === O.fields.join(',')));
    const ownershipHash = (response, field) => {
      let json;
      try {json = JSON.parse(response.body);} catch {return null;}
      if (!object(json)) return null;
      const values = [json, ...Object.values(json).filter(object)];
      const record = values.find(value => Object.hasOwn(value, field));
      const scalar = record?.[field];
      return ['string', 'number', 'boolean'].includes(typeof scalar) ?
        sha(typeof scalar === 'string' ? scalar : JSON.stringify(scalar)) : null;
    };
    const boundary = spec.accountBoundary;
    const boundaryReplayed = !boundary || O.hash !== T.hash &&
      boundary.sensitiveFields.some(field => O.fields.includes(field)) &&
      ownershipHash(O, boundary.field) === boundary.ownerHash &&
      ownershipHash(T, boundary.field) === boundary.outsiderHash;
    const oneAccountBoundaryReplayed = !spec.oneAccountBoundary ||
      ownershipHash(O, spec.oneAccountBoundary.field) === spec.oneAccountBoundary.ownerHash &&
      ownershipHash(A, spec.oneAccountBoundary.field) === spec.oneAccountBoundary.ownerHash;
    let confirmed = false, fixed = false;
    switch (spec.kind) {
      case 'idor': case 'nested-idor':
        confirmed = sameResource(T);
        fixed = denied(T.status);
        break;
      case 'missing-auth':
        confirmed = boundaryReplayed && (sameResource(A) || (A.status === 200 && hasOwner(A))) &&
          oneAccountBoundaryReplayed &&
          (spec.oneAccountPrivateFields ?? []).every(field => O.fields.includes(field) && A.fields.includes(field));
        fixed = denied(A.status) || (spec.oneAccountPrivateFields?.length > 0 &&
          spec.oneAccountPrivateFields.some(field => !O.fields.includes(field) || !A.fields.includes(field))) ||
          (!!spec.oneAccountBoundary && !oneAccountBoundaryReplayed);
        break;
      case 'list-leak':
        confirmed = T.status === 200 && hasOwner(T);
        fixed = denied(T.status) || (T.status === 200 && !hasOwner(T));
        break;
      case 'param-filter':
        confirmed = T.status === 200 && (hasOwner(T) || spec.extraFields?.some(field => T.fields.includes(field)));
        fixed = denied(T.status) || (T.status === 200 && !hasOwner(T) && !spec.extraFields?.some(field => T.fields.includes(field)));
        break;
      case 'bfla':
        confirmed = T.status === 200 && denied(A.status) && (hasOwner(T) || spec.extraFields?.some(field => T.fields.includes(field)));
        fixed = denied(T.status);
        break;
      default: return {verdict: 'inconclusive', controls, reason: 'unsupported proof kind'};
    }
    return {verdict: confirmed ? 'confirmed' : fixed ? 'not_reproduced' : 'inconclusive', controls};
  } catch (error) {
    return {verdict: 'inconclusive', reason: error.message};
  }
}
