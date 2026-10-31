// JavaScript mining for the black-box audit: fetches an origin's pages, approved scripts, chunks and
// source maps, and extracts endpoints with methods and parameters, hosts and buckets, masked secrets,
// libraries, environment leakage and comments. Implements docs/BLACKBOX_AUDIT.md sections 5.4 and 6.3.
import { hash, need } from '../util.mjs';
import { loopback, pathAllowed } from '../network.mjs';
import {credentialQueryKey, maskCredentialParams} from './private-query.mjs';
import {maskExcerpt} from './ledger.mjs';

const ACCEPT_HTML = 'text/html, application/json;q=0.9, */*;q=0.8';
const ACCEPT_SCRIPT = 'application/javascript, text/javascript;q=0.9, */*;q=0.8';
const ACCEPT_MAP = 'application/json, */*;q=0.8';
const SOURCE_MAP_VENDOR_PATH = /(?:^|\/)(?:node_modules|bower_components|vendor|vendors|third_party|third-party)(?:\/|$)|\/webpack\/(?:runtime|bootstrap|universalModuleDefinition)(?:\/|$)/i;
// A named webpack namespace belongs to a bundle, not necessarily to the
// application being audited. Its ./src entries may be package sources (for
// example, a Swagger UI bundle served by the application).
const SOURCE_MAP_NAMESPACE_PATH = /^webpack:\/\/[^/]+\//i;
const sourceMapKind = source => SOURCE_MAP_VENDOR_PATH.test(String(source)) ? 'vendor' :
  SOURCE_MAP_NAMESPACE_PATH.test(String(source)) ? 'namespace' : 'appLikely';
const PAGE_PATH = /(?:\/|\/[^/.]+|\/[^/]+\.(?:html?|php|aspx?|jsp|cfm))$/i;

const secretPattern = (name, regex, confidence, isPublic = false) => Object.freeze({name, regex, confidence, public: isPublic});

/** Secret scanner patterns, most specific first. A capture group, when present, holds the secret value. */
export const SECRET_PATTERNS = Object.freeze([
  secretPattern('private-key', /-----BEGIN (?:[A-Z]+ )*PRIVATE KEY(?: BLOCK)?-----(?:[\s\S]{0,4096}?-----END (?:[A-Z]+ )*PRIVATE KEY(?: BLOCK)?-----)?/, 'high'),
  secretPattern('aws-access-key', /\bAKIA[0-9A-Z]{16}\b/, 'high'),
  secretPattern('stripe-secret-key', /\bsk_live_[0-9A-Za-z]{10,247}\b/, 'high'),
  secretPattern('stripe-restricted-key', /\brk_live_[0-9A-Za-z]{10,247}\b/, 'high'),
  secretPattern('stripe-publishable-key', /\bpk_live_[0-9A-Za-z]{10,247}\b/, 'high', true),
  secretPattern('github-token', /\b(?:gh[po]_[0-9A-Za-z]{36}|github_pat_\w{22,255})\b/, 'high'),
  secretPattern('slack-token', /\bxox[abprs]-[0-9A-Za-z-]{10,250}/, 'high'),
  secretPattern('sendgrid-key', /\bSG\.[\w-]{22}\.[\w-]{43}\b/, 'high'),
  secretPattern('twilio-key', /\bSK[0-9a-f]{32}\b/, 'medium'),
  secretPattern('mailgun-key', /\bkey-[0-9a-f]{32}\b/, 'medium'),
  secretPattern('mapbox-secret-token', /\bsk\.eyJ[\w-]{10,}\.[\w-]{10,}/, 'high'),
  secretPattern('mapbox-public-token', /\bpk\.eyJ[\w-]{10,}\.[\w-]{10,}/, 'high', true),
  secretPattern('firebase-config', /apiKey["']?\s*:\s*["'](AIza[\w-]{35})["'][\s\S]{0,400}?projectId["']?\s*:\s*["'][\w-]+["']/, 'high', true),
  secretPattern('google-api-key', /\bAIza[\w-]{35}\b/, 'medium'),
  secretPattern('jwt', /\beyJ[\w-]{8,}\.eyJ[\w-]{8,}\.[\w-]*/, 'medium'),
  secretPattern('basic-auth-url', /\b[a-z][a-z0-9+.-]*:\/\/[^\s:@\/"'`${}]+:[^\s@\/"'`${}]+@[\w.-]+/i, 'high'),
  secretPattern('generic', /(?:api[_-]?key|secret|token|passw(?:or)?d)[\w-]*["']?\s*[:=]\s*["'](?=[^"'\s]*\d)(?=[^"'\s]*[a-z])(?![a-z]+:\/\/|\/)([^"'\s]{8,200})["']/i, 'low'),
]);

/** Non-overlapping secret matches in text; when two patterns overlap, the earlier (more specific) one wins. */
function scanSecrets(text) {
  const found = [];
  for (const pattern of SECRET_PATTERNS) {
    for (const match of text.matchAll(new RegExp(pattern.regex.source, `${pattern.regex.flags}gd`))) {
      const [start, end] = match.indices[1] ?? match.indices[0];
      if (!found.some(other => start < other.end && other.start < end)) found.push({pattern, value: text.slice(start, end), start, end});
    }
  }
  return found.sort((a, b) => a.start - b.start);
}

/** Source-review indicators contain locations and pattern names, never matched values or hashes. */
export function secretIndicators(text) {
  const locate = locator(text);
  const seen = new Set();
  return scanSecrets(text).filter(({value}) => {
    if (seen.has(value)) return false;
    seen.add(value);
    return true;
  }).map(({pattern, start}) => ({
    name: pattern.name, confidence: pattern.confidence, public: pattern.public,
    ...locate(start),
  }));
}

const maskValue = value => `${value.slice(0, 4)}…(${value.length})`;
const digest = text => `sha256:${hash(text)}`;

/** Replaces every SECRET_PATTERNS match in text with its masked form (first four characters and length). */
export function maskSecrets(text) {
  let masked = '', from = 0;
  for (const {value, start, end} of scanSecrets(text)) {
    masked += text.slice(from, start) + maskValue(value);
    from = end;
  }
  return masked + text.slice(from);
}

/** Algorithm, issuer, audience and expiry of a JWT, decoded for the report; the signature is never used. */
function jwtClaims(token) {
  const [header, payload] = token.split('.').map(part => parseJson(Buffer.from(part, 'base64url').toString('utf8')));
  const claims = {alg: header?.alg, iss: payload?.iss, aud: payload?.aud, exp: payload?.exp};
  return Object.fromEntries(Object.entries(claims).filter(([, value]) => value !== undefined));
}

function secretRecord({pattern, value, line, column}) {
  const record = {name: pattern.name, confidence: pattern.confidence, public: pattern.public, masked: maskValue(value), hash: digest(value), line, column};
  if (pattern.name === 'jwt') record.claims = jwtClaims(value);
  return record;
}

/** JSON.parse for untrusted text: undefined means the text is not JSON, which callers treat as "no data". */
function parseJson(text) {
  try { return JSON.parse(text); } catch { return undefined; }
}

const unique = list => [...new Set(list)];
const INDIRECT_REQUEST = /\b(?:fetch|axios\.(?:get|request)|[A-Za-z_$][\w$]*\.(?:get|request))\s*\(\s*(?!['"`])/g;
const GENERATED_METHOD_PATH = /(["'`])(GET|HEAD|POST|PUT|PATCH|DELETE|OPTIONS)\1\s*,\s*(["'`])(\/(?!\/)[^"'`\s\\]{1,240})\3/g;
const ROUTE_HINTS_PER_FILE = 32;
const INFERRED_CALLS_PER_FORM = 120;
const INFERRED_CLASSES_PER_FILE = 512;
const INFERRED_CLASS_SCAN_BYTES = 250000;
const ROUTE_HINT_WINDOW_BEFORE = 400;
const ROUTE_HINT_WINDOW_AFTER = 280;
function safeRouteLiteral(value) {
  if (!value || value.length > 100 || /[\\\x00-\x1f\x7f%]/.test(value) ||
      maskSecrets(value) !== value) return false;
  if (/^\/(?!\/)(?!.*(?:^|\/)\.\.?\/)\S*$/.test(value) &&
      /^\/[A-Za-z0-9_./?&=:-]*$/.test(value)) {
    return true;
  }
  if (/^\?[A-Za-z][A-Za-z0-9_-]{0,40}=\/[A-Za-z0-9_./-]{0,60}$/.test(value))
    return true;
  return /^[A-Za-z][A-Za-z0-9_-]{1,39}$/.test(value) && value.includes('-') &&
    !/(?:secret|token|password|credential|api.?key)/i.test(value);
}

// Keep route-shaped string pieces and code structure, but remove comments and every other literal.
function redactedRouteWindow(text) {
  let excerpt = '';
  const literals = [];
  for (let at = 0; at < text.length && excerpt.length < 900;) {
    if (text.startsWith('//', at)) {
      at = text.indexOf('\n', at + 2);
      if (at < 0) break;
      excerpt += ' ';
      continue;
    }
    if (text.startsWith('/*', at)) {
      const close = text.indexOf('*/', at + 2);
      at = close < 0 ? text.length : close + 2;
      excerpt += ' ';
      continue;
    }
    const quote = text[at];
    if (quote === "'" || quote === '"' || quote === '`') {
      let end = at + 1;
      while (end < text.length && text[end] !== quote) {
        if (text[end] === '\\') end++;
        end++;
      }
      const value = text.slice(at + 1, end);
      if (safeRouteLiteral(value)) {
        const masked = maskCredentialParams(value);
        literals.push(masked);
        excerpt += `${quote}${masked}${quote}`;
      } else excerpt += '"[literal]"';
      at = end < text.length ? end + 1 : end;
      continue;
    }
    const char = text[at++];
    excerpt += /[\x20-\x7e]/.test(char) ? char : ' ';
  }
  return {excerpt: excerpt.slice(0, 900).trim(), literals: unique(literals).slice(0, 16)};
}

/** Ranges that cannot be a safe starting point for a redacted code excerpt. */
function quotedAndCommentRanges(text) {
  const ranges = [];
  for (let at = 0; at < text.length;) {
    const start = at;
    if (text.startsWith('//', at)) {
      const end = text.indexOf('\n', at + 2);
      at = end < 0 ? text.length : end + 1;
    } else if (text.startsWith('/*', at)) {
      const end = text.indexOf('*/', at + 2);
      at = end < 0 ? text.length : end + 2;
    } else if (["'", '"', '`'].includes(text[at])) {
      const quote = text[at++];
      while (at < text.length) {
        if (text[at] === '\\') at += 2;
        else if (text[at++] === quote) break;
      }
      at = Math.min(at, text.length);
    } else {at++; continue;}
    ranges.push({start, end: at});
  }
  return ranges;
}

function coveringRange(ranges, offset) {
  let low = 0, high = ranges.length;
  while (low < high) {
    const middle = (low + high) >> 1;
    if (ranges[middle].start <= offset) low = middle + 1;
    else high = middle;
  }
  const range = ranges[low - 1];
  return range && offset < range.end ? range : null;
}

function safeExcerptStart(ranges, desired) {
  return coveringRange(ranges, desired)?.end ?? desired;
}

function routeHintsIn(text, maxHints = ROUTE_HINTS_PER_FILE) {
  const hints = [];
  let eligible = 0;
  const locate = locator(text);
  const unsafe = quotedAndCommentRanges(text);
  for (const match of text.matchAll(INDIRECT_REQUEST)) {
    if (coveringRange(unsafe, match.index)) continue;
    const open = text.indexOf('(', match.index);
    const call = readBalanced(text, open, 1000);
    const explicitMethod = /\bmethod\s*:\s*['"](post|put|patch|delete|head|options)['"]/i
      .exec(call?.inner ?? '')?.[1];
    const method = !call ? 'UNKNOWN' : explicitMethod ? explicitMethod.toUpperCase() :
      /\.request\s*\(/.test(match[0]) ? 'UNKNOWN' : 'GET';
    const start = safeExcerptStart(unsafe, Math.max(0, match.index - ROUTE_HINT_WINDOW_BEFORE));
    const context = redactedRouteWindow(text.slice(start, match.index + ROUTE_HINT_WINDOW_AFTER));
    if (!context.literals.some(value => value.startsWith('/'))) continue;
    eligible++;
    if (hints.length < maxHints) hints.push({id: `h${hints.length + 1}`,
      line: locate(match.index).line, method, ...context});
  }
  return {hints, cut: eligible - hints.length};
}

// A generated client may pass a literal method and path to a transport whose
// origin is configured elsewhere. Keep the call and host context for Muse.
export function generatedRequestHints(text) {
  const safeSnippet = value => maskExcerpt(maskSecrets(value)).slice(0, 900);
  const hostCandidates = unique([...text.matchAll(
    /\b(?:apiHost|baseURL|baseUrl|apiBase|endpointHost|serviceHost)\s*:\s*["'`]([^"'`]{1,180})["'`]/g)]
    .map(match => match[1]).filter(value => /^(?:https?:\/\/)?[A-Za-z0-9.-]+(?::\d+)?\/?$/.test(value)));
  const hostContext = [...text.matchAll(/\b(?:apiHost|baseURL|baseUrl|apiScheme)\b/g)]
    .slice(0, 8).map(match => safeSnippet(text.slice(Math.max(0, match.index - 230), match.index + 270)));
  const lineOf = locator(text);
  const hints = [];
  for (const match of text.matchAll(GENERATED_METHOD_PATH)) {
    const [, , method, , path] = match;
    if (!/^[A-Za-z0-9_./:{}?&=+%-]+$/.test(path) || maskSecrets(path) !== path) continue;
    const before = text.slice(Math.max(0, match.index - 180), match.index);
    const caller = /([A-Za-z_$][\w$]*)\s*\([^()]{0,100}$/.exec(before)?.[1];
    const functionName = [...before.matchAll(/(?:async\s+)?function\s+([A-Za-z_$][\w$]*)\s*\(/g)].at(-1)?.[1];
    const functionAt = caller ? text.indexOf(`function ${caller}(`) : -1;
    const callbackAt = functionName ? text.indexOf(`,${functionName})`, match.index + match[0].length) : -1;
    hints.push({method, path, line: lineOf(match.index).line,
      excerpt: safeSnippet(text.slice(Math.max(0, match.index - 220), match.index + 280)),
      ...(functionAt >= 0 ? {transport: safeSnippet(text.slice(functionAt, functionAt + 550))} : {}),
      ...(callbackAt >= 0 ? {caller: safeSnippet(text.slice(Math.max(0, callbackAt - 300), callbackAt + 120))} : {})});
  }
  return {hints, hostCandidates, hostContext};
}

function uniqueBy(list, key) {
  const seen = new Set();
  return list.filter(item => !seen.has(key(item)) && seen.add(key(item)));
}

/** Maps a character offset in text to its 1-based line and column. */
function locator(text) {
  const starts = [0];
  for (let at = text.indexOf('\n'); at !== -1; at = text.indexOf('\n', at + 1)) starts.push(at + 1);
  return offset => {
    let low = 0, high = starts.length - 1;
    while (low < high) {
      const middle = (low + high + 1) >> 1;
      if (starts[middle] <= offset) low = middle;
      else high = middle - 1;
    }
    return {line: low + 1, column: offset - starts[low] + 1};
  };
}

/**
 * Text inside the bracket at `open` and the index after its match; null when unbalanced within `limit` characters.
 * Scans are local and bounded: real call sites close within a few hundred characters, and a crafted file of
 * unclosed brackets costs at most (sites x limit), which callers keep small by scanning only literal-led calls.
 */
function readBalanced(text, open, limit = 2000) {
  let depth = 0, quote = null;
  for (let at = open; at < Math.min(text.length, open + limit); at++) {
    const char = text[at];
    if (quote) {
      if (char === '\\') at++;
      else if (char === quote) quote = null;
    } else if (char === '"' || char === "'" || char === '`') quote = char;
    else if ('([{'.includes(char)) depth++;
    else if (')]}'.includes(char) && --depth === 0) return {inner: text.slice(open + 1, at), end: at + 1};
  }
  return null;
}

/** Splits an argument list or an object literal body at its top-level commas. */
function splitArgs(inner) {
  const parts = [];
  let depth = 0, quote = null, from = 0;
  for (let at = 0; at < inner.length; at++) {
    const char = inner[at];
    if (quote) {
      if (char === '\\') at++;
      else if (char === quote) quote = null;
    } else if (char === '"' || char === "'" || char === '`') quote = char;
    else if ('([{'.includes(char)) depth++;
    else if (')]}'.includes(char)) depth--;
    else if (char === ',' && depth === 0) {
      parts.push(inner.slice(from, at).trim());
      from = at + 1;
    }
  }
  parts.push(inner.slice(from).trim());
  return parts.filter(Boolean);
}

const PROPERTY = /^(?:["']([^"']+)["']|([A-Za-z_$][\w$]*))\s*(?::|$)/;

/** Top-level property names of an object literal body: `a:1,"b-c":2,d` -> ['a', 'b-c', 'd']. */
function objectKeys(body) {
  return splitArgs(body).map(entry => PROPERTY.exec(entry)).filter(Boolean).map(match => match[1] ?? match[2]);
}

/** A client request's literal JSON body, including only fields and harmless literal examples. */
function nestedJsonLiteral(expression, name, depth = 0) {
  const text = String(expression ?? '').trim();
  if (!text || text.length > 256 || depth > 3 || credentialQueryKey(name) ||
      /(?:password|secret|token|api.?key|bearer|credential)/i.test(name) ||
      /^(?:email|username|user_name|login)$/i.test(name)) return null;
  const quoted = /^(["'`])([A-Za-z0-9][A-Za-z0-9_. -]{0,63})\1$/.exec(text);
  if (quoted) {
    const value = quoted[2];
    return maskSecrets(value) === value &&
      !/(?:password|secret|token|api.?key|bearer|credential)/i.test(value) ?
      {value, shape: {type: 'string'}} : null;
  }
  if (/^-?(?:0|[1-9]\d*)(?:\.\d+)?$/.test(text)) {
    const value = Number(text);
    return Number.isFinite(value) && Math.abs(value) <= 1e9 ?
      {value, shape: {type: Number.isInteger(value) ? 'integer' : 'number'}} : null;
  }
  if (text === 'true' || text === 'false') return {value: text === 'true',
    shape: {type: 'boolean'}};
  if (text === 'null') return {value: null, shape: {type: 'null'}};
  if (text.startsWith('{') && text.endsWith('}')) {
    const entries = splitArgs(text.slice(1, -1));
    if (entries.length > 12) return null;
    const parsed = entries.map(entry => {
      const property = PROPERTY.exec(entry);
      if (!property || !property[0].trimEnd().endsWith(':')) return null;
      const key = property[1] ?? property[2];
      if (!/^[A-Za-z_][A-Za-z0-9_.-]{0,79}$/.test(key)) return null;
      const nested = nestedJsonLiteral(entry.slice(property[0].length), key, depth + 1);
      return nested ? [key, nested] : null;
    });
    if (parsed.some(item => !item)) return null;
    return {value: Object.fromEntries(parsed.map(([key, item]) => [key, item.value])),
      shape: {type: 'object', properties: Object.fromEntries(parsed.map(([key, item]) =>
        [key, item.shape])), required: []}};
  }
  if (text.startsWith('[') && text.endsWith(']')) {
    const values = splitArgs(text.slice(1, -1));
    if (values.length > 4) return null;
    const parsed = values.map(value => nestedJsonLiteral(value, name, depth + 1));
    return parsed.every(Boolean) ? {value: parsed.map(item => item.value),
      shape: {type: 'array', ...(parsed[0] ? {items: parsed[0].shape} : {})}} : null;
  }
  return null;
}

function jsonBodyContract(expression) {
  const value = String(expression ?? '').trim();
  let body = value;
  if (body.startsWith('JSON.stringify(')) {
    const call = readBalanced(body, 'JSON.stringify'.length);
    if (!call || call.end !== body.length) return null;
    body = call.inner.trim();
  }
  if (!body.startsWith('{') || !body.endsWith('}')) return null;
  const fields = [], stringFields = [], fieldExamples = {},
    bodyFieldTypes = {}, fieldShapes = {}, fieldValueExamples = {};
  for (const entry of splitArgs(body.slice(1, -1))) {
    const property = PROPERTY.exec(entry);
    if (!property) continue;
    const name = property[1] ?? property[2];
    if (!/^[A-Za-z_][A-Za-z0-9_.-]{0,79}$/.test(name)) continue;
    fields.push(name);
    const value = entry.slice(property[0].length).trim();
    const nested = nestedJsonLiteral(value, name);
    if (nested) {
      bodyFieldTypes[name] = nested.shape.type;
      fieldShapes[name] = nested.shape;
      fieldValueExamples[name] = [JSON.stringify(nested.value)];
    }
    const literal = /^(?:"([A-Za-z0-9][A-Za-z0-9_. -]{0,63})"|'([A-Za-z0-9][A-Za-z0-9_. -]{0,63})'|`([A-Za-z0-9][A-Za-z0-9_. -]{0,63})`)$/.exec(value);
    if (!literal) continue;
    stringFields.push(name);
    const example = literal[1] ?? literal[2] ?? literal[3];
    if (!credentialQueryKey(name) && maskSecrets(example) === example &&
        !/(?:password|secret|token|api.?key|bearer)/i.test(example)) fieldExamples[name] = [example];
  }
  return fields.length ? {bodyEncoding: 'json', bodyFields: unique(fields),
    bodyStringFields: unique(stringFields), bodyFieldTypes, fieldShapes,
    fieldValueExamples, fieldExamples} : null;
}

function jsonBodyInOptions(options, {allowObjectData = false} = {}) {
  const entry = splitArgs(options.startsWith('{') && options.endsWith('}') ? options.slice(1, -1) : options)
    .find(part => /^(?:body|data|["'](?:body|data)["'])\s*:/.test(part));
  if (!entry) return null;
  const expression = entry.slice(entry.indexOf(':') + 1).trim();
  return expression.startsWith('JSON.stringify(') ||
    allowObjectData && /^(?:data|["']data["'])\s*:/.test(entry) ? jsonBodyContract(expression) : null;
}

/** Property names of the object literal that `regex` (ending at its opening brace) finds in text. */
function keysOf(text, regex) {
  const match = regex.exec(text);
  const object = match && readBalanced(text, match.index + match[0].length - 1);
  return object ? objectKeys(object.inner) : [];
}

const JOINABLE = /(["'])((?:\\.|(?!\1)[^\\\n])*)\1[ \t]*\+[ \t]*\1((?:\\.|(?!\1)[^\\\n])*)\1/g;
const CONCAT_CALL = /(["'])(?:\\.|(?!\1)[^\\\n])*\1\.concat\(/g;
const TEMPLATE_SLOT = /\$\{[^{}\n`]*(?:\{[^{}\n`]*\}[^{}\n`]*)*\}/g;
const BASE64_LITERAL = /(["'`])([A-Za-z0-9+\/_-]{41,}={0,2})\1/g;
const NOT_TEXT = /[\x00-\x08\x0b\x0c\x0e-\x1f\x7f\ufffd]/;

/** Rewrites `"literal".concat(a, "b")`, Babel's form of a template literal, as `"literal"+a+"b"`. */
function concatCallsToPlus(text) {
  let out = '', from = 0;
  for (const match of text.matchAll(CONCAT_CALL)) {
    if (match.index < from) continue;
    const open = match.index + match[0].length - 1;
    const call = readBalanced(text, open);
    if (!call || call.inner.includes('\n')) continue;
    out += text.slice(from, open - '.concat'.length) + ['', ...splitArgs(call.inner)].join('+');
    from = call.end;
  }
  return out + text.slice(from);
}

/** Base64 literals over 40 characters that decode to readable text (a JSON config, embedded text). */
function decodedLiterals(text) {
  const blocks = [];
  for (const match of text.matchAll(BASE64_LITERAL)) {
    const decoded = Buffer.from(match[2], 'base64').toString('utf8');
    if (decoded.trim().length >= 8 && !NOT_TEXT.test(decoded)) blocks.push({text: decoded, offset: match.index});
  }
  return blocks;
}

/** Normalized code with the line structure of `text`, plus the decoded base64 blocks and their literal offsets. */
function normalizeParts(text) {
  let code = concatCallsToPlus(text);
  for (let pass = 0; pass < 32; pass++) {
    const joined = code.replace(JOINABLE, (_, quote, left, right) => quote + left + right + quote);
    if (joined === code) break;
    code = joined;
  }
  return {code: code.replace(TEMPLATE_SLOT, '{id}'), decoded: decodedLiterals(text)};
}

/**
 * Normalizes minified code for matching: joins 'a'+'b' (and "a".concat(...)) concatenations, keeps template
 * slots as {id}, and appends the text of base64 literals over 40 characters that decode to text or JSON.
 */
export function normalizeScript(text) {
  const {code, decoded} = normalizeParts(text);
  return [code, ...decoded.map(block => block.text)].join('\n');
}

const PATH_LITERAL = /(["'`])((?:https?:\/\/[^\/"'`\s]+)?\/(?!\/)[^"'`\s<>\\^|(),;+*!]*)\1/g;
const STRING_PART = /(["'`])([^"'`\s<>\\^|(),;+*!]*)\1/y;
const OPERAND = /[\w$.]+(?:\([^()]*\)|\[[^\]]*\])*/y;
const PLUS = /[ \t]*\+[ \t]*/y;
const FIRST_QUOTE = /\s*["'`]/y;
const CALL = /(?:\bfetch|\.(get|post|put|patch|delete|head))\s*\(/g;
const OBJECT_REQUEST_CALL = /(?:\baxios(?:\.request)?|\b[A-Za-z_$][\w$]*\.request|\$\.ajax|\bjQuery\.ajax)\s*\(\s*\{/g;
const XHR_OPEN = /\b[A-Za-z_$][\w$]*\.open\s*\(/g;
const URL_PROPERTY = /^(?:url|path|["'](?:url|path)["'])\s*:\s*/;
const BASE_URL_PROPERTY = /^(?:baseURL|["']baseURL["'])\s*:\s*/;
const ALLOW_ABSOLUTE_PROPERTY = /^(?:allowAbsoluteUrls|["']allowAbsoluteUrls["'])\s*:\s*(true|false)\s*$/;
const AXIOS_INSTANCE = /\bconst\s+([A-Za-z_$][\w$]*)\s*=\s*axios\.create\s*\(/g;
const STATIC_CONST = /\bconst\s+([A-Za-z_$][\w$]*)\s*=\s*/g;
const METHOD_PROPERTY = /^(?:method|type|["'](?:method|type)["'])\s*:\s*(["'`])([A-Za-z]+)\1/;
const METHOD_KEY = /^(?:method|type|["'](?:method|type)["'])\s*:/;
const HTTP_METHODS = new Set(['GET', 'HEAD', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS']);
const ROUTE = /\bpath\s*:\s*(["'`])(\/[^"'`\s]*)\1/dg;
const NOT_ENDPOINT = /^\/(?:application|text|image|audio|video|font|multipart)\/[\w.+-]+$|\.(?:png|jpe?g|gif|svg|webp|avif|ico|bmp|woff2?|ttf|otf|eot|css|m?js|map|mp4|webm|mp3|wav)$/i;
const HEADERS_OBJECT = /\bheaders\s*:\s*\{/;
const PARAMS_OBJECT = /\bparams\s*:\s*\{/;
const JSON_BODY = /\bbody\s*:\s*JSON\.stringify\(\s*\{/;

/**
 * Reads the string literal at `at` and any `+` chain after it. A variable after '/' or '=' becomes {id};
 * other variables are returned in `vars` (for example a URLSearchParams appended after '?').
 */
function readConcat(source, at) {
  STRING_PART.lastIndex = at;
  const head = STRING_PART.exec(source);
  if (!head) return null;
  const chain = {value: head[2], starts: [at], end: STRING_PART.lastIndex, templated: head[2].includes('{id}'), vars: []};
  for (;;) {
    PLUS.lastIndex = chain.end;
    if (!PLUS.exec(source)) return chain;
    const next = PLUS.lastIndex;
    STRING_PART.lastIndex = next;
    const part = STRING_PART.exec(source);
    if (part) {
      chain.value += part[2];
      chain.starts.push(next);
      chain.end = STRING_PART.lastIndex;
      continue;
    }
    OPERAND.lastIndex = next;
    const operand = OPERAND.exec(source);
    if (!operand?.[0]) return chain;
    if (/[\/=]$/.test(chain.value)) {
      chain.value += '{id}';
      chain.templated = true;
    } else chain.vars.push(operand[0]);
    chain.end = OPERAND.lastIndex;
  }
}

/** {path, params} for a path or same-origin URL value, or null when it has no letter, is a MIME type or a static file. */
function toEndpoint(value, base) {
  let rest = value;
  if (/^https?:\/\//i.test(rest)) {
    const lower = rest.toLowerCase();
    if (!base || !(lower === base || lower.startsWith(`${base}/`))) return null;
    rest = rest.slice(base.length) || '/';
  }
  if (!rest.startsWith('/') || rest.startsWith('//')) return null;
  const [beforeHash] = rest.split('#');
  const cut = beforeHash.indexOf('?');
  const rawPath = cut === -1 ? beforeHash : beforeHash.slice(0, cut);
  const query = cut === -1 ? '' : beforeHash.slice(cut + 1);
  const path = rawPath.replace(/\/:[A-Za-z_]\w*/g, '/{id}').replace(/\[(?:\.\.\.)?[\w-]+\]/g, '{id}').replace(/(.)\/+$/, '$1');
  if (!/[A-Za-z]/.test(path.replaceAll('{id}', '')) || NOT_ENDPOINT.test(path)) return null;
  const params = [...query.matchAll(/(?:^|&)([^=&{}]+)=/g)].map(match => match[1]);
  const examples = {};
  for (const [key, example] of new URLSearchParams(query)) {
    if (credentialQueryKey(key) || !/^[A-Za-z_][A-Za-z0-9_.-]{0,63}$/.test(key) ||
        !/^[A-Za-z0-9_.-]{1,32}$/.test(example) || /^[0-9a-f]{16,}$/i.test(example) ||
        maskSecrets(example) !== example) continue;
    const values = examples[key] ?? [];
    if (!values.includes(example) && values.length < 4) values.push(example);
    examples[key] = values;
  }
  return {path, params, examples};
}

function fetchMethod(options) {
  if (!/\bmethod\s*:/.test(options)) return 'GET';
  return /\bmethod\s*:\s*["'`]([A-Za-z]+)["'`]/.exec(options)?.[1].toUpperCase() ?? 'UNKNOWN';
}

/** A static axios instance base, or null when the instance has a base we cannot resolve. */
function axiosBases(source) {
  const bases = new Map();
  const aliases = new Map();
  for (const match of source.matchAll(STATIC_CONST)) {
    const at = match.index + match[0].length;
    const chain = readConcat(source, at);
    if (!chain || chain.vars.length || chain.templated ||
        !/^\s*(?:[;,]|$|\n)/.test(source.slice(chain.end, chain.end + 12))) continue;
    aliases.set(match[1], aliases.has(match[1]) ? null : {value: chain.value, at: match.index});
  }
  for (const match of source.matchAll(AXIOS_INSTANCE)) {
    const name = match[1];
    const open = match.index + match[0].length - 1;
    const call = readBalanced(source, open);
    if (!call) continue;
    const config = splitArgs(call.inner)[0];
    if (!config?.startsWith('{') || !config.endsWith('}')) continue;
    const entries = splitArgs(config.slice(1, -1));
    const entry = entries.find(item => BASE_URL_PROPERTY.test(item));
    if (!entry) continue;
    const prefix = BASE_URL_PROPERTY.exec(entry)[0];
    const at = open + 1 + call.inner.indexOf(config) + 1 + config.slice(1, -1).indexOf(entry) + prefix.length;
    const chain = readConcat(source, at);
    const expression = entry.slice(prefix.length).trim();
    const alias = /^[A-Za-z_$][\w$]*$/.test(expression) ? aliases.get(expression) : null;
    const literal = chain?.end === at + entry.length - prefix.length && !chain.vars.length &&
      !chain.templated ? chain.value : alias?.at < match.index ? alias.value : null;
    const safe = literal && !/[?#]/.test(literal) &&
      (/^\/(?!\/)/.test(literal) || /^https?:\/\//i.test(literal));
    const setting = entries.find(item => /^(?:allowAbsoluteUrls|["']allowAbsoluteUrls["'])\s*:/.test(item));
    const allowAbsolute = setting ? ALLOW_ABSOLUTE_PROPERTY.exec(setting)?.[1] === 'true' : true;
    bases.set(name, bases.has(name) ? null : safe && (!setting || ALLOW_ABSOLUTE_PROPERTY.test(setting)) ?
      {url: literal, allowAbsolute} : null);
  }
  return bases;
}

function axiosReceiver(source, at) {
  return /(?:^|[^\w$.])([A-Za-z_$][\w$]*)$/.exec(source.slice(Math.max(0, at - 100), at))?.[1] ?? null;
}

function hasBaseOverride(options) {
  const trimmed = options.trim();
  return trimmed.startsWith('{') && trimmed.endsWith('}') ?
    splitArgs(trimmed.slice(1, -1)).some(entry => BASE_URL_PROPERTY.test(entry)) :
    /\bbaseURL\s*:/.test(trimmed);
}

/** Axios trims slashes at the join; URL parsing then normalizes dot segments. */
function resolvedAxiosChain(chain, instance, origin) {
  if (instance.allowAbsolute && /^(?:https?:\/\/|\/\/)/i.test(chain.value)) return chain;
  try {
    const combined = `${instance.url.replace(/\/+$/, '')}/${chain.value.replace(/^\/+/, '')}`;
    const url = new URL(combined, /^https?:\/\//i.test(origin ?? '') ? origin : 'https://source.invalid');
    let value = /^https?:\/\//i.test(instance.url) ? url.href : `${url.pathname}${url.search}`;
    if (chain.templated) value = value.replace(/%7Bid%7D/gi, '{id}');
    return {...chain, value};
  } catch {return null;}
}

/** Resolve fetch(new URL(...)) when its literal URL and base establish this origin. */
function fetchUrlConstructor(source, open, base) {
  const prefix = /^\s*new\s+URL\s*\(/.exec(source.slice(open + 1, open + 40));
  if (!prefix) return null;
  const constructorOpen = open + prefix[0].length;
  const constructor = readBalanced(source, constructorOpen);
  if (!constructor || !/^\s*(?:\.href|\.toString\(\))?\s*[,)]/.test(source.slice(constructor.end, constructor.end + 40))) return null;
  const args = splitArgs(constructor.inner);
  if (args.length < 1 || args.length > 2) return null;
  const firstAt = constructorOpen + 1 + constructor.inner.indexOf(args[0]);
  const relative = readConcat(source, firstAt);
  if (!relative || relative.end !== firstAt + args[0].length) return null;
  const baseArg = args[1];
  const baseAt = baseArg ? constructorOpen + 1 + constructor.inner.lastIndexOf(baseArg) : -1;
  const baseChain = baseArg ? readConcat(source, baseAt) : null;
  const absoluteBase = baseChain && baseChain.end === baseAt + baseArg.length && !baseChain.vars.length &&
    !baseChain.templated ? baseChain.value :
    /^(?:(?:window|self|globalThis|document)\.)?location\.origin$/.test(baseArg ?? '') ? base : null;
  let target;
  try {
    if (!base || (baseArg && (!absoluteBase || !/^https?:\/\//i.test(absoluteBase)))) return null;
    target = baseArg ? new URL(relative.value, absoluteBase) : new URL(relative.value);
    if (target.origin !== base) return null;
  } catch {return null;}
  return {...relative, value: target.href};
}

/** The call site of fetch(...) or client.get/post/put/patch/delete/head(...) whose first argument is a path or URL literal. */
function callSite(source, match, base, bases) {
  const verb = match[1]?.toUpperCase();
  const open = match.index + match[0].length - 1;
  const receiver = verb ? axiosReceiver(source, match.index) : null;
  const instance = receiver && bases.has(receiver) ? bases.get(receiver) : undefined;
  let chain = !verb ? fetchUrlConstructor(source, open, base) : null;
  if (!chain) {
    FIRST_QUOTE.lastIndex = open + 1;
    if (FIRST_QUOTE.exec(source)) chain = readConcat(source, FIRST_QUOTE.lastIndex - 1);
  }
  if (!chain) return null;
  const call = readBalanced(source, open);
  if (!call || chain.end >= call.end) return null;
  const args = splitArgs(call.inner);
  const sendsBody = ['POST', 'PUT', 'PATCH'].includes(verb);
  const options = (sendsBody ? args[2] : args[1]) ?? '';
  const body = sendsBody && args[1]?.startsWith('{') ? objectKeys(args[1].slice(1, -1)) : [];
  const bodyContract = sendsBody ? jsonBodyContract(args[1]) :
    fetchMethod(options) !== 'GET' ? jsonBodyInOptions(options) : null;
  const skip = instance === null || (instance !== undefined && hasBaseOverride(options));
  if (!skip && instance) chain = resolvedAxiosChain(chain, instance, base);
  if (!chain || (!skip && !/^(?:\/|https?:\/\/)/i.test(chain.value))) return null;
  return {chain, skip, method: verb ?? fetchMethod(options), kind: 'callsite', headers: keysOf(options, HEADERS_OBJECT),
    params: [...body, ...keysOf(options, PARAMS_OBJECT), ...keysOf(options, JSON_BODY)],
    ...(bodyContract ?? {})};
}

/** axios({url, method}), client.request({...}) and $.ajax({url, type}) keep the URL in a config object. */
function objectRequestSite(source, match, base, bases) {
  const open = match.index + match[0].length - 1;
  const receiver = /^([A-Za-z_$][\w$]*)\.request\b/.exec(match[0])?.[1];
  const instance = receiver && bases.has(receiver) ? bases.get(receiver) : undefined;
  const object = readBalanced(source, open);
  if (!object) return null;
  const entries = splitArgs(object.inner);
  const urlEntry = entries.find(entry => URL_PROPERTY.test(entry));
  if (!urlEntry) return null;
  const prefix = URL_PROPERTY.exec(urlEntry)[0];
  const start = open + 1 + object.inner.indexOf(urlEntry) + prefix.length;
  let chain = readConcat(source, start);
  if (!chain) return null;
  const methodEntry = entries.find(entry => METHOD_KEY.test(entry));
  const method = methodEntry ? METHOD_PROPERTY.exec(methodEntry)?.[2]?.toUpperCase() ?? 'UNKNOWN' : 'GET';
  if (method !== 'UNKNOWN' && !HTTP_METHODS.has(method)) return null;
  const skip = instance === null || (instance !== undefined && entries.some(entry => BASE_URL_PROPERTY.test(entry)));
  if (!skip && instance) chain = resolvedAxiosChain(chain, instance, base);
  if (!chain || (!skip && !/^(?:\/|https?:\/\/)/i.test(chain.value))) return null;
  return {chain, skip, method, kind: 'config-call', headers: keysOf(object.inner, HEADERS_OBJECT),
    params: [...keysOf(object.inner, PARAMS_OBJECT), ...keysOf(object.inner, JSON_BODY)],
    ...(['POST', 'PUT', 'PATCH'].includes(method) ?
      jsonBodyInOptions(object.inner, {allowObjectData: !/\$\.ajax|jQuery\.ajax/.test(match[0])}) ?? {} : {})};
}

/** XMLHttpRequest.open(method, url) exposes a method even when the URL is a concatenated literal. */
function xhrOpenSite(source, match) {
  const open = match.index + match[0].length - 1;
  const call = readBalanced(source, open);
  if (!call) return null;
  const args = splitArgs(call.inner);
  const verb = /^(["'`])([A-Za-z]+)\1$/.exec(args[0] ?? '')?.[2]?.toUpperCase();
  if (!HTTP_METHODS.has(verb) || !args[1]) return null;
  const start = open + 1 + call.inner.indexOf(args[1]);
  const chain = readConcat(source, start);
  if (!chain || !/^(?:\/|https?:\/\/)/i.test(chain.value)) return null;
  return {chain, method: verb, kind: 'xhr-open'};
}

/** Keys of `name = new URLSearchParams({...})` assignments shortly before `before`, for variables appended after '?'. */
function searchParamKeys(source, before, names) {
  if (!names.length) return [];
  const recent = source.slice(Math.max(0, before - 600), before);
  return names.filter(name => /^[A-Za-z_$][\w$]*$/.test(name))
    .flatMap(name => {
      const escaped = name.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
      const fromObject = keysOf(recent, new RegExp(`(?<![\\w$])${escaped}\\s*=\\s*new URLSearchParams\\(\\s*\\{`));
      const assignments = [...recent.matchAll(new RegExp(`\\b(?:const|let|var)\\s+${escaped}\\s*=\\s*([^;]{0,250})`, 'g'))];
      const expression = assignments.at(-1)?.[1] ?? '';
      const fromSuffix = [...expression.matchAll(/[?&]([A-Za-z_][A-Za-z0-9_.-]{0,79})=/g)]
        .map(match => match[1]);
      return unique([...fromObject, ...fromSuffix]);
    });
}

/** Endpoints in one normalized source: call sites first, then route tables, then the remaining path literals. */
function endpointsIn(source, base, lineOf) {
  const found = [], claimed = new Set();
  const bases = axiosBases(source);
  const add = (chain, {method, kind, headers = [], params = [], skip = false,
    bodyEncoding, bodyFields, bodyStringFields, bodyFieldTypes, fieldShapes,
    fieldValueExamples, fieldExamples}) => {
    chain.starts.forEach(start => claimed.add(start));
    if (skip) return;
    const target = toEndpoint(chain.value, base);
    if (!target) return;
    const query = searchParamKeys(source, chain.starts[0], chain.vars);
    found.push({path: target.path, method, params: unique([...target.params, ...query, ...params]),
      examples: target.examples, headers: unique(headers), line: lineOf(chain.starts[0]), kind,
      ...(bodyEncoding ? {bodyEncoding, bodyFields, bodyStringFields,
        ...(Object.keys(bodyFieldTypes ?? {}).length ? {bodyFieldTypes} : {}),
        ...(Object.keys(fieldShapes ?? {}).length ? {fieldShapes} : {}),
        ...(Object.keys(fieldValueExamples ?? {}).length ? {fieldValueExamples} : {}),
        ...(Object.keys(fieldExamples ?? {}).length ? {fieldExamples} : {})} : {})});
  };
  for (const match of source.matchAll(CALL)) {
    const site = callSite(source, match, base, bases);
    if (site) add(site.chain, site);
  }
  for (const match of source.matchAll(OBJECT_REQUEST_CALL)) {
    const site = objectRequestSite(source, match, base, bases);
    if (site) add(site.chain, site);
  }
  for (const match of source.matchAll(XHR_OPEN)) {
    const site = xhrOpenSite(source, match);
    if (site) add(site.chain, site);
  }
  // A path passed beside an explicit verb to a generated transport wrapper
  // is a request contract, not evidence of a same-origin anonymous GET.
  for (const match of source.matchAll(GENERATED_METHOD_PATH)) {
    const literal = `${match[3]}${match[4]}${match[3]}`;
    claimed.add(match.index + match[0].lastIndexOf(literal));
  }
  for (const match of source.matchAll(ROUTE)) {
    const at = match.indices[1][0];
    if (!claimed.has(at)) add({value: match[2], starts: [at], vars: []}, {method: 'UNKNOWN', kind: 'route'});
  }
  for (const match of source.matchAll(PATH_LITERAL)) {
    if (claimed.has(match.index)) continue;
    const chain = readConcat(source, match.index);
    if (chain) add(chain, {method: 'UNKNOWN', kind: chain.templated ? 'template' : 'literal'});
  }
  return found;
}

/** A public client may prefix a path with its configured hostServer. Keep the inferred base
 * explicit: the literal path is a same-origin candidate until a request verifies it. */
function inferredHostServerGets(source, base, lineOf) {
  const found = [];
  let cut = 0;
  const call = /\.(get|head)\s*\(\s*`\$\{this\.hostServer\}(\/[^`\\\s]*)`/g;
  for (const match of source.matchAll(call)) {
    const value = match[2].replace(TEMPLATE_SLOT, '{id}');
    const target = toEndpoint(value, base);
    if (!target || /\{id\}/.test(target.path)) continue;
    if (found.length < INFERRED_CALLS_PER_FORM) found.push({path: target.path, method: match[1].toUpperCase(),
      params: target.params, examples: target.examples, headers: [], line: lineOf(match.index),
      kind: 'callsite-inferred-base'});
    else cut++;
  }
  return {endpoints: found, cut};
}

/** Object fields supplied to a named client method, only when every observed call agrees. */
function callerObjectFields(source) {
  const byName = new Map();
  for (const match of source.matchAll(/\.([A-Za-z_$][\w$]*)\s*\(\s*\{/g)) {
    const object = readBalanced(source, match.index + match[0].length - 1);
    if (!object || !/^\s*\)/.test(source.slice(object.end, object.end + 8))) continue;
    const fields = objectKeys(object.inner).filter(name =>
      /^[A-Za-z_][A-Za-z0-9_.-]{0,79}$/.test(name));
    if (!fields.length || fields.length > 8) continue;
    const entries = byName.get(match[1]) ?? [];
    entries.push(fields);
    byName.set(match[1], entries);
  }
  return new Map([...byName].filter(([, entries]) => entries.every(fields =>
    fields.join('\0') === entries[0].join('\0'))).map(([name, entries]) => [name, entries[0]]));
}

/** Match a literal caller body to its injected client class, not just a common
 * method name such as save(). Every receiver binding and object shape must
 * agree before fields are attributed to a route. */
function receiverObjectFields(source) {
  const symbols = new Map();
  for (const match of source.matchAll(/\b(?:this\.)?([A-Za-z_$][\w$]*)\s*=\s*[A-Za-z_$][\w$]*\s*\(\s*([A-Za-z_$][\w$]*)\s*\)/g)) {
    const entries = symbols.get(match[1]) ?? new Set();
    entries.add(match[2]);
    symbols.set(match[1], entries);
  }
  const byClient = new Map();
  for (const match of source.matchAll(/(?:this\.)?([A-Za-z_$][\w$]*)\.([A-Za-z_$][\w$]*)\s*\(\s*\{/g)) {
    const candidates = symbols.get(match[1]);
    if (candidates?.size !== 1) continue;
    const object = readBalanced(source, match.index + match[0].length - 1);
    if (!object || !/^\s*\)/.test(source.slice(object.end, object.end + 8))) continue;
    const fields = objectKeys(object.inner).filter(name =>
      /^[A-Za-z_][A-Za-z0-9_.-]{0,79}$/.test(name));
    if (!fields.length || fields.length > 8) continue;
    const key = `${[...candidates][0]}\0${match[2]}`;
    const entries = byClient.get(key) ?? [];
    entries.push(fields);
    byClient.set(key, entries);
  }
  return new Map([...byClient].filter(([, entries]) => entries.every(fields =>
    fields.join('\0') === entries[0].join('\0'))).map(([key, entries]) => [key, entries[0]]));
}

/** A direct HTTP call inside a one-argument class method, with a body equal to that argument. */
function enclosingMethod(block, at, bodyArgument) {
  if (!/^[A-Za-z_$][\w$]*$/.test(bodyArgument ?? '')) return null;
  let found = null;
  for (const match of block.matchAll(/(?:^|[};])\s*([A-Za-z_$][\w$]*)\s*\(([A-Za-z_$][\w$]*)\)\s*\{/g)) {
    if (match.index > at) break;
    if (match[2] !== bodyArgument) continue;
    const open = match.index + match[0].length - 1;
    const method = readBalanced(block, open, INFERRED_CLASS_SCAN_BYTES);
    if (method && open < at && at < method.end) found = match[1];
  }
  return found;
}

/** Recover methods and query keys from client classes whose host field is built from hostServer.
 * The imported hostServer value is unknown here, so these are candidates until HTTP recon checks them. */
function inferredClassClientRoutes(source, base, lineOf) {
  const found = [];
  const callers = callerObjectFields(source);
  const receiverCallers = receiverObjectFields(source);
  let inspected = 0, classesCut = 0, routesCut = 0;
  for (const declaration of source.matchAll(/\bclass\s+([A-Za-z_$][\w$]*)\s*\{/g)) {
    if (++inspected > INFERRED_CLASSES_PER_FILE) {classesCut++; continue;}
    const open = declaration.index + declaration[0].length - 1;
    const block = readBalanced(source, open, INFERRED_CLASS_SCAN_BYTES);
    if (!block) {classesCut++; continue;}
    const before = source.slice(Math.max(0, declaration.index - 96), declaration.index);
    const clientSymbol = /([A-Za-z_$][\w$]*)\s*=\s*\(\(\)\s*=>\s*\{\s*$/.exec(before)?.[1] ??
      declaration[1];
    const fields = [...block.inner.matchAll(/(?<![\w$.])host\s*=\s*this\.hostServer\s*\+\s*([`'\"])/g)]
      .map(match => readConcat(block.inner, match.index + match[0].length - 1))
      .filter(chain => chain && !chain.vars.length && !chain.templated &&
        /^\/(?!\/)/.test(chain.value) && !/[?#]/.test(chain.value) &&
        toEndpoint(chain.value, base));
    const hostPath = fields.length === 1 && !/\bthis\.host\s*=/.test(block.inner) ? fields[0].value : null;
    for (const call of block.inner.matchAll(/\bthis\.(?:http|client|api)\.(get|head|post|put|patch|delete)\s*\(/g)) {
      const callOpen = call.index + call[0].length - 1;
      const invocation = readBalanced(block.inner, callOpen);
      if (!invocation) continue;
      const args = splitArgs(invocation.inner);
      const first = args[0]?.trim() ?? '';
      let field, suffix, queryVars = [];
      const template = /^`\$\{this\.(hostServer|host)\}([^`]*)`$/.exec(first);
      const concat = /^this\.(hostServer|host)\s*\+\s*/.exec(first);
      if (template) {
        field = template[1];
        suffix = template[2].replace(TEMPLATE_SLOT, '{id}');
      } else if (concat) {
        field = concat[1];
        const expression = first.slice(concat[0].length).replace(TEMPLATE_SLOT, '{id}');
        const chain = readConcat(expression, 0);
        if (!chain || chain.end !== expression.length) continue;
        suffix = chain.value;
        queryVars = chain.vars;
      } else if (/^this\.(hostServer|host)$/.test(first)) {
        field = first.slice(5);
        suffix = '';
      } else continue;
      const prefix = field === 'hostServer' ? '' : hostPath;
      if (prefix == null || suffix && !/^[/?]/.test(suffix)) continue;
      const value = suffix.startsWith('/') ? `${prefix.replace(/\/$/, '')}${suffix}` : `${prefix}${suffix}`;
      const target = toEndpoint(value, base);
      if (!target) continue;
      const method = call[1].toUpperCase();
      const sendsBody = ['POST', 'PUT', 'PATCH'].includes(method);
      const options = sendsBody ? args[2] ?? '' : args[1] ?? '';
      const body = sendsBody && args[1]?.startsWith('{') && args[1].endsWith('}') ?
        objectKeys(args[1].slice(1, -1)) : [];
      const bodyContract = sendsBody ? jsonBodyContract(args[1]) : null;
      const clientMethod = sendsBody && !bodyContract ?
        enclosingMethod(block.inner, call.index, args[1]?.trim()) : null;
      const endpoint = {path: target.path, method,
        params: unique([...target.params, ...searchParamKeys(block.inner, call.index, queryVars),
          ...body, ...keysOf(options, PARAMS_OBJECT),
          ...keysOf(options, JSON_BODY)]), examples: target.examples,
        headers: keysOf(options, HEADERS_OBJECT), line: lineOf(open + 1 + call.index),
        kind: 'callsite-inferred-base', ...(bodyContract ?? {}),
        ...(clientMethod ? {clientMethod, clientSymbol} : {})};
      if (found.length < INFERRED_CALLS_PER_FORM) found.push(endpoint);
      else routesCut++;
    }
  }
  const destinations = new Map(), symbolDestinations = new Map();
  for (const item of found) if (item.clientMethod) {
    const paths = destinations.get(item.clientMethod) ?? new Set();
    paths.add(item.path);
    destinations.set(item.clientMethod, paths);
    const key = `${item.clientSymbol}\0${item.clientMethod}`;
    const symbolPaths = symbolDestinations.get(key) ?? new Set();
    symbolPaths.add(item.path);
    symbolDestinations.set(key, symbolPaths);
  }
  for (const item of found) if (item.clientMethod) {
    const key = `${item.clientSymbol}\0${item.clientMethod}`;
    const receiverFields = symbolDestinations.get(key)?.size === 1 ?
      receiverCallers.get(key) : null;
    const fields = receiverFields ?? (destinations.get(item.clientMethod)?.size === 1 ?
      callers.get(item.clientMethod) : null);
    if (fields) {
      item.bodyEncoding = 'json';
      item.bodyFields = fields;
      item.bodyStringFields = [];
      item.fieldExamples = {};
      item.bodyEvidence = receiverFields ? 'same-file-receiver-object' :
        'same-file-caller-object';
    }
    delete item.clientMethod;
    delete item.clientSymbol;
  }
  return {endpoints: found, routesCut, classesCut};
}

function withoutShadowedUnknown(endpoints) {
  const known = new Set(endpoints.filter(endpoint => endpoint.method !== 'UNKNOWN').map(endpoint => endpoint.path));
  return endpoints.filter(endpoint => endpoint.method !== 'UNKNOWN' || !known.has(endpoint.path));
}

/** One endpoint per method and path (parameters and headers merged); UNKNOWN is dropped where a method is known. */
function mergeEndpoints(endpoints) {
  const byKey = new Map();
  for (const endpoint of endpoints) {
    const key = `${endpoint.method} ${endpoint.path}`;
    const seen = byKey.get(key);
    if (!seen) {
      byKey.set(key, {...endpoint, ...(endpoint.source ? {sources: [endpoint.source]} : {})});
      continue;
    }
    seen.params = unique([...seen.params, ...endpoint.params]);
    seen.headers = unique([...seen.headers, ...endpoint.headers]);
    if (endpoint.bodyEncoding) {
      seen.bodyEncoding = seen.bodyEncoding && seen.bodyEncoding !== endpoint.bodyEncoding ?
        'mixed' : endpoint.bodyEncoding;
      seen.bodyFields = unique([...(seen.bodyFields ?? []), ...(endpoint.bodyFields ?? [])]);
      seen.bodyStringFields = unique([...(seen.bodyStringFields ?? []), ...(endpoint.bodyStringFields ?? [])]);
      if (Object.keys(endpoint.bodyFieldTypes ?? {}).length)
        seen.bodyFieldTypes = {...(seen.bodyFieldTypes ?? {}), ...endpoint.bodyFieldTypes};
      if (Object.keys(endpoint.fieldShapes ?? {}).length)
        seen.fieldShapes = {...(seen.fieldShapes ?? {}), ...endpoint.fieldShapes};
      for (const [name, values] of Object.entries(endpoint.fieldValueExamples ?? {})) {
        seen.fieldValueExamples ??= {};
        seen.fieldValueExamples[name] = unique([...(seen.fieldValueExamples[name] ?? []), ...values])
          .slice(0, 3);
      }
      for (const [name, values] of Object.entries(endpoint.fieldExamples ?? {})) {
        seen.fieldExamples ??= {};
        seen.fieldExamples[name] = unique([...(seen.fieldExamples[name] ?? []), ...values]).slice(0, 4);
      }
      if (endpoint.bodyEvidence) seen.bodyEvidence = endpoint.bodyEvidence;
    }
    for (const [key, values] of Object.entries(endpoint.examples ?? {}))
      seen.examples[key] = unique([...(seen.examples[key] ?? []), ...values]).slice(0, 4);
    if (endpoint.source) seen.sources = unique([...(seen.sources ?? []), endpoint.source]).slice(0, 8);
  }
  return withoutShadowedUnknown([...byKey.values()]);
}

const URL_TEXT = /\b(https?|wss?):\/\/(?:[^\s\/@"'`<>]+@)?([a-z0-9](?:[a-z0-9.-]*[a-z0-9])?)(?::(\d+))?(\/[^\s"'`<>]*)?/gi;
const HOST_LITERAL = /(["'`])([a-z0-9-]+(?:\.[a-z0-9-]+)+)\1/gi;
const INTERNAL_HOST = /\.(?:internal|local|corp|lan|intranet|localdomain)$|^(?:10(?:\.\d{1,3}){3}|192\.168(?:\.\d{1,3}){2}|172\.(?:1[6-9]|2\d|3[01])(?:\.\d{1,3}){2}|169\.254(?:\.\d{1,3}){2})$/;
const FIREBASE_HOST = /\.(?:firebaseio|firebaseapp)\.com$|^firebasestorage\.googleapis\.com$/;
const SERVICE_HOST = /(?:^|\.)(?:supabase\.co|auth0\.com|okta\.com|oktapreview\.com|amazoncognito\.com|sentry\.io|segment\.(?:io|com)|google-analytics\.com|googletagmanager\.com|mixpanel\.com|amplitude\.com|algolia\.net|stripe\.com|intercom\.io)$|^cognito-idp\.[a-z0-9-]+\.amazonaws\.com$/;
const BUCKET_HOSTS = [ // [host pattern, capture group holding the bucket name, or 0 for the first path segment]
  [/^(.+)\.s3[.-](?:[a-z0-9-]+\.)?amazonaws\.com$/, 1],
  [/^s3[.-](?:[a-z0-9-]+\.)?amazonaws\.com$/, 0],
  [/^(.+)\.storage\.googleapis\.com$/, 1],
  [/^storage\.googleapis\.com$/, 0],
  [/^([a-z0-9]+)\.blob\.core\.windows\.net$/, 1],
  [/^[a-z0-9]+\.r2\.cloudflarestorage\.com$/, 0],
];
const IGNORED_HOSTS = new Set(['www.w3.org', 'w3.org', 'reactjs.org', 'react.dev', 'fb.me', 'schema.org']);
const ENVIRONMENT_LABEL = /^(?:staging|stage|stg|dev|develop|qa|uat|sandbox|preprod|preview)$/;

/** Kind of a host named in an asset: internal name or private address, storage bucket, Firebase, known service, WebSocket or plain URL. */
function classifyHost(host, scheme = 'https', path = '') {
  if (INTERNAL_HOST.test(host)) return {kind: 'internal'};
  for (const [pattern, group] of BUCKET_HOSTS) {
    const match = pattern.exec(host);
    if (match) return {kind: 'bucket', bucket: group ? match[group] : path.split('/')[1] || null};
  }
  if (FIREBASE_HOST.test(host)) return {kind: 'firebase'};
  if (SERVICE_HOST.test(host)) return {kind: 'service'};
  return {kind: /^wss?$/i.test(scheme) ? 'ws' : 'url'};
}

/** Hosts named in a source (every URL, plus bare internal, bucket and service names) and environment hints from those names. */
function hostsIn(source, base, lineOf) {
  const hosts = [], env = [];
  for (const match of source.matchAll(URL_TEXT)) {
    const [, scheme, name, port, path = ''] = match;
    const host = name.toLowerCase();
    if (IGNORED_HOSTS.has(host) || `${scheme}://${host}${port ? `:${port}` : ''}`.toLowerCase() === base) continue;
    if (loopback(host) || host.startsWith('127.')) {
      env.push({kind: 'environment', value: port ? `${host}:${port}` : host, line: lineOf(match.index)});
      continue;
    }
    hosts.push({host, ...classifyHost(host, scheme, path)});
    if (host.split(/[.-]/).some(label => ENVIRONMENT_LABEL.test(label))) env.push({kind: 'environment', value: host, line: lineOf(match.index)});
  }
  for (const match of source.matchAll(HOST_LITERAL)) {
    const host = match[2].toLowerCase();
    const named = classifyHost(host);
    if (named.kind !== 'url') hosts.push({host, ...named});
  }
  return {hosts, env};
}

const ENVIRONMENT_WORD = /(["'`])(staging|stage|dev|qa|uat|sandbox|preprod)\1/g;
const FLAG = /\b(is(?:Admin|SuperAdmin|Superuser|Staff|Internal|Debug|Beta)|enable[A-Z]\w*|debug(?:Mode|Enabled)|feature(?:Flags?|Toggles?))\b/g;
const CONSOLE_CALL = /\bconsole\.(?:log|debug|info|warn|error)\(([^()]*(?:\([^()]*\)[^()]*)*)\)/g;
const SENSITIVE_ARGUMENT = /\b(?:user|session|token|auth|password|request|req|response|res|headers|cookie|account|profile)\b/i;
const HIDDEN_SEGMENT = /^(?:admin|administrator|internal|debug|impersonate|superuser|sudo|staff|backoffice)$/i;

/** Environment names, feature flags and console logging of user or request data in a source. */
function envIn(source, lineOf) {
  const env = [];
  for (const match of source.matchAll(ENVIRONMENT_WORD)) env.push({kind: 'environment', value: match[2], line: lineOf(match.index)});
  for (const match of source.matchAll(FLAG)) env.push({kind: 'flag', value: match[1], line: lineOf(match.index)});
  for (const match of source.matchAll(CONSOLE_CALL)) {
    if (SENSITIVE_ARGUMENT.test(match[1])) env.push({kind: 'debug', value: match[0].slice(0, 160), line: lineOf(match.index)});
  }
  return env;
}

/** Endpoints whose path names an admin, internal, debug or impersonation area. */
function hiddenRoutes(endpoints) {
  return endpoints.filter(endpoint => endpoint.path.split('/').some(segment => HIDDEN_SEGMENT.test(segment)))
    .map(endpoint => ({kind: 'hidden-route', value: endpoint.path, line: endpoint.line}));
}

const BANNER = /\/\*[!*][\s*]*(?:@license\s+)?([A-Za-z][\w.-]*)\s+v?(\d+\.\d+\.\d+(?:-[\w.]+)?)/g;
const KNOWN_LIBRARY = /\b(jquery|react-dom|react|lodash|underscore|moment|axios|vue|angular|bootstrap|handlebars|dompurify|backbone|d3|socket\.io|core-js)(?:@|\/|\s+v?)(\d+\.\d+\.\d+)\b/gi;

/** Libraries and versions from banner comments and from versions adjacent to a known library name. */
function librariesIn(text, locate) {
  const found = [];
  for (const pattern of [BANNER, KNOWN_LIBRARY]) {
    for (const match of text.matchAll(pattern)) found.push({name: match[1].toLowerCase(), version: match[2], line: locate(match.index).line});
  }
  return uniqueBy(found, library => `${library.name}@${library.version}`);
}

const BLOCK_COMMENT = /(?<=^|[\s;{}(,])\/\*([\s\S]{0,2000}?)\*\//gm;
const LINE_COMMENT = /(?<=^|[\s;{}])\/\/(?![#@]\s*source)([^\n]*)/gm;
const NOTABLE = /\b(?:TODO|FIXME|HACK|XXX)\b|@author\b|[\w.+-]+@[\w-]+(?:\.[\w-]+)*\.[A-Za-z]{2,}\b|\b[A-Z][A-Z0-9]+-\d{2,}\b|\/(?:api|internal|admin)\//;

/** Comments that carry TODO notes, author emails, ticket numbers or route names. */
function commentsIn(text, locate) {
  const comments = [];
  for (const pattern of [BLOCK_COMMENT, LINE_COMMENT]) {
    for (const match of text.matchAll(pattern)) {
      const body = match[1].replace(/^\s*\*+/gm, '').replace(/\s+/g, ' ').trim();
      if (NOTABLE.test(body)) comments.push({text: body.slice(0, 200), line: locate(match.index).line});
    }
  }
  return comments.sort((a, b) => a.line - b.line);
}

const SOURCE_MAP_COMMENT = /^[ \t]*\/\/[#@][ \t]*sourceMappingURL[ \t]*=[ \t]*(\S+)/gm;

/** The script's last sourceMappingURL, resolved against its URL; null when absent or inline (data:). */
function sourceMapUrlOf(text, url) {
  const value = [...text.matchAll(SOURCE_MAP_COMMENT)].at(-1)?.[1];
  if (!value || /^data:/i.test(value)) return null;
  return url && URL.canParse(value, url) ? new URL(value, url).href : value;
}

/** Replaces any found secret value that reached another field (a comment, a path, a logged line) with its masked form. */
function withMaskedValues(result, values) {
  let json = JSON.stringify(result);
  for (const value of unique(values).sort((a, b) => b.length - a.length)) {
    json = json.split(JSON.stringify(value).slice(1, -1)).join(JSON.stringify(maskValue(value)).slice(1, -1));
  }
  return JSON.parse(json);
}

/**
 * Extracts endpoints (with method, parameters, headers, line and kind), hosts, secrets, libraries, environment
 * leakage, the source map URL and notable comments from one script. `origin` decides which absolute URLs are
 * endpoints. Secret values are never returned: each secret carries a masked form and a SHA-256.
 */
export function extractFromScript(text, {url = null, origin = null,
  maxRouteHints = ROUTE_HINTS_PER_FILE} = {}) {
  const base = origin || url ? new URL(origin || url).origin : null;
  const locate = locator(text);
  const {code, decoded} = normalizeParts(text);
  const locateCode = locator(code);
  const sources = [
    {source: code, lineOf: offset => locateCode(offset).line},
    ...decoded.map(block => ({source: block.text, lineOf: () => locate(block.offset).line})),
  ];
  const found = [
    ...scanSecrets(text).map(match => ({...match, ...locate(match.start)})),
    ...decoded.flatMap(block => scanSecrets(block.text).map(match => ({...match, ...locate(block.offset)}))),
  ];
  const directHostRoutes = inferredHostServerGets(text, base, offset => locate(offset).line);
  const classRoutes = inferredClassClientRoutes(text, base, offset => locate(offset).line);
  const endpoints = mergeEndpoints([
    ...sources.flatMap(({source, lineOf}) => endpointsIn(source, base, lineOf)),
    ...directHostRoutes.endpoints,
    ...classRoutes.endpoints,
  ]);
  const generated = generatedRequestHints(text);
  const generatedHints = generated.hints.map(hint => ({kind: 'generated-client', method: hint.method,
    line: hint.line, literals: [hint.path],
    excerpt: maskExcerpt(maskSecrets([
      generated.hostCandidates.length ? `Host config: ${generated.hostCandidates.join(', ')}` : '',
      hint.caller, hint.excerpt, hint.transport, ...generated.hostContext,
    ].filter(Boolean).join(' '))).slice(0, 900)}));
  const routeHints = routeHintsIn(text, Math.max(0, maxRouteHints - generatedHints.length));
  const allHints = [...generatedHints, ...routeHints.hints].slice(0, maxRouteHints)
    .map((hint, index) => ({...hint, id: `h${index + 1}`}));
  const named = sources.map(({source, lineOf}) => hostsIn(source, base, lineOf));
  const env = [...named.flatMap(item => item.env), ...sources.flatMap(({source, lineOf}) => envIn(source, lineOf)), ...hiddenRoutes(endpoints)];
  const result = {
    endpoints,
    inferredRoutesCut: directHostRoutes.cut + classRoutes.routesCut,
    inferredClassesCut: classRoutes.classesCut,
    routeHints: allHints,
    routeHintsCut: routeHints.cut + Math.max(0, generatedHints.length - maxRouteHints),
    hosts: uniqueBy(named.flatMap(item => item.hosts), host => `${host.kind} ${host.host}`),
    secrets: uniqueBy(found.map(secretRecord), secret => secret.hash),
    libraries: librariesIn(text, locate),
    env: uniqueBy(env, item => `${item.kind} ${item.value}`),
    sourceMapUrl: sourceMapUrlOf(text, url),
    comments: commentsIn(text, locate),
    domSignals: {
      fragmentSource: sources.some(({source}) => /\b(?:window\.)?location\s*(?:\.\s*hash|\[\s*['"]hash['"]\s*\])/i.test(source)),
      htmlSink: sources.some(({source}) => /\b(?:innerHTML|outerHTML|insertAdjacentHTML|document\s*\.\s*write)\b/i.test(source)),
    },
  };
  return withMaskedValues(result, found.map(match => match.value));
}

const SCRIPT_TAG = /<script\b([^>]*)>([\s\S]*?)<\/script\s*>/gi;
const LINK_TAG = /<link\b([^>]*)>/gi;
const ANCHOR_TAG = /<a\b([^>]*)>/gi;
const FORM_TAG = /<form\b([^>]*)>([\s\S]*?)<\/form\s*>/gi;
const FORM_CONTROL = /<(input|select|textarea|button)\b([^>]*)>/gi;
const ATTRIBUTE = /([^\s=\/>"']+)(?:\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s>"']+)))?/g;
const JAVASCRIPT_TYPE = /^(?:module|(?:text|application)\/(?:x-)?(?:java|ecma)script)\b/i;
const INITIAL_STATE = /__INITIAL_STATE__\s*=\s*\{/;

function attributesOf(text) {
  const attributes = {};
  for (const [, name, double, single, bare] of text.matchAll(ATTRIBUTE)) attributes[name.toLowerCase()] = (double ?? single ?? bare ?? '').replaceAll('&amp;', '&');
  return attributes;
}

/** An absolute http(s) or ws(s) URL without fragment; null for empty, fragment-only, script, mail, phone and data links. */
function absoluteUrl(href, base) {
  if (!href || /^\s*(?:#|(?:javascript|mailto|tel|data):)/i.test(href) || !URL.canParse(href, base)) return null;
  const resolved = new URL(href, base);
  resolved.hash = '';
  return /^(?:https?|wss?):$/.test(resolved.protocol) ? resolved.href : null;
}

function addOnce(list, value) {
  if (value && !list.includes(value)) list.push(value);
}

/** Script, module-preload and link URLs (absolute), inline scripts, and parsed inline JSON (__NEXT_DATA__, __INITIAL_STATE__). */
export function extractFromHtml(text, {url} = {}) {
  const page = {scripts: [], links: [], inline: [], json: [], modulepreload: [], forms: []};
  for (const [, raw, body] of text.matchAll(SCRIPT_TAG)) {
    const attributes = attributesOf(raw);
    const type = attributes.type ?? '';
    if (attributes.src) {
      addOnce(page.scripts, absoluteUrl(attributes.src, url));
    } else if (/json/i.test(type)) {
      const value = /ld\+json/i.test(type) ? undefined : parseJson(body.trim());
      if (value !== undefined) page.json.push(value);
    } else if ((!type || JAVASCRIPT_TYPE.test(type)) && body.trim()) {
      page.inline.push(body);
      const state = INITIAL_STATE.exec(body);
      const object = state && readBalanced(body, state.index + state[0].length - 1, body.length);
      const value = object ? parseJson(`{${object.inner}}`) : undefined;
      if (value !== undefined) page.json.push(value);
    }
  }
  for (const [, raw] of text.matchAll(LINK_TAG)) {
    const attributes = attributesOf(raw);
    const rel = (attributes.rel ?? '').toLowerCase().split(/\s+/);
    const preload = rel.includes('modulepreload') || (rel.includes('preload') && attributes.as === 'script');
    addOnce(preload ? page.modulepreload : page.links, absoluteUrl(attributes.href, url));
  }
  for (const [, raw] of text.matchAll(ANCHOR_TAG)) addOnce(page.links, absoluteUrl(attributesOf(raw).href, url));
  if (url) for (const [, raw, body] of text.matchAll(FORM_TAG)) {
    const attributes = attributesOf(raw);
    const action = attributes.action && !attributes.action.startsWith('#') ?
      absoluteUrl(attributes.action, url) : absoluteUrl(url, url);
    if (!action || !['http:', 'https:'].includes(new URL(action).protocol)) continue;
    const method = String(attributes.method ?? 'GET').toUpperCase();
    if (method === 'DIALOG') continue;
    const fields = [], requiredFields = [];
    for (const [, tag, rawControl] of body.matchAll(FORM_CONTROL)) {
      const control = attributesOf(rawControl);
      const type = String(control.type ?? '').toLowerCase();
      if (!control.name || 'disabled' in control ||
          ['submit', 'button', 'reset', 'image'].includes(type) ||
          tag.toLowerCase() === 'button') continue;
      addOnce(fields, control.name);
      if ('required' in control) addOnce(requiredFields, control.name);
    }
    const contentType = String(attributes.enctype ?? 'application/x-www-form-urlencoded')
      .split(';', 1)[0].trim().toLowerCase();
    page.forms.push({action, method: method === 'POST' ? 'POST' : 'GET',
      contentType, fields, requiredFields});
  }
  return page;
}

const NPM_NAMES = {angularjs: 'angular', 'vue.js': 'vue', 'moment.js': 'moment', 'lo-dash': 'lodash'};

/** The OSV query key for a detected library: the npm ecosystem, the npm package name and a version without a 'v'. */
export function libraryAdvisoryKey(library) {
  const name = String(library.name).toLowerCase();
  return {ecosystem: 'npm', name: NPM_NAMES[name] ?? name, version: String(library.version).replace(/^v/i, '')};
}

const SCRIPT_REFERENCE = /(["'`])((?:https?:\/\/[^"'`\s]+?|\.{0,2}\/[^"'`\s]*?)\.m?js(?:\?[^"'`\s]*)?)\1/g;

/** Absolute URLs of script files named by string literals: dynamic imports, chunk paths, script URLs. */
function scriptRefs(text, url) {
  return [...text.matchAll(SCRIPT_REFERENCE)].map(match => absoluteUrl(match[2], url)).filter(Boolean);
}

const looksLikeHtml = response => /text\/html/i.test(response.type ?? response.headers?.['content-type'] ?? '') || /^\s*<(?:!doctype|html)\b/i.test(response.body ?? '');
const withinBudget = miner => miner.assets < miner.maxFiles && miner.bytes < miner.maxTotal;

function siblingMapUrl(url) {
  const map = new URL(url);
  map.search = '';
  map.hash = '';
  map.pathname += '.map';
  return map.href;
}

/**
 * One anonymous GET through the guarded requester with purpose 'asset' (the scope admits discover documents and
 * same-origin scripts and maps for it, and the ledger stores no excerpt of the body, which may hold a key).
 * Script and map requests pass `maxBytes` and count against maxFiles; pages keep the requester's default cap.
 * Refused and blocked results are logged and give null.
 */
async function request(miner, url, {accept, maxBytes}) {
  if (maxBytes) miner.assets++;
  let allowance = null;
  if (maxBytes) {
    // A response can consume at most its reserved share of the shared byte
    // budget. Wait for in-flight peers to release unused shares before deciding
    // that the budget is exhausted.
    for (;;) {
      const available = miner.maxTotal - miner.bytes - miner.reservedBytes;
      if (available > 0) {
        allowance = Math.min(maxBytes, available);
        miner.reservedBytes += allowance;
        miner.activeByteRequests++;
        break;
      }
      if (!miner.activeByteRequests) {
        miner.byteBudgetCuts++;
        return {budgetCut: true};
      }
      await new Promise(resolve => miner.byteWaiters.push(resolve));
    }
  }
  try {
    const response = await miner.requester({url, identity: 'anonymous', step: 'recon',
      purpose: 'asset', ...(maxBytes ? {maxBytes: allowance} : {}),
      headers: {accept}});
    if (response.refused || response.blocked) {
      miner.log({stage: 'assets', message: `${response.refused ? 'refused' : 'blocked'} ${url}: ${response.reason}`, url, reason: response.reason, evidenceId: response.evidenceId});
      return null;
    }
    const bytes = Buffer.byteLength(response.body ?? '');
    if (allowance != null && bytes > allowance) {
      // The guarded requester normally enforces maxBytes. Keep the aggregate
      // cap even if an injected requester violates that contract.
      miner.bytes += allowance;
      miner.byteBudgetCuts++;
      miner.log({stage: 'assets', message: `blocked ${url}: asset byte budget exceeded`,
        url, reason: 'asset-byte-budget', evidenceId: response.evidenceId});
      return null;
    }
    miner.bytes += bytes;
    return response;
  } finally {
    if (allowance != null) {
      miner.reservedBytes -= allowance;
      miner.activeByteRequests--;
      for (const wake of miner.byteWaiters.splice(0)) wake();
    }
  }
}

/** An off-origin static file may be fetched only from an exact host listed by the operator. */
function approvedAsset(miner, url) {
  return url.origin === miner.base || (miner.assetHosts.has(url.hostname) && /\.(?:js|mjs|map)$/.test(url.pathname));
}

/** Queues a script once. Other third-party scripts are logged and never fetched. */
function enqueue(miner, url, level, foundBy) {
  const target = new URL(url);
  target.hash = '';
  if (miner.seen.has(target.href)) return;
  miner.seen.add(target.href);
  if (!approvedAsset(miner, target)) {
    miner.log({stage: 'assets', message: `off-origin script not fetched: ${target.href}`, url: target.href});
    return;
  }
  miner.queue.push({url: target.href, level, foundBy});
}

/** A mined file: URL, size, content hash, how it was found, its evidence ID and everything extracted from it. */
function fileRecord(miner, url, response, foundBy, contentHash = digest(response.body)) {
  const record = {url, bytes: Buffer.byteLength(response.body), hash: contentHash, foundBy, evidenceId: response.evidenceId,
    ...extractFromScript(response.body, {url, origin: miner.base}), sourceMap: 'absent'};
  if (foundBy !== 'page') attachModelSource(record, [{name: url, text: response.body}]);
  return record;
}

// Keep source text available to Muse during this run without adding bundle content to saved assets.json.
function attachModelSource(record, sources) {
  const modelSource = sources.filter(item => typeof item?.text === 'string' && item.text.trim())
    .map(item => ({name: item.name, text: item.text}));
  if (modelSource.length) Object.defineProperty(record, 'modelSource', {value: modelSource});
}

function sourceName(value) {
  if (typeof value !== 'string') return '[invalid source]';
  const name = value.split(/[?#]/, 1)[0];
  return name.length <= 300 && !/[\x00-\x1f\x7f]/.test(name) && maskSecrets(name) === name ?
    name : '[redacted]';
}

/** Only literal public URLs can recover a missing original. webpack:// and similar names are virtual. */
export function publicSourceUrl(map, index, mapUrl, origin) {
  const source = map.sources?.[index];
  const root = typeof map.sourceRoot === 'string' ? map.sourceRoot : '';
  if (typeof source !== 'string' || source.length > 1000 ||
      maskSecrets(source) !== source || maskSecrets(root) !== root) return null;
  if (/^[a-z][a-z0-9+.-]*:/i.test(source) && !/^https?:\/\//i.test(source)) return null;
  let literal = source;
  if (!/^https?:\/\//i.test(literal) && !literal.startsWith('/')) {
    // Relative source names without a virtual sourceRoot resolve beside the
    // map. A sourceRoot may also name a public directory on this origin.
    if (root) {
      if (root.startsWith('//') ||
          (/^[a-z][a-z0-9+.-]*:/i.test(root) && !/^https?:\/\//i.test(root)))
        return null;
      const directoryReference = root.endsWith('/') ? root : `${root}/`;
      if (!URL.canParse(directoryReference, mapUrl)) return null;
      const directory = new URL(directoryReference, mapUrl);
      if (directory.origin !== origin || directory.search || directory.hash) return null;
      if (!URL.canParse(literal, directory)) return null;
      literal = new URL(literal, directory).href;
    }
  }
  if (literal.startsWith('//') || !URL.canParse(literal, mapUrl)) return null;
  const url = new URL(literal, mapUrl);
  if (url.origin !== origin || url.username || url.password || url.search || url.hash) return null;
  return url.href;
}

/** Inspect every embedded original, with application entries before dependencies. */
export function selectedSourceMapEntries(map) {
  if (!Array.isArray(map?.sources)) return [];
  const entries = map.sources.map((rawSource, index) => ({
    index, source: sourceName(rawSource),
    kind: sourceMapKind(rawSource),
    hasContent: typeof map.sourcesContent?.[index] === 'string',
  })).filter(entry => entry.hasContent);
  const rank = {appLikely: 0, namespace: 1, vendor: 2};
  return entries.sort((a, b) => rank[a.kind] - rank[b.kind] || a.index - b.index);
}

/** A source map's file record: its sources and what its sourcesContent yields, each item tagged with its source file. */
function sourceMapRecord(miner, url, response, map, scriptUrl) {
  // The fetched map is byte-bounded. Inspect every embedded original, with
  // application entries first; preserve each index into sourcesContent.
  const selected = selectedSourceMapEntries(map);
  const count = (kind, embedded) => map.sources.filter((source, index) =>
    sourceMapKind(source) === kind &&
      (typeof map.sourcesContent?.[index] === 'string') === embedded).length;
  const appLikelySelected = selected.filter(entry => entry.kind === 'appLikely').length;
  const namespaceSelected = selected.filter(entry => entry.kind === 'namespace').length;
  const vendorSelected = selected.filter(entry => entry.kind === 'vendor').length;
  const appLikelyAvailable = count('appLikely', true);
  const namespaceAvailable = count('namespace', true);
  const vendorAvailable = count('vendor', true);
  const appLikelyUnavailable = count('appLikely', false);
  const namespaceUnavailable = count('namespace', false);
  const vendorUnavailable = count('vendor', false);
  const record = {url, bytes: Buffer.byteLength(response.body), hash: digest(response.body), foundBy: `sourcemap:${new URL(scriptUrl).pathname}`,
    evidenceId: response.evidenceId, sources: selected.map(entry => entry.source),
    sourcesCut: Math.max(0, map.sources.length - selected.length),
    sourceSelection: {appLikelySelected, appLikelyCut: appLikelyAvailable - appLikelySelected,
      appLikelyUnavailable, vendorSelected, vendorCut: vendorAvailable - vendorSelected,
      vendorUnavailable, ...(namespaceAvailable || namespaceUnavailable ? {
        namespaceSelected, namespaceCut: namespaceAvailable - namespaceSelected,
        namespaceUnavailable} : {})},
    endpoints: [], routeHints: [], routeHintsCut: 0, inferredRoutesCut: 0,
    inferredClassesCut: 0,
    hosts: [], secrets: [], libraries: [], env: [], comments: [], sourceMapUrl: null};
  selected.forEach(({index, source}) => {
    const content = map.sourcesContent?.[index];
    if (typeof content !== 'string') return;
    const found = extractFromScript(content, {url, origin: miner.base,
      maxRouteHints: Number.POSITIVE_INFINITY});
    for (const key of ['endpoints', 'secrets', 'libraries', 'env', 'comments']) record[key].push(...found[key].map(item => ({...item, source})));
    record.routeHintsCut += found.routeHintsCut ?? 0;
    record.inferredRoutesCut += found.inferredRoutesCut ?? 0;
    record.inferredClassesCut += found.inferredClassesCut ?? 0;
    for (const hint of found.routeHints ?? [])
      record.routeHints.push({...hint, id: `h${record.routeHints.length + 1}`, source});
    record.hosts.push(...found.hosts);
  });
  record.endpoints = mergeEndpoints(record.endpoints);
  record.hosts = uniqueBy(record.hosts, host => `${host.kind} ${host.host}`);
  record.secrets = uniqueBy(record.secrets, secret => secret.hash);
  attachModelSource(record, selected.map(({index, source}) =>
    ({name: source, text: map.sourcesContent?.[index]})));
  miner.sourceMapSourcesCut += record.sourcesCut;
  return record;
}

/** Fetches a script's source map; a budget skip is distinct from an absent map. */
async function mineSourceMap(miner, scriptUrl, declared) {
  let status = 'absent', budgetCut = false;
  for (const candidate of unique([declared, siblingMapUrl(scriptUrl)].filter(Boolean))) {
    if (!URL.canParse(candidate) || !approvedAsset(miner, new URL(candidate))) {
      status = 'off-origin';
      continue;
    }
    if (miner.seen.has(candidate)) continue;
    if (!withinBudget(miner)) {
      budgetCut = true;
      continue;
    }
    miner.seen.add(candidate);
    const response = await request(miner, candidate, {accept: ACCEPT_MAP, maxBytes: miner.maxBytes});
    if (response?.budgetCut) {budgetCut = true; continue;}
    const map = response?.status === 200 ? parseJson(response.body) : undefined;
    if (!Array.isArray(map?.sources) || typeof map.mappings !== 'string') continue;
    const record = sourceMapRecord(miner, candidate, response, map, scriptUrl);
    miner.files.push(record);
    const summary = {url: candidate, script: scriptUrl, sources: record.sources,
      evidenceId: response.evidenceId, ...(record.sourcesCut ? {sourcesCut: record.sourcesCut} : {})};
    miner.sourceMaps.push(summary);
    for (let index = 0; index < map.sources.length; index++) {
      if (typeof map.sourcesContent?.[index] === 'string') continue;
      const originalUrl = publicSourceUrl(map, index, candidate, miner.base);
      if (!originalUrl) {
        miner.sourceMapOriginalsUnresolvable++;
        continue;
      }
      const targets = miner.originals.get(originalUrl) ?? [];
      targets.push({record, summary, source: sourceName(map.sources[index]),
        kind: sourceMapKind(map.sources[index])});
      miner.originals.set(originalUrl, targets);
    }
    return 'exposed';
  }
  if (budgetCut) {
    miner.sourceMapBudgetCut++;
    miner.log({stage: 'assets', message: 'source map not fetched within asset budget',
      script: new URL(scriptUrl).pathname, reason: 'asset-budget'});
    return 'budget-cut';
  }
  return status;
}

/** After primary assets, recover originals named by literal same-origin URLs in source maps. */
async function minePublicOriginals(miner) {
  for (const [url, targets] of miner.originals) {
    // A page or map at the same URL is not a recovered JavaScript original.
    let available = miner.files.some(file => file.url === url &&
      file.foundBy !== 'page' && !file.foundBy.startsWith('sourcemap:'));
    if (!available) {
      if (!withinBudget(miner)) {
        miner.sourceMapOriginalsBudgetCut += targets.length;
        continue;
      }
      miner.seen.add(url);
      miner.sourceMapOriginalsAttempted += targets.length;
      let response;
      try { response = await request(miner, url, {accept: ACCEPT_SCRIPT, maxBytes: miner.maxBytes}); }
      catch { /* Count a failed public-original fetch below. */ }
      if (response?.budgetCut) {
        miner.sourceMapOriginalsBudgetCut += targets.length;
        continue;
      }
      if (response?.status === 200 && typeof response.body === 'string' && !looksLikeHtml(response)) {
        available = true;
        const contentHash = digest(response.body);
        if (!miner.hashes.has(contentHash)) {
          miner.hashes.add(contentHash);
          const file = fileRecord(miner, url, response, `sourcemap-original:${new URL(targets[0].summary.url).pathname}`,
            contentHash);
          file.source = targets[0].source;
          for (const key of ['endpoints', 'secrets', 'libraries', 'env', 'comments'])
            file[key] = file[key].map(item => ({...item, source: file.source}));
          miner.files.push(file);
        }
      }
      if (!available) miner.sourceMapOriginalsFetchFailed += targets.length;
    }
    if (!available) continue;
    for (const {record, summary, source, kind} of targets) {
      record.sources.push(source);
      record.sourcesCut--;
      miner.sourceMapSourcesCut--;
      record.sourceSelection[`${kind}Selected`]++;
      record.sourceSelection[`${kind}Unavailable`]--;
      summary.sources = record.sources;
      if (record.sourcesCut) summary.sourcesCut = record.sourcesCut;
      else delete summary.sourcesCut;
      miner.sourceMapOriginalsRecovered++;
    }
  }
}

async function minePage(miner, url) {
  need(new URL(url).origin === miner.base, `Page ${url} is not on ${miner.base}.`);
  if (miner.seen.has(url)) return;
  miner.seen.add(url);
  const response = await request(miner, url, {accept: ACCEPT_HTML});
  if (response?.status !== 200) return;
  const html = extractFromHtml(response.body, {url});
  const record = fileRecord(miner, url, response, 'page');
  attachModelSource(record, html.inline.map((text, index) =>
    ({name: `${url}#inline-${index + 1}`, text})));
  for (const form of html.forms) {
    const action = new URL(form.action);
    if (action.origin !== miner.base) continue;
    const params = [...new Set([...action.searchParams.keys(),
      ...(form.method === 'GET' ? form.fields : [])])];
    const endpoint = {path: action.pathname, method: form.method, params,
      headers: [], source: 'public-html'};
    if (form.method === 'POST') {
      endpoint.bodyEncoding = form.contentType === 'application/x-www-form-urlencoded' ?
        'form' : form.contentType === 'multipart/form-data' ? 'multipart' : 'raw';
      endpoint.contentType = form.contentType;
      endpoint.bodyFields = form.fields;
      endpoint.bodyStringFields = form.fields;
      endpoint.bodyRequiredFields = form.requiredFields;
    }
    record.endpoints.push(endpoint);
  }
  record.scripts = html.scripts.filter(script => new URL(script).origin === miner.base).slice(0, 8);
  record.scriptCut = Math.max(0, html.scripts.length - record.scripts.length);
  miner.files.push(record);
  const foundBy = `page:${new URL(url).pathname}`;
  for (const script of [...html.scripts, ...html.modulepreload, ...scriptRefs(response.body, url)]) enqueue(miner, script, 1, foundBy);
  if (!miner.crawlPaths.length || !/html/i.test(response.type ?? response.headers?.['content-type'] ?? '')) return;
  const depth = miner.pageDepth.get(url) ?? 0;
  if (depth >= miner.maxPageDepth) return;
  const candidates = html.links.filter(link => {
    const target = new URL(link);
    return target.origin === miner.base && !target.search && PAGE_PATH.test(target.pathname) &&
      pathAllowed(target.pathname, miner.crawlPaths) && !miner.queuedPages.has(target.href);
  });
  miner.pageCut += Math.max(0, candidates.length - miner.maxLinksPerPage);
  for (const link of candidates.slice(0, miner.maxLinksPerPage)) {
    miner.queuedPages.add(link);
    miner.pageDepth.set(link, depth + 1);
    miner.pageQueue.push(link);
  }
}

async function mineScript(miner, item) {
  const response = await request(miner, item.url, {accept: ACCEPT_SCRIPT, maxBytes: miner.maxBytes});
  if (response?.status !== 200 || looksLikeHtml(response)) return;
  const contentHash = digest(response.body);
  if (miner.hashes.has(contentHash)) return; // the same content was already mined under another URL
  miner.hashes.add(contentHash);
  const record = fileRecord(miner, item.url, response, item.foundBy, contentHash);
  miner.files.push(record);
  record.sourceMap = await mineSourceMap(miner, item.url, record.sourceMapUrl);
  if (item.level >= miner.depth) return;
  const foundBy = `chunk:${new URL(item.url).pathname}`;
  for (const reference of scriptRefs(response.body, item.url)) enqueue(miner, reference, item.level + 1, foundBy);
}

/** The aggregate entry for `key`, created from `item` on first sight, with `file` added to its files. */
function collect(map, key, item, file) {
  if (!map.has(key)) map.set(key, {...item, files: []});
  const entry = map.get(key);
  if (!entry.files.includes(file)) entry.files.push(file);
  return entry;
}

/** The MinedSummary: the file records plus endpoints, hosts, secrets and libraries deduplicated across files. */
function summarize(miner) {
  const endpoints = new Map(), hosts = new Map(), secrets = new Map(), libraries = new Map();
  for (const file of miner.files) {
    for (const endpoint of file.endpoints) {
      const entry = collect(endpoints, `${endpoint.method} ${endpoint.path}`, {path: endpoint.path, method: endpoint.method,
        params: [], headers: []}, file.url);
      entry.params = unique([...entry.params, ...endpoint.params]);
      entry.headers = unique([...entry.headers, ...endpoint.headers]);
      if (endpoint.bodyEncoding) {
        entry.bodyEncoding = entry.bodyEncoding && entry.bodyEncoding !== endpoint.bodyEncoding ?
          'mixed' : endpoint.bodyEncoding;
        if (endpoint.contentType) entry.contentType = endpoint.contentType;
        entry.bodyFields = unique([...(entry.bodyFields ?? []), ...(endpoint.bodyFields ?? [])]);
        entry.bodyStringFields = unique([...(entry.bodyStringFields ?? []), ...(endpoint.bodyStringFields ?? [])]);
        if (endpoint.bodyRequiredFields?.length) entry.bodyRequiredFields =
          unique([...(entry.bodyRequiredFields ?? []), ...endpoint.bodyRequiredFields]);
        if (Object.keys(endpoint.bodyFieldTypes ?? {}).length)
          entry.bodyFieldTypes = {...(entry.bodyFieldTypes ?? {}), ...endpoint.bodyFieldTypes};
        if (Object.keys(endpoint.fieldShapes ?? {}).length)
          entry.fieldShapes = {...(entry.fieldShapes ?? {}), ...endpoint.fieldShapes};
        for (const [name, values] of Object.entries(endpoint.fieldValueExamples ?? {})) {
          entry.fieldValueExamples ??= {};
          entry.fieldValueExamples[name] = unique([...(entry.fieldValueExamples[name] ?? []), ...values])
            .slice(0, 3);
        }
        for (const [name, values] of Object.entries(endpoint.fieldExamples ?? {})) {
          entry.fieldExamples ??= {};
          entry.fieldExamples[name] = unique([...(entry.fieldExamples[name] ?? []), ...values]).slice(0, 4);
        }
        if (endpoint.bodyEvidence) entry.bodyEvidence = endpoint.bodyEvidence;
      }
      if (endpoint.kind === 'callsite-inferred-base') entry.inferredBase = true;
      const sources = endpoint.sources ?? (endpoint.source ? [endpoint.source] : []);
      if (sources.length) entry.sources = unique([...(entry.sources ?? []), ...sources]).slice(0, 8);
      for (const [key, values] of Object.entries(endpoint.examples ?? {})) {
        entry.examples ??= {};
        entry.examples[key] = unique([...(entry.examples[key] ?? []), ...values]).slice(0, 4);
      }
    }
    for (const host of file.hosts) collect(hosts, `${host.kind} ${host.host}`, host, file.url);
    for (const secret of file.secrets) collect(secrets, secret.hash, {...secret, url: file.url}, file.url);
    for (const library of file.libraries) collect(libraries, `${library.name}@${library.version}`, {name: library.name, version: library.version}, file.url);
  }
  const namespacedUnavailable = miner.files.reduce((count, file) =>
    count + (file.sourceSelection?.namespaceUnavailable ?? 0), 0);
  const appUnavailable = miner.files.reduce((count, file) =>
    count + (file.sourceSelection?.appLikelyUnavailable ?? 0), 0);
  const vendorUnavailable = miner.files.reduce((count, file) =>
    count + (file.sourceSelection?.vendorUnavailable ?? 0), 0);
  return {files: miner.files, endpoints: withoutShadowedUnknown([...endpoints.values()]), hosts: [...hosts.values()], secrets: [...secrets.values()],
    libraries: [...libraries.values()], sourceMaps: miner.sourceMaps,
    stats: {files: miner.files.length, bytes: miner.bytes, pages: miner.pagesVisited,
      pagesCut: miner.pageCut, sourceMapSourcesCut: miner.sourceMapSourcesCut,
      sourceMapBudgetCut: miner.sourceMapBudgetCut,
      ...(miner.byteBudgetCuts ? {assetByteBudgetCuts: miner.byteBudgetCuts} : {}),
      ...(miner.sourceMapOriginalsAttempted ?
        {sourceMapOriginalsAttempted: miner.sourceMapOriginalsAttempted} : {}),
      ...(miner.sourceMapOriginalsRecovered ?
        {sourceMapOriginalsRecovered: miner.sourceMapOriginalsRecovered} : {}),
      ...(miner.sourceMapOriginalsBudgetCut ?
        {sourceMapOriginalsBudgetCut: miner.sourceMapOriginalsBudgetCut} : {}),
      ...(miner.sourceMapOriginalsUnresolvable ?
        {sourceMapOriginalsUnresolvable: miner.sourceMapOriginalsUnresolvable} : {}),
      ...(miner.sourceMapOriginalsFetchFailed ?
        {sourceMapOriginalsFetchFailed: miner.sourceMapOriginalsFetchFailed} : {}),
      sourceMapAppSourcesSelected: miner.files.reduce((count, file) =>
        count + (file.sourceSelection?.appLikelySelected ?? 0), 0),
      sourceMapAppSourcesCut: miner.files.reduce((count, file) =>
        count + (file.sourceSelection?.appLikelyCut ?? 0), 0),
      ...(appUnavailable ? {sourceMapAppSourcesUnavailable: appUnavailable} : {}),
      sourceMapVendorSourcesSelected: miner.files.reduce((count, file) =>
        count + (file.sourceSelection?.vendorSelected ?? 0), 0),
      sourceMapVendorSourcesCut: miner.files.reduce((count, file) =>
        count + (file.sourceSelection?.vendorCut ?? 0), 0),
      ...(vendorUnavailable ? {sourceMapVendorSourcesUnavailable: vendorUnavailable} : {}),
      ...(namespacedUnavailable ? {sourceMapNamespacedSourcesUnavailable: namespacedUnavailable} : {}),
      routeHintsCut: miner.files.reduce((count, file) => count + (file.routeHintsCut ?? 0), 0),
      inferredRoutesCut: miner.files.reduce((count, file) => count + (file.inferredRoutesCut ?? 0), 0),
      inferredClassesCut: miner.files.reduce((count, file) => count + (file.inferredClassesCut ?? 0), 0)}};
}

/**
 * Mines one origin's JavaScript (design 5.4 collection, 6.3): fetches `pages` as HTML, their same-origin or
 * operator-approved asset-host scripts
 * and module preloads, chunks named inside scripts one level per `depth`, and each script's source map. Linked
 * same-origin HTML pages are followed only under `crawlPaths`, up to `maxPages` and `maxPageDepth`. Every
 * request goes through `requester` as the anonymous identity; other third-party scripts are never fetched. Bounded
 * by `maxFiles` asset requests, `maxBytes` per file and `maxTotal` bytes. Returns the MinedSummary.
 */
export async function mineOrigin(origin, {requester, pages = ['/'], assetHosts = [], crawlPaths = [],
  maxPages = 30, maxPageDepth = 3, maxLinksPerPage = 50, maxFiles = 60, maxBytes = 16 * 1024 * 1024,
  maxTotal = 64 * 1024 * 1024, depth = 3, workers = 1, log = () => {}} = {}) {
  need(typeof requester === 'function', 'mineOrigin needs a requester function.');
  need(Number.isInteger(maxPages) && maxPages >= 1 && maxPages <= 30, 'maxPages must be a whole number from 1 to 30.');
  need(Number.isInteger(maxPageDepth) && maxPageDepth >= 0 && maxPageDepth <= 5,
    'maxPageDepth must be a whole number from 0 to 5.');
  need(Number.isInteger(maxLinksPerPage) && maxLinksPerPage >= 1 && maxLinksPerPage <= 50,
    'maxLinksPerPage must be a whole number from 1 to 50.');
  need(Array.isArray(crawlPaths) && crawlPaths.every(path => typeof path === 'string' && path.startsWith('/')),
    'crawlPaths must be a list of allowed path prefixes.');
  const base = new URL(origin).origin;
  const pageQueue = unique(pages.map(page => new URL(page, base).href));
  const miner = {base, requester, assetHosts: new Set(assetHosts), crawlPaths, maxPages, maxPageDepth, maxLinksPerPage,
    maxFiles, maxBytes, maxTotal, depth, log, files: [], sourceMaps: [], queue: [], originals: new Map(),
    seen: new Set(), hashes: new Set(),
    assets: 0, bytes: 0, pageQueue, queuedPages: new Set(pageQueue), pageDepth: new Map(), pagesVisited: 0,
    pageCut: 0, sourceMapSourcesCut: 0, sourceMapBudgetCut: 0,
    sourceMapOriginalsAttempted: 0, sourceMapOriginalsRecovered: 0,
    sourceMapOriginalsBudgetCut: 0, sourceMapOriginalsUnresolvable: 0,
    sourceMapOriginalsFetchFailed: 0, reservedBytes: 0,
    activeByteRequests: 0, byteWaiters: [], byteBudgetCuts: 0};
  const scriptWorkers = Number.isInteger(workers) && workers > 0 ? workers : 1;
  while (miner.pageQueue.length && miner.pagesVisited < maxPages && miner.bytes < miner.maxTotal) {
    const page = miner.pageQueue.shift();
    miner.pagesVisited++;
    await minePage(miner, page);
    // A page's scripts take priority over lower-value linked pages when request budgets are tight.
    while (miner.queue.length && withinBudget(miner)) {
      // Reserve script request slots before awaits. A slow script or map must
      // not hold up unrelated bundles, while maps still follow their script.
      const remainingBytes = Math.max(0, miner.maxTotal - miner.bytes - miner.reservedBytes);
      const byteSlots = Math.max(1, Math.floor(remainingBytes / Math.max(1, miner.maxBytes)));
      const slots = Math.min(scriptWorkers, byteSlots, miner.queue.length,
        miner.maxFiles - miner.assets);
      if (!slots) break;
      const batch = miner.queue.splice(0, slots);
      const settled = await Promise.allSettled(batch.map(item => mineScript(miner, item)));
      const failure = settled.find(item => item.status === 'rejected');
      if (failure) throw failure.reason;
    }
  }
  miner.pageCut += miner.pageQueue.length;
  if (miner.pageCut) log({stage: 'assets', message: `${miner.pageCut} linked pages cut by page or byte budget`, skipped: miner.pageQueue});
  if (miner.queue.length) log({stage: 'assets', message: `asset budget reached: ${miner.queue.length} scripts not fetched`, skipped: miner.queue.map(item => item.url)});
  await minePublicOriginals(miner);
  const summary = summarize(miner);
  const writes = summary.endpoints.filter(endpoint => !['GET', 'HEAD', 'UNKNOWN'].includes(endpoint.method)).length;
  log({stage: 'assets', message: `mined ${summary.stats.files} files: ${summary.endpoints.length} endpoints (${writes} non-GET), ${summary.hosts.length} hosts, ${summary.secrets.length} secrets, ${summary.sourceMaps.length} source maps`, stats: summary.stats});
  return summary;
}
