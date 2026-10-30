// Evidence ledger of a black-box run: one append-only evidence.jsonl writer that assigns ev- IDs and chains
// every line to the previous one with SHA-256. Before a record reaches disk, credential values are scrubbed
// by exact value, redact() runs as a second net and the excerpt is masked and capped.
// Implements design section 14 (and the 2 KB excerpt bound of section 17) of docs/BLACKBOX_AUDIT.md.
import fs from 'node:fs';
import {maskCredentialParams} from './private-query.mjs';
import path from 'node:path';
import { redact, hash, now, need } from '../util.mjs';

const REDACTED = '[REDACTED]';
const EXCERPT_CHARS = 2048;
const LEDGER_FIELDS = ['id', 'prev', 'at'];
// Quantifiers are bounded (RFC 5321 lengths) so long runs in a hostile body cannot cause quadratic backtracking.
const EMAIL_SOURCE = '[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9-]{1,63}(?:\\.[A-Za-z0-9-]{1,63}){0,8}\\.[A-Za-z]{2,24}';
const EMAIL = new RegExp(EMAIL_SOURCE, 'g');
const IS_EMAIL = new RegExp(`^${EMAIL_SOURCE}$`);
const PHONE = /(?<![\w@.+-])\+?\(?\d[\d ()-]{7,22}\d(?![\w-])/g;
// Secret-looking content, so an exposure body (an .env file, a config) is stored masked (design 5.5, 14).
const PRIVATE_KEY = /-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?(?:-----END [A-Z ]*PRIVATE KEY-----|$)/g;
const KNOWN_TOKEN = /\beyJ[\w-]{8,}\.[\w-]{8,}\.[\w-]*|\b(?:AKIA[0-9A-Z]{16}|[rs]k_live_[0-9A-Za-z]{8,}|gh[pousr]_[0-9A-Za-z]{20,}|github_pat_\w{20,}|xox[abprs]-[\w-]{10,}|AIza[\w-]{35})/g;
const URL_PASSWORD = /(\b[a-z][a-z0-9+.-]{0,31}:\/\/[^\s/:@]{1,256}:)[^\s/@]{1,256}@/gi;
const ENV_ASSIGNMENT = /^([ \t]*(?:export[ \t]+)?[A-Z][A-Z0-9_]{0,127}[ \t]*=[ \t]*)\S.*$/gm;
const SECRET_FIELD = /("[^"\\]{0,64}(?:password|passwd|secret|token|api[_-]?key|private[_-]?key|credential)[^"\\]{0,64}"\s*:\s*)("(?:[^"\\]|\\.)*"|-?\d[\d.eE+-]*)/gi;

/**
 * Opens <runDir>/evidence.jsonl for appending (an existing ledger is continued, never truncated).
 * append(record) scrubs `secrets` from every string, applies redact(), masks the excerpt, assigns
 * `id` ('ev-0001'…), `prev` ('sha256:' + hash of the previous line, null first) and `at`, then
 * writes the line with appendFileSync and returns the id.
 * @returns {{append: (record: object) => string, count: () => number, file: string, close: () => void}}
 */
export function createLedger(runDir, {run = null, redactFields = [], secrets = []} = {}) {
  need(runDir, 'The evidence ledger needs a run folder.');
  fs.mkdirSync(runDir, {recursive: true});
  const file = path.join(runDir, 'evidence.jsonl');
  const existing = fs.existsSync(file) ? fs.readFileSync(file, 'utf8').split('\n').filter(Boolean) : [];
  let records = existing.length;
  let prev = records ? chainHash(existing.at(-1)) : null;
  let closed = false;

  function append(record) {
    need(!closed, 'The evidence ledger is closed.');
    const {run: recordRun, ...fields} = sanitize(record, secrets, redactFields);
    const id = evidenceId(records + 1);
    const line = JSON.stringify({id, prev, run: recordRun ?? run, ...fields, at: now()});
    fs.appendFileSync(file, `${line}\n`);
    records += 1;
    prev = chainHash(line);
    return id;
  }

  return {append, count: () => records, file, close: () => { closed = true; }};
}

/**
 * Recomputes the hash chain of a ledger file. A modified line is detected at the next record,
 * whose `prev` no longer matches; a removed or reordered line is detected by its position.
 * @returns {{ok: boolean, records: number, brokenAt: string|null}}
 */
export function verifyLedger(file) {
  need(fs.existsSync(file), `Evidence ledger not found: ${file}`);
  const lines = fs.readFileSync(file, 'utf8').split('\n').filter(Boolean);
  let prev = null;
  for (const [index, line] of lines.entries()) {
    const expected = evidenceId(index + 1);
    const record = parseRecord(line);
    if (record?.id !== expected || record.prev !== prev) return {ok: false, records: lines.length, brokenAt: expected};
    prev = chainHash(line);
  }
  return {ok: true, records: lines.length, brokenAt: null};
}

/**
 * Masks an excerpt (pure). Values of fields named in `redactFields` become '[email]', '[phone]' or
 * '[redacted]'; any email or phone-looking value becomes '[email]' or '[phone]'; secret-looking
 * content (env-file assignments, secret-named JSON fields, private keys, JWTs, well-known key
 * formats, passwords in URLs) becomes '[redacted]'. Ordinary numbers, dates and IDs are kept.
 */
export function maskExcerpt(text, redactFields = []) {
  let masked = maskCredentialParams(String(text ?? ''))
    .replace(PRIVATE_KEY, '[redacted]')
    .replace(KNOWN_TOKEN, '[redacted]')
    .replace(URL_PASSWORD, '$1[redacted]@')
    .replace(ENV_ASSIGNMENT, '$1[redacted]')
    .replace(SECRET_FIELD, '$1"[redacted]"');
  for (const field of redactFields) {
    masked = masked.replace(fieldPattern(field), (whole, prefix, value) => `${prefix}"${maskedValue(value)}"`);
  }
  return masked.replace(EMAIL, '[email]').replace(PHONE, candidate => (looksLikePhone(candidate) ? '[phone]' : candidate));
}

/**
 * Returns a deep copy of `value` with every secret replaced by '[REDACTED]' in every string and
 * object key (pure). Each secret is also matched URL-encoded and JSON-escaped; longer secrets are
 * replaced first so one secret that contains another leaves no fragment.
 */
export function scrub(value, secrets = []) {
  const variants = secretVariants(secrets);
  return mapStrings(value, text => variants.reduce((out, secret) => out.split(secret).join(REDACTED), text));
}

function sanitize(record, secrets, redactFields) {
  need(record && typeof record === 'object' && !Array.isArray(record), 'A ledger record must be an object.');
  const data = JSON.parse(JSON.stringify(record));
  for (const field of LEDGER_FIELDS) delete data[field];
  const scrubbed = scrub(data, secrets);
  // redact() runs per string: on a whole object its JSON round-trip breaks on text such as `Bearer "x`.
  // One call over every string joined by NUL settles the usual case where it changes nothing (hot path).
  const joined = stringsOf(scrubbed).join('\u0000');
  const clean = redact(joined) === joined ? scrubbed : mapStrings(scrubbed, redact);
  if (typeof clean.excerpt === 'string') clean.excerpt = maskExcerpt(clean.excerpt, redactFields).slice(0, EXCERPT_CHARS);
  return clean;
}

function stringsOf(value) {
  if (typeof value === 'string') return [value];
  if (Array.isArray(value)) return value.flatMap(stringsOf);
  if (value && typeof value === 'object') return Object.entries(value).flatMap(([key, item]) => [key, ...stringsOf(item)]);
  return [];
}

function secretVariants(secrets) {
  const values = secrets.filter(secret => typeof secret === 'string' && secret.length > 0);
  const variants = values.flatMap(secret => [
    secret,
    secret.isWellFormed() ? encodeURIComponent(secret) : secret,
    JSON.stringify(secret).slice(1, -1),
    secret.replaceAll('/', '\\/'),
  ]);
  return [...new Set(variants)].sort((a, b) => b.length - a.length);
}

function mapStrings(value, transform) {
  if (typeof value === 'string') return transform(value);
  if (Array.isArray(value)) return value.map(item => mapStrings(item, transform));
  if (value && typeof value === 'object') {
    return Object.fromEntries(Object.entries(value).map(([key, item]) => [transform(key), mapStrings(item, transform)]));
  }
  return value;
}

function fieldPattern(field) {
  const name = String(field).replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  return new RegExp(`("${name}"\\s*:\\s*)("(?:[^"\\\\]|\\\\.)*"|-?\\d[\\d.eE+-]*|true|false)`, 'gi');
}

function maskedValue(raw) {
  const value = raw.startsWith('"') ? raw.slice(1, -1) : raw;
  if (IS_EMAIL.test(value)) return '[email]';
  if (looksLikePhone(value)) return '[phone]';
  return '[redacted]';
}

/** Ten to fifteen digits with a leading + or separators, and not a date: keeps IDs, amounts and timestamps. */
function looksLikePhone(text) {
  const digits = text.replace(/\D/g, '').length;
  if (digits < 10 || digits > 15 || /^\d{4}-\d{2}-\d{2}/.test(text)) return false;
  return text.startsWith('+') || /[ ()-]/.test(text);
}

/** A line that is not JSON is a broken chain, which verifyLedger reports by position. */
function parseRecord(line) {
  try {
    return JSON.parse(line);
  } catch {
    return null;
  }
}

function evidenceId(number) {
  return `ev-${String(number).padStart(4, '0')}`;
}

function chainHash(line) {
  return `sha256:${hash(line)}`;
}
