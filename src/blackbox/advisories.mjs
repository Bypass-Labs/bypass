// Bounded OSV lookups for versions observed in public client assets. A match is a lead, not an exploit proof.
import {safeRequest} from '../network.mjs';
import {hash} from '../util.mjs';
import {libraryAdvisoryKey} from './assets.mjs';

const OSV_URL = 'https://api.osv.dev/v1/query';
const MAX_PACKAGES = 50;
const MAX_PAGES = 2;
const MAX_MATCHES = 20;
const PACKAGE_NAME = /^(?:@[a-z0-9][a-z0-9._-]*\/)?[a-z0-9][a-z0-9._-]{0,99}$/;
const VERSION = /^\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?$/;
const ADVISORY_ID = /^[A-Za-z0-9][A-Za-z0-9._-]{1,99}$/;
const clean = (value, limit = 240) => String(value ?? '').replace(/[\x00-\x1f\x7f<>`|]/g, ' ').replace(/\s+/g, ' ').trim().slice(0, limit);
function assetPath(value) {
  try {
    const url = new URL(value);
    return ['http:', 'https:'].includes(url.protocol) && !url.username && !url.password ?
      `${url.origin}${url.pathname}` : null;
  } catch {return null;}
}

async function defaultQuery(payload, {timeoutMs = 5000} = {}) {
  return safeRequest(OSV_URL, {method: 'POST', headers: {'content-type': 'application/json'},
    body: JSON.stringify(payload), timeout: timeoutMs, maxBytes: 256 * 1024,
    signal: AbortSignal.timeout(timeoutMs)});
}

function candidates(summaries) {
  const found = new Map();
  for (const summary of summaries) for (const file of summary?.files ?? []) {
    for (const library of file.libraries ?? []) {
      if (!library || typeof library !== 'object') continue;
      const key = libraryAdvisoryKey(library);
      if (key.ecosystem !== 'npm' || !PACKAGE_NAME.test(key.name) || !VERSION.test(key.version)) continue;
      const id = `${key.name}@${key.version}`;
      if (!found.has(id)) found.set(id, {...key, files: new Set()});
      const source = assetPath(file.url);
      if (source) found.get(id).files.add(source);
    }
  }
  return [...found.values()].map(item => ({...item, files: [...item.files]}));
}

function advisory(vuln, name) {
  if (!ADVISORY_ID.test(vuln?.id ?? '') || vuln.withdrawn) return null;
  const fixedVersions = new Set();
  const affectedRows = (Array.isArray(vuln.affected) ? vuln.affected : [])
    .filter(item => !item?.package?.name || item.package.name === name);
  for (const affected of affectedRows) {
    for (const range of Array.isArray(affected?.ranges) ? affected.ranges : []) {
      if (range?.type !== 'ECOSYSTEM' && range?.type !== 'SEMVER') continue;
      for (const event of Array.isArray(range.events) ? range.events : [])
        if (VERSION.test(event?.fixed ?? '')) fixedVersions.add(event.fixed);
    }
  }
  const rating = [vuln.database_specific?.severity,
    ...affectedRows.map(item => item?.ecosystem_specific?.severity)]
    .find(value => ['LOW', 'MODERATE', 'HIGH', 'CRITICAL'].includes(value)) ?? null;
  return {id: vuln.id, summary: clean(vuln.summary), rating, fixedVersions: [...fixedVersions].slice(0, 5),
    url: `https://osv.dev/vulnerability/${encodeURIComponent(vuln.id)}`};
}

/** Query only package/version pairs extracted from served assets, with a fixed query and response budget. */
export async function lookupAdvisories(summaries, {enabled = false, offline = false, query = defaultQuery,
  ledger, deadline = Infinity, nowMs = () => Date.now(), log = () => {}} = {}) {
  const available = candidates(Array.isArray(summaries) ? summaries : [summaries]);
  const stats = {available: available.length, checked: 0, requests: 0, cut: 0, errors: 0, matches: 0};
  const status = !enabled ? 'disabled' : offline ? 'offline' : available.length ? 'checked' : 'no-libraries';
  const records = [];
  if (status !== 'checked') return {status, stats, records, incomplete: false};
  if (!ledger) throw Error('OSV lookups need an evidence ledger.');
  const selected = available.slice(0, MAX_PACKAGES);
  stats.cut += available.length - selected.length;
  for (const item of selected) {
    if (nowMs() >= deadline) {stats.cut += selected.length - records.length; break;}
    const record = {...item, advisories: [], evidence: [], status: 'checked'};
    const seen = new Set();
    let pageToken = null;
    for (let page = 0; page < MAX_PAGES; page++) {
      if (nowMs() >= deadline) {stats.cut++; record.status = 'cut'; break;}
      const payload = {package: {name: item.name, ecosystem: 'npm'}, version: item.version,
        ...(pageToken ? {page_token: pageToken} : {})};
      let response, body, error = null;
      try {
        stats.requests++;
        response = await query(payload, {timeoutMs: Math.max(1, Math.min(5000, deadline - nowMs()))});
        if (response?.status !== 200) throw Error(`OSV returned HTTP ${response?.status ?? 'unknown'}`);
        body = JSON.parse(response.body);
        if (!body || typeof body !== 'object' || Array.isArray(body) ||
            !Array.isArray(body.vulns ?? []) || (body.vulns ?? []).length > 1000)
          throw Error('OSV returned an invalid or oversized result.');
      } catch (cause) {error = clean(cause?.message ?? 'OSV query failed', 160);}
      const entries = error ? [] : body.vulns ?? [];
      const evidenceId = ledger.append({step: 'discovery', kind: 'lookup', source: 'osv',
        request: {method: 'POST', url: OSV_URL},
        ...(response ? {response: {status: response.status, bytes: Buffer.byteLength(response.body ?? ''),
          hash: `sha256:${hash(response.body ?? '')}`}} : {}),
        ...(error ? {blocked: {reason: error}} : {}),
        package: item.name, version: item.version, page: page + 1,
        advisories: entries.length, error});
      record.evidence.push(evidenceId);
      if (error) {stats.errors++; record.status = 'error'; break;}
      for (const entry of entries) {
        const parsed = advisory(entry, item.name);
        if (!parsed || seen.has(parsed.id)) continue;
        seen.add(parsed.id);
        if (record.advisories.length < MAX_MATCHES) record.advisories.push(parsed);
        else stats.cut++;
      }
      if (body.next_page_token != null &&
          (typeof body.next_page_token !== 'string' || body.next_page_token.length > 1000)) {
        stats.cut++;
        record.status = 'cut';
        break;
      }
      pageToken = body.next_page_token || null;
      if (!pageToken) break;
      if (page === MAX_PAGES - 1) {stats.cut++; record.status = 'cut';}
    }
    if (record.status === 'checked') stats.checked++;
    stats.matches += record.advisories.length;
    records.push(record);
  }
  log({stage: 'advisories', message: `OSV checked ${stats.checked} of ${stats.available} detected package versions; ${stats.matches} advisory leads, ${stats.cut} cuts, ${stats.errors} errors`});
  return {status, stats, records, incomplete: stats.cut > 0 || stats.errors > 0};
}
