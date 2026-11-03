import fs from 'node:fs';
import path from 'node:path';
import { execFileSync } from 'node:child_process';
import { need } from '../util.mjs';
import { inventory } from '../repository.mjs';
import { maskSecrets } from './assets.mjs';
import { maskExcerpt } from './ledger.mjs';

const text = (value, length = 600) => maskExcerpt(maskSecrets(
  String(value ?? '').replace(/[\x00-\x1f\x7f]/g, ' ').slice(0, length)));

/** Pass a saved source hypothesis to the live runner as evidence, never as a verdict. */
export async function sourceFindingFocus(root, findingId, pathOverride = null) {
  const state = JSON.parse(fs.readFileSync(path.join(root, '.bypass/state.json'), 'utf8'));
  const finding = state.findings?.find(item => item.id === findingId);
  need(finding, `Finding ${findingId} was not found in this application project.`);
  need(finding.sourceEvidence?.kind === 'source',
    `Finding ${findingId} has no source evidence to hand off.`);
  const route = pathOverride ?? finding.resourcePath;
  need(typeof route === 'string' && route.startsWith('/') && !route.startsWith('//'),
    `Finding ${findingId} needs a concrete application path. Pass --focus-path.`);
  let sourceRevision = null;
  try { sourceRevision = execFileSync('git', ['rev-parse', 'HEAD'],
    {cwd: root, encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore']}).trim(); }
  catch { /* A copied source tree has no Git revision to attest. */ }
  const recordedFingerprint = finding.sourceEvidence.sourceFingerprint ??
    finding.sourceFingerprint ?? null;
  const currentFingerprint = recordedFingerprint ? (await inventory(root)).fingerprint : null;
  return {findingId, path: route, method: finding.method ?? finding.request?.method ?? 'UNKNOWN',
    title: text(finding.title, 180), category: text(finding.category, 80),
    hypothesis: text(finding.hypothesis),
    source: {file: text(finding.sourceEvidence.file, 240),
      line: finding.sourceEvidence.line ?? null,
      quote: text(finding.sourceEvidence.quote, 300),
      fingerprint: recordedFingerprint},
    sourceSnapshotMatches: recordedFingerprint ? currentFingerprint === recordedFingerprint : null,
    sourceRevision};
}

/** An explicit app revision endpoint can attest the checkout used for a focused proof. */
export async function checkLiveRevision(focus, requester, revisionPath, revisionField = 'revision') {
  if (!revisionPath) return {status: 'unverified', sourceRevision: focus.sourceRevision,
    reason: 'No live revision endpoint was supplied.'};
  const response = await requester({url: revisionPath, identity: 'anonymous', method: 'GET',
    step: 'recon', purpose: 'task', noCache: true});
  let document;
  try { document = JSON.parse(response.body); } catch { /* No JSON revision fact. */ }
  const liveRevision = revisionField.split('.').reduce((value, key) => value?.[key], document);
  const exact = typeof liveRevision === 'string' && /^[0-9a-f]{40,64}$/i.test(liveRevision) ?
    liveRevision : null;
  return {status: exact && focus.sourceRevision ?
      (exact === focus.sourceRevision ? 'matched' : 'mismatched') : 'unverified',
    sourceRevision: focus.sourceRevision, liveRevision: exact,
    path: revisionPath, field: revisionField, evidenceId: response.evidenceId ?? null};
}
