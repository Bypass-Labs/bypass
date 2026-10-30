// Muse explains independently proved findings. It has no authority to create or upgrade a verdict.
import {maskExcerpt} from './ledger.mjs';
import {maskSecrets} from './assets.mjs';

const PAGE_FINDINGS = 20;
const PAGE_BYTES = 20000;
const MAX_PAGES = 8;
const clean = (value, length = 700) => maskExcerpt(maskSecrets(String(value ?? ''))).slice(0, length);

function findingFact(item) {
  return {id: item.id, kind: item.kind, pattern: clean(item.pattern),
    severity: item.severity, rule: item.rule,
    evidence: (item.evidence ?? []).slice(0, 20),
    confirmation: (item.confirmation ?? []).slice(0, 20),
    reach: {observed: item.reach?.observed ?? null, basis: clean(item.reach?.basis)},
    tags: (item.tags ?? []).slice(0, 12).map(value => clean(value, 100)),
    proofExecuted: !!item.proof};
}

function chainFact(item) {
  return {id: item.id, template: item.template,
    findings: (item.findings ?? []).slice(0, 10),
    proofExecuted: !!item.proof,
    reach: {observed: item.reach?.observed ?? null, basis: clean(item.reach?.basis)},
    steps: (item.steps ?? []).slice(0, 8).map(step => ({
      use: clean(step.use, 220),
      evidence: (step.evidence ?? []).slice(0, 8).map(value => clean(value, 100))})),
    evidence: (item.steps ?? []).flatMap(step => step.evidence ?? []).slice(0, 20)};
}

function pageContext(entries, chains) {
  const ids = new Set(entries.map(item => item.id));
  return {findings: entries, chains: chains.filter(item =>
    item.status === 'confirmed' && item.proof &&
    (item.findings ?? []).some(id => ids.has(id)))
    .slice(0, 5).map(chainFact)};
}

function assessmentPages(findings, chains) {
  const rows = findings.map(findingFact);
  const fit = entries => {
    if (entries.length === 1 ||
        Buffer.byteLength(JSON.stringify(pageContext(entries, chains))) <= PAGE_BYTES) return [entries];
    const middle = Math.ceil(entries.length / 2);
    return [...fit(entries.slice(0, middle)), ...fit(entries.slice(middle))];
  };
  const pages = [];
  for (let at = 0; at < rows.length; at += PAGE_FINDINGS)
    pages.push(...fit(rows.slice(at, at + PAGE_FINDINGS)));
  return pages;
}

/** Paged model annotations remain hypotheses attached only to exact, already proved finding IDs. */
export async function assessFindings(findings, chains = [], {infer = null, model = null,
  maxModelPages = MAX_PAGES, maxConcurrency = 1, log = () => {}} = {}) {
  const pages = assessmentPages(findings, chains);
  const modelCoverage = {pagesAvailable: pages.length, pagesSent: 0,
    findingsAvailable: findings.length, findingsSent: 0, workerPeak: 0};
  if (!infer || !model || !findings.length) return {notes: [], chainNotes: [], modelCalls: 0,
    modelError: null, modelCoverage};
  let modelCalls = 0, modelError = null, activeWorkers = 0;
  const notes = [], chainNotes = [], seenChains = new Set();
  const requestPage = async page => {
    const entries = pages[page];
    const context = {page: page + 1, pages: pages.length, ...pageContext(entries, chains)};
    if (Buffer.byteLength(JSON.stringify(context)) > PAGE_BYTES)
      return {page, context, entries, error: new Error('Assessment page ' +
        (page + 1) + ' exceeds the ' + PAGE_BYTES + '-byte context limit.')};
    modelCalls++;
    activeWorkers++;
    modelCoverage.workerPeak = Math.max(modelCoverage.workerPeak, activeWorkers);
    try {
      const response = await infer(model, [{role: 'system', content: 'Assess only these independently proved HTTP findings and sealed, confirmed compound chains. Explain impact, preconditions and remediation in plain language using the recorded steps and evidence. Chain notes are interpretation, not new findings. Do not add a finding or chain, upgrade severity, claim code execution, or invent a victim count. Return notes only for exact supplied IDs.'},
        {role: 'user', content: JSON.stringify(context)}], {schema: {type: 'object', properties: {
        notes: {type: 'array', maxItems: PAGE_FINDINGS, items: {type: 'object', properties: {
          id: {type: 'string'}, impact: {type: 'string', maxLength: 700},
          preconditions: {type: 'string', maxLength: 700}, remediation: {type: 'string', maxLength: 700}},
        required: ['id', 'impact', 'preconditions', 'remediation'],
        additionalProperties: false}},
        chainNotes: {type: 'array', maxItems: PAGE_FINDINGS, items: {type: 'object', properties: {
          id: {type: 'string'}, impact: {type: 'string', maxLength: 700},
          preconditions: {type: 'string', maxLength: 700}, remediation: {type: 'string', maxLength: 700}},
        required: ['id', 'impact', 'preconditions', 'remediation'],
        additionalProperties: false}}}, required: ['notes', 'chainNotes'], additionalProperties: false}});
      return {page, context, entries, response};
    } catch (error) {
      return {page, context, entries, error};
    } finally {activeWorkers--;}
  };
  const pageLimit = Math.min(pages.length, Math.max(0, Math.floor(maxModelPages)));
  const width = Math.max(1, Math.min(pageLimit || 1, Math.floor(maxConcurrency) || 1));
  for (let at = 0; at < pageLimit; at += width) {
    const completed = await Promise.all(Array.from({length: Math.min(width, pageLimit - at)},
      (_, offset) => requestPage(at + offset)));
    let failed = false;
    // Commit in page order even if Muse finishes a later page first.
    for (const {page, context, entries, response, error} of completed) {
      if (error) {
        modelError ??= error.message;
        log({stage: 'assessment', message: 'Muse assessment failed on page ' +
          (page + 1) + ': ' + error.message});
        failed = true;
        continue;
      }
      const byId = new Set(entries.map(item => item.id));
      notes.push(...(Array.isArray(response?.notes) ? response.notes : [])
        .filter(item => byId.has(item.id)).slice(0, PAGE_FINDINGS)
        .map(item => ({id: item.id, impact: clean(item.impact),
          preconditions: clean(item.preconditions), remediation: clean(item.remediation)})));
      const chainIds = new Set(context.chains.map(item => item.id));
      for (const item of Array.isArray(response?.chainNotes) ? response.chainNotes : []) {
        if (!chainIds.has(item.id) || seenChains.has(item.id)) continue;
        seenChains.add(item.id);
        chainNotes.push({id: item.id, impact: clean(item.impact),
          preconditions: clean(item.preconditions), remediation: clean(item.remediation)});
      }
      modelCoverage.pagesSent++;
      modelCoverage.findingsSent += entries.length;
    }
    if (failed) break;
  }
  for (const finding of findings) {
    const note = notes.find(item => item.id === finding.id);
    if (note) finding.assessment = note;
  }
  for (const chain of chains) {
    const note = chainNotes.find(item => item.id === chain.id);
    if (note) chain.assessment = note;
  }
  log({stage: 'assessment', message: 'Muse annotated ' + notes.length +
    ' proved findings and reviewed ' + modelCoverage.findingsSent + ' of ' +
    modelCoverage.findingsAvailable + '; annotated ' + chainNotes.length +
    ' sealed chains; deterministic verdicts were unchanged'});
  return {notes, chainNotes, modelCalls, modelError, modelCoverage};
}
