import test from 'node:test';
import assert from 'node:assert/strict';
import {assessFindings} from '../src/blackbox/assessment.mjs';

const findings = () => Array.from({length: 25}, (_, index) => ({
  id: 'f-' + String(index + 1).padStart(3, '0'), kind: 'idor',
  pattern: '/api/items/{id}', severity: 'medium', rule: 'confirmed/cross-account-read',
  verdict: 'confirmed', evidence: ['e-1'], confirmation: ['e-2'],
  reach: {observed: 1, basis: 'one owner record was read'}, tags: [], proof: '/tmp/proof.mjs',
}));

test('Muse assesses every proved finding in bounded pages without changing verdicts', async () => {
  const records = findings();
  const chain = {id: 'c-001', status: 'confirmed', template: 'list-id-to-item-read',
    proof: '/tmp/compound.mjs', severity: 'high',
    findings: ['f-001', 'f-025'], reach: {observed: 1},
    steps: [{use: 'Read the owner item through the public list', evidence: ['e-3']}]};
  const unsealed = {...chain, id: 'c-002', proof: null};
  const seen = new Set();
  let chainPages = 0;
  const result = await assessFindings(records, [chain, unsealed], {model: {model: 'fixture'},
    infer: async (_model, messages) => {
      const context = JSON.parse(messages[1].content);
      assert.ok(Buffer.byteLength(messages[1].content) <= 20000);
      assert.ok(context.findings.length <= 20);
      assert.ok(context.chains.every(item => item.proofExecuted && item.id === 'c-001'));
      if (context.chains.some(item => item.id === 'c-001')) chainPages++;
      if (context.chains.length) assert.deepEqual(context.chains[0].steps,
        [{use: 'Read the owner item through the public list', evidence: ['e-3']}]);
      for (const item of context.findings) seen.add(item.id);
      return {chainNotes: [...context.chains.map(item => ({id: item.id,
        impact: 'One owner item was exposed', preconditions: 'Public list is reachable',
        remediation: 'Enforce object ownership'})),
      {id: 'c-999', impact: 'Invented', preconditions: '', remediation: ''}],
      notes: [...context.findings.map(item => ({id: item.id,
        impact: 'Account data exposure', preconditions: 'Two test accounts',
        remediation: 'Check ownership'})),
      {id: 'f-999', impact: 'Invented', preconditions: '', remediation: ''}]};
    }});
  assert.equal(result.modelCalls, 2);
  assert.deepEqual(result.modelCoverage, {pagesAvailable: 2, pagesSent: 2,
    findingsAvailable: 25, findingsSent: 25, workerPeak: 1});
  assert.equal(seen.size, 25);
  assert.equal(result.notes.length, 25);
  assert.equal(result.chainNotes.length, 1);
  assert.equal(chainPages, 2);
  assert.equal(chain.assessment.impact, 'One owner item was exposed');
  assert.equal(chain.severity, 'high');
  assert.equal(unsealed.assessment, undefined);
  assert.ok(records.every(item => item.verdict === 'confirmed' &&
    item.assessment?.remediation === 'Check ownership'));
  assert.ok(!result.notes.some(item => item.id === 'f-999'));
});

test('assessment reports model-page cuts and leaves unread findings unannotated', async () => {
  const records = findings();
  const result = await assessFindings(records, [], {model: {model: 'fixture'}, maxModelPages: 1,
    infer: async (_model, messages) => ({notes: JSON.parse(messages[1].content).findings.map(item => ({
      id: item.id, impact: 'Observed', preconditions: 'Test accounts', remediation: 'Fix'}))})});
  assert.equal(result.modelCalls, 1);
  assert.equal(result.modelCoverage.pagesSent, 1);
  assert.equal(result.modelCoverage.findingsSent, 20);
  assert.equal(result.notes.length, 20);
  assert.equal(records[24].assessment, undefined);
});

test('bounded Muse assessment pages overlap and retain finding and chain evidence order', async () => {
  const records = Array.from({length: 45}, (_, index) => ({
    ...findings()[0], id: `f-${String(index + 1).padStart(3, '0')}`,
    evidence: [`ev-${index + 1}`], confirmation: [`poc-${index + 1}`]}));
  const chain = {id: 'c-001', status: 'confirmed', proof: '/tmp/chain.mjs',
    findings: ['f-001', 'f-025'], steps: [{use: 'Combined proved reads',
      evidence: ['chain-evidence']}]};
  let active = 0, peak = 0;
  const finished = [];
  const result = await assessFindings(records, [chain], {model: {model: 'fixture'},
    maxConcurrency: 2, infer: async (_model, messages) => {
      const context = JSON.parse(messages[1].content);
      active++;
      peak = Math.max(peak, active);
      assert.ok(context.findings.every(item => item.proofExecuted &&
        item.evidence.length === 1 && item.confirmation.length === 1));
      await new Promise(resolve => setTimeout(resolve, context.page === 1 ? 60 : 5));
      finished.push(context.page);
      active--;
      return {notes: context.findings.map(item => ({id: item.id,
        impact: `Page ${context.page} used ${item.evidence[0]}`,
        preconditions: `Proof ${item.confirmation[0]}`,
        remediation: 'Repair the observed boundary'})),
      chainNotes: context.chains.map(item => ({id: item.id,
        impact: `Page ${context.page} used ${item.steps[0].evidence[0]}`,
        preconditions: 'Both findings proved', remediation: 'Repair both steps'}))};
    }});
  assert.equal(peak, 2);
  assert.equal(result.modelCoverage.workerPeak, 2);
  assert.equal(result.modelCalls, 3);
  assert.deepEqual(finished.slice(0, 2), [2, 1],
    'the second page should finish first to exercise ordered commit');
  assert.deepEqual(result.notes.map(item => item.id), records.map(item => item.id));
  assert.ok(records.every((item, index) =>
    item.assessment.impact.includes(`ev-${index + 1}`) &&
    item.assessment.preconditions.includes(`poc-${index + 1}`)));
  assert.equal(result.chainNotes.length, 1);
  assert.equal(chain.assessment.impact, 'Page 1 used chain-evidence');
});
