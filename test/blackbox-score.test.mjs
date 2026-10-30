import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import {temp} from './helpers.mjs';
import {scoreBlackbox} from '../scripts/blackbox-score.mjs';

test('the real CLI scores planted, fixed, and mixed local apps with replayable proofs', async t => {
  const root = temp();
  t.after(() => fs.rmSync(root, {recursive: true, force: true}));
  const score = await scoreBlackbox({trials: 3, seed: 424242, out: root});
  assert.equal(score.results.length, 3);
  assert.deepEqual(score.results[0].enabled,
    ['idor', 'list-leak', 'open-redirect', 'nosql-operator-bypass',
      'http-parameter-pollution', 'graphql-bola', 'host-header-redirect', 'jwt-unsigned',
      'ssrf-loopback', 'ssti-arithmetic', 'missing-auth', 'anonymous-credential-data',
      'sql-boolean', 'xxe-hosts', 'xxe-body-hosts', 'public-api-credential']);
  assert.deepEqual(score.results[1].enabled, []);
  assert.ok(score.results[2].enabled.length > 0 && score.results[2].enabled.length < 16);
  assert.equal(new Set(score.results.map(trial => trial.paths.item)).size, 3);
  assert.ok(score.rows[0].found > 16);
  for (const field of ['missed', 'falsePositives', 'neverHits', 'proofRegressions'])
    assert.equal(score.rows[0][field], 0, field);
  assert.equal(score.rows[0].modelCalls, 0);
  for (const trial of score.results) {
    const run = trial.runs[0];
    assert.deepEqual(run.found, trial.expected);
    if (trial.expected.length) {
      assert.equal(run.replayExitCode, 1);
      assert.equal(run.afterFixReplayExitCode, 0);
      assert.deepEqual(trial.fixedControls[0].findings, []);
    }
  }
  assert.deepEqual(JSON.parse(fs.readFileSync(path.join(root, 'score.json'), 'utf8')).rows,
    score.rows);
});
