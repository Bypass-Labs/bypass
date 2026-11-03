import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import {temp} from './helpers.mjs';
import {execute} from '../src/service.mjs';
import {change} from '../src/store.mjs';
import {pluginOnboarding} from '../src/plugin-onboarding.mjs';
import {latestRemediation, remediationCheckpoint} from '../src/remediation-checkpoint.mjs';
import {mcpClient} from './mcp-client.mjs';

const review = 'run_1234abcd';
const sha = 'a'.repeat(40);

async function project() {
  const root = temp(), origin = 'http://127.0.0.1:4555';
  fs.writeFileSync(path.join(root, 'app.mjs'), 'export const app = true;\n');
  await execute('init', [root]);
  await execute('target add', ['app'], {project: root, url: origin, environment: 'local'});
  await execute('target verify', ['app'], {project: root, method: 'local'});
  await execute('target authorize', ['app'], {project: root, paths: '/', methods: 'GET,HEAD,POST', rps: 5, accept: true});
  const runs = ['bx-20261103-11111111', 'bx-20261103-22222222'];
  await change(root, state => {
    state.settings.reviewMode = 'combined';
    state.runs.push({id: review, status: 'completed', host: {mode: 'combined', target: 'app'},
      result: {findings: ['finding-one', 'finding-two']}});
  });
  for (const [index, id] of runs.entries()) {
    const dir = path.join(root, '.bypass', 'runs', id);
    fs.mkdirSync(path.join(dir, 'poc', 'f-001'), {recursive: true});
    fs.writeFileSync(path.join(dir, 'run.json'), JSON.stringify({run: id, origin,
      focus: {findingId: index ? 'finding-two' : 'finding-one'}}));
    fs.writeFileSync(path.join(dir, 'poc', 'f-001', 'spec.json'), '{}');
  }
  return {root, origin, runs};
}

test('combined PR checkpoint survives onboarding and waits for the merged deployed revision', async () => {
  const {root, origin, runs} = await project();
  const opened = await remediationCheckpoint(root, {action: 'open', review,
    pr: 'https://git.example.test/team/app/pulls/7', branch: 'fix/issue', runs,
    revisionPath: '/api/version'});
  assert.equal(opened.status, 'pending_merge');
  assert.equal(opened.target, origin);
  assert.deepEqual(opened.proofRuns, runs);
  assert.deepEqual(opened.sourceFindings.map(item => item.finding), ['finding-one', 'finding-two']);
  assert.deepEqual(await remediationCheckpoint(root, {action: 'open', review,
    pr: opened.pr, branch: opened.branch, runs: [...runs].reverse()}), opened,
  'retrying the same PR handoff must not create a second checkpoint');
  assert.equal(latestRemediation(root)?.review, review);
  const resumed = await pluginOnboarding(root, root);
  assert.equal(resumed.stage, 'release');
  assert.deepEqual(resumed.nextAction.arguments, {action: 'status', review});
  const pending = await remediationCheckpoint(root, {action: 'status', review});
  assert.equal(pending.status, 'pending_merge');
  assert.equal(pending.nextAction.waitFor, 'pull_request_merge');
  assert.equal(pending.nextAction.tool, undefined, 'pending merge must not loop on status');

  let replays = 0;
  const verify = async (_root, run) => {
    replays++;
    return {integrity: {ok: true}, proofs: [{id: 'f-001', verdict: run === runs[0] ?
      'not_reproduced' : 'confirmed'}]};
  };
  const notDeployed = await remediationCheckpoint(root, {action: 'replay', review, mergeRevision: sha},
    {request: async () => ({status: 200, body: JSON.stringify({revision: 'b'.repeat(40)})}), verify});
  assert.equal(notDeployed.status, 'pending_deployment');
  assert.equal(notDeployed.deployment.liveRevision, 'b'.repeat(40));
  assert.equal(replays, 0, 'old deployment must not be reported as a fixed build');

  const deployed = await remediationCheckpoint(root, {action: 'replay', review},
    {request: async () => ({status: 200, body: JSON.stringify({revision: sha})}), verify});
  assert.equal(deployed.status, 'still_vulnerable');
  assert.deepEqual(deployed.results.map(item => item.status), ['not_reproduced', 'still_vulnerable']);
  assert.deepEqual(deployed.results.map(item => item.finding), ['finding-one', 'finding-two']);
  assert.equal(replays, 2);
  assert.equal(latestRemediation(root)?.status, 'still_vulnerable', 'confirmed proof remains actionable');

  const observed = await remediationCheckpoint(root, {action: 'replay', review},
    {request: async () => ({status: 200, body: JSON.stringify({revision: sha})}),
      verify: async (_root, run) => ({integrity: {ok: true}, proofs: [{id: 'f-001',
        verdict: run === runs[0] ? 'not_reproduced' : 'observed'}]})});
  assert.equal(observed.status, 'inconclusive');
  assert.equal(observed.results[1].status, 'inconclusive', 'observed is not a sealed confirmation');

  const fixed = await remediationCheckpoint(root, {action: 'replay', review},
    {request: async () => ({status: 200, body: JSON.stringify({revision: sha})}),
      verify: async () => ({integrity: {ok: true}, proofs: [{id: 'f-001', verdict: 'not_reproduced'}]})});
  assert.equal(fixed.status, 'retested');
  assert.equal(latestRemediation(root), null, 'only resolved proofs close the release checkpoint');
});

test('unreachable or inconclusive proofs remain open and deployment identity is honest', async () => {
  const {root, runs} = await project();
  await remediationCheckpoint(root, {action: 'open', review,
    pr: 'https://git.example.test/team/app/pulls/8', branch: 'fix/issue', runs});
  const waiting = await remediationCheckpoint(root, {action: 'replay', review, mergeRevision: sha});
  assert.equal(waiting.status, 'pending_deployment');
  assert.equal(waiting.deployment.status, 'unverified');
  const replayed = await remediationCheckpoint(root, {action: 'replay', review, deploymentObserved: true},
    {verify: async (_root, run) => run === runs[0] ?
      {integrity: {ok: true}, proofs: [{id: 'f-001', verdict: 'inconclusive', reason: 'target unreachable'}]} :
      {integrity: {ok: false}, proofs: [{id: 'f-001', verdict: 'not_reproduced'}]}});
  assert.equal(replayed.status, 'inconclusive');
  assert.equal(replayed.deployment.status, 'unverified');
  assert.deepEqual(replayed.results.map(item => item.status), ['inconclusive', 'inconclusive']);
  assert.equal(latestRemediation(root)?.review, review);
});

test('installed MCP exposes the durable PR handoff on a new session', async t => {
  const {root, runs} = await project();
  const client = await mcpClient(root, {stateDir: temp()});
  const opened = await client.call('bypass_remediation', {action: 'open', review,
    pr: 'https://git.example.test/team/app/pulls/9', branch: 'fix/issue', runs});
  assert.equal(opened.status, 'pending_merge');
  await client.close();
  const restarted = await mcpClient(root, {stateDir: temp()});
  t.after(() => restarted.close());
  const resumed = await restarted.call('bypass_onboarding');
  assert.equal(resumed.stage, 'release');
  assert.equal(resumed.nextAction.arguments.review, review);
});
