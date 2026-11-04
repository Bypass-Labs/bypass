import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import http from 'node:http';
import {fileURLToPath} from 'node:url';
import {temp, cli} from './helpers.mjs';
import {execFile} from '../src/util.mjs';
import {createBlackboxProgress, progressLine} from '../src/blackbox/progress.mjs';
import {blackboxOutcomeText, regressionExportText} from '../src/ui.mjs';

test('web progress separates executed, queued untested and beyond budget', () => {
  assert.deepEqual(progressLine({stage: 'web-probes', message:
    '181 web leads executed; 8 queued untested; 2 confirmed security findings; 7 beyond budget'}),
  {label: 'Web tests', text: '181 leads executed · 8 queued untested · 2 confirmed findings · 7 beyond budget',confirmed:2});
  assert.deepEqual(progressLine({stage: 'web-probes', message:
    '2 web leads executed; 0 queued untested; 0 confirmed security findings; 25 deferred to later pass'}),
  {label: 'Web tests', text: '2 leads executed · 25 deferred to later pass',confirmed:0});
});

test('Muse recovery and page progress explain preserved work without saying the audit paused',()=>{
  assert.deepEqual(progressLine({stage:'web-plan',message:'Muse web planning failed on page 2: Model request timed out. Earlier evidence is saved; retry explicitly.'}),
    {label:'Muse recovered',text:'A bounded Muse batch exceeded 60 seconds. Earlier evidence is saved; the audit continues with available and later work.'});
  assert.deepEqual(progressLine({stage:'web-plan',message:'Muse reviewed 20 of 80 web candidates in 1 of 3 pages'}),
    {label:'Muse web',text:'20 of 80 candidates reviewed · 1/3 bounded batches completed'});
  assert.deepEqual(progressLine({stage:'web-plan',message:'Muse reviewed 0 of 59 remaining web candidates in 0 of 3 pages'}),
    {label:'Muse web',text:'No new candidates reviewed in this pass · 59 remain available · continuing with saved evidence'});
});

test('source progress exposes bounded batch work and retained security leads',()=>{
  assert.deepEqual(progressLine({stage:'source',message:
    'Muse source review started: 37 of 37 route excerpts · 4 bounded batches · 4 parallel workers'}),
  {label:'Muse source',text:'Reviewing 37/37 route excerpts in 4 bounded batches · 4 parallel workers'});
  assert.deepEqual(progressLine({stage:'source',message:
    'Muse source batch 2/4 complete · 9 route excerpts reviewed'}),
  {label:'Muse source',text:'Source batch 2/4 complete · 9 route excerpts reviewed'});
  assert.deepEqual(progressLine({stage:'source',message:
    'Muse source review complete: 4/4 bounded batches · 37/37 route excerpts · 18 route notes · 6 security leads retained'}),
  {label:'Muse source',text:'Source review complete · 4/4 batches · 37/37 excerpts · 18 route notes · 6 security leads'});
});

test('the final audit screen leads with impact, remediation, coding brief and exact replay commands',()=>{
  const text=blackboxOutcomeText({run:'bx-20261103-1234abcd',projectRoot:'/tmp/app',origin:'https://app.test',
    memory:{saved:['memory_1']},findings:[{id:'f-001',verdict:'confirmed',severity:'medium',cwe:'CWE-307',
      title:'Login attempts are not throttled',pattern:'/api/login',rule:'20 failures without 429',
      assessment:{impact:'Attackers can automate guessing.',preconditions:'The endpoint is public.',
        remediation:'Return 429 and add progressive delays.'}}]});
  assert.match(text,/MEDIUM · CWE-307/);assert.match(text,/Business impact\nAttackers can automate guessing/);
  assert.match(text,/Recommended fix\nReturn 429/);assert.match(text,/COPY FOR YOUR CODING AGENT/);
  assert.match(text,/bypass blackbox verify 'bx-20261103-1234abcd' --project '\/tmp\/app'/);
  assert.match(text,/✓ Saved 1 confirmed finding/);
  const exported=regressionExportText({output:'/tmp/app/tests',files:["/tmp/app/tests/f-001.test.mjs"]});
  assert.match(exported,/✓ Saved 1 standalone regression test/);assert.match(exported,/node --test '\/tmp\/app\/tests\/f-001\.test\.mjs'/);
});

const CLI = fileURLToPath(new URL('../bin/bypass.mjs', import.meta.url));

test('plain CLI shows audit milestones, replay commands, and an honest coverage summary', async t => {
  const root = temp();
  t.after(() => fs.rmSync(root, {recursive: true, force: true}));
  const server = http.createServer((request, response) => {
    const url = new URL(request.url, 'http://local');
    if (url.pathname === '/openapi.json') {
      response.writeHead(200, {'content-type': 'application/json'});
      response.end(JSON.stringify({openapi: '3.0.0', paths: {'/api/go': {get: {
        parameters: [{name: 'next', in: 'query'}]}}}}));
    } else if (url.pathname === '/api/go') {
      const next = url.searchParams.get('next') ?? '/';
      if (/[\r\n]/.test(next)) {response.writeHead(400); response.end(); return;}
      response.writeHead(302, {location: next});
      response.end();
    } else {response.writeHead(404); response.end();}
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  t.after(() => new Promise(resolve => server.close(resolve)));
  const origin = `http://127.0.0.1:${server.address().port}`;
  assert.equal((await cli(root, 'blackbox', 'scope', origin, '--include', '/api')).code, 0);
  const run = await execFile(process.execPath, [CLI, 'blackbox', origin, '--project', root,
    '--accept-local', '--no-model', '--non-interactive'], {cwd: root, timeout: 30000});
  assert.equal(run.code, 1, run.stderr || run.stdout);
  assert.match(run.stderr, /BYPASS  \/  blackbox  ·  http:\/\/127\.0\.0\.1:/);
  assert.match(run.stderr, /1\/6  Doing  Scope and host discovery/);
  assert.match(run.stderr, /3\/6  Doing  Recon: routes and responses/);
  assert.match(run.stderr, /6\/6  Done   Report and coverage/);
  assert.match(run.stderr, /\d+ HTTP · 0 Muse(?: · \d+ findings?)? · \d+\/\d+ checks/);
  assert.match(run.stderr, /Accounts\s+Anonymous only/);
  assert.match(run.stderr, /Web tests\s+\d+ leads/);
  assert.match(run.stderr, /Web tests[^\n]*1 confirmed finding/);
  assert.doesNotMatch(run.stderr, /\x1b\[/);
  assert.doesNotMatch(run.stderr, /none of OWNER_TOKEN|No test accounts:|0 schemas, 0 root fields|0 public private-key candidates|off-origin script not fetched/);
  assert.match(run.stdout, /Findings: 1 confirmed/);
  assert.match(run.stdout, /Class coverage\s+\d+ of \d+ partly tested · \d+ not tested/);
  assert.match(run.stdout, /Report groups\s+\d+ exercised · \d+ partial · \d+ not tested \(24 broad groups\)/);
  assert.match(run.stdout, /bypass blackbox verify/);
  assert.match(run.stdout, /bypass blackbox export/);
  assert.match(run.stdout, /Exit 1/);
});

test('interactive progress redraws one colored live line as counters advance', () => {
  let clock = 1000;
  const chunks = [];
  const progress = createBlackboxProgress('http://127.0.0.1:3000', {write: value => chunks.push(value),
    isTTY: true, color: true, columns: () => 80, now: () => clock});
  progress({stage: 'progress', type: 'phase', state: 'doing', step: 4, total: 6,
    title: 'Test observed leads', requests: 10, modelCalls: 2});
  clock += 200;
  progress({stage: 'progress', type: 'task-total', total: 3});
  clock += 200;
  progress({stage: 'progress', type: 'request', requests: 11});
  clock += 200;
  progress({stage: 'progress', type: 'model', modelCalls: 3});
  progress({stage:'progress',type:'model-start',call:3,
    activity:'Planning an HTTP-sequence check',active:2,configured:4});
  clock += 25000;
  progress({stage:'progress',type:'model-finish',call:3,
    activity:'Planning an HTTP-sequence check',status:'completed',durationMs:25000,
    active:1,configured:4});
  clock += 200;
  progress({stage: 'progress', type: 'task-done', confirmed: true});
  progress({stage: 'progress', type: 'task-untested'});
  progress({stage: 'progress', type: 'phase', state: 'done', step: 4, total: 6,
    title: 'Test observed leads', requests: 11, modelCalls: 3});
  progress.finish();
  const output = chunks.join('');
  const plain = output.replace(/\x1b\[[0-9;]*m/g, '');
  assert.match(output, /\x1b\[2K/);
  assert.match(output, /\x1b\[36m/);
  assert.match(output, /11 HTTP · 3 Muse · 1 check run/);
  assert.match(output, /1 check run · 1 untested/);
  assert.match(plain, /Muse 3\s+Planning an HTTP-sequence check · started · 2\/4 active/);
  assert.match(plain, /Muse 3\s+completed · 00:25 · 1 still active/);
  assert.match(output, /4\/6  Done/);
});

test('live progress does not present provisional task estimates as untested checks', () => {
  const chunks = [];
  const progress = createBlackboxProgress('http://127.0.0.1:3000', {
    write: value => chunks.push(value), isTTY: true, color: false,
    columns: () => 100});
  progress({stage: 'progress', type: 'phase', state: 'doing', step: 4, total: 6,
    title: 'Plan and test observed leads'});
  progress({stage: 'progress', type: 'task-estimate', total: 10});
  progress({stage: 'progress', type: 'task-done'});
  progress({stage: 'progress', type: 'task-done'});
  progress({stage: 'progress', type: 'task-total', total: 12});
  progress({stage: 'progress', type: 'phase', state: 'done', step: 4, total: 6,
    title: 'Plan and test observed leads'});
  progress.finish();
  const output = chunks.join('');
  assert.match(output, /2 checks run/);
  assert.doesNotMatch(output, /2\/(?:10|12|22) checks/);
});

test('completed progress reconciles early deferred checks retried by a later pass', () => {
  const chunks = [];
  const progress = createBlackboxProgress('http://127.0.0.1:3000', {
    write: value => chunks.push(value), isTTY: false, color: false});
  progress({stage: 'progress', type: 'phase', state: 'doing', step: 4, total: 6,
    title: 'Plan and test observed leads'});
  // The live counter includes all pass records: early, primary and late.
  for (const [total, untested] of [[122, 38], [188, 14], [356, 78]]) {
    progress({stage: 'progress', type: 'task-total', total});
    for (let index = 0; index < total - untested; index++)
      progress({stage: 'progress', type: 'task-done'});
    for (let index = 0; index < untested; index++)
      progress({stage: 'progress', type: 'task-untested'});
  }
  // The late pass superseded 38 early deferred records; 13 private-read
  // checks were counted in the final ledger outside the live task counter.
  progress({stage: 'progress', type: 'task-reconcile', total: 641, done: 549,
    untested: 92});
  for (const [step, title] of [[4, 'Plan and test observed leads'],
    [5, 'Replay and assess'], [6, 'Report and coverage']]) {
    if (step !== 4) progress({stage: 'progress', type: 'phase', state: 'doing',
      step, total: 6, title});
    progress({stage: 'progress', type: 'phase', state: 'done', step, total: 6,
      title});
  }
  progress.finish();
  const completed = chunks.join('');
  assert.match(completed, /4\/6  Done[^\n]*549\/641 checks · 92 untested/);
  assert.match(completed, /5\/6  Done[^\n]*549\/641 checks · 92 untested/);
  assert.match(completed, /6\/6  Done[^\n]*549\/641 checks · 92 untested/);
  assert.doesNotMatch(completed, /130 untested/);
});

test('interactive recon shows the route review counter during Muse follow-up', () => {
  const chunks = [];
  const progress = createBlackboxProgress('http://127.0.0.1:3000', {write: value => chunks.push(value),
    isTTY: true, color: false, columns: () => 80});
  progress({stage: 'progress', type: 'phase', state: 'doing', step: 3, total: 6,
    title: 'Recon: routes and responses', requests: 40, modelCalls: 5});
  progress({stage: 'progress', type: 'recon-total', routesAvailable: 93});
  progress({stage: 'progress', type: 'recon', routesReviewed: 12, routesAvailable: 93,
    pathsAccepted: 4});
  progress({stage: 'progress', type: 'phase', state: 'done', step: 3, total: 6,
    title: 'Recon: routes and responses', requests: 61, modelCalls: 7});
  progress.finish();
  const output = chunks.join('');
  assert.match(output, /12\/93 routes/);
  assert.match(output, /\+4 paths/);
});

test('plain progress prints a quiet heartbeat with live counters during a long Muse call', () => {
  let clock = 0;
  const chunks = [];
  const progress = createBlackboxProgress('http://127.0.0.1:3000', {
    write: value => chunks.push(value), isTTY: false, color: false, now: () => clock});
  progress({stage: 'progress', type: 'phase', state: 'doing', step: 2, total: 6,
    title: 'Recon: assets and source', requests: 39, modelCalls: 1});
  clock = 14999;
  progress.heartbeat();
  assert.equal(chunks.filter(value => value.includes('…')).length, 0);
  progress({stage: 'progress', type: 'request', requests: 40});
  progress({stage: 'progress', type: 'model', modelCalls: 2});
  clock = 15000;
  progress.heartbeat();
  progress.heartbeat();
  assert.equal(chunks.filter(value => value.includes('…')).length, 1);
  assert.match(chunks.join(''), /… 2\/6  Recon: assets and source  ·  00:15  ·  40 HTTP · 2 Muse/);
  clock = 30000;
  progress.heartbeat();
  assert.equal(chunks.filter(value => value.includes('…')).length, 2);
  progress({stage: 'progress', type: 'phase', state: 'done', step: 2, total: 6,
    title: 'Recon: assets and source', requests: 40, modelCalls: 2});
  clock = 45000;
  progress.heartbeat();
  progress.finish();
  assert.equal(chunks.filter(value => value.includes('…')).length, 2);
  assert.doesNotMatch(chunks.join(''), /\x1b\[/);
});

test('plain heartbeat is not delayed another full period by a recent status line', async () => {
  let clock = 0;
  const chunks = [];
  const progress = createBlackboxProgress('http://127.0.0.1:3000', {
    write: value => chunks.push(value), isTTY: false, color: false, now: () => clock});
  progress({stage: 'progress', type: 'phase', state: 'doing', step: 2, total: 6,
    title: 'Recon: assets and source'});
  clock = 100;
  progress({stage: 'assets', message: 'mined 1 files: 1 endpoints (0 non-GET), 0 hosts, 0 secrets, 0 source maps'});
  clock = 15100;
  await new Promise(resolve => setTimeout(resolve, 1200));
  progress.finish();
  assert.match(chunks.join(''), /… 2\/6  Recon: assets and source/);
});

test('research progress names the active route and counts feedback attempts', () => {
  const chunks = [];
  const progress = createBlackboxProgress('http://127.0.0.1:3000', {
    write: value => chunks.push(value), isTTY: true, color: false, columns: () => 100});
  progress({stage: 'progress', type: 'phase', state: 'doing', step: 4, total: 6,
    title: 'Test observed leads', requests: 10, modelCalls: 2});
  progress({stage: 'progress', type: 'research-attempt'});
  progress({stage: 'research', message: '/api/compute · attempt 1 · not reproduced'});
  progress.finish();
  const output = chunks.join('');
  assert.match(output, /1 research tries/);
  assert.match(output, /Muse research\s+\/api\/compute · attempt 1 · not reproduced/);
});
