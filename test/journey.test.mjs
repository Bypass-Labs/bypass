import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { temp, port, cli } from './helpers.mjs';
import { startDemo, updateDemo } from '../src/demo.mjs';
import { execute } from '../src/service.mjs';
import { read, change } from '../src/store.mjs';
import { execFile, delay } from '../src/util.mjs';
import { replay } from '../src/portable-check.mjs';
import { specFor } from '../src/checks.mjs';

test('full real fixture journey: discover → prove → fix → retest → standalone replay → regression → monitoring → new route',async t=>{
  const root=temp();const demo=await startDemo(root,{port:await port()});t.after(async()=>{await updateDemo(root,'stop');await delay(600);});
  assert.match(demo.url,/127.0.0.1/);assert.equal(read(root).project.repository.kind,'git');
  const first=await cli(root,'scan');assert.equal(first.code,3);assert.equal(first.data.run.result.regression.length,0);
  const finding=read(root).findings[0];
  const proof=await cli(root,'verify',finding.id);assert.equal(proof.code,1);assert.equal(proof.data.status,'confirmed_fixture');assert.equal(proof.data.verification.controls[0].status,200);assert.equal(proof.data.verification.controls[1].status,200);
  assert.equal((await cli(root,'test','save',finding.id)).code,0);assert.equal(read(root).checks[0].baseline,'failing_reproduction');
  // A normal source edit (as Muse would make) changes the running app without a restart.
  const app=path.join(root,'app.mjs');fs.writeFileSync(app,fs.readFileSync(app,'utf8').replace('enforceOwnership = false','enforceOwnership = true'));
  const retest=await cli(root,'retest',finding.id,'--build','operator-build-123');assert.equal(retest.code,0);assert.equal(retest.data.status,'fixed_verified');
  const check=read(root).checks[0];assert.ok(check);assert.equal(retest.data.verification.controls[1].status,403);
  const repeated=await cli(root,'retest',finding.id);assert.equal(repeated.code,0);assert.equal(read(root).checks.length,1);
  const exported=await cli(root,'test','export','--all');assert.equal(exported.code,0);
  const standalone=await execFile(process.execPath,['--test',...exported.data.files],{cwd:root,env:{NODE_TEST_CONTEXT:undefined}});assert.equal(standalone.code,0,standalone.stdout+standalone.stderr);assert.match(standalone.stdout,/# tests 1/);
  const clean=await cli(root,'test','run','--all');assert.equal(clean.code,0);assert.equal(clean.data.run.result.modelCalls,0);
  const rescan=await cli(root,'scan');assert.equal(rescan.data.run.result.findings.length,0);assert.equal(rescan.data.run.result.exactPassingChecksExcluded.length,1);
  await cli(root,'demo','regress');
  const regression=await cli(root,'test','run','--all');assert.equal(regression.code,1);assert.equal(regression.data.run.result.results[0].status,'failed');assert.equal(regression.data.run.result.modelCalls,0);
  const failedStandalone=await execFile(process.execPath,['--test',...exported.data.files],{cwd:root,env:{NODE_TEST_CONTEXT:undefined}});assert.equal(failedStandalone.code,1,failedStandalone.stdout+failedStandalone.stderr);assert.match(failedStandalone.stdout,/# fail 1/);
  const monitor=await cli(root,'monitor','add','hourly','--target','demo','--every','1h');assert.equal(monitor.code,0);
  const worker=await cli(root,'monitor','worker','--once');assert.equal(worker.code,0);assert.equal(worker.data.runs.length,1);
  const context=await cli(root,'context');assert.ok(context.data.recentEvents.some(e=>e.kind==='monitor-result'&&e.message.includes('regression detected')));
  await cli(root,'demo','fix');await cli(root,'retest',finding.id);
  await cli(root,'demo','add-route');
  const newRoute=await cli(root,'scan');assert.equal(newRoute.data.run.result.regression[0].status,'stale');assert.ok(newRoute.data.run.result.findings.length);
  const exportFinding=read(root).findings.find(f=>f.fingerprint.endsWith('invoice-export'));assert.ok(exportFinding);assert.equal((await cli(root,'verify',exportFinding.id)).code,1);
  await cli(root,'demo','fix');assert.equal((await cli(root,'retest',exportFinding.id)).code,0);assert.equal(read(root).checks.length,2);
  const reportFile=path.join(root,'run-report.md');const report=await cli(root,'report','--format','md','--out',reportFile);assert.equal(report.code,0);assert.match(fs.readFileSync(reportFile,'utf8'),/Analysis simulated/);
  const revoke=await cli(root,'target','revoke','demo');assert.equal(revoke.code,0);assert.equal(read(root).monitors[0].enabled,false);assert.equal((await cli(root,'test','run','--all')).code,3);
});

test('positive-control failures are blocked, source changes become stale, and detached jobs can be cancelled',async t=>{
  const root=temp();await startDemo(root,{port:await port()});t.after(async()=>{await updateDemo(root,'stop');await delay(600);});
  await execute('scan',[],{project:root});const finding=read(root).findings[0];await updateDemo(root,'fix');await execute('retest',[finding.id],{project:root});
  let state=read(root),check=state.checks[0];let spec=specFor(state,check,'demo');spec.resourceId='nonexistent';
  const blocked=await replay(spec);assert.equal(blocked.status,'blocked');assert.equal(blocked.requests,1);assert.match(blocked.reason,/positive control/);
  spec=specFor(state,check,'demo');spec.outsider=spec.owner;assert.equal((await replay(spec)).status,'blocked');
  fs.appendFileSync(path.join(root,'app.mjs'),'\n// changed deployment logic\n');
  const stale=await execute('test run',[],{project:root,all:true});assert.equal(stale.exitCode,3);assert.equal(stale.run.result.results[0].status,'stale');
  await change(root,s=>{s.targets[0].authorization.maxRequestsPerSecond=1;});
  const background=await cli(root,'test','run','--all','--detach');assert.equal(background.code,0);assert.equal(background.data.status,'accepted');
  await delay(200);await cli(root,'run','stop',background.data.runId);
  const cancelled=await cli(root,'run','watch',background.data.runId,'--timeout','10s');assert.equal(cancelled.code,130);assert.equal(cancelled.data.run.status,'cancelled');
});
