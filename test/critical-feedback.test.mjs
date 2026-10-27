import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { temp } from './helpers.mjs';
import { execute, readiness } from '../src/service.mjs';
import { read, change } from '../src/store.mjs';
import { createRun, executeRun, scanPlan } from '../src/engine.mjs';
import { watchRun } from '../src/jobs.mjs';
import { pluginOnboarding } from '../src/plugin-onboarding.mjs';
import { startPOC, stopPOC } from '../src/poc.mjs';
import { printResult } from '../src/ui.mjs';
import { comparePlugin } from '../src/runtime-identity.mjs';
import { inferenceFailure } from '../src/inference.mjs';
import { Fault } from '../src/util.mjs';

const onboarding=root=>pluginOnboarding(root,root,{checkDocker:async()=>({available:true})});
async function fixture(t){const root=path.join(temp(),'app');await startPOC({dir:root});t.after(()=>stopPOC(root));return root;}
const noAI={prepareAgents:async()=>assert.fail('No Docker before valid accounts/resource'),infer:async()=>assert.fail('No AI before valid accounts/resource'),testModel:async()=>assert.fail('No model preflight before valid accounts/resource')};

test('missing credentials are blocked consistently in plan, status and onboarding, with zero model calls',async t=>{
  const root=await fixture(t);
  await change(root,s=>{delete s.identities[1].fixtureValue;s.identities[1].secretEnv='BYPASS_TEST_MISSING_ACCOUNT';});
  const plan=scanPlan(read(root),{mode:'combined'}),status=readiness(root),setup=await onboarding(root);
  assert.equal(plan.blackBox.status,'blocked');assert.match(plan.blockers.join(' '),/BYPASS_TEST_MISSING_ACCOUNT.*terminal/);
  assert.equal(status.ready.liveTesting,false);assert.equal(status.ready.liveReview,false);assert.equal(setup.ready.live,false);
  assert.equal(setup.nextAction.id,'accounts');
  const run=await createRun(root,'scan',{mode:'combined'}),result=await executeRun(root,run.id,null,null,{runtime:noAI});
  assert.equal(result.run.status,'failed');assert.equal(result.run.modelCalls,0);assert.equal(result.run.result.details.stage,'setup');
  assert.equal((await watchRun(root,run.id,100)).run.status,'failed');
});

test('placeholder resource is rejected by real owner control before any model or container',async t=>{
  const root=await fixture(t);
  await change(root,s=>{s.targets[0].probes[0].binding.resourcePath='/api/invoices/placeholder';s.targets[0].probes[0].binding.resourceId='placeholder';});
  assert.equal(scanPlan(read(root),{mode:'combined'}).blackBox.status,'preflight_required');
  assert.equal((await onboarding(root)).nextAction.tool,'bypass_test_probe');
  const run=await createRun(root,'scan',{mode:'combined'}),result=await executeRun(root,run.id,null,null,{runtime:noAI});
  assert.equal(result.run.status,'failed');assert.equal(result.exitCode,3);assert.equal(result.run.modelCalls,0);
  assert.equal(result.run.result.details.stage,'accounts');assert.equal(result.run.agentEvidence.preflight[0].requests,3);
  assert.match(result.run.result.message,/Owner positive control/);assert.equal(readiness(root).ready.liveTesting,false);
});

test('positive preflight validates only three controls; changing token, binding or expiry invalidates readiness',async t=>{
  const root=await fixture(t);
  const check=await execute('probe test',['invoice'],{project:root});
  assert.equal(check.exitCode,0);assert.equal(check.validation.status,'ready');assert.equal(check.validation.requests,3);
  assert.equal(check.validation.securityConclusion,false);assert.equal(check.validation.modelCalls,0);
  assert.deepEqual(check.validation.controls.map(c=>c.label),['owner identity','outsider identity','owner access']);
  assert.equal(readiness(root).ready.liveReview,true);assert.equal((await onboarding(root)).ready.live,true);
  await change(root,s=>{s.identities[1].fixtureValue='invalid-test-token';});
  assert.equal(readiness(root).ready.liveReview,false);
  const blocked=await execute('probe test',['invoice'],{project:root});assert.equal(blocked.exitCode,3);assert.match(blocked.validation.reason,/refresh|Refresh/);
  await change(root,s=>{s.identities[1].fixtureValue='poc-outsider-token';});
  await execute('probe test',['invoice'],{project:root});
  await change(root,s=>{s.targets[0].probes[0].binding.idField='wrong';});assert.equal(readiness(root).ready.liveReview,false);
  await change(root,s=>{s.targets[0].probes[0].binding.idField='id';s.targets[0].probes[0].validation.checkedAt='2000-01-01T00:00:00Z';});assert.equal(readiness(root).ready.liveReview,false);
});

test('failed white-box run preserves source reads and structured cause, terminates watch and stays compact in context',async()=>{
  const root=temp();fs.writeFileSync(path.join(root,'app.js'),'export const route = "/api/items";\n');
  await execute('init',[root]);await execute('engine use',['docker'],{project:root});await execute('model add',['muse'],{project:root,provider:'muse-code'});
  const run=await createRun(root,'scan',{mode:'code'});
  const result=await executeRun(root,run.id,null,null,{runtime:{
    prepareAgents:async()=>({image:'scripted'}),
    infer:async(_profile,messages,{onProgress})=>{if(messages[0].content.startsWith('Plan'))return {focus:'Review'};onProgress({kind:'phase',phase:'stream_failed',httpStatus:503,message:'Provider HTTP 503'});throw new Fault('Provider unavailable',3,{reason:'provider_unavailable',nativeExitCode:1});},
    runContainer:async(_role,_task,rpc)=>rpc('model',{messages:[{role:'user',content:'review'}]})
  }});
  assert.equal(result.run.status,'failed');assert.equal(result.run.exitCode,3);
  assert.equal(result.run.result.details.stage,'white-box');assert.equal(result.run.result.details.call,2);assert.equal(result.run.result.details.httpStatus,503);
  assert.equal(result.run.agentEvidence.containers[0].status,'failed');assert.equal(result.run.agentEvidence.focus,'Review');
  assert.equal(result.run.agentEvidence.sourceReads[0].file,'app.js');assert.equal(result.run.agentEvidence.modelUsage.at(-1).status,'failed');
  assert.equal((await watchRun(root,run.id,100)).run.status,'failed');
  const context=await execute('context',[],{project:root});assert.equal(context.summary.latestRun.id,run.id);assert.equal(context.summary.latestRun.sourceReads,1);
  assert.equal(context.summary.latestRun.steps,undefined);assert.equal(context.summary.latestRun.result,undefined);
  assert.equal(JSON.parse(fs.readFileSync(path.join(root,'.bypass/runs',run.id+'.json'))).status,'failed');
});

test('failed model configuration never shows ready and active runs outrank old findings',async()=>{
  const root=temp();await execute('init',[root]);await execute('engine use',['docker'],{project:root});await execute('model add',['muse'],{project:root,provider:'muse-code'});
  await change(root,s=>{s.models[0].lastAttempt={status:'failed',checkedAt:new Date().toISOString()};s.findings.push({id:'mock',simulation:true,status:'simulated_unproven'});});
  assert.equal(readiness(root).ready.model,false);assert.equal(scanPlan(read(root),{mode:'code'}).whiteBox.status,'blocked');assert.equal((await onboarding(root)).stage,'connection');
  assert.equal(readiness(root).findings.total,0);assert.equal(readiness(root).findings.hiddenSimulated,1);
  assert.equal((await execute('finding list',[],{project:root})).findings.length,0);assert.equal(read(root).findings.length,1,'historical evidence retained');
  const run=await createRun(root,'scan',{mode:'code'});assert.equal(readiness(root).next,`run watch ${run.id}`);
});

test('doctor renders environment checks, not saved security checks',t=>{
  const output=[];t.mock.method(console,'log',line=>output.push(line));
  printResult({kind:'environment-diagnostics',runtime:{version:'test',sourcePath:'/tool'},checks:[{name:'Node >=22',ok:true,version:'v22'},{name:'Docker',ok:false,message:'Socket permission denied'}],message:'Diagnostics only'});
  assert.match(output.join('\n'),/Environment checks/);assert.match(output.join('\n'),/Socket permission denied/);assert.doesNotMatch(output.join('\n'),/undefined|saved checks/);
});

test('installed versus loaded cache detects stale session even at the same version',()=>{
  const record={version:'0.2.4',cache_path:'/home/plugins/cache/new/package',source:{path:'/home/tool/plugin'}};
  assert.equal(comparePlugin(record,{version:'0.2.4',sourcePath:'/home/plugins/cache/old/package/runtime'}).restartRequired,true);
  assert.equal(comparePlugin(record,{version:'0.2.4',sourcePath:'/home/plugins/cache/new/package/runtime'}).restartRequired,false);
});

test('provider diagnostic retains HTTP cause without returning provider text or tokens',()=>{
  const error=inferenceFailure({code:1,stderr:'PRIVATE_TOKEN source body'},[{kind:'task_lifecycle',event:{details:{facets:[{kind:'external_attempt',http_status:429}]}}}]);
  assert.equal(error.details.reason,'usage_limit');assert.equal(error.details.httpStatus,429);assert.doesNotMatch(JSON.stringify(error),/PRIVATE_TOKEN|source body/);
});


test('doctor works before initialization without creating project state',async()=>{
  const root=temp(),result=await execute('doctor',[],{project:root});
  assert.equal(result.kind,'environment-diagnostics');assert.equal(result.readiness,null);
  assert.ok(result.checks.some(c=>c.name==='Node >=22'));assert.ok(result.checks.some(c=>c.name==='Docker'));
  assert.equal(fs.existsSync(path.join(root,'.bypass')),false);
});
