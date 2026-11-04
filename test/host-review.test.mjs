import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import http from 'node:http';
import { mcpClient } from './mcp-client.mjs';
import { temp } from './helpers.mjs';
import { read, change } from '../src/store.mjs';
import { execute } from '../src/service.mjs';
import { execFile } from '../src/util.mjs';
import { stopPOC } from '../src/poc.mjs';
import { beginHostReview, hostReviewStep, combinedFocusBudget, combinedReviewHandoff } from '../src/host-review.mjs';
import { inExecutionMode } from '../src/execution-mode.mjs';
import { inventory } from '../src/repository.mjs';

function saveFocusedProof(folder,url,route,{verdict='confirmed',spec={}}={}) {
  const proof=path.join(folder,'poc','f-001','poc.mjs');
  fs.mkdirSync(path.dirname(proof),{recursive:true});
  fs.writeFileSync(proof,'// saved proof fixture\n');
  fs.writeFileSync(path.join(path.dirname(proof),'spec.json'),JSON.stringify(spec));
  fs.writeFileSync(path.join(folder,'findings.json'),JSON.stringify([{id:'f-001',
    verdict,url:new URL(route,url).href,proof}]));
}

test('connected combined handoff carries cited leads into one full live run and reports its proof',async()=>{
  const root=temp(),url='http://127.0.0.1:4444';
  fs.writeFileSync(path.join(root,'routes.mjs'),"app.get('/api/one', handler);\n");
  await execute('init',[root]);
  await execute('target add',['app'],{project:root,url,environment:'local'});
  await execute('target verify',['app'],{project:root,method:'local'});
  const scope=path.join(root,'approved.json');
  fs.writeFileSync(scope,JSON.stringify({paths:['/'],methods:['GET','HEAD'],maxRequestsPerSecond:7}));
  await execute('target authorize',['app'],{project:root,'scope-file':scope,accept:true});
  const started=await beginHostReview(root,{mode:'combined',modelCalls:12,minutes:5,broadLive:true});
  const proposed=await hostReviewStep(root,{id:started.runId,action:'source',candidates:[{
    title:'Unprotected route',category:'missing-authentication',file:'routes.mjs',line:1,
    quote:"app.get('/api/one', handler);",resourcePath:'/api/one',
    hypothesis:'Anonymous caller may read the route.',recommendation:'Require a session.'}]});
  await change(root,s=>{s.runs.find(run=>run.id===started.runId).status='completed';});
  const ready=await hostReviewStep(root,{id:started.runId,action:'status'});
  assert.equal(ready.nextAction.tool,'bypass_blackbox_setup');
  assert.equal(ready.liveValidation.length,1);
  const handoff=combinedReviewHandoff(root,started.runId,url);
  assert.equal(handoff.limits['model-calls'],12);
  assert.equal(handoff.sourceContext.securityLeads[0].id,proposed.findings[0]);
  assert.equal(handoff.sourceContext.endpoints[0].path,'/api/one');
  assert.equal(handoff.sourceContext.modelCalls,0);
  const folder=path.join(root,'.bypass','runs','bx-connected');fs.mkdirSync(folder,{recursive:true});
  fs.writeFileSync(path.join(folder,'run-start.json'),JSON.stringify({run:'bx-connected',
    status:'running',combinedReviewId:started.runId,origin:url,startedAt:new Date().toISOString()}));
  const running=await hostReviewStep(root,{id:started.runId,action:'status'});
  assert.equal(running.nextAction.tool,'bypass_blackbox_next');
  assert.equal(running.liveAudit.runId,'bx-connected');
  assert.throws(()=>combinedReviewHandoff(root,started.runId,url),/already has a live audit/);
  const proof=path.join(folder,'poc','one','poc.mjs');fs.mkdirSync(path.dirname(proof),{recursive:true});
  fs.writeFileSync(proof,'// fixture\n');
  fs.writeFileSync(path.join(path.dirname(proof),'spec.json'),JSON.stringify({request:{path:'/api/one'}}));
  fs.writeFileSync(path.join(folder,'findings.json'),JSON.stringify([{id:'proof-one',verdict:'confirmed',
    sourceFinding:{id:proposed.findings[0]},url:`${url}/api/one`,proof}]));
  fs.writeFileSync(path.join(folder,'report.json'),JSON.stringify({surface:{application:{sourceFindings:[{
    id:proposed.findings[0],path:'/api/one',status:'confirmed live',liveReason:'Fresh proof.'}]}}}));
  fs.writeFileSync(path.join(folder,'run.json'),JSON.stringify({run:'bx-connected',status:'partial',
    combinedReviewId:started.runId,scope:{target:{origin:url}},startedAt:new Date().toISOString(),
    finishedAt:new Date().toISOString(),stats:{modelCalls:3}}));
  const done=await hostReviewStep(root,{id:started.runId,action:'status'});
  assert.equal(done.liveValidation[0].status,'confirmed');
  assert.equal(done.liveValidation[0].runId,'bx-connected');
  assert.equal(done.liveAudit.confirmed,1);
  assert.equal(done.combinedBudget.modelCallsUsed,3);
  assert.equal(done.nextAction.tool,'bypass_findings');
});

test('combined review retains exact scope and advances every focused source finding',async()=>{
  const root=temp(),url='http://127.0.0.1:4444';
  fs.writeFileSync(path.join(root,'routes.mjs'),"app.get('/api/one', handler);\napp.post('/api/two', handler);\n");
  await execute('init',[root]);
  await execute('target add',['app'],{project:root,url,environment:'local'});
  await execute('target verify',['app'],{project:root,method:'local'});
  const approved=path.join(root,'approved.json');
  fs.writeFileSync(approved,JSON.stringify({paths:['/api'],methods:['GET','HEAD','POST','PUT','PATCH','DELETE','OPTIONS'],maxRequestsPerSecond:7}));
  await execute('target authorize',['app'],{project:root,'scope-file':approved,accept:true});
  const started=await beginHostReview(root,{mode:'combined',modelCalls:73,minutes:15});
  const candidate=(title,line,resourcePath)=>({title,category:'missing-authentication',file:'routes.mjs',line,
    quote:fs.readFileSync(path.join(root,'routes.mjs'),'utf8').split('\n')[line-1],resourcePath,
    hypothesis:'The route may be accessible without authentication.',recommendation:'Require a valid session.'});
  const proposed=await hostReviewStep(root,{id:started.runId,action:'source',candidates:[candidate('First route',1,'/api/one'),candidate('Second route',2,'/api/two')]});
  assert.equal(proposed.liveValidation.length,2);
  assert.deepEqual(proposed.liveValidation[0].setup.arguments,{url,include:'/api',methods:'GET,HEAD,POST,PUT,PATCH,DELETE,OPTIONS',rps:7,environment:'local',out:proposed.liveValidation[0].setup.arguments.out,'model-calls':73,minutes:proposed.liveValidation[0].setup.arguments.minutes});
  assert.ok(proposed.liveValidation[0].setup.arguments.minutes>0&&proposed.liveValidation[0].setup.arguments.minutes<=15);
  assert.equal(proposed.liveValidation[0].runLimits['model-calls'],73);
  assert.equal(proposed.liveValidationProgress.pending,2);
  await change(root,s=>{s.runs.find(run=>run.id===started.runId).status='completed';});
  const first=proposed.liveValidation[0].finding;
  const folder=path.join(root,'.bypass','runs','bx-focused-one');fs.mkdirSync(folder,{recursive:true});
  fs.writeFileSync(path.join(folder,'run.json'),JSON.stringify({run:'bx-focused-one',focus:{findingId:first,path:'/api/one'},scope:{target:{origin:url}},startedAt:new Date().toISOString(),finishedAt:new Date().toISOString(),stats:{tasks:1,confirmed:1,modelCalls:11}}));
  saveFocusedProof(folder,url,'/api/one');
  const progress=await hostReviewStep(root,{id:started.runId,action:'status'});
  assert.equal(progress.liveValidation[0].status,'confirmed');
  assert.equal(progress.liveValidationProgress.pending,1);
  assert.equal(progress.nextAction.tool,'bypass_blackbox_setup');
  assert.equal(progress.nextAction.finding,proposed.liveValidation[1].finding);
  assert.equal(progress.nextAction.arguments.methods,'GET,HEAD,POST,PUT,PATCH,DELETE,OPTIONS');
  assert.equal(progress.nextAction.arguments['model-calls'],62);
  assert.equal(progress.combinedBudget.modelCallsUsed,11);
  assert.equal(combinedFocusBudget(root,progress.liveValidation[1].finding).modelCallsRemaining,62);
  await change(root,s=>{s.runs.find(run=>run.id===started.runId).options.modelCalls=11;});
  const partial=await hostReviewStep(root,{id:started.runId,action:'status'});
  assert.deepEqual(partial.remediation.confirmed.map(item=>item.finding),[first]);
  assert.deepEqual(partial.remediation.untested,[proposed.liveValidation[1].finding]);
  assert.match(partial.nextAction.message,/Offer to fix all confirmed issues/);
  await change(root,s=>{s.runs.find(run=>run.id===started.runId).options.modelCalls=73;});
  const second=path.join(root,'.bypass','runs','bx-focused-two');fs.mkdirSync(second,{recursive:true});
  fs.writeFileSync(path.join(second,'run.json'),JSON.stringify({run:'bx-focused-two',focus:{findingId:first,path:'/api/one'},scope:{target:{origin:url}},startedAt:new Date(Date.now()+1000).toISOString(),finishedAt:new Date().toISOString(),stats:{tasks:1,modelCalls:62,notReproduced:1}}));
  const exhausted=await hostReviewStep(root,{id:started.runId,action:'status'});
  assert.equal(exhausted.combinedBudget.modelCallsRemaining,0);
  assert.equal(exhausted.nextAction.tool,'bypass_findings');
  await assert.rejects(inExecutionMode('muse-host',()=>execute('blackbox',[url],
    {project:root,finding:progress.liveValidation[1].finding})),/Combined audit limit reached/);
  for(const [name,finding,offset] of [
    ['bx-focused-three',first,2000],
    ['bx-focused-four',progress.liveValidation[1].finding,3000]]){
    const folder=path.join(root,'.bypass','runs',name);fs.mkdirSync(folder,{recursive:true});
    fs.writeFileSync(path.join(folder,'run.json'),JSON.stringify({run:name,focus:{findingId:finding,path:finding===first?'/api/one':'/api/two'},
      scope:{target:{origin:url}},startedAt:new Date(Date.now()+offset).toISOString(),
      finishedAt:new Date(Date.now()+offset).toISOString(),stats:{tasks:1,confirmed:1,modelCalls:0}}));
    saveFocusedProof(folder,url,finding===first?'/api/one':'/api/two');
  }
  await change(root,state=>{state.runs.find(run=>run.id===started.runId).status='completed';});
  const ready=await hostReviewStep(root,{id:started.runId,action:'status'});
  assert.deepEqual(ready.remediation.confirmed.map(item=>item.finding),
    [first,progress.liveValidation[1].finding]);
  assert.match(ready.nextAction.message,/Offer to fix all confirmed issues and open a PR/);
  const fingerprint=(await inventory(root)).fingerprint;
  const generated=path.join(root,'tests/security/blackbox/bx-focused-one-f-001.test.mjs');
  fs.mkdirSync(path.dirname(generated),{recursive:true});fs.writeFileSync(generated,'export const regression = true;');
  assert.equal((await inventory(root)).fingerprint,fingerprint,'generated blackbox regressions must not invalidate source citations');
  const focused=path.join(root,'tests/security/blackbox-f001/bx-focused-two-f-001.test.mjs');
  fs.mkdirSync(path.dirname(focused),{recursive:true});fs.writeFileSync(focused,'export const regression = true;');
  assert.equal((await inventory(root)).fingerprint,fingerprint,'focused regression output must not invalidate source citations');
});

test('combined receipt does not promote unsealed or unrelated focused tasks to proof',async()=>{
  const root=temp(),url='http://127.0.0.1:4444';
  fs.writeFileSync(path.join(root,'routes.mjs'),"app.post('/login', handler);\n");
  await execute('init',[root]);
  await execute('target add',['app'],{project:root,url,environment:'local'});
  await execute('target verify',['app'],{project:root,method:'local'});
  const approved=path.join(root,'approved.json');
  fs.writeFileSync(approved,JSON.stringify({paths:['/'],methods:['GET'],maxRequestsPerSecond:2}));
  await execute('target authorize',['app'],{project:root,'scope-file':approved,accept:true});
  const started=await beginHostReview(root,{mode:'combined',modelCalls:20,minutes:15});
  const quote=fs.readFileSync(path.join(root,'routes.mjs'),'utf8').trim();
  const candidate={title:'First route',category:'missing-authentication',file:'routes.mjs',line:1,
    quote,resourcePath:'/login',hypothesis:'Anonymous access may succeed.',recommendation:'Require a session.'};
  const proposed=await hostReviewStep(root,{id:started.runId,action:'source',candidates:[candidate]});
  await change(root,s=>{s.runs.find(run=>run.id===started.runId).status='completed';});
  const folder=path.join(root,'.bypass','runs','bx-focused-unsealed');fs.mkdirSync(folder,{recursive:true});
  fs.writeFileSync(path.join(folder,'run.json'),JSON.stringify({run:'bx-focused-unsealed',
    focus:{findingId:proposed.liveValidation[0].finding,path:'/login'},scope:{target:{origin:url}},
    startedAt:new Date().toISOString(),finishedAt:new Date().toISOString(),stats:{tasks:1,confirmed:1,modelCalls:1}}));
  assert.equal((await hostReviewStep(root,{id:started.runId,action:'status'})).liveValidation[0].status,'inconclusive');
  const saved=JSON.parse(fs.readFileSync(path.join(folder,'run.json'),'utf8'));
  saved.stats={tasks:1,notReproduced:1,modelCalls:1};
  fs.writeFileSync(path.join(folder,'run.json'),JSON.stringify(saved));
  const unrelated=await hostReviewStep(root,{id:started.runId,action:'status'});
  assert.equal(unrelated.liveValidation[0].status,'untested');
  assert.match(unrelated.liveValidation[0].reason,/focused hypothesis/);
  saved.stats={tasks:1,blocked:1,modelCalls:1};
  fs.writeFileSync(path.join(folder,'run.json'),JSON.stringify(saved));
  assert.equal((await hostReviewStep(root,{id:started.runId,action:'status'})).liveValidation[0].status,'untested');
  saveFocusedProof(folder,url,'/api/other');
  assert.equal((await hostReviewStep(root,{id:started.runId,action:'status'})).liveValidation[0].status,'untested');
  saveFocusedProof(folder,url,'/private',{spec:{prelude:[{method:'POST',path:'/login'}],
    subject:{method:'GET',path:'/private'}}});
  assert.equal((await hostReviewStep(root,{id:started.runId,action:'status'})).liveValidation[0].status,'confirmed');
});

test('combined receipt shows source leads without a live route as blocked',async()=>{
  const root=temp(),url='http://127.0.0.1:4444';
  fs.writeFileSync(path.join(root,'app.mjs'),'export const weak = true;\n');
  await execute('init',[root]);
  await execute('target add',['app'],{project:root,url,environment:'local'});
  await execute('target verify',['app'],{project:root,method:'local'});
  const approved=path.join(root,'approved.json');
  fs.writeFileSync(approved,JSON.stringify({paths:['/'],methods:['GET'],maxRequestsPerSecond:2}));
  await execute('target authorize',['app'],{project:root,'scope-file':approved,accept:true});
  const started=await beginHostReview(root,{mode:'combined',modelCalls:20,minutes:15});
  const proposed=await hostReviewStep(root,{id:started.runId,action:'source',candidates:[{
    title:'Source issue without route',category:'insecure-configuration',file:'app.mjs',line:1,
    quote:'export const weak = true;',resourcePath:null,hypothesis:'A configuration may be weak.',
    recommendation:'Tighten the configuration.'}]});
  assert.equal(proposed.liveValidationProgress.total,1);
  assert.equal(proposed.liveValidation[0].status,'blocked');
  assert.match(proposed.liveValidation[0].reason,/No concrete application path/);
});

test('native MCP journey: host plans, source hypotheses, real proof, fix, exported regression; no API calls even with inherited keys',async t=>{
  let apiRequests=0;const trap=http.createServer((_q,r)=>{apiRequests++;r.writeHead(500);r.end();});await new Promise(r=>trap.listen(0,'127.0.0.1',r));t.after(()=>trap.close());
  const home=temp(),c=await mcpClient(home,{stateDir:path.join(home,'state'),env:{OPENAI_API_KEY:'ignored-host-key',MODEL_API_KEY:'ignored-host-key',BYPASS_HOST_TEST_API_KEY:'ignored-host-key'}});t.after(()=>c.close());
  const fixture=await c.call('bypass_demo_start',{kind:'real'}),root=fixture.root;t.after(()=>stopPOC(root));
  // Even an old profile pointed at a reachable API cannot change host execution.
  await change(root,s=>{s.models=[{name:'legacy',provider:'local',model:'anything',baseUrl:`http://127.0.0.1:${trap.address().port}/v1`,secretEnv:'BYPASS_HOST_TEST_API_KEY'}];s.activeModel='legacy';});
  const onboarding=await c.call('bypass_onboarding');assert.equal(onboarding.ready.source,true);assert.equal(onboarding.steps.some(s=>['model','docker'].includes(s.id)),false);assert.equal(onboarding.ai.billing.verified,false);
  await c.call('bypass_test_model');assert.equal(apiRequests,0);
  const run=await c.call('bypass_scan',{mode:'combined'});assert.equal(run.status,'awaiting_host');assert.equal(run.executionMode,'muse-host');
  const source=await c.call('bypass_review_step',{id:run.runId,action:'read',paths:['policy.mjs','server.mjs']});assert.match(source.files[0].source,/Boolean\(account\)/);
  const candidate={title:'Missing invoice owner check',category:'cross-account-access',file:'policy.mjs',line:2,quote:'  return Boolean(account);',resourcePath:'/api/invoices/inv-101',hypothesis:'Any authenticated account can access the invoice.',recommendation:'Compare caller to invoice.ownerId.'};
  const ungrounded=await c.raw('bypass_review_step',{id:run.runId,action:'source',candidates:[{...candidate,quote:'invented'}]});assert.equal(ungrounded.result.isError,true);
  const sourceResult=await c.call('bypass_review_step',{id:run.runId,action:'source',candidates:[candidate],knowledge:[{topic:'authorization',title:'Invoice ownership missing',summary:'Current policy accepts any signed-in account.',file:'policy.mjs',line:2,quote:candidate.quote}]});
  assert.equal(sourceResult.liveValidation[0]?.finding,read(root).findings[0].id);
  assert.equal(sourceResult.liveValidation[0]?.url,read(root).targets[0].url);
  assert.equal(read(root).findings[0].status,'unproven');
  const proof=await c.call('bypass_review_step',{id:run.runId,action:'probe',index:0});assert.equal(proof.observation.status,'failed');assert.deepEqual(proof.observation.controls.map(x=>x.status),[200,200,200,200,401]);
  const findingId=proof.findings[0];assert.equal(read(root).findings[0].status,'confirmed');
  const earlyFinish=await c.call('bypass_review_step',{id:run.runId,action:'finish'});assert.equal(earlyFinish.status,'awaiting_host');
  await c.call('bypass_add_probe',{name:'login-anonymous',path:'/api/me',kind:'anonymous',expected:'private','resource-id':'account-alice'});
  const finished=await c.call('bypass_review_step',{id:run.runId,action:'complete'});assert.equal(finished.status,'completed');assert.ok(fs.existsSync(run.evidence));
  assert.equal(finished.liveValidation.find(item=>item.finding===findingId)?.status,'confirmed');
  assert.ok(finished.remediation.confirmed.some(item=>item.finding===findingId&&item.proofSource==='host-probe'));
  await c.call('bypass_demo_control',{action:'fix'});const fixed=await c.call('bypass_retest',{id:findingId});assert.equal(fixed.status,'fixed_verified');assert.ok(fixed.savedCheck);
  const exported=await c.call('bypass_export_tests',{all:true});const actual=await execFile(process.execPath,['--test',...exported.files],{env:{NODE_TEST_CONTEXT:undefined}});assert.equal(actual.code,0,actual.stdout+actual.stderr);
  const replay=await c.call('bypass_run_tests',{all:true});assert.equal((await c.wait(replay.runId)).exitCode,0);
  await c.call('bypass_demo_control',{action:'regress'});const regression=await c.call('bypass_run_tests',{all:true});const failed=await c.wait(regression.runId);assert.equal(failed.exitCode,1);assert.equal(failed.modelCalls,0);
  const memory=await c.call('bypass_feature_context',{task:'Add invoice export while preserving account ownership'});assert.ok(JSON.stringify(memory).includes('ownership'));
  assert.equal(apiRequests,0);assert.ok(read(root).runs.every(r=>r.modelCalls===0));assert.doesNotMatch(fs.readFileSync(path.join(root,'.bypass/state.json'),'utf8'),/ignored-host-key/);
});

test('active initialized workspace is reused; source changes invalidate citations; cancellation retains evidence',async t=>{
  const root=temp();fs.writeFileSync(path.join(root,'app.mjs'),'export const access = true;\n');await execute('init',[root]);
  const c=await mcpClient(root,{stateDir:path.join(temp(),'state')});t.after(()=>c.close());
  assert.equal(fs.realpathSync((await c.call('bypass_onboarding')).selectedRepository),fs.realpathSync(root));
  const run=await c.call('bypass_scan',{mode:'code'});await c.call('bypass_review_step',{id:run.runId,action:'read',paths:['app.mjs']});
  fs.writeFileSync(path.join(root,'app.mjs'),'export const access = false;\n');
  const stale=await c.raw('bypass_review_step',{id:run.runId,action:'source',candidates:[]});assert.equal(stale.result.isError,true);assert.match(stale.result.content[0].text,/Source changed/);
  const state=await c.call('bypass_review_step',{id:run.runId,action:'status'});assert.ok(state.lastError);
  const cancelled=await c.call('bypass_stop_run',{id:run.runId});assert.equal(cancelled.status,'cancelled');assert.ok(fs.existsSync(cancelled.evidence));
  const finish=await c.raw('bypass_review_step',{id:run.runId,action:'finish'});assert.equal(finish.result.isError,true);
});
