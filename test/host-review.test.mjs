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
  await c.call('bypass_review_step',{id:run.runId,action:'source',candidates:[candidate],knowledge:[{topic:'authorization',title:'Invoice ownership missing',summary:'Current policy accepts any signed-in account.',file:'policy.mjs',line:2,quote:candidate.quote}]});
  assert.equal(read(root).findings[0].status,'unproven');
  const proof=await c.call('bypass_review_step',{id:run.runId,action:'probe',index:0});assert.equal(proof.observation.status,'failed');assert.deepEqual(proof.observation.controls.map(x=>x.status),[200,200,200,200,401]);
  const findingId=proof.findings[0];assert.equal(read(root).findings[0].status,'confirmed');
  const earlyFinish=await c.call('bypass_review_step',{id:run.runId,action:'finish'});assert.equal(earlyFinish.status,'awaiting_host');
  await c.call('bypass_add_probe',{name:'login-anonymous',path:'/api/me',kind:'anonymous',expected:'private','resource-id':'account-alice'});
  const finished=await c.call('bypass_review_step',{id:run.runId,action:'complete'});assert.equal(finished.status,'completed');assert.ok(fs.existsSync(run.evidence));
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
