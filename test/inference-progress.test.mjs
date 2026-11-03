import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { modelResponseSchema } from '../src/inference.mjs';
import { executeRealScan } from '../src/real-engine.mjs';
import { createRun } from '../src/engine.mjs';
import { execute } from '../src/service.mjs';
import { read, change } from '../src/store.mjs';
import { Fault } from '../src/util.mjs';
import { temp } from './helpers.mjs';

test('structured responses satisfy Muse strict required-properties contract recursively',()=>{
  const visit=value=>{
    if(!value||typeof value!=='object')return;
    if(value.type==='object'){
      assert.deepEqual([...value.required].sort(),Object.keys(value.properties).sort());
      assert.equal(value.additionalProperties,false);
    }
    for(const child of Object.values(value))if(Array.isArray(child))child.forEach(visit);else visit(child);
  };
  for(const role of ['orchestrator','white-box','black-box'])visit(modelResponseSchema(role));
});

test('real review stops at failed preflight before Docker, source upload or further inference',async()=>{
  const root=temp();await execute('init',[root]);await execute('model add',['muse'],{project:root,provider:'meta','secret-env':'BYPASS_UNIT_API_KEY',model:'test-model',stream:false});await execute('engine use',['docker'],{project:root});
  const run=await createRun(root,'scan',{mode:'code'}),stages=[];
  await assert.rejects(executeRealScan(root,run.id,{mode:'code'},{report:async stage=>stages.push(stage),runtime:{
    testModel:async(_profile,_root,{timeoutMs})=>{assert.equal(timeoutMs,30000);throw new Fault('Provider unavailable',3,{reason:'provider_unavailable'});},
    prepareAgents:async()=>assert.fail('Must not start Docker'),infer:async()=>assert.fail('Must not send source'),runContainer:async()=>assert.fail('Must not start workers')
  }}),error=>error.details.stage==='connection'&&error.details.next==='model test');
  const state=read(root);assert.equal(state.runs[0].modelCalls,1);assert.equal(state.runs[0].agentEvidence.modelUsage[0].status,'failed');
  assert.equal(state.models[0].lastAttempt.status,'failed');assert.deepEqual(stages,['replay','connection']);
});

test('recent preflight retains the configured model and displays its timeout',async t=>{
  const root=temp();await execute('init',[root]);await execute('model add',['muse'],{project:root,provider:'meta','secret-env':'BYPASS_UNIT_API_KEY',model:'test-model',stream:false,'timeout-ms':180000});await execute('engine use',['docker'],{project:root});
  await change(root,s=>{s.models[0].lastAttempt={status:'connected',checkedAt:new Date().toISOString(),model:'resolved-model'};});
  const run=await createRun(root,'scan',{mode:'code'});
  const progress=[];
  t.mock.timers.enable({apis:['setInterval','Date']});
  const result=await executeRealScan(root,run.id,{mode:'code'},{report:async(_stage,message)=>{progress.push(message);},runtime:{
    testModel:async()=>assert.fail('Must reuse recent connection check'),prepareAgents:async()=>({image:'test'}),
    infer:async(profile,_messages,{schema})=>{assert.equal(profile.model,'test-model');assert.equal(profile.timeoutMs,180000);assert.deepEqual(schema,modelResponseSchema('orchestrator'));t.mock.timers.tick(10000);return {focus:'Review source'};},
    runContainer:async()=>({result:{candidates:[]},container:{role:'white-box'}})
  }});assert.equal(result.modelCalls,1);
  assert.ok(progress.some(message=>message.includes('waiting for muse · 10s / 180s')));
});

test('no-timeout scans remove connection and worker deadlines and display cancellation',async t=>{
  const root=temp();await execute('init',[root]);
  await execute('model add',['local'],{project:root,provider:'custom','base-url':'http://127.0.0.1:8000/v1',model:'test-model','secret-env':'BYPASS_UNIT_API_KEY','timeout-ms':0});
  await execute('engine use',['docker'],{project:root});
  const run=await createRun(root,'scan',{mode:'code'}),progress=[];
  t.mock.timers.enable({apis:['setInterval','Date']});
  const result=await executeRealScan(root,run.id,{mode:'code'},{report:async(_stage,message)=>{progress.push(message);},runtime:{
    testModel:async(profile,_root,{timeoutMs})=>{assert.equal(timeoutMs,0);return {status:'connected',checkedAt:new Date().toISOString(),model:profile.model};},
    prepareAgents:async()=>({image:'test'}),
    infer:async profile=>{assert.equal(profile.timeoutMs,0);t.mock.timers.tick(10000);return {focus:'Review source'};},
    runContainer:async(_role,_task,_rpc,{timeoutMs})=>{assert.equal(timeoutMs,0);return {result:{candidates:[]},container:{role:'white-box'}};}
  }});
  assert.equal(result.modelCalls,2);
  assert.ok(progress.some(message=>message.includes('one small prompt · no timeout')));
  assert.ok(progress.some(message=>message.includes('waiting for local · 10s / no timeout · cancel to stop')));
});
