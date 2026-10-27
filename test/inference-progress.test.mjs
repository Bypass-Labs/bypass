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

test('recent preflight avoids another synthetic request and keeps the explicitly configured model',async()=>{
  const root=temp();await execute('init',[root]);await execute('model add',['muse'],{project:root,provider:'meta','secret-env':'BYPASS_UNIT_API_KEY',model:'test-model',stream:false});await execute('engine use',['docker'],{project:root});
  await change(root,s=>{s.models[0].lastAttempt={status:'connected',checkedAt:new Date().toISOString(),model:'resolved-model'};});
  const run=await createRun(root,'scan',{mode:'code'});
  const result=await executeRealScan(root,run.id,{mode:'code'},{report:async()=>{},runtime:{
    testModel:async()=>assert.fail('Must reuse recent connection check'),prepareAgents:async()=>({image:'test'}),
    infer:async(profile,_messages,{schema})=>{assert.equal(profile.model,'test-model');assert.deepEqual(schema,modelResponseSchema('orchestrator'));return {focus:'Review source'};},
    runContainer:async()=>({result:{candidates:[]},container:{role:'white-box'}})
  }});assert.equal(result.modelCalls,1);
});
