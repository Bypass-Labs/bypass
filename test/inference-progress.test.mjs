import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { infer, museProgress, modelResponseSchema } from '../src/inference.mjs';
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

test('streamed Muse progress handles fragmented JSON and excludes source, reasoning and diagnostic values',()=>{
  const events=[],receive=museProgress(p=>events.push(p));
  const line=p=>JSON.stringify({payload:p})+'\n';
  const stream=line({kind:'run_model_configured',model_id:'actual-model'})+line({kind:'task_lifecycle',event:{kind:'status',message:'SECRET',details:{phase:'opening_stream'}}})+line({kind:'run_output_delta',text:'private source and reasoning'})+line({kind:'run_terminal',text:'private completion'});
  for(let i=0;i<stream.length;i+=7)receive(stream.slice(i,i+7));
  assert.equal(events.length,2);assert.equal(events[0].model,'actual-model');assert.equal(events[1].phase,'opening_stream');
  assert.doesNotMatch(JSON.stringify(events),/SECRET|private/);
});

test('real review stops at failed preflight before Docker, source upload or further inference',async()=>{
  const root=temp();await execute('init',[root]);await execute('model add',['muse'],{project:root,provider:'muse-code'});await execute('engine use',['docker'],{project:root});
  const run=await createRun(root,'scan',{mode:'code'}),stages=[];
  await assert.rejects(executeRealScan(root,run.id,{mode:'code'},{report:async stage=>stages.push(stage),runtime:{
    testModel:async(_profile,_root,{timeoutMs})=>{assert.equal(timeoutMs,30000);throw new Fault('Provider unavailable',3,{reason:'provider_unavailable'});},
    prepareAgents:async()=>assert.fail('Must not start Docker'),infer:async()=>assert.fail('Must not send source'),runContainer:async()=>assert.fail('Must not start workers')
  }}),error=>error.details.stage==='connection'&&error.details.next==='model test');
  const state=read(root);assert.equal(state.runs[0].modelCalls,1);assert.equal(state.runs[0].agentEvidence.modelUsage[0].status,'failed');
  assert.equal(state.models[0].lastAttempt.status,'failed');assert.deepEqual(stages,['replay','connection']);
});

test('recent preflight avoids another synthetic request and pins the resolved default model',async()=>{
  const root=temp();await execute('init',[root]);await execute('model add',['muse'],{project:root,provider:'muse-code'});await execute('engine use',['docker'],{project:root});
  await change(root,s=>{s.models[0].lastAttempt={status:'connected',checkedAt:new Date().toISOString(),model:'resolved-model'};});
  const run=await createRun(root,'scan',{mode:'code'});
  const result=await executeRealScan(root,run.id,{mode:'code'},{report:async()=>{},runtime:{
    testModel:async()=>assert.fail('Must reuse recent connection check'),prepareAgents:async()=>({image:'test'}),
    infer:async(profile,_messages,{schema})=>{assert.equal(profile.model,'resolved-model');assert.deepEqual(schema,modelResponseSchema('orchestrator'));return {focus:'Review source'};},
    runContainer:async()=>({result:{candidates:[]},container:{role:'white-box'}})
  }});assert.equal(result.modelCalls,1);
});

test('Muse adapter uses structured output and configurable effort, preserves a bounded timeout and removes temporary prompts',async t=>{
  const root=temp(),bin=path.join(root,'bin'),log=path.join(root,'args.json');fs.mkdirSync(bin);
  fs.writeFileSync(path.join(bin,'muse'),`#!${process.execPath}
const fs=require('fs'),a=process.argv.slice(2),value=k=>a[a.indexOf(k)+1];
fs.writeFileSync(${JSON.stringify(log)},JSON.stringify({args:a,schema:JSON.parse(fs.readFileSync(value('--output-schema'),'utf8'))}));
if(process.env.BYPASS_INFERENCE_HANG==='1'){process.on('SIGTERM',()=>{});setInterval(()=>{},1000);}else{console.log(JSON.stringify({payload:{kind:'run_model_configured',model_id:'test-model'}}));console.log(JSON.stringify({payload:{kind:'run_terminal',terminal:'completed',text:'{"focus":"Inspect access controls"}'}}));}
`,{mode:0o755});
  const oldPath=process.env.PATH;process.env.PATH=bin+path.delimiter+oldPath;
  t.after(()=>{process.env.PATH=oldPath;delete process.env.BYPASS_INFERENCE_HANG;fs.rmSync(root,{recursive:true,force:true});});
  const progress=[],profile={provider:'muse-code',model:'test-model',effort:'low'},schema=modelResponseSchema('orchestrator');
  const response=await infer(profile,[{role:'user',content:'test'}],{schema,onProgress:p=>progress.push(p)});
  assert.equal(response.focus,'Inspect access controls');assert.equal(progress[0].model,'test-model');
  const saved=JSON.parse(fs.readFileSync(log,'utf8')),value=k=>saved.args[saved.args.indexOf(k)+1];
  assert.equal(value('--reasoning-effort'),'low');assert.deepEqual(saved.schema,schema);assert.equal(fs.existsSync(value('--workspace')),false);
  process.env.BYPASS_INFERENCE_HANG='1';const before=Date.now();
  await assert.rejects(infer(profile,[],{schema,timeoutMs:200}),e=>e.details.reason==='model_timeout'&&e.details.timeoutMs===200);
  assert.ok(Date.now()-before<2000);const args=JSON.parse(fs.readFileSync(log,'utf8')).args;assert.equal(fs.existsSync(args[args.indexOf('--workspace')+1]),false);
});
