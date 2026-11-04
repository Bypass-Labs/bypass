import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import http from 'node:http';
import { modelResponseSchema, infer } from '../src/inference.mjs';
import { executeSourceReview } from '../src/real-engine.mjs';
import { createRun, executeRun } from '../src/engine.mjs';
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
  for(const role of ['orchestrator','white-box','white-box-live'])visit(modelResponseSchema(role));
  assert.throws(()=>modelResponseSchema('black-box'),/Unknown model response role/);
});

test('real review stops at failed preflight before Docker, source upload or further inference',async()=>{
  const root=temp();await execute('init',[root]);await execute('model add',['muse'],{project:root,provider:'meta','secret-env':'BYPASS_UNIT_API_KEY',model:'test-model',stream:false});await execute('engine use',['docker'],{project:root});
  const run=await createRun(root,'scan',{mode:'code'}),stages=[];
  await assert.rejects(executeSourceReview(root,run.id,{mode:'code'},{report:async stage=>stages.push(stage),runtime:{
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
  const result=await executeSourceReview(root,run.id,{mode:'code'},{report:async(_stage,message)=>{progress.push(message);},runtime:{
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
  const result=await executeSourceReview(root,run.id,{mode:'code'},{report:async(_stage,message)=>{progress.push(message);},runtime:{
    testModel:async(profile,_root,{timeoutMs})=>{assert.equal(timeoutMs,0);return {status:'connected',checkedAt:new Date().toISOString(),model:profile.model};},
    prepareAgents:async()=>({image:'test'}),
    infer:async profile=>{assert.equal(profile.timeoutMs,0);t.mock.timers.tick(10000);return {focus:'Review source'};},
    runContainer:async(_role,_task,_rpc,{timeoutMs})=>{assert.equal(timeoutMs,0);return {result:{candidates:[]},container:{role:'white-box'}};}
  }});
  assert.equal(result.modelCalls,2);
  assert.ok(progress.some(message=>message.includes('one small prompt · no timeout')));
  assert.ok(progress.some(message=>message.includes('waiting for local · 10s / no timeout · cancel to stop')));
});

test('citation failures persist safe diagnostics and attribute validation to white-box, not memory',async()=>{
  const root=temp();await execute('init',[root]);
  fs.writeFileSync(path.join(root,'app.js'),'const actual = true;\nconst other = false;\n');
  await execute('model add',['local'],{project:root,provider:'meta','secret-env':'BYPASS_UNIT_API_KEY'});
  await execute('engine use',['docker'],{project:root});
  await change(root,s=>{s.models[0].lastAttempt={status:'connected',checkedAt:new Date().toISOString()};});
  const run=await createRun(root,'scan',{mode:'code'});
  const result=await executeRun(root,run.id,undefined,undefined,{runtime:{
    prepareAgents:async()=>({image:'test'}),infer:async()=>({focus:'Review source'}),
    runContainer:async(_role,_task,rpc)=>{
      await rpc('read_files',{paths:['app.js']});
      return {container:{role:'white-box'},result:{
        knowledge:[{topic:'data-model',title:'Actual value',summary:'A cited interpretation.',file:'app.js',line:1,quote:'const actual = true;'}],
        candidates:[{title:'Candidate',category:'authorization',hypothesis:'Hypothesis',recommendation:'Review ownership',file:'app.js',line:1,quote:'const other = false;'}]
      }};
    }
  }});
  assert.equal(result.exitCode,3);assert.equal(result.run.result.details.stage,'white-box');
  assert.equal(result.run.result.details.reason,'source_citation_invalid');
  assert.deepEqual(result.run.result.details.citation,{candidateNumber:1,file:'app.js',line:1,issue:'quote_mismatch',quoteCharacters:20,actualLineCharacters:20,matchingReadLines:[2],includesLineNumber:false,multiline:false});
  assert.match(result.run.result.message,/Candidate 1 at app.js:1.*quote matches read line\(s\) 2/);
  const saved=JSON.parse(fs.readFileSync(path.join(root,'.bypass','runs',run.id+'.json'),'utf8'));
  assert.deepEqual(saved.result.details,result.run.result.details);
  assert.equal(saved.stage,'white-box');assert.equal(saved.agentEvidence.memory.learned.saved.length,1);
  assert.equal(read(root).findings.length,0);
  assert.doesNotMatch(JSON.stringify(saved.result.details)+saved.result.message,/const actual|const other/);
});

test('invalid model actions persist response diagnostics in run results and usage and print safe progress',async t=>{
  let requests=0;
  const server=http.createServer((req,res)=>{
    req.resume();res.setHeader('content-type','application/json');
    res.end(JSON.stringify({choices:[{finish_reason:'stop',message:{role:'assistant',content:++requests===1?'{"focus":"Review source"}':'PRIVATE_OUTPUT prose',reasoning_content:'PRIVATE_REASONING'}}]}));
  });
  await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve));
  t.after(()=>{server.closeAllConnections();server.close();});
  const root=temp();await execute('init',[root]);
  await execute('model add',['local'],{project:root,provider:'custom','base-url':`http://127.0.0.1:${server.address().port}/v1`,model:'test-model','secret-env':'BYPASS_UNIT_API_KEY',stream:false});
  await execute('engine use',['docker'],{project:root});
  const run=await createRun(root,'scan',{mode:'code'}),progress=[];
  const result=await executeRun(root,run.id,undefined,event=>progress.push(event),{runtime:{
    infer,prepareAgents:async()=>({image:'test'}),
    runContainer:async(_role,_task,rpc)=>rpc('model',{messages:[{role:'user',content:'Review source'}]})
  }});
  assert.equal(result.exitCode,3);assert.equal(result.run.result.details.stage,'white-box');
  const saved=JSON.parse(fs.readFileSync(path.join(root,'.bypass','runs',run.id+'.json'),'utf8'));
  const d=saved.result.details.responseDiagnostics;
  assert.equal(d.jsonStatus,'invalid_json');assert.equal(d.contentCharacters,20);assert.equal(d.toolCallCount,0);
  assert.deepEqual(saved.agentEvidence.modelUsage.at(-1).responseDiagnostics,d);
  assert.ok(progress.some(event=>event.message.includes('Response diagnostics:')&&event.message.includes('invalid_json')));
  assert.doesNotMatch(JSON.stringify(saved.result.details)+JSON.stringify(progress),/PRIVATE_OUTPUT|PRIVATE_REASONING/);
});

test('source review repairs one malformed action and counts both requests',async()=>{
  const root=temp();await execute('init',[root]);
  await execute('model add',['muse'],{project:root,provider:'meta','secret-env':'BYPASS_UNIT_API_KEY',model:'test-model',stream:false});
  await execute('engine use',['docker'],{project:root});
  await change(root,s=>{s.models[0].lastAttempt={status:'connected',checkedAt:new Date().toISOString()};});
  const run=await createRun(root,'scan',{mode:'code'}),progress=[],calls=[];
  const result=await executeSourceReview(root,run.id,{mode:'code'},{report:async(_role,message)=>progress.push(message),runtime:{
    testModel:async()=>assert.fail('Recent preflight should be reused'),prepareAgents:async()=>({image:'test'}),
    infer:async(_profile,messages,{session})=>{
      calls.push({messages,session});
      if(calls.length===1)throw new Fault('Invalid action',3,{reason:'invalid_arguments',
        responseDiagnostics:{jsonStatus:'empty_content',jsonSource:'content'}});
      return {focus:'Review source'};
    },
    runContainer:async()=>({result:{candidates:[]},container:{role:'white-box'}})
  }});
  assert.equal(result.modelCalls,2);
  assert.equal(calls.length,2);
  assert.equal(calls[0].session,calls[1].session);
  assert.equal(calls[1].messages.length,1);
  assert.match(calls[1].messages[0].content,/exactly one security_action/);
  assert.ok(progress.some(message=>message.includes('retrying once with the same evidence')));
  assert.deepEqual(read(root).runs[0].agentEvidence.modelUsage.map(item=>item.status),['failed','completed']);
});
