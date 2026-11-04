import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import http from 'node:http';
import { spawnSync } from 'node:child_process';
import { execute } from '../src/service.mjs';
import { change } from '../src/store.mjs';
import { inExecutionMode } from '../src/execution-mode.mjs';
import { ScannerClient } from '../src/scanner/client.mjs';
import { scannerDirectory,scannerOutput,prepareScanner } from '../src/scanner/runtime.mjs';
import { closeScannerSessions } from '../src/scanner/service.mjs';
import { manifest } from '../src/scanner/contracts.mjs';
import { validateJSON } from '../src/schema.mjs';
import { parse } from '../src/catalog.mjs';
import { temp,addTestModel } from './helpers.mjs';

const python=process.env.BYPASS_TEST_PYTHON||'python3';
const available=spawnSync(python,['--version']).status===0;
async function source(){
  const root=temp();fs.writeFileSync(path.join(root,'app.py'),'def invoice(request, invoices):\n    return invoices[request.invoice_id]\n');
  await execute('init',[root]);return root;
}
async function connect({root}){
  const client=new ScannerClient(python,['-m','bypass_scanner'],{timeoutMs:15000,
    env:{...process.env,PYTHONPATH:path.join(scannerDirectory,'src'),PYTHONDONTWRITEBYTECODE:'1',BYPASS_SCANNER_SOURCE:root,BYPASS_SCANNER_OUTPUT:scannerOutput(root,true)}});
  await client.initialize();return client;
}
const call=(key,args,options,context)=>inExecutionMode('muse-host',()=>execute(key,args,options,context));
async function next(root,context){
  for(let i=0;i<50;i++){
    const status=await call('discover status',[context.run],{project:root},context);
    if(status.run.status==='awaiting_reasoning')return call('discover next_task',[context.run],{project:root},context);
    assert.equal(status.run.status,'running',JSON.stringify(status));
    await new Promise(resolve=>setTimeout(resolve,20));
  }
  assert.fail('Policy snapshot never became ready');
}
function mapping(ref){return {summary:'Invoice lookup uses caller-supplied object ID.',assumptions:['Deployment exposure unknown'],openQuestions:[],reviewedEvidence:[ref],
  surfaces:[{id:'invoice',title:'Invoice read',paths:['app.py'],evidence:[ref],policies:['authz/object-access']}]};}
function finding(ref){return {outcome:'candidates',rationale:'The source path has an object lookup without an observed owner binding.',reviewedEvidence:[ref],openQuestions:[],followUps:[],
  candidates:[{title:'Invoice ownership boundary',hypothesis:'The selected invoice is returned without an owner comparison on this path.',attackerInput:'request.invoice_id',impact:'Other owner invoice may be disclosed.',
    evidence:[ref],counterevidence:'No binding in this function; unknown upstream middleware remains a prerequisite.',assumptions:['Unprivileged caller reaches the handler'],openQuestions:['Is an upstream guard enforced?'],
    trace:[{evidenceId:ref,role:'entrypoint'},{evidenceId:ref,role:'sink'}]}]};}

test('SAST, policy, and combined plans have independent exact-ID selectors without Docker or API settings',async()=>{
  const root=temp();
  for(const [mode,detectors] of [['sast',['codeql']],['codeql',['codeql']],['policy',['policy']],['both',['codeql','policy']]]){
    const args=['discover','--plan','--detector',mode,...(detectors.includes('codeql')?['--rule','js/sql-injection','--exclude-rule','js/xss']:[]),
      ...(detectors.includes('policy')?['--policy','authz/object-access','--exclude-policy','filesystem/path-containment']:[])];
    const parsed=parse(args),result=await execute(parsed.key,parsed.args,{...parsed.options,project:root});
    assert.deepEqual(result.plan.detectors,detectors);
    assert.equal(result.plan.modelCalls,0);
    if(detectors.includes('codeql'))assert.deepEqual(result.plan.includeRules,['js/sql-injection']);
    if(detectors.includes('policy'))assert.deepEqual(result.plan.includePolicies,['authz/object-access']);
  }
  const listed=await execute('scanner policies');assert.equal(listed.policies.length,32);
  assert.deepEqual(fs.readdirSync(root),[]);
  await assert.rejects(execute('discover',[],{project:root,plan:true,detector:'policy',rule:'js/sql-injection'}),/require the sast/);
});

test('standalone policy requires a valid API profile before connecting a scanner',async()=>{
  const root=await source();let connects=0;
  await assert.rejects(execute('discover',[],{project:root,detector:'policy'},{scannerConnect:async()=>{connects++;}}),/Configure and select an LLM API profile/);
  assert.equal(connects,0);assert.equal(fs.existsSync(path.join(root,'.bypass/scanner')),false);
});

test('policy image preparation selects the lightweight target and never requests a CodeQL build',async()=>{
  const calls=[];let built=false;
  const runner=async(_command,args)=>{
    calls.push(args);
    if(args[0]==='version')return {code:0,stdout:'fixture'};
    if(args[0]==='build'){built=true;return {code:0};}
    return built?{code:0,stdout:'sha256:'+'a'.repeat(64)}:{code:1,stdout:''};
  };
  const result=await prepareScanner({runner,detector:'policy'});
  assert.equal(result.codeql,null);
  assert.equal(calls.find(a=>a[0]==='build')[calls.find(a=>a[0]==='build').indexOf('--target')+1],'policy');
  assert.ok(result.image.tag.includes('policy-'));
});

test('Muse drives real Python tasks and evidence with a broken API profile and zero provider requests',{skip:!available},async t=>{
  const root=await source();
  const stateFile=path.join(root,'.bypass/state.json'),state=JSON.parse(fs.readFileSync(stateFile));
  state.models=[{name:'broken',provider:'invalid',secretEnv:'MUST_NOT_BE_ACCESSED'}];state.activeModel='broken';fs.writeFileSync(stateFile,JSON.stringify(state));
  const before=fs.readFileSync(stateFile,'utf8');
  const {default:OpenAI}=await import('openai');const requests=t.mock.method(OpenAI.prototype,'makeRequest',()=>assert.fail('Muse must not call a provider'));
  const context={scannerConnect:connect};
  try{
    const started=await call('discover',[],{project:root,'discovery-only':true,detector:'policy',policy:'authz/object-access'},context);context.run=started.run.id;
    let leased=await next(root,context);
    assert.equal(leased.nextAction.tool,'bypass_discover_evidence');
    for(const phase of ['mapping','policy']){
      const task=leased.task;assert.equal(task.phase,phase);
      const evidence=await call('discover evidence',[context.run],{project:root,task:task.id,operation:'read',arguments:{path:'app.py'}},context);
      const ref=evidence.evidence.reference.id;
      const result=await call('discover submit',[context.run],{project:root,task:task.id,sourceRevision:task.sourceRevision,result:phase==='mapping'?mapping(ref):finding(ref)},context);
      if(phase==='mapping')leased=await call('discover next_task',[context.run],{project:root},context);
      else{
        assert.equal(result.run.status,'completed');assert.equal(result.run.signalCount,1);
        assert.equal(result.run.reasoning.independentModelRequests,0);assert.equal(result.run.reasoning.hostTokens,null);
      }
    }
    assert.equal(requests.mock.callCount(),0);assert.equal(fs.readFileSync(stateFile,'utf8'),before);
  }finally{await closeScannerSessions();}
});

test('standalone no-timeout profiles disable model, task, and reasoning-stage deadlines',{skip:!available},async()=>{
  const root=await source();await addTestModel(root);
  await change(root,state=>{state.models[0].timeoutMs=0;});
  let turns=0;const progress=[];
  const context={scannerConnect:connect,onProgress:event=>progress.push(event),scannerSessionFactory:()=>{
    let task;
    return {turn:async(messages,options)=>{
      turns++;options.onProgress({kind:'phase',phase:'request'});
      task??=JSON.parse(messages[1].content);
      assert.equal(task.taskTimeoutDisabled,true);
      assert.equal(task.stageTimeoutDisabled,true);
      assert.equal(options.timeoutMs,0);assert.equal(task.expiresAt,0);
      assert.equal(Number.isInteger(options.timeoutMs),true);
      const last=JSON.parse(messages.at(-1).content);
      if(!last.evidence)return {action:'evidence',operation:'read',arguments:{path:'app.py'}};
      const ref=last.evidence.reference.id;
      const result=task.phase==='mapping'?mapping(ref):finding(ref);
      validateJSON(task.resultSchema,result);
      return {action:'submit',result};
    }};
  }};
  const result=await execute('discover',[],{project:root,'discovery-only':true,detector:'policy',policy:'authz/object-access'},context);
  assert.equal(result.run.status,'completed',JSON.stringify(result));assert.equal(result.run.signalCount,1);
  assert.equal(progress[0].message,`Scanner run: ${result.run.id}`);
  assert.equal(progress[0].runId,result.run.id);
  assert.equal(turns,4);assert.equal(result.run.reasoning.independentModelRequests,4);assert.equal(result.run.reasoning.hostReasoning,false);
  const signal=JSON.parse(fs.readFileSync(path.join(root,'.bypass/scanner',result.run.id,'signals.json')))[0];
  validateJSON(manifest.schemas.signal,signal);assert.equal(signal.evaluation,'not_run');
  const saved=JSON.parse(fs.readFileSync(path.join(root,'.bypass/scanner',result.run.id,'policy/state.json')));
  for(const task of saved.tasks){
    assert.equal(task.definition.taskTimeoutDisabled,true);
    assert.equal(task.definition.expiresAt,0);assert.equal(task.definition.stageTimeoutDisabled,true);
  }
});

test('API driver failure persists an interrupted run and retains usage receipts',{skip:!available},async()=>{
  const root=await source();await addTestModel(root);
  const result=await execute('discover',[],{project:root,detector:'policy',policy:'authz/object-access'},
    {scannerConnect:connect,scannerSessionFactory:()=>({turn:async(_messages,options)=>{options.onProgress({kind:'phase',phase:'request'});throw new Error('Synthetic provider failure');}})});
  assert.equal(result.status,'interrupted');assert.equal(result.exitCode,3);
  assert.equal(result.run.reasoning.independentModelRequests,1);
  assert.equal(result.run.signalCount,0);
});

test('resuming with a no-timeout profile replaces old task deadlines without resetting stage budgets',{skip:!available},async()=>{
  const root=await source();await addTestModel(root);
  const interrupted=await execute('discover',[],{project:root,'discovery-only':true,detector:'policy',policy:'authz/object-access'},
    {scannerConnect:connect,scannerSessionFactory:()=>({turn:async(messages,options)=>{
      assert.equal(JSON.parse(messages[1].content).taskTimeoutDisabled,false);
      options.onProgress({kind:'phase',phase:'request'});
      throw new Error('Synthetic interruption before profile change');
    }})});
  assert.equal(interrupted.status,'interrupted');
  const filename=path.join(root,'.bypass/scanner',interrupted.run.id,'policy/state.json');
  const before=JSON.parse(fs.readFileSync(filename));
  await change(root,state=>{state.models[0].timeoutMs=0;});
  const progress=[];
  const result=await execute('discover resume',[interrupted.run.id],{project:root},
    {scannerConnect:connect,onProgress:event=>progress.push(event),scannerSessionFactory:()=>{
      let task;
      return {turn:async(messages,options)=>{
        task??=JSON.parse(messages[1].content);
        assert.equal(task.taskTimeoutDisabled,true);assert.equal(task.expiresAt,0);
        assert.equal(task.stageTimeoutDisabled,true);assert.equal(options.timeoutMs,0);
        options.onProgress({kind:'phase',phase:'request'});
        const last=JSON.parse(messages.at(-1).content);
        if(!last.evidence)return {action:'evidence',operation:'read',arguments:{path:'app.py'}};
        const ref=last.evidence.reference.id;
        return {action:'submit',result:task.phase==='mapping'?mapping(ref):finding(ref)};
      }};
    }});
  assert.equal(result.run.status,'completed',JSON.stringify(result));
  assert.equal(progress[0].message,`Scanner run: ${result.run.id} · resuming`);
  assert.equal(result.run.reasoning.independentModelRequests,5);
  assert.equal(JSON.parse(fs.readFileSync(filename)).deadline,before.deadline);
});

test('an interrupted real scanner retains safe rejection feedback and correction usage',{skip:!available},async()=>{
  const root=await source();await addTestModel(root);let turns=0;
  const result=await execute('discover',[],{project:root,detector:'policy',policy:'authz/object-access'},
    {scannerConnect:connect,scannerSessionFactory:()=>({turn:async(_messages,options)=>{
      turns++;options.onProgress({kind:'phase',phase:'request'});
      if(turns===1)return {action:'submit',operation:'read',arguments:{path:'PRIVATE_SOURCE'},result:{}};
      throw new Error('Synthetic provider interruption');
    }})});
  assert.equal(result.status,'interrupted');assert.equal(result.run.reasoning.independentModelRequests,2);
  assert.equal(result.run.signalCount,0);
  const saved=JSON.parse(fs.readFileSync(path.join(root,'.bypass/scanner',result.run.id,'manifest.json')));
  assert.match(saved.message,/Synthetic provider interruption/);assert.match(saved.message,/Last rejected security action/);
  assert.match(saved.message,/"receivedFields":\["action","operation","arguments","result"\]/);
  assert.doesNotMatch(saved.message,/PRIVATE_SOURCE/);
});

test('standalone policy repairs invalid actions beyond ten turns through the real provider transport',{skip:!available},async t=>{
  const root=await source();let requests=0;const phaseTurns=new Map(),references=new Map();
  const key='BYPASS_POLICY_TRANSPORT_TEST_KEY',previous=process.env[key];process.env[key]='synthetic-policy-key';
  t.after(()=>{if(previous===undefined)delete process.env[key];else process.env[key]=previous;});
  const server=http.createServer((request,response)=>{
    assert.equal(request.url,'/v1/chat/completions');assert.equal(request.headers.authorization,'Bearer synthetic-policy-key');
    let body='';request.on('data',chunk=>body+=chunk);request.on('end',()=>{
      requests++;const message=JSON.parse(body),task=JSON.parse(message.messages[1].content),last=JSON.parse(message.messages.at(-1).content);
      const turns=(phaseTurns.get(task.phase)||0)+1;phaseTurns.set(task.phase,turns);
      if(last.evidence)references.set(task.phase,last.evidence.reference.id);
      assert.equal(message.tools[0].function.parameters.type,'object');
      const schema=message.tools[0].function.parameters;
      const completed={action:'submit',result:task.phase==='mapping'?mapping(references.get(task.phase)):finding(references.get(task.phase))};
      const action=turns===12?{...completed,operation:'read',arguments:{}}:turns===13?{action:'submit'}:
        turns===14?{action:'evidence',operation:'read',arguments:{path:'app.py'},result:{},PRIVATE_FIELD:'PRIVATE_VALUE'}:
        turns===16?{action:'submit',result:null}:turns>=17?completed:{action:'evidence',operation:'read',arguments:{path:'app.py'}};
      if([12,13,14,16].includes(turns))assert.throws(()=>validateJSON(schema,action));
      if(turns>=13&&turns<=17){
        assert.equal(last.status,'error');assert.match(last.message,/correct the rejected action/);
        assert.doesNotMatch(JSON.stringify(last),/PRIVATE_FIELD|PRIVATE_VALUE/);
      }
      if(turns===13||turns===16){
        assert.equal(message.messages.at(-1).role,'tool');
        assert.equal(message.messages.at(-1).tool_call_id,`rejected-${task.phase}-${turns-1}`);
      }
      const assistant=[12,15].includes(turns)?{role:'assistant',content:null,tool_calls:[{id:`rejected-${task.phase}-${turns}`,type:'function',
        function:{name:'security_action',arguments:turns===15?'{"action":':JSON.stringify(action)}}]}:{role:'assistant',content:JSON.stringify(action)};
      response.setHeader('content-type','application/json');
      response.end(JSON.stringify({id:'fixture',object:'chat.completion',choices:[{index:0,finish_reason:assistant.tool_calls?'tool_calls':'stop',message:assistant}]}));
    });
  });
  await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve));t.after(()=>new Promise(resolve=>server.close(resolve)));
  await execute('model add',['policy-api'],{project:root,provider:'custom','base-url':`http://127.0.0.1:${server.address().port}/v1`,model:'fixture',stream:false,'secret-env':key,'allow-private':true,'timeout-ms':0});
  const result=await execute('discover',[],{project:root,'discovery-only':true,detector:'policy',policy:'authz/object-access'},{scannerConnect:connect});
  assert.equal(result.run.status,'completed',JSON.stringify(result));assert.equal(requests,34);
  assert.deepEqual([...phaseTurns.values()],[17,17]);
  assert.equal(result.run.reasoning.independentModelRequests,34);
  assert.equal(result.run.signalCount,1);
});

test('real standalone Python tasks use explicit JSON-schema content with zero inference deadlines',{skip:!available},async t=>{
  const root=await source();let requests=0;
  const key='BYPASS_POLICY_JSON_TEST_KEY',previous=process.env[key];process.env[key]='synthetic-key';
  t.after(()=>{if(previous===undefined)delete process.env[key];else process.env[key]=previous;});
  const server=http.createServer(async(request,response)=>{
    let body='';for await(const chunk of request)body+=chunk;
    const input=JSON.parse(body),task=JSON.parse(input.messages[1].content),last=JSON.parse(input.messages.at(-1).content);
    assert.equal(input.tools,undefined);assert.equal(input.response_format.type,'json_schema');
    assert.equal(task.stageTimeoutDisabled,true);assert.equal(task.expiresAt,0);
    assert.match(input.messages[0].content,/as JSON in final response content/);
    const action=last.evidence?{action:'submit',result:task.phase==='mapping'?mapping(last.evidence.reference.id):finding(last.evidence.reference.id)}:
      {action:'evidence',operation:'read',arguments:{path:'app.py'}};
    validateJSON(input.response_format.json_schema.schema,action);requests++;
    response.setHeader('content-type','application/json');
    response.end(JSON.stringify({choices:[{finish_reason:'stop',message:{role:'assistant',content:requests===1?'SYNTHETIC_INVALID_JSON':JSON.stringify(action)}}]}));
  });
  await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve));t.after(()=>new Promise(resolve=>server.close(resolve)));
  await execute('model add',['policy-json'],{project:root,provider:'custom','base-url':`http://127.0.0.1:${server.address().port}/v1`,model:'fixture',stream:false,'secret-env':key,'timeout-ms':0,'response-mode':'json-schema'});
  const result=await execute('discover',[],{project:root,'discovery-only':true,detector:'policy',policy:'authz/object-access','debug-log':true,'debug-raw':true},{scannerConnect:connect});
  assert.equal(result.run.status,'completed',JSON.stringify(result));assert.equal(requests,5);assert.equal(result.run.signalCount,1);
  const debugDirectory=path.join(root,'.bypass/debug'),files=fs.readdirSync(debugDirectory);
  assert.equal(files.length,1);
  const records=fs.readFileSync(path.join(debugDirectory,files[0]),'utf8').trim().split('\n').map(line=>JSON.parse(line));
  const rejection=records.find(record=>record.event==='rejected_response');
  assert.equal(rejection.raw.content,'SYNTHETIC_INVALID_JSON');
  assert.equal(rejection.diagnostics.jsonStatus,'invalid_json');
  assert.equal(records.filter(record=>record.event==='request').length,5);
});
