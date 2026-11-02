import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { execute } from '../src/service.mjs';
import { inExecutionMode } from '../src/execution-mode.mjs';
import { ScannerClient } from '../src/scanner/client.mjs';
import { scannerDirectory, scannerOutput } from '../src/scanner/runtime.mjs';
import { closeScannerSessions } from '../src/scanner/service.mjs';
import { parse } from '../src/catalog.mjs';
import { temp, addTestModel } from './helpers.mjs';

const python=process.env.BYPASS_TEST_PYTHON||'python3';
const available=spawnSync(python,['--version']).status===0;
const host=(key,args,options,context)=>inExecutionMode('muse-host',()=>execute(key,args,options,context));
async function source(){
  const root=temp();
  fs.writeFileSync(path.join(root,'app.py'),'def invoice(actor, key, invoices):\n    return invoices[key]\n');
  fs.writeFileSync(path.join(root,'input.sarif'),JSON.stringify({version:'2.1.0',runs:[{results:[
    {ruleId:'invoice-access',message:{text:'Invoice ownership boundary'},locations:[{physicalLocation:{artifactLocation:{uri:'app.py'},region:{startLine:2}}}]}
  ]}]}));
  await execute('init',[root]);
  return root;
}
async function connect({root,sarif}){
  const client=new ScannerClient(python,['-m','bypass_scanner'],{timeoutMs:15000,env:{
    ...process.env,PYTHONPATH:path.join(scannerDirectory,'src'),PYTHONDONTWRITEBYTECODE:'1',
    BYPASS_SCANNER_SOURCE:root,BYPASS_SCANNER_OUTPUT:scannerOutput(root,true),...(sarif?{BYPASS_SCANNER_SARIF:sarif}:{})
  }});
  await client.initialize();
  return client;
}
async function ready(root,run,context){
  for(let i=0;i<100;i++){
    const result=await host('discover status',[run],{project:root},context);
    if(result.run.status!=='running')return result;
    await new Promise(resolve=>setTimeout(resolve,20));
  }
  assert.fail('Scanner did not settle');
}
function verdict(task,ref,outcome='confirmed'){
  return {caseId:task.caseId,outcome,severity:outcome==='confirmed'?'medium':'unknown',
    severityRationale:'Source-level impact and exposure, not a detector score.',
    rationale:'Read the function and inspect controls on this source path.',
    evidence:[ref],counterevidence:'No owner comparison is present in the cited function.',
    prerequisites:['The function is called with an unprivileged actor and an invoice key.'],
    impact:'The function returns the selected invoice without an actor binding.',
    openQuestions:outcome==='needs_review'?['Is an external guard applied?']:[],
    nextAction:outcome==='needs_review'?'Review upstream guard configuration.':'Review the source-only conclusion.',
    followUpQuestions:[]};
}
function mapping(ref){
  return {summary:'Invoice lookup accepts a caller-selected key.',assumptions:[],openQuestions:[],reviewedEvidence:[ref],
    surfaces:[{id:'invoice',title:'Invoice read',paths:['app.py'],evidence:[ref],policies:['authz/object-access']}]};
}
function candidate(ref){
  return {outcome:'candidates',rationale:'Read the invoice implementation.',reviewedEvidence:[ref],openQuestions:[],followUps:[],
    candidates:[{title:'Invoice ownership boundary',hypothesis:'No owner comparison on this path.',
      attackerInput:'key',impact:'Another owner invoice may be returned.',evidence:[ref],
      counterevidence:'Caller guards are not established.',assumptions:['Unprivileged caller reaches the function.'],
      openQuestions:['Is a caller guard enforced?'],trace:[{evidenceId:ref,role:'entrypoint'},{evidenceId:ref,role:'sink'}]}]};
}
function scripted(onTask=()=>{}){
  return ()=>{
    let task;
    return {turn:async(messages,options)=>{
      options.onProgress({kind:'phase',phase:'request'});
      task??=JSON.parse(messages[1].content);
      onTask(task,messages[0].content);
      const last=JSON.parse(messages.at(-1).content);
      if(!last.evidence)return {action:'evidence',operation:'read',arguments:{path:'app.py'}};
      const ref=last.evidence.reference.id;
      return {action:'submit',result:task.kind!=='discovery'?verdict(task,ref):
        task.phase==='mapping'?mapping(ref):candidate(ref)};
    }};
  };
}

test('default evaluation requires standalone readiness; opt-out plans and CLI parsing stay model-free',async()=>{
  const root=await source();
  let connects=0;
  await assert.rejects(execute('discover',[],{project:root,sarif:'input.sarif'},
    {scannerConnect:async()=>{connects++;}}),/Configure and select an LLM API profile/);
  assert.equal(connects,0);
  const plan=await execute('discover',[],{project:root,plan:true});
  assert.equal(plan.plan.evaluation,'auto');
  assert.equal(plan.plan.reasoning.apiProfileRequired,true);
  const parsed=parse(['discover','--plan','--discovery-only']);
  const discovery=await execute(parsed.key,parsed.args,parsed.options);
  assert.equal(discovery.plan.evaluation,'off');
  assert.equal(discovery.plan.reasoning.executor,'none');
  const enabled=await host('discover',[],{plan:true,'discovery-only':false});
  assert.equal(enabled.plan.evaluation,'auto');
  assert.equal(parse(['discover','evaluate','scan']).key,'discover evaluate');
});

test('Muse evaluates real SAST-import tasks in-session without reading broken provider settings',{skip:!available},async t=>{
  const root=await source();
  const filename=path.join(root,'.bypass/state.json'),state=JSON.parse(fs.readFileSync(filename));
  state.models=[{name:'broken',provider:'invalid',secretEnv:'MUST_NOT_BE_READ'}];
  state.activeModel='broken';
  fs.writeFileSync(filename,JSON.stringify(state));
  const before=fs.readFileSync(filename,'utf8');
  const {default:OpenAI}=await import('openai');
  const requests=t.mock.method(OpenAI.prototype,'makeRequest',()=>assert.fail('Muse must not independently call a provider'));
  const context={scannerConnect:connect};
  try{
    const started=await host('discover',[],{project:root,sarif:'input.sarif'},context);
    const run=started.run.id;
    assert.equal((await ready(root,run,context)).run.stage,'evaluation');
    const leased=await host('discover next_task',[run],{project:root},context),task=leased.task;
    assert.equal(task.kind,'evaluation');
    assert.equal(leased.nextAction.tool,'bypass_discover_evidence');
    const evidence=await host('discover evidence',[run],{project:root,task:task.id,operation:'read',arguments:{path:'app.py'}},context);
    const result=await host('discover submit',[run],{project:root,task:task.id,sourceRevision:task.sourceRevision,
      result:verdict(task,evidence.evidence.reference.id,'needs_review')},context);
    assert.equal(result.run.status,'incomplete');
    assert.equal(result.run.evaluationSummary.needs_review,1);
    assert.equal(result.run.reasoning.independentModelRequests,0);
    assert.equal(result.nextAction.tool,'bypass_discover_report');
    assert.equal(requests.mock.callCount(),0);
    assert.equal(fs.readFileSync(filename,'utf8'),before);
  }finally{await closeScannerSessions();}
});

test('standalone automatically evaluates SAST imports and preserves source-only report distinctions',{skip:!available},async()=>{
  const root=await source();
  await addTestModel(root);
  let tasks=0;
  const result=await execute('discover',[],{project:root,sarif:'input.sarif'},
    {scannerConnect:connect,scannerSessionFactory:scripted((task,system)=>{
      tasks++;
      assert.equal(task.kind,'evaluation');
      assert.match(system,/Only evaluation\/deep_investigation/);
    })});
  assert.equal(result.run.status,'completed',JSON.stringify(result));
  assert.equal(tasks,2);
  assert.equal(result.run.reasoning.independentModelRequests,2);
  const report=JSON.parse(fs.readFileSync(path.join(root,'.bypass/scanner',result.run.id,'report.json')));
  assert.equal(report.signals[0].evaluation,'not_run');
  assert.equal(report.cases[0].outcome,'confirmed');
  assert.equal(report.cases[0].evaluation.runtimeReproduced,false);
});

test('combined import and policy discovery transition to evaluation with separate usage budgets',{skip:!available},async()=>{
  const root=await source();
  await addTestModel(root);
  const config={policyLimits:{maxModelRequests:4},evaluationLimits:{maxModelRequests:4}};
  fs.writeFileSync(path.join(root,'scanner.json'),JSON.stringify(config));
  const result=await execute('discover',[],{project:root,sarif:'input.sarif',detector:'both',policy:'authz/object-access',config:'scanner.json'},
    {scannerConnect:connect,scannerSessionFactory:scripted()});
  assert.equal(result.run.status,'completed',JSON.stringify(result));
  assert.equal(result.run.signalCount,2);
  assert.equal(result.run.evaluationSummary.confirmed,2);
  assert.equal(result.run.policy.modelRequests,4);
  assert.equal(result.run.evaluationSummary.modelRequests,4);
  assert.equal(result.run.reasoning.independentModelRequests,8);
});

test('discovery-only saved runs can be evaluated explicitly through the standalone entry point',{skip:!available},async()=>{
  const root=await source();
  const discovery=await execute('discover',[],{project:root,sarif:'input.sarif','discovery-only':true},{scannerConnect:connect});
  assert.equal(discovery.run.evaluation,'not_run');
  assert.equal(discovery.run.modelCalls,0);
  await addTestModel(root);
  const result=await execute('discover evaluate',[discovery.run.id],{project:root},
    {scannerConnect:connect,scannerSessionFactory:scripted()});
  assert.equal(result.run.status,'completed',JSON.stringify(result));
  assert.equal(result.run.evaluationSummary.confirmed,1);
});

test('interrupted saved-run evaluation resumes with API readiness and preserves attempted usage',{skip:!available},async()=>{
  const root=await source();
  const discovery=await execute('discover',[],{project:root,sarif:'input.sarif','discovery-only':true},{scannerConnect:connect});
  await addTestModel(root);
  const failed=await execute('discover evaluate',[discovery.run.id],{project:root},{
    scannerConnect:connect,scannerSessionFactory:()=>({turn:async(_messages,options)=>{
      options.onProgress({kind:'phase',phase:'request'});
      throw new Error('Synthetic evaluation interruption');
    }})
  });
  assert.equal(failed.status,'interrupted');
  assert.equal(failed.run.stage,'evaluation');
  assert.equal(failed.run.reasoning.independentModelRequests,1);
  const resumed=await execute('discover resume',[discovery.run.id],{project:root},
    {scannerConnect:connect,scannerSessionFactory:scripted()});
  assert.equal(resumed.run.status,'completed',JSON.stringify(resumed));
  assert.equal(resumed.run.reasoning.independentModelRequests,3);
  assert.equal(resumed.run.evaluationSummary.confirmed,1);
});
