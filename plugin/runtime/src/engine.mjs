import { replayEnvironment } from './credentials.mjs';
import { requireStandaloneAPI } from './execution-mode.mjs';
import { consolidateMemory } from './project-memory.mjs';
import { read, change, event, writeEvidence } from './store.mjs';
import { inventory } from './repository.mjs';
import { runChecks, saveCheck, specFor } from './checks.mjs';
import { replay } from './portable-check.mjs';
import { id, now, hash, named, need, outcome, aggregate, delay, redact } from './util.mjs';
import { scopeReady } from './network.mjs';
import { demoConfig } from './demo.mjs';
import { realEngine, realPlan, executeRealScan } from './real-engine.mjs';

export function scanPlan(state,options={}){
  need(!(options.base&&options.full),'Choose --base or --full, not both.');
  const mode=options.mode || state.settings.reviewMode || 'combined',targetName=options.target||state.activeTarget;
  need(['code','live','combined'].includes(mode),'Scan mode must be code, live, or combined.');
  if(realEngine(state))return realPlan(state,options);
  const target=targetName?named(state.targets,targetName,'Target'):null;
  const blockers=[];
  if(mode!=='code'){
    if(!target)blockers.push('Add and select a target.');
    else try{scopeReady(target);}catch(e){blockers.push(e.message);}
  }
  return {mode,target:targetName,comparison:options.base?`Git reference ${options.base}`:'full eligible source inventory',engine:'mock',simulation:true,realAnalysis:false,modelCalls:0,
    repository:{kind:state.project.repository.kind,path:state.project.root,remote:state.project.repository.remote,branch:state.project.repository.branch},app:target?{name:target.name,url:target.url,environment:target.environment}:null,
    whiteBox:{status:mode==='live'?'skipped':'simulated',implemented:false,description:mode==='live'?'Source review is not selected.':'Local source inventory works; vulnerability discovery is mocked.'},
    blackBox:{status:mode==='code'?'deferred':blockers.length?'blocked':'simulated',implemented:false,description:mode==='code'?'App investigation is deferred. Code preview can run now.':blockers.length?blockers.join(' '):'Deployed-app investigation is mocked. Saved authorized HTTP checks can replay.'},
    stages:['Replay saved tests','Inventory changed source','Simulate candidate discovery','Simulate live engine handoff','Persist evidence and context'],
    savedChecks:state.checks.filter(c=>c.enabled).length,blockers,
    dataFlow:{source:'local inventory only',inference:'simulated; selected model not called',requests:mode==='code'?'none':'saved tests only, within authorized scope',evidence:'local .bypass/runs'},
    message:'Analysis and automated exploit verification are simulated. This scan cannot establish that a real application is secure.'};
}
export async function createRun(root,kind,options={}){
  return change(root,s=>{const run={id:id('run'),kind,options,status:'queued',createdAt:now(),steps:[],cancelRequested:false,simulation:kind==='scan',modelCalls:0};s.runs.push(run);s.runs=s.runs.slice(-100);return run;});
}
async function progress(root,runId,stage,message){
  await change(root,s=>{const run=named(s.runs,runId,'Run');run.stage=stage;run.steps.push({at:now(),stage,message});});
}
function mockCandidate(state,inv,targetName){
  const fixture=!!state.demo&&targetName===state.demo.target;
  const exportRoute=fixture&&state.demo.exportEnabled;
  return {id:id('finding'),fingerprint:`mock:${targetName||'code'}:${exportRoute?'invoice-export':'invoice-read'}`,
    title:!fixture?'Example: a resource needs an account-boundary check':exportRoute?'Invoice export needs an account-boundary check':'Invoice read needs an account-boundary check',
    severity:'high',status:'simulated_unproven',simulation:true,fixture,target:targetName||null,
    sourceEvidence:{kind:'mock',message:'Scenario supplied by the mock engine; not a detected code vulnerability.',filesInspected:inv.sourceFileCount},
    hypothesis:'A second account may be able to read a resource belonging to the first account.',
    recommendation:'Enforce the authenticated account’s ownership before returning the resource; keep owner access working.',
    binding:fixture?{resourcePath:exportRoute?'/api/exports/invoice-acme-001':'/api/invoices/invoice-acme-001',resourceId:'invoice-acme-001',owner:'demo-owner',outsider:'demo-outsider',idField:'id'}:null,
    sourceFingerprint:inv.fingerprint,createdAt:now(),history:[]};
}
export async function executeRun(root,runId,externalSignal,onProgress,{runtime}={}){
  if(read(root).runs.find(r=>r.id===runId)?.kind==='scan'&&realEngine(read(root)))requireStandaloneAPI();
  const controller=new AbortController();
  const report=async(stage,message)=>{await progress(root,runId,stage,message);onProgress?.({stage,message});};
  const cancel=()=>controller.abort();externalSignal?.addEventListener('abort',cancel,{once:true});
  if(externalSignal?.aborted)cancel();
  const timer=setInterval(()=>{try{if(named(read(root).runs,runId,'Run').cancelRequested)controller.abort();}catch{controller.abort();}},150);
  let result,failed=false;
  try{
    await change(root,s=>{const r=named(s.runs,runId,'Run');r.status='running';r.startedAt=now();r.pid=process.pid;});
    const initial=read(root),run=named(initial.runs,runId,'Run'),options=run.options;
    if(run.kind==='tests'||run.kind==='monitor'){
      await report('replay','Running saved checks without a model.');
      result=await runChecks(root,{all:!options.checkId,checkId:options.checkId,target:options.target,signal:controller.signal,runId});
    }else if(realEngine(initial)){
      result=await executeRealScan(root,runId,options,{signal:controller.signal,report,...(runtime?{runtime}:{})});
    }else{
      const plan=scanPlan(initial,options);
      need(!plan.blockers.length,plan.blockers.join(' '),3,{plan});
      await report('replay',plan.mode==='code'?'Code-only preview: saved HTTP checks deferred.':'Replaying saved checks before simulated investigation.');
      const regression=plan.mode==='code'?{results:[],exitCode:0,modelCalls:0}:await runChecks(root,{all:true,target:plan.target,signal:controller.signal,runId});
      if(controller.signal.aborted)throw Object.assign(new Error('Run cancelled.'),{code:130});
      await report('inventory',plan.mode==='live'?'Live-only mode: source inventory skipped.':'Hashing source locally; no repository content is sent to a model.');
      const inv=plan.mode==='live'?{fingerprint:null,files:[],sourceFileCount:0,routes:[],skipped:true}:await inventory(root,options.base);
      await report('mock-analysis','Simulated discovery: preparing an example, not a detected vulnerability.');
      // A small cancellable boundary also exercises the real detached-job lifecycle.
      await delay(100,undefined,{signal:controller.signal});
      const current=read(root);if(current.demo)Object.assign(current.demo,demoConfig(root));
      const candidate=mockCandidate(current,inv,plan.target);
      const passed=regression.results.filter(r=>r.status==='passed').map(r=>r.id);
      const alreadyCovered=current.checks.some(c=>passed.includes(c.id)&&current.findings.find(f=>f.id===c.findingId)?.fingerprint===candidate.fingerprint);
      let finding=null;
      if(!alreadyCovered)finding=await change(root,s=>{
        const existing=s.findings.find(f=>f.fingerprint===candidate.fingerprint);
        if(existing){existing.lastRunId=runId;existing.sourceFingerprint=inv.fingerprint;return existing;}
        candidate.lastRunId=runId;s.findings.push(candidate);event(s,'candidate',candidate.title,{findingId:candidate.id,simulation:true});return candidate;
      });
      const investigate=regression.results.filter(r=>r.status!=='passed');
      result={plan,inventory:inv,regression:regression.results,findings:finding?[finding.id]:[],investigate:investigate.map(r=>({id:r.id,reason:r.reason})),
        exactPassingChecksExcluded:passed,engine:'mock',simulation:true,modelCalls:0,simulatedInvestigations:alreadyCovered?investigate.length:1+investigate.length,
        coverageComplete:false,exitCode:regression.exitCode===1?1:3,
        message:'Walkthrough scan complete. Analysis is simulated; no real security conclusion is available.'};
    }
    if(controller.signal.aborted){result.exitCode=130;result.message='Run cancelled.';}
  }catch(e){
    failed=true;const state=read(root),run=named(state.runs,runId,'Run');
    result=redact({exitCode:controller.signal.aborted?130:(Number.isInteger(e.code)?e.code:3),message:e.message,details:{stage:run.stage||'setup',next:'status',...e.details},modelCalls:run.modelCalls||0,simulation:!realEngine(state),engine:realEngine(state)?'docker':'mock',coverageComplete:false,
      findings:state.findings.filter(f=>f.lastRunId===runId).map(f=>f.id),partial:true});
  }
  finally{clearInterval(timer);externalSignal?.removeEventListener('abort',cancel);}
  const partial=named(read(root).runs,runId,'Run').partialRegression;
  if(partial)result.regression??=partial.results;
  if(partial?.exitCode===1&&result.exitCode!==130){result.exitCode=1;result.regression??=partial.results;}
  let final=await change(root,s=>{const r=named(s.runs,runId,'Run');Object.assign(r,{status:result.exitCode===130?'cancelled':failed?'failed':result.exitCode===3||result.executionFailures?.length?'incomplete':'completed',finishedAt:now(),exitCode:result.exitCode,result,modelCalls:result.modelCalls||0});event(s,'run-finished',`${r.kind}: ${r.status}`,{runId,exitCode:r.exitCode});return r;});
  await consolidateMemory(root,{runId});
  final=named(read(root).runs,runId,'Run');
  writeEvidence(root,final);return outcome({run:final},final.exitCode);
}
export async function verifyFinding(root,findingId,{target,build,retest=false,signal}={}){
  const state=read(root),finding=named(state.findings,findingId,'Finding');
  target=target||finding.target||state.activeTarget;
  const t=named(state.targets,target,'Target');scopeReady(t);
  need(finding.target===target,'Finding is bound to another target. Add an explicit saved-test binding for another environment.',3);
  if(!['docker','host'].includes(finding.engine)&&(!finding.fixture||!state.demo||target!==state.demo.target)){
    const verification={status:'simulated_unproven',simulation:true,requests:0,modelCalls:0,reason:'The live verification engine is mocked. No exploit was sent to this deployed application.'};
    await change(root,s=>{const f=named(s.findings,findingId,'Finding');f.history.push({at:now(),action:retest?'retest':'verify',...verification});f.verification=verification;});
    return outcome({findingId,verification},3);
  }
  need(finding.binding,'This source hypothesis has no approved HTTP resource binding. Add the matching probe and run review again.',3);
  const check={target,fixture:!!finding.fixture,engine:finding.engine,bindings:{[target]:finding.binding}};
  const spec=specFor(state,check,target);
  const result=await replay(spec,{signal,env:await replayEnvironment(state,spec,{signal})});
  const inv=await inventory(root);
  const real=['docker','host'].includes(finding.engine);
  const previouslyConfirmed=finding.history.some(h=>h.status==='failed')||finding.verification?.status==='failed';
  const status=result.status==='failed'?(real?'confirmed':'confirmed_fixture'):retest&&result.status==='passed'&&(!real||previouslyConfirmed)?'fixed_verified':result.status==='passed'?(real?'not_reproduced':'not_reproduced_fixture'):'blocked';
  await change(root,s=>{const f=named(s.findings,findingId,'Finding');f.status=status;f.verification={...result,origin:t.url,fixture:!!finding.fixture,simulation:false,at:now(),build:build?{value:build,source:'operator-supplied, not attested'}:null};f.history.push({action:retest?'retest':'verify',...f.verification});f.sourceFingerprint=inv.fingerprint;event(s,status,`${f.title}: ${status}`,{findingId});});
  let saved=null;
  if(['fixed_verified','confirmed','confirmed_fixture'].includes(status)&&state.settings.autoSave){saved=await saveCheck(root,findingId);await change(root,s=>{const c=named(s.checks,saved.id,'Check');c.sourceFingerprint=inv.fingerprint;c.baseline=status==='fixed_verified'?'fixed_verified':'failing_reproduction';c.lastResult={...result,origin:t.url,bindingFingerprint:hash(finding.binding),resourcePath:finding.binding.resourcePath,checkedAt:now(),target};});saved=named(read(root).checks,saved.id,'Check');}
  if(real)await consolidateMemory(root);
  return outcome({findingId,status,verification:result,fixtureOnly:!!finding.fixture,savedCheck:saved,build:build||null},result.status==='failed'?1:result.status==='passed'?0:3);
}
