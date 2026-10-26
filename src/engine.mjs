import { read, change, event, writeEvidence } from './store.mjs';
import { inventory } from './repository.mjs';
import { runChecks, saveCheck, specFor } from './checks.mjs';
import { replay } from './portable-check.mjs';
import { id, now, named, need, outcome, aggregate, delay } from './util.mjs';
import { scopeReady } from './network.mjs';
import { demoConfig } from './demo.mjs';

export function scanPlan(state,options={}){
  need(!(options.base&&options.full),'Choose --base or --full, not both.');
  const mode=options.mode || 'combined',targetName=options.target||state.activeTarget;
  need(['code','live','combined'].includes(mode),'Scan mode must be code, live, or combined.');
  const target=targetName?named(state.targets,targetName,'Target'):null;
  const blockers=[];
  if(mode!=='code'){
    if(!target)blockers.push('Add and select a target.');
    else try{scopeReady(target);}catch(e){blockers.push(e.message);}
  }
  return {mode,target:targetName,comparison:options.base?`Git reference ${options.base}`:'full eligible source inventory',engine:'mock',simulation:true,realAnalysis:false,modelCalls:0,
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
export async function executeRun(root,runId,externalSignal){
  const controller=new AbortController();
  const cancel=()=>controller.abort();externalSignal?.addEventListener('abort',cancel,{once:true});
  const timer=setInterval(()=>{try{if(named(read(root).runs,runId,'Run').cancelRequested)controller.abort();}catch{controller.abort();}},150);
  let result;
  try{
    await change(root,s=>{const r=named(s.runs,runId,'Run');r.status='running';r.startedAt=now();r.pid=process.pid;});
    const initial=read(root),run=named(initial.runs,runId,'Run'),options=run.options;
    if(run.kind==='tests'||run.kind==='monitor'){
      await progress(root,runId,'replay','Running saved checks without a model.');
      result=await runChecks(root,{all:!options.checkId,checkId:options.checkId,target:options.target,signal:controller.signal,runId});
    }else{
      const plan=scanPlan(initial,options);
      need(!plan.blockers.length,plan.blockers.join(' '),3,{plan});
      await progress(root,runId,'replay','Saved checks run before simulated investigation.');
      const regression=plan.mode==='code'?{results:[],exitCode:0,modelCalls:0}:await runChecks(root,{all:true,target:plan.target,signal:controller.signal,runId});
      if(controller.signal.aborted)throw Object.assign(new Error('Run cancelled.'),{code:130});
      await progress(root,runId,'inventory','Hashing source locally; no repository content is sent to a model.');
      const inv=await inventory(root,options.base);
      await progress(root,runId,'mock-analysis','MOCK engine: creating a clearly labeled candidate for the product walkthrough.');
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
  }catch(e){result={exitCode:controller.signal.aborted?130:(e.code||3),message:e.message,details:e.details||{},modelCalls:0};}
  finally{clearInterval(timer);externalSignal?.removeEventListener('abort',cancel);}
  const final=await change(root,s=>{const r=named(s.runs,runId,'Run');Object.assign(r,{status:result.exitCode===130?'cancelled':'completed',finishedAt:now(),exitCode:result.exitCode,result});event(s,'run-finished',`${r.kind}: ${r.status}`,{runId,exitCode:r.exitCode});return r;});
  writeEvidence(root,final);return outcome({run:final},final.exitCode);
}
export async function verifyFinding(root,findingId,{target,build,retest=false,signal}={}){
  const state=read(root),finding=named(state.findings,findingId,'Finding');
  target=target||finding.target||state.activeTarget;
  const t=named(state.targets,target,'Target');scopeReady(t);
  need(finding.target===target,'Finding is bound to another target. Add an explicit saved-test binding for another environment.',3);
  if(!finding.fixture||!state.demo||target!==state.demo.target){
    const verification={status:'simulated_unproven',simulation:true,requests:0,modelCalls:0,reason:'The live verification engine is mocked. No exploit was sent to this deployed application.'};
    await change(root,s=>{const f=named(s.findings,findingId,'Finding');f.history.push({at:now(),action:retest?'retest':'verify',...verification});f.verification=verification;});
    return outcome({findingId,verification},3);
  }
  const check={target,fixture:true,bindings:{[target]:finding.binding}};
  const result=await replay(specFor(state,check,target),{signal});
  const inv=await inventory(root);
  const status=result.status==='failed'?'confirmed_fixture':retest&&result.status==='passed'?'fixed_verified':result.status==='passed'?'not_reproduced_fixture':'blocked';
  await change(root,s=>{const f=named(s.findings,findingId,'Finding');f.status=status;f.verification={...result,fixture:true,simulation:false,at:now(),build:build?{value:build,source:'operator-supplied, not attested'}:null};f.history.push({action:retest?'retest':'verify',...f.verification});f.sourceFingerprint=inv.fingerprint;event(s,status,`${f.title}: ${status}`,{findingId});});
  let saved=null;
  if(status==='fixed_verified'&&state.settings.autoSave){saved=await saveCheck(root,findingId);await change(root,s=>{const c=named(s.checks,saved.id,'Check');c.sourceFingerprint=inv.fingerprint;c.lastResult={...result,checkedAt:now(),target};});saved=named(read(root).checks,saved.id,'Check');}
  return outcome({findingId,status,verification:result,fixtureOnly:true,savedCheck:saved,build:build||null},result.status==='failed'?1:result.status==='passed'?0:3);
}
