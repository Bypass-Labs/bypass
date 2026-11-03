import { assessmentPolicy, createWorklist, applyDispositions, workProgress, observeSource } from './review-worklist.mjs';
import { requireSource } from './application-setup.mjs';
import { read, change, writeEvidence } from './store.mjs';
import { inventory } from './repository.mjs';
import { sourceReader, groundCandidates } from './real-engine.mjs';
import { runChecks } from './checks.mjs';
import { reviewReadiness } from './review-readiness.mjs';
import { saveSourceCandidates, executeProbe } from './security-execution.mjs';
import { consolidateMemory, recallMemory, rememberSource } from './project-memory.mjs';
import fs from 'node:fs';
import path from 'node:path';
import { testRegistration, registrationStatus } from './registration.mjs';
import { hostAI } from './execution-mode.mjs';
import { id, now, named, need, outcome, hash, abortFault, redact } from './util.mjs';

const HOST_SOURCE_BYTES=2000000;
const hostReader=(root,inv)=>sourceReader(root,inv,{maxBytes:HOST_SOURCE_BYTES});

function focusedValidationRuns(root, sourceRun, origin) {
  const dir=path.join(root,'.bypass','runs');
  const latest=new Map(),all=[];
  if(!fs.existsSync(dir))return {latest,all};
  for(const entry of fs.readdirSync(dir)){
    if(!entry.startsWith('bx-'))continue;
    try{
      const saved=JSON.parse(fs.readFileSync(path.join(dir,entry,'run.json'),'utf8'));
      if(!saved.focus?.findingId||saved.scope?.target?.origin!==origin||
        !sourceRun.result?.findings?.includes(saved.focus.findingId)||
        Date.parse(saved.startedAt)<Date.parse(sourceRun.startedAt))continue;
      saved.sealedFindings=focusedProofs(path.join(dir,entry),saved);
      all.push(saved);
      const previous=latest.get(saved.focus.findingId);
      if(!previous||Date.parse(saved.startedAt)>Date.parse(previous.startedAt))latest.set(saved.focus.findingId,saved);
    }catch{ /* Ignore unrelated or unfinished run folders. */ }
  }
  return {latest,all};
}

function focusedProofs(runDir, saved) {
  let findings;
  try {findings=JSON.parse(fs.readFileSync(path.join(runDir,'findings.json'),'utf8'));}
  catch {return [];}
  if(!Array.isArray(findings))return [];
  const origin=saved.scope.target.origin;
  const focusPath=new URL(saved.focus.path,origin).pathname;
  const proofRoot=path.resolve(runDir,'poc')+path.sep;
  return findings.filter(finding=>{
    if(finding.verdict!=='confirmed'||typeof finding.proof!=='string')return false;
    const proof=path.resolve(finding.proof);
    const specFile=path.join(path.dirname(proof),'spec.json');
    if(!proof.startsWith(proofRoot)||path.basename(proof)!=='poc.mjs'||
      !fs.existsSync(proof)||!fs.existsSync(specFile))return false;
    let spec;
    try {spec=JSON.parse(fs.readFileSync(specFile,'utf8'));}
    catch {return false;}
    const steps=[spec.request,spec.subject,...(Array.isArray(spec.prelude)?spec.prelude:[]),
      ...(Array.isArray(spec.observe)?spec.observe:[]),
      ...(Array.isArray(spec.rawRequests)?spec.rawRequests:[])];
    return [finding.url,finding.pattern,...steps.map(step=>
      typeof step==='string'?step:step?.path??step?.url)].some(value=>{
      if(typeof value!=='string')return false;
      try {const url=new URL(value,origin);return url.origin===origin&&url.pathname===focusPath;}
      catch {return false;}
    });
  });
}

function budgetForRun(run, focusedRuns) {
  const {modelCalls,minutes}=run.options??{};
  if(modelCalls==null||minutes==null)return null;
  const modelCallsUsed=focusedRuns.reduce((sum,saved)=>sum+(saved.stats?.modelCalls??0),0);
  const modelCallsRemaining=Math.max(0,modelCalls-modelCallsUsed);
  const minutesRemaining=Math.max(0,(Date.parse(run.startedAt)+minutes*60000-Date.now())/60000);
  return {modelCalls,minutes,modelCallsUsed,modelCallsRemaining,minutesRemaining,
    exhausted:modelCallsRemaining===0||minutesRemaining===0};
}

export function combinedFocusBudget(root, findingId) {
  const state=read(root);
  const run=state.runs.filter(item=>item.executionMode==='muse-host'&&item.host?.mode==='combined'&&
    item.result?.findings?.includes(findingId))
    .sort((a,b)=>Date.parse(b.startedAt)-Date.parse(a.startedAt))[0];
  if(!run||run.options?.modelCalls==null||run.options?.minutes==null)return null;
  const target=state.targets.find(item=>item.name===run.host.target);
  if(!target?.url)return null;
  return {...budgetForRun(run,focusedValidationRuns(root,run,target.url).all),
    rps:run.host.scope?.maxRequestsPerSecond,reviewRunId:run.id};
}

function focusedOutcome(saved) {
  if(!saved)return {status:'pending'};
  const counts=saved.stats??{};
  const status=!saved.finishedAt?'running':saved.sealedFindings.length?'confirmed':
    counts.confirmed>0||counts.inconclusive>0?'inconclusive':'untested';
  return {status,runId:saved.run,proofs:saved.sealedFindings.map(item=>item.id),
    ...(status==='untested'&&counts.tasks>0?
      {reason:'No test of the focused hypothesis was independently recorded.'}:{}),
    counts:{confirmed:counts.confirmed??0,
    notReproduced:counts.notReproduced??0,inconclusive:counts.inconclusive??0,
    blocked:counts.blocked??0,tasks:counts.tasks??0}};
}

export function hostPlan(state, options={}) {
  const mode=options.mode||state.settings.reviewMode||'combined';need(['code','live','combined'].includes(mode),'Invalid review mode.');
  need(!(options.base&&options.full),'Choose base or full, not both.');
  const ready=reviewReadiness(state,{targetName:options.target||state.activeTarget,executionMode:'muse-host'});
  return {executionMode:'muse-host',engine:'host',simulation:false,mode,target:ready.target?.name||null,ai:hostAI(),
    assessmentPolicy,limits:{sourceBytes:HOST_SOURCE_BYTES,operations:128,probes:64},repository:state.project.repository,app:ready.target?{url:ready.target.url,environment:ready.target.environment}:null,
    blockers:mode==='code'?[]:ready.liveBlockers,coverageGaps:ready.coverageGaps,registration:registrationStatus(ready.target),savedChecks:state.checks.filter(c=>c.enabled).length,
    whiteBox:{status:mode==='live'?'not_run':'host_plans',description:'Muse reads eligible source and submits exact cited hypotheses.'},
    blackBox:{status:mode==='code'?'not_run':ready.liveBlockers.length?'blocked':'host_selects',description:'Muse selects approved probes; observed controls determine confirmation.'},
    dataFlow:{source:'Returned to the active Muse session on request',inference:'Muse host only; plugin API calls disabled',evidence:'Local .bypass/runs'},
    message:'Bounded authentication and account-boundary POC; source hypotheses alone are not confirmed vulnerabilities.'};
}
const receipt=(root,run)=>{const state=read(root),work=workProgress(run,state);
  const target=state.targets.find(item=>item.name===run.host?.target);
  const approved=run.host?.scope;
  const setup=approved&&target?.url?{url:target.url,include:approved.paths.join(','),
    methods:approved.methods.join(','),rps:approved.maxRequestsPerSecond,
    environment:target.environment,
    out:`blackbox.focus.${hash({url:target.url,scope:approved}).slice(0,12)}.scope.json`}:null;
  const focused=target?.url?focusedValidationRuns(root,run,target.url):{latest:new Map(),all:[]};
  const combinedBudget=run.host?.mode==='combined'?budgetForRun(run,focused.all):null;
  const runLimits=combinedBudget&&!combinedBudget.exhausted?
    {'model-calls':combinedBudget.modelCallsRemaining,minutes:combinedBudget.minutesRemaining}:null;
  if(runLimits&&setup)Object.assign(setup,runLimits);
  const hostConfirmed=new Set(run.result?.confirmed??[]);
  const liveValidation=run.host?.mode==='combined'&&target?.url?
    (run.result?.findings??[]).map(id=>state.findings.find(item=>item.id===id))
      .filter(item=>item?.sourceEvidence?.kind==='source')
      .map(item=>({finding:item.id,title:item.title,path:item.resourcePath,
        source:item.sourceEvidence,tool:'bypass_blackbox_start',url:target.url,
        setup:setup&&item.resourcePath?{tool:'bypass_blackbox_setup',arguments:setup}:null,
        runLimits,
        ...(hostConfirmed.has(item.id)?{status:'confirmed',runId:run.id,proofSource:'host-probe'}:
          !item.resourcePath?{status:'blocked',reason:'No concrete application path was supplied for focused validation.'}:
            focusedOutcome(focused.latest.get(item.id))),
        message:item.resourcePath?'Use the exact approved setup, then start with finding set to this ID. Record its terminal outcome and continue the remaining findings.':
          'Record this source lead as blocked until a concrete application path is observed or supplied.'})) : [];
  const pendingValidation=liveValidation.filter(item=>item.status==='pending');
  const runningValidation=liveValidation.find(item=>item.status==='running');
  const confirmedValidation=liveValidation.filter(item=>item.status==='confirmed')
    .map(item=>({finding:item.finding,title:item.title,runId:item.runId,
      ...(item.proofs?{proofs:item.proofs}:{}),
      ...(item.proofSource?{proofSource:item.proofSource}:{})}));
  for(const id of hostConfirmed){
    if(confirmedValidation.some(item=>item.finding===id))continue;
    const finding=state.findings.find(item=>item.id===id);
    if(finding)confirmedValidation.push({finding:id,title:finding.title,runId:run.id,proofSource:'host-probe'});
  }
  const remediation=['completed','incomplete'].includes(run.status)&&
    !runningValidation&&(!pendingValidation.length||combinedBudget?.exhausted)&&confirmedValidation.length?
    {confirmed:confirmedValidation,untested:pendingValidation.map(item=>item.finding),
    message:`Offer to fix all confirmed issues and open a PR. Application edits require the user to select that remediation action.${pendingValidation.length?` ${pendingValidation.length} source leads remain untested due the combined audit limit.`:''}`}:null;
  return ({runId:run.id,status:run.status,executionMode:'muse-host',pluginModelCalls:0,simulation:false,coverageComplete:false,
  assessmentPolicy,work,continueRequired:run.status==='awaiting_host'&&work.pending>0,
  progress:{stage:run.stage,work,lastCompleted:run.steps.at(-1)||null,elapsedSeconds:Math.floor((Date.now()-Date.parse(run.startedAt))/1000),waitingSeconds:Math.floor((Date.now()-Date.parse(run.steps.at(-1)?.at||run.startedAt))/1000),waitingFor:run.status==='awaiting_host'?'Muse reasoning; no internal worker':null,resume:{tool:'bypass_review_step',arguments:{id:run.id,action:run.status==='cancelled'?'resume':'status'}},cancel:{tool:'bypass_stop_run',arguments:{id:run.id}}},
  evidence:`${root}/.bypass/runs/${run.id}.json`,findings:run.result?.findings||[],liveValidation,combinedBudget,remediation,
  liveValidationProgress:{total:liveValidation.length,completed:liveValidation.length-pendingValidation.length-Number(!!runningValidation),pending:pendingValidation.length,running:runningValidation?.finding??null},
  probes:run.result?.probes||[],registration:run.result?.registration,coverageGaps:run.result?.coverageGaps||[],
  outcomes:{confirmed:run.result?.confirmed||[],notRun:run.result?.notRun||null,executionFailures:run.result?.probes?.filter(p=>p.status==='blocked').map(p=>({resource:p.resource,reason:p.reason}))||[]},
  nextAction:['completed','incomplete'].includes(run.status)?
    (runningValidation?{tool:'bypass_blackbox_next',message:`Continue the focused validation of ${runningValidation.finding} in this Muse session.`}:
      pendingValidation.length&&combinedBudget?.exhausted?{tool:'bypass_findings',arguments:{run:run.id},
        message:`Combined audit limit reached. ${pendingValidation.length} source findings remain untested live; report them explicitly.${remediation?` ${remediation.message}`:''}`}:
      pendingValidation.length&&setup?{tool:'bypass_blackbox_setup',arguments:setup,
        finding:pendingValidation[0].finding,message:`Validate ${pendingValidation[0].finding}, then refresh this source run's status for the next finding. Do not stop after one.`}:
        {tool:run.result?.findings?.length?'bypass_findings':'bypass_run',arguments:run.result?.findings?.length?{run:run.id}:{id:run.id},
          ...(remediation?{message:remediation.message}:{})}):
    {tool:'bypass_review_step',arguments:{id:run.id,action:work.next.action,...work.next.arguments},message:work.next.message},
  guidance:remediation?'Present the proposed fixes and saved regressions for every confirmed issue, then offer the remediation choice. Only a separate explicit user selection authorizes application edits and a PR.':
    'Continue the assessment until the recorded worklist has no actionable pending work. A finding is an interim update, not permission to stop or fix code. Show Done / Now / Next, elapsed time, counts, and the honest estimate or uncertainty. Read source, configure supported probes, refresh, execute controls, and record specific blockers for remaining routes. Do not edit application source or configuration. Generate recommendations and regression artifacts. A separate explicit remediation request is required for fixes.'});};
export async function beginHostReview(root,options={},context={}) {
  const initial=read(root),plan=hostPlan(initial,options);need(!plan.blockers.length,plan.blockers.join(' '),3);
  if(options.modelCalls!=null)need(Number.isSafeInteger(options.modelCalls)&&options.modelCalls>0,
    'Muse decision-call limit must be a positive whole number.');
  if(options.minutes!=null)need(Number.isFinite(options.minutes)&&options.minutes>0,
    'Combined audit time limit must be a positive number of minutes.');
  if(plan.mode!=='live')await requireSource(root);
  const run={id:id('run'),kind:'scan',options,status:'awaiting_host',stage:'planning',createdAt:now(),startedAt:now(),steps:[],simulation:false,executionMode:'muse-host',modelCalls:0,
    host:{mode:plan.mode,target:plan.target,reads:[],sourceSubmitted:false,visited:[],operations:0},result:{engine:'host',simulation:false,modelCalls:0,findings:[],probes:[],coverageComplete:false}};
  await change(root,s=>{s.runs.push(run);});
  try {
    context.onProgress?.({message:'Replaying saved checks and preparing source for Muse'});
    const regression=plan.mode==='code'?{results:[],exitCode:0}:await runChecks(root,{all:true,target:plan.target,signal:context.signal,runId:run.id});
    const inv=plan.mode==='live'?{files:[],fingerprint:null,routes:[],sourceFileCount:0}:await inventory(root,options.base);
    if(context.signal?.aborted)throw abortFault(context.signal);
    const current=read(root),target=current.targets.find(t=>t.name===plan.target);
    const passed=regression.results.filter(r=>r.status==='passed').map(r=>r.id);
    const bindings=plan.mode==='code'?[]:(target?.probes||[]).filter(p=>!current.checks.some(c=>passed.includes(c.id)&&hash(c.bindings[plan.target])===hash(p.binding))).map(p=>({...p.binding,name:p.name}));
    let initialSource=[];
    if(inv.files.length>0&&inv.files.length<=4&&inv.files.reduce((n,file)=>n+fs.statSync(path.join(root,file)).size,0)<=32000){
      const reader=hostReader(root,inv);initialSource=reader.read(inv.files);run.host.reads.push(inv.files);observeSource(run,initialSource);
    }
    const registration=plan.mode==='code'?{status:'not_run',reason:'Source-only review; no registration requests.'}:await testRegistration(root,{target:plan.target,signal:context.signal});
    await consolidateMemory(root);const memory=await recallMemory(root,{target:plan.target,inv,mode:plan.mode,forAgent:true,limit:8,maxBytes:8000});
    const saved=await change(root,s=>{const r=named(s.runs,run.id,'Run');Object.assign(r.host,{inventory:inv,bindings,reads:run.host.reads,sourceCoverage:run.host.sourceCoverage||{},scope:structuredClone(target?.authorization||null),worklist:createWorklist(inv,target,plan.mode)});r.result.registration=registration;if(!registration.reused)r.result.findings.push(...(registration.findings||[]));r.result.coverageGaps=plan.coverageGaps;r.result.regression=regression.results;r.result.exactPassingChecksExcluded=passed;r.steps.push({at:now(),stage:'planning',message:'Ready for Muse to choose source reads and approved probes.'});return r;});
    writeEvidence(root,saved);
    return outcome({...receipt(root,saved),plan,initialSource,inventory:{files:inv.files.slice(0,400),totalFiles:inv.files.length,routes:inv.routes?.slice(0,80),routeLocations:inv.routeLocations?.slice(0,160)},resources:bindings.map((b,index)=>({index,name:b.name,resourcePath:b.resourcePath,resourceId:b.resourceId})),memory,
      nextAction:{tool:'bypass_review_step',arguments:{id:run.id,action:plan.mode==='live'||initialSource.length?'complete':'read'},message:'Read needed source in batches, then use complete to submit cited hypotheses and test every remaining configured resource. The review stays open until every discovered in-scope route has evidence or a specific disposition. Credentials are optional. Discover signup and resource routes from source; configure supported checks and refresh resources before completing.'}});
  } catch(error) {
    const saved=await change(root,s=>{const r=named(s.runs,run.id,'Run');r.status=context.signal?.aborted?'cancelled':'failed';r.finishedAt=now();r.result.message=redact(error.message);r.exitCode=context.signal?.aborted?130:3;return r;});writeEvidence(root,saved);throw error;
  }
}
const busy=new Set(),controllers=new Map();
export async function hostReviewStep(root,args,{signal,onProgress}={}) {
  const key=`${root}:${args.id}`;
  if(args.action==='cancel'&&controllers.has(key)){controllers.get(key).abort();return outcome({runId:args.id,status:'cancelling',message:'Cancellation requested; current HTTP request will stop and retain evidence.'});}
  const controller=new AbortController();signal=signal?AbortSignal.any([signal,controller.signal]):controller.signal;
  need(!busy.has(key),'This review already has an operation in progress. Retry after it completes.',3);busy.add(key);controllers.set(key,controller);
  try {
    let run=named(read(root).runs,args.id,'Run');need(run.executionMode==='muse-host','This is not a host-orchestrated review.',3);
    if(args.action==='resume'){need(run.status==='cancelled','Only cancelled reviews need resume.',3);need(Date.now()-Date.parse(run.createdAt)<86400000,'Review expired; start a new one.',3);if(run.host.mode!=='live')need((await inventory(root,run.options.base)).fingerprint===run.host.inventory.fingerprint,'Source changed; start a new review.',3);await change(root,s=>{const r=named(s.runs,args.id,'Run');r.status='awaiting_host';delete r.finishedAt;delete r.exitCode;});return outcome({...receipt(root,named(read(root).runs,args.id,'Run')),message:'Saved review resumed. HTTP operations will recheck current scope.'});}
    if(args.action==='status')return outcome({...receipt(root,run),sourceReads:run.host.reads,sourceSubmitted:run.host.sourceSubmitted,worklist:run.host.worklist,resources:run.host.bindings?.map((b,index)=>({index,name:b.name,resourcePath:b.resourcePath,tested:run.host.visited.includes(index)})),lastError:run.host.lastError});
    need(run.status==='awaiting_host','Review is finished. Start a new review; saved findings can still be retested.',3);
    if(args.action==='cancel'){const saved=await change(root,s=>{const r=named(s.runs,args.id,'Run');r.status='cancelled';r.finishedAt=now();r.exitCode=130;return r;});writeEvidence(root,saved);return outcome(receipt(root,saved));}
    need(Date.now()-Date.parse(run.createdAt)<86400000,'Review expired after 24 hours. Start a new review; evidence is retained.',3);
    if(run.host.operations>=128){
      run.host.limitReason||='Review operation budget exhausted (128 operations); further investigation is blocked. Remaining configured HTTP controls can still run.';
      if(!['probe','complete','finish','coverage'].includes(args.action))throw new Error(run.host.limitReason);
    }
    if(signal?.aborted)throw abortFault(signal);
    const {inventory:inv,mode,target}=run.host;let {bindings}=run.host;
    if(mode!=='live')need((await inventory(root,run.options.base)).fingerprint===inv.fingerprint,'Source changed during assessment. Review permissions do not authorize remediation. Inspect the change; retain evidence and start a fresh source review when appropriate.',3);
    run.host.worklist??=createWorklist(inv,read(root).targets.find(t=>t.name===target),mode);
    if(mode!=='code'&&['probe','complete','finish','refresh'].includes(args.action)){
      const current=read(root),app=current.targets.find(t=>t.name===target);
      for(const p of app?.probes||[]){
        const previous=bindings.find(b=>b.name===p.name);
        if(previous)need(hash(Object.fromEntries(Object.entries(previous).filter(([key])=>key!=='name')))===hash(p.binding),'Probe configuration changed during assessment. Preserve this evidence and start a new review for the changed binding.',3);
        if(!bindings.some(b=>b.name===p.name)&&!current.checks.some(c=>run.result.exactPassingChecksExcluded.includes(c.id)&&hash(c.bindings[target])===hash(p.binding)))bindings.push({...p.binding,name:p.name});
      }
    }
    let result={};
    const persist=async()=>{await change(root,s=>{const r=named(s.runs,args.id,'Run');r.result=run.result;});};
    if(args.action==='read'||args.action==='source'||(args.action==='complete'&&mode!=='live'&&!run.host.sourceSubmitted&&!run.host.limitReason)){
      need(mode!=='live','This is a live-only review.',3);
      const current=await inventory(root,run.options.base);need(current.fingerprint===inv.fingerprint,'Source changed during review. Start a new review for fresh citations; use retest for existing findings.',3);
      const reader=hostReader(root,inv);for(const batch of run.host.reads)observeSource(run,reader.read(batch));
      if(args.action==='read'){const files=reader.read(args.paths);run.host.reads.push(args.paths);observeSource(run,files);result={files};}
      else {
        need(reader.readFiles.size>0,'Read application source before submitting source conclusions.',3);
        const candidates=groundCandidates(args.candidates||[],reader,inv).filter(c=>!read(root).checks.some(check=>run.result.exactPassingChecksExcluded.includes(check.id)&&check.bindings[target]?.resourcePath===c.resourcePath));
        await saveSourceCandidates(root,{candidates,bindings,targetName:target,sourceFingerprint:inv.fingerprint,runId:args.id,engine:'host',candidateIds:run.result.findings});
        run.result.findings=[...new Set(run.result.findings)];
        result={hypotheses:candidates.length,knowledge:await rememberSource(root,args.knowledge||[],reader,inv,args.id)};run.host.sourceSubmitted=true;await change(root,s=>{Object.assign(named(s.runs,args.id,'Run'),run);});
      }
    }
    if(args.action==='coverage'){
      const reader=hostReader(root,inv);for(const batch of run.host.reads)observeSource(run,reader.read(batch));
      result={dispositions:args.dispositions?applyDispositions(run,args.dispositions,reader,read(root)):[],worklist:run.host.worklist};
    }
    if(args.action==='refresh'){
      need(mode!=='code','Source-only reviews have no live probes.',3);
      const current=read(root),app=named(current.targets,target,'Target');
      run.result.registration=await testRegistration(root,{target,signal});if(!run.result.registration.reused)run.result.findings=[...new Set([...run.result.findings,...(run.result.registration.findings||[])])];
      result={resources:bindings.map((b,index)=>({index,name:b.name,path:b.resourcePath})),registration:run.result.registration};
    }
    if(args.action==='probe'||args.action==='complete'){
      const indexes=args.action==='complete'?(mode==='code'?[]:bindings.map((_,i)=>i).filter(i=>!run.host.visited.includes(i))):[args.index];
      if(args.action==='probe')need(mode!=='code'&&Number.isInteger(args.index)&&bindings[args.index],'Choose a configured resource index from this live review.',3);
      for(const index of indexes){
      need(!run.host.visited.includes(index),'This resource was already tested. Use verify or retest for follow-up.',3);
      const rawBinding=bindings[index],binding=Object.fromEntries(Object.entries(rawBinding).filter(([k])=>k!=='name'));
      const current=read(root).targets.find(t=>t.name===target)?.probes?.find(p=>p.name===rawBinding.name);
      need(current&&hash(current.binding)===hash(binding),'Probe configuration changed. Start a new review.',3);
      onProgress?.({message:`Testing ${rawBinding.name}: owner, other account, anonymous controls`});
      const probeStarted=Date.now();
      result={observation:await executeProbe(root,{binding,rawBinding,bindingIndex:index,targetName:target,sourceFingerprint:inv.fingerprint,runId:args.id,engine:'host',candidateIds:run.result.findings,probes:run.result.probes,signal,persist})};
      if(signal?.aborted)throw abortFault(signal);
      result.observation.elapsedMs=Date.now()-probeStarted;
      run.host.visited.push(index);run.steps.push({at:now(),stage:'probe',message:`${rawBinding.name}: ${result.observation.status} · ${run.host.visited.length}/${bindings.length} configured probes executed; continuing assessment`});
      await change(root,s=>{Object.assign(named(s.runs,args.id,'Run'),run);});writeEvidence(root,run);
      onProgress?.({message:`${rawBinding.name}: ${result.observation.status}. ${run.host.visited.length}/${bindings.length} configured probes executed. ${result.observation.status==='failed'?'Finding and regression saved; continuing assessment.':'Continuing remaining checks.'}`});
      }
    }
    if(args.action==='finish'||args.action==='complete'){
      const work=workProgress(run,read(root));
      if(work.canFinish||run.host.limitReason&&!work.configuredProbes.pending){
        run.status=work.blocked||run.host.limitReason?'incomplete':'completed';run.finishedAt=now();
        run.result.confirmed=run.result.findings.filter(id=>read(root).findings.find(f=>f.id===id)?.status==='confirmed'&&Date.parse(read(root).findings.find(f=>f.id===id)?.verification?.at)>=Date.parse(run.startedAt));
        run.result.notRun={source:mode==='live'||!run.host.sourceSubmitted||work.source.remainingFiles>0,sourceFiles:work.source.remainingFiles,resources:bindings.filter((_,i)=>!run.host.visited.includes(i)).map(b=>b.name),routes:(run.host.worklist||[]).filter(r=>r.status==='pending'||r.status==='blocked')};
        run.result.scopeExecuted=work.scopeExecuted;run.result.work=work;
        run.result.message=work.blocked||work.pending?'Assessment ended with specific blockers; remaining coverage is incomplete. See the worklist.':'Recorded assessment worklist executed. Report findings, recommendations and regressions. This is not an exhaustive security clearance.';
        run.exitCode=run.result.confirmed.length||run.result.regression.some(r=>r.status==='failed')||run.result.registration?.status==='failed'?1:3;run.result.exitCode=run.exitCode;
      }else{
        result={...result,finishDeferred:true,message:'Assessment continues: actionable work remains. Follow nextAction without asking whether to go deeper.'};
      }
    }
    need(['read','source','probe','refresh','coverage','complete','finish'].includes(args.action),'Unsupported host review action.',3);
    run.stage=args.action;run.host.operations++;delete run.host.lastError;run.steps.push({at:now(),stage:args.action,message:`Muse-directed ${args.action} complete`});
    await change(root,s=>{Object.assign(named(s.runs,args.id,'Run'),run);});writeEvidence(root,run);await consolidateMemory(root);
    return outcome({...receipt(root,run),...result});
  } catch(error) {
    await change(root,s=>{const r=s.runs.find(r=>r.id===args.id);if(r?.executionMode==='muse-host'){if(/source budget exceeded|operation budget exhausted/.test(error.message))r.host.limitReason=redact(error.message);r.host.lastError={message:redact(error.message),at:now(),retryable:!signal?.aborted};if(signal?.aborted){r.status='cancelled';r.finishedAt=now();r.exitCode=130;}writeEvidence(root,r);}}).catch(()=>{});
    throw error;
  } finally {busy.delete(key);controllers.delete(key);}
}
