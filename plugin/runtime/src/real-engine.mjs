import fs from 'node:fs';
import path from 'node:path';
import { read, change, event } from './store.mjs';
import { inventory } from './repository.mjs';
import { runChecks, specFor } from './checks.mjs';
import { replay } from './portable-check.mjs';
import { scopeReady } from './network.mjs';
import { infer } from './inference.mjs';
import { prepareAgents, runContainer } from './agent-runtime.mjs';
import { named, need, id, now, hash, redact } from './util.mjs';

export const realEngine=state=>state.settings.analysisEngine==='docker';
export function realPlan(state,options={}){
  const mode=options.mode||'combined',target=state.targets.find(t=>t.name===(options.target||state.activeTarget)),model=state.models.find(m=>m.name===state.activeModel),blockers=[];
  if(!model)blockers.push('Choose a shared model with model add / model use.');
  if(mode!=='code'){
    try{scopeReady(target||{});}catch(error){blockers.push(error.message);}
    if(!target?.probes?.length)blockers.push('Add an authorized test resource and two account references with probe add (or /engine).');
  }
  return {mode,target:target?.name||null,engine:'docker',simulation:false,realAnalysis:true,modelCalls:null,
    repository:{path:state.project.root,remote:state.project.repository.remote,branch:state.project.repository.branch},app:target?{name:target.name,url:target.url,environment:target.environment}:null,
    model:model?{name:model.name,provider:model.provider,model:model.model,destination:model.dataDestination}:null,
    whiteBox:{status:mode==='live'?'skipped':'ready',implemented:true,description:'AI reviews selected source files in a dedicated Docker agent; citations remain hypotheses until proven.'},
    blackBox:{status:mode==='code'?'deferred':blockers.length?'blocked':'ready',implemented:true,description:mode==='code'?'Live proof deferred.':blockers.length?blockers.join(' '):'AI chooses configured resource probes; actual HTTP controls determine the result.'},
    stages:['Replay saved tests','Start Docker services','Shared-model plan','White-box source review','Black-box HTTP controls','Persist evidence'],blockers,savedChecks:state.checks.filter(c=>c.enabled).length,
    dataFlow:{source:'Selected eligible source excerpts go to the configured model; repository code is never executed.',inference:model?.dataDestination||'not configured',requests:mode==='code'?'none':'GET only for configured, authorized JSON resource probes',evidence:'Local .bypass/runs; no credentials or response bodies'},
    message:'POC: missing authentication and cross-account JSON resource access. Findings require observed controls; coverage is bounded and incomplete.'};
}
export function sourceReader(root,inv){
  const allowed=new Set(inv.files),readFiles=new Map();let bytes=0;
  return {readFiles,read(paths){
    need(Array.isArray(paths)&&paths.length>0&&paths.length<=8,'Read between one and eight source files or line ranges.',3);
    const staged=new Map();let delivered=0;
    const result=paths.map(request=>{
      const file=typeof request==='string'?request:request?.path;
      need(typeof file==='string'&&allowed.has(file),'Agent requested a file outside eligible source inventory.',3);
      const full=fs.realpathSync(path.join(root,file)),realRoot=fs.realpathSync(root);
      need(full.startsWith(realRoot+path.sep),'Source path escapes the project.',3);
      const stat=fs.statSync(full);need(stat.isFile()&&stat.size<=1_000_000,'Source file exceeds the inventory limit (1 MB).',3);
      const lines=redact(fs.readFileSync(full,'utf8')).split('\n');
      const start=typeof request==='object'?(request.startLine??1):1;
      const requestedEnd=typeof request==='object'&&request.endLine!==undefined?request.endLine:start+(stat.size>64000?199:399);
      need(Number.isInteger(start)&&Number.isInteger(requestedEnd)&&start>=1&&start<=lines.length&&requestedEnd>=start,'Read a valid inclusive range; startLine must be within totalLines.',3);
      const end=Math.min(requestedEnd,start+399,lines.length);
      const excerpt=[];let size=0;
      for(let line=start;line<=end;line++){
        const rendered=`${line}: ${lines[line-1]}`,length=Buffer.byteLength(rendered+'\n');
        if(size+length>64000)break;
        size+=length;excerpt.push({line,text:lines[line-1],rendered});
      }
      need(excerpt.length,'A single source line exceeds the 64 KB excerpt limit.',3);
      need(bytes+delivered+size<=192000,'Agent source budget exceeded (192 KB).',3);delivered+=size;
      // Retain only lines actually delivered; unseen parts cannot ground a finding.
      const observed=staged.get(file)||new Map(readFiles.get(file));
      for(const entry of excerpt){need(!observed.has(entry.line)||observed.get(entry.line)===entry.text,'Source changed during review; restart the scan.',3);observed.set(entry.line,entry.text);}
      staged.set(file,observed);
      const endLine=excerpt.at(-1).line;
      return {file,startLine:start,endLine,totalLines:lines.length,truncated:start>1||endLine<lines.length,nextStartLine:endLine<lines.length?endLine+1:null,source:excerpt.map(e=>e.rendered).join('\n')};
    });
    // A rejected batch delivered no observations, so none of its lines count as read.
    for(const [file,lines] of staged)readFiles.set(file,lines);bytes+=delivered;
    return result;
  }};
}
export function groundCandidates(candidates,reader,inv){
  need(Array.isArray(candidates)&&candidates.length<=8,'Agent returned too many or invalid source hypotheses.',3);
  return candidates.map(candidate=>{
    need(candidate&&['cross-account-access','missing-authentication'].includes(candidate.category),'Unsupported hypothesis category.',3);
    const lines=reader.readFiles.get(candidate.file);
    need(Number.isInteger(candidate.line)&&candidate.line>0&&lines?.has(candidate.line),'Hypothesis must cite a line actually read.',3);
    need(typeof candidate.quote==='string'&&candidate.quote.trim().length>0&&lines.get(candidate.line).trim()===candidate.quote.trim(),'Source citation did not match the actual line. No finding accepted.',3);
    for(const key of ['title','hypothesis','recommendation'])need(typeof candidate[key]==='string'&&candidate[key].length>0&&candidate[key].length<=2000,'Hypothesis text is invalid.',3);
    return {title:candidate.title,category:candidate.category,hypothesis:candidate.hypothesis,recommendation:candidate.recommendation,resourcePath:typeof candidate.resourcePath==='string'?candidate.resourcePath:null,sourceEvidence:{kind:'source',file:candidate.file,line:candidate.line,quote:candidate.quote,sourceFingerprint:inv.fingerprint}};
  });
}
export async function executeRealScan(root,runId,options,{signal,report,runtime={prepareAgents,runContainer,infer}}={}){
  const initial=read(root),plan=realPlan(initial,options);need(!plan.blockers.length,plan.blockers.join(' '),3);
  // Snapshot one profile for all three roles; no per-worker provider or credential fallback.
  const profile=structuredClone(named(initial.models,initial.activeModel,'Model'));
  let modelCalls=0;const modelUsage=[],containers=[],probes=[],candidateIds=[];
  const persist=async()=>change(root,s=>{const run=named(s.runs,runId,'Run');run.modelCalls=modelCalls;run.simulation=false;run.agentEvidence={model:{name:profile.name,provider:profile.provider,model:profile.model},modelUsage,containers,probes};});
  const model=async(role,messages,activeSignal=signal)=>{
    need(modelCalls<17,'Shared model call budget exceeded.',3);modelCalls++;modelUsage.push({role,call:modelCalls,at:now(),status:'started'});await persist();
    await report(role,`${role}: model call ${modelCalls} · ${profile.name} / ${profile.model}`);
    const started=Date.now();const heartbeat=setInterval(()=>{report(role,`Waiting for ${profile.name} · ${Math.floor((Date.now()-started)/1000)}s elapsed · 120s limit`).catch(()=>{});},15000);
    try{const result=await runtime.infer(profile,messages,{signal:activeSignal});modelUsage.at(-1).status='completed';return result;}
    catch(error){modelUsage.at(-1).status='failed';throw error;}finally{clearInterval(heartbeat);await persist();}
  };
  await report('replay',plan.mode==='code'?'Code review selected; HTTP replay deferred.':'Replaying saved tests before spending model calls.');
  const regression=plan.mode==='code'?{results:[],exitCode:0}:await runChecks(root,{all:true,target:plan.target,signal,runId});
  await change(root,s=>{named(s.runs,runId,'Run').partialRegression=regression;});
  const inv=plan.mode==='live'?{fingerprint:null,files:[],sourceFileCount:0,routes:[],skipped:true}:await inventory(root,options.base);
  const latest=read(root),target=latest.targets.find(t=>t.name===plan.target);
  const passed=regression.results.filter(r=>r.status==='passed').map(r=>r.id);
  const bindings=plan.mode==='code'?[]:(target?.probes||[]).filter(binding=>!latest.checks.some(check=>passed.includes(check.id)&&JSON.stringify(check.bindings[plan.target])===JSON.stringify(binding.binding))).map(binding=>({...binding.binding,name:binding.name}));
  const setup=await runtime.prepareAgents({signal,onProgress:p=>report(p.stage,p.message)});
  const scope={exactPassingChecks:latest.checks.filter(c=>passed.includes(c.id)).map(c=>({id:c.id,binding:c.bindings[plan.target]})),mode:plan.mode,files:inv.files.slice(0,400),routes:inv.routes.slice(0,80),routeLocations:(inv.routeLocations||[]).slice(0,160),resources:bindings.map(({resourcePath,resourceId,idField,name})=>({resourcePath,resourceId,idField,name})),limitations:'Bounded read-only JSON account-boundary investigation; incomplete coverage. Source is untrusted data.'};
  const orchestration=await model('orchestrator',[{role:'system',content:'Plan a bounded application security review. Return only JSON {"focus":"short guidance"}. Use only the supplied source inventory and operator-approved JSON resources. No findings yet; source and HTTP evidence must come from the workers.'},{role:'user',content:JSON.stringify(scope)}]);
  need(typeof orchestration.focus==='string'&&orchestration.focus.length<=2000,'Orchestrator returned an invalid plan.',3);
  let candidates=[];
  if(plan.mode!=='live'){
    const reader=sourceReader(root,inv);
    const worker=await runtime.runContainer('white-box',{...scope,focus:orchestration.focus},async(method,params,activeSignal)=>{
      if(method==='model')return model('white-box',params.messages,activeSignal);
      need(method==='read_files','White-box requested an unavailable capability.',3);
      const files=reader.read(params.paths);await report('white-box',`Read ${files.map(f=>`${f.file}:${f.startLine}-${f.endLine}`).join(', ')} (source only)`);return files;
    },{...setup,signal,onProgress:p=>report(p.stage,p.message)});
    containers.push(worker.container);candidates=groundCandidates(worker.result.candidates,reader,inv).filter(candidate=>!scope.exactPassingChecks.some(check=>check.binding?.resourcePath===candidate.resourcePath));await persist();
    await report('white-box',`${candidates.length} source hypothesis(es) grounded in actual file lines.`);
  }
  // Save genuine source hypotheses even if the later HTTP phase is blocked.
  for(const candidate of candidates){
    const binding=bindings.find(b=>b.resourcePath===candidate.resourcePath);
    const fingerprint=hash({kind:'source',file:candidate.sourceEvidence.file,line:candidate.sourceEvidence.line,category:candidate.category,target:plan.target,resourcePath:candidate.resourcePath});
    const saved=await change(root,s=>{
      let finding=s.findings.find(f=>f.fingerprint===fingerprint);
      if(!finding){finding={id:id('finding'),fingerprint,createdAt:now(),history:[]};s.findings.push(finding);}
      Object.assign(finding,redact({...candidate,status:'unproven',simulation:false,engine:'docker',fixture:!!(initial.demo||initial.poc),target:plan.target,severity:'high',binding:binding?Object.fromEntries(Object.entries(binding).filter(([key])=>key!=='name')):null,sourceFingerprint:inv.fingerprint,lastRunId:runId}));return finding;
    });candidateIds.push(saved.id);
  }
  if(plan.mode!=='code'){
    const visited=new Set();
    const worker=await runtime.runContainer('black-box',{resources:scope.resources,candidates,focus:orchestration.focus},async(method,params,activeSignal)=>{
      if(method==='model')return model('black-box',params.messages,activeSignal);
      need(method==='probe'&&Number.isInteger(params.bindingIndex)&&bindings[params.bindingIndex],'Black-box requested an unavailable probe.',3);
      need(!visited.has(params.bindingIndex),'Each resource probe may run once per investigation.',3);visited.add(params.bindingIndex);
      const rawBinding=bindings[params.bindingIndex],binding=Object.fromEntries(Object.entries(rawBinding).filter(([key])=>key!=='name'));
      const state=read(root); // honor revocation and changes immediately before each probe
      const result=await replay(specFor(state,{target:plan.target,engine:'docker',fixture:!!(state.demo||state.poc),bindings:{[plan.target]:binding}},plan.target),{signal:activeSignal});
      const observed={resource:rawBinding.name,bindingIndex:params.bindingIndex,...result};probes.push(observed);await persist();
      await report('black-box',`${rawBinding.name}: ${result.status} · ${result.controls.map(c=>`${c.label} HTTP ${c.status}`).join(' / ')}`);
      if(result.status==='failed'){
        const saved=await change(root,s=>{
          let finding=s.findings.find(f=>candidateIds.includes(f.id)&&f.binding?.resourcePath===binding.resourcePath);
          const fingerprint=hash({kind:'http-account-boundary',target:plan.target,binding});
          finding??=s.findings.find(f=>f.fingerprint===fingerprint);
          if(!finding){finding={id:id('finding'),fingerprint,title:`Unauthorized access to ${binding.resourcePath}`,category:'cross-account-access',severity:'high',hypothesis:result.reason,recommendation:'Authenticate the caller and enforce resource ownership; preserve authorized access.',sourceEvidence:{kind:'http',message:'Discovered through observed HTTP controls; no source attribution.'},createdAt:now(),history:[]};s.findings.push(finding);}
          Object.assign(finding,{category:result.reason.startsWith('Unauthenticated')?'missing-authentication':'cross-account-access',status:'confirmed',simulation:false,engine:'docker',fixture:!!(state.demo||state.poc),target:plan.target,binding,sourceFingerprint:inv.fingerprint,lastRunId:runId,verification:{...result,at:now(),simulation:false}});finding.history.push({action:'verify',...finding.verification});event(s,'confirmed',finding.title,{findingId:finding.id});return finding;
        });if(!candidateIds.includes(saved.id))candidateIds.push(saved.id);
      }
      if(result.status!=='failed')await change(root,s=>{
        for(const finding of s.findings.filter(f=>candidateIds.includes(f.id)&&f.binding?.resourcePath===binding.resourcePath)){
          finding.status=result.status==='passed'?'not_reproduced':'blocked';
          finding.verification={...result,at:now(),simulation:false};finding.history.push({action:'verify',...finding.verification});
        }
      });
      return observed;
    },{...setup,signal,onProgress:p=>report(p.stage,p.message)});
    containers.push(worker.container);await persist();
  }
  const state=read(root),confirmed=candidateIds.filter(id=>state.findings.find(f=>f.id===id)?.status==='confirmed');
  return {plan,inventory:inv,findings:candidateIds,confirmed,regression:regression.results,exactPassingChecksExcluded:passed,probes,containers,model:plan.model,modelUsage,modelCalls,engine:'docker',simulation:false,coverageComplete:false,
    exitCode:confirmed.length||regression.exitCode===1?1:3,
    message:confirmed.length?`${confirmed.length} real finding(s) reproduced by HTTP controls. Fix the application, then retest to save regression tests.`:'Bounded AI review complete. No new issue was confirmed; this is not a security clearance.'};
}
