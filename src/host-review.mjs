import { read, change, writeEvidence } from './store.mjs';
import { inventory } from './repository.mjs';
import { sourceReader, groundCandidates } from './real-engine.mjs';
import { runChecks } from './checks.mjs';
import { reviewReadiness } from './review-readiness.mjs';
import { validateProbe } from './probe-preflight.mjs';
import { saveSourceCandidates, executeProbe } from './security-execution.mjs';
import { consolidateMemory, recallMemory, rememberSource } from './project-memory.mjs';
import { hostAI } from './execution-mode.mjs';
import { id, now, named, need, outcome, hash, abortFault, redact } from './util.mjs';

export function hostPlan(state, options={}) {
  const mode=options.mode||'combined';need(['code','live','combined'].includes(mode),'Invalid review mode.');
  need(!(options.base&&options.full),'Choose base or full, not both.');
  const ready=reviewReadiness(state,{targetName:options.target||state.activeTarget,executionMode:'muse-host'});
  return {executionMode:'muse-host',engine:'host',simulation:false,mode,target:ready.target?.name||null,ai:hostAI(),
    repository:state.project.repository,app:ready.target?{url:ready.target.url,environment:ready.target.environment}:null,
    blockers:mode==='code'?[]:ready.liveBlockers,savedChecks:state.checks.filter(c=>c.enabled).length,
    whiteBox:{status:mode==='live'?'not_run':'host_plans',description:'Muse reads eligible source and submits exact cited hypotheses.'},
    blackBox:{status:mode==='code'?'not_run':ready.liveBlockers.length?'blocked':'host_selects',description:'Muse selects approved probes; observed controls determine confirmation.'},
    dataFlow:{source:'Returned to the active Muse session on request',inference:'Muse host only; plugin API calls disabled',evidence:'Local .bypass/runs'},
    message:'Bounded authentication and account-boundary POC; source hypotheses alone are not confirmed vulnerabilities.'};
}
const receipt=(root,run)=>({runId:run.id,status:run.status,executionMode:'muse-host',pluginModelCalls:0,simulation:false,coverageComplete:false,
  evidence:`${root}/.bypass/runs/${run.id}.json`,findings:run.result?.findings||[],probes:run.result?.probes||[],
  outcomes:{confirmed:run.result?.confirmed||[],notRun:run.result?.notRun||null,executionFailures:run.result?.probes?.filter(p=>p.status==='blocked').map(p=>({resource:p.resource,reason:p.reason}))||[]},
  nextAction:run.status==='completed'?{tool:run.result?.findings?.length?'bypass_finding':'bypass_run',arguments:{id:run.result?.findings?.[0]||run.id}}:{tool:'bypass_review_step',arguments:{id:run.id,action:'status'}},
  guidance:'Muse must choose and execute the next step. Do not wait for an internal AI worker. Read source, submit cited hypotheses, select approved probes, then finish. Use host coding tools to propose/apply fixes within user permissions and bypass_retest to verify.'});
export async function beginHostReview(root,options={},context={}) {
  const initial=read(root),plan=hostPlan(initial,options);need(!plan.blockers.length,plan.blockers.join(' '),3);
  const run={id:id('run'),kind:'scan',options,status:'awaiting_host',stage:'planning',createdAt:now(),startedAt:now(),steps:[],simulation:false,executionMode:'muse-host',modelCalls:0,
    host:{mode:plan.mode,target:plan.target,reads:[],sourceSubmitted:false,visited:[],operations:0},result:{engine:'host',simulation:false,modelCalls:0,findings:[],probes:[],coverageComplete:false}};
  await change(root,s=>{s.runs.push(run);});
  try {
    context.onProgress?.({message:'Replaying saved checks and preparing source for Muse'});
    const regression=plan.mode==='code'?{results:[],exitCode:0}:await runChecks(root,{all:true,target:plan.target,signal:context.signal,runId:run.id});
    if(plan.mode!=='code')for(const probe of initial.targets.find(t=>t.name===plan.target).probes){const result=await validateProbe(root,probe.name,{target:plan.target,signal:context.signal});need(result.status==='ready',result.reason,3);}
    const inv=plan.mode==='live'?{files:[],fingerprint:null,routes:[],sourceFileCount:0}:await inventory(root,options.base);
    if(context.signal?.aborted)throw abortFault(context.signal);
    const current=read(root),target=current.targets.find(t=>t.name===plan.target);
    const passed=regression.results.filter(r=>r.status==='passed').map(r=>r.id);
    const bindings=plan.mode==='code'?[]:(target?.probes||[]).filter(p=>!current.checks.some(c=>passed.includes(c.id)&&JSON.stringify(c.bindings[plan.target])===JSON.stringify(p.binding))).map(p=>({...p.binding,name:p.name}));
    await consolidateMemory(root);const memory=await recallMemory(root,{target:plan.target,inv,mode:plan.mode,forAgent:true,limit:8,maxBytes:8000});
    const saved=await change(root,s=>{const r=named(s.runs,run.id,'Run');Object.assign(r.host,{inventory:inv,bindings});r.result.regression=regression.results;r.result.exactPassingChecksExcluded=passed;r.steps.push({at:now(),stage:'planning',message:'Ready for Muse to choose source reads and approved probes.'});return r;});
    writeEvidence(root,saved);
    return outcome({...receipt(root,saved),plan,inventory:{files:inv.files.slice(0,400),totalFiles:inv.files.length,routes:inv.routes?.slice(0,80),routeLocations:inv.routeLocations?.slice(0,160)},resources:bindings.map((b,index)=>({index,name:b.name,resourcePath:b.resourcePath,resourceId:b.resourceId})),memory,
      nextAction:{tool:'bypass_review_step',arguments:{id:run.id,action:plan.mode==='live'?'probe':'read'},message:'Choose paths from inventory, or a resource index from resources.'}});
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
    if(args.action==='status')return outcome({...receipt(root,run),sourceReads:run.host.reads,sourceSubmitted:run.host.sourceSubmitted,resources:run.host.bindings?.map((b,index)=>({index,name:b.name,resourcePath:b.resourcePath,tested:run.host.visited.includes(index)})),lastError:run.host.lastError});
    need(run.status==='awaiting_host','Review is finished. Start a new review; saved findings can still be retested.',3);
    if(args.action==='cancel'){const saved=await change(root,s=>{const r=named(s.runs,args.id,'Run');r.status='cancelled';r.finishedAt=now();r.exitCode=130;return r;});writeEvidence(root,saved);return outcome(receipt(root,saved));}
    need(Date.now()-Date.parse(run.createdAt)<86400000,'Review expired after 24 hours. Start a new review; evidence is retained.',3);
    need(args.action==='finish'||run.host.operations<32,'Review reached 32 operations; finish or start a smaller review.',3);
    if(signal?.aborted)throw abortFault(signal);
    const {inventory:inv,mode,target,bindings}=run.host;
    let result={};
    const persist=async()=>{await change(root,s=>{const r=named(s.runs,args.id,'Run');r.result=run.result;});};
    if(args.action==='read'||args.action==='source'){
      need(mode!=='live','This is a live-only review.',3);
      const current=await inventory(root,run.options.base);need(current.fingerprint===inv.fingerprint,'Source changed during review. Start a new review for fresh citations; use retest for existing findings.',3);
      const reader=sourceReader(root,inv);for(const batch of run.host.reads)reader.read(batch);
      if(args.action==='read'){const files=reader.read(args.paths);run.host.reads.push(args.paths);result={files};}
      else {
        need(!run.host.sourceSubmitted,'Source hypotheses were already recorded for this review.',3);
        const candidates=groundCandidates(args.candidates||[],reader,inv).filter(c=>!read(root).checks.some(check=>run.result.exactPassingChecksExcluded.includes(check.id)&&check.bindings[target]?.resourcePath===c.resourcePath));
        await saveSourceCandidates(root,{candidates,bindings,targetName:target,sourceFingerprint:inv.fingerprint,runId:args.id,engine:'host',candidateIds:run.result.findings});
        result={hypotheses:candidates.length,knowledge:await rememberSource(root,args.knowledge||[],reader,inv,args.id)};run.host.sourceSubmitted=true;
      }
    } else if(args.action==='probe'){
      need(mode!=='code'&&Number.isInteger(args.index)&&bindings[args.index],'Choose a configured resource index from this live review.',3);
      need(!run.host.visited.includes(args.index),'This resource was already tested. Use verify or retest for follow-up.',3);
      const rawBinding=bindings[args.index],binding=Object.fromEntries(Object.entries(rawBinding).filter(([k])=>k!=='name'));
      const current=read(root).targets.find(t=>t.name===target)?.probes?.find(p=>p.name===rawBinding.name);
      need(current&&hash(current.binding)===hash(binding),'Probe configuration changed. Start a new review.',3);
      onProgress?.({message:`Testing ${rawBinding.name}: owner, other account, anonymous controls`});
      result={observation:await executeProbe(root,{binding,rawBinding,bindingIndex:args.index,targetName:target,sourceFingerprint:inv.fingerprint,runId:args.id,engine:'host',candidateIds:run.result.findings,probes:run.result.probes,signal,persist})};
      if(signal?.aborted)throw abortFault(signal);
      run.host.visited.push(args.index);
    } else if(args.action==='finish'){
      run.status='completed';run.finishedAt=now();run.result.confirmed=run.result.findings.filter(id=>read(root).findings.find(f=>f.id===id)?.status==='confirmed');
      run.result.notRun={source:mode==='live'||!run.host.sourceSubmitted,resources:bindings.filter((_,i)=>!run.host.visited.includes(i)).map(b=>b.name)};
      run.result.message='Host-directed bounded review finished. See confirmed findings, suspected source issues, blocked executions and not-run coverage. No security clearance.';
      run.exitCode=run.result.confirmed.length||run.result.regression.some(r=>r.status==='failed')?1:3;run.result.exitCode=run.exitCode;
    } else need(false,'Unsupported host review action.',3);
    run.host.operations++;delete run.host.lastError;run.steps.push({at:now(),stage:args.action,message:`Muse-directed ${args.action} complete`});
    await change(root,s=>{Object.assign(named(s.runs,args.id,'Run'),run);});writeEvidence(root,run);await consolidateMemory(root);
    return outcome({...receipt(root,run),...result});
  } catch(error) {
    await change(root,s=>{const r=s.runs.find(r=>r.id===args.id);if(r?.executionMode==='muse-host'){r.host.lastError={message:redact(error.message),at:now(),retryable:!signal?.aborted};if(signal?.aborted){r.status='cancelled';r.finishedAt=now();r.exitCode=130;}writeEvidence(root,r);}}).catch(()=>{});
    throw error;
  } finally {busy.delete(key);controllers.delete(key);}
}
