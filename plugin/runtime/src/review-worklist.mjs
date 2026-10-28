import { hash, need, now } from './util.mjs';
import { pathAllowed } from './network.mjs';

export const assessmentPolicy={intent:'assessment',applicationEdits:'not_authorized',allowedOutputs:['findings','fix recommendations','security evidence','regression tests'],
  instruction:'Review/test/continue/keep working means continue assessment. Do not edit application source, configuration or dependencies to remediate findings. Remediation requires a separate explicit request. Report discoveries progressively and continue all actionable planned work.'};
export const coverageReasons=['missing_identity','missing_resource','permission_required','external_side_effect','unsupported','not_applicable'];
const routeId=(method,path)=>'route_'+hash({method,path}).slice(0,12);
export function createWorklist(inv,target,mode){
  if(mode==='code')return [];
  const seen=new Set();
  return (inv.routeLocations||[]).filter(r=>!seen.has(routeId(r.method,r.path))&&seen.add(routeId(r.method,r.path))).map(r=>{
    const inScope=target?.authorization&&pathAllowed(r.path,target.authorization.paths)&&(!r.method||target.authorization.methods.includes(r.method));
    const collection=r.path.replace(/\/(?:[:][\w]+|\{[\w]+\})$/,'');
    const setupCandidates=(inv.routeLocations||[]).filter(s=>collection!==r.path&&s.path===collection&&['GET','POST'].includes(s.method)&&target?.authorization&&pathAllowed(s.path,target.authorization.paths)&&target.authorization.methods.includes(s.method)).map(s=>({method:s.method,path:s.path,file:s.file,line:s.line}));
    return {id:routeId(r.method,r.path),kind:'route',path:r.path,method:r.method||'UNKNOWN',file:r.file,line:r.line,setupCandidates,status:inScope?'pending':'out_of_scope',...(inScope?{}:{reason:'Outside the recorded methods or paths; no testing permission inferred.'})};
  });
}
export function observeSource(run,files){
  run.host.sourceCoverage??={};
  for(const f of files){
    const ranges=[...(run.host.sourceCoverage[f.file]?.ranges||[]),[f.startLine,f.endLine]].sort((a,b)=>a[0]-b[0]),merged=[];
    for(const range of ranges){const previous=merged.at(-1);if(previous&&range[0]<=previous[1]+1)previous[1]=Math.max(previous[1],range[1]);else merged.push([...range]);}
    run.host.sourceCoverage[f.file]={totalLines:f.totalLines,ranges:merged};
  }
}
export function sourceProgress(run){
  const inv=run.host.inventory||{},remaining=[];let filesRead=0,completeFiles=0,linesRead=0;
  if(run.host.mode==='live')return {filesRead:0,completeFiles:0,remaining,linesRead:0,eligibleFiles:0};
  for(const file of inv.files||[]){
    const observation=run.host.sourceCoverage?.[file],total=observation?.totalLines||inv.fileLineCounts?.[file],ranges=observation?.ranges||[];
    if(ranges.length)filesRead++;
    linesRead+=ranges.reduce((n,[start,end])=>n+end-start+1,0);
    let startLine=1;for(const [start,end] of ranges){if(start>startLine)break;startLine=Math.max(startLine,end+1);}
    if(total&&startLine>total)completeFiles++;else remaining.push({path:file,startLine,endLine:Math.min(startLine+399,total||startLine+399)});
  }
  return {filesRead,completeFiles,remaining,linesRead,eligibleFiles:inv.files?.length||0,meaning:'Delivered source ranges, not proof that every security property was analyzed.'};
}
export function routeMatches(pattern,actual){
  if(typeof pattern!=='string'||typeof actual!=='string')return false;
  const parts=pattern.split('/'),values=actual.split('/');
  return parts.length===values.length&&parts.every((part,i)=>part===values[i]||/^:[A-Za-z_][\w]*$/.test(part)&&!!values[i]||/^\{[A-Za-z_]\w*\}$/.test(part)&&!!values[i]);
}
export function reconcileWorklist(run,state){
  const items=run.host.worklist||[],bindings=run.host.bindings||[];
  // Only runtime observations can mark a route checked. A host disposition cannot.
  const observations=(run.result.probes||[]).map(p=>({path:bindings[p.bindingIndex]?.resourcePath,method:'GET',status:p.status,reason:p.reason,evidence:p.resource}));
  for(const id of run.result.exactPassingChecksExcluded||[]){const c=state.checks.find(c=>c.id===id),binding=c?.bindings?.[run.host.target];if(binding)observations.push({path:binding.resourcePath,method:'GET',status:'passed',evidence:id});}
  for(const row of items){
    if(row.status==='out_of_scope')continue;
    const proof=observations.find(p=>p.path&&['GET','UNKNOWN'].includes(row.method)&&routeMatches(row.path,p.path)&&['passed','failed','observed'].includes(p.status));
    if(proof){row.status='checked';row.evidence=proof.evidence;row.result=proof.status;delete row.reasonCode;delete row.reason;}
  }
  return items;
}
export function applyDispositions(run,updates,reader,state){
  need(Array.isArray(updates)&&updates.length>0&&updates.length<=100,'Provide 1–100 route dispositions.');
  const applied=[];
  for(const item of updates){
    const row=run.host.worklist?.find(r=>r.id===item.id);need(row,'Use a route ID from the review worklist.');
    need(!['checked','out_of_scope'].includes(row.status),'Runtime evidence and scope dispositions cannot be overwritten.');
    need(coverageReasons.includes(item.reasonCode),'Choose a supported blocker or not_applicable reason.');
    need(typeof item.reason==='string'&&item.reason.trim().length>=20&&item.reason.length<=1500,'Explain the specific blocker, attempted resolution and what would unblock it.');
    need(reader?.readFiles.get(row.file)?.has(row.line),'Read the cited route declaration before classifying it.');
    if(item.reasonCode==='missing_resource'&&row.setupCandidates?.length){
      const attempts=(item.evidenceRunIds||[]).map(id=>state?.runs.find(r=>r.id===id));
      need(attempts.length&&attempts.every(r=>['request','resource-discovery'].includes(r?.kind)&&r.options.target===run.host.target&&Date.parse(r.startedAt)>=Date.parse(run.startedAt)&&r.result?.requests>0&&row.setupCandidates.some(s=>s.path===r.options.path&&s.method===r.options.method)),'A missing ID is preparation work. Inspect the suggested collection/create routes and attempt authorized discovery or synthetic setup; cite its request run IDs. Use a specific side-effect or permission blocker if setup itself cannot run.',3);
      need(!attempts.some(r=>r.result.httpStatus>=200&&r.result.httpStatus<300&&r.result.resourceId),'Setup returned a resource ID. Configure its access probe and continue instead of declaring it missing.',3);
      need(!attempts.some(r=>r.result.probes?.length),'Discovery configured owned-resource probes. Execute them before declaring resources missing.',3);
      need(!row.setupCandidates.some(s=>s.method==='POST')||attempts.some(r=>r.options.method==='POST'),'An empty collection does not block authorized synthetic setup. Inspect the POST handler and create a minimal isolated record, or cite the specific side-effect/permission constraint.',3);
    }
    applied.push({...row,status:item.reasonCode==='not_applicable'?'not_applicable':'blocked',reasonCode:item.reasonCode,reason:item.reason.trim(),dispositionAt:now(),evidence:{file:row.file,line:row.line,requestRuns:item.evidenceRunIds||[],kind:'host assessment; not HTTP proof'}});
  }
  for(const item of applied)Object.assign(run.host.worklist.find(r=>r.id===item.id),item);
  return applied;
}
export function workProgress(run,state){
  const routes=reconcileWorklist(run,state),bindings=run.host.bindings||[],visited=run.host.visited||[];
  const pendingProbes=bindings.map((b,i)=>({id:'probe_'+i,index:i,name:b.name,path:b.resourcePath})).filter(b=>!visited.includes(b.index));
  const pendingRoutes=routes.filter(r=>r.status==='pending'),blockedRoutes=routes.filter(r=>r.status==='blocked');
  const blockedProbes=(run.result.probes||[]).filter(p=>['blocked','cancelled'].includes(p.status));
  const source=sourceProgress(run),sourcePending=run.host.mode!=='live'&&(!run.host.sourceSubmitted||source.remaining.length>0);
  const pending=(sourcePending?1:0)+pendingProbes.length+pendingRoutes.length;
  const blocked=blockedRoutes.length+blockedProbes.length+(run.host.limitReason?1:0);
  const samples=(run.result.probes||[]).filter(p=>Number.isFinite(p.elapsedMs)).map(p=>p.elapsedMs/1000);
  const average=samples.length?samples.reduce((a,b)=>a+b,0)/samples.length:null;
  const eta=average!==null&&samples.length>=2?{minSeconds:Math.ceil(average*pendingProbes.length*.75),maxSeconds:Math.ceil(average*pendingProbes.length*2),basis:`${samples.length} observed probe durations`,covers:'Configured HTTP probes only; source analysis, setup and new discoveries are excluded.'}:null;
  const total=routes.length+bindings.length+(run.host.mode==='live'?0:1);
  const finished=['completed','incomplete'].includes(run.status);
  return {total,pending,blocked,checked:routes.filter(r=>r.status==='checked').length+(run.result.probes||[]).filter(p=>['passed','failed','observed'].includes(p.status)).length+(run.host.sourceSubmitted?1:0),notApplicable:routes.filter(r=>r.status==='not_applicable').length,outOfScope:routes.filter(r=>r.status==='out_of_scope').length,
    source:{...source,submitted:!!run.host.sourceSubmitted,remaining:source.remaining.slice(0,8),remainingFiles:source.remaining.length},
    configuredProbes:{total:bindings.length,executed:visited.length,pending:pendingProbes.length},routes:{total:routes.length,pending:pendingRoutes.length,checked:routes.filter(r=>r.status==='checked').length,blocked:blockedRoutes.length},
    remaining:[...(sourcePending?[{id:'source',description:'Read eligible source and submit cited assessment conclusions.'}]:[]),...pendingProbes,...pendingRoutes].slice(0,8),blockers:[...blockedRoutes,...blockedProbes,...(run.host.limitReason?[{reason:run.host.limitReason,kind:'runtime_limit'}]:[])].slice(0,8),eta,
    overallETA:pendingRoutes.length||sourcePending?'Unknown while source investigation and resource setup remain.':eta?'See configured-probe estimate.':'Estimating after observed probe timings.',
    canFinish:!pending,scopeExecuted:!pending&&!blocked,phase:finished?(blocked?'finished_with_blockers':'finished'):sourcePending?'source review':pendingProbes.length?'HTTP controls':pendingRoutes.length?'resolve remaining routes':'report',
    next:pendingProbes.length?{action:'complete',message:'Execute all remaining configured controls; a finding is not a stop condition.'}:run.host.limitReason?{action:'finish',message:'A runtime budget blocks further source work. Retain explicit incomplete coverage; report the limit.'}:sourcePending?(source.remaining.length?{action:'read',arguments:{paths:source.remaining.slice(0,8)},message:'Continue the unread source ranges. Reading one file is not completing source review.'}:{action:'source',message:'Submit source conclusions for the ranges reviewed.'}):pendingRoutes.length?{action:'coverage',message:'Inspect remaining routes and their setupCandidates; derive safe payloads/selectors, use authorized scoped requests to obtain synthetic IDs, configure probes and continue. Record specific blockers only after attempting available preparation.'}:{action:'finish',message:'Report findings, recommendations, saved regressions and any blockers. Do not start application fixes.'}};
}
