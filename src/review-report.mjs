import { createWorklist, workProgress, routeMatches } from './review-worklist.mjs';
import { need } from './util.mjs';

// Keep all historical records addressable. Group only a source hypothesis and
// matching HTTP proof in the same app/category; never promote the whole list.
export function findingSummary(findings){
  const source=findings.filter(f=>f.sourceEvidence?.kind==='source');
  const groups=new Map();
  for(const f of findings){
    const matches=f.binding?source.filter(s=>s.target===f.target&&s.category===f.category&&routeMatches(s.resourcePath,f.binding.resourcePath)):[];
    const key=matches.length===1?matches[0].id:f.id;
    if(!groups.has(key))groups.set(key,[]);groups.get(key).push(f);
  }
  const issues=[...groups.values()].map(records=>{
    const primary=records.find(f=>f.status==='confirmed')||records.find(f=>f.status==='fixed_verified')||records[0];
    return {id:primary.id,title:primary.title,status:primary.status,category:primary.category,severity:primary.severity,severityBasis:primary.status==='confirmed'?'confirmed behavior; impact still requires context':'provisional source assessment',recordIds:records.map(f=>f.id)};
  });
  return {records:findings.length,distinctIssues:issues.length,confirmed:issues.filter(f=>f.status==='confirmed').length,duplicateRecords:findings.length-issues.length,issues};
}

export function assessmentCoverage(state,currentInventory,{run:runId,target}={}){
  const original=runId?state.runs.find(r=>r.id===runId):state.runs.findLast(r=>r.kind==='scan'&&(!target||(r.host?.target||r.options?.target)===target));
  need(!runId||original,`Review '${runId}' was not found.`);
  const findings=state.findings.filter(f=>(!target||f.target===target)&&(!original||(original.result?.findings||[]).includes(f.id)||f.lastRunId===original.id));
  const summary=findingSummary(findings);
  if(!original?.host)return {runId:original?.id||null,work:null,summary,complete:false,reason:original?'This run has no durable host assessment worklist. Use its explicit evidence; coverage is not established.':'No assessment run recorded.',nextAction:{tool:'bypass_scan',arguments:{mode:state.settings.reviewMode||'combined',...(target?{target}:{})}}};
  const run=structuredClone(original),app=state.targets.find(t=>t.name===run.host.target),legacy=!run.host.worklist;
  run.host.worklist??=createWorklist(run.host.inventory||{},app,run.host.mode);
  const work=workProgress(run,state),sourceChanged=run.host.mode!=='live'&&run.host.inventory.fingerprint!==currentInventory.fingerprint;
  const awaiting=run.status==='awaiting_host',needsContinuation=work.pending>0;
  return {runId:run.id,recordedStatus:run.status,legacyWorklist:legacy,sourceChanged,sourceReadEvidence:run.host.sourceCoverage?'recorded delivered ranges':'legacy run; complete delivered ranges were not recorded',
    scope:run.host.scope||null,scopeProvenance:run.host.scope?'recorded at review start':'legacy run: scope snapshot unavailable; reconstructed routes use current permission and do not attest historical coverage',
    work,worklist:run.host.worklist,summary,complete:false,completionClaimSupported:!legacy&&!sourceChanged&&work.canFinish&&work.scopeExecuted,needsContinuation,
    message:needsContinuation?'Assessment work remains. A completed run or a short findings list does not mean the agreed scope was executed. Continue available work without asking whether to go deeper.':'Read the blockers and individual behavior evidence. No result is an exhaustive security clearance.',
    nextAction:awaiting&&!sourceChanged?{tool:'bypass_review_step',arguments:{id:run.id,action:work.next.action,...work.next.arguments},message:work.next.message}:{tool:'bypass_scan',arguments:{mode:run.host.mode,...(run.host.target?{target:run.host.target}:{})},message:sourceChanged?'Source changed. Start a fresh assessment using saved app setup and permissions; keep prior evidence.':'Start a continuation assessment using saved setup; exact passing checks are reused. No new DNS or account setup is implied.'}};
}
