import fs from 'node:fs';
import path from 'node:path';
import { createWorklist, workProgress, routeMatches } from './review-worklist.mjs';
import {unverifiedResponseEffect} from './blackbox/impact.mjs';
import { need } from './util.mjs';

function reportChoices(confirmed,inspectable){
  const actions=[{id:'inspect',label:'Inspect any report entry (confirmed, source, or observation)',editsCode:false,items:inspectable}];
  if(confirmed)actions.push({id:'fix',label:'Fix confirmed issues and open a PR',editsCode:true});
  actions.push({id:'leave',label:'Leave findings open',editsCode:false});
  return actions;
}

function appendChoices(lines,actions){
  lines.push('', 'What would you like to do next?',
    ...actions.map((action,index)=>`${index+1}. ${action.label}`));
}

const rateLimitImpact='Twenty rapid invalid login attempts against a synthetic, nonexistent identity received explicit denials without a visible throttling signal. This proof does not establish whether a real account has per-account lockout or whether distributed attempts are limited.';
const confirmedLiveProof=proof=>proof?.verdict==='confirmed'&&
  typeof proof.proof==='string'&&proof.proof!=='not generated'&&
  Array.isArray(proof.confirmation)&&proof.confirmation.length>0;

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

// The MCP host hides tool results in its activity log. Return a complete,
// user-facing review in one result so the host can display it before asking
// whether to inspect evidence or edit the application.
export function findingReview(root,run,findings){
  const summary=findingSummary(findings);
  const liveRun=run?.result?.blackbox?.run||null;
  const runDir=liveRun?path.join(root,'.bypass','runs',liveRun):null;
  const reportPath=runDir?path.join(runDir,'report.md'):null;
  let live=null;
  if(runDir)try{live=JSON.parse(fs.readFileSync(path.join(runDir,'report.json'),'utf8'));}catch{}
  const liveById=new Map((live?.findings||[]).map(item=>[item.id,item]));
  const byId=new Map(findings.map(item=>[item.id,item]));
  const issues=summary.issues.map(group=>{
    const records=group.recordIds.map(id=>byId.get(id)).filter(Boolean);
    const primary=byId.get(group.id);
    const proofId=records.map(item=>item.verification?.blackboxFindingId).find(Boolean)||null;
    const proof=proofId?liveById.get(proofId):null;
    const responseEffectOnly=unverifiedResponseEffect(proof)||proof?.verdict==='observed';
    const source=records.find(item=>item.sourceEvidence?.kind==='source')?.sourceEvidence;
    const sourceLive=(live?.surface?.application?.sourceFindings||[]).find(item=>
      records.some(record=>record.id===item.id))||null;
    const hostVerification=records.find(item=>item.verification?.controls?.length)?.verification;
    const linkedRun=records.find(item=>item.verification?.blackboxFindingId===proofId)?.verification?.blackboxRun||liveRun;
    const check=proofId&&linkedRun?path.join(root,'tests','security','blackbox',`${linkedRun}-${proofId}.test.mjs`):null;
    const liveImpactProved=group.status==='confirmed'&&(
      confirmedLiveProof(proof)||
      hostVerification?.status==='failed');
    return {id:group.id,recordIds:group.recordIds,
      title:responseEffectOnly&&proof?.kind==='rate-limit-auth-gate'?
        `${primary.title} (real-account or valid-code impact unverified)`:
        responseEffectOnly?`Response effect on ${proof?.pattern||primary.resourcePath||'the tested route'} (${primary.title} remains a hypothesis)`:primary.title,
      status:responseEffectOnly?'observed response effect; exploitability unverified':
        liveImpactProved?'exploitable (live proof confirmed)':
        sourceLive?.status==='not exploitable via tested path'?'not exploitable via tested path':
        source?'source weakness; exploitability unverified':
        group.status==='confirmed'?'live exploitability unverified':group.status,
      severity:responseEffectOnly?'unrated':group.severity,
      severityBasis:responseEffectOnly&&proof?.kind==='rate-limit-auth-gate'?
        'Synthetic invalid attempts showed no visible throttling; real-account or valid-code impact was not established':
        responseEffectOnly?'A response change replayed under controls; no security impact was established':
        !liveImpactProved&&group.status==='confirmed'?
          'Saved finding status has no connected live proof in this report; severity remains provisional':
          group.severityBasis,
      path:primary.resourcePath||proof?.pattern||null,
      source:source?{file:source.file,line:source.line}:null,
      impact:responseEffectOnly&&proof?.kind==='rate-limit-auth-gate'&&proof.webProof?.mode==='login'?rateLimitImpact:
        responseEffectOnly?'Security impact not established by this proof.':
        proof?.kind==='rate-limit-auth-gate'&&proof.webProof?.mode==='login'?rateLimitImpact:
        primary.impact||'Business impact not established by this proof.',
      liveProof:proofId&&proof?{id:proofId,verdict:proof.verdict,
        evidence:proof?.evidence||[],confirmation:proof?.confirmation||[],
        controls:(proof?.evidenceTable||[]).filter(item=>item.status!=null).slice(0,12)
          .map(item=>`${item.identity||'unknown'} ${item.method||'HTTP'} ${item.status} (${item.id})`),
        file:proof?.proof||(linkedRun?path.join(root,'.bypass','runs',linkedRun,'poc',proofId,'poc.mjs'):'No proof file recorded')}:null,
      hostControls:hostVerification?.controls?.map(item=>`${item.label} HTTP ${item.status}`)||[],
      unprovenReason:proof?null:proofId?
        `Linked proof ${proofId} is missing from the saved live report; its reference alone does not establish exploitability.`:
        sourceLive?.status==='not exploitable via tested path'?
        `${sourceLive.liveReason} The source weakness remains recorded for review.`:group.status==='confirmed'?
        'No connected black-box proof is linked; see the configured HTTP probe controls and source run evidence.':
        /(?:otp|2fa|mfa)/i.test(primary.resourcePath||'')&&
        /throttl|rate.limit|attempt|guess/i.test(primary.title)?
        'No completed live OTP proof is linked. Throttling needs a valid test-account challenge; the source observation alone does not establish deployed behavior.':
        'No completed live proof is linked to this source lead.',
      regression:check&&fs.existsSync(check)?check:null,
      recommendation:primary.recommendation||'Investigate the recorded behavior and validate the expected access policy.'};
  });
  const coverage={blocked:live?.summary?.blocked??null,inconclusive:live?.summary?.inconclusive??null,
    complete:live?.coverage?.complete===true,
    limitations:[...(live?.limitations||[]).filter(item=>/identit|account|same-role|time window|probe catalog|silence is not safety/i.test(item)).slice(0,8),
      ...(liveRun?['Source and deployed revision were not attested as identical; source-only leads may describe a different build.']:[])]};
  const sourceRunPath=run?path.join(root,'.bypass','runs',`${run.id}.json`):null;
  const savedReportPath=reportPath&&fs.existsSync(reportPath)?reportPath:null;
  const withoutConnectedProof=issues.filter(item=>!item.liveProof).length;
  const securityProofs=issues.filter(item=>item.status.startsWith('exploitable')).length;
  const blockedPaths=issues.filter(item=>item.status==='not exploitable via tested path').length;
  const unverifiedWeaknesses=issues.filter(item=>item.status==='source weakness; exploitability unverified').length;
  const responseEffects=issues.filter(item=>item.status.startsWith('observed response effect')).length;
  const linkedProofIds=new Set(issues.map(item=>item.liveProof?.id).filter(Boolean));
  const otherObservations=(live?.findings||[]).filter(item=>item.verdict==='observed'&&
    !linkedProofIds.has(item.id));
  const inspectable=[...issues.map((item,index)=>({id:item.id,reportNumber:index+1,
    title:item.title,status:item.status,kind:'finding',detailTool:'bypass_finding'})),
    ...otherObservations.map(item=>({id:item.id,title:item.title||'Observed response change',
      status:'observation; security impact unverified',kind:'observation',
      reportPath:savedReportPath,proofPath:item.proof||null}))];
  const lines=[`# Security audit results`,
    `Source review: ${run?.id||'unknown'}${liveRun?` · Live audit: ${liveRun}`:' · No connected live audit'}`,
    `Full report: ${savedReportPath||'No connected live report'}`,
    `Source evidence: ${sourceRunPath||'none'}`,
    `${summary.records} review ${summary.records===1?'entry':'entries'} from ${live?.findings?.length??0} saved live evidence records; ${withoutConnectedProof} ${withoutConnectedProof===1?'entry has':'entries have'} no linked black-box proof. Related entries may share a root cause. ${securityProofs} exploitable proof ${securityProofs===1?'record':'records'}, ${responseEffects} unrated response ${responseEffects===1?'effect':'effects'}, ${otherObservations.length} other ${otherObservations.length===1?'observation':'observations'}.`,
    `Exploitability: ${securityProofs} exploitable · ${blockedPaths} not exploitable via tested path · ${unverifiedWeaknesses} source ${unverifiedWeaknesses===1?'weakness':'weaknesses'} with exploitability unverified · ${responseEffects} observed response effects.`,
    'Exploitable means a fresh live proof showed reachable security impact. Not exploitable via tested path means an executed check was denied or did not reproduce in this environment; it does not clear other paths. Blocked, untested, or inconclusive source weaknesses remain unverified.',
    `Coverage: ${coverage.complete?'recorded complete':'partial'}${coverage.blocked!=null?` · ${coverage.blocked} blocked · ${coverage.inconclusive} inconclusive`:''}.`,
    ...coverage.limitations.map(item=>`- Limit: ${item}`),
    ''];
  for(const [index,item] of issues.entries()){
    lines.push(`## ${index+1}. ${item.title}`,
      `Status: ${item.status} · Severity: ${item.severity}. ${item.severityBasis}.`,
      `Path: ${item.path||'not recorded'}${item.source?` · Source: ${item.source.file}:${item.source.line}`:''}`,
      `Impact: ${item.impact}`,
      item.liveProof?`${item.status.startsWith('observed response effect')?'Live effect replay':'Live proof'}: ${item.liveProof.id} · ${item.status.startsWith('observed response effect')?'observed':item.liveProof.verdict} · Evidence: ${item.liveProof.evidence.join(', ')||'see proof'} · Fresh ${item.status.startsWith('observed response effect')?'replay':'confirmation'}: ${item.liveProof.confirmation.join(', ')||'see report'}`:`Live proof: none. ${item.unprovenReason}`,
      ...(item.liveProof?[`Proof file: ${item.liveProof.file}`]:[]),
      ...(item.liveProof?.controls.length?[`Observed controls: ${item.liveProof.controls.join('; ')}`]:[]),
      ...(!item.liveProof&&item.hostControls.length?[`Configured HTTP controls: ${item.hostControls.join('; ')}`]:[]),
      `Regression: ${item.regression||'No exported regression found at the default path.'}`,
      `Recommendation: ${item.recommendation}`,'');
  }
  if(otherObservations.length)lines.push('## Other observed behavior · security impact unverified','',
    ...otherObservations.map(item=>`${item.id} · ${item.title||'Response changed'} · ${item.pattern||item.url||'route not recorded'}\nProof: ${item.proof||'see full report'}\nEvidence: ${(item.evidence||[]).join(', ')||'see full report'}`),'');
  lines.push(`Full report: ${savedReportPath||'No connected live report'}`);
  const nextActions=reportChoices(securityProofs,inspectable);
  appendChoices(lines,nextActions);
  const classifiedById=new Map(issues.map(item=>[item.id,item]));
  return {presentation:lines.join('\n'),summary:{...summary,confirmed:securityProofs,observedResponseEffects:responseEffects,
    otherObservations:otherObservations.length,
    issues:summary.issues.map(group=>({...group,
      status:classifiedById.get(group.id)?.status??group.status,
      severity:classifiedById.get(group.id)?.severity??group.severity,
      title:classifiedById.get(group.id)?.title??group.title}))},issues,coverage,
    paths:{liveReport:savedReportPath,sourceRun:sourceRunPath},inspectable,nextActions};
}

export function blackboxFindingReview(root,result){
  const reportPath=result?.reportPath||null;
  let report=null;
  if(reportPath)try{report=JSON.parse(fs.readFileSync(path.join(path.dirname(reportPath),'report.json'),'utf8'));}catch{}
  if(!report)return null;
  const liveRun=report.header?.run||result.run||'unknown';
  const liveFindings=report.findings||[];
  const responseEffects=liveFindings.filter(unverifiedResponseEffect).length;
  const otherObservations=liveFindings.filter(item=>item.verdict==='observed'&&
    !unverifiedResponseEffect(item)).length;
  const securityFindings=liveFindings.filter(item=>confirmedLiveProof(item)&&
    !unverifiedResponseEffect(item)).length;
  const unverifiedFindings=liveFindings.length-securityFindings-responseEffects-otherObservations;
  const lines=['# Running-app security audit results',
    `Target: ${report.header?.origin||'unknown'} · Run: ${liveRun}`,
    `Full report: ${reportPath}`,
    `${liveFindings.length} live evidence records: ${securityFindings} exploitable findings, ${unverifiedFindings} with live exploitability unverified, ${responseEffects} unrated response effects, ${otherObservations} other observations. Related routes may share a root cause.`,
    'Exploitable means a fresh live proof showed reachable security impact. An executed negative check applies only to its tested path and environment; blocked or incomplete checks leave exploitability unverified.',
    `Coverage: ${report.coverage?.complete?'recorded complete':'partial'} · ${report.summary?.blocked??0} blocked · ${report.summary?.inconclusive??0} inconclusive.`,
    ...(report.limitations||[]).filter(item=>/identit|account|same-role|time window|probe catalog|silence is not safety/i.test(item)).slice(0,8).map(item=>`- Limit: ${item}`),''];
  for(const [index,item] of liveFindings.entries()){
    const effect=unverifiedResponseEffect(item);
    const observed=effect||item.verdict==='observed';
    const title=item.title||
      (item.kind==='rate-limit-auth-gate'?'No visible throttling after synthetic invalid attempts':'Untitled live result');
    const check=path.join(root,'tests','security','blackbox',`${liveRun}-${item.id}.test.mjs`);
    lines.push(`## ${index+1}. ${effect&&item.kind==='rate-limit-auth-gate'?
      `${title} (real-account or valid-code impact unverified)`:
      effect?`Response effect on ${item.pattern||item.url||'the tested route'} (${title} remains a hypothesis)`:title}`,
      `Status: ${observed?'observed response effect; exploitability unverified':confirmedLiveProof(item)?'exploitable (live proof confirmed)':'live exploitability unverified'} · Severity: ${observed?'unrated':item.severity||'unrated'}.`,
      `Path: ${item.pattern||item.url||'not recorded'}`,
      `Impact: ${effect&&item.kind==='rate-limit-auth-gate'&&item.webProof?.mode==='login'?rateLimitImpact:
        observed?'Security impact not established by this proof.':
        item.kind==='rate-limit-auth-gate'&&item.webProof?.mode==='login'?rateLimitImpact:
        item.assessment?.impact||'Business impact not established by this proof.'}`,
      `Proof: ${item.id} · Evidence: ${(item.evidence||[]).join(', ')||'see proof'} · Fresh ${observed?'replay':'confirmation'}: ${(item.confirmation||[]).join(', ')||'see report'}`,
      `Proof file: ${item.proof||path.join(path.dirname(reportPath),'poc',item.id,'poc.mjs')}`,
      `Observed controls: ${(item.evidenceTable||[]).filter(row=>row.status!=null).slice(0,12).map(row=>`${row.identity||'unknown'} ${row.method||'HTTP'} ${row.status} (${row.id})`).join('; ')||'see full report'}`,
      `Regression: ${fs.existsSync(check)?check:'No exported regression found at the default path.'}`,
      `Recommendation: ${item.assessment?.remediation||item.remediation||'Investigate the recorded behavior and intended access policy.'}`,'');
  }
  lines.push(`Full report: ${reportPath}`);
  const inspectable=liveFindings.map((item,index)=>({id:item.id,reportNumber:index+1,
    title:item.title||'Observed response change',
    status:item.verdict==='observed'||unverifiedResponseEffect(item)?
      'observation; security impact unverified':confirmedLiveProof(item)?
        'exploitable (live proof confirmed)':'live exploitability unverified',
    kind:'live-evidence',reportPath,proofPath:item.proof||null}));
  const nextActions=reportChoices(securityFindings,inspectable);
  appendChoices(lines,nextActions);
  return {presentation:lines.join('\n'),run:report.header?.run||result.run||null,
    findings:liveFindings.length,securityFindings,unverifiedFindings,
    observedResponseEffects:responseEffects,otherObservations,reportPath,inspectable,nextActions};
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
