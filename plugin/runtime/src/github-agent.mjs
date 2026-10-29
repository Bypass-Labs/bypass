import { githubPolicy, GITHUB_POLICY_PATH, assessmentConclusion } from './github-policy.mjs';
import { restoreGitHubState } from './github-api.mjs';
import { reviewSource } from './github-review.mjs';
import { verifyLive } from './github-live.mjs';
import { now, redact } from './util.mjs';

// Model and source text are rendered as plain text, never Markdown links/mentions.
export const plain=value=>String(value??'').replace(/[\x00-\x1f\x7f]/g,' ').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/@/g,'&#64;').replace(/([\\`*_\[\]{}()#!|])/g,'\\$1');
export function githubSummary(report){
  const lines=[`## Bypass · ${plain(report.kind)} · ${report.sha?.slice(0,7)||'setup'}`,``,
    `Execution: **${report.execution}** · Merge policy: **${report.blocking?'blocking':'report only'}** · Model calls: **${report.modelCalls||0}** · Duration: **${Math.ceil((report.durationMs||0)/1000)}s**`,
    '',`${report.findings.length} source concerns · ${report.checks.filter(c=>c.status==='failed').length} observed failures · ${report.checks.filter(c=>c.status==='passed').length} passed checks · ${report.blockers.length} blockers.`,
    '', 'A completed assessment covers only the source and saved checks listed here. Source concerns are not runtime proof. Report-only success does not mean no security issues.'];
  if(report.source)lines.push('',`Source: ${report.source.completedFiles.length}/${report.source.files.length} selected files completed; ${report.source.excluded.length} changed files excluded. ${plain(report.source.scope)}`);
  if(report.kind==='review')lines.push('Live verification: deferred to a successful registered deployment; production credentials are not used by PR source review.');
  if(report.kind==='smoke')lines.push('This check attaches to the default-branch policy revision. The live rows identify the actual deployed commits; they may be older than the default branch.');
  if(report.restoredFrom)lines.push(`History: restored from Actions run ${report.restoredFrom}. Historical results are not current proof.`);
  else lines.push('History: no retained baseline artifact found; this run cannot claim that an earlier failure was fixed.');
  if(report.findings.length){
    lines.push('','### Source concerns');
    for(const f of report.findings.slice(0,30))lines.push(`- **${plain(f.severity)}** · ${plain(f.title)} · ${plain(f.sourceEvidence.file)}:${f.sourceEvidence.line} · ${plain(f.change)}`,`  ${plain(f.hypothesis)}`,`  Recommendation: ${plain(f.recommendation)}`);
    if(report.findings.length>30)lines.push('Additional concerns are in the report artifact.');
  }
  if(report.checks.length){
    lines.push('','### Observed checks');
    for(const c of report.checks)lines.push(`- ${plain(c.target)}/${plain(c.id)}: **${plain(c.status)}** · ${plain(c.transition||'')} · ${plain(c.reason)}${c.sha?' · release '+c.sha.slice(0,7):''}`);
  }
  if(report.blockers.length){lines.push('','### Incomplete work');for(const b of report.blockers)lines.push('- '+plain(b));}
  lines.push('','No application source was executed or modified. HTTP tests use only the approved saved contracts. No automatic fixes, commits, merges or approvals.');
  return redact(lines.join('\n')).slice(0,60000);
}

export async function runGitHubAgent(api,{eventName,event,operation='auto',prNumber,runId,signal,progress=()=>{},dependencies={}}){
  const started=Date.now(),report={version:1,kind:'setup',execution:'incomplete',findings:[],checks:[],blockers:[],modelCalls:0,startedAt:now()};
  let context,policy,previous,state,checkId;
  try{
    context=await api.resolve(eventName,event,operation,prNumber);Object.assign(report,{kind:context.kind,sha:context.sha,policySha:context.policySha,repository:context.repository,pr:context.pr});
    policy=githubPolicy(JSON.parse(await api.file(GITHUB_POLICY_PATH,context.policySha)));report.blocking=policy.review.blocking;
    const restored=await (dependencies.restore||restoreGitHubState)(api,context,runId);previous=restored.state;report.restoredFrom=restored.restoredFrom;
    const created=await api.request(`${api.base}/check-runs`,{method:'POST',body:{name:checkName(context.kind),head_sha:context.sha,status:'in_progress',external_id:`bypass-${runId}`,output:{title:'Review started',summary:'Reading trusted policy and security history. Findings do not stop the remaining work.'}}});checkId=created.id;
    if(['review','baseline'].includes(context.kind)){
      try{
        const source=await (dependencies.review||reviewSource)(api,context,policy,previous,{signal,progress});
        report.source=source;report.findings=source.findings;report.modelCalls+=source.modelCalls;report.blockers.push(...source.blockers);
      }catch(error){report.blockers.push(`Source review: ${error.message}`);}
    }
    if(['verify','smoke'].includes(context.kind)||(context.kind==='baseline'&&Object.keys(policy.targets).length)){
      try{
        const live=await (dependencies.live||verifyLive)(api,context,policy,previous,{signal,progress});
        report.checks=live.checks;report.blockers.push(...live.blockers);report.modelCalls+=live.modelCalls;previous={...previous,targets:live.targets};
      }catch(error){report.blockers.push(`Live verification: ${error.message}`);}
    }
    report.execution=signal?.aborted?'cancelled':report.blockers.length?'incomplete':'complete';
    if(context.pr&&(await api.currentPR(context.pr)).head.sha!==context.sha){report.execution='cancelled';report.blockers.push('Superseded by a newer PR head. Its summary was not overwritten.');}
    if(context.kind!=='review'){
      const findings=new Map((previous.findings||[]).filter(f=>typeof f.id==='string').map(f=>[f.id,f]));
      for(const f of report.findings)findings.set(f.id,f);
      state=redact({version:1,repositoryId:context.repositoryId,runId:Number(runId),kind:context.kind,policySha:context.policySha,findings:[...findings.values()].slice(-500),targets:previous.targets,updatedAt:now()});
      while(Buffer.byteLength(JSON.stringify(state))>1800000){
        if(state.findings.length)state.findings.shift();
        else{const first=Object.keys(state.targets)[0];if(!first)break;delete state.targets[first];}
        state.retentionTrimmed=true;
      }
    }
  }catch(error){report.blockers.push(error.message);report.execution=signal?.aborted?'cancelled':'incomplete';}
  report.durationMs=Date.now()-started;report.finishedAt=now();report.conclusion=policy?assessmentConclusion(report,policy):'failure';
  let summary=githubSummary(report);
  if(checkId){
    try{
      // Publish the sticky comment before finalizing so publishing errors cannot leave a green check.
      if(context.pr&&report.execution!=='cancelled')await publishComment(api,context,summary);
      await api.request(`${api.base}/check-runs/${checkId}`,{method:'PATCH',body:{status:'completed',conclusion:report.conclusion,output:{title:report.execution==='complete'?`Completed · ${report.findings.length} source concerns · ${report.checks.filter(c=>c.status==='failed').length} HTTP failures`:'Incomplete — see blocked work',summary,annotations:report.findings.slice(0,50).map(f=>({path:f.sourceEvidence.file,start_line:f.sourceEvidence.line,end_line:f.sourceEvidence.line,annotation_level:'warning',title:String(f.title).slice(0,255),message:redact(`${f.hypothesis}\nRecommendation: ${f.recommendation}`).slice(0,4000)}))}}});
    }catch(error){
      report.blockers.push(`Publish: ${error.message}`);report.execution='incomplete';report.conclusion='failure';summary=githubSummary(report);
      try{await api.request(`${api.base}/check-runs/${checkId}`,{method:'PATCH',body:{status:'completed',conclusion:'failure',output:{title:'Incomplete — publication failed',summary}}});}catch{/* The failed Actions job remains visible even when Checks API is unavailable. */}
    }
  }
  return {report:redact(report),state,summary,exitCode:report.conclusion==='success'?0:report.execution==='complete'?1:3};
}
export function checkName(kind){return kind==='review'?'Bypass / PR review':kind==='baseline'?'Bypass / baseline':kind==='verify'?'Bypass / deployment':'Bypass / smoke';}
async function publishComment(api,context,summary){
  if((await api.currentPR(context.pr)).head.sha!==context.sha)return;
  const marker='<!-- bypass-security-agent:v1 -->',body=marker+'\n'+summary;
  const comments=await api.pages(`/issues/${context.pr}/comments`,{cap:2000});
  const prior=comments.find(c=>c.user?.login==='github-actions[bot]'&&c.user?.type==='Bot'&&c.body?.startsWith(marker));
  // Recheck after pagination; events may arrive while a review is running.
  if((await api.currentPR(context.pr)).head.sha!==context.sha)return;
  await api.request(prior?`${api.base}/issues/comments/${prior.id}`:`${api.base}/issues/${context.pr}/comments`,{method:prior?'PATCH':'POST',body:{body}});
}
