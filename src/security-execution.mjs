import { routeMatches } from './review-worklist.mjs';
import { read, change, event } from './store.mjs';
import { specFor, saveCheck } from './checks.mjs';
import { replay } from './portable-check.mjs';
import { rememberObservation } from './project-memory.mjs';
import { id, hash, now, redact } from './util.mjs';
import { replayEnvironment } from './credentials.mjs';
// Both the host plugin and API agents use these exact finding/proof operations.
export async function saveSourceCandidates(root,{candidates,bindings,targetName,sourceFingerprint,runId,engine='docker',candidateIds=[]}) {
  const initial=read(root),target=initial.targets.find(t=>t.name===targetName);
  for(const candidate of candidates){
    const binding=bindings.find(b=>b.resourcePath===candidate.resourcePath)||bindings.find(b=>routeMatches(candidate.resourcePath,b.resourcePath));
    const fingerprint=hash({kind:'source',file:candidate.sourceEvidence.file,line:candidate.sourceEvidence.line,category:candidate.category,target:targetName,resourcePath:candidate.resourcePath});
    const saved=await change(root,s=>{
      let finding=s.findings.find(f=>f.fingerprint===fingerprint);
      if(!finding){finding={id:id('finding'),fingerprint,createdAt:now(),history:[]};s.findings.push(finding);}
      const priorProof=finding.verification&&finding.binding;
      Object.assign(finding,redact({...candidate,status:priorProof?finding.status:'unproven',simulation:false,engine:engine,fixture:!!(initial.demo||initial.poc),target:targetName,targetOrigin:target?.url||null,severity:'high',binding:priorProof?finding.binding:binding?Object.fromEntries(Object.entries(binding).filter(([key])=>key!=='name')):null,sourceFingerprint:sourceFingerprint,lastRunId:runId}));return finding;
    });candidateIds.push(saved.id);
  }

  return candidateIds;
}
export async function executeProbe(root,{binding,rawBinding,bindingIndex,targetName,sourceFingerprint,runId,engine='docker',candidateIds,probes,signal,persist=async()=>{},report=async()=>{}}) {
      const state=read(root); // honor revocation and changes immediately before each probe
      let result;
      try{const spec=specFor(state,{target:targetName,engine:engine,fixture:!!(state.demo||state.poc),bindings:{[targetName]:binding}},targetName);
        result=await replay(spec,{signal,env:await replayEnvironment(state,spec,{signal})});
      }catch(error){result={status:signal?.aborted?'cancelled':'blocked',reason:redact(error.message),controls:[],requests:0,modelCalls:0};}
      const observed={resource:rawBinding.name,bindingIndex:bindingIndex,...result};probes.push(observed);await rememberObservation(root,{target:state.targets.find(t=>t.name===targetName),binding,result,runId,sourceFingerprint:sourceFingerprint});await persist();
      await report('black-box',`${rawBinding.name}: ${result.status} · ${result.controls.map(c=>`${c.label} HTTP ${c.status}`).join(' / ')}`);
      if(result.status==='failed'){
        const saved=await change(root,s=>{
          let finding=s.findings.find(f=>candidateIds.includes(f.id)&&f.binding?.resourcePath===binding.resourcePath);
          finding??=s.findings.find(f=>candidateIds.includes(f.id)&&!f.binding&&f.target===targetName&&f.sourceEvidence?.kind==='source'&&routeMatches(f.resourcePath,binding.resourcePath)&&f.category===(binding.kind==='unverified-account-access'?'email-verification':result.reason.startsWith('Unauthenticated')?'missing-authentication':'cross-account-access'));
          const fingerprint=hash({kind:'http-account-boundary',target:targetName,binding});
          finding??=s.findings.find(f=>f.fingerprint===fingerprint);
          if(!finding){finding={id:id('finding'),fingerprint,title:`${binding.kind==='unverified-account-access'?'Unverified email account access':'Unauthorized access'} to ${binding.resourcePath}`,category:binding.kind==='unverified-account-access'?'email-verification':'cross-account-access',severity:'high',hypothesis:result.reason,recommendation:'Authenticate the caller and enforce resource ownership; preserve authorized access.',sourceEvidence:{kind:'http',message:'Discovered through observed HTTP controls; no source attribution.'},createdAt:now(),history:[]};s.findings.push(finding);}
          Object.assign(finding,{category:binding.kind==='unverified-account-access'?'email-verification':result.reason.startsWith('Unauthenticated')?'missing-authentication':'cross-account-access',status:'confirmed',simulation:false,engine:engine,fixture:!!(state.demo||state.poc),target:targetName,binding,sourceFingerprint:sourceFingerprint,lastRunId:runId,verification:{...result,origin:state.targets.find(t=>t.name===targetName).url,at:now(),simulation:false}});finding.history.push({action:'verify',...finding.verification});event(s,'confirmed',finding.title,{findingId:finding.id});return finding;
        });if(!candidateIds.includes(saved.id))candidateIds.push(saved.id);
        if(read(root).settings.autoSave)await saveCheck(root,saved.id);
      }
      if(result.status!=='failed')await change(root,s=>{
        for(const finding of s.findings.filter(f=>candidateIds.includes(f.id)&&(f.binding?.resourcePath===binding.resourcePath||!f.binding&&f.target===targetName&&f.sourceEvidence?.kind==='source'&&routeMatches(f.resourcePath,binding.resourcePath)))){
          finding.binding??=binding;
          if(!finding.history.some(h=>h.status==='failed'))finding.status=result.status==='passed'?'not_reproduced':result.status==='observed'?'unproven':'blocked';
          finding.verification={...result,origin:state.targets.find(t=>t.name===targetName).url,at:now(),simulation:false};finding.history.push({action:'verify',...finding.verification});
        }
      });
      return observed;
}
