import dns from 'node:dns/promises';
import { replay, jsonField } from './portable-check.mjs';
import { safeRequest, pathAllowed } from './network.mjs';
import { need, hash, now } from './util.mjs';
import { sha } from './github-policy.mjs';

const pause=ms=>new Promise(resolve=>setTimeout(resolve,ms));
async function txt(host){
  const resolver=new dns.Resolver({timeout:4000,tries:2});return resolver.resolveTxt(host);
}
export function checkBinding(spec){
  const {authorization,ownershipExpiresAt,timeoutMs,title,...contract}=spec;return hash(contract);
}
export async function verifyLive(api,context,policy,previous,{env=process.env,signal,progress=()=>{},resolveTxt=txt,request=safeRequest,runCheck=replay,sleep=pause}={}){
  const result={checks:[],findings:[],blockers:[],modelCalls:0,targets:structuredClone(previous.targets||{})};
  const deployedOrigin=context.kind==='verify'?new URL(context.deploymentURL).origin:null;
  const targets=Object.entries(policy.targets).filter(([,t])=>context.kind!=='verify'||(t.environment===context.environment&&t.origin===deployedOrigin));
  if(!targets.length){result.blockers.push('No approved target and saved checks match this environment and deployment origin. Connect a verified target and export its approved checks.');return result;}
  if(context.kind==='smoke'&&!policy.smoke.enabled){result.blockers.push('Scheduled smoke is disabled in policy.');return result;}
  for(const [name,target] of targets){
    const pending=[];
    try{
      need(target.checks.length,'No executable checks configured for this target.',3);
      const token=env[target.ownershipTokenEnv];need(/^bypass-verification=[A-Za-z0-9_-]{16,}$/.test(token||''),'DNS ownership secret is missing or invalid.',3);
      const records=await resolveTxt(`_bypass-verification.${new URL(target.origin).hostname}`);
      need(records.some(r=>r.join('')===token),'Current DNS ownership proof does not match. No app requests sent.',3);
      const deployment=context.kind==='verify'?{id:context.deploymentId,sha:context.sha,url:context.deploymentURL}:await api.latestDeployment(target.environment,target.origin);
      need(sha(deployment.sha),'Registered deployment has no immutable source SHA.',3);
      const deployedURL=new URL(deployment.url);need(deployedURL.origin===target.origin&&!deployedURL.username&&!deployedURL.password,'Deployment URL does not match the approved target.',3);
      const valid=target.checks.filter(check=>{
        const s=check.spec,a=s.authorization;
        const ready=Date.parse(a.expiresAt)>Date.now()&&Date.parse(s.ownershipExpiresAt)>Date.now()&&pathAllowed(target.revision.path,a.paths);
        if(!ready)result.checks.push({id:check.id,target:name,status:'blocked',reason:'Scope or ownership expired, or the build-revision endpoint is outside scope.',modelCalls:0,requests:0});
        return ready;
      });
      if(!valid.length)continue;
      const gap=1000/Math.min(...valid.map(c=>c.spec.authorization.maxRequestsPerSecond));
      const revision=async()=>{
        const response=await request(target.origin+target.revision.path,{signal,maxBytes:16384,timeout:8000,headers:{'Cache-Control':'no-cache'}});
        need(response.status===200,'Build-revision endpoint is unavailable.',3);
        need(jsonField(JSON.parse(response.body),target.revision.field)===deployment.sha,'App is not serving the registered deployment SHA. Fix remains unverified; retry after rollout.',3);
      };
      await revision();progress(`${name} · release ${deployment.sha.slice(0,7)} verified · replaying ${valid.length} saved checks`);
      for(const check of valid){
        if(signal?.aborted)throw new Error('Cancelled');
        await sleep(gap);
        let observed;try{observed=await runCheck(check.spec,{env,signal});}catch{observed={status:'blocked',reason:'Saved check execution failed.',modelCalls:0};}
        const binding=checkBinding(check.spec),key=hash([name,check.id,binding]);
        const old=previous.targets?.[key];
        const entry={id:check.id,findingId:check.findingId||null,target:name,origin:target.origin,binding,deploymentId:deployment.id,sha:deployment.sha,checkedAt:now(),...observed};
        entry.transition=entry.status==='failed'?(old?.status==='passed'?'regressed':'observed_failure'):entry.status==='passed'?(old?.everFailed?'fix_verified':'passed'):'blocked';
        pending.push({entry,key,old});progress(`${name} · ${pending.length}/${valid.length} · ${check.id}: ${entry.status} · continuing remaining checks`);
      }
      // A rolling deployment must not turn a mix of versions into a verified fix.
      await sleep(gap);await revision();
      for(const {entry,key,old} of pending){
        result.checks.push(entry);
        if(['passed','failed'].includes(entry.status))result.targets[key]={status:entry.status,everFailed:entry.status==='failed'||!!old?.everFailed,sha:entry.sha,checkId:entry.id,target:name,binding:entry.binding,checkedAt:entry.checkedAt,history:[...(Array.isArray(old?.history)?old.history:[]).slice(-19),{status:entry.status,sha:entry.sha,at:entry.checkedAt,deploymentId:entry.deploymentId}]};
      }
    }catch(error){
      result.blockers.push(`${name}: ${error.message}`);
      for(const {entry} of pending)result.checks.push({...entry,assertionStatus:entry.status,status:'blocked',transition:'release_unverified',reason:'Release identity was not stable across the replay. No fix verified.'});
    }
  }
  for(const check of result.checks)if(!['passed','failed'].includes(check.status))result.blockers.push(`${check.target}/${check.id}: ${check.reason}`);
  // Bound rolling memory without discarding evidence in the report artifact.
  result.targets=Object.fromEntries(Object.entries(result.targets).slice(-500));
  return result;
}
