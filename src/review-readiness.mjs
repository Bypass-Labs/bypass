import { executionMode as currentExecutionMode } from './execution-mode.mjs';
import { scopeReady } from './network.mjs';
import { specFor } from './checks.mjs';
import { hash } from './util.mjs';
import { credentialHelp, storedToken, credentialStatus } from './credentials.mjs';

export { credentialHelp };
export const activeFindings=state=>currentExecutionMode()==='muse-host'||state.settings?.analysisEngine==='docker'?state.findings.filter(f=>!f.simulation&&f.sourceEvidence?.kind!=='mock'):state.findings;

export function probeConfiguration(state,target,probe,env=process.env){
  const fixture=target?.environment==='local'&&(state.demo?.target===target.name||(state.poc&&target.pocFixture));
  const spec=specFor(state,{engine:'docker',fixture:!!fixture,bindings:{[target.name]:probe.binding}},target.name);
  if(spec.kind==='anonymous')return {spec,signature:hash({project:state.project.id,spec})};
  const credentials=[spec.owner,spec.outsider].map(identity=>{
    if(!identity.checkPath)throw new Error(`Add the signed-in JSON endpoint for ${identity.name}.`);
    scopeReady(target,identity.checkPath);
    const value=storedToken(state,target,identity,env)||(fixture?identity.fixtureValue:null);
    if(!value)throw new Error(credentialHelp(identity.secretEnv));
    if(/[\r\n]/.test(value))throw new Error(`Invalid credential in ${identity.secretEnv}. ${credentialHelp(identity.secretEnv)}`);
    return value;
  });
  if(spec.owner.name===spec.outsider.name||credentials[0]===credentials[1])throw new Error('Use two different signed-in accounts and credentials.');
  // Only a one-way digest is persisted, never tokens. Changing credentials, scope,
  // selectors or resource invalidates the displayed preflight immediately.
  const identity=i=>({name:i.name,type:i.type,secretEnv:i.secretEnv,header:i.header,checkPath:i.checkPath});
  const signature=hash({project:state.project.id,origin:spec.origin,authorization:spec.authorization,ownershipExpiresAt:spec.ownershipExpiresAt,binding:probe.binding,owner:identity(spec.owner),outsider:identity(spec.outsider),credentials});
  return {spec,signature};
}

// Read-only and shared by onboarding, status and scan planning. HTTP validation
// is explicit; every live run repeats it before any model invocation.
export function reviewReadiness(state,{targetName=state.activeTarget,env=process.env,dockerAvailable,executionMode=currentExecutionMode()}={}){
  const target=state.targets.find(t=>t.name===targetName),model=state.models.find(m=>m.name===state.activeModel),sourceBlockers=[],liveBlockers=[];
  if(executionMode!=='muse-host'&&!model)sourceBlockers.push('Choose an API-key profile with model add / model use.');
  if(executionMode!=='muse-host'&&model&&model.executionMode!=='standalone-api')sourceBlockers.push('Legacy model profile requires migration. Create an explicit API-key profile or use the Muse plugin.');
  if(executionMode!=='muse-host'&&model?.secretEnv&&!env[model.secretEnv])sourceBlockers.push(`Set ${model.secretEnv} to the chosen provider API key before a standalone AI review. No subscription login is used.`);
  if(executionMode!=='muse-host'&&model?.lastAttempt?.status==='failed')sourceBlockers.push('The last model connection check failed. Run model test before retrying, or select another model.');
  const modelReady=executionMode==='muse-host'||!!model&&!sourceBlockers.length;
  if(executionMode!=='muse-host'&&dockerAvailable===false)sourceBlockers.push('Docker is unavailable to this process. Run engine doctor.');
  let authorized=false;try{scopeReady(target||{});authorized=true;}catch(error){liveBlockers.push(error.message);}
  const fixture=target?.environment==='local'&&(state.demo?.target===target.name||(state.poc&&target.pocFixture));
  const identities=state.identities.filter(i=>i.target===target?.name);
  const missingEnvironment=identities.filter(i=>!credentialStatus(state,target,i,env).available&&!(fixture&&i.fixtureValue)).map(i=>i.secretEnv);
  const usable=identities.filter(i=>{try{scopeReady(target,i.checkPath);return i.checkPath&&(credentialStatus(state,target,i,env).available||(fixture&&i.fixtureValue));}catch{return false;}});
  const probes=(target?.probes||[]).map(probe=>{
    try{
      const {signature}=probeConfiguration(state,target,probe,env),last=probe.validation;
      const fresh=last?.signature===signature&&Date.now()-Date.parse(last.checkedAt)<5*60*1000;
      return {name:probe.name,path:probe.binding.resourcePath,configured:true,ready:!!(fresh&&last.status==='ready'),status:fresh?last.status:'preflight_required',...(fresh?{reason:last.reason,checkedAt:last.checkedAt}:{})};
    }catch(error){return {name:probe.name,path:probe.binding.resourcePath,configured:false,ready:false,status:'blocked',reason:error.message};}
  });
  const source=sourceBlockers.length===0,canValidateLive=source&&liveBlockers.length===0;
  return {target,model,identities,usable,missingEnvironment,authorized,probes,sourceBlockers,liveBlockers,source,canValidateLive,live:canValidateLive,modelReady,coverageGaps:[...(!probes.length?['No exact resource probes configured; discover routes from source before live proof.']:[]),...probes.filter(p=>!p.configured).map(p=>`${p.name}: ${p.reason}`),...(usable.length<2?['Cross-account checks need two valid accounts; source, public-surface and registration checks can proceed.']:[])]};
}
