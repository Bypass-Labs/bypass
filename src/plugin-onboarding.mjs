import { read } from './store.mjs';
import { VERSION } from './util.mjs';
import { workspaceInfo } from './project-selection.mjs';
import { dockerStatus } from './agent-runtime.mjs';
import { scopeReady } from './network.mjs';
import { reviewReadiness } from './review-readiness.mjs';
import { pluginIdentity } from './runtime-identity.mjs';

// This checklist is executable product state, not a set of prose hints for a model.
export async function pluginOnboarding(cwd,root,{intent='real',signal,checkDocker=dockerStatus}={}){
  const [workspace,identity]=await Promise.all([workspaceInfo(cwd,root),pluginIdentity()]);
  if(!root)return {version:VERSION,runtime:identity,intent,workspace,stage:'repository',steps:[{id:'repository',status:'needed',label:'Choose application repository'}],
    ready:{source:false,live:false},nextAction:{id:'repository',tool:'bypass_connect_repository',question:workspace.isBypassSource?'Which application should we review? Give its folder or Git URL; this folder contains the Bypass tool.':`Review the repository at ${workspace.repository.path}, or choose another folder/Git URL?`},
    guidance:'This is setup, not a security finding. Ask the one repository question in plain language. When the user answers, call the tool yourself and continue onboarding; do not end with an MCP command for them to execute.'};
  const state=read(root),real=intent==='real',engine=state.settings.analysisEngine==='docker'?'docker':'mock',model=state.models.find(m=>m.name===state.activeModel),target=state.targets.find(t=>t.name===state.activeTarget);
  const runtime=real?await checkDocker({signal}):{available:true,message:'Offline preview does not require Docker.'};
  const ready=reviewReadiness(state,{dockerAvailable:runtime.available});
  const steps=[{id:'repository',label:'Application repository',status:'complete',path:root},{id:'engine',label:'Analysis engine',status:engine===(real?'docker':'mock')?'complete':'needed',current:engine,requested:real?'docker':'mock',tool:'bypass_engine'},
    {id:'model',label:'Model profile (connection checked before review)',status:!real?'not_required':model&&ready.modelReady?'complete':'needed',profile:model?{name:model.name,provider:model.provider,model:model.model,destination:model.dataDestination,connection:model.lastAttempt?.status||model.lastTest?.status||'not tested'}:null,tool:'bypass_add_model'},
    {id:'docker',label:'Docker services',status:runtime.available?'complete':'needed',message:runtime.message,tool:'bypass_engine_doctor'}];
  const modelSecretMissing=real&&model?.secretEnv&&!process.env[model.secretEnv];
  if(modelSecretMissing)steps[2]={...steps[2],status:'needed',missingEnvironment:[model.secretEnv],message:'Load this environment variable in the terminal that starts Muse. Do not paste the value into chat.'};
  let owned=false,authorized=false;
  if(target){owned=target.ownership?.status==='verified'&&Date.parse(target.ownership.expiresAt)>Date.now();try{scopeReady(target);authorized=true;}catch{}}
  const challenge=target&&!owned?target.challenge:null;
  steps.push({id:'app',label:'Running app',status:target?'complete':'needed',url:target?.url||null,environment:target?.environment||null,tool:'bypass_add_target'},
    {id:'ownership',label:target?.environment==='local'?'Local ownership acknowledgment':'App ownership',status:owned?'complete':target?'needed':'waiting',tool:'bypass_verify_target',...(challenge?{challenge:{record:challenge.record,value:challenge.token,method:target.environment==='local'?'local':'dns',expiresAt:challenge.expiresAt,renewRequired:Date.parse(challenge.expiresAt)<=Date.now()}}:{})},
    {id:'scope',label:'Testing permission',status:authorized?'complete':owned?'needed':'waiting',tool:'bypass_authorize_target',paths:target?.authorization?.paths||[],message:'Ownership and testing permission are separate; production requires explicit acknowledgment.'});
  const {identities,usable,missingEnvironment,probes}=ready;
  steps.push({id:'accounts',label:'Two test accounts',status:!real?'not_required':usable.length>=2?'complete':authorized?'needed':'waiting',tool:'bypass_add_identity',configured:identities.map(i=>({name:i.name,type:i.type,secretEnv:i.secretEnv,checkPath:i.checkPath})),missingEnvironment,message:'Two distinct accounts, environment-variable references, and a signed-in JSON identity endpoint. HTTP controls validate the identities when reviewing.'},
    {id:'resource',label:'Owner-owned JSON resource',status:!real?'not_required':probes.length&&probes.every(p=>p.configured)?'complete':authorized&&usable.length>=2?'needed':'waiting',tool:'bypass_add_probe',probes,message:'Provide the exact GET path, expected resource ID and JSON identifier fields. No guessing customer resource IDs.'});
  if(real)steps.push({id:'validation',label:'Validate accounts and owner resource before AI',status:ready.live?'complete':ready.canValidateLive?'needed':'waiting',tool:'bypass_test_probe',message:'Three authorized GET requests per resource; no model calls or cross-account tests. Valid for five minutes; every live scan repeats this check.'});
  const connectionFailed=real&&model?.lastAttempt?.status==='failed';
  const source=(!real||ready.source)&&steps.slice(0,4).every(s=>['complete','not_required'].includes(s.status));
  const live=source&&authorized&&(!real||ready.live);
  const next=steps.find(s=>s.status==='needed');
  const nextAction=next?{id:next.id,tool:next.tool,question:questions[next.id],...(next.id==='engine'?{arguments:{mode:real?'docker':'mock'},automatic:true}:{}),...(next.id==='ownership'?{challenge:next.challenge}:{}),...(next.missingEnvironment?.length?{missingEnvironment:next.missingEnvironment}:{})}:{id:'review',tool:'bypass_scan',arguments:{mode:'combined'},message:'Show repository, app, model and scope, then start the requested review.'};
  if(next?.id==='validation'){const probe=probes.find(p=>!p.ready);nextAction.arguments={name:probe.name};nextAction.automatic=probe.status!=='blocked';nextAction.message='Check the approved logins and owner resource now; stop on blocked controls before spending model calls.';if(probe.status==='blocked')nextAction.question=`The last account/resource check was blocked: ${probe.reason} Repair that input before testing again; repository and DNS setup are saved.`;}
  if(next?.id==='model'&&modelSecretMissing){delete nextAction.tool;nextAction.question='Load the named model credential environment variable in the terminal that launches Muse, then restart Muse. Keep the existing profile.';}
  if(next?.id==='accounts'&&identities.length>=2){
    const incomplete=identities.find(i=>!i.checkPath);
    if(incomplete){nextAction.tool='bypass_update_identity';nextAction.arguments={name:incomplete.name};nextAction.question=`What JSON endpoint identifies the signed-in account for ${incomplete.name}? The existing account reference is saved.`;}
    else if(missingEnvironment.length){delete nextAction.tool;nextAction.question='Your account references are saved. Load the named environment variables in the terminal that launches Muse, then restart; do not paste credential values into chat.';}
    else{nextAction.tool='bypass_authorize_target';nextAction.question='The configured identity endpoint is outside the authorized paths. Review and explicitly authorize a scope that includes the login controls.';}
  }
  if(next?.id==='ownership'&&target?.environment==='local')nextAction.question=`Confirm you control the local app at ${target.url}; then Bypass can record local ownership. Testing permission is a separate next step.`;
  if(connectionFailed&&!modelSecretMissing&&engine==='docker')Object.assign(nextAction,{id:'connection',tool:'bypass_test_model',arguments:{name:model.name},question:'The last model connection check failed. Check it once before retrying the review, or choose another model connection. Your repository and app setup are saved.',reason:model.lastAttempt.reason});
  return {version:VERSION,runtime:identity,intent,workspace,selectedRepository:root,engine,stage:nextAction.id==='connection'?'connection':next?.id||'ready',steps,ready:{source,live},readinessMeaning:'Source readiness means model configuration is usable; the connection is checked before source upload. Live readiness also requires recent positive HTTP controls. Every live review revalidates accounts and resource before AI; model responses are bounded to 60 seconds.',nextAction,
    alternatives:source&&!live?[{label:real?'Review source now; finish app setup later':'Run offline code preview',tool:'bypass_scan',arguments:{mode:'code'}}]:[],
    guidance:'Show the compact checklist and ask only for the next missing choice. Perform tool calls yourself after the user answers. Do not describe missing setup as a security finding or search example folders. Honor an explicit code-only choice without repeating app questions.'};
}
const questions={validation:'Validate the configured accounts and owner resource with three authorized GET requests before AI.',engine:'Enable the requested analysis engine.',model:'Use your Muse subscription, a compatible local model, or a self-hosted endpoint? All three roles share the selected profile; confirm the model ID when matching the host session.',docker:'Start Docker Desktop or Colima, then continue. Other setup can be completed while Docker starts.',app:'Where is this repository running? Give its app URL and environment, or choose source-only for now.',ownership:'Publish this TXT record, then let Bypass check it. Source review can run while DNS propagates.',scope:'Which paths do you authorize for read-only testing on this app?',accounts:'Which environment-variable names hold the owner and other-account credentials, and what JSON endpoint identifies the signed-in account?',resource:'What exact JSON resource belongs to the owner? Provide its GET path and expected resource ID.'};
