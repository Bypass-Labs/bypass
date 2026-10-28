import { hostAI } from './execution-mode.mjs';
import { read } from './store.mjs';
import { VERSION } from './util.mjs';
import { workspaceInfo } from './project-selection.mjs';
import { scopeReady } from './network.mjs';
import { reviewReadiness } from './review-readiness.mjs';
import { pluginIdentity } from './runtime-identity.mjs';
import { credentialStatus } from './credentials.mjs';
import { registrationStatus } from './registration.mjs';

// This checklist is executable product state, not a set of prose hints for a model.
export async function pluginOnboarding(cwd,root,{intent='real',signal}={}){
  const [workspace,identity]=await Promise.all([workspaceInfo(cwd,root),pluginIdentity()]);
  if(!root)return {version:VERSION,runtime:identity,intent,workspace,stage:'repository',steps:[{id:'repository',status:'needed',label:'Choose application repository'}],
    ready:{source:false,live:false},nextAction:{id:'repository',tool:'bypass_connect_repository',question:workspace.isBypassSource?'Which application should we review? Give its folder or Git URL; this folder contains the Bypass tool.':`Review the repository at ${workspace.repository.path}, or choose another folder/Git URL?`},
    guidance:'This is setup, not a security finding. Ask the one repository question in plain language. When the user answers, call the tool yourself and continue onboarding; do not end with an MCP command for them to execute.'};
  const state=read(root),real=true,engine='host',target=state.targets.find(t=>t.name===state.activeTarget);
  if(intent==='preview'&&state.demo)return {version:VERSION,runtime:identity,intent,workspace,selectedRepository:root,engine:'mock',simulation:true,ai:hostAI(),stage:'ready',steps:[{id:'repository',label:'Explicit preview fixture',status:'complete',path:root}],ready:{source:true,live:true},nextAction:{tool:'bypass_scan',arguments:{mode:'combined'}},guidance:'Explicit seeded preview only. Discovery is simulated; fixture HTTP proof and saved replay are real.'};
  const ready=reviewReadiness(state,{executionMode:'muse-host'});
  const steps=[{id:'repository',label:'Application repository',status:'complete',path:root},
    {id:'host',label:'AI reasoning in this Muse session',status:'complete',message:'No provider profile or API key required.',billing:hostAI().billing}];
  let owned=false,authorized=false;
  if(target){owned=target.ownership?.status==='verified'&&Date.parse(target.ownership.expiresAt)>Date.now();try{scopeReady(target);authorized=true;}catch{}}
  const challenge=target&&!owned?target.challenge:null;
  steps.push({id:'app',label:'Running app',status:target?'complete':'needed',url:target?.url||null,environment:target?.environment||null,tool:'bypass_add_target'},
    {id:'ownership',label:target?.environment==='local'?'Local ownership acknowledgment':'App ownership',status:owned?'complete':target?'needed':'waiting',tool:'bypass_verify_target',...(challenge?{challenge:{record:challenge.record,value:challenge.token,method:target.environment==='local'?'local':'dns',expiresAt:challenge.expiresAt,renewRequired:Date.parse(challenge.expiresAt)<=Date.now()}}:{})},
    {id:'scope',label:'Testing permission',status:authorized?'complete':owned?'needed':'waiting',tool:'bypass_authorize_target',paths:target?.authorization?.paths||[],message:'Ownership and testing permission are separate; production requires explicit acknowledgment.'});
  const {identities,usable,missingEnvironment,probes}=ready;
  steps.push({id:'accounts',label:'Test accounts (optional)',status:usable.length>=2?'complete':'optional',tool:'bypass_import_identity',configured:identities.map(i=>({name:i.name,type:i.type,credential:credentialStatus(state,target,i)})),message:'Use existing accounts or let an authorized registration check create dedicated accounts. Missing credentials do not block source or anonymous checks.'},
    {id:'registration',label:'Account registration check',status:target?.registration?'configured':'optional',tool:'bypass_configure_registration',...registrationStatus(target)},
    {id:'resource',label:'Resource checks (discovered from source)',status:probes.length?'configured':'optional',tool:'bypass_add_probe',probes,message:'Muse derives routes and response selectors from source. JSON and HTML checks can run anonymously; cross-account checks use two accounts. Exact test resource IDs must come from authorized setup.'});
  const source=true;
  const live=source&&authorized&&(!real||ready.live);
  const next=steps.find(s=>s.status==='needed');
  const nextAction=next?{id:next.id,tool:next.tool,question:questions[next.id],...(next.id==='engine'?{arguments:{mode:real?'docker':'mock'},automatic:true}:{}),...(next.id==='ownership'?{challenge:next.challenge}:{}),...(next.missingEnvironment?.length?{missingEnvironment:next.missingEnvironment}:{})}:{id:'review',tool:'bypass_scan',arguments:{mode:'combined'},message:'Show repository, app and scope, then start the requested review.'};
  if(next?.id==='ownership'&&target?.environment==='local')nextAction.question=`Confirm you control the local app at ${target.url}; then Bypass can record local ownership. Testing permission is a separate next step.`;
  return {version:VERSION,runtime:identity,intent,workspace,selectedRepository:root,engine,ai:hostAI(),stage:next?.id||'ready',steps,ready:{source,live},coverageGaps:ready.coverageGaps,readinessMeaning:'Muse plans source review directly. Live requests require current ownership and explicit scope. Account controls are required only for authenticated checks. Host billing mode is not attested by MCP.',nextAction,
    alternatives:source&&!live?[{label:real?'Review source now; finish app setup later':'Run offline code preview',tool:'bypass_scan',arguments:{mode:'code'}}]:[],
    guidance:'Show Done / Now / Next. Complete steps yourself when the conversation already supplies the inputs and permission. Import known private account files; reuse routes and selectors from source and resource IDs from authorized setup. Ask only for a genuinely missing user choice, sign-in or permission. Do not ask users to export tokens, run refresh scripts or restart Muse for account credentials. Do not describe missing setup as a security finding or search unrelated private files/example folders. Honor an explicit code-only choice.'};
}
const questions={validation:'Validate the configured accounts and owner resource with three authorized GET requests before AI.',engine:'Enable the requested analysis engine.',app:'Where is this repository running? Give its app URL and environment, or choose source-only for now.',ownership:'Publish this TXT record, then let Bypass check it. Source review can run while DNS propagates.',scope:'Which paths do you authorize for read-only testing on this app?',accounts:'Connect two dedicated test accounts. Import their known private file yourself; if no credentials are available, ask for a private file location or the necessary sign-in. Derive the identity endpoint from source.',resource:'Select an exact owner resource using the source and IDs from authorized setup. Ask for an existing test resource only if none is known; creating data or widening scope requires permission.'};
