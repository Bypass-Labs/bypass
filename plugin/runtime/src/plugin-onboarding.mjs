import { hostAI } from './execution-mode.mjs';
import { read } from './store.mjs';
import { VERSION, need } from './util.mjs';
import { workspaceInfo } from './project-selection.mjs';
import { scopeReady, appOriginInput } from './network.mjs';
import { reviewReadiness } from './review-readiness.mjs';
import { pluginIdentity } from './runtime-identity.mjs';
import { credentialStatus } from './credentials.mjs';
import { registrationStatus } from './registration.mjs';
import { appConnection } from './app-connection.mjs';
import { methodInput } from './http-methods.mjs';

// This checklist is executable product state, not a set of prose hints for a model.
export async function pluginOnboarding(cwd,root,{intent='real',mode='combined',url,environment,reviewScope=false,signal}={}){
  need(['code','combined'].includes(mode),'Choose code or combined review.');
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
  steps.push({id:'app',label:'App address',status:target?'complete':'needed',url:target?.url||null,environment:target?.environment||null,tool:'bypass_add_target'},
    {id:'ownership',label:target?.environment==='local'?'Local ownership acknowledgment':'App ownership',status:owned?'complete':target?'needed':'waiting',tool:'bypass_verify_target',...(challenge?{challenge:{record:challenge.record,value:challenge.token,method:target.environment==='local'?'local':'dns',expiresAt:challenge.expiresAt,renewRequired:Date.parse(challenge.expiresAt)<=Date.now()}}:{})},
    {id:'scope',label:'Testing permission',status:authorized?'complete':owned?'needed':'waiting',tool:'bypass_authorize_target',paths:target?.authorization?.paths||[],methods:target?.authorization?.methods||[],message:'Ownership and testing permission are separate; production requires explicit acknowledgment.'});
  const {identities,usable,missingEnvironment,probes}=ready;
  steps.push({id:'accounts',label:'Test accounts (optional)',status:usable.length>=2?'complete':'optional',tool:'bypass_import_identity',configured:identities.map(i=>({name:i.name,type:i.type,credential:credentialStatus(state,target,i)})),message:'Use existing accounts or let an authorized registration check create dedicated accounts. Missing credentials do not block source or anonymous checks.'},
    {id:'registration',label:'Account registration check',status:target?.registration?'configured':'optional',tool:'bypass_configure_registration',...registrationStatus(target)},
    {id:'resource',label:'Resource checks (discovered from source)',status:probes.length?'configured':'optional',tool:'bypass_add_probe',probes,message:'Muse derives routes and response selectors from source. JSON and HTML checks can run anonymously; cross-account checks use two accounts. Exact test resource IDs must come from authorized setup.'});
  const source=true;
  const requestedOrigin=mode==='combined'&&url?appOriginInput(url):null;
  const live=source&&authorized&&(!real||ready.live)&&(!requestedOrigin||target?.url===requestedOrigin);
  const next=steps.find(s=>s.status==='needed');
  let nextAction=next?{id:next.id,tool:next.tool,question:questions[next.id],...(next.id==='ownership'?{challenge:next.challenge}:{})}:{id:'review',tool:'bypass_scan',arguments:{mode:'combined'},message:'Show repository, app and scope, then start the requested review.'};
  if(mode==='code'){
    nextAction={id:'review',tool:'bypass_scan',arguments:{mode:'code'},message:'Review the code now. App connection is deferred; do not ask for URL, DNS, testing permission or accounts for this review.'};
    for(const step of steps)if(['app','ownership','scope'].includes(step.id)&&step.status!=='complete')step.status='deferred';
  }else if(url||!target){
    const saved=requestedOrigin?state.targets.find(t=>t.url===requestedOrigin):null;
    if(saved){
      need(!environment||environment===saved.environment,`This app is saved as ${saved.environment}. Review its saved configuration before changing its environment.`);
      if(saved.name!==target?.name)nextAction={id:'app',tool:'bypass_use_target',arguments:{name:saved.name},automatic:true,message:'Reuse the saved app and its existing ownership record; do not create a duplicate.'};
    }else{
      nextAction=appConnection({url,environment});
      if(nextAction.automatic){const base=nextAction.arguments.name;let n=2;while(state.targets.some(t=>t.name===nextAction.arguments.name))nextAction.arguments.name=base+n++;}
    }
  }
  if(reviewScope&&mode!=='code'&&owned&&(!requestedOrigin||requestedOrigin===target.url))nextAction={id:'scope',tool:'bypass_authorize_target'};
  if(nextAction.id==='ownership'&&target?.environment==='local')nextAction.question=`Do you control the app at ${target.url} on this computer?`;
  if(nextAction.id==='scope')Object.assign(nextAction,{question:`Which HTTP methods may Bypass use on ${target.url}?`,input:methodInput(target.authorization?.methods),
    scope:{url:target.url,environment:target.environment,paths:target.authorization?.paths||[],maxRequestsPerSecond:target.authorization?.maxRequestsPerSecond||2,expiresAt:target.authorization?.expiresAt||null},
    guidance:'Present a method picker with custom input, showing the exact URL, source-derived paths, request limit and expiry. Identify production explicitly. If the host has no multi-select, offer Read (GET/HEAD), Read + create (GET/HEAD/POST), and Custom methods with comma-separated input. Explain that POST can create data/start jobs, PUT/PATCH change data and DELETE removes it. Pass exactly the user-selected methods to bypass_authorize_target after permission; do not silently add methods. Then use bypass_request for authorized setup requests and observed resource IDs for probes.'});
  return {version:VERSION,runtime:identity,intent,mode,workspace,selectedRepository:root,engine,ai:hostAI(),stage:nextAction.id==='review'?'ready':nextAction.id,steps,ready:{source,live},coverageGaps:mode==='code'?[]:ready.coverageGaps,readinessMeaning:'Muse plans source review directly. Live requests require current ownership and explicit scope. Account controls are required only for authenticated checks. Host billing mode is not attested by MCP.',nextAction,
    alternatives:mode!=='code'&&source&&!live?[{label:'Review code now; connect the app later',tool:'bypass_scan',arguments:{mode:'code'}}]:[],
    guidance:'Show a compact Done / Now / Next and only the current question, not the full setup checklist. Follow nextAction.input: text means one free-text question, not a menu. Reuse the user-supplied app URL and environment by passing them to bypass_onboarding; never substitute a local README/example address. Complete steps yourself when the conversation already supplies the inputs and permission. Import known private account files; reuse routes and selectors from source and resource IDs from authorized setup. Ask only for a genuinely missing user choice, sign-in or permission. Do not ask users to export tokens, run refresh scripts or restart Muse for account credentials. Do not describe missing setup as a security finding or search unrelated private files/example folders. For an explicit code-only choice call bypass_scan with mode code immediately; do not ask for live setup.'};
}
const questions={ownership:'Verify that you control this app: add the TXT record below in your DNS settings, then say "check DNS". You can review the code while it updates.'};
