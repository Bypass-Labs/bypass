import { executionMode, hostAI, requireStandaloneAPI } from './execution-mode.mjs';
import { beginHostReview, hostPlan, hostReviewStep } from './host-review.mjs';
import { memorySummary, recallMemory, featureContext, forgetMemory, setMemory, consolidateMemory } from './project-memory.mjs';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawn } from 'node:child_process';
import { commandInvocation } from './command.mjs';
import { rootFrom, read, change, initStore, snapshot, atomic, event } from './store.mjs';
import { need, named, safeName, envName, now, duration, outcome, execFile, Fault, redact } from './util.mjs';
import { samePluginPackage, museInstallState } from './muse-install-state.mjs';
import { connectRepository, repositoryInfo, inventory } from './repository.mjs';
import { targetURL, makeChallenge, verifyOwnership, authorization, scopeReady, safeRequest } from './network.mjs';
import { modelProfile, testModel } from './models.mjs';
import { scanPlan, executeRun, verifyFinding } from './engine.mjs';
import { monitorSummary } from './plugin-context.mjs';
import { realEngine } from './real-engine.mjs';
import { reviewReadiness, activeFindings, credentialHelp } from './review-readiness.mjs';
import { validateProbe } from './probe-preflight.mjs';
import { configureRegistration, testRegistration, registrationStatus } from './registration.mjs';
import { importCredential, removeCredential, credentialStatus, credentialEnvironment } from './credentials.mjs';
import { summarizeRun, terminalRun } from './run-state.mjs';
import { runtimeIdentity } from './runtime-identity.mjs';
import { dockerStatus, prepareAgents } from './agent-runtime.mjs';
import { specFor, saveCheck, bindCheck, exportChecks } from './checks.mjs';
import { dispatchRun, watchRun, startWorker, workerStatus, runMonitor } from './jobs.mjs';
import { startDemo, updateDemo, serveDemo, demoConfig, CLI } from './demo.mjs';

export const PACKAGE_ROOT=path.resolve(path.dirname(fileURLToPath(import.meta.url)),'..');
function loadJSON(file){try{return JSON.parse(fs.readFileSync(path.resolve(file),'utf8'));}catch{throw new Fault(`Cannot parse JSON file: ${file}`);}}
function filter(list,options,keys){return list.filter(item=>keys.every(k=>!options[k]||item[k]===options[k]));}
const wrap=value=>value?.schemaVersion==='bypass.v1'?value:outcome(value);
export function readiness(root){
  const s=read(root),target=s.targets.find(t=>t.name===s.activeTarget),model=s.models.find(m=>m.name===s.activeModel);
  const host=executionMode()==='muse-host';
  const shared=reviewReadiness(s),liveReady=shared.authorized,liveReview=host||realEngine(s)?shared.live:liveReady;
  const findings=activeFindings(s),latest=s.runs.at(-1),active=latest&&!terminalRun(latest);
  const next=active?(latest.executionMode==='muse-host'?`Continue review ${latest.id} in Muse`:`run watch ${latest.id}`):realEngine(s)&&shared.sourceBlockers.length?'model test':latest?.status==='failed'?(latest.result?.details?.next||`run show ${latest.id}`):s.checks.some(c=>c.enabled)?'test run --all':findings.length?'finding list':liveReview?'scan --mode combined':'scan --mode code';
  return {runtime:runtimeIdentity(),project:s.project,root,ai:host?hostAI():{mode:'standalone-api'},engine:{mode:host?'host':realEngine(s)?'docker':'mock',analysisImplemented:host||realEngine(s),label:host?'Muse plans; Bypass executes':realEngine(s)?'Docker agents · real source review and scoped HTTP proof':'MOCK analysis · real setup and saved-test replay'},
    review:(executionMode()==='muse-host'?hostPlan:scanPlan)(s,{mode:liveReview?'combined':'code'}),
    model:host?{name:'Active Muse session',provider:'muse-host',destination:'Host session',connection:'host managed'}:model?{name:model.name,provider:model.provider,destination:model.dataDestination,connection:model.lastAttempt?.status||model.lastTest?.status||'not tested'}:null,
    target:target?{name:target.name,url:target.url,environment:target.environment,ownership:target.ownership?.status||'pending',authorized:liveReady}:null,
    ready:{repository:true,model:host||realEngine(s)?shared.modelReady:!!model,source:host||realEngine(s)?shared.source:true,target:!!target,authorized:liveReady,liveTesting:liveReview,liveReview,canValidateLive:shared.canValidateLive},probes:shared.probes,coverageGaps:shared.coverageGaps,registration:registrationStatus(target),blockers:{source:shared.sourceBlockers,live:shared.liveBlockers},
    findings:{total:findings.length,hiddenSimulated:s.findings.length-findings.length,confirmed:findings.filter(f=>f.status==='confirmed').length,fixtureConfirmed:findings.filter(f=>f.status==='confirmed_fixture').length,simulated:findings.filter(f=>f.status==='simulated_unproven').length,fixed:findings.filter(f=>f.status==='fixed_verified').length},
    checks:{total:s.checks.length,enabled:s.checks.filter(c=>c.enabled).length,passed:s.checks.filter(c=>c.lastResult?.status==='passed').length,failed:s.checks.filter(c=>c.lastResult?.status==='failed').length},
    memory:memorySummary(s),worker:workerStatus(root),monitors:s.monitors.length,latestRun:summarizeRun(latest),
    privacy:{evidence:'local',sourceUpload:host||realEngine(s),analysisInference:host?'Active Muse session receives requested excerpts; no plugin model requests':realEngine(s)?'Selected source excerpts sent to the active model':'not invoked (mock engine)',secretStorage:'Test accounts: owner-only local store outside the repository, or environment references for CI. Firebase refresh is automatic. Public fixture credentials only in demo.'},
    next,
    limitations:[host||realEngine(s)?'Bounded source, JSON/HTML access and registration checks; incomplete coverage.':'White-box and black-box engines are simulated.','Hosted Bypass account, cloud scheduler, and deployment attestation are not connected.','No passing result implies complete security coverage.']};
}

export async function execute(key,args=[],o={},context={}){
  const working=path.resolve(o.project||context.cwd||process.cwd());
  if(['scan','verify','retest','test run'].includes(key)){
    const fixtureRoot=rootFrom(working,false);
    if(fixtureRoot&&read(fixtureRoot).poc){const {resumePOC}=await import('./poc.mjs');await resumePOC(fixtureRoot,{automatic:true,signal:context.signal});}
  }
  if(executionMode()==='muse-host'&&['model add','model test','model use'].includes(key))return outcome({ai:hostAI(),message:'Model setup and independent connection tests are disabled in the Muse plugin. Continue in the active host session.'});
  if(executionMode()==='muse-host'&&key==='scan'&&!read(rootFrom(working)).demo)return o.plan?outcome({plan:hostPlan(read(rootFrom(working)),o)}):beginHostReview(rootFrom(working),o,context);
  if(key==='host review')return hostReviewStep(rootFrom(working),o,context);
  if(key==='init'||key==='repo connect'){
    const config=o.config?loadJSON(o.config):null;
    const {root,repository}=await connectRepository(o.repo||args[0]||config?.repo||working,o.dir||config?.dir,context);
    const {resumed}=initStore(root,repository,o.name||config?.name);
    if(resumed)await change(root,s=>{s.project.repository=repository;s.project.root=root;});
    if(config){
      if(config.model&&!read(root).models.some(m=>m.name===config.model.name))await execute('model add',[config.model.name],{...config.model,project:root},context);
      if(config.target&&!read(root).targets.some(t=>t.name===config.target.name))await execute('target add',[config.target.name],{...config.target,project:root},context);
    }
    await consolidateMemory(root);
    return outcome({root,resumed,message:resumed?'Existing project resumed; settings and evidence retained.':'Repository connected. No source code was executed.',readiness:readiness(root)});
  }
  if(key==='poc start'){const {startPOC}=await import('./poc.mjs');return outcome(await startPOC(o));}
  if(key==='poc stop'){const {stopPOC}=await import('./poc.mjs');return outcome(await stopPOC(rootFrom(working)));}
  if(key==='poc resume'){const {resumePOC}=await import('./poc.mjs');return outcome(await resumePOC(rootFrom(working),{signal:context.signal}));}
  if(key==='demo start')return outcome(await startDemo(o.dir||path.join(PACKAGE_ROOT,'.demo/ledger'),{port:o.port||4317}));
  if(key==='auth login'&&o.device)throw new Fault('Hosted device authentication is unavailable. Standalone AI uses explicit provider API keys.',3);
  if(key==='auth status'||key==='auth login')return outcome(executionMode()==='muse-host'?{ai:hostAI()}:{mode:'standalone-api',accountRequired:false,message:'AI requires a provider API key. Configure it with model add; installed-agent logins are never used.'});
  if(key==='mcp serve'){const {serveMCP}=await import('./mcp.mjs');await serveMCP(working);return null;}
  if(key==='integrate muse'||key==='integrate status'||key==='integrate remove')return integrate(key,args,o,working,context);
  if(key==='doctor'){
    const root=rootFrom(working,false);let s;try{s=read(root);}catch{}
    const checks=[{name:'Node >=22',ok:Number(process.versions.node.split('.')[0])>=22,version:process.version}];
      for(const binary of ['git','muse']){try{const r=await execFile(binary,['--version']);checks.push({name:binary,ok:r.code===0,version:r.stdout});}catch(e){checks.push({name:binary,ok:false,message:e.message,optional:binary==='muse'&&s?.models.find(m=>m.name===s.activeModel)?.provider!=='muse-code'});}}
      if(executionMode()!=='muse-host'&&(!s||realEngine(s))){const docker=await dockerStatus(context);checks.push({name:'Docker',ok:docker.available,version:docker.version,message:docker.message});}
      return outcome({kind:'environment-diagnostics',checks,runtime:runtimeIdentity(),readiness:s?readiness(root):null,message:'Doctor checks configuration and executables. It does not prove model access or app security.'},checks.some(c=>!c.ok&&!c.optional)?3:0);
  }
  const root=rootFrom(working);const s=read(root);const targetName=o.target||s.activeTarget;
  let result;
  switch(key){
    case 'engine use':{
      need(['docker','mock'].includes(args[0]),'Choose docker or mock.');
      result=await change(root,state=>{state.settings.analysisEngine=args[0];return {engine:args[0],message:args[0]==='docker'?'Real agents selected. Source excerpts go to your shared model. Use engine doctor and probe add, then scan.':'Offline mocked preview selected.'};});break;
    }
    case 'engine doctor':result=executionMode()==='muse-host'?{available:true,engine:'host',ai:hostAI(),message:'Plugin test execution needs no Docker or model profile.'}:{...(await dockerStatus(context)),engine:realEngine(s)?'docker':'mock',model:s.models.find(m=>m.name===s.activeModel)||null};break;
    case 'engine prepare':result=await prepareAgents(context);break;
    case 'registration configure':result=await configureRegistration(root,o);break;
    case 'registration status':result=registrationStatus(named(s.targets,targetName,'Target'));break;
    case 'registration test':{const registration=await testRegistration(root,{target:targetName,signal:context.signal});return outcome({registration},registration.status==='failed'?1:['blocked','cancelled'].includes(registration.status)?3:0);}
    case 'probe discover':{const {discoverResources}=await import('./resource-discovery.mjs');result=await discoverResources(root,o,context);break;}
    case 'request':{const {scopedRequest}=await import('./scoped-request.mjs');return scopedRequest(root,o,context);}
    case 'probe test':{const validation=await validateProbe(root,args[0],{target:targetName,signal:context.signal});return outcome({validation},validation.status==='ready'?0:3);}
    case 'probe list':result={target:targetName,probes:named(s.targets,targetName,'Target').probes||[]};break;
    case 'probe add':{
      safeName(args[0]);const t=named(s.targets,targetName,'Target');scopeReady(t,o.path);
      const anonymous=o.kind==='anonymous',html=o.response==='html';
      need(!o.kind||['anonymous','cross-account-resource'].includes(o.kind),'Probe kind must be anonymous or cross-account-resource.');
      need(!o.response||['json','html'].includes(o.response),'Response must be json or html.');
      need(o.path&&(html?typeof o['match-text']==='string'&&o['match-text'].length>=8&&o['match-text'].length<=1000:o['resource-id']),'Provide an exact path and JSON resource ID, or HTML response with a specific 8–1000 character content marker.');
      need(o.path.startsWith('/')&&!o.path.startsWith('//')&&!/[?#\\]/.test(o.path)&&!/%(?:2f|5c|2e|25)/i.test(o.path)&&!o.path.split('/').includes('..'),'Probe path must be an exact safe path without query strings.');
      const binding={resourcePath:o.path,resourceId:o['resource-id'],...(html?{response:'html',matchText:o['match-text']}:{idField:o['id-field']||'id'}),...(anonymous?{kind:'anonymous',expected:o.expected}:{owner:o.owner,outsider:o.outsider,identityField:o['identity-field']||'id'})};
      if(anonymous)need(['private','public'].includes(o.expected),'Choose the intended public/private policy; public availability alone is not a vulnerability.');
      else{need(o.owner&&o.outsider&&o.owner!==o.outsider,'Choose two different account identities.');
      for(const name of [o.owner,o.outsider]){const identity=named(s.identities,name,'Identity');need(identity.checkPath,'Each identity needs --check-path (for example /api/me).');scopeReady(t,identity.checkPath);}}
      specFor(s,{target:targetName,engine:'docker',bindings:{[targetName]:binding}},targetName);
      result=await change(root,state=>{const target=named(state.targets,targetName,'Target');target.probes??=[];need(target.probes.length<6||target.probes.some(p=>p.name===args[0]),'POC supports up to six approved resources per target.');target.probes=target.probes.filter(p=>p.name!==args[0]);target.probes.push({name:args[0],binding});return {probe:target.probes.at(-1),target:targetName};});break;
    }
    case 'status':result=readiness(root);break;
    case 'repo show':result={repository:await repositoryInfo(root)};break;
    case 'config show':result=snapshot(s);break;
    case 'config set':result=await change(root,state=>{
      const [key,value]=args;
      if(key==='autoSave'){need(['true','false'].includes(value),'autoSave must be true or false.');state.settings.autoSave=value==='true';}
      else if(key==='requestTimeoutMs'){need(Number(value)>=1000&&Number(value)<=60000,'requestTimeoutMs must be between 1000 and 60000.');state.settings.requestTimeoutMs=Number(value);}
      else if(key==='project.name'){need(value.length<=100,'Project name is too long.');state.project.name=value;}
      else throw new Fault('Supported settings: autoSave, requestTimeoutMs, project.name. Use target/model commands for their settings.');
      return {key,value};});break;
    case 'auth logout':result=await change(root,state=>{state.auth=null;return {message:'Bypass-local account metadata cleared. Use muse logout to sign out of Muse itself.'};});break;
    case 'target add':{
      safeName(args[0]);need(o.url,'--url is required.');const environment=o.environment||'staging',url=targetURL(o.url,environment);
      result=await change(root,state=>{need(!state.targets.some(t=>t.name===args[0]),'A target with this name already exists.');const t={name:args[0],url,environment,createdAt:now(),ownership:{status:'pending'},authorization:null};t.challenge=makeChallenge(state.project,t);state.targets.push(t);state.activeTarget??=t.name;return {target:t,next:`bypass target verify ${t.name} --method ${environment==='local'?'local':'dns'}`};});break;
    }
    case 'target list':result={targets:s.targets,active:s.activeTarget};break;
    case 'target show':result={target:named(s.targets,args[0]||s.activeTarget,'Target')};break;
    case 'target use':result=await change(root,state=>{state.activeTarget=named(state.targets,args[0],'Target').name;return {activeTarget:state.activeTarget};});break;
    case 'target verify':{
      const name=args[0]||s.activeTarget;let t=named(s.targets,name,'Target');
      if(o.renew){result=await change(root,state=>{const target=named(state.targets,name,'Target');target.challenge=makeChallenge(state.project,target);target.ownership={status:'pending'};target.authorization=null;return {target,message:'New ownership challenge issued; previous authorization invalidated.'};});break;}
      let ownership;
      try{ownership=await verifyOwnership(t,o.method||(t.environment==='local'?'local':'dns'),{wait:o.wait,signal:context.signal});}
      catch(error){if(error.details?.challenge&&!context.signal?.aborted)return outcome({kind:'setup-pending',status:error.details.expired?'expired':'pending',target:name,challenge:error.details.challenge,message:error.message,nextAction:{tool:'bypass_verify_target',arguments:{name,method:o.method||'dns',...(error.details.expired?{renew:true}:{})}},alternative:error.details.alternative,liveRequestsAllowed:false},3);throw error;}
      result=await change(root,state=>{const target=named(state.targets,name,'Target');need(target.challenge.id===t.challenge.id,'Challenge changed during verification; retry.',3);target.ownership=ownership;event(state,'ownership',`${name}: ownership verified`);return {target,next:`bypass target authorize ${name}`};});break;
    }
    case 'target authorize':{
      const name=args[0]||s.activeTarget;
      need(o['scope-file']||o.accept,'Review scope, then provide --scope-file or --accept --paths /api. Ownership alone is not authorization.');
      need(!(o['scope-file']&&o.methods!==undefined),'Choose methods in the scope file or with --methods, not both.');
      const scope=context.scope||(o['scope-file']?loadJSON(o['scope-file']):{paths:(o.paths||'/api').split(','),methods:o.methods,productionAcknowledged:!!o.production});
      result=await change(root,state=>{const t=named(state.targets,name,'Target');t.authorization=authorization(t,scope);event(state,'authorized',`${name}: testing authorized`,{scope:t.authorization});return {target:t.name,authorization:t.authorization};});break;
    }
    case 'target revoke':case 'target remove':result=await change(root,state=>{
      const t=named(state.targets,args[0],'Target');t.authorization=null;t.ownership={status:'revoked'};
      state.monitors.filter(m=>m.target===t.name).forEach(m=>m.enabled=false);
      state.runs.filter(r=>r.options.target===t.name&&['queued','running'].includes(r.status)).forEach(r=>r.cancelRequested=true);
      if(key==='target remove'){state.targets=state.targets.filter(x=>x.name!==t.name);if(state.activeTarget===t.name)state.activeTarget=state.targets[0]?.name||null;}
      event(state,'revoked',`${t.name}: authorization revoked`);return {target:t.name,message:'Testing revoked; monitors paused; historical evidence retained.'};});break;
    case 'identity add':{
      safeName(args[0]);need(o['secret-env'],'--secret-env is required. Bypass stores a reference, never the credential.');envName(o['secret-env']);need(['bearer','cookie','header'].includes(o.type),'--type must be bearer, cookie, or header.');
      if(o.type==='header')need(/^[A-Za-z][A-Za-z0-9-]*$/.test(o.header||'')&&!['host','connection','content-length','transfer-encoding'].includes(o.header.toLowerCase()),'Supply a safe custom --header name.');
      const checkPath=o['check-path']||null;if(checkPath)need(checkPath.startsWith('/')&&!/[?#\\]/.test(checkPath),'Identity check path must be a path without query strings.');
      result=await change(root,state=>{named(state.targets,targetName,'Target');need(!state.identities.some(i=>i.name===args[0]),'Identity name already exists.');const identity={name:args[0],target:targetName,type:o.type,secretEnv:o['secret-env'],header:o.header||null,checkPath,createdAt:now()};state.identities.push(identity);return {identity};});break;
    }
    case 'identity import':{
      safeName(args[0]);need(o.file&&o['token-field'],'Provide the private file path and token field name. Never pass a raw token.');
      const existing=s.identities.find(i=>i.name===args[0]),target=named(s.targets,o.target||existing?.target||targetName,'Target');
      need(!existing||existing.target===target.name,'An existing identity cannot move between targets.');
      const identity={...existing,name:args[0],target:target.name,type:o.type||existing?.type||'bearer',secretEnv:envName(o['secret-env']||existing?.secretEnv||`BYPASS_${args[0].toUpperCase().replaceAll('-','_')}_TOKEN`),header:o.header||existing?.header||null,checkPath:o['check-path']||existing?.checkPath||null,createdAt:existing?.createdAt||now()};
      need(['bearer','cookie','header'].includes(identity.type),'Choose bearer, cookie or header.');
      if(identity.type==='header')need(/^[A-Za-z][A-Za-z0-9-]*$/.test(identity.header||'')&&!['host','connection','content-length','transfer-encoding'].includes(identity.header.toLowerCase()),'Supply a safe custom header.');
      if(identity.checkPath)need(identity.checkPath.startsWith('/')&&!/[?#\\]/.test(identity.checkPath),'Invalid check path.');
      const ref=importCredential(s,target,identity,o);identity.credentialRef=ref;delete identity.fixtureValue;delete identity.lastTest;
      try{result=await change(root,state=>{const current=state.identities.find(i=>i.name===identity.name);need(current?.credentialRef===existing?.credentialRef,'Account changed during import; retry.',3);need(state.project.id===s.project.id&&named(state.targets,target.name,'Target').url===target.url,'Project changed during import; retry.',3);state.identities=state.identities.filter(i=>i.name!==identity.name);state.identities.push(identity);return {identity,credential:credentialStatus(state,target,identity),message:'Account connected privately. Continue in this session; no export or restart needed.'};});}
      catch(error){removeCredential(s,ref);throw error;}
      removeCredential(s,existing?.credentialRef);break;
    }
    case 'identity refresh':{
      const identity=named(s.identities,args[0],'Identity'),target=named(s.targets,identity.target,'Target');
      need(identity.credentialRef,'Import the account with its refresh token first.');
      await credentialEnvironment(s,target,[identity],{force:true,signal:context.signal});
      result={identity:identity.name,credential:credentialStatus(s,target,identity),message:'Account refreshed privately; continue in this session.'};break;
    }
    case 'identity list':result={identities:filter(s.identities,o,['target']).map(({fixtureValue,...x})=>({...x,credential:credentialStatus(s,s.targets.find(t=>t.name===x.target),x)}))};break;
    case 'identity test':{
      const identity=named(s.identities,args[0],'Identity'),target=named(s.targets,identity.target,'Target');need(identity.checkPath,'Configure --check-path before testing this identity.');scopeReady(target,identity.checkPath);
      const env=await credentialEnvironment(s,target,[identity],{signal:context.signal});
      const secret=env[identity.secretEnv]||(target.environment==='local'&&(s.demo?.target===identity.target||(s.poc&&target.pocFixture))?identity.fixtureValue:null);need(secret,credentialHelp(identity.secretEnv),3);
      const headers=identity.type==='bearer'?{Authorization:`Bearer ${secret}`}:identity.type==='cookie'?{Cookie:secret}:{[identity.header]:secret};
      const response=await safeRequest(target.url+identity.checkPath,{headers,allowLocal:target.environment==='local',timeout:s.settings.requestTimeoutMs,signal:context.signal});
      const check={httpStatus:response.status,status:response.status>=200&&response.status<300?'accepted':'blocked',checkedAt:now(),bodyStored:false,message:'Endpoint accepted the request; account role is not automatically attested.'};
      await change(root,state=>{named(state.identities,args[0],'Identity').lastTest=check;});return outcome({identity:args[0],check},check.status==='accepted'?0:3);
    }
    case 'identity update':{
      const previous=named(s.identities,args[0],'Identity').credentialRef;
      result=await change(root,state=>{const identity=named(state.identities,args[0],'Identity');need(o['secret-env']||o['check-path'],'Supply --secret-env or --check-path.');if(o['secret-env']){identity.secretEnv=envName(o['secret-env']);delete identity.fixtureValue;delete identity.credentialRef;}if(o['check-path']){need(o['check-path'].startsWith('/')&&!/[?#\\]/.test(o['check-path']),'Invalid check path.');identity.checkPath=o['check-path'];}delete identity.lastTest;return {identity};});
      if(o['secret-env'])removeCredential(s,previous);break;
    }
    case 'identity remove':{
      const previous=named(s.identities,args[0],'Identity').credentialRef;
      result=await change(root,state=>{named(state.identities,args[0],'Identity');state.identities=state.identities.filter(i=>i.name!==args[0]);return {removed:args[0],message:'Local credentials removed. The application account itself is unchanged.'};});removeCredential(s,previous);break;
    }
    case 'model add':{
      safeName(args[0]);const profile=modelProfile(args[0],o);result=await change(root,state=>{need(!state.models.some(m=>m.name===args[0]),'Model profile already exists.');state.models.push(profile);state.activeModel??=profile.name;return {model:profile};});break;
    }
    case 'model list':result={models:s.models,active:s.activeModel,privacy:'Standalone profiles use explicit API keys. Muse plugin reasoning stays in the active host session.'};break;
    case 'model use':result=await change(root,state=>{state.activeModel=named(state.models,args[0],'Model').name;return {activeModel:state.activeModel};});break;
    case 'model test':{
      const m=named(s.models,args[0]||s.activeModel,'Model');
      try {
        const check=await testModel(m,root,context);
        await change(root,state=>{const model=named(state.models,m.name,'Model');model.lastTest=check;model.lastAttempt=check;});
        result={model:m.name,check};
      } catch(error) {
        await change(root,state=>{named(state.models,m.name,'Model').lastAttempt={status:error.code===130?'skipped':'failed',checkedAt:now(),reason:error.details?.reason||'connection_check',message:redact(error.message),repositorySent:false};});
        throw error;
      }
      break;
    }
    case 'model remove':result=await change(root,state=>{named(state.models,args[0],'Model');state.models=state.models.filter(m=>m.name!==args[0]);if(state.activeModel===args[0])state.activeModel=state.models[0]?.name||null;return {removed:args[0]};});break;
    case 'scan':{
      const plan=scanPlan(s,o);if(o.plan)return outcome({plan},plan.blockers.length?3:0);
      return dispatchRun(root,'scan',{mode:o.mode||'combined',target:targetName,base:o.base,full:!!o.full},!!o.detach,context.signal,context.onProgress);
    }
    case 'finding list':result={findings:filter(activeFindings(s),{...o,lastRunId:o.run},['target','status','severity','lastRunId'])};break;
    case 'finding show':result={finding:named(s.findings,args[0],'Finding')};break;
    case 'verify':case 'retest':return verifyFinding(root,args[0],{target:o.target,build:o.build,retest:key==='retest',signal:context.signal});
    case 'test list':result={checks:filter(s.checks,o,['target'])};break;
    case 'test show':result={check:named(s.checks,args[0],'Check')};break;
    case 'test save':result={check:await saveCheck(root,args[0])};break;
    case 'test run':need(o.all||args[0],'Specify a check ID or --all.');need(!(o.all&&args[0]),'Choose a check ID or --all.');return dispatchRun(root,'tests',{checkId:args[0],target:targetName},!!o.detach,context.signal,context.onProgress);
    case 'test bind':need(o.all||args[0],'Specify a check ID or --all.');need(o.file&&o.target,'Supply --file <binding.json> and --target.');result=await bindCheck(root,o.all?'all':args[0],o.target,loadJSON(o.file));break;
    case 'test export':need(o.all||args[0],'Specify a check ID or --all.');result=exportChecks(root,{checkId:args[0],all:o.all,target:o.target,out:o.out,force:o.force});break;
    case 'test disable':case 'test enable':result=await change(root,state=>{const c=named(state.checks,args[0],'Check');if(key==='test disable')need(o.reason,'--reason is required.');c.enabled=key==='test enable';c.disabledReason=c.enabled?null:o.reason;event(state,'check-setting',`${c.id}: ${c.enabled?'enabled':'disabled'}`,{reason:c.disabledReason});return {check:c};});break;
    case 'coverage':{
      const inv=await inventory(root);result={scope:'Specific saved HTTP behaviors only',complete:false,sourceFingerprint:inv.fingerprint,checks:s.checks.map(c=>({id:c.id,behavior:c.title,target:c.target,status:!c.enabled?'disabled':['failed','blocked'].includes(c.lastResult?.status)?c.lastResult.status:c.sourceFingerprint!==inv.fingerprint?'stale':c.lastResult?.status||'not-run',sourceChanged:c.sourceFingerprint!==inv.fingerprint,lastResult:c.lastResult})),unproven:s.findings.filter(f=>f.status==='simulated_unproven').map(f=>({id:f.id,title:f.title,simulation:true})),message:'A route is not fully covered just because one behavior on that route has a test.'};break;
    }
    case 'memory':case 'memory list':result=await recallMemory(root,{query:o.query,target:o.target});break;
    case 'memory show':{const packet=await recallMemory(root,{query:args[0],limit:1});result=packet.entries.find(e=>e.id===args[0]);need(result,'Memory record not found in this project.');result={kind:'memory-record',entry:result};break;}
    case 'memory forget':result=await forgetMemory(root,args[0]);break;
    case 'memory use':need(['on','off'].includes(args[0]),'Use memory use on or off.');result=await setMemory(root,args[0]==='on');break;
    case 'context':if(o.task!==undefined){result=await featureContext(root,{task:o.task,files:o.files,target:o.target});break;}need(!o.files,'Supply --task with --files.');result={project:s.project.name,engine:realEngine(s)?'docker':'mock',summary:readiness(root),memory:await recallMemory(root,{forAgent:true,limit:8,maxBytes:10000}),latestMonitor:monitorSummary(s),finding:o.finding?named(s.findings,o.finding,'Finding'):null,recentEvents:s.events.slice(-15),attention:s.checks.filter(c=>c.enabled&&['failed','blocked','stale'].includes(c.lastResult?.status)),next:readiness(root).next};break;
    case 'report':{
      const r=named(s.runs,o.run||s.runs.at(-1)?.id,'Run'),format=o.format||'json';need(['json','md'].includes(format),'Report format must be json or md.');
      const content=format==='json'?JSON.stringify(redact(r),null,2):`# Bypass run ${r.id}\n\nStatus: ${r.status}. Exit: ${r.exitCode}.\n\nAnalysis simulated: ${r.simulation}. Model calls: ${r.result?.modelCalls??0}.\n\n${r.result?.message||''}\n\n## Evidence\n\n\`\`\`json\n${JSON.stringify(redact(r.result),null,2)}\n\`\`\`\n`;
      if(o.out){const file=path.resolve(root,o.out);need(!fs.existsSync(file),'Report destination exists. Choose another filename.');atomic(file,content);result={path:file,format,runId:r.id};}else result={format,content};break;
    }
    case 'run list':result={runs:s.runs.map(({result,steps,...r})=>r)};break;
    case 'run show':result={run:named(s.runs,args[0],'Run')};break;
    case 'run watch':return watchRun(root,args[0],o.timeout?duration(o.timeout):300000,context.signal);
    case 'run stop':if(s.runs.find(r=>r.id===args[0])?.executionMode==='muse-host')return hostReviewStep(root,{id:args[0],action:'cancel'},context);result=await change(root,state=>{const r=named(state.runs,args[0],'Run');if(['queued','running'].includes(r.status))r.cancelRequested=true;return {runId:r.id,status:r.status,cancelRequested:r.cancelRequested};});break;
    case 'monitor add':{
      safeName(args[0]);need((o.runner||'local')==='local','Hosted cloud workers are not configured. Use --runner local.',3,{implemented:false});const everyMs=duration(o.every||'1h',10000);
      result=await change(root,state=>{const t=named(state.targets,targetName,'Target');scopeReady(t);need(!state.monitors.some(m=>m.name===args[0]),'Monitor name already exists.');const m={name:args[0],target:targetName,everyMs,runner:'local',enabled:true,createdAt:now(),nextRunAt:now()};state.monitors.push(m);return {monitor:m,worker:workerStatus(root),next:'bypass monitor worker --detach'};});break;
    }
    case 'monitor list':result={monitors:s.monitors,worker:workerStatus(root)};break;
    case 'monitor run':return runMonitor(root,args[0],context.signal);
    case 'monitor pause':case 'monitor resume':result=await change(root,state=>{const m=named(state.monitors,args[0],'Monitor');m.enabled=key==='monitor resume';if(m.enabled)scopeReady(named(state.targets,m.target,'Target'));return {monitor:m};});break;
    case 'monitor remove':result=await change(root,state=>{named(state.monitors,args[0],'Monitor');state.monitors=state.monitors.filter(m=>m.name!==args[0]);return {removed:args[0]};});break;
    case 'monitor worker':return startWorker(root,{detach:o.detach,once:o.once,stop:o.stop,signal:context.signal});
    case 'ci init':{
      need(!o.provider||o.provider==='github','Only GitHub Actions is supported.');named(s.targets,targetName,'Target');const file=path.join(root,'.github/workflows/bypass-security.yml');need(!fs.existsSync(file)||o.force,'Workflow exists; review before replacing with --force.');
      const exported=exportChecks(root,{all:true,target:targetName,force:o.force});
      const identities=s.identities.filter(i=>i.target===targetName);const envLines=[...new Set(identities.map(i=>i.secretEnv))].map(name=>`      ${name}: \${{ secrets.${name} }}`).join('\n');
      const workflow=`name: Bypass saved security checks\non:\n  workflow_dispatch:\n  pull_request:\npermissions:\n  contents: read\njobs:\n  regression:\n    runs-on: ubuntu-latest\n    timeout-minutes: 10\n    env:\n${envLines||'      BYPASS_CI: "true"'}\n    steps:\n      - uses: actions/checkout@v4\n      - uses: actions/setup-node@v4\n        with:\n          node-version: '22'\n      - name: Run exported checks (no model or Bypass account)\n        run: node --test tests/security/bypass/*.test.mjs\n`;
      atomic(file,workflow);result={workflow:file,tests:exported.files,notPublished:true,notes:['Review and commit generated files. Configure the named repository secrets.','Fork pull requests do not receive secrets; run authorized checks in a trusted workflow.','The local demo URL is not reachable on hosted GitHub runners. Bind a verified deployed target before enabling CI.']};break;
    }
    case 'demo status':result={demo:s.demo?demoConfig(root):null};break;
    case 'demo fix':case 'demo regress':case 'demo add-route':case 'demo reset':case 'demo stop':result=await updateDemo(root,key.split(' ')[1]);break;
    case '_run':return executeRun(root,args[0]);
    case '_demo-serve':await serveDemo(root);return null;
    default:throw new Fault(`Unknown operation: ${key}`);
  }
  return wrap(result);
}

async function integrate(key,args,o,working,{signal,onProgress}={}){
  const native=(phase,...args)=>{
    const operation=args[1],message=`Muse plugin ${operation}${operation==='install'?' — retaining the bundled runtime; this can take up to two minutes':''}`;
    const step={phase,operation,timeoutMs:120000};
    onProgress?.({...step,status:'started',message});
    const timer=setInterval(()=>onProgress?.({...step,status:'waiting',message:`Still waiting for ${message}`}),10000);
    return execFile('muse',args,{cwd:working,signal,killGroup:true,timeout:120000}).catch(error=>{
      if(error.details?.causeCode==='ENOENT')throw new Fault('Muse Code is not available on PATH. Install or update Muse Code, sign in through its account flow, then retry integration. Native integration was tested with Muse 1.4.13.',3,{reason:'host_unavailable'});
      throw error;
    }).finally(()=>clearInterval(timer));
  };
  if(key==='integrate status'){
    const r=await native('check','plugins','inspect','bypass','--json');let data;try{data=JSON.parse(r.stdout);}catch{data={message:r.stderr||r.stdout};}return outcome({integration:data,...museInstallState(data)},r.code===0?0:3);
  }
  if(key==='integrate remove'){
    need(args[0]==='muse','Only muse is supported.');const r=await native('install','plugins','remove','bypass','--json');return outcome({message:r.stdout||r.stderr},r.code===0?0:3);
  }
  const inspected=await native('check','plugins','inspect','bypass','--json');
  let existing;try{existing=JSON.parse(inspected.stdout);}catch{}
  const plugin=fs.existsSync(path.join(PACKAGE_ROOT,'../.muse-plugin/plugin.json'))?path.resolve(PACKAGE_ROOT,'..'):path.join(PACKAGE_ROOT,'plugin');
  if(inspected.code===0&&existing?.valid&&existing.record?.id==='bypass'&&(!o.replace||samePluginPackage(plugin,existing.record.cache_path))){
    return outcome({alreadyInstalled:true,installed:existing.record,...museInstallState(existing),
      message:`Bypass is already installed in Muse${existing.record.source?.path?` from ${existing.record.source.path}`:''}. No second installation is needed.`,
    });
  }
  need(fs.existsSync(path.join(plugin,'runtime/bin/bypass.mjs')),'The bundled Muse plugin runtime is missing. In the Bypass checkout, run npm run plugin:build, then retry.',3);
  const validation=await native('check','plugins','validate',plugin,'--json');need(validation.code===0,'Muse rejected plugin validation. Use a host with native plugins support (tested with Muse 1.4.13), update Muse if needed, then inspect the validation diagnostics and retry. The installed plugin has not been removed.',3,{validation:validation.stdout});
  const scope=o.scope||'project';need(['user','project'].includes(scope),'Scope must be user or project.');
  let replaced=false,replacementStarted=false;
  let installed,installationError;
  try{
    if(o.replace&&existing?.record?.id==='bypass'){
      replacementStarted=true;
      const removed=await native('install','plugins','remove','bypass','--json');
      need(removed.code===0,'Could not replace the existing Muse plugin. Run muse plugins inspect bypass for details.',3);replaced=true;
    }
    installed=await native('install','plugins','install',plugin,'--scope',scope,'--json');
  }catch(error){installationError=error;}
  if(installationError||installed.code!==0){
    let restored=false;
    if(replacementStarted&&existing.record.source?.path){
      // Removal can finish just before cancellation hides its result. Inspect
      // without the cancelled signal before deciding whether restoration is needed.
      if(!replaced){
        onProgress?.({phase:'restore',operation:'inspect',status:'started',timeoutMs:120000,message:'Checking the previous Muse plugin after interrupted replacement.'});
        try{
          const current=await execFile('muse',['plugins','inspect','bypass','--json'],{cwd:working,killGroup:true,timeout:120000});
          const value=JSON.parse(current.stdout);
          restored=current.code===0&&value.valid&&value.record?.id==='bypass'&&value.record.source?.path===existing.record.source.path&&value.record.package_sha256===existing.record.package_sha256;
        }catch{}
      }
      if(!restored){
        onProgress?.({phase:'restore',operation:'install',status:'started',timeoutMs:120000,message:'Restoring the previous Muse plugin after an interrupted or failed installation.'});
        // Rollback must still run after cancellation. It restores the user's prior
        // source through Muse, with its own bound and without granting runtime trust.
        try{const rollback=await execFile('muse',['plugins','install',existing.record.source.path,'--scope',scope,'--json'],{cwd:working,killGroup:true,timeout:120000});restored=rollback.code===0;}catch{}
      }
    }
    let diagnostic;try{diagnostic=JSON.parse(installed?.stdout).error?.message;}catch{}
    const reason=redact(String(installationError?.message||diagnostic||installed?.stderr||'Run muse plugins inspect bypass for details.')).replace(/[\x00-\x1f\x7f]/g,' ').slice(0,500);
    throw new Fault(`Muse plugin installation did not finish: ${reason}${replacementStarted?restored?' Previous plugin source restored; inspect its native approval state.':' Previous plugin could not be restored automatically; inspect Muse before retrying.':''}`,installationError?.code===130?130:3,{previousPluginRestored:restored,previousSource:existing?.record?.source?.path});
  }
  if(replaced&&existing.record.enabled===false){
    const disabled=await native('verify','plugins','disable','bypass','--json');
    need(disabled.code===0,'The new package was installed, but Muse could not restore its disabled state. Open /plugins and disable Bypass before proceeding.',3);
  }
  const confirmation=await native('verify','plugins','inspect','bypass','--json');
  let confirmed;try{confirmed=JSON.parse(confirmation.stdout);}catch{}
  need(confirmation.code===0&&confirmed?.valid,'Muse did not confirm a valid installation. Run bypass integrate status for the current state.',3);
  const expectedVersion=loadJSON(path.join(plugin,'.muse-plugin/plugin.json')).version;
  need(confirmed.record?.version===expectedVersion,`Muse reports Bypass ${confirmed.record?.version||'an unknown version'} after installing ${expectedVersion}. Installation is not verified. Rerun the public Muse installer before continuing.`,3);
  return outcome({plugin,scope,installed:JSON.parse(installed.stdout),...museInstallState(confirmed),message:'Bypass is installed. Full tools, commands, security memory and the session hook are included. Muse permission review is the next step.'});
}
