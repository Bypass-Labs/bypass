import fs from 'node:fs';
import path from 'node:path';
import { executionMode, hostAI } from '../execution-mode.mjs';
import { rootFrom, read } from '../store.mjs';
import { outcome, need, abortFault, delay } from '../util.mjs';
import { validateJSON } from '../schema.mjs';
import { manifest, scannerCapabilities, validateOperation } from './contracts.mjs';
import { scannerDoctor, prepareScanner, connectScanner, scannerOutput, defaultResources } from './runtime.mjs';

const sessions = new Map();
const connecting = new Map();
const terminal = run => ['completed','incomplete','failed','cancelled','interrupted'].includes(run?.status);
const csv = value => Array.isArray(value) ? value : String(value).split(',').map(item=>item.trim()).filter(Boolean);
const scopeFlags = {'include-tests':'includeTests','include-examples':'includeExamples','include-generated':'includeGenerated'};

function continuation(operation,input,result) {
  if(operation==='artifact')return result.nextOffset>=0?{tool:'bypass_discover_artifact',arguments:{run:input.run,path:input.path,offset:result.nextOffset}}:null;
  if(!result.run)return null;
  const run=result.run.id;
  if(result.task)return {tool:'bypass_discover_evidence',arguments:{run,task:result.task.id,operation:'inventory',arguments:{limit:50}}};
  if(result.run.status==='awaiting_reasoning')return {tool:'bypass_discover_next_task',arguments:{run}};
  if(operation==='report')return result.artifacts?.[0]?{tool:'bypass_discover_artifact',arguments:{run,path:result.artifacts[0].path,offset:0}}:null;
  if(operation==='signals'&&result.nextCursor>=0)return {tool:'bypass_discover_signals',arguments:{run,cursor:result.nextCursor}};
  return terminal(result.run)?{tool:'bypass_discover_report',arguments:{run,format:'md'}}:{tool:'bypass_discover_status',arguments:{run}};
}

export function discoveryPlan(options={},config={}) {
  return {kind:'scanner-plan',status:'ready',protocolVersion:manifest.protocolVersion,executionMode:executionMode(),
    detector:config.detectors?.length===2?'both':config.detectors?.[0]==='policy'?'policy':'sast',detectors:config.detectors||['codeql'],implementedStages:['discovery'],evaluation:'not_run',modelCalls:0,
    includeRules:config.includeRules??(options.rule?csv(options.rule):[]),excludeRules:config.excludeRules??(options['exclude-rule']?csv(options['exclude-rule']):[]),
    includePolicies:config.includePolicies||[],excludePolicies:config.excludePolicies||[],
    reasoning:config.detectors?.includes('policy')?{executor:executionMode(),apiProfileRequired:executionMode()!=='muse-host',hostUsage:'unavailable'}:{executor:'none'},
    languages:config.languages?.length?config.languages:options.languages?csv(options.languages):'local source detection',
    scope:{...Object.fromEntries(Object.entries(scopeFlags).map(([flag,name])=>[name,config[name]??options[flag]??false])),
      defaultExclusions:manifest.sourceScope.categories,buildContext:'retained',artifact:'analysis-scope.json'},
    prerequisites:['Docker installed/running','An explicitly connected source repository',config.detectors?.includes('codeql')||!config.detectors?'Pinned CodeQL image; first preparation downloads the bundle and toolchains':'Lightweight Python evidence runtime; no CodeQL download',
      ...(config.detectors?.includes('policy')?[executionMode()==='muse-host'?'Active Muse session supplies reasoning':'Configured standalone LLM API profile']:[])],
    message:'SAST and policy selections are independent; exact-ID exclusions win. SAST requires no LLM. Policy reasoning uses the active Muse session or an explicit standalone API profile. Planning sends no model requests.'};
}

function configuration(root,options) {
  let config={};
  if(options.config){
    const filename=path.resolve(root,options.config);
    need(fs.statSync(filename).isFile()&&!fs.lstatSync(filename).isSymbolicLink(),'Scanner configuration must be a regular JSON file.',2);
    config=JSON.parse(fs.readFileSync(filename,'utf8'));
  }
  if(options.languages!==undefined)config.languages=csv(options.languages);
  if(options.rule!==undefined)config.includeRules=csv(options.rule);
  if(options['exclude-rule']!==undefined)config.excludeRules=csv(options['exclude-rule']);
  if(options.policy!==undefined)config.includePolicies=csv(options.policy);
  if(options['exclude-policy']!==undefined)config.excludePolicies=csv(options['exclude-policy']);
  if(options.detector!==undefined){
    need(Object.hasOwn(manifest.detectorAliases,options.detector),'Choose sast, policy, or both (codeql is an alias for sast).',2);
    config.detectors=manifest.detectorAliases[options.detector];
  }
  config.detectors??=['codeql'];
  for(const [flag,name] of Object.entries(scopeFlags))if(options[flag]!==undefined)config[name]=options[flag];
  validateJSON(manifest.schemas.config,config,'scanner configuration');
  config.detectors=[...new Set(config.detectors.map(d=>d==='sast'?'codeql':d))];
  need(config.detectors.includes('codeql')||(options.rule===undefined&&options['exclude-rule']===undefined),'Explicit SAST rule flags require the sast detector.',2);
  need(config.detectors.includes('policy')||(options.policy===undefined&&options['exclude-policy']===undefined),'Explicit policy rule flags require the policy detector.',2);
  if(config.detectors.includes('policy')&&!config.policyCatalogs?.length){
    const catalog=JSON.parse(fs.readFileSync(new URL('../../scanner/policies/catalog.json',import.meta.url),'utf8'));
    const ids=catalog.policies.map(p=>p.id);
    for(const id of [...(config.includePolicies||[]),...(config.excludePolicies||[])])need(ids.includes(id),`Unknown policy ID: ${id}. Use scanner policies.`,2);
    const selected=ids.filter(id=>(!config.includePolicies?.length||config.includePolicies.includes(id))&&!config.excludePolicies?.includes(id));
    need(selected.length,'Policy selection is empty.',2);
  }
  const resources={...defaultResources,...config.resources};
  need(resources.memoryMb>=resources.ramMb+1024,'Container memory must exceed CodeQL RAM by at least 1024 MB.',2);
  return {config,resources};
}

function selectedRoot(options,context) {
  const root=rootFrom(options.project||context.cwd);
  const state=read(root);
  need(state.project.repository.kind!=='app','CodeQL requires a selected source repository, not an app-only profile.',2);
  scannerOutput(root);
  return root;
}

function runConfiguration(root,run) {
  need(/^scan_[a-f0-9]{24}$/.test(run||''),'Invalid scanner run ID.',2);
  const base=scannerOutput(root),filename=path.join(base,run,'manifest.json');
  need(fs.existsSync(filename),'Scanner run not found in the selected project.',2);
  for(const file of [path.join(base,run),filename])need(!fs.lstatSync(file).isSymbolicLink(),'Scanner artifacts must not be symlinked.',2);
  const state=JSON.parse(fs.readFileSync(filename,'utf8'));
  validateJSON(manifest.schemas.config,state.config,'saved scanner configuration');
  return {config:{...state.config,detectors:state.config.detectors||['codeql']},resources:{...defaultResources,...state.config.resources}};
}

async function connection(root,options,context,resources,sarif,reuse=false) {
  // Concurrent Muse calls must share a single owned container per project.
  while(connecting.has(root))await connecting.get(root).catch(()=>{});
  const pending=openConnection(root,options,context,resources,sarif,reuse);
  connecting.set(root,pending);
  try{return await pending;}finally{connecting.delete(root);}
}

async function openConnection(root,options,context,resources,sarif,reuse) {
  let session=sessions.get(root);
  if(session?.client.failure){clearInterval(session.timer);sessions.delete(root);session=null;}
  if(session&&!reuse&&((sarif!==undefined&&session.sarif!==sarif)||session.detector!==context.detector||JSON.stringify(session.resources)!==JSON.stringify(resources))){
    need(![...session.runs.values()].some(run=>!terminal(run)),'A scanner is active with different input/resource settings; finish or cancel it first.',3);
    clearInterval(session.timer);await session.client.close();sessions.delete(root);session=null;
  }
  if(!session){
    const factory=context.scannerConnect||connectScanner;
    const client=await factory({root,sarif,resources,signal:context.signal,onProgress:context.onProgress,detector:context.detector});
    session={client,sarif,resources,detector:context.detector,runs:new Map(),owned:new Set(),busy:false};sessions.set(root,session);
    session.timer=setInterval(async()=>{
      if(session.busy||session.client.failure)return;
      session.busy=true;
      try{
        for(const [id,previous] of session.runs){
          if(terminal(previous)||previous.status==='awaiting_reasoning')continue;
          const result=await session.client.call('status',{run:id});
          if(result.run){session.runs.set(id,result.run);if(session.owned.has(id))await session.client.pumpBuild?.(result.run);}
        }
      }catch{/* A subsequent status call reports connection loss and permits recovery. */}
      finally{session.busy=false;}
    },500);
    session.timer.unref();
  }
  return session;
}

export async function closeScannerSessions() {
  await Promise.allSettled([...connecting.values()]);
  const current=[...sessions.values()];sessions.clear();
  await Promise.allSettled(current.map(async session=>{clearInterval(session.timer);await session.client.close();}));
}

async function waitForRun(session,result,context) {
  const id=result.run.id;
  let phase='';
  while(!terminal(result.run)){
    if(context.signal?.aborted){
      await session.client.stopBuilds?.(id);
      await session.client.call('cancel',{run:id});
      for(let i=0;i<40;i++){
        result=await session.client.call('status',{run:id});
        if(terminal(result.run))break;
        await delay(150);
      }
      return {...result,status:'cancelled'};
    }
    if(result.run.status==='awaiting_reasoning'){
      const {runAPIDriver}=await import('./api-driver.mjs');
      return runAPIDriver(context.profileState,{client:session.client,run:result.run,limits:context.policyLimits,
        signal:context.signal,onProgress:context.onProgress,...(context.scannerSessionFactory?{sessionFactory:context.scannerSessionFactory}:{})});
    }
    await session.client.pumpBuild?.(result.run);
    if(result.run.phase!==phase){phase=result.run.phase;context.onProgress?.({stage:'scanner',message:`Discovery ${phase} · ${result.run.signalCount} unevaluated signals`});}
    await delay(400);
    result=await session.client.call('status',{run:id});
    if(result.status==='error')break;
    session.runs.set(id,result.run);
  }
  return result;
}

export async function scannerService(key,args=[],options={},context={}) {
  if(context.signal?.aborted)throw abortFault(context.signal);
  if(key==='scanner doctor'||key==='scanner prepare'){
    need(options.detector===undefined||Object.hasOwn(manifest.detectorAliases,options.detector),'Choose sast, policy, or both.',2);
    const detector=options.detector==='policy'?'policy':'codeql';
    const diagnostics=await (key==='scanner doctor'?scannerDoctor:prepareScanner)({...context,detector});
    return outcome({kind:'scanner-diagnostics',...diagnostics,modelCalls:0},diagnostics.status==='blocked'?3:0);
  }
  const host=executionMode()==='muse-host', ai=host?hostAI():{mode:'deterministic',reasoning:'No LLM is used for CodeQL discovery'};
  if(key==='discover'&&options.plan){
    const base=path.resolve(options.project||context.cwd||process.cwd());
    return outcome({plan:discoveryPlan(options,configuration(base,options).config),ai});
  }
  const operation=key==='scanner policies'?'policies':key==='scanner rules'?'rules':key==='discover'?'start':key.slice('discover '.length);
  if(operation==='policies'){
    const catalog=JSON.parse(fs.readFileSync(new URL('../../scanner/policies/catalog.json',import.meta.url),'utf8'));
    validateJSON(manifest.schemas.policyCatalog,catalog,'policy catalog');
    const query=(options.query||'').toLowerCase();
    return outcome({protocolVersion:manifest.protocolVersion,status:'ready',operation,modelCalls:0,
      policies:catalog.policies.filter(p=>(p.id+' '+p.title).toLowerCase().includes(query)),ai});
  }
  if(operation==='capabilities'){
    // Inspect only: no source selection, image build, or provider access.
    const diagnostics=await scannerDoctor(context);
    return outcome({...scannerCapabilities(diagnostics.image.available),ai});
  }
  if(operation==='rules'){
    const input=Object.fromEntries(['language','query','cursor','limit'].filter(name=>options[name]!==undefined).map(name=>[name,['cursor','limit'].includes(name)?Number(options[name]):options[name]]));
    validateOperation(operation,input);
    const client=await (context.scannerConnect||connectScanner)({signal:context.signal,onProgress:context.onProgress});
    try{return outcome({...await client.call('rules',input,{signal:context.signal}),ai});}finally{await client.close();}
  }
  const root=selectedRoot(options,context);
  let input, resources, sarif,config;
  if(operation==='start'){
    const configured=configuration(root,options);resources=configured.resources;config=configured.config;
    if(options.sarif){sarif=path.resolve(root,options.sarif);need(fs.statSync(sarif).isFile()&&!fs.lstatSync(sarif).isSymbolicLink(),'SARIF input must be a regular file.',2);}
    input={config,executionMode:executionMode(),importSarif:!!sarif};
  }else{
    ({config,resources}=runConfiguration(root,args[0]));
    input={run:args[0],...Object.fromEntries(['format','path','offset','cursor','limit','task','sourceRevision','result','operation','arguments'].filter(name=>options[name]!==undefined).map(name=>[name,['offset','cursor','limit'].includes(name)?Number(options[name]):options[name]]))};
  }
  context={...context,detector:config.detectors.includes('codeql')?'codeql':'policy'};
  if(config.detectors.includes('policy')&&!host&&['start','resume'].includes(operation)){
    const {standaloneProfile}=await import('./api-driver.mjs');
    context.profileState=read(root);standaloneProfile(context.profileState);
    context.policyLimits=config.policyLimits;
  }
  validateOperation(operation,input);
  const session=await connection(root,options,context,resources,sarif,!['start','resume'].includes(operation));
  try{
    if(operation==='cancel')await session.client.stopBuilds?.(args[0]);
    let result=await session.client.call(operation,input,{signal:context.signal});
    if(result.run){
      session.runs.set(result.run.id,result.run);
      if(['start','resume'].includes(operation))session.owned.add(result.run.id);
      if(session.owned.has(result.run.id))await session.client.pumpBuild?.(result.run);
    }
    if(!host&&['start','resume'].includes(operation)&&result.run)result=await waitForRun(session,result,context);
    const code=result.status==='cancelled'?130:['incomplete','failed','interrupted','error','not_implemented'].includes(result.status)?3:0;
    const nextAction=continuation(operation,input,result);
    const executionAI=config.detectors.includes('policy')&&!host?{mode:'standalone-api',reasoning:'Policy discovery uses the explicitly configured provider; source hypotheses remain unevaluated.'}:ai;
    return outcome({...result,ai:executionAI,...(result.run?{runId:result.run.id}:{}),...(nextAction?{nextAction}:{})},code);
  }finally{
    if(!host){clearInterval(session.timer);await session.client.close();sessions.delete(root);}
  }
}
