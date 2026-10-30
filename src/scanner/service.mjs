import fs from 'node:fs';
import path from 'node:path';
import { executionMode, hostAI } from '../execution-mode.mjs';
import { rootFrom, read } from '../store.mjs';
import { outcome, need, abortFault, delay } from '../util.mjs';
import { validateJSON } from '../schema.mjs';
import { manifest, scannerCapabilities, unavailable, validateOperation } from './contracts.mjs';
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
  if(operation==='report')return result.artifacts?.[0]?{tool:'bypass_discover_artifact',arguments:{run,path:result.artifacts[0].path,offset:0}}:null;
  if(operation==='signals'&&result.nextCursor>=0)return {tool:'bypass_discover_signals',arguments:{run,cursor:result.nextCursor}};
  return terminal(result.run)?{tool:'bypass_discover_report',arguments:{run,format:'md'}}:{tool:'bypass_discover_status',arguments:{run}};
}

export function discoveryPlan(options={},config={}) {
  return {kind:'scanner-plan',status:'ready',protocolVersion:manifest.protocolVersion,executionMode:executionMode(),
    detector:'codeql',implementedStages:['discovery'],evaluation:'not_run',modelCalls:0,
    includeRules:config.includeRules??(options.rule?csv(options.rule):[]),excludeRules:config.excludeRules??(options['exclude-rule']?csv(options['exclude-rule']):[]),
    languages:config.languages?.length?config.languages:options.languages?csv(options.languages):'local source detection',
    scope:{...Object.fromEntries(Object.entries(scopeFlags).map(([flag,name])=>[name,config[name]??options[flag]??false])),
      defaultExclusions:manifest.sourceScope.categories,buildContext:'retained',artifact:'analysis-scope.json'},
    prerequisites:['Docker installed/running','An explicitly connected source repository','First-use image preparation downloads the pinned bundle and toolchains'],
    message:'CodeQL discovery emits unevaluated signals. Rules use exact IDs; exclusions win. Default queries are upstream security-extended. No LLM settings or calls are required. Scan network is off except explicitly configured build workers.'};
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
  for(const [flag,name] of Object.entries(scopeFlags))if(options[flag]!==undefined)config[name]=options[flag];
  validateJSON(manifest.schemas.config,config,'scanner configuration');
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

function runResources(root,run) {
  need(/^scan_[a-f0-9]{24}$/.test(run||''),'Invalid scanner run ID.',2);
  const base=scannerOutput(root),filename=path.join(base,run,'manifest.json');
  need(fs.existsSync(filename),'Scanner run not found in the selected project.',2);
  for(const file of [path.join(base,run),filename])need(!fs.lstatSync(file).isSymbolicLink(),'Scanner artifacts must not be symlinked.',2);
  const state=JSON.parse(fs.readFileSync(filename,'utf8'));
  validateJSON(manifest.schemas.config,state.config,'saved scanner configuration');
  return {...defaultResources,...state.config.resources};
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
  if(session&&!reuse&&((sarif!==undefined&&session.sarif!==sarif)||JSON.stringify(session.resources)!==JSON.stringify(resources))){
    need(![...session.runs.values()].some(run=>!terminal(run)),'A scanner is active with different input/resource settings; finish or cancel it first.',3);
    clearInterval(session.timer);await session.client.close();sessions.delete(root);session=null;
  }
  if(!session){
    const factory=context.scannerConnect||connectScanner;
    const client=await factory({root,sarif,resources,signal:context.signal,onProgress:context.onProgress});
    session={client,sarif,resources,runs:new Map(),owned:new Set(),busy:false};sessions.set(root,session);
    session.timer=setInterval(async()=>{
      if(session.busy||session.client.failure)return;
      session.busy=true;
      try{
        for(const [id,previous] of session.runs){
          if(terminal(previous))continue;
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
    await session.client.pumpBuild?.(result.run);
    if(result.run.phase!==phase){phase=result.run.phase;context.onProgress?.({stage:'scanner',message:`CodeQL ${phase} · ${result.run.signalCount} unevaluated signals`});}
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
    const diagnostics=await (key==='scanner doctor'?scannerDoctor:prepareScanner)(context);
    return outcome({kind:'scanner-diagnostics',...diagnostics,modelCalls:0},diagnostics.status==='blocked'?3:0);
  }
  const host=executionMode()==='muse-host', ai=host?hostAI():{mode:'deterministic',reasoning:'No LLM is used for CodeQL discovery'};
  if(key==='discover'&&options.plan){
    const base=path.resolve(options.project||context.cwd||process.cwd());
    return outcome({plan:discoveryPlan(options,configuration(base,options).config),ai});
  }
  const operation=key==='scanner rules'?'rules':key==='discover'?'start':key.slice('discover '.length);
  if(operation==='capabilities'){
    // Inspect only: no source selection, image build, or provider access.
    const diagnostics=await scannerDoctor(context);
    return outcome({...scannerCapabilities(diagnostics.image.available),ai});
  }
  if(['next_task','evidence','submit'].includes(operation)){
    const input={run:args[0],...Object.fromEntries(['task','sourceRevision','result','operation','arguments'].filter(name=>options[name]!==undefined).map(name=>[name,options[name]]))};
    validateOperation(operation,input);return outcome({...unavailable(operation),ai},3);
  }
  if(operation==='rules'){
    const input=Object.fromEntries(['language','query','cursor','limit'].filter(name=>options[name]!==undefined).map(name=>[name,['cursor','limit'].includes(name)?Number(options[name]):options[name]]));
    validateOperation(operation,input);
    const client=await (context.scannerConnect||connectScanner)({signal:context.signal,onProgress:context.onProgress});
    try{return outcome({...await client.call('rules',input,{signal:context.signal}),ai});}finally{await client.close();}
  }
  const root=selectedRoot(options,context);
  let input, resources, sarif;
  if(operation==='start'){
    need(!options.detector||options.detector==='codeql','This implementation supports only the codeql detector.',2);
    const configured=configuration(root,options);resources=configured.resources;
    if(options.sarif){sarif=path.resolve(root,options.sarif);need(fs.statSync(sarif).isFile()&&!fs.lstatSync(sarif).isSymbolicLink(),'SARIF input must be a regular file.',2);}
    input={detector:'codeql',config:configured.config,executionMode:executionMode(),importSarif:!!sarif};
  }else{
    resources=runResources(root,args[0]);
    input={run:args[0],...Object.fromEntries(['format','path','offset','cursor','limit'].filter(name=>options[name]!==undefined).map(name=>[name,['offset','cursor','limit'].includes(name)?Number(options[name]):options[name]]))};
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
    return outcome({...result,ai,...(result.run?{runId:result.run.id}:{}),...(nextAction?{nextAction}:{})},code);
  }finally{
    if(!host){clearInterval(session.timer);await session.client.close();sessions.delete(root);}
  }
}
