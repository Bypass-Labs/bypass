import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import net from 'node:net';
import { execute, readiness } from './service.mjs';
import { read, change, event } from './store.mjs';
import { terminalRun, summarizeRun } from './run-state.mjs';
import { need, named, outcome, delay, abortFault } from './util.mjs';
import { projectPath } from './project-selection.mjs';

const action=(label,tool,args={})=>({label,tool,arguments:args});
function nextForRun(run){
  if(run.status==='awaiting_host')return action('Continue planning and testing in Muse','bypass_review_step',{id:run.id,action:'status'});
  if(!terminalRun(run))return action('Follow this review', 'bypass_watch_run',{id:run.id,after:run.steps?.length||0});
  if(run.status==='failed'||run.status==='interrupted')return action('Inspect the saved failure before retrying','bypass_run',{id:run.id});
  if(run.status==='cancelled')return action('Review saved progress','bypass_run',{id:run.id});
  if(run.result?.confirmed?.length||run.result?.findings?.length)return action('Inspect findings and their evidence','bypass_findings',{run:run.id});
  if(run.kind!=='scan')return action('Inspect saved regression results','bypass_tests');
  return action('Read the bounded review result','bypass_run',{id:run.id});
}
export function progressSnapshot(root,run,after=0){
  const steps=run.steps||[],terminal=terminalRun(run);
  return {run:summarizeRun(run),terminal,cursor:steps.length,events:steps.slice(after),
    done:[...new Set(steps.map(s=>s.stage))].filter(stage=>run.status==='completed'||stage!==run.stage),now:terminal?`${run.status}: ${run.result?.message||'execution finished'}`:steps.at(-1)?.message||'Queued for execution',
    next:nextForRun(run),evidence:path.join(root,'.bypass/runs',run.id+'.json'),
    meaning:run.exitCode===1?'Observed vulnerability or regression; this is a security result, not a tool failure.':run.exitCode===3?'Incomplete or bounded evidence; not a clean bill of health.':terminal?'Execution finished; inspect its evidence and coverage.':'Still running; acceptance is not a passing result.'};
}
export async function runProgress(root,id,{after=0,waitMs=10000,signal,onProgress}={}){
  const deadline=Date.now()+waitMs;
  while(true){
    if(signal?.aborted)throw abortFault(signal);
    const run=named(read(root).runs,id,'Run');
    if(terminalRun(run)||(run.steps?.length||0)>after||Date.now()>=deadline){
      const progress=progressSnapshot(root,run,after);
      for(const step of progress.events)onProgress?.(step);
      return outcome({kind:'run-progress',...progress});
    }
    if(run.pid){try{process.kill(run.pid,0);}catch(error){if(error.code==='ESRCH'){
      // Reuse the CLI's interrupted-run recovery, with a bounded watch.
      await execute('run watch',[id],{project:root,timeout:'1ms'},{signal}).catch(()=>{});continue;
    }}}
    try{await delay(Math.min(250,Math.max(1,deadline-Date.now())),undefined,{signal});}catch{throw abortFault(signal);}
  }
}
export function pluginDashboard(root){
  if(!root)return outcome({kind:'plugin-dashboard',selectedRepository:null,done:[],now:'Choose your application or try an isolated demo',next:action('Connect your application','bypass_onboarding'),alternatives:[action('Run the real local demo','bypass_demo_start',{kind:'real'}),action('Browse available actions','bypass_help')]});
  const state=read(root),status=readiness(root),run=state.runs.findLast(r=>!terminalRun(r))||state.runs.at(-1);
  const done=['Repository connected',...(status.model?['Model profile selected ('+status.model.connection+')']:[]),...(status.target?.ownership==='verified'?['App ownership verified']:[]),...(status.ready.authorized?['Testing scope authorized']:[]),...(status.checks.total?[`${status.checks.total} saved regression checks`]:[])];
  return outcome({kind:'plugin-dashboard',selectedRepository:root,application:status.project.name,app:status.target,engine:status.engine,model:status.model,done,
    now:run&&!terminalRun(run)?run.steps?.at(-1)?.message||'Review queued':run?`${run.status}: ${run.result?.message||'Latest operation finished'}`:'Ready to continue setup or request a review',
    next:run?nextForRun(run):action('Continue setup','bypass_onboarding'),latestRun:run?progressSnapshot(root,run,run.steps?.length||0):null,
    findings:status.findings,checks:status.checks,worker:status.worker,monitoring:{schedules:state.monitors.length,enabled:state.monitors.filter(m=>m.enabled).length,running:status.worker.status==='running'},
    recentEvents:state.events.slice(-8),actions:[action('Review source or app','bypass_onboarding'),action('Saved tests','bypass_tests'),action('Security memory','bypass_memory'),action('All available actions','bypass_help')]});
}
export function validateProjectOutput(root,relative){
  need(!path.isAbsolute(relative)&&!relative.split(/[\\/]/).includes('..'),'Output path must stay inside the selected repository.');
  let current=root;
  for(const part of relative.split(/[\\/]/).filter(Boolean)){
    current=path.join(current,part);
    if(fs.existsSync(current)||(()=>{try{return fs.lstatSync(current).isSymbolicLink();}catch{return false;}})())need(!fs.lstatSync(current).isSymbolicLink(),'Output path must not traverse a symbolic link.');
  }
}
export async function startPluginDemo(cwd,previous,args,signal){
  need(!args.model,'Choose the Muse model in the host session. The plugin never overrides the active model or uses a separate API profile.');
  const kind=args.kind||'real';
  const root=args.dir?projectPath(args.dir,cwd):fs.mkdtempSync(path.join(os.tmpdir(),'bypass-muse-demo-'));
  need(!fs.existsSync(root)||(fs.statSync(root).isDirectory()&&fs.readdirSync(root).length===0),'Choose an empty demo directory. Existing application files are unchanged.');
  let port=args.port;
  if(!port){const server=net.createServer();await new Promise((resolve,reject)=>{server.once('error',reject);server.listen(0,'127.0.0.1',resolve);});port=server.address().port;await new Promise(resolve=>server.close(resolve));}
  const result=await execute(kind==='real'?'poc start':'demo start',[],{dir:root,port,project:undefined},{signal});
  return {...result,kind:'plugin-demo',demoMode:kind,fixtureOnly:true,
    nextAction:kind==='real'?action('Review fixture setup with the active Muse session','bypass_onboarding'):action('Preview the seeded review','bypass_scan',{mode:'combined'}),
    journey:['Review source and HTTP behavior','Inspect account-access evidence','Apply fixture fix and retest','Export and replay saved tests','Reintroduce the fixture bug and catch it with zero model calls','Run one monitor tick, restore the fix, and stop the fixture'],
    message:kind==='real'?'Isolated app selected in Muse. The active Muse session plans the review; Bypass executes real source reads and scoped HTTP controls. No separate model key is needed.':'Isolated preview selected in Muse. Discovery is seeded; HTTP proof and saved replay are real. Zero Bypass analysis model calls; Muse chat still uses its own provider.'};
}
export async function controlPluginDemo(root,actionName,{signal}={}){
  const state=read(root);need(state.demo||state.poc,'This action is only available for a generated Bypass fixture, never a customer application.');
  if(actionName==='status')return outcome({fixtureOnly:true,root,kind:state.poc?'real':'preview',fixture:state.poc||state.demo,dashboard:pluginDashboard(root)});
  if(actionName==='stop'){
    for(const run of state.runs.filter(r=>!terminalRun(r)))await execute('run stop',[run.id],{project:root});
    for(const monitor of state.monitors.filter(m=>m.enabled))await execute('monitor pause',[monitor.name],{project:root});
    await execute('monitor worker',[],{project:root,stop:true});
    return execute(state.poc?'poc stop':'demo stop',[],{project:root},{signal});
  }
  if(!state.poc)return execute('demo '+actionName,[],{project:root},{signal});
  need(['fix','regress','reset'].includes(actionName),'For a new route in the real POC, use Muse coding tools in the returned fixture directory, then add a probe. The canned add-route action belongs to the offline preview.');
  const file=path.join(root,'policy.mjs');validateProjectOutput(root,'policy.mjs');
  const fixed=actionName==='fix';
  fs.writeFileSync(file,`export function mayReadInvoice(account, invoice) { return ${fixed?'account === invoice.ownerId':'Boolean(account)'}; }\n`);
  await change(root,s=>{event(s,'fixture-change',`Real POC fixture ${actionName}; policy source changed. Retest required.`);});
  return outcome({fixtureOnly:true,action:actionName,file,fixed,verified:false,message:'Fixture source changed and will reload on the next request. Use bypass_retest or bypass_run_tests to observe the behavior.'});
}
export function operationFailed(result){
  if(result?.plan)return false;
  const code=result?.exitCode??0;
  if(code===0)return false;
  if(code===1&&(result?.verification?.status==='failed'||result?.run?.status==='completed'))return false;
  return true;
}
