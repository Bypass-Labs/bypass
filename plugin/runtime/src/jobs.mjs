import fs from 'node:fs';
import { terminalRun } from './run-state.mjs';
import path from 'node:path';
import { spawn } from 'node:child_process';
import { read, change, atomic, event } from './store.mjs';
import { CLI } from './demo.mjs';
import { createRun, executeRun } from './engine.mjs';
import { need, now, named, delay, outcome, abortFault } from './util.mjs';

export async function dispatchRun(root,kind,options={},detach=false,signal,onProgress){
  const run=await createRun(root,kind,options);
  if(!detach)return executeRun(root,run.id,signal,onProgress);
  const file=path.join(root,'.bypass',`${run.id}.log`),fd=fs.openSync(file,'a',0o600);
  const child=spawn(process.execPath,[CLI,'_run','--project',root,run.id],{detached:true,stdio:['ignore',fd,fd],env:process.env});
  child.unref();fs.closeSync(fd);
  await change(root,s=>{named(s.runs,run.id,'Run').pid=child.pid;});
  return outcome({runId:run.id,status:'accepted',pid:child.pid,message:'Accepted for background execution; this is not a passing result.',next:`bypass run watch ${run.id}`});
}
export async function watchRun(root,runId,timeoutMs=300000,signal){
  const deadline=Date.now()+timeoutMs;
  while(true){
    if(signal?.aborted)throw abortFault(signal);
    const run=named(read(root).runs,runId,'Run');
    if(terminalRun(run))return outcome({run},run.exitCode??3);
    if(run.pid){try{process.kill(run.pid,0);}catch(e){if(e.code==='ESRCH'){
      await change(root,s=>{Object.assign(named(s.runs,runId,'Run'),{status:'interrupted',exitCode:3,finishedAt:now()});});continue;
    }}}
    need(Date.now()<deadline,'Run is still active; use run show or watch again.',3,{runId});try{await delay(200,undefined,{signal});}catch{throw abortFault(signal);}
  }
}
export async function runMonitor(root,name,signal){
  const monitor=named(read(root).monitors,name,'Monitor');
  need(monitor.runner==='local','Cloud monitoring is not configured. Use a local worker for this skeleton.',3);
  const result=await dispatchRun(root,'monitor',{target:monitor.target},false,signal);
  await change(root,s=>{const m=named(s.monitors,name,'Monitor');m.lastRunId=result.run.id;m.lastRunAt=now();m.nextRunAt=new Date(Date.now()+m.everyMs).toISOString();event(s,'monitor-result',`${m.name}: ${result.run.result.empty?'no saved checks':result.exitCode===0?'passed':result.exitCode===1?'regression detected':'blocked'}`,{runId:result.run.id,monitor:m.name});});
  return result;
}
export async function startWorker(root,{detach=false,once=false,stop=false,signal}={}){
  if(signal?.aborted)throw abortFault(signal);
  const file=path.join(root,'.bypass/worker.json');
  if(stop){if(fs.existsSync(file)){const state=JSON.parse(fs.readFileSync(file,'utf8'));state.stopRequested=true;atomic(file,state);}return outcome({message:'Stop requested. Local worker will exit after its current check.'});}
  if(detach){
    if(fs.existsSync(file)){const w=JSON.parse(fs.readFileSync(file,'utf8'));if(w.status==='running'&&Date.now()-Date.parse(w.heartbeatAt)<10000)return outcome({message:'Worker is already active.',worker:w});}
    const log=fs.openSync(path.join(root,'.bypass/worker.log'),'a',0o600);
    const child=spawn(process.execPath,[CLI,'monitor','worker','--project',root],{detached:true,stdio:['ignore',log,log],env:process.env});child.unref();fs.closeSync(log);
    for(let i=0;i<30;i++){await delay(100);if(fs.existsSync(file)){const w=JSON.parse(fs.readFileSync(file,'utf8'));if(w.pid===child.pid)return outcome({message:'Local monitor worker is running. This machine must remain awake.',worker:w});}}
    throw Object.assign(new Error('Worker did not start. Check .bypass/worker.log.'),{code:3});
  }
  // A directory lock ensures two shells cannot run the same scheduler concurrently.
  const lock=path.join(root,'.bypass/worker.lock');
  try{fs.mkdirSync(lock);}catch(e){
    if(e.code!=='EEXIST')throw e;
    let active=false;try{const w=JSON.parse(fs.readFileSync(file,'utf8'));process.kill(w.pid,0);active=true;}catch{}
    need(!active,'A local worker is already active.',3);fs.rmSync(lock,{recursive:true,force:true});fs.mkdirSync(lock);
  }
  let stopped=false;const onStop=()=>{stopped=true;};process.on('SIGINT',onStop);process.on('SIGTERM',onStop);
  signal?.addEventListener('abort',onStop,{once:true});
  atomic(file,{pid:process.pid,startedAt:now(),heartbeatAt:now(),stopRequested:false,status:'running'});
  const heartbeat=setInterval(()=>{try{const w=JSON.parse(fs.readFileSync(file,'utf8'));if(w.stopRequested)stopped=true;else atomic(file,{...w,heartbeatAt:now()});}catch{stopped=true;}},1000);
  const runs=[];
  try{
    do{
      for(const m of read(root).monitors.filter(x=>x.enabled&&Date.parse(x.nextRunAt)<=Date.now())){
        if(stopped)break;
        try{const result=await runMonitor(root,m.name,signal);runs.push(result.run.id);}catch(e){await change(root,s=>{const monitor=named(s.monitors,m.name,'Monitor');monitor.lastError=e.message;monitor.nextRunAt=new Date(Date.now()+monitor.everyMs).toISOString();event(s,'monitor-blocked',`${m.name}: ${e.message}`);});}
      }
      if(once)break;await delay(500);
    }while(!stopped);
  }finally{clearInterval(heartbeat);atomic(file,{pid:process.pid,status:'stopped',stoppedAt:now(),heartbeatAt:now()});fs.rmSync(lock,{recursive:true,force:true});process.off('SIGINT',onStop);process.off('SIGTERM',onStop);signal?.removeEventListener('abort',onStop);}
  return outcome({runs,status:'stopped'});
}
export function workerStatus(root){
  const file=path.join(root,'.bypass/worker.json');if(!fs.existsSync(file))return {status:'not-running'};
  try{const worker=JSON.parse(fs.readFileSync(file,'utf8'));return {...worker,status:worker.status==='running'&&Date.now()-Date.parse(worker.heartbeatAt)<10000?'running':'stopped'};}catch{return {status:'unknown'};}
}
