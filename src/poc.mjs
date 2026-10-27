import fs from 'node:fs';
import path from 'node:path';
import net from 'node:net';
import { spawn } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { execute } from './service.mjs';
import { read, change } from './store.mjs';
import { need, execFile, delay, now } from './util.mjs';
import { safeRequest } from './network.mjs';
const packageRoot=fileURLToPath(new URL('../',import.meta.url));
export async function startPOC(options={}){
  const root=path.resolve(options.dir||path.join(packageRoot,'.demo',`poc-${Date.now()}`));
  need(!fs.existsSync(root)||fs.readdirSync(root).length===0,'POC destination must be empty. Existing projects are never overwritten.');
  fs.mkdirSync(root,{recursive:true});
  fs.cpSync(path.join(packageRoot,'examples/poc-api'),root,{recursive:true});
  await execFile('git',['init','--quiet',root]);
  await execute('init',[root],{});
  await execute('model add',['muse'],{project:root,provider:'muse-code',model:options.model||'Muse session default'});
  if(options.project){try{const source=read(options.project);if(source.activeModel)await change(root,s=>{s.models=[structuredClone(source.models.find(m=>m.name===source.activeModel))];s.activeModel=source.activeModel;});}catch{}}
  const port=options.port?Number(options.port):await new Promise((resolve,reject)=>{const server=net.createServer();server.on('error',reject);server.listen(0,'127.0.0.1',()=>{const p=server.address().port;server.close(()=>resolve(p));});});
  need(Number.isInteger(port)&&port>=1024&&port<=65535,'Choose a port between 1024 and 65535.');
  const log=fs.openSync(path.join(root,'.bypass/poc-api.log'),'a',0o600);
  const child=spawn(process.execPath,[path.join(root,'server.mjs')],{cwd:root,env:{...process.env,PORT:String(port)},detached:true,stdio:['ignore',log,log]});child.unref();fs.closeSync(log);
  const url=`http://127.0.0.1:${port}`;let ready=false;
  try{
    for(let i=0;i<40;i++){await delay(100);try{const r=await safeRequest(url+'/api/me',{allowLocal:true,headers:{Authorization:'Bearer poc-owner-token'}});if(JSON.parse(r.body).id==='account-alice'){ready=true;break;}}catch{}}
    need(ready,'The local POC app could not start. Inspect .bypass/poc-api.log.',3);
    await execute('target add',['poc'],{project:root,url,environment:'local'});
    await execute('target verify',['poc'],{project:root,method:'local'});
    await execute('target authorize',['poc'],{project:root,accept:true,paths:'/api'});
    for(const [name,token] of [['owner','poc-owner-token'],['outsider','poc-outsider-token']]){
      await execute('identity add',[name],{project:root,target:'poc',type:'bearer','secret-env':`BYPASS_POC_${name.toUpperCase()}`,'check-path':'/api/me'});
      await change(root,s=>{s.identities.find(i=>i.name===name).fixtureValue=token;});
    }
    // Only public fixture tokens; this is distinct from deployed credentials.
    await change(root,s=>{s.poc={pid:child.pid,url,createdAt:now()};s.targets.find(t=>t.name==='poc').pocFixture=true;});
    await execute('probe add',['invoice'],{project:root,path:'/api/invoices/inv-101','resource-id':'inv-101',owner:'owner',outsider:'outsider'});
    await execute('engine use',['docker'],{project:root});
    return {root,url,pid:child.pid,engine:'docker',message:'Real AI POC ready. Public fixture accounts only. Run scan, inspect evidence, edit policy.mjs, then retest.',fix:'In policy.mjs require account === invoice.ownerId.',next:`bypass --project ${root}`};
  }catch(error){try{process.kill(child.pid,'SIGTERM');}catch{}throw error;}
}
export async function stopPOC(root){
  const state=read(root);need(state.poc,'This is not a POC fixture.');
  // Confirm the process command before stopping; never kill a reused PID.
  const processInfo=await execFile('ps',['-p',String(state.poc.pid),'-o','command=']);
  if(processInfo.stdout.includes(path.join(root,'server.mjs')))try{process.kill(state.poc.pid,'SIGTERM');}catch{}
  await change(root,s=>{s.poc.stoppedAt=now();});return {stopped:true,root};
}
