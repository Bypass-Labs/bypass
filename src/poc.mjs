import fs from 'node:fs';
import path from 'node:path';
import net from 'node:net';
import { randomUUID } from 'node:crypto';
import { spawn } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { execute } from './service.mjs';
import { read, change } from './store.mjs';
import { need, execFile, delay, now, hash } from './util.mjs';
import { safeRequest } from './network.mjs';
const packageRoot=fileURLToPath(new URL('../',import.meta.url));
export async function startPOC(options={}){
  const root=path.resolve(options.dir||path.join(packageRoot,'.demo',`poc-${Date.now()}`));
  need(!fs.existsSync(root)||fs.readdirSync(root).length===0,'POC destination must be empty. Existing projects are never overwritten.');
  fs.mkdirSync(root,{recursive:true});
  // Only these two bundled files form the fixture. Avoid Node's native recursive
  // copy path, which can abort on Unicode Windows paths (nodejs/node#59636).
  for(const file of ['server.mjs','policy.mjs'])fs.copyFileSync(path.join(packageRoot,'examples/poc-api',file),path.join(root,file),fs.constants.COPYFILE_EXCL);
  await execFile('git',['init','--quiet',root]);
  await execute('init',[root],{});
  if(options.project){try{const source=read(options.project);if(source.activeModel)await change(root,s=>{s.models=[structuredClone(source.models.find(m=>m.name===source.activeModel))];s.activeModel=source.activeModel;});}catch{}}
  if(options.model){need(read(root).activeModel,'Select an API profile in --project before overriding its model. The Muse plugin uses the active host model.');await change(root,s=>{s.models[0].model=options.model;delete s.models[0].lastAttempt;delete s.models[0].lastTest;});}
  const port=options.port?Number(options.port):await new Promise((resolve,reject)=>{const server=net.createServer();server.on('error',reject);server.listen(0,'127.0.0.1',()=>{const p=server.address().port;server.close(()=>resolve(p));});});
  need(Number.isInteger(port)&&port>=1024&&port<=65535,'Choose a port between 1024 and 65535.');
  const log=fs.openSync(path.join(root,'.bypass/poc-api.log'),'a',0o600);
  const instanceId=randomUUID(),control=path.join(root,'.bypass/poc-control.json');
  fs.writeFileSync(control,JSON.stringify({instanceId,stop:false}),{mode:0o600});
  const child=spawn(process.execPath,[path.join(root,'server.mjs')],{cwd:root,env:{...process.env,PORT:String(port),BYPASS_POC_CONTROL_FILE:control,BYPASS_POC_INSTANCE:instanceId},detached:true,stdio:['ignore',log,log]});child.unref();fs.closeSync(log);
  const url=`http://127.0.0.1:${port}`;let ready=false;
  try{
    for(let i=0;i<40;i++){await delay(100);try{const r=await safeRequest(url+'/health',{allowLocal:true});if(JSON.parse(r.body).instanceId===instanceId){ready=true;break;}}catch{}}
    need(ready,'The local POC app could not start. Inspect .bypass/poc-api.log.',3);
    await execute('target add',['poc'],{project:root,url,environment:'local'});
    await execute('target verify',['poc'],{project:root,method:'local'});
    await execute('target authorize',['poc'],{project:root,accept:true,paths:'/api'});
    for(const [name,token] of [['owner','poc-owner-token'],['outsider','poc-outsider-token']]){
      await execute('identity add',[name],{project:root,target:'poc',type:'bearer','secret-env':`BYPASS_POC_${name.toUpperCase()}`,'check-path':'/api/me'});
      await change(root,s=>{s.identities.find(i=>i.name===name).fixtureValue=token;});
    }
    // Only public fixture tokens; this is distinct from deployed credentials.
    await change(root,s=>{s.poc={pid:child.pid,url,instanceId,createdAt:now()};s.targets.find(t=>t.name==='poc').pocFixture=true;});
    await execute('probe add',['invoice'],{project:root,path:'/api/invoices/inv-101','resource-id':'inv-101',owner:'owner',outsider:'outsider'});
    await execute('engine use',['docker'],{project:root});
    return {root,url,pid:child.pid,engine:'docker',message:'Isolated security POC ready. Public fixture accounts only. Run scan, inspect evidence, edit policy.mjs, then retest.',fix:'In policy.mjs require account === invoice.ownerId.',next:`bypass --project ${root}`};
  }catch(error){try{process.kill(child.pid,'SIGTERM');}catch{}throw error;}
}
export async function stopPOC(root){
  const state=read(root);need(state.poc,'This is not a POC fixture.');
  if(state.poc.instanceId){
    // The generated server watches its own instance-bound file. Works on Windows
    // without ps, and cannot signal an unrelated process after PID reuse.
    fs.writeFileSync(path.join(root,'.bypass/poc-control.json'),JSON.stringify({instanceId:state.poc.instanceId,stop:true}),{mode:0o600});
    for(let i=0;i<30;i++){
      await delay(100);
      try{const r=await safeRequest(state.poc.url+'/health',{allowLocal:true,timeout:1000});if(JSON.parse(r.body).instanceId!==state.poc.instanceId)break;}
      catch{break;}
      need(i<29,'Fixture shutdown is still pending; retry poc stop.',3);
    }
  }else{
    need(process.platform!=='win32','This older fixture lacks portable shutdown. Stop its original server terminal.');
    const processInfo=await execFile('ps',['-p',String(state.poc.pid),'-o','command=']);
    if(processInfo.stdout.includes(path.join(root,'server.mjs')))try{process.kill(state.poc.pid,'SIGTERM');}catch{}
  }
  await change(root,s=>{s.poc.stoppedAt=now();});return {stopped:true,root};
}
const restarting=new Map();
export async function resumePOC(root,{automatic=false,signal}={}){
  if(restarting.has(root))return restarting.get(root);
  const work=(async()=>{
    const state=read(root),fixture=state.poc;
    need(fixture?.instanceId,'This project has no recorded recoverable local fixture.',3);
    need(!automatic||!fixture.stoppedAt,'This fixture was deliberately stopped. Use poc resume (Muse: demo control resume) to restart it.',3);
    const url=new URL(fixture.url),target=state.targets.find(t=>t.pocFixture);
    need(url.hostname==='127.0.0.1'&&url.protocol==='http:'&&target?.url===url.origin&&target.environment==='local','Fixture origin no longer matches the recorded local target.',3);
    let response;
    try{response=await safeRequest(url.origin+'/health',{allowLocal:true,timeout:1000,signal});}catch(error){if(signal?.aborted)throw error;}
    if(response){let identity;try{identity=JSON.parse(response.body).instanceId;}catch{}
      need(identity===fixture.instanceId,'The saved port belongs to another service; Bypass will not replace or stop it.',3);
      return {root,url:url.origin,resumed:false,running:true};
    }
    // Restart only the bundled server. The policy module is executable too; permit only the known fixture forms
    // during recovery, never arbitrary application code.
    for(const name of ['server.mjs','policy.mjs','.bypass','.bypass/poc-control.json','.bypass/poc-api.log'])need(!fs.lstatSync(path.join(root,name)).isSymbolicLink(),'Fixture recovery cannot traverse symlinks.',3);
    need(hash(fs.readFileSync(path.join(root,'server.mjs'),'utf8'))===hash(fs.readFileSync(path.join(packageRoot,'examples/poc-api/server.mjs'),'utf8')),'Fixture server changed; automatic execution is disabled. Create a fresh demo or restore the bundled server.',3);
    const policy=fs.readFileSync(path.join(root,'policy.mjs'),'utf8').replace(/\s+/g,'');
    need(['exportfunctionmayReadInvoice(account,invoice){returnBoolean(account);}','exportfunctionmayReadInvoice(account,invoice){returnaccount===invoice.ownerId;}'].includes(policy),'Fixture policy contains custom executable code. Automatic recovery only supports the bundled vulnerable/fixed forms.',3);
    const control=path.join(root,'.bypass/poc-control.json');
    fs.writeFileSync(control,JSON.stringify({instanceId:fixture.instanceId,stop:false}),{mode:0o600});
    const log=fs.openSync(path.join(root,'.bypass/poc-api.log'),'a',0o600);
    const child=spawn(process.execPath,[path.join(root,'server.mjs')],{cwd:root,env:{...process.env,PORT:url.port,BYPASS_POC_CONTROL_FILE:control,BYPASS_POC_INSTANCE:fixture.instanceId},detached:true,stdio:['ignore',log,log]});
    child.unref();fs.closeSync(log);let spawnError;child.on('error',e=>{spawnError=e;});
    try{
      let ready=false;
      for(let i=0;i<40;i++){
        need(!signal?.aborted&&!spawnError,'Fixture restart cancelled or failed.',3);await delay(100);
        try{const r=await safeRequest(url.origin+'/health',{allowLocal:true,timeout:1000,signal});if(JSON.parse(r.body).instanceId===fixture.instanceId){ready=true;break;}}catch{}
      }
      need(ready,'Fixture restart failed. Evidence is retained; inspect .bypass/poc-api.log.',3);
      await change(root,s=>{s.poc.pid=child.pid;s.poc.resumedAt=now();delete s.poc.stoppedAt;});
      return {root,url:url.origin,resumed:true,running:true,identityPreserved:true,message:'Local fixture restarted; findings, checks and source edits retained.'};
    }catch(error){try{child.kill('SIGTERM');}catch{}throw error;}
  })();
  restarting.set(root,work);try{return await work;}finally{restarting.delete(root);}
}
