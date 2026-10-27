import fs from 'node:fs';
import { fileURLToPath } from 'node:url';
import { spawn } from 'node:child_process';
import { randomUUID } from 'node:crypto';
import { execFile, need, hash, Fault, abortFault } from './util.mjs';

const directory=fileURLToPath(new URL('../agents/',import.meta.url));
export const agentTag=()=>`bypass-agent:${hash(fs.readFileSync(directory+'worker.mjs','utf8')+fs.readFileSync(directory+'Dockerfile','utf8')).slice(0,16)}`;
export async function dockerStatus({signal}={}){
  try{
    const result=await execFile('docker',['version','--format','{{.Server.Version}}'],{timeout:10000,signal});
    return {available:result.code===0,version:result.code===0?result.stdout:null,message:result.code===0?'Docker is ready.':'Start Docker Desktop or Colima, then retry. No simulated fallback is used.'};
  }catch(error){if(signal?.aborted)throw error;return {available:false,message:'Docker is unavailable. Install/start Docker Desktop or Colima and make docker available in this terminal.'};}
}
export async function prepareAgents({signal,onProgress}={}){
  const status=await dockerStatus({signal});need(status.available,status.message,3);
  const tag=agentTag();let inspect=await execFile('docker',['image','inspect',tag,'--format','{{.Id}}'],{signal});
  if(inspect.code!==0){
    onProgress?.({stage:'containers',message:'Building the two agent services (first run downloads the Node base image)…'});
    const build=await execFile('docker',['build','--tag',tag,directory],{signal,timeout:300000,killGroup:true});
    need(build.code===0,'Agent image build failed. Check Docker networking and disk space; run engine doctor.',3);
    inspect=await execFile('docker',['image','inspect',tag,'--format','{{.Id}}'],{signal});
  }
  need(inspect.code===0&&/^sha256:[a-f0-9]{64}$/.test(inspect.stdout),'Cannot resolve the agent image.',3);
  return {image:inspect.stdout,tag,dockerVersion:status.version};
}
export function containerArgs(name,image,role){return ['run','--rm','-i','--name',name,'--label','com.bypass.agent=true','--label',`com.bypass.role=${role}`,'--network','none','--read-only','--cap-drop','ALL','--security-opt','no-new-privileges','--pids-limit','32','--memory','128m','--cpus','1',image,role];}
export async function runContainer(role,task,rpc,{image,signal,onProgress,timeoutMs=600000}={}){
  const name=`bypass-${role}-${randomUUID().slice(0,8)}`;
  onProgress?.({stage:role,message:`Starting ${role} agent · ${name} · shared model`});
  let child,result,failure,buffer='',bytes=0,busy=false,requests=0;
  const controller=new AbortController(),combined=signal?AbortSignal.any([signal,controller.signal]):controller.signal;
  const timer=setTimeout(()=>controller.abort(new Fault(`${role} exceeded ten minutes.`,3)),timeoutMs);
  try{
    return await new Promise((resolve,reject)=>{
      const stop=error=>{failure??=error;child?.kill('SIGKILL');};
      const abort=()=>stop(abortFault(combined));
      child=spawn('docker',containerArgs(name,image,role),{stdio:['pipe','pipe','pipe'],shell:false});
      combined.addEventListener('abort',abort,{once:true});
      if(combined.aborted)abort();
      child.stdin.on('error',()=>{});
      child.on('error',error=>{failure=error;});
      child.stderr.on('data',chunk=>{bytes+=chunk.length;if(bytes>2000000)stop(new Fault('Agent output limit exceeded.',3));});
      child.stdout.on('data',chunk=>{
        bytes+=chunk.length;buffer+=chunk;if(bytes>2000000||buffer.length>700000){stop(new Fault('Agent output limit exceeded.',3));return;}
        let newline;
        while((newline=buffer.indexOf('\n'))>=0){
          const line=buffer.slice(0,newline);buffer=buffer.slice(newline+1);
          let message;try{message=JSON.parse(line);}catch{stop(new Fault('Invalid agent protocol response.',3));return;}
          if(message.type==='request'){
            if(busy||++requests>24||!Number.isInteger(message.id)){stop(new Fault('Agent request budget or protocol violated.',3));return;}
            busy=true;
            Promise.resolve().then(()=>rpc(message.method,message.params,combined)).then(value=>{
              child.stdin.write(JSON.stringify({type:'response',id:message.id,result:value})+'\n');
            }).catch(error=>{
              if(role==='white-box'&&message.method==='read_files'&&!combined.aborted){
                child.stdin.write(JSON.stringify({type:'response',id:message.id,error:String(error.message).slice(0,1000)})+'\n');
              }else stop(error);
            }).finally(()=>{busy=false;});
          }else if(message.type==='result'&&!busy&&!result){result=message.result;child.stdin.end();}
          else if(message.type==='failure')stop(new Fault(String(message.message).slice(0,300),3));
          else stop(new Fault('Unexpected agent protocol message.',3));
        }
      });
      child.on('close',code=>{combined.removeEventListener('abort',abort);if(failure)reject(failure);else if(code!==0||!result)reject(new Fault(`${role} container exited without a result (${code}).`,3));else resolve({result,container:{name,image,role,requests}});});
      child.stdin.write(JSON.stringify({type:'start',task})+'\n');
    });
  }finally{
    clearTimeout(timer);controller.abort();
    // Also remove the daemon-side process when the client is cancelled or crashes.
    try{await execFile('docker',['rm','--force',name],{timeout:10000});}catch{}
  }
}
