import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { randomUUID } from 'node:crypto';
import { execFile, hash, need, abortFault, Fault } from '../util.mjs';
import { ScannerClient } from './client.mjs';
import { manifest } from './contracts.mjs';

export const scannerDirectory = fileURLToPath(new URL('../../scanner/', import.meta.url));
export const defaultResources = {...manifest.resourceDefaults};
export const imagePlatform = 'linux/amd64';

export function scannerPackageFiles(root = scannerDirectory) {
  const files = ['Dockerfile','.dockerignore','pyproject.toml','README.md','codeql-lock.json','protocol/v3.json'];
  function visit(relative) {
    for (const entry of fs.readdirSync(path.join(root,relative),{withFileTypes:true}).sort((a,b)=>a.name.localeCompare(b.name))) {
      const name = `${relative}/${entry.name}`;
      if (entry.isDirectory() && entry.name !== '__pycache__') visit(name);
      else if (entry.isFile() && entry.name.endsWith('.py')) files.push(name);
    }
  }
  visit('src');
  for(const entry of fs.readdirSync(path.join(root,'policies'),{withFileTypes:true}).sort((a,b)=>a.name.localeCompare(b.name)))
    if(entry.isFile()&&/\.(json|md)$/.test(entry.name))files.push('policies/'+entry.name);
  return files;
}

export function scannerTag(detector='codeql') {
  return `bypass-scanner:${detector==='policy'?'policy-':''}${hash(scannerPackageFiles().map(name=>[name,fs.readFileSync(path.join(scannerDirectory,name),'utf8')])).slice(0,16)}`;
}

export async function scannerDoctor({signal,runner=execFile,detector='codeql'}={}) {
  const tag=scannerTag(detector), lock=JSON.parse(fs.readFileSync(path.join(scannerDirectory,'codeql-lock.json')));
  const base={image:{tag,available:false,platform:imagePlatform},runtime:detector,codeql:detector==='policy'?null:{version:lock.version,bundleSha256:lock.bundleSha256},analysisImplemented:true,implementedStages:['discovery']};
  let docker;
  try {docker=await runner('docker',['version','--format','{{.Server.Version}}'],{signal,timeout:10000});}
  catch(error){if(signal?.aborted)throw error;return {...base,docker:{available:false},status:'blocked',message:'Docker is unavailable. Install/start Docker Desktop or Colima; no repository clone or host CodeQL installation is required.'};}
  if(docker.code!==0)return {...base,docker:{available:false},status:'blocked',message:'Docker cannot be reached. Check its daemon, context, and socket permissions.'};
  const inspected=await runner('docker',['image','inspect',tag,'--format','{{.Id}}'],{signal,timeout:10000});
  const id=inspected.code===0&&/^sha256:[a-f0-9]{64}$/.test(inspected.stdout)?inspected.stdout:null;
  return {...base,docker:{available:true,version:docker.stdout},image:{...base.image,available:!!id,id},status:id?'ready':'blocked',
    message:id?`${detector} discovery image is ready. Formal AI evaluation is unavailable.`:`First ${detector} use prepares its bundled image; scanner prepare can prewarm it.`};
}

const preparations=new Map();
export async function prepareScanner({signal,onProgress,runner=execFile,detector='codeql'}={}) {
  const diagnostics=await scannerDoctor({signal,runner,detector});
  need(diagnostics.docker.available,diagnostics.message,3);
  if(diagnostics.image.available)return diagnostics;
  const tag=diagnostics.image.tag;
  if(preparations.has(tag))return preparations.get(tag);
  const promise=(async()=>{
    onProgress?.({stage:'scanner-prepare',message:detector==='policy'?'Preparing the lightweight Python policy evidence runtime. No CodeQL bundle or LLM key is installed in this image.':'Preparing pinned CodeQL and toolchains from the bundled recipe. First use downloads dependencies; no clone or API key is required.'});
    const started=Date.now(), timer=setInterval(()=>onProgress?.({stage:'scanner-prepare',message:`Preparing CodeQL image · ${Math.round((Date.now()-started)/1000)}s elapsed. Scan-time network access remains off by default.`}),15000);
    try{
      const result=await runner('docker',['build',...(detector==='policy'?['--target','policy']:[]),'--platform',imagePlatform,'--tag',tag,scannerDirectory],{signal,timeout:1800000,killGroup:true});
      need(result.code===0,'CodeQL image preparation failed. Check Docker networking, disk space, and the pinned toolchain downloads.',3);
      const inspected=await runner('docker',['image','inspect',tag,'--format','{{.Id}}'],{signal,timeout:10000});
      need(inspected.code===0&&/^sha256:[a-f0-9]{64}$/.test(inspected.stdout),'Cannot resolve the prepared CodeQL image.',3);
      return {...diagnostics,status:'ready',image:{...diagnostics.image,available:true,id:inspected.stdout},
        message:'Pinned CodeQL discovery image is ready. AI evaluation is not implemented.'};
    }finally{clearInterval(timer);}
  })();
  preparations.set(tag,promise);
  try{return await promise;}finally{preparations.delete(tag);}
}

export function scannerOutput(root,create=false) {
  const base=path.resolve(root), destination=path.join(base,'.bypass','scanner');
  for(const name of [path.join(base,'.bypass'),destination]){
    if(fs.existsSync(name))need(!fs.lstatSync(name).isSymbolicLink()&&fs.statSync(name).isDirectory(),'Scanner output must be a real directory inside the selected project.',2);
    else if(create)fs.mkdirSync(name,{mode:0o700});
  }
  return destination;
}

export function scannerContainerArgs(name,image,{root,output,sarif,resources={},network='none',worker}={}) {
  const limits={...defaultResources,...resources};
  const args=['create','--rm','-i','--name',name,'--platform',imagePlatform,'--label','com.bypass.scanner=true',
    '--network',network,'--read-only','--cap-drop','ALL','--security-opt','no-new-privileges','--pids-limit','512',
    '--memory',`${limits.memoryMb}m`,'--cpus',String(limits.cpus),'--tmpfs','/tmp:rw,nosuid,nodev,exec,mode=1777,size=1g',
    '--user',`${process.getuid?.()||65532}:${process.getgid?.()||65532}`,'--env',`BYPASS_SCANNER_IMAGE=${image}`];
  const mount=(source,target,readonly)=>{
    need(!source.includes(','),'Docker mount paths cannot contain commas.',2);
    args.push('--mount',`type=bind,src=${source},dst=${target}${readonly?',readonly':''}`);
  };
  if(root)mount(path.resolve(root),'/inputs/source',true);
  if(output)mount(path.resolve(output),'/outputs',false);
  if(sarif)mount(path.resolve(sarif),'/inputs/findings.sarif',true);
  if(worker)args.push('--entrypoint','python');
  args.push(image);
  if(worker)args.push('-m','bypass_scanner.worker',worker.run,worker.job);
  return args;
}

export async function connectScanner({root,output,sarif,resources={},signal,onProgress,runner=execFile,timeoutMs,prepare=true,detector='codeql'}={}) {
  const diagnostics=await (prepare?prepareScanner:scannerDoctor)({signal,onProgress,runner,detector});
  need(diagnostics.image.available,diagnostics.message,3);
  if(root){need(fs.statSync(root).isDirectory(),'Select an existing source directory.',2);output??=scannerOutput(root,true);}
  const name=`bypass-scanner-${randomUUID()}`, helpers=new Map();
  const remove=async target=>{try{await runner('docker',['rm','--force',target],{timeout:10000});}catch{}};
  const args=scannerContainerArgs(name,diagnostics.image.id,{root,output,sarif,resources});
  let created;
  try{created=await runner('docker',args,{timeout:20000,killGroup:true});}
  catch(error){await remove(name);throw error;}
  if(created.code!==0){await remove(name);throw new Fault('Cannot create CodeQL scanner container.',3);}
  if(signal?.aborted){await remove(name);throw abortFault(signal);}
  let client;
  const cleanup=async()=>{
    await Promise.allSettled([...helpers.values()].map(item=>remove(item.name)));
    await remove(name);
  };
  client=new ScannerClient('docker',['start','--attach','--interactive',name],{timeoutMs,onClose:cleanup});
  client.scanner={root,output,sarif,resources,image:diagnostics.image.id};
  client.stopBuilds=async run=>{await Promise.allSettled([...helpers.values()].filter(item=>!item.finished&&(!run||item.run===run)).map(item=>remove(item.name)));};
  client.pumpBuild=async run=>{
    const job=run.networkJob;
    // A backend deadline can retire a job while its helper is still running.
    await Promise.allSettled([...helpers.entries()].filter(([id,item])=>!item.finished&&item.run===run.id&&id!==job?.id).map(([,item])=>remove(item.name)));
    if(!job||helpers.has(job.id))return;
    need(/^scan_[a-f0-9]{24}$/.test(run.id)&&/^[a-f0-9]{32}$/.test(job.id),'Invalid scanner build request.',3);
    const helperName=`bypass-codeql-build-${job.id}`;
    const item={name:helperName,run:run.id};helpers.set(job.id,item);
    item.done=(async()=>{
      try{
        const creation=await runner('docker',scannerContainerArgs(helperName,diagnostics.image.id,{output,resources,network:'bridge',worker:{run:run.id,job:job.id}}),{timeout:20000,killGroup:true});
        need(creation.code===0,'Could not create the explicitly network-enabled extraction worker.',3);
        onProgress?.({stage:'scanner-extract',message:`${job.language}: running configured network-enabled extraction in a separate container; query analysis stays offline.`});
        await runner('docker',['start','--attach',helperName],{
          timeout:((resources.timeoutSeconds??defaultResources.timeoutSeconds)+manifest.networkStartupSeconds)*1000,killGroup:true
        });
      }catch{/* The backend records a failed extraction receipt below. */}
      finally{
        await remove(helperName);
        if(!client.failure)await client.call('build_failed',{run:run.id,job:job.id}).catch(()=>{});
        item.finished=true;
      }
    })();
  };
  try{await client.initialize({signal});return client;}
  catch(error){await client.close();throw error;}
}
