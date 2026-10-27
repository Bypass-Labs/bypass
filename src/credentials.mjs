import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { randomUUID } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { Fault, need, hash, registerSecret, delay } from './util.mjs';
import { scopeReady, safeRequest } from './network.mjs';

// Secrets never enter project state, MCP arguments/results, or the model context.
// This is an owner-only local store, not encryption against the logged-in user.
const limit=128*1024, windowsDirectories=new Set();
export const credentialHelp=name=>`Connect the saved test account with identity import (Muse: bypass_import_identity), using its private file and field names. ${name} remains available for CI. Do not paste credentials into chat; no terminal exports or Muse restart are needed.`;
function privateStat(stat,directory=false){
  need(directory?stat.isDirectory():stat.isFile(),'Credential storage must be a regular file or directory.',3);
  if(process.platform!=='win32')need(stat.uid===process.getuid()&&(stat.mode&0o077)===0,'Credential file must belong to you and be private (chmod 600 for files, 700 for the store).',3);
}
function directory(state,create=false){
  const dir=path.resolve(process.env.BYPASS_CREDENTIAL_DIR||path.join(os.homedir(),'.local/state/bypass/credentials'));
  const relative=path.relative(path.resolve(state.project.root),dir);
  need(relative.startsWith('..'+path.sep)||relative==='..'||path.isAbsolute(relative),'Keep the private credential store outside the application repository.',3);
  if(create)fs.mkdirSync(dir,{recursive:true,mode:0o700});
  try{privateStat(fs.lstatSync(dir),true);}catch(error){if(error instanceof Fault)throw error;throw new Fault('Private account store is unavailable. Reconnect the test account.',3);}
  if(process.platform==='win32'&&!windowsDirectories.has(dir)){
    try{
      // Replace the DACL, including any explicit grants on an existing folder.
      // The path is data in an environment variable, never PowerShell source.
      const operation=create?`
        $acl = [System.Security.AccessControl.DirectorySecurity]::new()
        $acl.SetOwner($sid)
        $acl.SetAccessRuleProtection($true, $false)
        $rule = [System.Security.AccessControl.FileSystemAccessRule]::new($sid, [System.Security.AccessControl.FileSystemRights]::FullControl, [System.Security.AccessControl.InheritanceFlags]'ContainerInherit,ObjectInherit', [System.Security.AccessControl.PropagationFlags]::None, [System.Security.AccessControl.AccessControlType]::Allow)
        $acl.AddAccessRule($rule)
        [System.IO.Directory]::SetAccessControl($env:BYPASS_ACL_DIRECTORY, $acl)
      `:`
        $acl = [System.IO.Directory]::GetAccessControl($env:BYPASS_ACL_DIRECTORY)
        if ($acl.GetOwner([System.Security.Principal.SecurityIdentifier]).Value -ne $sid.Value) { throw 'Wrong directory owner' }
        foreach ($rule in $acl.GetAccessRules($true, $true, [System.Security.Principal.SecurityIdentifier])) {
          if ($rule.AccessControlType -eq 'Allow' -and $rule.IdentityReference.Value -ne $sid.Value) { throw 'Directory grants another account access' }
        }
      `;
      const script=`$ErrorActionPreference='Stop'; $ProgressPreference='SilentlyContinue'; try { $sid=[System.Security.Principal.WindowsIdentity]::GetCurrent().User; ${operation} } catch { [Console]::Error.WriteLine($_.Exception.Message); exit 1 }`;
      execFileSync('powershell.exe',['-NoProfile','-NonInteractive','-EncodedCommand',Buffer.from(script,'utf16le').toString('base64')],{stdio:['ignore','pipe','pipe'],windowsHide:true,timeout:15000,env:{...process.env,BYPASS_ACL_DIRECTORY:dir}});
    }catch(error){throw new Fault(`Could not restrict the credential store to your Windows account. ${String(error.stderr||error.code||'Permission update failed').replace(/[\r\n]+/g,' ').slice(0,1000)}`,3);}
    windowsDirectories.add(dir);
  }
  return dir;
}
function fileFor(state,ref){need(/^[a-f0-9-]{36}$/.test(ref||''),'Invalid private credential reference.',3);return path.join(directory(state),ref+'.json');}
function binding(state,target,identity){return hash({project:state.project.id,root:path.resolve(state.project.root),origin:target.url,target:target.name,identity:identity.name,secretEnv:identity.secretEnv});}
function readFile(file,{privateFile=true}={}){
  let fd;
  try{
    need(!fs.lstatSync(file).isSymbolicLink(),'Credential input cannot be a symbolic link.',3);
    fd=fs.openSync(file,fs.constants.O_RDONLY|(fs.constants.O_NOFOLLOW||0));
    const stat=fs.fstatSync(fd);need(stat.isFile()&&stat.size<=limit,'Credential input must be a small regular file.',3);
    if(privateFile)privateStat(stat);
    return fs.readFileSync(fd,'utf8');
  }catch(error){if(error instanceof Fault)throw error;throw new Fault('Cannot read the private credential file. Check that it exists and is accessible to Bypass.',3);}
  finally{if(fd!==undefined)fs.closeSync(fd);}
}
// Deliberately a data parser: never source/eval a file or run a refresh script.
export function credentialFields(file,{privateFile=true}={}){
  const text=readFile(file,{privateFile}),fields=Object.create(null);
  if(text.trimStart().startsWith('{')){
    let value;try{value=JSON.parse(text);}catch{throw new Fault('Credential JSON is invalid.',3);}
    need(value&&typeof value==='object'&&!Array.isArray(value),'Expected a JSON object of credential fields.',3);
    for(const [key,item] of Object.entries(value))if(typeof item==='string')fields[key]=item;
  }else for(const line of text.split(/\r?\n/)){
    if(!line.trim()||line.trimStart().startsWith('#'))continue;
    const match=line.match(/^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*?)\s*$/);
    need(match&&!Object.hasOwn(fields,match[1]),'Expected unique KEY=value entries in the credential file; shell commands are not supported.',3);
    let value=match[2];const literal=value.startsWith("'");
    if(value.startsWith("'")||value.startsWith('"')){const quote=value[0];need(value.endsWith(quote)&&!value.slice(1,-1).includes(quote),'Unsupported quoting in credential file.',3);value=value.slice(1,-1);}
    else need(!/[\s#;|&<>]/.test(value),'Unsupported value in credential file.',3);
    need(literal||!/[`$\\]/.test(value),'Shell expressions and escapes are not supported in credential files.',3);
    fields[match[1]]=value;
  }
  if(privateFile)Object.values(fields).forEach(registerSecret);
  return fields;
}
function selected(fields,key,label){need(typeof key==='string'&&Object.hasOwn(fields,key)&&fields[key],`The file is missing the selected ${label} field.`,3);return fields[key];}
function claims(token){try{return JSON.parse(Buffer.from(token.split('.')[1],'base64url').toString('utf8'));}catch{return {};}}
function expiration(token){const exp=claims(token).exp;return Number.isFinite(exp)?exp*1000:null;}
function tokenValue(token){need(typeof token==='string'&&token.length>0&&token.length<32768&&!/[\r\n\0]/.test(token),'Invalid account credential.',3);registerSecret(token);return token;}
function firebaseClaims(token,projectId,subject){
  const value=claims(token);
  need(value.aud===projectId&&value.iss===`https://securetoken.google.com/${projectId}`&&typeof value.sub==='string'&&value.sub&&(!subject||value.sub===subject)&&Number.isFinite(value.exp),'Firebase token does not match this project and account. Import the correct account credentials.',3);
  return value;
}
function writeRecord(state,ref,record){
  const file=fileFor(state,ref),tmp=file+'.'+randomUUID()+'.tmp';
  try{fs.writeFileSync(tmp,JSON.stringify(record),{mode:0o600,flag:'wx'});fs.renameSync(tmp,file);}finally{fs.rmSync(tmp,{force:true});}
}
function readRecord(state,target,identity){
  let record;try{record=JSON.parse(readFile(fileFor(state,identity.credentialRef)));}catch(error){if(error instanceof Fault)throw error;throw new Fault('Private credential record is invalid. Reconnect this test account.',3);}
  need(record.version===1&&record.binding===binding(state,target,identity),'Private credential belongs to a different repository, origin, or account. Reconnect this test account.',3);
  tokenValue(record.token);if(record.refreshToken)registerSecret(record.refreshToken);if(record.apiKey)registerSecret(record.apiKey);
  return record;
}
export function importCredential(state,target,identity,options){
  const fields=credentialFields(path.resolve(state.project.root,options.file||'')),token=tokenValue(selected(fields,options['token-field'],'token'));
  const provider=options.provider||'static';need(['static','firebase'].includes(provider),'Credential provider must be static or firebase.');
  const record={version:1,binding:binding(state,target,identity),provider,token,expiresAt:expiration(token),updatedAt:new Date().toISOString()};
  if(provider==='firebase'){
    need(identity.type==='bearer','Firebase accounts require bearer authentication.');
    record.refreshToken=tokenValue(selected(fields,options['refresh-token-field'],'refresh token'));
    const config=options['config-file']?credentialFields(path.resolve(state.project.root,options['config-file']),{privateFile:false}):fields;
    record.apiKey=selected(config,options['api-key-field']||'VITE_FIREBASE_API_KEY','Firebase API key');registerSecret(record.apiKey);
    record.projectId=options['project-id']||claims(token).aud;
    need(typeof record.projectId==='string'&&/^[a-z0-9][a-z0-9-]{3,62}$/.test(record.projectId),'Supply the Firebase project ID.');
    record.subject=firebaseClaims(token,record.projectId).sub;
  }
  directory(state,true);const ref=randomUUID();writeRecord(state,ref,record);return ref;
}
export function removeCredential(state,ref){if(ref)fs.rmSync(fileFor(state,ref),{force:true});}
export function registerProjectCredentials(state){
  for(const identity of state.identities.filter(i=>i.credentialRef)){
    const target=state.targets.find(t=>t.name===identity.target);if(!target)continue;
    try{readRecord(state,target,identity);}catch{/* An unavailable credential blocks requests, not local memory retrieval. */}
  }
}
export function credentialStatus(state,target,identity,env=process.env){
  try{
    if(identity.credentialRef){const record=readRecord(state,target,identity),expired=record.expiresAt!==null&&record.expiresAt<=Date.now()+60000;return {source:'private-store',provider:record.provider,available:!expired||record.provider==='firebase',status:expired?(record.provider==='firebase'?'refresh_on_use':'expired'):'ready',expiresAt:record.expiresAt?new Date(record.expiresAt).toISOString():null};}
    const available=!!env[identity.secretEnv];return {source:'environment',available,status:available?'ready':'missing'};
  }catch(error){return {source:'private-store',available:false,status:'reconnect',reason:error.message};}
}
// Read-only readiness can use an expired, refreshable token for its signature.
// The executor always refreshes before sending any request to the application.
export function storedToken(state,target,identity,env=process.env){
  if(!identity.credentialRef)return env[identity.secretEnv];
  const record=readRecord(state,target,identity);
  need(record.provider==='firebase'||record.expiresAt===null||record.expiresAt>Date.now()+60000,`Refresh the test account with identity import. Its saved token has expired. No Muse restart is needed.`,3);
  return record.token;
}
async function withLock(state,ref,signal,fn){
  const lock=fileFor(state,ref)+'.lock',deadline=Date.now()+20000;
  while(true){
    if(signal?.aborted)throw new Fault('Credential refresh cancelled.',3);
    try{const fd=fs.openSync(lock,'wx',0o600);fs.writeFileSync(fd,String(process.pid));fs.closeSync(fd);break;}
    catch(error){
      if(error.code!=='EEXIST')throw new Fault('Cannot lock the private credential store.',3);
      try{const pid=Number(readFile(lock));if(Number.isInteger(pid)&&pid>0){try{process.kill(pid,0);}catch(e){if(e.code==='ESRCH'){fs.unlinkSync(lock);continue;}}}else if(Date.now()-fs.statSync(lock).mtimeMs>30000){fs.unlinkSync(lock);continue;}}catch{}
      need(Date.now()<deadline,'Account credentials are being refreshed. Retry shortly.',3);await delay(50);
    }
  }
  try{return await fn();}finally{fs.rmSync(lock,{force:true});}
}
export async function resolveCredential(state,target,identity,{env=process.env,signal,force=false,request=safeRequest}={}){
  scopeReady(target,identity.checkPath);
  if(!identity.credentialRef)return env[identity.secretEnv];
  let record=readRecord(state,target,identity);
  const due=()=>force||record.expiresAt!==null&&record.expiresAt<=Date.now()+60000;
  if(!due())return record.token;
  need(record.provider==='firebase','Refresh this account by importing its new token. No Muse restart is needed.',3);
  return withLock(state,identity.credentialRef,signal,async()=>{
    record=readRecord(state,target,identity);if(!due())return record.token;
    let response,data;
    try{
      const deadline=AbortSignal.timeout(10000),requestSignal=signal?AbortSignal.any([signal,deadline]):deadline;
      response=await request(`https://securetoken.googleapis.com/v1/token?key=${encodeURIComponent(record.apiKey)}`,{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded',Referer:target.url+'/'},body:new URLSearchParams({grant_type:'refresh_token',refresh_token:record.refreshToken}).toString(),timeout:8000,maxBytes:32768,signal:requestSignal});
      need(response.status===200,'Firebase refresh was rejected.');data=JSON.parse(response.body);
      registerSecret(data.id_token);registerSecret(data.refresh_token);
      firebaseClaims(data.id_token,record.projectId,record.subject);
      // Secure Token can return the numeric project number in project_id.
      // The ID token audience/issuer above bind the actual Firebase project ID.
      need(data.user_id===record.subject&&Number(data.expires_in)>60&&Number(data.expires_in)<=86400,'Firebase refresh returned a different account or invalid lifetime.');
      record.token=tokenValue(data.id_token);record.refreshToken=tokenValue(data.refresh_token);
      record.expiresAt=Math.min(expiration(record.token),Date.now()+Number(data.expires_in)*1000);need(record.expiresAt>Date.now()+60000,'Firebase returned an expired token.');
    }catch{throw new Fault(signal?.aborted?'Credential refresh cancelled.':'Automatic Firebase refresh failed. Reconnect this test account with identity import; repository, DNS and scope are saved. No Muse restart is needed.',3);}
    record.updatedAt=new Date().toISOString();writeRecord(state,identity.credentialRef,record);return record.token;
  });
}
export async function credentialEnvironment(state,target,identities,{env=process.env,...options}={}){
  scopeReady(target);const resolved={...env},seen=new Map();
  for(const identity of identities){
    need(identity.target===target.name,'Identity belongs to another target.',3);
    const value=await resolveCredential(state,target,identity,{env,...options});
    if(value){need(!seen.has(identity.secretEnv)||seen.get(identity.secretEnv)===value,'Use different credential reference names for the two accounts.',3);seen.set(identity.secretEnv,value);resolved[identity.secretEnv]=value;registerSecret(value);}
  }
  return resolved;
}
export async function replayEnvironment(state,spec,options){const target=state.targets.find(t=>t.url===spec.origin&&t.name===spec.owner.target);need(target,'Target not found.',3);return credentialEnvironment(state,target,[spec.owner,spec.outsider],options);}
