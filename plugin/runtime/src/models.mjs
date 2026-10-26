import { execFile, need, envName, now, Fault } from './util.mjs';
import { safeRequest, loopback } from './network.mjs';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';

export function modelProfile(name, options) {
  const provider=options.provider;
  need(['local','endpoint','muse-code'].includes(provider),'Choose --provider local, endpoint, or muse-code.');
  if(provider==='muse-code')return {name,provider,model:options.model || 'Muse session default',dataDestination:'Muse Code account/provider',contributorMode:'off for Bypass-launched smoke checks',createdAt:now()};
  need(options['base-url']&&options.model,'Endpoint profiles require --base-url and --model.');
  const u=new URL(options['base-url']);
  need(!u.username&&!u.password&&!u.search&&!u.hash,'Model URL must not contain credentials, queries, or fragments.');
  need(u.protocol==='https:'||(u.protocol==='http:'&&loopback(u.hostname)),'Use HTTPS for remote inference, or HTTP for a loopback model.');
  need(provider!=='local'||loopback(u.hostname),'Local model profiles must use a loopback endpoint.');
  return {name,provider,baseUrl:u.toString().replace(/\/$/,''),model:options.model,secretEnv:options['secret-env']?envName(options['secret-env']):null,allowPrivate:!!options['allow-private'],dataDestination:provider==='local'?'this machine':u.origin,createdAt:now()};
}
export async function testModel(profile, root) {
  if(profile.provider==='muse-code'){
    const workspace=fs.mkdtempSync(path.join(os.tmpdir(),'bypass-model-smoke-'));
    let r;
    try { r=await execFile('muse',['exec','--workspace',workspace,'--preset','empty','--contributor-mode','off','--no-foreign-personal-context','--no-session-log','--disable-web-tools','--disable-reminders','--disable-request-user-input','--disable-write','--disable-shell','--max-model-steps','1','Reply with exactly BYPASS_MODEL_OK. Do not use tools or read files.'],{cwd:workspace,timeout:90000,env:{MUSE_CONTRIBUTOR_MODE:'0'}}); }
    finally { fs.rmSync(workspace,{recursive:true,force:true}); }
    need(r.code===0&&r.stdout.includes('BYPASS_MODEL_OK'),'Muse Code smoke check did not complete. Run muse login and check your subscription/model access.',3);
    return {status:'connected',provider:profile.provider,checkedAt:now(),syntheticPrompt:true,repositorySent:false,workspace:'empty temporary directory',note:'Muse’s native provider and personal configuration still apply.'};
  }
  const token=profile.secretEnv?process.env[profile.secretEnv]:null;
  if(profile.secretEnv)need(token,`Set ${profile.secretEnv} in the launching environment.`,3);
  const base=profile.baseUrl.endsWith('/v1')?profile.baseUrl:profile.baseUrl+'/v1';
  const response=await safeRequest(base+'/chat/completions',{allowLocal:profile.provider==='local'||loopback(new URL(base).hostname),allowPrivate:profile.allowPrivate,method:'POST',headers:{'Content-Type':'application/json',...(token?{Authorization:`Bearer ${token}`}:{})},body:JSON.stringify({model:profile.model,messages:[{role:'user',content:'Reply with exactly BYPASS_MODEL_OK.'}],max_tokens:32,stream:false}),timeout:60000});
  need(response.status===200,`Model endpoint returned HTTP ${response.status}. Check endpoint, model ID, and credential reference.`,3);
  let data;try{data=JSON.parse(response.body);}catch{throw new Fault('Model endpoint did not return JSON.',3);}
  need(typeof data.choices?.[0]?.message?.content==='string','Endpoint does not match the supported chat-completions response contract.',3);
  return {status:'connected',provider:profile.provider,model:profile.model,checkedAt:now(),syntheticPrompt:true,repositorySent:false,contract:'OpenAI-compatible chat completions'};
}
