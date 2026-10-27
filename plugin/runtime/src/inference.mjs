import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { execFile, need, Fault, abortFault } from './util.mjs';
import { safeRequest, loopback } from './network.mjs';

export function parseModelJSON(text){
  need(typeof text==='string'&&text.length<=64000,'Model response is absent or too large.',3);
  const plain=text.trim().replace(/^```(?:json)?\s*/,'').replace(/\s*```$/,'');
  try {const value=JSON.parse(plain);need(value&&typeof value==='object'&&!Array.isArray(value),'Expected a JSON object.',3);return value;}catch{throw new Fault('Model response was not the required JSON object. No finding was confirmed by this response.',3);}
}
export async function infer(profile,messages,{signal,timeoutMs=120000}={}){
  const deadline=AbortSignal.timeout(timeoutMs),combined=signal?AbortSignal.any([signal,deadline]):deadline;
  try{
    if(profile.provider==='muse-code'){
      const workspace=fs.mkdtempSync(path.join(os.tmpdir(),'bypass-inference-'));
      try{
        const promptFile=path.join(workspace,'request.txt');
        fs.writeFileSync(promptFile,JSON.stringify(messages),{mode:0o600});
        const result=await execFile('muse',['exec','--json','--provider','meta','--workspace',workspace,'--preset','empty','--contributor-mode','off','--no-foreign-personal-context','--no-session-log','--disable-web-tools','--disable-reminders','--disable-request-user-input','--disable-write','--disable-shell','--max-model-steps','1','--reasoning-effort','low',...(profile.model&&profile.model!=='Muse session default'?['--model',profile.model]:[]),'--prompt-file',promptFile],{cwd:workspace,signal:combined,timeout:timeoutMs,killGroup:true,env:{MUSE_CONTRIBUTOR_MODE:'0'}});
        const terminal=result.stdout.split('\n').flatMap(line=>{try{return [JSON.parse(line).payload];}catch{return [];}}).findLast(e=>e?.kind==='run_terminal');
        need(result.code===0&&terminal?.terminal==='completed','Muse inference did not complete. Check muse usage/login or choose another model; no mock fallback was used.',3);
        return parseModelJSON(terminal.text);
      }finally{fs.rmSync(workspace,{recursive:true,force:true});}
    }
    const token=profile.secretEnv?process.env[profile.secretEnv]:null;
    need(!profile.secretEnv||token,`Set ${profile.secretEnv} before running the agent.`,3);
    const base=profile.baseUrl.endsWith('/v1')?profile.baseUrl:profile.baseUrl+'/v1';
    const response=await safeRequest(base+'/chat/completions',{allowLocal:profile.provider==='local'||loopback(new URL(base).hostname),allowPrivate:profile.allowPrivate,method:'POST',headers:{'Content-Type':'application/json',...(token?{Authorization:`Bearer ${token}`}:{})},body:JSON.stringify({model:profile.model,messages,max_tokens:4096,stream:false}),timeout:timeoutMs,signal:combined,maxBytes:262144});
    need(response.status===200,`Model returned HTTP ${response.status}. Check endpoint, model and credentials; no mock fallback was used.`,3);
    let data;try{data=JSON.parse(response.body);}catch{throw new Fault('Model endpoint returned invalid JSON.',3);}
    return parseModelJSON(data.choices?.[0]?.message?.content);
  }catch(error){if(signal?.aborted)throw abortFault(signal);if(deadline.aborted)throw new Fault('Model response exceeded two minutes. Run is incomplete; retry or change model.',3);throw error;}
}
