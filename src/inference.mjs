import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { execFile, need, Fault, abortFault } from './util.mjs';
import { safeRequest, loopback } from './network.mjs';

export const INFERENCE_TIMEOUT_MS=60000;
// Expose a small allowlist of transport facts, never model reasoning or provider text.
export function museProgress(onProgress){
  let buffer='';
  return chunk=>{
    buffer+=chunk;let newline;
    while((newline=buffer.indexOf('\n'))>=0){
      const line=buffer.slice(0,newline);buffer=buffer.slice(newline+1);
      let event;try{event=JSON.parse(line).payload;}catch{continue;}
      if(event?.kind==='run_model_configured'&&/^[\w./:-]{1,160}$/.test(event.model_id||''))onProgress?.({kind:'model',model:event.model_id});
      const phase=event?.event?.details?.phase;
      const labels={opening_stream:'Muse connected; waiting for the provider response',stream_succeeded:'Provider response received; validating JSON'};
      if(event?.kind==='task_lifecycle'&&event.event.kind==='status'&&labels[phase])onProgress?.({kind:'phase',phase,message:labels[phase]});
      if(phase==='stream_failed'){
        const status=event.event.details.facets?.find(f=>f.kind==='external_attempt')?.http_status;
        if(Number.isInteger(status)&&status>=400&&status<=599)onProgress?.({kind:'phase',phase,message:`Muse provider returned HTTP ${status}`});
      }
    }
  };
}

export function parseModelJSON(text){
  need(typeof text==='string'&&text.length<=64000,'Model response is absent or too large.',3);
  const plain=text.trim().replace(/^```(?:json)?\s*/,'').replace(/\s*```$/,'');
  try {const value=JSON.parse(plain);need(value&&typeof value==='object'&&!Array.isArray(value),'Expected a JSON object.',3);return value;}catch{throw new Fault('Model response was not the required JSON object. No finding was confirmed by this response.',3);}
}
export function inferenceFailure(result,events){
  const terminal=events.findLast(e=>e?.kind==='run_terminal');
  // Inspect diagnostic fields only, never prompt echoes, model content or tool output.
  const failures=events.filter(e=>e?.event?.kind==='failed').map(e=>e.event.reason||e.event.error);
  const diagnostic=JSON.stringify([terminal?.reason,result.stderr,...failures]);
  let reason='muse_failed',message='Muse stopped before returning a completed model response. Retry the review; your setup and earlier evidence are saved.';
  if(/429|rate.?limit|quota|allowance.*(?:exhaust|exceed|limit)/i.test(diagnostic)){reason='usage_limit';message='Muse reports a provider usage limit. Check muse usage and retry when allowance is available.';}
  else if(/401|unauthori[sz]ed|login required|not logged|invalid.*(?:api.?key|token)/i.test(diagnostic)){reason='authentication';message='Muse reports an authentication failure. Renew the Muse login, then retry the review.';}
  else if(/context.{0,20}(?:limit|length|window)|too many tokens|request.{0,20}too large/i.test(diagnostic)){reason='context_limit';message='Muse reports an input/context limit. Review a smaller source scope or select a model with sufficient context.';}
  else if(/400|invalid_request|schema/i.test(diagnostic)){reason='request_format';message='Muse rejected the model request format. Update Bypass or choose a compatible model; repeating this request will not fix it.';}
  else if(/step.{0,10}limit|maximum.{0,20}steps/i.test(diagnostic)){reason='model_step_limit';message='Muse reached its single-response step limit instead of returning JSON. Retry the review; no finding was accepted from that response.';}
  else if(/network|ECONN|ENOTFOUND|TLS|timed out|502|503|504|overload/i.test(diagnostic)){reason='provider_unavailable';message='Muse reports a provider/network interruption. Retry the review; your setup and earlier evidence are saved.';}
  return new Fault(message+' No mock fallback was used.',3,{reason,nativeExitCode:result.code,terminal:typeof terminal?.terminal==='string'?terminal.terminal.slice(0,40):'missing'});
}
export function modelResponseSchema(role){
  if(role==='orchestrator')return {type:'object',properties:{focus:{type:'string',maxLength:2000}},required:['focus'],additionalProperties:false};
  const properties={action:{type:'string',enum:role==='white-box'?['read_files','finish']:['probe','finish']},summary:{type:'string'}};
  if(role==='white-box'){
    properties.paths={type:'array',maxItems:8,items:{anyOf:[{type:'string'},{type:'object',properties:{path:{type:'string'},startLine:{type:'integer',minimum:1},endLine:{type:'integer',minimum:1}},required:['path','startLine','endLine'],additionalProperties:false}]}};
    properties.candidates={type:'array',maxItems:8,items:{type:'object',properties:{title:{type:'string'},category:{type:'string',enum:['cross-account-access','missing-authentication']},file:{type:'string'},line:{type:'integer',minimum:1},quote:{type:'string'},resourcePath:{type:['string','null']},hypothesis:{type:'string'},recommendation:{type:'string'}},required:['title','category','file','line','quote','resourcePath','hypothesis','recommendation'],additionalProperties:false}};
  }else properties.bindingIndex={type:['integer','null'],minimum:0};
  // Muse's strict schema contract requires every property; unused arrays are empty.
  return {type:'object',properties,required:Object.keys(properties),additionalProperties:false};
}
export async function infer(profile,messages,{signal,timeoutMs=INFERENCE_TIMEOUT_MS,onProgress,schema}={}){
  const deadline=AbortSignal.timeout(timeoutMs),combined=signal?AbortSignal.any([signal,deadline]):deadline;
  try{
    if(profile.provider==='muse-code'){
      const workspace=fs.mkdtempSync(path.join(os.tmpdir(),'bypass-inference-'));
      try{
        const promptFile=path.join(workspace,'request.txt');
        fs.writeFileSync(promptFile,JSON.stringify(messages),{mode:0o600});
        const schemaFile=path.join(workspace,'response-schema.json');
        if(schema)fs.writeFileSync(schemaFile,JSON.stringify(schema),{mode:0o600});
        const result=await execFile('muse',['exec','--json','--provider','meta','--workspace',workspace,'--preset','empty','--contributor-mode','off','--no-foreign-personal-context','--no-session-log','--disable-web-tools','--disable-reminders','--disable-request-user-input','--disable-write','--disable-shell','--max-model-steps','1','--reasoning-effort',profile.effort||'minimal',...(profile.model&&profile.model!=='Muse session default'?['--model',profile.model]:[]),...(schema?['--output-schema',schemaFile]:[]),'--prompt-file',promptFile],{cwd:workspace,signal:combined,timeout:timeoutMs,killGroup:true,env:{MUSE_CONTRIBUTOR_MODE:'0'},onStdout:museProgress(onProgress)});
        const events=result.stdout.split('\n').flatMap(line=>{try{return [JSON.parse(line).payload];}catch{return [];}});
        const terminal=events.findLast(e=>e?.kind==='run_terminal');
        if(result.code!==0||terminal?.terminal!=='completed')throw inferenceFailure(result,events);
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
  }catch(error){if(signal?.aborted)throw abortFault(signal);if(deadline.aborted||error.details?.reason==='timeout')throw new Fault(`Model did not finish within ${Math.ceil(timeoutMs/1000)} seconds. Review incomplete; setup and earlier evidence are saved. Check the model connection before retrying.`,3,{reason:'model_timeout',retryable:true,next:'model test',timeoutMs});throw error;}
}
