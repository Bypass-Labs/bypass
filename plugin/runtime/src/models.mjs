import { execFile, need, envName, now, Fault, abortFault } from './util.mjs';
import { safeRequest, loopback } from './network.mjs';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';

export function modelProfile(name, options) {
  const provider=options.provider;
  need(['local','endpoint','muse-code'].includes(provider),'Choose --provider local, endpoint, or muse-code.');
  if(provider==='muse-code'){
    const effort=options.effort||'minimal';
    need(['minimal','low','medium','high'].includes(effort),'Choose --effort minimal, low, medium, or high.');
    return {name,provider,model:options.model || 'Muse session default',effort,dataDestination:'Muse Code account/provider',contributorMode:'off for Bypass-launched requests',createdAt:now()};
  }
  need(options['base-url']&&options.model,'Endpoint profiles require --base-url and --model.');
  const u=new URL(options['base-url']);
  need(!u.username&&!u.password&&!u.search&&!u.hash,'Model URL must not contain credentials, queries, or fragments.');
  need(u.protocol==='https:'||(u.protocol==='http:'&&loopback(u.hostname)),'Use HTTPS for remote inference, or HTTP for a loopback model.');
  need(provider!=='local'||loopback(u.hostname),'Local model profiles must use a loopback endpoint.');
  return {name,provider,baseUrl:u.toString().replace(/\/$/,''),model:options.model,secretEnv:options['secret-env']?envName(options['secret-env']):null,allowPrivate:!!options['allow-private'],dataDestination:provider==='local'?'this machine':u.origin,createdAt:now()};
}
export const MODEL_CHECK_TIMEOUT_MS=45000;
const marker='BYPASS_MODEL_OK';
const fail=(reason,message)=>new Fault(message,3,{reason});

function museFailure(result, terminal, events) {
  // Classify provider diagnostics without printing or saving raw provider output or credentials.
  const diagnostics=events.flatMap(event=>[event?.reason,event?.error,event?.event?.reason,event?.event?.error]).filter(Boolean);
  const detail=`${result.stderr}\n${JSON.stringify(terminal||{})}\n${JSON.stringify(diagnostics)}`;
  if(/429|rate.?limit|quota|allowance.*(?:exhaust|exceed|limit|insufficient)|exhaust/i.test(detail))return fail('usage_limit','Muse reports a usage limit. Run muse usage to check your allowance, then retry later. You can continue setup now.');
  if(/401|unauthori[sz]ed|not logged|login required|sign.?in|expired|invalid.*(key|token)|missing.*(key|credential)/i.test(detail))return fail('authentication','Muse needs a valid login. Run muse login in another terminal, then retry. If META_API_KEY is set, it takes priority over your login; check that override privately.');
  if(/unknown.*(option|argument)|unexpected.*(option|argument)|unrecognized.*(option|argument)/i.test(detail))return fail('cli_version','This Muse CLI does not support the connection-check options. Update Muse, then retry. You can continue setup without the check.');
  if(/403|model.*(not found|unavailable|not available|access|unsupported)|access denied/i.test(detail))return fail('model_access','Muse could not access the selected model. Check model access in Muse and run muse usage; then retry.');
  if(/network|ENOTFOUND|ECONN|DNS|TLS|certificate|connect.*fail|timed out/i.test(detail))return fail('network','Muse could not reach its provider. Check your network, VPN, or proxy, then run muse usage and retry.');
  return fail('muse_failed',`Muse did not complete the test (exit ${result.code}). Run muse usage to check account access, or try a short prompt in Muse. You can continue setup and retry later.`);
}

export async function testModel(profile, root, {signal:externalSignal,onProgress,timeoutMs=MODEL_CHECK_TIMEOUT_MS}={}) {
  const deadline=new AbortController();
  const timer=setTimeout(()=>deadline.abort(fail('timeout',`No model response within ${Math.ceil(timeoutMs/1000)} seconds. Your profile is saved. This can be a slow provider or network; it does not by itself mean your login is wrong. Retry later or continue setup.`)),timeoutMs);
  const signal=externalSignal?AbortSignal.any([externalSignal,deadline.signal]):deadline.signal;
  const started=Date.now();
  const progress=message=>onProgress?.({message,elapsedSeconds:Math.floor((Date.now()-started)/1000),timeoutSeconds:Math.ceil(timeoutMs/1000)});
  const heartbeat=onProgress?setInterval(()=>progress(`Waiting for ${profile.provider==='muse-code'?'Muse':'your model server'}…`),5000):null;
  try {
    if(signal.aborted)throw abortFault(signal);
    if(profile.provider==='muse-code'){
      progress('Checking that Muse Code is installed…');
      const version=await execFile('muse',['--version'],{timeout:5000,signal,killGroup:true});
      need(version.code===0,'Muse CLI could not start. Check muse --version in your terminal.',3,{reason:'cli_unavailable'});
      const workspace=fs.mkdtempSync(path.join(os.tmpdir(),'bypass-model-smoke-'));
      let result;
      try {
        progress('Muse is installed. Sending the small test prompt; waiting for a reply…');
        result=await execFile('muse',['exec','--json','--provider','meta','--workspace',workspace,'--preset','empty','--contributor-mode','off','--no-foreign-personal-context','--no-session-log','--disable-web-tools','--disable-reminders','--disable-request-user-input','--disable-write','--disable-shell','--max-model-steps','1','--reasoning-effort',profile.effort||'minimal',...(profile.model&&profile.model!=='Muse session default'?['--model',profile.model]:[]),`Reply with exactly ${marker}. Do not use tools or read files.`],{cwd:workspace,timeout:timeoutMs,signal,killGroup:true,env:{MUSE_CONTRIBUTOR_MODE:'0'}});
      } finally { fs.rmSync(workspace,{recursive:true,force:true}); }
      const events=result.stdout.split('\n').flatMap(line=>{try{return [JSON.parse(line).payload];}catch{return [];}});
      const terminal=events.findLast(event=>event?.kind==='run_terminal');
      if(result.code!==0 || terminal?.terminal!=='completed')throw museFailure(result,terminal,events);
      // The prompt itself contains the marker. Only a completed assistant reply is evidence.
      need(terminal.text?.trim()===marker,'Muse responded, but did not return the expected test reply. Connection is not confirmed; retry the check.',3,{reason:'unexpected_response'});
      const configured=events.findLast(event=>event?.kind==='run_model_configured');
      return {status:'connected',provider:profile.provider,model:configured?.model_id||profile.model,checkedAt:now(),elapsedMs:Date.now()-started,syntheticPrompt:true,repositorySent:false,workspace:'empty temporary directory',note:'A small reply worked; a complete source review can still fail.'};
    }
    const token=profile.secretEnv?process.env[profile.secretEnv]:null;
    if(profile.secretEnv)need(token,`Set ${profile.secretEnv} in the terminal that launches Bypass, then retry. Enter the variable name in setup, never its secret value.`,3,{reason:'credential_missing'});
    const base=profile.baseUrl.endsWith('/v1')?profile.baseUrl:profile.baseUrl+'/v1';
    progress('Contacting your model server with the small test prompt…');
    const response=await safeRequest(base+'/chat/completions',{allowLocal:profile.provider==='local'||loopback(new URL(base).hostname),allowPrivate:profile.allowPrivate,method:'POST',headers:{'Content-Type':'application/json',...(token?{Authorization:`Bearer ${token}`}:{})},body:JSON.stringify({model:profile.model,messages:[{role:'user',content:`Reply with exactly ${marker}.`}],max_tokens:32,stream:false}),timeout:timeoutMs,signal});
    const guidance=response.status===401||response.status===403?'Check the credential environment variable and model access.':response.status===404?'Check the server base URL and loaded model ID.':response.status===429?'Check the server usage limit and retry later.':response.status>=500?'The model server reported an error. Check that it is ready and retry later.':'Check endpoint, model ID, and credential reference.';
    need(response.status===200,`Model endpoint returned HTTP ${response.status}. ${guidance}`,3,{reason:`http_${response.status}`});
    let data;try{data=JSON.parse(response.body);}catch{throw fail('response_format','Model endpoint did not return JSON. Check that the URL is an API endpoint, not a web page.');}
    need(typeof data.choices?.[0]?.message?.content==='string','Endpoint does not match the supported chat-completions response contract.',3,{reason:'response_format'});
    need(data.choices[0].message.content.trim()===marker,'The model server responded, but did not return the expected test reply. Retry with the correct loaded model.',3,{reason:'unexpected_response'});
    return {status:'connected',provider:profile.provider,model:profile.model,checkedAt:now(),elapsedMs:Date.now()-started,syntheticPrompt:true,repositorySent:false,contract:'OpenAI-compatible chat completions'};
  } catch(error) {
    if(signal.aborted)throw abortFault(signal);
    if(error.details?.causeCode==='ENOENT')throw fail('cli_missing','Muse Code was not found in this terminal. Install Muse, reopen your terminal, and check muse --version. You can continue setup now.');
    if(error.details?.reason==='timeout')throw fail('timeout','The Muse command did not respond in time. Run muse --version, check your network, and retry. Your setup is saved.');
    if(/ECONNREFUSED/.test(error.message))throw fail('server_unavailable',`Your model server is not accepting connections at ${profile.baseUrl}. Start the server, load the selected model, and retry.`);
    throw error;
  } finally {clearTimeout(timer);clearInterval(heartbeat);}
}
