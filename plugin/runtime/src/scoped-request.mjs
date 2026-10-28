import fs from 'node:fs';
import path from 'node:path';
import { read, change, event, writeEvidence } from './store.mjs';
import { scopeReady, pathAllowed, safeRequest } from './network.mjs';
import { credentialEnvironment } from './credentials.mjs';
import { httpMethod, mayChangeData } from './http-methods.mjs';
import { jsonField } from './portable-check.mjs';
import { need, named, id, now, hash, delay, redact, registerSecret, outcome } from './util.mjs';

// A single operator/host-directed request for setup or observation. Writes are
// never put in automatic scan/replay queues and a response is not a finding.
export async function scopedRequest(root,o,{signal,request=safeRequest}={}){
  const state=read(root),target=named(state.targets,o.target||state.activeTarget,'Target'),method=httpMethod(o.method||'GET');
  const resourcePath=o.path;
  need(typeof resourcePath==='string'&&resourcePath.startsWith('/')&&!resourcePath.startsWith('//')&&!/[\x00-\x20\x7f?#\\]/.test(resourcePath)&&pathAllowed(resourcePath,[resourcePath]),'Provide an exact app path without a query string, fragment, whitespace or traversal.');
  scopeReady(target,resourcePath,method);
  need(!(o.body!==undefined&&o['body-file']),'Choose an inline JSON body or a body file, not both.');
  let body=o.body;
  if(o['body-file']){
    const file=path.resolve(root,o['body-file']);need(fs.statSync(file).isFile()&&fs.statSync(file).size<=65536,'Request JSON file must be at most 64 KiB.');
    try{body=JSON.parse(fs.readFileSync(file,'utf8'));}catch{throw new Error('Request body file must contain valid JSON.');}
  }
  need(body===undefined||body!==null&&typeof body==='object','Use a JSON object or array as the request body.');
  need(body===undefined||!['GET','HEAD','TRACE'].includes(method),`${method} requests do not accept a body in this runner.`);
  need(method!=='TRACE'||!o.identity,'TRACE cannot send account credentials.');
  const payload=body===undefined?undefined:JSON.stringify(body);
  need(payload===undefined||Buffer.byteLength(payload)<=65536,'Request body must be at most 64 KiB.');
  if(o['id-field'])need(typeof o['id-field']==='string'&&o['id-field'].length<=256&&!/token|secret|password|cookie|authorization/i.test(o['id-field']),'Select a resource ID field, not a credential field.');
  const headers={Accept:'application/json','User-Agent':'Bypass-Request/0.1',...(payload!==undefined?{'Content-Type':'application/json','Content-Length':String(Buffer.byteLength(payload))}:{})};
  if(o.identity){
    const identity=named(state.identities,o.identity,'Identity');need(identity.target===target.name,'Identity belongs to another app.');
    const env=await credentialEnvironment(state,target,[identity],{signal});
    const fixture=target.environment==='local'&&(state.demo?.target===target.name||state.poc&&target.pocFixture);
    const token=env[identity.secretEnv]||(fixture?identity.fixtureValue:null);
    need(typeof token==='string'&&token&&!/[\r\n\0]/.test(token),'Connect this account before sending an authenticated request.',3);registerSecret(token);
    if(identity.type==='bearer')headers.Authorization=`Bearer ${token}`;
    else if(identity.type==='cookie')headers.Cookie=token;
    else {need(/^[A-Za-z][A-Za-z0-9-]*$/.test(identity.header)&&!['host','connection','content-length','transfer-encoding','content-type'].includes(identity.header.toLowerCase()),'Invalid identity header.');headers[identity.header]=token;}
  }
  const runId=id('run'),fingerprint=hash(target.authorization);
  const reserved=await change(root,s=>{
    const app=named(s.targets,target.name,'Target');scopeReady(app,resourcePath,method);
    need(hash(app.authorization)===fingerprint,'Testing scope changed; review it before sending this request.',3);
    const scheduledAt=Math.max(Date.now(),app.nextDirectRequestAt||0);
    app.nextDirectRequestAt=scheduledAt+Math.ceil(1000/app.authorization.maxRequestsPerSecond);
    const run={id:runId,kind:'request',pid:process.pid,options:{target:target.name,method,path:resourcePath,identity:o.identity||null,bodyPresent:payload!==undefined},status:'running',createdAt:now(),startedAt:now(),steps:[],modelCalls:0,
      result:{status:'pending',origin:app.url,method,path:resourcePath,requests:0,modelCalls:0,securityConclusion:false,automaticReplay:false,bodyStored:false}};
    s.runs.push(run);return {run,scheduledAt};
  });
  writeEvidence(root,reserved.run);
  let result={...reserved.run.result},exitCode=0;
  try{
    await delay(Math.max(0,reserved.scheduledAt-Date.now()),undefined,{signal});
    const current=read(root),app=named(current.targets,target.name,'Target');scopeReady(app,resourcePath,method);
    need(app.url===target.url&&hash(app.authorization)===fingerprint,'Testing scope changed before the request.',3);
    need(!named(current.runs,runId,'Run').cancelRequested,'Request cancelled before sending.',130);
    if(signal?.aborted)throw signal.reason;
    // Durable send boundary: recovery treats a crash after this point as an
    // unknown outcome. It must inspect the app before repeating a possible write.
    const sending=await change(root,s=>{const current=named(s.targets,target.name,'Target');scopeReady(current,resourcePath,method);need(hash(current.authorization)===fingerprint,'Testing scope changed before sending.',3);const r=named(s.runs,runId,'Run');need(!r.cancelRequested,'Request cancelled before sending.',130);Object.assign(r.result,{requests:1,status:'sending',outcome:'unknown',next:'If interrupted, inspect the app before repeating this request. Bypass will not retry it.'});r.steps.push({at:now(),stage:'request',message:`Sending ${method} ${resourcePath}`});return r;});writeEvidence(root,sending);
    result.requests=1;
    const response=await request(app.url+resourcePath,{method,headers,body:payload,allowLocal:app.environment==='local',timeout:state.settings.requestTimeoutMs,signal,maxBytes:131072});
    let resourceId=null;
    if(o['id-field'])try{const value=jsonField(JSON.parse(response.body),o['id-field']);if(['string','number'].includes(typeof value)&&/^[A-Za-z0-9_-]{1,160}$/.test(String(value)))resourceId=String(value);}catch{}
    result={...result,status:'observed',httpStatus:response.status,...(o['id-field']?{resourceId,idField:o['id-field']}:{}),
      message:'HTTP response observed. This request alone is not a confirmed security finding.',
      next:resourceId?'Use this observed test resource ID for access controls.':'Inspect the status and source contract before choosing the next check.'};
    if(mayChangeData([method]))result.cleanup='This request may create or change data or start a job. Track the observed test resource and clean it up using an explicitly allowed method/path.';
  }catch(error){
    exitCode=signal?.aborted||error.code===130?130:3;
    result={...result,status:exitCode===130?'cancelled':'blocked',reason:redact(error.message),outcome:result.requests?'unknown':'not_sent',
      next:result.requests?'The request may have been applied. Inspect the app before repeating it; Bypass did not retry.':'Review the exact method and path permissions, then try again.'};
  }
  const finished=await change(root,s=>{const run=named(s.runs,runId,'Run');Object.assign(run,{status:exitCode===130?'cancelled':exitCode?'failed':'completed',finishedAt:now(),exitCode,result:redact(result)});event(s,'request',`${method} ${resourcePath}: ${result.httpStatus||result.status}`,{runId,target:target.name});return run;});
  writeEvidence(root,finished);
  return outcome({kind:'scoped-request',runId,...finished.result},exitCode);
}
