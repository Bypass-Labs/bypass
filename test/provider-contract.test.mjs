import test from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import fs from 'node:fs';
import path from 'node:path';
import { apiProfile, providers, ProviderSession } from '../src/providers.mjs';
import { inExecutionMode } from '../src/execution-mode.mjs';
import { testModel } from '../src/models.mjs';
import { modelResponseSchema } from '../src/inference.mjs';
import { temp } from './helpers.mjs';

const schema=modelResponseSchema('orchestrator');
async function endpoint(t,handler,options={}){
  const calls=[];const server=http.createServer(async(req,res)=>{let body='';for await(const chunk of req)body+=chunk;calls.push({path:req.url,headers:req.headers,body:JSON.parse(body)});handler(req,res,calls.at(-1),calls.length);});
  await new Promise(r=>server.listen(0,'127.0.0.1',r));t.after(()=>{server.closeAllConnections();server.close();});
  const old=process.env.BYPASS_CONTRACT_API_KEY;process.env.BYPASS_CONTRACT_API_KEY='contract-test-value';t.after(()=>{if(old===undefined)delete process.env.BYPASS_CONTRACT_API_KEY;else process.env.BYPASS_CONTRACT_API_KEY=old;});
  return {calls,profile:apiProfile('test',{provider:'custom','base-url':`http://127.0.0.1:${server.address().port}/v1`,model:'explicit-model','secret-env':'BYPASS_CONTRACT_API_KEY',stream:false,...options})};
}
const chat=(res,message)=>{res.setHeader('content-type','application/json');res.end(JSON.stringify({choices:[{finish_reason:message.tool_calls?'tool_calls':'stop',message}]}));};
const action=(value,id='c1')=>({role:'assistant',content:null,reasoning_content:'opaque-reasoning-state',tool_calls:[{id,type:'function',function:{name:'security_action',arguments:JSON.stringify(value)}}]});

test('presets use official destinations, explicit transport and configurable models',()=>{
  const expected={meta:['https://api.meta.ai/v1','responses'],openai:['https://api.openai.com/v1','responses'],anthropic:['https://api.anthropic.com/v1','chat'],moonshot:['https://api.moonshot.ai/v1','chat'],deepseek:['https://api.deepseek.com','chat']};
  for(const [provider,[base,transport]] of Object.entries(expected)){const p=apiProfile('p',{provider});assert.equal(p.baseUrl,base);assert.equal(p.transport,transport);assert.equal(p.executionMode,'standalone-api');assert.equal(apiProfile('p',{provider,model:'explicit-model'}).model,'explicit-model');}
  assert.throws(()=>apiProfile('p',{provider:'anthropic',transport:'responses'}),/No automatic/);
  assert.throws(()=>apiProfile('p',{provider:'anthropic',effort:'high'}),/Unsupported reasoning/);
  assert.throws(()=>apiProfile('p',{provider:'openai','base-url':'https://other.example/v1'}),/explicit --secret-env/);
  for(const provider of ['muse-code','local','endpoint','kimi'])assert.throws(()=>apiProfile('p',{provider}),/explicitly replaced/);
});

test('API key is mandatory; plugin guard wins even with inherited keys and never calls the endpoint',async t=>{
  const {profile,calls}=await endpoint(t,()=>assert.fail('Must not contact API'));
  await assert.rejects(inExecutionMode('muse-host',()=>new ProviderSession(profile).turn([{role:'user',content:'x'}],{schema})),e=>e.details.reason==='host_owned_inference');
  await assert.rejects(inExecutionMode('muse-host',()=>testModel(profile)),e=>e.details.reason==='host_owned_inference');
  delete process.env.BYPASS_CONTRACT_API_KEY;
  await assert.rejects(new ProviderSession(profile).turn([{role:'user',content:'x'}]),e=>e.details.reason==='credential_missing');
  await assert.rejects(new ProviderSession({provider:'muse-code'}).turn([]),e=>e.details.reason==='profile_migration');
  assert.equal(calls.length,0);
  const source=fs.readFileSync(new URL('../src/inference.mjs',import.meta.url),'utf8')+fs.readFileSync(new URL('../src/models.mjs',import.meta.url),'utf8');assert.doesNotMatch(source,/execFile|spawn|homedir|muse.*exec/);
});

test('Chat tool replay retains call IDs and reasoning, validates arguments locally and never echoes raw errors',async t=>{
  const {profile,calls}=await endpoint(t,(_req,res,_call,n)=>chat(res,action({focus:n===1?'inspect':'done'},'call-'+n)));
  const session=new ProviderSession(profile),messages=[{role:'user',content:'Choose next action'}];
  assert.equal((await session.turn(messages,{schema})).focus,'inspect');
  messages.push({role:'assistant',content:'prior action'},{role:'user',content:'{"observation":"actual test"}'});
  assert.equal((await session.turn(messages,{schema})).focus,'done');
  const replay=calls[1].body.messages;assert.equal(replay[1].reasoning_content,'opaque-reasoning-state');assert.equal(replay[2].tool_call_id,'call-1');assert.equal(replay[2].role,'tool');
  assert.equal(calls[0].path,'/v1/chat/completions');assert.equal(calls[0].headers.authorization,'Bearer contract-test-value');
  assert.equal(calls[0].body.model,'explicit-model');assert.equal(calls[0].body.messages[0].content.includes('contract-test-value'),false);
});

test('Responses replays opaque reasoning and function results without previous_response_id',async t=>{
  const {profile,calls}=await endpoint(t,(_req,res,_call,n)=>{res.setHeader('content-type','application/json');res.end(JSON.stringify({status:'completed',output:[{type:'reasoning',id:'rs',encrypted_content:'opaque',summary:[]},{type:'function_call',call_id:'c'+n,name:'security_action',arguments:'{"focus":"ok"}'}]}));},{transport:'responses'});
  const session=new ProviderSession(profile);await session.turn([{role:'user',content:'start'}],{schema});await session.turn([{role:'user',content:'result'}],{schema});
  assert.equal(calls[1].path,'/v1/responses');assert.equal(calls[1].body.store,false);assert.equal(calls[1].body.previous_response_id,undefined);
  assert.equal(calls[1].body.input[1].encrypted_content,'opaque');assert.deepEqual(calls[1].body.input.at(-1),{type:'function_call_output',call_id:'c1',output:'result'});
});

test('malformed arguments, unknown fields and unsupported tool names cannot execute',async t=>{
  for(const value of ['not-json','{"focus":4}','{"focus":"ok","shell":"bad"}']){
    const {profile}=await endpoint(t,(_req,res)=>{const a=action({});a.tool_calls[0].function.arguments=value;chat(res,a);});
    await assert.rejects(new ProviderSession(profile).turn([{role:'user',content:'x'}],{schema}));
  }
});

test('auth/rate failures have actionable categories, no body/key leakage and no retries',async t=>{
  for(const [status,reason] of [[401,'authentication'],[403,'authentication'],[429,'rate_limit'],[400,'unsupported_request'],[503,'provider_unavailable']]){
    const {profile,calls}=await endpoint(t,(_req,res)=>{res.writeHead(status,{'content-type':'application/json'});res.end('{"error":{"message":"PRIVATE_BODY contract-test-value"}}');});
    await assert.rejects(new ProviderSession(profile).turn([{role:'user',content:'x'}]),e=>{assert.equal(e.details.reason,reason);assert.doesNotMatch(e.message,/PRIVATE_BODY|contract-test-value/);return true;});assert.equal(calls.length,1);
  }
});

test('streamed fragmented tool calls assemble correctly; interruption and token truncation fail closed',async t=>{
  const {profile}=await endpoint(t,(_req,res)=>{res.writeHead(200,{'content-type':'text/event-stream'});for(const delta of [{tool_calls:[{index:0,id:'c1',function:{name:'security_action',arguments:'{"fo'}}]},{tool_calls:[{index:0,function:{arguments:'cus":"ok"}'}}]}])res.write('data: '+JSON.stringify({choices:[{delta}]})+'\n\n');res.end('data: {"choices":[{"delta":{},"finish_reason":"tool_calls"}]}\n\ndata: [DONE]\n\n');},{stream:true});
  assert.deepEqual(await new ProviderSession(profile).turn([{role:'user',content:'x'}],{schema}),{focus:'ok'});
  const bad=await endpoint(t,(_req,res)=>chat(res,{role:'assistant',content:'partial'}));
  // A cancellation signal terminates a response that has started streaming.
  const hanging=await endpoint(t,(_req,res)=>{res.writeHead(200,{'content-type':'text/event-stream'});res.write(': waiting\n\n');},{stream:true});
  const c=new AbortController();setTimeout(()=>c.abort(),80);const start=Date.now();
  await assert.rejects(new ProviderSession(hanging.profile).turn([{role:'user',content:'x'}],{signal:c.signal}),e=>e.code===130);assert.ok(Date.now()-start<1500);
  await assert.rejects(new ProviderSession(bad.profile).turn([{role:'user',content:'x'}],{schema}),/no valid security action/);
});

test('synthetic connection check requires exact assistant marker and saves no credential',async t=>{
  const {profile}=await endpoint(t,(_req,res)=>chat(res,{role:'assistant',content:'BYPASS_MODEL_OK'}));
  const result=await testModel(profile,temp());assert.equal(result.repositorySent,false);assert.equal(result.status,'connected');assert.doesNotMatch(JSON.stringify(result),/contract-test-value/);
});

test('each preset uses its supported request contract; Claude workspace/auto choice and DeepSeek thinking toggle',async t=>{
  process.env.BYPASS_TEST_WORKSPACE='workspace-test';t.after(()=>delete process.env.BYPASS_TEST_WORKSPACE);
  for(const provider of ['meta','openai','anthropic','moonshot','deepseek']){
    const {profile,calls}=await endpoint(t,(_req,res,call)=>{
      res.setHeader('content-type','application/json');
      if(call.path.endsWith('/responses'))res.end(JSON.stringify({status:'completed',output:[{type:'function_call',name:'security_action',call_id:'call',arguments:'{"focus":"ok"}'}]}));
      else chat(res,action({focus:'ok'}));
    },{provider,...(provider==='anthropic'?{'workspace-env':'BYPASS_TEST_WORKSPACE'}:{}),...(provider==='deepseek'?{effort:'none'}:{})});
    await new ProviderSession(profile).turn([{role:'user',content:'x'}],{schema});
    assert.equal(calls[0].body.tool_choice,'auto');assert.equal(calls[0].body.response_format,undefined);
    if(provider==='anthropic'){assert.equal(calls[0].headers['anthropic-workspace-id'],'workspace-test');assert.equal(calls[0].body.reasoning_effort,undefined);}
    if(provider==='deepseek'){assert.deepEqual(calls[0].body.thinking,{type:'disabled'});assert.equal(calls[0].body.reasoning_effort,undefined);}
  }
});
test('redirects are not followed and credential changes cannot switch billing mid-session',async t=>{
  const {profile,calls}=await endpoint(t,(_req,res)=>{res.writeHead(307,{location:'https://other-provider.example/v1/chat/completions'});res.end();});
  await assert.rejects(new ProviderSession(profile).turn([{role:'user',content:'x'}]));assert.equal(calls.length,1);
  const ok=await endpoint(t,(_req,res)=>chat(res,action({focus:'ok'}))),session=new ProviderSession(ok.profile);
  await session.turn([{role:'user',content:'x'}],{schema});process.env.BYPASS_CONTRACT_API_KEY='changed-provider-key';
  await assert.rejects(session.turn([{role:'user',content:'result'}],{schema}),e=>e.details.reason==='credential_changed');assert.equal(ok.calls.length,1);
});

test('release-bundled official SDK executes the same API contract without node_modules',async t=>{
  const {ProviderSession:BundledSession}=await import('../plugin/runtime/src/providers.mjs');
  const {profile}=await endpoint(t,(_req,res)=>chat(res,{role:'assistant',content:'BYPASS_MODEL_OK'}));
  assert.equal(await new BundledSession(profile).turn([{role:'user',content:'Reply with exactly BYPASS_MODEL_OK.'}]),'BYPASS_MODEL_OK');
});

test('SDK environment headers, billing identifiers, alternate credentials and debug logging cannot override the profile',async t=>{
  const inherited={OPENAI_API_KEY:'unselected-key',OPENAI_ADMIN_KEY:'unselected-admin',OPENAI_ORG_ID:'other-org',OPENAI_PROJECT_ID:'other-project',OPENAI_WEBHOOK_SECRET:'unused-webhook',OPENAI_BASE_URL:'https://unselected.example/v1',OPENAI_LOG:'debug',OPENAI_CUSTOM_HEADERS:'Authorization: Bearer wrong-key\nOpenAI-Project: wrong-billing\nX-Private-Value: do-not-forward'};
  const previous=Object.fromEntries(Object.keys(inherited).map(k=>[k,process.env[k]]));Object.assign(process.env,inherited);
  t.after(()=>{for(const [key,value] of Object.entries(previous)){if(value===undefined)delete process.env[key];else process.env[key]=value;}});
  const {profile,calls}=await endpoint(t,(_req,res)=>chat(res,{role:'assistant',content:'BYPASS_MODEL_OK'}));
  assert.equal(await new ProviderSession(profile).turn([{role:'user',content:'synthetic'}]),'BYPASS_MODEL_OK');
  assert.equal(calls[0].headers.authorization,'Bearer contract-test-value');
  for(const header of ['openai-organization','openai-project','x-private-value'])assert.equal(calls[0].headers[header],undefined);
});
