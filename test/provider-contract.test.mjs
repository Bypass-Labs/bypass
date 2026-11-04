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
import { execute } from '../src/service.mjs';
import { read } from '../src/store.mjs';

const schema=modelResponseSchema('orchestrator');
async function endpoint(t,handler,options={}){
  const calls=[];const server=http.createServer(async(req,res)=>{let body='';for await(const chunk of req)body+=chunk;calls.push({path:req.url,headers:req.headers,body:JSON.parse(body)});handler(req,res,calls.at(-1),calls.length);});
  await new Promise(r=>server.listen(0,'127.0.0.1',r));t.after(()=>{server.closeAllConnections();server.close();});
  const old=process.env.BYPASS_CONTRACT_API_KEY;process.env.BYPASS_CONTRACT_API_KEY='contract-test-value';t.after(()=>{if(old===undefined)delete process.env.BYPASS_CONTRACT_API_KEY;else process.env.BYPASS_CONTRACT_API_KEY=old;});
  return {calls,profile:apiProfile('test',{provider:'custom','base-url':`http://127.0.0.1:${server.address().port}/v1`,model:'explicit-model','secret-env':'BYPASS_CONTRACT_API_KEY',stream:false,...options})};
}
const chat=(res,message)=>{res.setHeader('content-type','application/json');res.end(JSON.stringify({choices:[{finish_reason:message.tool_calls?'tool_calls':'stop',message}]}));};
const action=(value,id='c1')=>({role:'assistant',content:null,reasoning_content:'opaque-reasoning-state',tool_calls:[{id,type:'function',function:{name:'security_action',arguments:JSON.stringify(value)}}]});

test('explicit JSON-schema profiles persist and send schema constraints without tools in both transports',async t=>{
  for(const transport of ['chat','responses'])await t.test(transport,async t=>{
    const {profile,calls}=await endpoint(t,(_req,res)=>{
      if(transport==='chat')chat(res,{role:'assistant',content:'{"focus":"ok"}'});
      else{res.setHeader('content-type','application/json');res.end(JSON.stringify({status:'completed',output:[{type:'message',role:'assistant',content:[{type:'output_text',text:'{"focus":"ok"}'}]}]}));}
    },{transport,'response-mode':'json-schema'});
    const root=temp();await execute('init',[root]);
    await execute('model add',['json'],{project:root,provider:'custom','base-url':profile.baseUrl,model:profile.model,'secret-env':profile.secretEnv,transport,'response-mode':'json-schema',stream:false});
    const saved=read(root).models.find(p=>p.name==='json');assert.equal(saved.responseMode,'json-schema');
    const session=new ProviderSession(saved);
    for(let i=0;i<2;i++)assert.deepEqual(await session.turn([{role:'user',content:i?'feedback':'start'}],{schema}),{focus:'ok'});
    for(const call of calls){
      assert.equal(call.body.tools,undefined);assert.equal(call.body.tool_choice,undefined);
      const format=transport==='chat'?call.body.response_format.json_schema:call.body.text.format;
      assert.equal(format.name,'security_action');assert.equal(format.strict,true);assert.deepEqual(format.schema,schema);
    }
    assert.equal((transport==='chat'?calls[1].body.messages:calls[1].body.input).at(-1).role,'user');
  });
  assert.throws(()=>apiProfile('bad',{provider:'meta','response-mode':'json-schema'}),/custom provider/);
  assert.throws(()=>apiProfile('bad',{provider:'meta','response-mode':'invalid'}),/Response mode/);
});

test('JSON-schema mode fails explicitly on unsupported servers without fallback or retry',async t=>{
  const {profile,calls}=await endpoint(t,(_req,res)=>{res.statusCode=400;res.setHeader('content-type','application/json');res.end(JSON.stringify({error:{message:'Unsupported format'}}));},{'response-mode':'json-schema'});
  await assert.rejects(new ProviderSession(profile).turn([{role:'user',content:'x'}],{schema}));
  assert.equal(calls.length,1);
});

test('JSON-schema Chat supports streamed content and still rejects schema-invalid JSON',async t=>{
  for(const valid of [true,false])await t.test(String(valid),async t=>{
    const {profile}=await endpoint(t,(_req,res)=>{
      res.writeHead(200,{'content-type':'text/event-stream'});
      res.end(`data: ${JSON.stringify({choices:[{delta:{content:valid?'{"focus":"ok"}':'{"focus":4}'},finish_reason:'stop'}]})}\n\ndata: [DONE]\n\n`);
    },{stream:true,'response-mode':'json-schema'});
    const result=new ProviderSession(profile).turn([{role:'user',content:'x'}],{schema});
    if(valid)assert.deepEqual(await result,{focus:'ok'});
    else await assert.rejects(result,error=>error.details.responseDiagnostics.schemaStatus==='invalid');
  });
});

test('presets use official destinations, explicit transport and configurable models',()=>{
  const expected={meta:['https://api.meta.ai/v1','responses'],openai:['https://api.openai.com/v1','responses'],anthropic:['https://api.anthropic.com/v1','chat'],moonshot:['https://api.moonshot.ai/v1','chat'],deepseek:['https://api.deepseek.com','chat']};
  for(const [provider,[base,transport]] of Object.entries(expected)){const p=apiProfile('p',{provider});assert.equal(p.baseUrl,base);assert.equal(p.transport,transport);assert.equal(p.executionMode,'standalone-api');assert.equal(apiProfile('p',{provider,model:'explicit-model'}).model,'explicit-model');}
  assert.throws(()=>apiProfile('p',{provider:'anthropic',transport:'responses'}),/No automatic/);
  assert.throws(()=>apiProfile('p',{provider:'anthropic',effort:'high'}),/Unsupported reasoning/);
  assert.throws(()=>apiProfile('p',{provider:'openai','base-url':'https://other.example/v1'}),/explicit --secret-env/);
  for(const provider of ['muse-code','local','endpoint','kimi'])assert.throws(()=>apiProfile('p',{provider}),/explicitly replaced/);
  assert.equal(apiProfile('p',{provider:'meta','timeout-ms':'0'}).timeoutMs,0);
  assert.equal(apiProfile('p',{provider:'meta'}).timeoutMs,60000);
  for(const timeout of [-1,1,999,180001,'invalid'])assert.throws(()=>apiProfile('p',{provider:'meta','timeout-ms':timeout}),/Model timeout/);
});

test('custom profiles persist explicit reasoning effort and forward the selected protocol field',async t=>{
  for(const transport of ['chat','responses'])await t.test(transport,async t=>{
    const {profile,calls}=await endpoint(t,(_req,res)=>{
      if(transport==='chat')chat(res,action({focus:'test'}));
      else{res.setHeader('content-type','application/json');res.end(JSON.stringify({status:'completed',output:[{type:'function_call',name:'security_action',call_id:'c1',arguments:'{"focus":"test"}'}]}));}
    },{transport,effort:'minimal'});
    const root=temp();await execute('init',[root]);
    await execute('model add',['glimmer-minimal'],{project:root,provider:'custom','base-url':profile.baseUrl,model:profile.model,'secret-env':profile.secretEnv,transport,effort:'minimal',stream:false});
    await execute('model use',['glimmer-minimal'],{project:root});
    const saved=read(root).models.find(model=>model.name===read(root).activeModel);
    assert.equal(saved.effort,'minimal');
    assert.equal((await new ProviderSession(saved).turn([{role:'user',content:'Synthetic check'}],{schema})).focus,'test');
    if(transport==='chat'){assert.equal(calls[0].body.reasoning_effort,'minimal');assert.equal(calls[0].body.reasoning,undefined);}
    else{assert.deepEqual(calls[0].body.reasoning,{effort:'minimal'});assert.equal(calls[0].body.reasoning_effort,undefined);}
    for(const effort of ['minimal','low','medium','high','xhigh','max'])assert.equal(apiProfile('test',{provider:'custom','base-url':profile.baseUrl,model:profile.model,effort}).effort,effort);
    for(const effort of ['none','invalid'])assert.throws(()=>apiProfile('test',{provider:'custom','base-url':profile.baseUrl,model:profile.model,effort}),/Unsupported reasoning/);
  });
});

test('custom profiles omit reasoning overrides by default and never retry unsupported efforts',async t=>{
  for(const transport of ['chat','responses'])await t.test(transport,async t=>{
    const {profile,calls}=await endpoint(t,(_req,res)=>{
      if(transport==='chat')chat(res,action({focus:'test'}));
      else{res.setHeader('content-type','application/json');res.end(JSON.stringify({status:'completed',output:[{type:'function_call',name:'security_action',call_id:'c1',arguments:'{"focus":"test"}'}]}));}
    },{transport});
    await new ProviderSession(profile).turn([{role:'user',content:'Synthetic check'}],{schema});
    assert.equal(calls[0].body.reasoning_effort,undefined);assert.equal(calls[0].body.reasoning,undefined);
    const rejected=await endpoint(t,(_req,res)=>{res.writeHead(400,{'content-type':'application/json'});res.end('{"error":{"message":"PRIVATE_UNSUPPORTED_SETTING"}}');},{transport,effort:'minimal'});
    await assert.rejects(new ProviderSession(rejected.profile).turn([{role:'user',content:'Synthetic check'}],{schema}),error=>{
      assert.equal(error.details.reason,'unsupported_request');assert.doesNotMatch(error.message,/PRIVATE_UNSUPPORTED_SETTING/);return true;
    });
    assert.equal(rejected.calls.length,1);
  });
});

test('provider sessions allow scanner opt-in beyond ten turns while retaining the default cap',async t=>{
  const {profile,calls}=await endpoint(t,(_req,res)=>chat(res,action({focus:'test'})));
  const unlimited=new ProviderSession(profile,{maxTurns:null});
  for(let turn=0;turn<12;turn++)assert.equal((await unlimited.turn([{role:'user',content:'Synthetic observation'}],{schema})).focus,'test');
  assert.equal(calls.length,12);
  const bounded=new ProviderSession(profile);
  for(let turn=0;turn<10;turn++)await bounded.turn([{role:'user',content:'Synthetic observation'}],{schema});
  await assert.rejects(bounded.turn([{role:'user',content:'Synthetic observation'}],{schema}),/exceeded 10 turns/);
  assert.equal(calls.length,22);
  for(const maxTurns of [0,-1,1.5,Infinity])assert.throws(()=>new ProviderSession(profile,{maxTurns}),/Provider turn limit/);
});

test('no-timeout profiles retain SDK parsing without deadline or socket timers',async t=>{
  for(const transport of ['chat','responses'])for(const stream of [false,true]){
    await t.test(`${transport} ${stream?'streamed':'buffered'}`,async t=>{
      const {profile}=await endpoint(t,(_req,res)=>{
        if(!stream){
          if(transport==='chat')chat(res,{role:'assistant',content:'BYPASS_MODEL_OK'});
          else{res.setHeader('content-type','application/json');res.end(JSON.stringify({status:'completed',output:[{type:'message',content:[{type:'output_text',text:'BYPASS_MODEL_OK'}]}]}));}
        }else{
          res.writeHead(200,{'content-type':'text/event-stream'});
          const event=transport==='chat'?{choices:[{delta:{content:'BYPASS_MODEL_OK'},finish_reason:'stop'}]}:
            {type:'response.completed',response:{status:'completed',output:[{type:'message',content:[{type:'output_text',text:'BYPASS_MODEL_OK'}]}]}};
          res.end(`data: ${JSON.stringify(event)}\n\ndata: [DONE]\n\n`);
        }
      },{transport,stream,'timeout-ms':0});
      t.mock.method(AbortSignal,'timeout',()=>assert.fail('No model deadline expected'));
      t.mock.method(globalThis,'setTimeout',()=>assert.fail('No SDK deadline expected'));
      const socketTimers=[];
      const setTimeout=http.ClientRequest.prototype.setTimeout;
      t.mock.method(http.ClientRequest.prototype,'setTimeout',function(ms,...args){socketTimers.push(ms);return setTimeout.call(this,ms,...args);});
      assert.equal((await testModel(profile)).status,'connected');
      assert.deepEqual(socketTimers,[0]);
    });
  }
});

test('no-timeout requests remain cancellable before headers and during the body',async t=>{
  for(const stream of [false,true])for(const headers of [false,true])await t.test(`${stream?'streamed':'buffered'} ${headers?'body':'headers'}`,async t=>{
    const controller=new AbortController();
    const {profile}=await endpoint(t,(_req,res)=>{
      if(headers){res.writeHead(200,{'content-type':stream?'text/event-stream':'application/json'});res.flushHeaders();}
      setImmediate(()=>controller.abort());
    },{'timeout-ms':0,stream});
    await assert.rejects(new ProviderSession(profile).turn([{role:'user',content:'x'}],{signal:controller.signal}),e=>e.code===130);
  });
});

test('explicit per-call deadlines still bound no-timeout profiles',async t=>{
  const {profile}=await endpoint(t,(_req,res)=>{res.writeHead(200,{'content-type':'application/json'});res.flushHeaders();},{'timeout-ms':0});
  await assert.rejects(new ProviderSession(profile).turn([{role:'user',content:'x'}],{timeoutMs:50}),e=>e.details.reason==='model_timeout');
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

test('rejected tool actions retain matching correction outputs in Chat and Responses',async t=>{
  for(const transport of ['chat','responses'])for(const argumentsText of ['{"focus":4}','{"focus":'])await t.test(`${transport} ${argumentsText}`,async t=>{
    const {profile,calls}=await endpoint(t,(_req,res,_call,n)=>{
      const argumentsValue=n===1?argumentsText:'{"focus":"corrected"}';
      if(transport==='chat'){
        const message=action({},`c${n}`);message.tool_calls[0].function.arguments=argumentsValue;chat(res,message);
      }else{
        res.setHeader('content-type','application/json');
        res.end(JSON.stringify({status:'completed',output:[{type:'function_call',call_id:`c${n}`,name:'security_action',arguments:argumentsValue}]}));
      }
    },{transport});
    const session=new ProviderSession(profile);
    await assert.rejects(session.turn([{role:'user',content:'start'}],{schema}));
    assert.deepEqual(await session.turn([{role:'user',content:'validation feedback'}],{schema}),{focus:'corrected'});
    const output=transport==='chat'?calls[1].body.messages.at(-1):calls[1].body.input.at(-1);
    assert.deepEqual(output,transport==='chat'?{role:'tool',tool_call_id:'c1',content:'validation feedback'}:
      {type:'function_call_output',call_id:'c1',output:'validation feedback'});
  });
});

test('Responses reports a safe incomplete-output reason without response contents',async t=>{
  const {profile}=await endpoint(t,(_req,res)=>{
    res.setHeader('content-type','application/json');
    res.end(JSON.stringify({status:'incomplete',incomplete_details:{reason:'max_output_tokens'},
      output:[{type:'message',content:[{type:'output_text',text:'PRIVATE_BODY'}]}]}));
  },{transport:'responses'});
  await assert.rejects(new ProviderSession(profile).turn([{role:'user',content:'x'}],{schema}),error=>{
    assert.equal(error.details.reason,'incomplete_output');
    assert.equal(error.details.providerReason,'max_output_tokens');
    assert.doesNotMatch(error.message,/PRIVATE_BODY/);
    return true;
  });
});

test('malformed arguments, unknown fields and unsupported tool names cannot execute',async t=>{
  for(const value of ['not-json','{"focus":4}','{"focus":"ok","shell":"bad"}']){
    const {profile}=await endpoint(t,(_req,res)=>{const a=action({});a.tool_calls[0].function.arguments=value;chat(res,a);});
    await assert.rejects(new ProviderSession(profile).turn([{role:'user',content:'x'}],{schema}));
  }
});

test('multiple bounded actions are classified for an automatic smaller-page retry',async t=>{
  const {profile}=await endpoint(t,(_req,res)=>{
    const first=action({focus:'one'},'c1').tool_calls[0];
    const second=action({focus:'two'},'c2').tool_calls[0];
    chat(res,{role:'assistant',content:null,tool_calls:[first,second]});
  });
  await assert.rejects(new ProviderSession(profile).turn([{role:'user',content:'x'}],{schema}),error=>{
    assert.equal(error.details.reason,'multiple_actions');
    assert.match(error.message,/more than one security action/);
    return true;
  });
});

test('schema failures report only declared field names and unknown-field counts, never values or unknown names',async t=>{
  const {profile}=await endpoint(t,(_req,res)=>chat(res,{role:'assistant',content:'{"focus":4,"PRIVATE_FIELD":"PRIVATE_VALUE"}'}));
  const progress=[];
  await assert.rejects(new ProviderSession(profile).turn([{role:'user',content:'x'}],{schema,onProgress:event=>progress.push(event)}),error=>{
    const d=error.details.responseDiagnostics;
    assert.deepEqual(d.actionFields,['focus']);assert.equal(d.unknownFieldCount,1);assert.equal(d.schemaStatus,'invalid');
    assert.doesNotMatch(JSON.stringify(d)+JSON.stringify(progress),/PRIVATE_FIELD|PRIVATE_VALUE/);
    return true;
  });
});

test('rejected actions record safe response shape and parse classifications in both Chat modes',async t=>{
  for(const stream of [false,true])for(const content of ['',null,'PRIVATE_OUTPUT prose','{"focus":','{"focus":4}']){
    await t.test(`${stream?'streamed':'buffered'} ${content===null?'null':content.length}`,async t=>{
      const {profile}=await endpoint(t,(_req,res)=>{
        if(!stream)chat(res,{role:'assistant',content,reasoning_content:'PRIVATE_REASONING'});
        else{
          res.writeHead(200,{'content-type':'text/event-stream'});
          res.end(`data: ${JSON.stringify({choices:[{delta:{content,reasoning_content:'PRIVATE_REASONING'},finish_reason:'stop'}]})}\n\ndata: [DONE]\n\n`);
        }
      },{stream});
      const progress=[];
      await assert.rejects(new ProviderSession(profile).turn([{role:'user',content:'x'}],{schema,onProgress:event=>progress.push(event)}),error=>{
        const d=error.details.responseDiagnostics;
        assert.equal(d.contentType,content===null&&!stream?'null':'string');
        assert.equal(d.contentCharacters,content?.length??0);assert.equal(d.reasoningCharacters,17);
        assert.equal(d.toolCallCount,0);assert.equal(d.finishReason,'stop');
        assert.equal(d.jsonStatus,content==='{"focus":4}'?'parsed':content?'invalid_json':'empty_content');
        if(content==='{"focus":4}')assert.equal(d.schemaStatus,'invalid');
        assert.deepEqual(progress.at(-1).diagnostics,d);
        assert.doesNotMatch(JSON.stringify(d)+progress.at(-1).message,/PRIVATE_OUTPUT|PRIVATE_REASONING|contract-test-value/);
        return true;
      });
    });
  }
});

test('tool argument failures record counts and syntax failure without arguments or tool names',async t=>{
  const {profile}=await endpoint(t,(_req,res)=>chat(res,{role:'assistant',content:null,tool_calls:[{id:'c1',type:'function',function:{name:'security_action',arguments:'PRIVATE_ARGUMENTS'}}]}));
  await assert.rejects(new ProviderSession(profile).turn([{role:'user',content:'x'}],{schema}),error=>{
    const d=error.details.responseDiagnostics;
    assert.equal(d.toolCallCount,1);assert.deepEqual(d.toolArgumentCharacters,[17]);
    assert.equal(d.finishReason,'tool_calls');assert.equal(d.jsonSource,'tool_arguments');assert.equal(d.jsonStatus,'invalid_json');
    assert.doesNotMatch(JSON.stringify(d),/PRIVATE_ARGUMENTS|security_action/);
    return true;
  });
});

test('Responses invalid JSON records protocol status without generated text',async t=>{
  const {profile}=await endpoint(t,(_req,res)=>{res.setHeader('content-type','application/json');res.end(JSON.stringify({status:'completed',output:[{type:'message',content:[{type:'output_text',text:'PRIVATE_OUTPUT'}]}]}));},{transport:'responses'});
  await assert.rejects(new ProviderSession(profile).turn([{role:'user',content:'x'}],{schema}),error=>{
    const d=error.details.responseDiagnostics;
    assert.equal(d.transport,'responses');assert.equal(d.finishReason,'completed');assert.equal(d.jsonStatus,'invalid_json');
    assert.equal(d.contentCharacters,14);assert.doesNotMatch(JSON.stringify(d),/PRIVATE_OUTPUT/);
    return true;
  });
});

test('unknown finish reasons are classified instead of logged verbatim',async t=>{
  const {profile}=await endpoint(t,(_req,res)=>{res.setHeader('content-type','application/json');res.end(JSON.stringify({choices:[{finish_reason:'PRIVATE_FINISH',message:{role:'assistant',content:'PRIVATE_OUTPUT'}}]}));});
  await assert.rejects(new ProviderSession(profile).turn([{role:'user',content:'x'}],{schema}),error=>{
    assert.equal(error.details.responseDiagnostics.finishReason,'unknown');
    assert.equal(error.details.reason,'incomplete_output');
    assert.doesNotMatch(JSON.stringify(error.details),/PRIVATE_FINISH|PRIVATE_OUTPUT/);
    return true;
  });
});

test('auth/billing/rate failures have actionable categories, no body/key leakage and no retries',async t=>{
  for(const [status,reason] of [[401,'authentication'],[403,'authorization'],[402,'billing'],[429,'rate_limit'],[400,'unsupported_request'],[503,'provider_unavailable']]){
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
  const {profile}=await endpoint(t,(_req,res)=>chat(res,{role:'assistant',content:'BYPASS_MODEL_OK'}),{'timeout-ms':0});
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
