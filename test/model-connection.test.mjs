import test from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import dns from 'node:dns/promises';
import fs from 'node:fs';
import path from 'node:path';
import { execute, readiness } from '../src/service.mjs';
import { read } from '../src/store.mjs';
import { Fault } from '../src/util.mjs';
import { checkModelConnection } from '../src/model-check.mjs';
import { temp } from './helpers.mjs';

async function fixture(t,handler,options={}){
  const server=http.createServer(handler);await new Promise(r=>server.listen(0,'127.0.0.1',r));t.after(()=>{server.closeAllConnections();server.close();});
  const root=temp();await execute('init',[root]);await execute('model add',['api'],{project:root,provider:'custom','base-url':`http://127.0.0.1:${server.address().port}/v1`,model:'fixture','secret-env':'BYPASS_UNIT_API_KEY',stream:false,...options});return root;
}
test('no-timeout model checks display unlimited waiting instead of a synthetic deadline',async t=>{
  const root=await fixture(t,(req,res)=>{req.resume();res.writeHead(200,{'content-type':'application/json'});res.end(JSON.stringify({choices:[{finish_reason:'stop',message:{role:'assistant',content:'BYPASS_MODEL_OK'}}]}));},{'timeout-ms':0});
  const output=[];await checkModelConnection(root,'api',{write:x=>output.push(x)});
  assert.match(output.join('\n'),/no timeout; cancel to stop/);
  assert.doesNotMatch(output.join('\n'),/up to 45 seconds/);
});
test('terminal connection checks preserve Meta preflight in a fresh folder without reading missing state',async t=>{
  const root=temp(),output=[],keys=['MODEL_API_KEY','META_API_KEY','LLM_KEY'];
  const previous=Object.fromEntries(keys.map(key=>[key,process.env[key]]));
  for(const key of keys)process.env[key]='';
  t.after(()=>{for(const key of keys){if(previous[key]===undefined)delete process.env[key];else process.env[key]=previous[key];}});
  await assert.rejects(checkModelConnection(root,undefined,{write:x=>output.push(x)}),error=>{
    assert.equal(error.code,3);assert.equal(error.details.reason,'credential_missing');
    assert.match(error.message,/MODEL_API_KEY/);return true;
  });
  assert.match(output.join('\n'),/up to 45 seconds/);
  assert.equal(fs.existsSync(path.join(root,'.bypass/state.json')),false);
});
test('terminal connection checks resolve the active no-timeout profile from an ancestor project',async t=>{
  const root=await fixture(t,(req,res)=>{req.resume();res.writeHead(200,{'content-type':'application/json'});res.end(JSON.stringify({choices:[{finish_reason:'stop',message:{role:'assistant',content:'BYPASS_MODEL_OK'}}]}));},{'timeout-ms':0});
  const child=path.join(root,'nested');fs.mkdirSync(child);
  const output=[];await checkModelConnection(child,undefined,{write:x=>output.push(x)});
  assert.match(output.join('\n'),/no timeout; cancel to stop/);
  assert.match(output.join('\n'),/Connection verified/);
});
test('API smoke preserves successful history while a failed retest supersedes readiness',async t=>{
  let fail=false;const root=await fixture(t,(req,res)=>{req.resume();res.writeHead(fail?401:200,{'content-type':'application/json'});res.end(fail?'{"error":{"message":"PRIVATE_SECRET"}}':JSON.stringify({choices:[{finish_reason:'stop',message:{role:'assistant',content:'BYPASS_MODEL_OK'}}]}));});
  const output=[];await checkModelConnection(root,'api',{write:x=>output.push(x)});assert.match(output.join('\n'),/Connection verified/);fail=true;
  assert.doesNotMatch(output.join('\n'),/undefined|NaN/);
  await assert.rejects(execute('model test',['api'],{project:root}),e=>e.details.reason==='authentication'&&!e.message.includes('PRIVATE_SECRET'));
  assert.equal(read(root).models[0].lastTest.status,'connected');assert.equal(readiness(root).model.connection,'failed');
});
test('model deadline includes DNS resolution and preserves the profile',async t=>{
  const root=temp();await execute('init',[root]);await execute('model add',['api'],{project:root,provider:'custom','base-url':'https://model.example.test/v1',model:'fixture','secret-env':'BYPASS_UNIT_API_KEY'});
  t.mock.method(dns,'lookup',()=>new Promise(()=>{}));
  await assert.rejects(execute('model test',['api'],{project:root},{timeoutMs:50}),e=>e.details.reason==='model_timeout');
  assert.equal(read(root).activeModel,'api');
});
test('cancelling an API smoke closes the request and records skipped, not connected',async t=>{
  const controller=new AbortController();const root=await fixture(t,(req,res)=>{req.resume();controller.abort(new Fault('Connection check skipped.',130,{skipped:true}));});
  const result=await checkModelConnection(root,'api',{write:()=>{},run:work=>work(controller.signal)});
  assert.equal(result.skipped,true);assert.equal(read(root).models[0].lastAttempt.status,'skipped');assert.equal(read(root).models[0].lastTest,undefined);
});
test('HTTP 402 is retained as a non-retryable billing attempt without raw provider details',async t=>{
  const root=await fixture(t,(req,res)=>{req.resume();res.writeHead(402,{'content-type':'application/json'});res.end('{"error":{"code":"billing_not_configured","message":"PRIVATE_TEAM_ID"}}');});
  await assert.rejects(execute('model test',['api'],{project:root}),error=>error.details.reason==='billing'&&error.details.retryable===false&&!error.message.includes('PRIVATE_TEAM_ID'));
  const attempt=read(root).models[0].lastAttempt;assert.equal(attempt.status,'failed');assert.equal(attempt.reason,'billing');assert.doesNotMatch(attempt.message,/PRIVATE_TEAM_ID/);
});
