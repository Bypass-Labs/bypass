import test from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import dns from 'node:dns/promises';
import { execute, readiness } from '../src/service.mjs';
import { read } from '../src/store.mjs';
import { Fault } from '../src/util.mjs';
import { checkModelConnection } from '../src/model-check.mjs';
import { temp } from './helpers.mjs';

async function fixture(t,handler){
  const server=http.createServer(handler);await new Promise(r=>server.listen(0,'127.0.0.1',r));t.after(()=>{server.closeAllConnections();server.close();});
  const root=temp();await execute('init',[root]);await execute('model add',['api'],{project:root,provider:'custom','base-url':`http://127.0.0.1:${server.address().port}/v1`,model:'fixture','secret-env':'BYPASS_UNIT_API_KEY',stream:false});return root;
}
test('API smoke preserves successful history while a failed retest supersedes readiness',async t=>{
  let fail=false;const root=await fixture(t,(req,res)=>{req.resume();res.writeHead(fail?401:200,{'content-type':'application/json'});res.end(fail?'{"error":{"message":"PRIVATE_SECRET"}}':JSON.stringify({choices:[{finish_reason:'stop',message:{role:'assistant',content:'BYPASS_MODEL_OK'}}]}));});
  const output=[];await checkModelConnection(root,'api',{write:x=>output.push(x)});assert.match(output.join('\n'),/Connection verified/);fail=true;
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
