import test from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import fs from 'node:fs';
import path from 'node:path';
import { temp } from './helpers.mjs';
import { startPOC, stopPOC } from '../src/poc.mjs';
import { execute } from '../src/service.mjs';
import { read } from '../src/store.mjs';

test('standalone uses official SDK tool calls through both real Docker workers and shared HTTP proof',{skip:process.env.BYPASS_DOCKER_TESTS!=='1'},async t=>{
  const calls=[];const server=http.createServer(async(req,res)=>{
    let raw='';for await(const chunk of req)raw+=chunk;const body=JSON.parse(raw);calls.push(body);
    const system=body.messages[0].content;let message;
    if(!body.tools)message={role:'assistant',content:'BYPASS_MODEL_OK'};
    else{
      let action;
      if(system.startsWith('Plan a bounded'))action={focus:'Inspect invoice authorization.'};
      else if(system.startsWith('Review the actual'))action=body.messages.some(m=>m.role==='tool')?{action:'finish',summary:'Missing owner check',paths:[],knowledge:[],candidates:[{title:'Missing invoice ownership',category:'cross-account-access',file:'policy.mjs',line:2,quote:'  return Boolean(account);',resourcePath:'/api/invoices/inv-101',hypothesis:'Any signed-in account may read the invoice.',recommendation:'Require account === invoice.ownerId.'}]}:{action:'read_files',paths:['policy.mjs'],candidates:[],knowledge:[],summary:''};
      else action={action:'probe',bindingIndex:0,summary:''};
      message={role:'assistant',content:null,tool_calls:[{id:'call-'+calls.length,type:'function',function:{name:'security_action',arguments:JSON.stringify(action)}}]};
    }
    res.writeHead(200,{'content-type':'application/json'});res.end(JSON.stringify({choices:[{finish_reason:message.tool_calls?'tool_calls':'stop',message}]}));
  });
  await new Promise(r=>server.listen(0,'127.0.0.1',r));t.after(()=>{server.closeAllConnections();server.close();});
  const root=path.join(temp(),'fixture');await startPOC({dir:root});t.after(()=>stopPOC(root));
  await execute('model add',['api'],{project:root,provider:'custom','base-url':`http://127.0.0.1:${server.address().port}/v1`,model:'contract-model','secret-env':'BYPASS_UNIT_API_KEY',stream:false});
  const result=await execute('scan',[],{project:root,mode:'combined'});
  assert.equal(result.run.status,'completed',JSON.stringify(result.run.result));assert.equal(result.run.result.confirmed.length,1);assert.equal(result.run.result.containers.length,2);
  assert.ok(calls.some(c=>c.messages.some(m=>m.role==='tool')),'API tool result round trip occurred');assert.ok(calls.every(c=>c.model==='contract-model'));assert.equal(calls.length,5);
  assert.equal(result.run.modelCalls,5);assert.equal(read(root).findings[0].sourceEvidence.kind,'source');
  fs.writeFileSync(path.join(root,'policy.mjs'),'export function mayReadInvoice(account,invoice){return account===invoice.ownerId;}\n');
  const fixed=await execute('retest',[result.run.result.confirmed[0]],{project:root});assert.equal(fixed.status,'fixed_verified');assert.ok(fixed.savedCheck);
  const savedCalls=calls.length;delete process.env.BYPASS_UNIT_API_KEY;
  try{const replay=await execute('test run',[],{project:root,all:true});assert.equal(replay.exitCode,0);assert.equal(calls.length,savedCalls);}finally{process.env.BYPASS_UNIT_API_KEY='unit-fixture-key';}
});
