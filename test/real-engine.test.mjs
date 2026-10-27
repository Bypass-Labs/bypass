import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { runAgent } from '../agents/worker.mjs';
import { containerArgs } from '../src/agent-runtime.mjs';
import { parseModelJSON } from '../src/inference.mjs';
import { sourceReader, groundCandidates, executeRealScan } from '../src/real-engine.mjs';
import { createRun, verifyFinding } from '../src/engine.mjs';
import { execute } from '../src/service.mjs';
import { startPOC, stopPOC } from '../src/poc.mjs';
import { read, change } from '../src/store.mjs';
import { specFor, runChecks, exportChecks } from '../src/checks.mjs';
import { replay } from '../src/portable-check.mjs';
import { execFile } from '../src/util.mjs';
import { temp } from './helpers.mjs';

// Inference is deliberately scripted here; separate live validation uses real Muse + Docker.
function controlledRuntime(){
  const calls=[];
  return {calls,
    prepareAgents:async()=>({image:'test-image'}),
    runContainer:async(role,task,rpc)=>({result:await runAgent(role,task,rpc),container:{role,image:'test-image'}}),
    infer:async(profile,messages)=>{
      calls.push({profile:structuredClone(profile),messages});
      const system=messages[0].content;
      if(system.startsWith('Plan a bounded'))return {focus:'Inspect authentication and ownership.'};
      if(system.startsWith('Review the actual')){
        if(messages.length===2)return {action:'read_files',paths:['policy.mjs']};
        return {action:'finish',candidates:[{title:'Account ownership is not checked',category:'cross-account-access',file:'policy.mjs',line:2,quote:'  return Boolean(account);',resourcePath:'/api/invoices/inv-101',hypothesis:'Any authenticated account can read the invoice.',recommendation:'Compare account to invoice.ownerId.'}]};
      }
      if(messages.length===2)return {action:'probe',bindingIndex:0};
      return {action:'finish',summary:'Use observed controls.'};
    }
  };
}

test('real engine consumes source, proves HTTP failure, exports a fixed test, catches regression without AI',async()=>{
  const root=path.join(temp(),'app');await startPOC({dir:root});
  try{
    const runtime=controlledRuntime(),run=await createRun(root,'scan',{mode:'combined'});
    const result=await executeRealScan(root,run.id,{mode:'combined'},{runtime,report:async()=>{}});
    assert.equal(result.simulation,false);assert.equal(result.confirmed.length,1);assert.equal(result.modelCalls,4);
    assert.deepEqual(result.containers.map(c=>c.role),['white-box','black-box']);
    assert.ok(runtime.calls.every(c=>JSON.stringify(c.profile)===JSON.stringify(runtime.calls[0].profile)));
    assert.equal(result.probes[0].requests,5);
    assert.deepEqual(result.probes[0].controls.map(c=>c.status),[200,200,200,200,401]);
    const findingId=result.confirmed[0];assert.equal(read(root).findings[0].sourceEvidence.line,2);
    fs.writeFileSync(path.join(root,'policy.mjs'),'export function mayReadInvoice(account, invoice) { return account === invoice.ownerId; }\n');
    const retested=await verifyFinding(root,findingId,{retest:true});
    assert.equal(retested.status,'fixed_verified');assert.ok(retested.savedCheck);
    const exported=exportChecks(root,{all:true});
    const standalone=await execFile(process.execPath,['--test',...exported.files],{timeout:15000,env:{NODE_TEST_CONTEXT:undefined}});
    assert.equal(standalone.code,0,standalone.stdout+standalone.stderr);
    fs.writeFileSync(path.join(root,'policy.mjs'),'export function mayReadInvoice(account, invoice) { return Boolean(account); }\n');
    const regression=await runChecks(root,{all:true});assert.equal(regression.exitCode,1);assert.equal(regression.modelCalls,0);
    const broken=await execFile(process.execPath,['--test',...exported.files],{timeout:15000,env:{NODE_TEST_CONTEXT:undefined}});
    assert.equal(broken.code,1);assert.match(broken.stdout,/Another account/);
    // Invalid second-account login cannot masquerade as a passing negative control.
    await change(root,s=>{s.identities.find(i=>i.name==='outsider').fixtureValue='invalid-token';});
    const state=read(root),check=state.checks[0],invalid=await replay(specFor(state,check,'poc'));
    assert.equal(invalid.status,'blocked');assert.match(invalid.reason,/login controls/);
  }finally{await stopPOC(root);}
});

test('source citations cannot invent files or lines, and source reads cannot follow escaping symlinks',()=>{
  const root=temp(),outside=temp();fs.writeFileSync(path.join(root,'app.mjs'),'const actual = true;\n');
  fs.writeFileSync(path.join(outside,'secret.mjs'),'secret');fs.symlinkSync(outside,path.join(root,'linked'));
  const inv={files:['app.mjs','linked/secret.mjs'],fingerprint:'source-hash'},reader=sourceReader(root,inv);
  assert.throws(()=>reader.read(['.env']),/outside eligible/);
  assert.throws(()=>reader.read(['linked/secret.mjs']),/escapes/);
  reader.read(['app.mjs']);
  const candidate={category:'cross-account-access',file:'app.mjs',line:1,quote:'made up',title:'A',hypothesis:'B',recommendation:'C'};
  assert.throws(()=>groundCandidates([candidate],reader,inv),/did not match/);
  candidate.quote='const actual = true;';assert.equal(groundCandidates([candidate],reader,inv).length,1);
});

test('model output is data: reject executable/non-JSON output and unsupported worker capabilities',async()=>{
  assert.throws(()=>parseModelJSON('run shell rm -rf ...'),/JSON object/);
  assert.deepEqual(parseModelJSON('```json\n{"action":"finish"}\n```'),{action:'finish'});
  await assert.rejects(runAgent('white-box',{},async()=>({action:'shell',command:'anything'})),/Unsupported/);
  await assert.rejects(runAgent('black-box',{},async(method)=>method==='model'?{action:'probe',bindingIndex:0}:{}),/eight-turn/);
  const args=containerArgs('named','sha256:abc','white-box');
  for(const flag of ['--network','none','--read-only','--cap-drop','ALL','no-new-privileges','--memory','128m'])assert.ok(args.includes(flag));
  assert.ok(!args.includes('-v')&&!args.includes('--privileged'));
});

test('real source-only planning is available without DNS; HTTP proof needs approved resource and model',async()=>{
  const root=temp();await execute('init',[root],{});await execute('engine use',['docker'],{project:root});
  let plan=(await execute('scan',[],{project:root,mode:'code',plan:true})).plan;
  assert.match(plan.blockers.join(' '),/shared model/);
  await execute('model add',['local'],{project:root,provider:'local','base-url':'http://127.0.0.1:1234',model:'test-model'});
  plan=(await execute('scan',[],{project:root,mode:'code',plan:true})).plan;
  assert.deepEqual(plan.blockers,[]);assert.equal(plan.simulation,false);assert.equal(plan.blackBox.status,'deferred');
  const combined=(await execute('scan',[],{project:root,mode:'combined',plan:true})).plan;
  assert.ok(combined.blockers.length>=1);
});

test('Docker worker protocol completes and cancellation removes the actual container',{skip:process.env.BYPASS_DOCKER_TESTS!=='1'},async()=>{
  const {prepareAgents,runContainer}=await import('../src/agent-runtime.mjs');
  const setup=await prepareAgents();
  const completed=await runContainer('black-box',{resources:[{resourcePath:'/api/item'}]},async method=>method==='model'?{action:'probe',bindingIndex:0}:{status:'passed',controls:[]},setup);
  assert.equal(completed.container.role,'black-box');assert.match(completed.container.image,/^sha256:/);
  let name;const controller=new AbortController();
  const running=runContainer('white-box',{files:[]},async(_method,_params,signal)=>new Promise((resolve,reject)=>{signal.addEventListener('abort',()=>reject(new Error('Cancelled')),{once:true});}),{...setup,signal:controller.signal,onProgress:p=>{name=p.message.match(/bypass-white-box-[a-f0-9]+/)[0];}});
  setTimeout(()=>controller.abort(),600);
  await assert.rejects(running);
  const listed=await execFile('docker',['ps','-a','--filter',`name=${name}`,'--format','{{.Names}}']);assert.equal(listed.stdout,'');
});

test('black-box skips model calls when all approved behaviors already pass',async()=>{
  let calls=0;const result=await runAgent('black-box',{resources:[]},async()=>{calls++;throw new Error('Unexpected model call');});
  assert.equal(calls,0);assert.match(result.summary,/Exact passing checks/);
});

test('compatible local inference sends the configured model and rejects invalid output without fallback',async()=>{
  const http=await import('node:http'),{infer}=await import('../src/inference.mjs');let payload,invalid=false;
  const server=http.createServer(async(req,res)=>{let body='';for await(const chunk of req)body+=chunk;payload=JSON.parse(body);res.setHeader('Content-Type','application/json');res.end(JSON.stringify({choices:[{message:{content:invalid?'invented prose':'{"action":"finish","candidates":[]}'}}]}));});
  await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve));
  try{
    const profile={provider:'local',baseUrl:`http://127.0.0.1:${server.address().port}/v1`,model:'my-local-model'};
    const messages=[{role:'user',content:'Inspect the provided source.'}];
    assert.equal((await infer(profile,messages)).action,'finish');assert.equal(payload.model,'my-local-model');assert.deepEqual(payload.messages,messages);
    invalid=true;await assert.rejects(infer(profile,messages),/JSON object/);
  }finally{await new Promise(resolve=>server.close(resolve));}
});

test('anonymous exposure is confirmed independently of a correctly denied outsider',async()=>{
  const http=await import('node:http');
  const server=http.createServer((req,res)=>{
    const token=req.headers.authorization;res.setHeader('Content-Type','application/json');
    if(req.url==='/api/me'){res.end(JSON.stringify({id:token==='Bearer owner'?'alice':'bob'}));return;}
    if(token==='Bearer outsider'){res.writeHead(403);res.end('{}');return;}
    res.end(JSON.stringify({id:'resource-1'}));
  });
  await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve));
  try{
    const origin=`http://127.0.0.1:${server.address().port}`,expires=new Date(Date.now()+60000).toISOString();
    const spec={origin,environment:'local',authorization:{origin,paths:['/api'],methods:['GET'],maxRequestsPerSecond:100,expiresAt:expires},ownershipExpiresAt:expires,resourcePath:'/api/item',resourceId:'resource-1',requireIdentityControl:true,owner:{type:'bearer',secretEnv:'OWNER',checkPath:'/api/me'},outsider:{type:'bearer',secretEnv:'OUTSIDER',checkPath:'/api/me'}};
    const result=await replay(spec,{env:{OWNER:'owner',OUTSIDER:'outsider'}});
    assert.equal(result.status,'failed');assert.match(result.reason,/Unauthenticated/);assert.deepEqual(result.controls.map(c=>c.status),[200,200,200,403,200]);
  }finally{await new Promise(resolve=>server.close(resolve));}
});
