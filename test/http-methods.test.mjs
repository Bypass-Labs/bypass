import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import http from 'node:http';
import { spawn } from 'node:child_process';
import { CLI } from '../src/demo.mjs';
import { httpMethods, promptMethods } from '../src/http-methods.mjs';
import { authorization, scopeReady } from '../src/network.mjs';
import { scopedRequest } from '../src/scoped-request.mjs';
import { execute } from '../src/service.mjs';
import { read, change } from '../src/store.mjs';
import { temp, cli } from './helpers.mjs';
import { mcpClient } from './mcp-client.mjs';

async function setup(t,handler=(_q,r)=>r.end('{}')){
  const root=temp(),server=http.createServer(handler);
  await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve));t.after(()=>server.close());
  await execute('init',[root]);const o={project:root};
  await execute('target add',['app'],{...o,url:`http://127.0.0.1:${server.address().port}`,environment:'local'});
  await execute('target verify',['app'],{...o,method:'local'});
  const grant=methods=>execute('target authorize',['app'],{...o,accept:true},{scope:{paths:['/api'],methods,maxRequestsPerSecond:10}});
  await grant('GET,HEAD');return {root,o,grant};
}
const send=(r,status,data)=>{r.writeHead(status,{'Content-Type':'application/json'});r.end(JSON.stringify(data));};

test('method selection normalizes exact choices, permits custom methods, and preserves explicit production gates',async()=>{
  assert.deepEqual(httpMethods(),['GET','HEAD']);
  assert.deepEqual(httpMethods('get, POST post PROPFIND'),['GET','POST','PROPFIND']);
  assert.deepEqual(httpMethods('["GET", "HEAD", "POST", "PATCH", "PROPFIND"]'),['GET','HEAD','POST','PATCH','PROPFIND']);
  for(const value of [[],null,'*','POST\r\nHost:evil','CONNECT','PRI','GET /api','[]','["POST",null]','["POST",{}]','["POST",["GET"]]','["POST", "*"]','["POST"','["POST\\r\\nHost:evil"]'])assert.throws(()=>httpMethods(value));
  const answers=['*','1,3,PROPFIND'];let errors=0;
  assert.deepEqual(await promptMethods(async()=>answers.shift(),()=>errors++),['GET','POST','PROPFIND']);assert.ok(errors>0);
  const app={url:'https://app.example.com',environment:'production',ownership:{status:'verified',expiresAt:new Date(Date.now()+86400000).toISOString()}};
  assert.throws(()=>authorization(app,{paths:['/api'],methods:['POST']}),/Production/);
  app.authorization=authorization(app,{paths:['/api'],methods:['POST'],productionAcknowledged:true});
  assert.equal(scopeReady(app),true);assert.equal(scopeReady(app,'/api/jobs','POST'),true);
  assert.throws(()=>scopeReady(app,'/api/jobs'),/Method GET/);assert.throws(()=>scopeReady(app,'/other','POST'),/Path/);
});

test('every selectable method and a custom method reaches HTTP exactly once; CLI resolves a body file in the app',async t=>{
  const seen=[];const {root,o,grant}=await setup(t,(q,r)=>{let text='';q.on('data',b=>text+=b);q.on('end',()=>{seen.push({method:q.method,body:text});send(r,200,{id:'observed-id'});});});
  const methods=['GET','HEAD','POST','PUT','PATCH','DELETE','OPTIONS','PROPFIND'];await grant(methods);
  for(const method of methods){const result=await execute('request',[],{...o,method,path:'/api/jobs','id-field':'id'});assert.equal(result.httpStatus,200);assert.equal(result.requests,1);assert.equal(result.securityConclusion,false);}
  assert.deepEqual(seen.map(x=>x.method),methods);
  fs.writeFileSync(path.join(root,'payload.json'),JSON.stringify({label:'synthetic-job'}));
  const result=await cli(root,'request','--method','POST','--path','/api/jobs','--body-file','payload.json','--id-field','id');
  assert.equal(result.code,0,JSON.stringify(result));assert.equal(result.data.resourceId,'observed-id');assert.equal(seen.at(-1).body,'{"label":"synthetic-job"}');
  assert.equal(read(root).findings.length,0);assert.equal(read(root).checks.length,0);
});

test('packaged Muse flow selects POST, creates a resource, proves access and replays the fix without duplicate creation',async t=>{
  let posts=0,fixed=false;const tokenOwner='method-uat-owner-private',tokenOther='method-uat-other-private';
  const {root}=await setup(t,(q,r)=>{
    const user=q.headers.authorization===`Bearer ${tokenOwner}`?'owner':q.headers.authorization===`Bearer ${tokenOther}`?'outsider':null;
    if(q.url==='/api/me')return send(r,user?200:401,user?{id:user}:{});
    if(q.method==='POST'&&q.url==='/api/jobs'){
      let body='';q.on('data',b=>body+=b);q.on('end',()=>{assert.equal(user,'owner');assert.deepEqual(JSON.parse(body),{label:'private-body-sentinel'});posts++;send(r,201,{run:{id:'job-'+posts},token:'private-response-sentinel'});});return;
    }
    if(q.url==='/api/jobs/job-1')return send(r,!user?401:fixed&&user!=='owner'?403:200,{id:'job-1'});
    send(r,404,{});
  });
  fs.writeFileSync(path.join(root,'app.mjs'),'export const jobPath = "/api/jobs";\n');
  const c=await mcpClient(root,{packaged:true,stateDir:temp(),env:{BYPASS_METHOD_OWNER_TOKEN:tokenOwner,BYPASS_METHOD_OTHER_TOKEN:tokenOther}});t.after(()=>c.close());
  const approval=await c.call('bypass_onboarding',{reviewScope:true});
  assert.deepEqual(approval.nextAction.input.choices.map(c=>c.id),['approve','decline','custom']);
  const picker={nextAction:{input:approval.nextAction.custom.methods}};
  assert.equal(picker.nextAction.input.kind,'multiselect');assert.equal(picker.nextAction.input.allowCustom,true);
  assert.deepEqual(picker.nextAction.input.selected,['GET','HEAD']);
  assert.deepEqual(picker.nextAction.input.choices.map(x=>x.id),['GET','HEAD','POST','PUT','PATCH','DELETE','OPTIONS']);
  assert.equal(picker.nextAction.input.singleSelectFallback.tool,'request_user_input');
  assert.deepEqual(picker.nextAction.input.singleSelectFallback.choices[1].methods,['GET','HEAD','POST']);
  assert.equal(picker.nextAction.input.singleSelectFallback.choices[2].custom,true);
  assert.deepEqual(read(root).targets[0].authorization.methods,['GET','HEAD'],'opening the picker cannot expand a grant');
  const scopeFile=path.join(root,'approved-scope.json');
  fs.writeFileSync(scopeFile,JSON.stringify({paths:['/'],methods:['GET','HEAD','POST','PUT','PATCH','DELETE','OPTIONS'],maxRequestsPerSecond:2,productionAcknowledged:true}));
  await c.call('bypass_authorize_target',{name:'app','scope-file':scopeFile,accept:true,production:true});
  const saved=(await c.call('bypass_target',{name:'app'})).target.authorization;
  assert.deepEqual(saved.methods,['GET','HEAD','POST','PUT','PATCH','DELETE','OPTIONS']);assert.deepEqual(saved.paths,['/']);assert.equal(saved.maxRequestsPerSecond,2);assert.equal(saved.productionAcknowledged,true);
  await c.call('bypass_authorize_target',{name:'app',paths:'/api',methods:'["GET", "HEAD", "POST", "PATCH", "PROPFIND"]',accept:true});
  assert.deepEqual((await c.call('bypass_target',{name:'app'})).target.authorization.methods,['GET','HEAD','POST','PATCH','PROPFIND']);
  const malformed=await c.raw('bypass_authorize_target',{name:'app',paths:'/api',methods:'["POST", "*"]',accept:true});
  assert.equal(malformed.result.isError,true);
  assert.deepEqual(read(root).targets[0].authorization.methods,['GET','HEAD','POST','PATCH','PROPFIND'],'invalid input cannot alter the saved grant');
  await c.call('bypass_authorize_target',{name:'app',paths:'/api',methods:['GET','HEAD'],accept:true});
  const denied=await c.raw('bypass_request',{method:'POST',path:'/api/jobs'});assert.equal(denied.result.isError,true);assert.equal(posts,0);
  await c.call('bypass_authorize_target',{name:'app',paths:'/api',methods:['GET','HEAD','POST'],accept:true});
  for(const [name,secret] of [['owner','BYPASS_METHOD_OWNER_TOKEN'],['outsider','BYPASS_METHOD_OTHER_TOKEN']])await c.call('bypass_add_identity',{name,target:'app',type:'bearer','secret-env':secret,'check-path':'/api/me'});
  const created=await c.call('bypass_request',{method:'POST',path:'/api/jobs',identity:'owner',body:{label:'private-body-sentinel'},'id-field':'run.id'});
  assert.equal(created.httpStatus,201);assert.equal(created.resourceId,'job-1');assert.equal(created.automaticReplay,false);assert.equal(created.modelCalls,0);assert.equal(posts,1);
  assert.equal(read(root).findings.length,0,'setup is not proof');
  assert.equal((await c.raw('bypass_request',{method:'DELETE',path:'/api/jobs/job-1'})).result.isError,true);
  await c.call('bypass_add_probe',{name:'job',path:'/api/jobs/'+created.resourceId,'resource-id':created.resourceId,owner:'owner',outsider:'outsider'});
  const run=await c.call('bypass_scan',{mode:'combined'});
  const done=await c.call('bypass_review_step',{id:run.runId,action:'complete',candidates:[]});assert.equal(done.probes[0].status,'failed');
  assert.equal(read(root).checks.length,1);assert.equal(read(root).findings[0].status,'confirmed');
  fixed=true;const replay=await c.call('bypass_run_tests',{all:true}),finished=await c.wait(replay.runId);assert.equal(finished.exitCode,0);
  assert.equal(read(root).findings[0].status,'fixed_verified');assert.equal(posts,1,'saved replay must not repeat POST');
  const evidence=fs.readFileSync(path.join(root,'.bypass/runs',created.runId+'.json'),'utf8')+fs.readFileSync(path.join(root,'.bypass/state.json'),'utf8');
  assert.doesNotMatch(evidence,/private-body-sentinel|private-response-sentinel|method-uat-owner-private|method-uat-other-private/);
});

test('requests reject disallowed methods, paths, expired grants and unsafe inputs before HTTP',async t=>{
  const {root,grant}=await setup(t);let sent=0;const request=async()=>{sent++;return {status:200,body:'{}'};};
  await assert.rejects(scopedRequest(root,{method:'POST',path:'/api/jobs'},{request}),/Method POST/);
  await grant(['GET','POST']);
  for(const value of [{method:'DELETE',path:'/api/jobs'},{method:'POST',path:'/elsewhere'},{method:'POST',path:'/api/../outside'},{method:'POST',path:'/api/%2e%2e/outside'},{method:'POST',path:'//other/api'},{method:'GET',path:'/api/jobs',body:{a:1}},{method:'POST',path:'/api/jobs','id-field':'accessToken'}])await assert.rejects(scopedRequest(root,value,{request}));
  await change(root,s=>{s.targets[0].authorization.expiresAt='2000-01-01T00:00:00Z';});
  await assert.rejects(scopedRequest(root,{method:'POST',path:'/api/jobs'},{request}),/expired/);assert.equal(sent,0);assert.equal(read(root).runs.length,0);
});

test('scope changes and cancellation while rate-limited stop a write before dispatch',async t=>{
  for(const mode of ['revoke','cancel']){
    const {root,o,grant}=await setup(t);await grant(['POST']);
    await change(root,s=>{s.targets[0].nextDirectRequestAt=Date.now()+300;});
    let sent=0;const controller=new AbortController();
    const pending=scopedRequest(root,{method:'POST',path:'/api/jobs'},{signal:controller.signal,request:async()=>{sent++;return {status:201,body:'{}'};}});
    for(let i=0;i<100&&!read(root).runs.length;i++)await new Promise(resolve=>setTimeout(resolve,5));
    assert.equal(read(root).runs.length,1);
    if(mode==='revoke')await execute('target revoke',['app'],o);else controller.abort();
    const result=await pending;assert.equal(result.outcome,'not_sent');assert.equal(sent,0);assert.equal(result.requests,0);
    assert.equal(result.exitCode,mode==='cancel'?130:3);
  }
});

test('ambiguous write failures are recorded once with no retry; redirects are not followed',async t=>{
  const {root,grant}=await setup(t,(_q,r)=>{r.writeHead(307,{Location:'/api/another'});r.end();});await grant(['POST']);let requests=0;
  const failed=await scopedRequest(root,{method:'POST',path:'/api/jobs'},{request:async()=>{requests++;throw new Error('Response interrupted.');}});
  assert.equal(failed.outcome,'unknown');assert.equal(failed.exitCode,3);assert.equal(requests,1);assert.equal(read(root).runs[0].result.requests,1);
  const redirect=await scopedRequest(root,{method:'POST',path:'/api/jobs'});assert.equal(redirect.httpStatus,307);assert.equal(redirect.requests,1);assert.equal(read(root).checks.length,0);
});

test('a process crash leaves an unknown write outcome and watch recovers without dispatching it again',async t=>{
  let received,posts=0;const observed=new Promise(resolve=>{received=resolve;});
  const {root,grant}=await setup(t,(q,r)=>{posts++;received();r.on('close',()=>{});});await grant(['POST']);
  const child=spawn(process.execPath,[CLI,'request','--method','POST','--path','/api/jobs','--project',root,'--json'],{cwd:root,stdio:'ignore'});t.after(()=>child.kill());
  const closed=new Promise(resolve=>child.once('close',resolve));
  await Promise.race([observed,new Promise((_,reject)=>{const timer=setTimeout(()=>reject(new Error('No POST received')),10000);timer.unref();})]);
  child.kill('SIGKILL');await closed;
  const run=read(root).runs[0];assert.equal(run.result.outcome,'unknown');assert.match(run.result.next,/will not retry/);
  await execute('run watch',[run.id],{project:root,timeout:'1s'});
  assert.equal(read(root).runs[0].status,'interrupted');assert.equal(posts,1);assert.equal(read(root).runs[0].result.requests,1);
});
