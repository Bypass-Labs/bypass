import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import http from 'node:http';
import { temp } from './helpers.mjs';
import { execute } from '../src/service.mjs';
import { read, change } from '../src/store.mjs';
import { redact, registerSecret, execFile } from '../src/util.mjs';
import { mcpClient } from './mcp-client.mjs';
import { stopPOC } from '../src/poc.mjs';
import { replay } from '../src/portable-check.mjs';
import { specFor } from '../src/checks.mjs';
import { pluginIdentity } from '../src/runtime-identity.mjs';
import { configureRegistration, testRegistration } from '../src/registration.mjs';
import { inExecutionMode } from '../src/execution-mode.mjs';

async function app(t,handler){
  const root=temp(),server=http.createServer(handler);await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve));t.after(()=>server.close());
  await execute('init',[root]);const o={project:root};await execute('target add',['app'],{...o,url:`http://127.0.0.1:${server.address().port}`,environment:'local'});await execute('target verify',['app'],{...o,method:'local'});await execute('target authorize',['app'],{...o,accept:true,paths:'/api,/reports'});return {root,o,server};
}
async function client(t,root,packaged=false){const c=await mcpClient(root,{packaged,stateDir:temp(),env:{BYPASS_CREDENTIAL_DIR:temp()}});t.after(()=>c.close());return c;}
const send=(r,status,data)=>{r.writeHead(status,{'Content-Type':'application/json'});r.end(JSON.stringify(data));};

test('structural redaction preserves nested source, escapes, primitives and masks actual secrets',()=>{
  const secret='uat-redaction-token-unique-001';registerSecret(secret);
  const source={quote:'if (header.startsWith("Bearer ")) { return true; }',nested:['\\\n\t"',null,12,false,{token:secret,header:'Bearer abc.def-ghi'}]};
  const result=redact(source);assert.equal(result.quote,source.quote);assert.deepEqual(result.nested.slice(0,4),source.nested.slice(0,4));assert.equal(result.nested[4].token,'[REDACTED]');assert.equal(result.nested[4].header,'Bearer [REDACTED]');assert.equal(redact(undefined),undefined);
  assert.equal(source.nested[4].token,secret,'does not mutate evidence');assert.deepEqual(redact(JSON.parse('{"__proto__":"safe"}')),JSON.parse('{"__proto__":"safe"}'));
});

test('packaged MCP retrieves quoted source memory and completes a second review without JSON failure',async t=>{
  const root=temp(),quote='export const check = header => header.startsWith("Bearer ");';fs.writeFileSync(path.join(root,'auth.mjs'),quote+'\n');await execute('init',[root]);const c=await client(t,root,true);
  for(let i=0;i<2;i++){
    const run=await c.call('bypass_scan',{mode:'code'});assert.equal(run.initialSource[0].file,'auth.mjs');
    const done=await c.call('bypass_review_step',{id:run.runId,action:'complete',candidates:[],knowledge:[{topic:'authentication',title:'Bearer parsing',summary:'Parses bearer prefix; token validation must be checked separately.',file:'auth.mjs',line:1,quote}]});assert.equal(done.status,'completed');
    const memory=await c.call('bypass_memory');assert.ok(memory.entries.length);assert.match(JSON.stringify(memory),/Bearer/);
    const context=await c.call('bypass_feature_context',{task:'Preserve authentication when adding routes'});assert.ok(context.memory.entries.length);
  }
  assert.equal(read(root).runs.length,2);
});

test('credential-free HTML proof saves failing reproduction, exported test fails then passes; public content is not a finding',async t=>{
  let fixed=false;const {root}=await app(t,(q,r)=>{if(fixed){r.writeHead(403);return r.end();}r.writeHead(200,{'Content-Type':'text/html'});r.end('<title>Private UAT report 78231</title>');});
  const c=await client(t,root),setup=await c.call('bypass_onboarding');assert.equal(setup.stage,'ready');assert.equal(setup.steps.find(s=>s.id==='accounts').status,'optional');
  await c.call('bypass_add_probe',{name:'report',path:'/reports/78231',kind:'anonymous',response:'html','match-text':'Private UAT report 78231',expected:'private'});
  const run=await c.call('bypass_scan',{mode:'combined'}),done=await c.call('bypass_review_step',{id:run.runId,action:'complete',candidates:[]});assert.equal(done.probes[0].status,'failed');assert.equal(done.probes[0].requests,1);
  const [check]=read(root).checks;assert.equal(check.baseline,'failing_reproduction');assert.equal(read(root).findings[0].status,'confirmed');
  const exported=await c.call('bypass_export_tests',{id:read(root).findings[0].id});const runExport=()=>execFile(process.execPath,['--test',...exported.files],{env:{NODE_TEST_CONTEXT:undefined}});
  assert.equal((await runExport()).code,1);fixed=true;assert.equal((await runExport()).code,0);
  const replayRun=await c.call('bypass_run_tests',{id:read(root).findings[0].id});assert.equal(replayRun.status,'completed');assert.equal(replayRun.run.exitCode,0);assert.equal(read(root).findings[0].status,'fixed_verified');
  fixed=false;const publicSpec={...specFor(read(root),read(root).checks[0]),expected:'public'};assert.equal((await replay(publicSpec)).status,'observed');
  const absentMarker={...publicSpec,matchText:'Not a marker in the page'};assert.equal((await replay(absentMarker)).status,'blocked');
  await c.call('bypass_revoke_target',{name:'app'});const denied=await c.raw('bypass_scan',{mode:'live'});assert.equal(denied.result.isError,true);
});

test('registration creates and privately connects two accounts; discovery selects only owned IDs; retry creates no duplicates',async t=>{
  const tokens=new Map();let posts=0,privateFixed=false;
  const {root}=await app(t,(q,r)=>{
    const account=tokens.get(q.headers.authorization?.replace('Bearer ',''));
    if(q.method==='POST'&&q.url==='/api/signup'){let body='';q.on('data',x=>body+=x);q.on('end',()=>{const value=JSON.parse(body);assert.match(value.email,/@uat\.invalid$/);assert.ok(value.password.length>24);posts++;const token='unique-generated-token-'+posts;tokens.set(token,'user-'+posts);send(r,201,{token});});return;}
    if(q.url==='/api/me')return send(r,account?200:401,account?{id:account,emailVerified:false}:{error:'signin'});
    if(q.url==='/api/verified')return send(r,privateFixed?403:200,{id:account});
    if(q.url==='/api/items')return send(r,200,{items:[{id:'mine',ownerId:account},{id:'foreign',ownerId:'customer-someone-else'}]});
    if(q.url==='/api/items/mine')return send(r,!account?401:privateFixed&&account!=='user-1'?403:200,{id:'mine'});
    send(r,404,{});
  });
  const c=await client(t,root);await c.call('bypass_configure_registration',{path:'/api/signup','check-path':'/api/me','access-path':'/api/verified','email-domain':'uat.invalid','token-field':'token','verified-field':'emailVerified',accept:true,'require-verification':true});
  const run=await c.call('bypass_scan',{mode:'combined'});assert.equal(posts,2);assert.equal(run.registration.status,'failed');assert.equal(run.registration.accounts.every(a=>a.connected),true);assert.equal(run.registration.findings.length,1);assert.equal(run.registration.probes[0].status,'failed');
  const ids=read(root).identities;assert.equal(ids.length,2);assert.ok(ids.every(i=>i.credentialRef));assert.doesNotMatch(fs.readFileSync(path.join(root,'.bypass/state.json'),'utf8'),/unique-generated-token/);
  const discovered=await c.call('bypass_discover_resources',{path:'/api/items','resource-prefix':'/api/items','items-field':'items','owner-field':'ownerId',owner:ids[0].name,outsider:ids[1].name});assert.deepEqual(discovered.probes.map(p=>p.resourceId),['mine']);assert.doesNotMatch(JSON.stringify(discovered),/customer-someone-else|foreign/);
  await c.call('bypass_review_step',{id:run.runId,action:'refresh'});const done=await c.call('bypass_review_step',{id:run.runId,action:'complete',candidates:[]});assert.equal(done.probes[0].status,'failed');assert.equal(done.probes[0].requests,5);assert.equal(posts,2);
  const again=await c.call('bypass_test_registration');assert.equal(again.registration.reused,true);assert.equal(again.registration.requests,0);assert.equal(posts,2);
  privateFixed=true;const tests=await c.call('bypass_run_tests',{all:true});assert.equal((await c.wait(tests.runId)).exitCode,0);
});

test('signup success without verified-email policy is an observation and rejection is never a pass',async t=>{
  let reject=false;const {root,o}=await app(t,(q,r)=>q.method==='POST'?send(r,reject?429:201,{token:'new-account-token'}):send(r,200,{id:'new-user',verified:false}));
  const dir=temp(),old=process.env.BYPASS_CREDENTIAL_DIR;process.env.BYPASS_CREDENTIAL_DIR=dir;t.after(()=>{if(old===undefined)delete process.env.BYPASS_CREDENTIAL_DIR;else process.env.BYPASS_CREDENTIAL_DIR=old;});
  await execute('registration configure',[],{...o,path:'/api/signup','check-path':'/api/me','email-domain':'uat.invalid','token-field':'token','verified-field':'verified',accept:true});
  const first=await execute('registration test',[],o);assert.equal(first.registration.status,'observed');assert.ok(first.registration.observations.every(x=>!x.policyViolation));
  const {root:other,o:oo}=await app(t,(_q,r)=>send(r,429,{}));await execute('registration configure',[],{...oo,path:'/api/signup','check-path':'/api/me','email-domain':'uat.invalid','token-field':'token','verified-field':'verified',accept:true});
  const rejected=await execute('registration test',[],oo);assert.equal(rejected.registration.status,'blocked');assert.equal(rejected.registration.requests,1);assert.equal(read(other).identities.length,0);
});

test('dead fixture resumes in a fresh MCP process, retains finding/check IDs and validates matching closure',async t=>{
  let c=await client(t,temp()),demo=await c.call('bypass_demo_start',{kind:'real'});const root=demo.root;t.after(()=>stopPOC(root));
  const run=await c.call('bypass_scan',{mode:'combined'});assert.equal(run.initialSource.length,2);
  const done=await c.call('bypass_review_step',{id:run.runId,action:'complete',candidates:[{title:'Missing owner check',category:'cross-account-access',file:'policy.mjs',line:2,quote:'  return Boolean(account);',resourcePath:'/api/invoices/inv-101',hypothesis:'All users accepted.',recommendation:'Check owner.'}]});
  const finding=done.findings[0],check=read(root).checks[0].id,instance=read(root).poc.instanceId;
  await c.close();process.kill(read(root).poc.pid,'SIGTERM');await new Promise(r=>setTimeout(r,300));c=await client(t,root);
  await c.call('bypass_demo_control',{action:'fix'});assert.equal(read(root).poc.instanceId,instance);
  const testRun=await c.call('bypass_run_tests',{all:true});assert.equal((await c.wait(testRun.runId)).exitCode,0);assert.equal(read(root).findings.find(f=>f.id===finding).status,'fixed_verified');assert.equal(read(root).checks[0].id,check);
  await c.call('bypass_demo_control',{action:'regress'});const failing=await c.call('bypass_run_tests',{all:true});assert.equal((await c.wait(failing.runId)).exitCode,1);
  await c.call('bypass_demo_control',{action:'fix'});const passing=await c.call('bypass_run_tests',{all:true});assert.equal((await c.wait(passing.runId)).exitCode,0);assert.equal(read(root).findings[0].status,'fixed_verified');
});

test('cancelled host review exposes wait state and resumes without re-onboarding',async t=>{
  const root=temp();fs.writeFileSync(path.join(root,'app.mjs'),'export const a = true;');await execute('init',[root]);const c=await client(t,root);
  const run=await c.call('bypass_scan',{mode:'code'});assert.match(run.progress.waitingFor,/Muse/);assert.ok(run.progress.lastCompleted);
  await c.call('bypass_stop_run',{id:run.runId});const resumed=await c.call('bypass_review_step',{id:run.runId,action:'resume'});assert.equal(resumed.status,'awaiting_host');
  const malformed=await c.raw('bypass_review_step',{id:run.runId,action:'read',paths:'app.mjs'});assert.equal(malformed.error.code,-32602);assert.match(malformed.error.message,/paths:/);
  await c.call('bypass_review_step',{id:run.runId,action:'complete',candidates:[]});assert.equal(read(root).runs.length,1);
});

test('slow native plugin inspection yields known version; timeout is distinguished',async()=>{
  const result=await pluginIdentity({inspect:async()=>{await new Promise(r=>setTimeout(r,2100));return {code:0,stdout:JSON.stringify({record:{version:'0.7.0'}})};}});assert.equal(result.installedVersion,'0.7.0');assert.equal(result.installationCheck,'verified');
  const timeout=await pluginIdentity({inspect:async()=>{const e=new Error('timeout');e.details={reason:'timeout'};throw e;}});assert.equal(timeout.installationCheck,'timed_out');assert.ok(timeout.version);
});

test('Firebase signup contract binds project, stores refresh privately, and verifies the app identity',async t=>{
  const {root}=await app(t,(_q,r)=>send(r,200,{}));const store=temp(),old=process.env.BYPASS_CREDENTIAL_DIR;process.env.BYPASS_CREDENTIAL_DIR=store;t.after(()=>{if(old===undefined)delete process.env.BYPASS_CREDENTIAL_DIR;else process.env.BYPASS_CREDENTIAL_DIR=old;});
  fs.writeFileSync(path.join(root,'firebase.env'),'VITE_FIREBASE_API_KEY=public-uat-firebase-key\n');
  await configureRegistration(root,{provider:'firebase','config-file':'firebase.env','project-id':'uat-project','check-path':'/api/me','email-domain':'uat.invalid',accept:true,'require-verification':true});let signs=0;
  const result=await testRegistration(root,{request:async(url,o)=>{
    if(url.startsWith('https://identitytoolkit.googleapis.com/')){assert.equal(o.method,'POST');assert.equal(JSON.parse(o.body).returnSecureToken,true);const uid='firebase-uat-'+ ++signs;const token='header.'+Buffer.from(JSON.stringify({aud:'uat-project',iss:'https://securetoken.google.com/uat-project',sub:uid,exp:Math.floor(Date.now()/1000)+3600,email_verified:false})).toString('base64url')+'.signature';return {status:200,body:JSON.stringify({idToken:token,refreshToken:'private-refresh-'+signs})};}
    assert.ok(o.headers.Authorization);return {status:200,body:JSON.stringify({id:'firebase-uat-'+signs})};
  }});
  assert.equal(result.status,'observed');assert.equal(result.observations[0].policyViolation,true);assert.equal(result.probes[0].status,'blocked');assert.equal(signs,2);assert.equal(read(root).identities.length,2);assert.doesNotMatch(fs.readFileSync(path.join(root,'.bypass/state.json'),'utf8'),/private-refresh-|header\./);
});

test('registration permission gates make no requests; interrupted creation is never retried',async t=>{
  let posts=0;const {root,o}=await app(t,(_q,r)=>{posts++;send(r,201,{token:'unused-token'});});
  const settings={...o,path:'/api/signup','check-path':'/api/me','email-domain':'uat.invalid','token-field':'token','verified-field':'verified'};
  await assert.rejects(execute('registration configure',[],settings),/permission/);assert.equal(posts,0);
  await execute('registration configure',[],{...settings,accept:true});
  await change(root,s=>{s.targets[0].registration.attempts=[{name:'reserved-test',email:'bypass-reserved@uat.invalid',status:'reserved'}];});
  const resumed=await execute('registration test',[],o);assert.equal(resumed.registration.reused,true);assert.equal(resumed.registration.currentProof,false);assert.equal(posts,0);
  await execute('target revoke',['app'],o);const revoked=await execute('registration test',[],o);assert.equal(revoked.registration.status,'blocked');assert.equal(posts,0);
});

test('a blocked probe does not suppress an independent anonymous finding',async t=>{
  const {root,o}=await app(t,(_q,r)=>send(r,200,{id:'private-item'}));
  for(const name of ['owner','outsider'])await execute('identity add',[name],{...o,type:'bearer','secret-env':'BYPASS_MISSING_'+name.toUpperCase(),'check-path':'/api/me'});
  await execute('probe add',['needs_accounts'],{...o,path:'/api/private','resource-id':'private-item',owner:'owner',outsider:'outsider'});
  await execute('probe add',['anonymous'],{...o,path:'/api/private','resource-id':'private-item',kind:'anonymous',expected:'private'});
  const c=await client(t,root),run=await c.call('bypass_scan',{mode:'live'}),done=await c.call('bypass_review_step',{id:run.runId,action:'complete'});
  assert.deepEqual(done.probes.map(p=>p.status),['blocked','failed']);assert.equal(done.probes[0].requests,0);assert.equal(done.findings.length,1);
});

test('unrelated passing binding cannot close the original finding',async t=>{
  const {root,o}=await app(t,(q,r)=>send(r,q.url==='/api/other'?403:200,{id:'private-item'}));
  await execute('probe add',['private'],{...o,path:'/api/private','resource-id':'private-item',kind:'anonymous',expected:'private'});
  const c=await client(t,root),run=await c.call('bypass_scan',{mode:'live'});await c.call('bypass_review_step',{id:run.runId,action:'complete'});
  const check=read(root).checks[0];await change(root,s=>{s.checks[0].bindings.app.resourcePath='/api/other';});
  const replayed=await c.call('bypass_run_tests',{id:check.id});assert.equal(replayed.run.result.results[0].status,'passed');assert.equal(read(root).findings[0].status,'confirmed');
});

test('revoking scope during a signup response prevents the next account request',async t=>{
  const {root,o}=await app(t,(_q,r)=>send(r,404,{}));
  await execute('registration configure',[],{...o,path:'/api/signup','check-path':'/api/me','email-domain':'uat.invalid','token-field':'token','verified-field':'verified',accept:true});let calls=0;
  const result=await testRegistration(root,{request:async()=>{calls++;await execute('target revoke',['app'],o);return {status:201,body:'{}'};}});
  assert.equal(calls,1);assert.equal(result.status,'blocked');assert.equal(result.cleanup.length,1);
});
