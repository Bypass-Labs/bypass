import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import http from 'node:http';
import { temp } from './helpers.mjs';
import { mcpClient } from './mcp-client.mjs';
import { execute } from '../src/service.mjs';
import { read } from '../src/store.mjs';
import { importCredential, resolveCredential, credentialStatus, credentialFields, credentialEnvironment } from '../src/credentials.mjs';
import { redact } from '../src/util.mjs';

const token=(sub='owner',seconds=3600,aud='test-project')=>'eyJhbGciOiJub25lIn0.'+Buffer.from(JSON.stringify({sub,aud,iss:`https://securetoken.google.com/${aud}`,exp:Math.floor(Date.now()/1000)+seconds})).toString('base64url')+'.synthetic';
function env(t,key,value){const before=process.env[key];process.env[key]=value;t.after(()=>{if(before===undefined)delete process.env[key];else process.env[key]=before;});}
function secretFile(dir,values){const file=path.join(dir,'accounts.env');fs.writeFileSync(file,typeof values==='string'?values:JSON.stringify(values),{mode:0o600});return file;}
async function setup(t){
  const root=temp(),privateDir=temp();env(t,'BYPASS_CREDENTIAL_DIR',privateDir);
  await execute('init',[root]);await execute('target add',['app'],{project:root,url:'http://127.0.0.1:3456',environment:'local'});
  await execute('target verify',['app'],{project:root,method:'local'});await execute('target authorize',['app'],{project:root,accept:true,paths:'/api'});
  const state=read(root),target=state.targets[0],identity={name:'owner',target:'app',type:'bearer',secretEnv:'BYPASS_PRIVATE_OWNER_TOKEN',checkPath:'/api/me'};
  const file=secretFile(temp(),{ID:token('owner',-1),REFRESH:'synthetic-refresh-original',KEY:'synthetic-public-api-key'});
  identity.credentialRef=importCredential(state,target,identity,{file,'token-field':'ID',provider:'firebase','refresh-token-field':'REFRESH','api-key-field':'KEY'});
  return {root,privateDir,state,target,identity,file};
}
const response=(sub='owner',refresh='synthetic-refresh-rotated',aud='test-project')=>({status:200,body:JSON.stringify({id_token:token(sub,3600,aud),refresh_token:refresh,expires_in:'3600',user_id:sub,project_id:'1234567890'})});

test('Firebase refresh is automatic, coalesced across callers, and persists rotated refresh tokens',async t=>{
  const x=await setup(t);assert.equal(credentialStatus(x.state,x.target,x.identity).status,'refresh_on_use');let calls=0;
  const request=async(url,options)=>{calls++;assert.equal(new URL(url).origin,'https://securetoken.googleapis.com');assert.equal(options.headers.Referer,x.target.url+'/');assert.equal(options.method,'POST');assert.equal(new URLSearchParams(options.body).get('grant_type'),'refresh_token');await new Promise(r=>setTimeout(r,25));return response();};
  const tokens=await Promise.all(Array.from({length:4},()=>resolveCredential(x.state,x.target,x.identity,{request})));
  assert.equal(calls,1);assert.ok(tokens.every(v=>v===tokens[0]));assert.equal(credentialStatus(x.state,x.target,x.identity).status,'ready');
  const stored=JSON.parse(fs.readFileSync(path.join(x.privateDir,x.identity.credentialRef+'.json')));assert.equal(stored.refreshToken,'synthetic-refresh-rotated');
  await resolveCredential(x.state,x.target,x.identity,{force:true,request:async(_,o)=>{assert.equal(new URLSearchParams(o.body).get('refresh_token'),'synthetic-refresh-rotated');return response('owner','synthetic-refresh-second');}});
  assert.equal(process.env[x.identity.secretEnv],undefined);assert.doesNotMatch(JSON.stringify(redact({token:tokens[0],refresh:stored.refreshToken})),/synthetic/);
});

test('refresh failures, redirects, wrong account/project, and cancellation never release a token',async t=>{
  const x=await setup(t),record=()=>fs.readFileSync(path.join(x.privateDir,x.identity.credentialRef+'.json'),'utf8'),before=record();
  for(const r of [{status:302,body:'synthetic-refresh-original'},response('outsider'),response('owner','different','other-project'),{status:400,body:'synthetic-refresh-original'}, {status:200,body:'invalid'}]){
    await assert.rejects(resolveCredential(x.state,x.target,x.identity,{request:async()=>r}),error=>{assert.doesNotMatch(error.message,/synthetic-refresh-original/);return /refresh failed/.test(error.message);});assert.equal(record(),before);
  }
  await assert.rejects(resolveCredential(x.state,x.target,x.identity,{signal:AbortSignal.abort(),request:()=>assert.fail('No network after cancellation')}),/cancelled/);
});

test('credentials cannot cross project/origin/account bindings or revoked scope',async t=>{
  const x=await setup(t);for(const [s,target,identity] of [[{...x.state,project:{...x.state.project,id:'other'}},x.target,x.identity],[x.state,{...x.target,url:'https://other.example.com'},x.identity],[x.state,x.target,{...x.identity,name:'outsider'}]])assert.equal(credentialStatus(s,target,identity).status,'reconnect');
  await assert.rejects(resolveCredential(x.state,{...x.target,authorization:null},x.identity,{request:()=>assert.fail('No refresh after revocation')}),/authorization/);
  await assert.rejects(credentialEnvironment(x.state,x.target,[{...x.identity,checkPath:'/outside'}],{request:()=>assert.fail('No refresh outside scope')}),/outside/);
});

test('data-only import rejects unsafe files without evaluating shell or exposing input',async t=>{
  const x=await setup(t),file=secretFile(temp(),"export ID='private-value'\nexport REFRESH='refresh-value'\n");assert.equal(credentialFields(file).ID,'private-value');
  fs.writeFileSync(file,"ID='literal-p@$$word'\n");assert.equal(credentialFields(file).ID,'literal-p@$$word');
  for(const content of ["ID=$(touch /tmp/should-never-run)\n",'ID=first\nID=second','ID=secret;echo BAD','not an env file']){fs.writeFileSync(file,content);assert.throws(()=>credentialFields(file),/supported|Expected/);}
  fs.writeFileSync(file,'ID=private-value');if(process.platform!=='win32'){fs.chmodSync(file,0o644);assert.throws(()=>credentialFields(file),/private/);fs.chmodSync(file,0o600);const link=file+'.link';fs.symlinkSync(file,link);assert.throws(()=>credentialFields(link),/symbolic/);}
  env(t,'BYPASS_CREDENTIAL_DIR',path.join(x.root,'credentials'));assert.throws(()=>importCredential(x.state,x.target,x.identity,{file,'token-field':'ID'}),/outside/);
});

test('same running MCP session imports accounts, performs proof and saved replay, and repairs a rotated static token',async t=>{
  const root=temp(),vault=temp(),owner={value:'synthetic-private-owner-first'},outsider='synthetic-private-outsider';let requests=0,fixed=false;
  const server=http.createServer((req,res)=>{requests++;const who=req.headers.authorization===`Bearer ${owner.value}`?'owner':req.headers.authorization===`Bearer ${outsider}`?'outsider':null;res.setHeader('Content-Type','application/json');if(!who){res.writeHead(401);return res.end('{}');}if(req.url==='/api/me')return res.end(JSON.stringify({id:who}));if(req.url==='/api/items/item-1'&&(!fixed||who==='owner'))return res.end(JSON.stringify({id:'item-1'}));res.writeHead(403);res.end('{}');});await new Promise(r=>server.listen(0,'127.0.0.1',r));t.after(()=>server.close());
  env(t,'BYPASS_CREDENTIAL_DIR',vault);await execute('init',[root]);
  // Start MCP before the credential file exists; there are no account env values.
  const c=await mcpClient(root,{packaged:true,stateDir:temp(),env:{BYPASS_CREDENTIAL_DIR:vault,BYPASS_OWNER_TOKEN:'',BYPASS_OUTSIDER_TOKEN:''}});t.after(()=>c.close());const pid=c.child.pid;
  await c.call('bypass_add_target',{name:'app',url:`http://127.0.0.1:${server.address().port}`,environment:'local'});await c.call('bypass_verify_target',{name:'app',method:'local'});await c.call('bypass_authorize_target',{name:'app',accept:true,paths:'/api'});
  const file=secretFile(temp(),{OWNER:owner.value,OTHER:outsider,PASSWORD:'unused-private-password'}),outputs=[];
  for(const [name,field] of [['owner','OWNER'],['outsider','OTHER']])outputs.push(await c.call('bypass_import_identity',{name,file,'token-field':field,target:'app','check-path':'/api/me'}));
  assert.equal(requests,0,'import itself never calls the app');assert.equal((await c.call('bypass_onboarding',{mode:'live'})).stage,'ready');
  await c.call('bypass_add_probe',{name:'item',path:'/api/items/item-1','resource-id':'item-1',owner:'owner',outsider:'outsider'});
  const preflight=await c.call('bypass_test_probe',{name:'item'});assert.equal(preflight.validation.status,'ready');assert.equal(requests,3);assert.equal((await c.call('bypass_onboarding',{mode:'live'})).ready.live,true);
  const review=await c.call('bypass_scan',{mode:'live'});const proof=await c.call('bypass_review_step',{id:review.runId,action:'probe',index:0});assert.equal(proof.observation.status,'failed');await c.call('bypass_review_step',{id:review.runId,action:'finish'});
  fixed=true;const retest=await c.call('bypass_retest',{id:proof.findings[0]});assert.equal(retest.status,'fixed_verified');
  const job=await c.call('bypass_run_tests',{all:true});assert.equal((await c.wait(job.runId)).exitCode,0,'detached replay reads the private store too');
  await c.call('bypass_add_monitor',{name:'private-accounts',target:'app',every:'1h',runner:'local'});await c.call('bypass_monitor_worker',{action:'once'});
  assert.equal(read(root).runs.filter(r=>r.kind==='monitor').at(-1).exitCode,0,'monitor tick reads private credentials without shell exports');
  const oldRef=read(root).identities.find(i=>i.name==='owner').credentialRef;owner.value='synthetic-private-owner-second';secretFile(path.dirname(file),{OWNER:owner.value,OTHER:outsider});
  outputs.push(await c.call('bypass_import_identity',{name:'owner',file,'token-field':'OWNER'}));assert.equal(read(root).identities.length,2);assert.equal(fs.existsSync(path.join(vault,oldRef+'.json')),false);
  assert.equal((await c.call('bypass_test_identity',{name:'owner'})).check.status,'accepted');assert.equal(c.child.pid,pid);
  const exported=await c.call('bypass_export_tests',{all:true});assert.doesNotMatch(fs.readFileSync(exported.files[0],'utf8'),/credentialRef|synthetic-private|unused-private/);
  const text=JSON.stringify(outputs)+fs.readFileSync(path.join(root,'.bypass/state.json'),'utf8')+fs.readFileSync(path.join(root,'.bypass/project.json'),'utf8');assert.doesNotMatch(text,/synthetic-private|unused-private/);
  for(const file of fs.readdirSync(vault)){const record=JSON.parse(fs.readFileSync(path.join(vault,file)));assert.equal(record.PASSWORD,undefined);assert.doesNotMatch(JSON.stringify(record),/unused-private/);if(process.platform!=='win32')assert.equal(fs.statSync(path.join(vault,file)).mode&0o777,0o600);}
  const ref=read(root).identities.find(i=>i.name==='owner').credentialRef;await c.call('bypass_remove_identity',{name:'owner'});assert.equal(fs.existsSync(path.join(vault,ref+'.json')),false);
});

test('expired static tokens block, imported file can be removed, and CI environment compatibility remains',async t=>{
  const x=await setup(t);x.identity.credentialRef=importCredential(x.state,x.target,x.identity,{file:x.file,'token-field':'ID'});
  assert.equal(credentialStatus(x.state,x.target,x.identity).status,'expired');await assert.rejects(resolveCredential(x.state,x.target,x.identity),/importing/);
  const identity={...x.identity};delete identity.credentialRef;assert.equal(await resolveCredential(x.state,x.target,identity,{env:{[identity.secretEnv]:'ci-test-token'}}),'ci-test-token');
  const f=secretFile(temp(),{ID:'static-test-secret'});identity.credentialRef=importCredential(x.state,x.target,identity,{file:f,'token-field':'ID'});fs.unlinkSync(f);assert.equal(await resolveCredential(x.state,x.target,identity),'static-test-secret');
  const missing=path.join(temp(),'missing-store');process.env.BYPASS_CREDENTIAL_DIR=missing;assert.equal(credentialStatus(x.state,x.target,identity).status,'reconnect');assert.equal(fs.existsSync(missing),false,'readiness must not create credential storage');
});
