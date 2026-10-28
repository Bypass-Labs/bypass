import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import http from 'node:http';
import { temp } from './helpers.mjs';
import { execute } from '../src/service.mjs';
import { read, change } from '../src/store.mjs';
import { firebaseConfigs, discoverRegistration } from '../src/registration-discovery.mjs';
import { configureRegistration, registrationStatus, testRegistration } from '../src/registration.mjs';
import { mcpClient } from './mcp-client.mjs';
const apiKey='AIza'+'x'.repeat(35);
const config=(projectId='fixture-project')=>`{apiKey:"${apiKey}",projectId:"${projectId}",authDomain:"${projectId}.firebaseapp.com"}`;
async function fixture(t,{paths='/',publicConfig=false,handler}={}){
  const calls=[],server=http.createServer((req,res)=>{calls.push({url:req.url,method:req.method,authorization:req.headers.authorization,cookie:req.headers.cookie});if(handler)return handler(req,res);res.setHeader('Content-Type',req.url.endsWith('.js')?'application/javascript':'text/html');res.end(req.url.endsWith('.js')?`globalThis.MUST_NOT_RUN=true;const firebaseConfig=${config()};`:'<script type="module" src="/assets/main.js"></script>');});
  await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve));t.after(()=>new Promise(resolve=>server.close(resolve)));
  const root=temp(),url=`http://127.0.0.1:${server.address().port}`;await execute('init',[root]);await execute('target add',['app'],{project:root,url,environment:'local'});await execute('target verify',['app'],{project:root,method:'local'});
  await execute('target authorize',['app'],{project:root,accept:true,methods:['GET','POST'],paths,'public-config':publicConfig});
  await change(root,s=>{s.targets[0].authorization.maxRequestsPerSecond=10;});
  return {root,url,calls};
}

test('config parser accepts a literal tuple but never evaluates code or joins unrelated configs',()=>{
  assert.equal(firebaseConfigs(config())[0].projectId,'fixture-project');
  assert.deepEqual(firebaseConfigs('const c={apiKey:import.meta.env.VITE_FIREBASE_API_KEY,projectId:import.meta.env.VITE_FIREBASE_PROJECT_ID};'),[]);
  assert.deepEqual(firebaseConfigs(`{apiKey:"${apiKey}"}; {projectId:"separate-project"}`),[]);
  assert.deepEqual(firebaseConfigs(`{apiKey:"${apiKey}",projectId:"right-project",authDomain:"wrong-project.firebaseapp.com"}`),[]);
  assert.equal(firebaseConfigs(config()+';'+config()).length,1);assert.equal(firebaseConfigs(config()+';'+config('another-project')).length,2);
});

test('exact missing-project/source-template failure recovers from deployed public config without a user question',async t=>{
  const {root,calls}=await fixture(t);fs.mkdirSync(path.join(root,'ui'),{recursive:true});fs.writeFileSync(path.join(root,'ui/firebase.ts'),'const config={apiKey:import.meta.env.VITE_FIREBASE_API_KEY};');
  const result=await configureRegistration(root,{provider:'firebase',accept:true,'config-file':'ui/firebase.ts','check-path':'/api/profile','identity-field':'owner_uid','email-domain':'synthetic.example.test'});
  assert.equal(result.registration.projectId,'fixture-project');assert.equal(read(root).targets[0].registrationDiscovery.status,'found');assert.ok(calls.length>=2);assert.ok(calls.every(c=>c.method==='GET'&&!c.authorization&&!c.cookie));
  assert.equal(globalThis.MUST_NOT_RUN,undefined);assert.equal(fs.existsSync(path.join(root,'ui/.env')),false);assert.match(result.registration.configFile,/\.bypass[/\\]discovery/);
  assert.ok(!JSON.stringify(result).includes(apiKey));assert.equal(read(root).identities.length,0);assert.equal(result.registration.attempts,undefined);
});

test('project ID can be read from explicitly supplied resolved config without network discovery',async t=>{
  const {root,calls}=await fixture(t,{paths:'/api'}),file=path.join(root,'public-config.json');fs.writeFileSync(file,JSON.stringify({VITE_FIREBASE_API_KEY:apiKey,VITE_FIREBASE_PROJECT_ID:'fixture-project'}));
  const result=await configureRegistration(root,{provider:'firebase',accept:true,'config-file':file,'check-path':'/api/profile','email-domain':'synthetic.example.test'});
  assert.equal(result.registration.projectId,'fixture-project');assert.equal(calls.length,0);
});

test('discovery respects path scope; separately approved public-config read does not authorize general out-of-scope requests',async t=>{
  const {root,calls}=await fixture(t,{paths:'/api'});
  let result=await discoverRegistration(root);assert.equal(result.status,'scope_required');assert.equal(calls.length,0);assert.equal(result.nextAction.arguments.reviewScope,true);
  await execute('target authorize',['app'],{project:root,accept:true,paths:'/api',methods:['GET','POST'],'public-config':true});
  result=await discoverRegistration(root);assert.equal(result.status,'found');assert.ok(calls.length>0);
  await assert.rejects(execute('request',[],{project:root,path:'/outside'}),/outside the authorized scope/);
});

test('discovery never follows another origin and reports multiple projects instead of guessing',async t=>{
  const {root,calls}=await fixture(t,{handler:(req,res)=>{res.setHeader('Content-Type','text/html');res.end(`<script>${config()};${config('another-project')}</script><script src="https://unrelated.example.test/steal.js"></script>`);}});
  const result=await discoverRegistration(root);assert.equal(result.status,'ambiguous');assert.deepEqual(result.projectIds.sort(),['another-project','fixture-project']);assert.equal(result.configFile,null);assert.equal(calls.length,2);assert.equal(read(root).targets[0].registration,undefined);
  const chosen=await discoverRegistration(root,{'project-id':'fixture-project'});assert.equal(chosen.status,'found');assert.equal(chosen.projectId,'fixture-project');
});

test('packaged plugin offers automatic Firebase discovery and persists resolved setup without exposing the public API key',async t=>{
  const {root}=await fixture(t);const c=await mcpClient(root,{stateDir:temp(),packaged:true});t.after(()=>c.close());
  const result=await c.call('bypass_configure_registration',{provider:'firebase',accept:true,'check-path':'/api/profile'});
  assert.equal(result.registration.projectId,'fixture-project');assert.ok(!JSON.stringify(result).includes(apiKey));assert.equal(read(root).identities.length,0);
  assert.equal(result.registration.emailDomain,'bypass-test.example.invalid');
});

test('account picker saves consent across MCP sessions, then discovers Firebase without a project or domain question',async t=>{
  const {root,calls}=await fixture(t),options={stateDir:temp(),packaged:true};let c=await mcpClient(root,options);
  t.after(()=>c.close());
  const status=await c.call('bypass_registration'),input=status.nextAction.input;
  assert.deepEqual(input.choices.map(x=>x.id),['create','existing','skip']);assert.equal(input.hostControl,'request_user_input');assert.equal(input.allowCustom,true);assert.equal(input.choices[0].recommended,true);
  assert.equal(input.permission.maxAccounts,2);assert.equal(input.permission.emailDomain,'bypass-test.example.invalid');assert.equal(calls.length,0);
  assert.equal((await c.raw('bypass_choose_accounts',{mode:'create'})).result.isError,true);assert.equal(read(root).targets[0].accountChoice,undefined);
  await c.call('bypass_choose_accounts',{mode:'create',accept:true});assert.equal(calls.length,0);
  assert.equal((await c.raw('bypass_configure_registration',{provider:'firebase',accept:false,'check-path':'/api/profile'})).result.isError,true);assert.equal(calls.length,0);
  await c.close();c=await mcpClient(root,options);
  const resumed=await c.call('bypass_registration');assert.equal(resumed.nextAction.requiresAnswer,false);assert.equal(resumed.nextAction.automatic,true);
  const configured=await c.call('bypass_configure_registration',{provider:'firebase','check-path':'/api/profile'});
  assert.equal(configured.registration.projectId,'fixture-project');assert.equal(configured.registration.emailDomain,'bypass-test.example.invalid');assert.ok(calls.every(x=>x.method==='GET'));assert.equal(read(root).identities.length,0);
});

test('saved existing/skip choices suppress signup and repeated questions without deleting prior attempt history',async t=>{
  const {root,calls}=await fixture(t);
  await configureRegistration(root,{provider:'firebase',accept:true,'check-path':'/api/profile'});
  await change(root,s=>{s.targets[0].registration.attempts=[{name:'already_reserved',status:'reserved'}];});
  const count=calls.length;
  for(const mode of ['existing','skip']){
    await execute('registration choose',[],{project:root,mode});
    const status=registrationStatus(read(root).targets[0]);assert.equal(status.nextAction,null);assert.equal(status.choice.mode,mode);
    const run=await testRegistration(root);assert.equal(run.requests,0);assert.equal(calls.length,count);assert.equal(read(root).targets[0].registration.attempts.length,1);
    await assert.rejects(configureRegistration(root,{provider:'firebase','check-path':'/api/profile'}),/permission/);
  }
  await execute('registration choose',[],{project:root,mode:'create',accept:true});
  const retry=await testRegistration(root);assert.equal(retry.reused,true);assert.equal(retry.requests,0);assert.equal(calls.length,count);
});

test('account consent persists after a discovery failure but cannot silently authorize a changed scope',async t=>{
  let available=false;const {root,calls}=await fixture(t,{handler:(_q,res)=>res.end(available?`<script>${config()}</script>`:'No config here')});
  const missing=await configureRegistration(root,{provider:'firebase',accept:true,'check-path':'/api/profile'});
  assert.equal(missing.registrationConfigured,false);assert.equal(missing.discovery.nextAction.input.allowCustom,true);
  assert.equal(registrationStatus(read(root).targets[0]).permissionSaved,true);
  assert.equal(registrationStatus(read(root).targets[0]).nextAction.input.field,'registration-recovery');
  await execute('target authorize',['app'],{project:root,accept:true,paths:'/api',methods:['GET','POST'],'public-config':true});
  const count=calls.length;available=true;
  await assert.rejects(configureRegistration(root,{provider:'firebase','check-path':'/api/profile'}),/permission/);assert.equal(calls.length,count);
});

test('a landing page without config still discovers the SPA bundle via index.html, with progress and no signup',async t=>{
  const {root,calls}=await fixture(t,{handler:(req,res)=>{
    res.end(req.url==='/'?'<title>Private beta landing page</title>':req.url==='/index.html'?'<script type="module" src="/assets/main.js"></script>':`const cfg=${config()};`);
  }}),progress=[];
  const result=await configureRegistration(root,{provider:'firebase',accept:true,'check-path':'/api/profile'},{onProgress:step=>progress.push(step.message)});
  assert.equal(result.registration.projectId,'fixture-project');assert.deepEqual(calls.map(c=>c.url),['/','/index.html','/assets/main.js']);assert.equal(calls.filter(c=>c.method==='POST').length,0);
  assert.match(progress.join('\n'),/Reading public sign-in setup/);assert.match(fs.readFileSync(path.join(root,'.gitignore'),'utf8'),/\.bypass\/discovery\//);
});

test('discovery respects request budget and cancellation and stops after scope is revoked',async t=>{
  const {root}=await fixture(t);let calls=0;
  const bounded=await discoverRegistration(root,{}, {request:async()=>{calls++;return {status:200,body:Array.from({length:30},(_,i)=>`<script src="/assets/${calls}-${i}.js"></script>`).join('')};}});
  assert.equal(calls,8);assert.equal(bounded.status,'not_found');
  const abort=new AbortController();abort.abort();
  await assert.rejects(discoverRegistration(root,{}, {signal:abort.signal,request:async()=>assert.fail('No request after cancellation')}));
  calls=0;
  await assert.rejects(discoverRegistration(root,{}, {request:async()=>{calls++;await execute('target revoke',['app'],{project:root});return {status:200,body:`const cfg=${config()};<script src="/assets/next.js"></script>`};}}),/ownership|authorization/);
  assert.equal(calls,1);
});
