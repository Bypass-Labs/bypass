import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import dns from 'node:dns/promises';
import {temp} from './helpers.mjs';
import {execute} from '../src/service.mjs';
import {read,change} from '../src/store.mjs';
import {scopeReady} from '../src/network.mjs';
import {sharedOwnership} from '../src/ownership-store.mjs';
import {loadScope, observedMethodAuthorized} from '../src/blackbox/scope.mjs';
import {deriveLocalPostScope} from '../src/blackbox/anonymous.mjs';
import {mcpClient} from './mcp-client.mjs';
import {pluginOnboarding} from '../src/plugin-onboarding.mjs';

async function project(t){
  const root=temp();t.after(()=>fs.rmSync(root,{recursive:true,force:true}));
  await execute('init',[root]);return root;
}

test('packaged app-only setup reaches one approval picker without DNS, repository reads or authorization',async t=>{
  const host=temp(),stateDir=temp();t.after(()=>fs.rmSync(host,{recursive:true,force:true}));t.after(()=>fs.rmSync(stateDir,{recursive:true,force:true}));
  const c=await mcpClient(host,{stateDir,packaged:true});t.after(()=>c.close());
  const first=await c.call('bypass_onboarding');assert.equal(first.stage,'review-type');
  const choose=await c.call('bypass_onboarding',{mode:'live',url:'https://ux-demo.example.com',environment:'production'});
  const connected=await c.call(choose.nextAction.tool,choose.nextAction.arguments);
  const next=connected.nextAction;assert.equal(next.tool,'bypass_authorize_target');
  assert.deepEqual(next.input.choices.map(c=>c.label),['Approve','Decline','Custom instructions']);
  assert.equal(next.input.choices.some(c=>c.recommended),false,'no preselection counts as permission');
  assert.equal(fs.existsSync(path.join(host,'.bypass')),false);
  const target=read(connected.root).targets[0];assert.equal(target.authorization,null);assert.notEqual(target.ownership.status,'verified');
  assert.throws(()=>scopeReady(target));
  const rejected=await c.raw('bypass_authorize_target',{...next.arguments,accept:false});assert.equal(rejected.result.isError,true);
  assert.equal(read(connected.root).targets[0].authorization,null,'Decline/custom do not grant permission');
  const approved=await c.call(next.tool,{...next.arguments,accept:true,production:true});
  assert.equal(approved.nextAction.tool,'bypass_blackbox_setup');assert.equal(approved.onboarding.stage,'ready');
  assert.equal(approved.nextAction.arguments.url,'https://ux-demo.example.com');
  const saved=read(connected.root).targets[0];assert.equal(saved.ownership.status,'acknowledged');assert.equal(sharedOwnership(saved.url),null);
  assert.equal(scopeReady(saved,'/api/owned','POST'),true);assert.equal(scopeReady(saved,'/api/owned','DELETE'),true);
  assert.equal(read(connected.root).runs.length,0,'setup does not start an assessment');
  const custom=await c.call('bypass_onboarding',{reviewScope:true});
  await c.call(custom.nextAction.tool,{...custom.nextAction.arguments,accept:true,production:true,rps:0.5,paths:'/api',methods:['GET']});
  assert.equal(read(connected.root).targets[0].authorization.maxRequestsPerSecond,0.5);
  assert.deepEqual(read(connected.root).targets[0].authorization.methods,['GET']);
  assert.throws(()=>scopeReady(read(connected.root).targets[0],'/api/owned','POST'),/outside/);
  const blackbox=await c.call('bypass_blackbox_setup',{url:saved.url,plan:true});
  assert.equal(blackbox.scope.environment,'production');assert.deepEqual(blackbox.scope.paths,['/api']);
  assert.deepEqual(blackbox.scope.methods,['GET']);assert.equal(blackbox.scope.maxRequestsPerSecond,0.5);
  assert.equal(blackbox.nextAction.arguments.methods,'GET','the approved follow-up retains the saved plan');
  const prepared=await c.call(blackbox.nextAction.tool,blackbox.nextAction.arguments);
  assert.equal(prepared.ready,true,'the returned next action must work with the typed MCP schema');
});

test('verification-off still requires explicit consent, production approval, exact scope and expiry',async t=>{
  const root=await project(t),o={project:root};await execute('target add',['prod'],{...o,url:'https://scope-demo.example.com',environment:'production'});
  const file=path.join(root,'scope.json');fs.writeFileSync(file,JSON.stringify({paths:['/api'],methods:['GET'],productionAcknowledged:true}));
  await assert.rejects(execute('target authorize',['prod'],{...o,'scope-file':file}),/Explicitly confirm/);
  await assert.rejects(execute('target authorize',['prod'],{...o,accept:true,paths:'/api'}),/Production scope/);
  assert.equal(read(root).targets[0].authorization,null);
  await execute('target authorize',['prod'],{...o,accept:true,production:true,paths:'/api',methods:'GET,HEAD,POST'});
  let target=read(root).targets[0];assert.equal(scopeReady(target,'/api/items','POST'),true);
  assert.throws(()=>scopeReady(target,'/outside','GET'),/outside/);assert.throws(()=>scopeReady(target,'/api/items','DELETE'),/outside/);
  await change(root,s=>{s.targets[0].authorization.expiresAt='2000-01-01T00:00:00Z';});
  assert.throws(()=>scopeReady(read(root).targets[0]),/authorization/);
});

test('project DNS and HTTPS flags restore verification while a missing flag stays off',async t=>{
  const root=await project(t),o={project:root};
  await execute('target add',['app'],{...o,url:'https://strict-demo.example.com',environment:'staging'});
  await execute('target authorize',['app'],{...o,accept:true,paths:'/api'});
  await execute('config set',['ownershipVerification','dns'],o);
  assert.equal(read(root).targets[0].authorization,null);
  let plan=await pluginOnboarding(root,root,{mode:'live'});assert.equal(plan.stage,'ownership');
  await assert.rejects(execute('target authorize',['app'],{...o,accept:true,paths:'/api'}),/Verify control/);
  t.mock.method(dns,'resolveTxt',async()=>[[read(root).targets[0].challenge.token]]);
  await execute('target verify',['app'],o);
  await execute('target authorize',['app'],{...o,accept:true,paths:'/api'});assert.equal(scopeReady(read(root).targets[0]),true);
  const proof=read(root).targets[0].ownership;
  await execute('config set',['ownershipVerification','off'],o);
  await execute('target authorize',['app'],{...o,accept:true,paths:'/api'});
  assert.deepEqual(read(root).targets[0].ownership,proof,'explicit approval must preserve existing verified proof');
  await execute('config set',['ownershipVerification','http'],o);assert.equal(read(root).targets[0].authorization,null);
  await execute('target add',['http'],{...o,url:'https://file-demo.example.com',environment:'staging'});
  await execute('target use',['http'],o);
  plan=await pluginOnboarding(root,root,{mode:'live'});assert.equal(plan.stage,'ownership');assert.equal(read(root).targets[1].ownershipVerification,'http');
  assert.equal(plan.nextAction.challenge.method,'http');assert.match(plan.nextAction.challenge.url,/^https:\/\/file-demo/);
  await change(root,s=>{delete s.settings.ownershipVerification;});
  await execute('target add',['default-off'],{...o,url:'https://default-off.example.com',environment:'staging'});
  assert.equal(read(root).targets[2].ownershipVerification,'off');
  await execute('target use',['default-off'],o);
  plan=await pluginOnboarding(root,root,{mode:'live'});assert.equal(plan.stage,'scope');assert.equal(plan.nextAction.tool,'bypass_authorize_target');
  await assert.rejects(execute('config set',['ownershipVerification','whatever'],o),/off, dns, or http/);
});

test('read-only blackbox plan preserves scope and prepares the same bounded audit after approval',async t=>{
  const root=await project(t),url='https://plan-demo.example.com',o={project:root,environment:'production',include:'/api',methods:'GET,HEAD,POST',rps:2,'model-calls':17,minutes:4};
  const before=fs.readFileSync(path.join(root,'.bypass/state.json'),'utf8');
  const plan=await execute('blackbox setup',[url],{...o,plan:true});
  assert.equal(plan.kind,'blackbox-plan');assert.deepEqual(plan.input.choices.map(c=>c.id),['approve','decline','custom']);
  assert.equal(plan.scope.modelCalls,17);assert.equal(plan.scope.minutes,4);
  assert.equal(fs.existsSync(path.join(root,'blackbox.scope.json')),false);assert.equal(fs.readFileSync(path.join(root,'.bypass/state.json'),'utf8'),before);
  const setup=await execute('blackbox setup',[url],o);assert.equal(setup.steps.some(s=>s.kind==='ownership'),false);
  const approval=setup.steps.find(s=>s.kind==='authorization');assert.ok(approval);
  await execute('target authorize',[approval.target],{project:root,'scope-file':approval.file,accept:true,production:true});
  const {scope}=loadScope({origin:url,file:setup.scopeFile,targets:read(root).targets});
  assert.equal(scope.target.acknowledged,'operator-authorized');assert.equal(scope.limits.rps,2);assert.deepEqual(scope.methods,['GET','HEAD','POST']);
  const mined={endpoints:[{method:'POST',path:'/api/feedback',bodyEncoding:'json',bodyFields:['text']}]};
  const derived=await deriveLocalPostScope(scope,mined,async()=>({status:404}));
  assert.equal(derived.admitted.length,1,'explicitly approved POST works with project verification off');
  assert.equal(observedMethodAuthorized(scope,'DELETE'),false,'an acknowledgment never expands allowed methods');
  const strict=structuredClone(scope);strict.authorizedOrigins[url].ownershipVerification='dns';
  assert.equal(observedMethodAuthorized(strict,'POST'),false,'the off setting is required, not just an acknowledgment label');
  const saved=fs.readFileSync(setup.scopeFile,'utf8');
  const resumed=await execute('blackbox setup',[url],{project:root,plan:true});assert.equal(resumed.savedScope,true);assert.deepEqual(resumed.scope.paths,['/api']);assert.equal(resumed.scope.modelCalls,17);
  const slower=await execute('blackbox setup',[url],{project:root,plan:true,rps:1});
  assert.equal(slower.scope.maxRequestsPerSecond,2);assert.equal(slower.scope.runRequestsPerSecond,1,'distinguish the saved authorization limit from a slower run');
  await execute('blackbox setup',[url],{project:root,plan:true,rps:3,methods:'GET'});
  assert.equal(fs.readFileSync(setup.scopeFile,'utf8'),saved,'previewing custom settings does not mutate scope');
  await execute('target revoke',[approval.target],{project:root});assert.throws(()=>scopeReady(read(root).targets[0]),/ownership|authorization/);
  assert.equal(observedMethodAuthorized(scope,'POST'),false,'revocation applies to existing scope snapshots');
  assert.throws(()=>loadScope({origin:url,file:setup.scopeFile,targets:read(root).targets}),/ownership|authorization/);
});

test('blackbox setup inherits the connected production environment and exact authorization',async t=>{
  const root=await project(t),url='https://production-scope.example.com',o={project:root};
  await execute('target add',['production'],{...o,url,environment:'production'});
  await execute('target authorize',['production'],{...o,accept:true,production:true,paths:'/api',methods:'GET,HEAD',rps:2});
  const setup=await execute('blackbox setup',[url],o),scope=JSON.parse(fs.readFileSync(setup.scopeFile,'utf8'));
  assert.equal(setup.ready,true);assert.equal(scope.target.environment,'production');
  assert.deepEqual(scope.include,['/api']);assert.deepEqual(scope.methods,['GET','HEAD']);assert.equal(scope.limits.rps,2);
});
