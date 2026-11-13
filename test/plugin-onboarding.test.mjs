import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { temp } from './helpers.mjs';
import { execute } from '../src/service.mjs';
import { read, change } from '../src/store.mjs';
import { pluginOnboarding } from '../src/plugin-onboarding.mjs';
import { prepareBlackboxSetup } from '../src/blackbox/setup.mjs';
import { rememberSelection, savedSelection, sessionHint, monitorSummary } from '../src/plugin-context.mjs';
import { VERSION } from '../src/util.mjs';
import { mcpClient } from './mcp-client.mjs';
import { recommendedMethods } from '../src/http-methods.mjs';

const dockerReady=async()=>({available:true,message:'Docker ready (test dependency).'});
const checklist=(host,root,options={})=>pluginOnboarding(host,root,{mode:'combined',checkDocker:dockerReady,...options});

test('failed model preflight takes precedence over app questions without discarding setup',async()=>{
  const root=await sourceReady();
  await change(root,s=>{s.models[0].lastAttempt={status:'failed',reason:'timeout',checkedAt:new Date().toISOString()};});
  const result=await checklist(root,root);
  assert.equal(result.ready.source,true);assert.equal(result.nextAction.id,'app');
  assert.equal(result.nextAction.tool,'bypass_add_target');assert.equal(result.selectedRepository,root);
});
function environment(t,values){for(const [key,value] of Object.entries(values)){const old=process.env[key];process.env[key]=value;t.after(()=>{if(old===undefined)delete process.env[key];else process.env[key]=old;});}}
async function sourceReady(){const root=temp();fs.writeFileSync(path.join(root,'app.mjs'),'export const app = true;');await execute('init',[root]);await execute('config set',['ownershipVerification','dns'],{project:root});await execute('engine use',['docker'],{project:root});await execute('model add',['muse'],{project:root,provider:'meta','secret-env':'BYPASS_UNIT_API_KEY',model:'test-model',stream:false});return root;}

test('unselected context guides repository selection without leaking host demo history or mutating it',async t=>{
  const host=temp();environment(t,{BYPASS_PLUGIN_STATE_DIR:temp()});
  fs.writeFileSync(path.join(host,'package.json'),JSON.stringify({name:'@bypass-labs/bypass'}));
  await execute('init',[host]);await change(host,s=>{s.demo={target:'demo'};s.events.push({message:'OLD_DEMO_FAILURE_SENTINEL'});});
  const before=fs.readFileSync(path.join(host,'.bypass/state.json'),'utf8');
  const status=await checklist(host,null);assert.equal(status.version,VERSION);assert.equal(status.workspace.isBypassSource,true);
  assert.equal(status.nextAction.id,'repository');assert.equal(status.ready.source,false);
  assert.doesNotMatch(JSON.stringify(status),/OLD_DEMO_FAILURE_SENTINEL/);
  const hint=sessionHint(host);assert.equal(hint.selectedRepository,null);assert.equal(hint.analysis,undefined);
  assert.doesNotMatch(JSON.stringify(hint),/OLD_DEMO_FAILURE_SENTINEL/);
  assert.equal(fs.readFileSync(path.join(host,'.bypass/state.json'),'utf8'),before);
});

test('saved explicit selection survives sessions but cannot cross workspaces or select a replaced/example project',async t=>{
  environment(t,{BYPASS_PLUGIN_STATE_DIR:temp()});const host=temp(),other=temp(),app=await sourceReady();
  assert.equal(savedSelection(host),null);assert.equal(rememberSelection(host,app).remembered,true);
  assert.equal(savedSelection(host),app);assert.equal(savedSelection(other),null);
  assert.equal(sessionHint(host).engine,'host');assert.equal(sessionHint(host).version,VERSION);
  await change(app,s=>{s.project.id='replaced-project';});assert.equal(savedSelection(host),null);
  await change(app,s=>{s.poc={running:false};});assert.equal(rememberSelection(host,app).remembered,false);
  assert.equal(savedSelection(host),null);
});

test('host onboarding does not require a model or Docker and offers source review',async()=>{
  const root=temp();fs.writeFileSync(path.join(root,'app.mjs'),'export const app = true;');await execute('init',[root]);
  const status=await checklist(root,root,{checkDocker:async()=>assert.fail('No Docker check in host mode')});
  assert.equal(status.ready.source,true);assert.equal(status.nextAction.id,'app');assert.deepEqual(status.alternatives[0].arguments,{mode:'code'});
  assert.equal(status.steps.some(s=>['model','docker'].includes(s.id)),false);assert.equal(read(root).models.length,0);
});

test('deployed DNS challenge is exact, renews when expired and never implies testing permission',async()=>{
  const root=await sourceReady();await execute('target add',['staging'],{project:root,url:'https://app.example.com',environment:'staging'});
  let status=await checklist(root,root);assert.equal(status.stage,'ownership');assert.equal(status.ready.source,true);assert.equal(status.ready.live,false);
  assert.deepEqual(status.nextAction.challenge,{record:'_bypass-verification.app.example.com',value:read(root).targets[0].challenge.token,method:'dns',expiresAt:read(root).targets[0].challenge.expiresAt,renewRequired:false});
  await change(root,s=>{s.targets[0].challenge.expiresAt='2000-01-01T00:00:00Z';});
  assert.equal((await checklist(root,root)).nextAction.challenge.renewRequired,true);
  await execute('target verify',['staging'],{project:root,method:'dns',renew:true});
  status=await checklist(root,root);assert.equal(status.nextAction.challenge.renewRequired,false);assert.equal(read(root).targets[0].authorization,null);
});

test('local onboarding permits optional accounts and retains per-probe validation state',async t=>{
  environment(t,{BYPASS_ONBOARD_OWNER_TOKEN:'owner-test-value',BYPASS_ONBOARD_OTHER_TOKEN:'other-test-value'});
  const root=await sourceReady(),o={project:root};await execute('target add',['app'],{...o,url:'http://127.0.0.1:3456',environment:'local'});
  let status=await checklist(root,root);assert.equal(status.nextAction.challenge.method,'local');assert.match(status.nextAction.question,/on this computer/);
  await execute('target verify',['app'],{...o,method:'local'});status=await checklist(root,root);assert.equal(status.stage,'scope');assert.equal(status.ready.live,false);
  assert.deepEqual(status.nextAction.scope.methods,recommendedMethods);
  assert.deepEqual(status.nextAction.custom.methods.singleSelectFallback.choices.find(choice=>choice.label==='All methods').methods,
    ['GET','HEAD','POST','PUT','PATCH','DELETE','OPTIONS']);
  await execute('target authorize',['app'],{...o,paths:'/api',accept:true});status=await checklist(root,root);assert.equal(status.stage,'ready');assert.equal(status.steps.find(s=>s.id==='accounts').status,'optional');
  await execute('identity add',['owner'],{...o,target:'app',type:'bearer','secret-env':'BYPASS_ONBOARD_OWNER_TOKEN'});
  await execute('identity add',['other'],{...o,target:'app',type:'bearer','secret-env':'BYPASS_ONBOARD_OTHER_TOKEN','check-path':'/api/me'});
  status=await checklist(root,root);assert.equal(status.nextAction.tool,'bypass_scan');assert.ok(status.coverageGaps.length);
  await execute('identity update',['owner'],{...o,'check-path':'/api/me'});assert.equal((await checklist(root,root)).stage,'ready');
  await execute('probe add',['invoice'],{...o,target:'app',path:'/api/invoices/inv-101','resource-id':'inv-101',owner:'owner',outsider:'other'});
  status=await checklist(root,root);assert.deepEqual(status.ready,{source:true,live:true});assert.equal(status.stage,'ready');assert.equal(status.steps.find(s=>s.id==='resource').probes[0].status,'preflight_required');
  assert.doesNotMatch(JSON.stringify(status),/owner-test-value|other-test-value/);
  delete process.env.BYPASS_ONBOARD_OTHER_TOKEN;status=await checklist(root,root);
  assert.equal(status.ready.live,true);assert.equal(status.nextAction.tool,'bypass_scan');assert.ok(status.coverageGaps.some(x=>x.includes('BYPASS_ONBOARD_OTHER_TOKEN')));
  assert.equal(read(root).runs.length,0,'onboarding must not make any scan or model calls');
});

test('running-app-only wizard hands fresh and saved scopes to blackbox',async()=>{
  const root=temp(),url='http://127.0.0.1:3456';
  await execute('init',[root]);
  await execute('target add',['app'],{project:root,url,environment:'local'});
  await execute('target verify',['app'],{project:root,method:'local'});
  const file=path.join(root,'approved-scope.json');
  fs.writeFileSync(file,JSON.stringify({paths:['/api','/public'],methods:['GET','HEAD','POST','PATCH'],maxRequestsPerSecond:7}));
  await execute('target authorize',['app'],{project:root,'scope-file':file,accept:true});

  const first=await pluginOnboarding(root,root,{mode:'live'});
  assert.equal(first.stage,'ready');
  assert.equal(first.nextAction.tool,'bypass_blackbox_setup');
  assert.deepEqual(first.nextAction.arguments,{url,include:'/api,/public',methods:'GET,HEAD,POST,PATCH',rps:7,environment:'local'});
  assert.match(first.nextAction.message,/start the blackbox audit immediately/i);assert.match(first.nextAction.message,/Do not ask another setup question/i);
  assert.equal(read(root).runs.length,0);

  const options={...first.nextAction.arguments,'model-calls':12,minutes:1};
  const fresh=await prepareBlackboxSetup(root,url,options);
  assert.equal(fresh.ready,true);
  assert.equal(fresh.created,true);
  const second=await pluginOnboarding(root,root,{mode:'live'});
  assert.equal(second.nextAction.tool,'bypass_blackbox_setup');
  assert.deepEqual(second.nextAction.arguments,first.nextAction.arguments);
  const saved=await prepareBlackboxSetup(root,url,options);
  assert.equal(saved.ready,true);
  assert.equal(saved.created,false);
  assert.equal(saved.scopeFile,fresh.scopeFile);
  assert.equal(read(root).runs.length,0);
});

test('combined wizard asks for exact methods, rate and shared audit limits before approval',async()=>{
  const root=await sourceReady(),url='http://127.0.0.1:3456';
  await execute('target add',['app'],{project:root,url,environment:'local'});
  await execute('target verify',['app'],{project:root,method:'local'});
  await execute('target authorize',['app'],{project:root,paths:'/',methods:'GET,HEAD,POST',rps:2,accept:true});
  const ask=options=>pluginOnboarding(root,root,{mode:'combined',interactiveCombined:true,...options});
  let step=await ask();assert.equal(step.stage,'methods');assert.equal(step.nextAction.input.choices.length,3);
  const methods='GET,HEAD,POST,PUT,PATCH,DELETE,OPTIONS';
  step=await ask({methods});assert.equal(step.stage,'rps');assert.equal(step.nextAction.input.choices.length,3);
  step=await ask({methods,rps:12});assert.equal(step.stage,'model-calls');assert.equal(step.nextAction.input.choices.length,3);
  step=await ask({methods,rps:12,modelCalls:400});assert.equal(step.stage,'minutes');assert.equal(step.nextAction.input.choices.length,3);
  assert.deepEqual(step.nextAction.input.choices.find(choice=>choice.id==='quick').arguments,{minutes:10});
  assert.equal(step.nextAction.input.choices.find(choice=>choice.id==='custom').requiresInput,'minutes');
  await assert.rejects(ask({methods,rps:12,modelCalls:400,minutes:5}),
    /at least 10 minutes/);
  step=await ask({methods,rps:12,modelCalls:400,minutes:30});assert.equal(step.stage,'scope');
  assert.deepEqual(step.nextAction.arguments.methods,methods.split(','));
  assert.equal(step.nextAction.arguments.rps,12);
  step=await ask({methods,rps:12,modelCalls:400,minutes:30,scopeApproved:true});
  assert.equal(step.stage,'ready');assert.deepEqual(step.nextAction.arguments,{mode:'combined',modelCalls:400,minutes:30});
});

test('upfront intake collects one plan and proceeds directly to exact scope approval',async t=>{
  const root=await sourceReady(),url='http://127.0.0.1:3456';
  await execute('target add',['app'],{project:root,url,environment:'local'});
  await execute('target verify',['app'],{project:root,method:'local'});
  const client=await mcpClient(root,{stateDir:temp()});t.after(()=>client.close());
  const intake=await client.call('bypass_onboarding',{mode:'combined',upfrontIntake:true,url});
  assert.equal(intake.stage,'intake');
  assert.deepEqual(intake.nextAction.questions.map(item=>item.id),['auditPreset','scopePreset']);
  assert.equal(intake.nextAction.questions[0].input.choices.length,3);
  const approval=await client.call('bypass_onboarding',{auditPreset:'quick',scopePreset:'all',reviewScope:true});
  assert.equal(approval.stage,'scope');
  assert.deepEqual(approval.nextAction.scope.paths,['/']);
  assert.deepEqual(approval.nextAction.scope.methods,recommendedMethods);
  assert.equal(approval.nextAction.scope.maxRequestsPerSecond,20);
  const authorized=await client.call('bypass_authorize_target',{
    name:'app',paths:'/',methods:recommendedMethods.join(','),rps:20,accept:true});
  assert.equal(authorized.onboarding.stage,'ready');
  assert.deepEqual(authorized.nextAction.arguments,{mode:'combined',modelCalls:120,minutes:10});
  const scan=await client.call('bypass_scan',{mode:'combined'});
  const run=read(root).runs.find(item=>item.id===scan.runId);
  assert.equal(run.options.minutes,10);assert.equal(run.options.modelCalls,120);
});

test('remote app intake groups environment with duration and scope',async()=>{
  const root=await sourceReady();
  const intake=await pluginOnboarding(root,root,{mode:'combined',url:'https://app.example.com',upfrontIntake:true});
  assert.equal(intake.stage,'intake');
  assert.deepEqual(intake.nextAction.questions.map(item=>item.id),['environment','auditPreset','scopePreset']);
  assert.deepEqual(intake.nextAction.questions[0].input.choices.map(item=>item.id),
    ['production','staging','preview']);
});

test('upfront app-only plan carries selected limits to blackbox setup',async()=>{
  const root=await sourceReady(),url='http://127.0.0.1:3456';
  await execute('target add',['app'],{project:root,url,environment:'local'});
  await execute('target verify',['app'],{project:root,method:'local'});
  const result=await pluginOnboarding(root,root,{mode:'live',url,upfrontIntake:true,
    auditPreset:'thorough',scopePreset:'all',reviewScope:true});
  assert.equal(result.stage,'scope');
  await execute('target authorize',['app'],{project:root,paths:'/',methods:recommendedMethods.join(','),rps:20,accept:true});
  const ready=await pluginOnboarding(root,root,{mode:'live',url,upfrontIntake:true,
    auditPreset:'thorough',scopePreset:'all',scopeApproved:true});
  assert.equal(ready.nextAction.tool,'bypass_blackbox_setup');
  assert.equal(ready.nextAction.arguments.minutes,60);
  assert.equal(ready.nextAction.arguments['model-calls'],240);
});

test('upfront app-only intake reapproves a saved scope once, then starts setup',async t=>{
  const root=await sourceReady(),url='http://127.0.0.1:3456';
  await execute('target add',['app'],{project:root,url,environment:'local'});
  await execute('target verify',['app'],{project:root,method:'local'});
  await execute('target authorize',['app'],{project:root,paths:'/api',methods:'GET',rps:2,accept:true});
  const client=await mcpClient(root,{stateDir:temp()});t.after(()=>client.close());
  assert.equal((await client.call('bypass_onboarding',{mode:'live',url,upfrontIntake:true})).stage,'intake');
  const scope=await client.call('bypass_onboarding',{auditPreset:'standard',scopePreset:'all'});
  assert.equal(scope.stage,'scope');
  assert.deepEqual(scope.nextAction.scope.paths,['/']);
  const authorized=await client.call('bypass_authorize_target',{
    name:'app',paths:'/',methods:recommendedMethods.join(','),rps:20,accept:true});
  assert.equal(authorized.onboarding.stage,'ready');
  assert.equal(authorized.nextAction.tool,'bypass_blackbox_setup');
  assert.equal(authorized.nextAction.arguments.minutes,30);
  assert.equal(authorized.nextAction.arguments['model-calls'],120);
  assert.equal((await client.call('bypass_onboarding',{auditPreset:'quick'})).stage,'scope',
    'changing the duration invalidates the prior approval');
  assert.equal((await client.call('bypass_onboarding',{scopePreset:'custom'})).stage,'scope');
  const narrowed=await client.call('bypass_authorize_target',{
    name:'app',paths:'/api',methods:'GET',rps:2,accept:true});
  assert.equal(narrowed.onboarding.stage,'ready');
  assert.equal(narrowed.nextAction.arguments.include,'/api');
  assert.equal(narrowed.nextAction.arguments.methods,'GET');
  assert.equal(narrowed.nextAction.arguments.minutes,10);
});

test('combined MCP wizard carries selected scope and total limits into the source review',async t=>{
  const root=await sourceReady(),url='http://127.0.0.1:3456';
  await execute('target add',['app'],{project:root,url,environment:'local'});
  await execute('target verify',['app'],{project:root,method:'local'});
  await execute('target authorize',['app'],{project:root,paths:'/',methods:'GET,HEAD,POST',rps:2,accept:true});
  const client=await mcpClient(root,{stateDir:temp()});t.after(()=>client.close());
  const methods='GET,HEAD,POST,PUT,PATCH,DELETE,OPTIONS';
  assert.equal((await client.call('bypass_onboarding',{mode:'combined'})).stage,'methods');
  assert.equal((await client.call('bypass_onboarding',{methods})).stage,'rps');
  assert.equal((await client.call('bypass_onboarding',{rps:12})).stage,'model-calls');
  assert.equal((await client.call('bypass_onboarding',{modelCalls:400})).stage,'minutes');
  const approval=await client.call('bypass_onboarding',{minutes:30});
  assert.equal(approval.stage,'scope');
  assert.equal(approval.nextAction.arguments.rps,12);
  assert.deepEqual(approval.nextAction.arguments.methods,methods.split(','));
  const authorized=await client.call('bypass_authorize_target',{
    name:'app',paths:'/',methods,rps:12,accept:true});
  assert.equal(authorized.onboarding.stage,'ready');
  assert.deepEqual(authorized.nextAction.arguments,{mode:'combined',modelCalls:400,minutes:30});
  const scan=await client.call('bypass_scan',{mode:'combined',modelCalls:5,minutes:1});
  assert.equal(read(root).runs.find(run=>run.id===scan.runId).options.modelCalls,400);
  assert.equal(read(root).runs.find(run=>run.id===scan.runId).options.minutes,30);
  assert.equal(read(root).targets.find(target=>target.name==='app').authorization.maxRequestsPerSecond,12);
  assert.equal((await client.call('bypass_onboarding',{mode:'combined'})).stage,'methods',
    'a later combined review asks again instead of silently reusing an old run selection');
});

test('model credential absence repairs environment without duplicating the profile',async()=>{
  const root=temp();fs.writeFileSync(path.join(root,'app.mjs'),'export const app = true;');await execute('init',[root]);await execute('config set',['ownershipVerification','dns'],{project:root});await execute('engine use',['docker'],{project:root});
  await execute('model add',['private'],{project:root,provider:'custom','secret-env':'BYPASS_UNIT_API_KEY',stream:false,'base-url':'https://model.example.com',model:'own-model','secret-env':'BYPASS_NONEXISTENT_ONBOARD_KEY'});
  const status=await checklist(root,root);assert.equal(status.stage,'app');assert.equal(status.ready.source,true);
  assert.equal(status.nextAction.tool,'bypass_add_target');
  assert.equal(read(root).models.length,1);
});

test('historical monitor failure is superseded only by a later passing check on the same target',()=>{
  const state={runs:[{id:'old',kind:'monitor',exitCode:1,finishedAt:'2026-10-26T22:08:40.192Z',result:{results:[{id:'check',target:'app',status:'failed'}]}}],checks:[{id:'check',target:'app',lastResult:{status:'passed',target:'app',checkedAt:'2026-10-26T22:08:40.515Z'}}],monitors:[{enabled:false}]};
  assert.equal(monitorSummary(state).status,'superseded_by_passing_retest');assert.equal(monitorSummary(state).activeSchedules,0);
  state.checks[0].lastResult.target='another-app';assert.equal(monitorSummary(state).superseded,false);
  state.checks[0].lastResult.target='app';state.checks[0].lastResult.status='stale';assert.equal(monitorSummary(state).superseded,false);
  state.checks[0].lastResult.status='passed';state.checks[0].lastResult.checkedAt='2026-10-25T00:00:00Z';assert.equal(monitorSummary(state).superseded,false);
});
