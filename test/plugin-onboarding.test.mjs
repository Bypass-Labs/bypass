import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { temp } from './helpers.mjs';
import { execute } from '../src/service.mjs';
import { read, change } from '../src/store.mjs';
import { pluginOnboarding } from '../src/plugin-onboarding.mjs';
import { rememberSelection, savedSelection, sessionHint, monitorSummary } from '../src/plugin-context.mjs';
import { VERSION } from '../src/util.mjs';

const dockerReady=async()=>({available:true,message:'Docker ready (test dependency).'});
const checklist=(host,root,options={})=>pluginOnboarding(host,root,{checkDocker:dockerReady,...options});

test('failed model preflight takes precedence over app questions without discarding setup',async()=>{
  const root=await sourceReady();
  await change(root,s=>{s.models[0].lastAttempt={status:'failed',reason:'timeout',checkedAt:new Date().toISOString()};});
  const result=await checklist(root,root);
  assert.equal(result.ready.source,true);assert.equal(result.nextAction.id,'app');
  assert.equal(result.nextAction.tool,'bypass_add_target');assert.equal(result.selectedRepository,root);
});
function environment(t,values){for(const [key,value] of Object.entries(values)){const old=process.env[key];process.env[key]=value;t.after(()=>{if(old===undefined)delete process.env[key];else process.env[key]=old;});}}
async function sourceReady(){const root=temp();await execute('init',[root]);await execute('engine use',['docker'],{project:root});await execute('model add',['muse'],{project:root,provider:'meta','secret-env':'BYPASS_UNIT_API_KEY',model:'test-model',stream:false});return root;}

test('unselected context guides repository selection without leaking host demo history or mutating it',async t=>{
  const host=temp();environment(t,{BYPASS_PLUGIN_STATE_DIR:temp()});
  fs.writeFileSync(path.join(host,'package.json'),JSON.stringify({name:'@bypass-labs/cli-skeleton'}));
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
  const root=temp();await execute('init',[root]);
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

test('local onboarding reaches combined readiness only after scope, account repair and exact resource binding',async t=>{
  environment(t,{BYPASS_ONBOARD_OWNER_TOKEN:'owner-test-value',BYPASS_ONBOARD_OTHER_TOKEN:'other-test-value'});
  const root=await sourceReady(),o={project:root};await execute('target add',['app'],{...o,url:'http://127.0.0.1:3456',environment:'local'});
  let status=await checklist(root,root);assert.equal(status.nextAction.challenge.method,'local');assert.match(status.nextAction.question,/local app/);
  await execute('target verify',['app'],{...o,method:'local'});status=await checklist(root,root);assert.equal(status.stage,'scope');assert.equal(status.ready.live,false);
  await execute('target authorize',['app'],{...o,paths:'/api',accept:true});status=await checklist(root,root);assert.equal(status.stage,'accounts');
  await execute('identity add',['owner'],{...o,target:'app',type:'bearer','secret-env':'BYPASS_ONBOARD_OWNER_TOKEN'});
  await execute('identity add',['other'],{...o,target:'app',type:'bearer','secret-env':'BYPASS_ONBOARD_OTHER_TOKEN','check-path':'/api/me'});
  status=await checklist(root,root);assert.equal(status.nextAction.tool,'bypass_update_identity');assert.equal(status.nextAction.arguments.name,'owner');
  await execute('identity update',['owner'],{...o,'check-path':'/api/me'});assert.equal((await checklist(root,root)).stage,'resource');
  await execute('probe add',['invoice'],{...o,target:'app',path:'/api/invoices/inv-101','resource-id':'inv-101',owner:'owner',outsider:'other'});
  status=await checklist(root,root);assert.deepEqual(status.ready,{source:true,live:false});assert.equal(status.stage,'validation');assert.equal(status.nextAction.tool,'bypass_test_probe');
  assert.doesNotMatch(JSON.stringify(status),/owner-test-value|other-test-value/);
  delete process.env.BYPASS_ONBOARD_OTHER_TOKEN;status=await checklist(root,root);
  assert.equal(status.ready.live,false);assert.equal(status.nextAction.tool,'bypass_import_identity');assert.deepEqual(status.nextAction.missingEnvironment,['BYPASS_ONBOARD_OTHER_TOKEN']);
  assert.equal(read(root).runs.length,0,'onboarding must not make any scan or model calls');
});

test('model credential absence repairs environment without duplicating the profile',async()=>{
  const root=temp();await execute('init',[root]);await execute('engine use',['docker'],{project:root});
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
