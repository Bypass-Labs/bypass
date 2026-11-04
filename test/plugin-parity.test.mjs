import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { toolDefinitions } from '../src/mcp.mjs';
import { capabilityCatalog } from '../src/plugin-parity.mjs';
import { operationFailed } from '../src/plugin-experience.mjs';
import { temp } from './helpers.mjs';
import { mcpClient } from './mcp-client.mjs';
import { read } from '../src/store.mjs';
import { execFile, delay } from '../src/util.mjs';
import { execute } from '../src/service.mjs';

test('every public CLI command and option has a plugin operation or an explicit host lifecycle mapping',()=>{
  const catalog=capabilityCatalog(toolDefinitions);
  assert.deepEqual(catalog.filter(c=>!c.tool&&!c.hostOwned),[]);
  assert.deepEqual(catalog.flatMap(c=>c.options.filter(o=>!o.available).map(o=>`${c.command} --${o.flag}`)),[]);
  assert.deepEqual(catalog.filter(c=>c.hostOwned).map(c=>c.command),['mcp serve']);
  assert.equal(new Set(toolDefinitions.map(t=>t.name)).size,toolDefinitions.length);
  assert.ok(toolDefinitions.find(tool=>tool.name==='bypass_install_plugin').inputSchema.properties.install,
    'the plugin keeps its existing install field for backward compatibility');
  assert.equal(operationFailed({exitCode:1,verification:{status:'failed'}}),false);
  assert.equal(operationFailed({exitCode:1,run:{status:'failed'}}),true);
});

test('complete preview demo stays inside MCP: proof, fix, test controls, exports, regression, scheduler, reports and return to app',async t=>{
  const host=temp(),app=temp(),stateDir=temp(),c=await mcpClient(host,{stateDir});
  t.after(()=>c.child.kill());let fixture;
  t.after(async()=>{if(fixture){await execute('monitor worker',[],{project:fixture,stop:true}).catch(()=>{});await execute('demo stop',[],{project:fixture}).catch(()=>{});}await c.close().catch(()=>{});});
  const help=await c.call('bypass_help');assert.ok(help.capabilities.find(c=>c.command==='ci init').tool);
  assert.equal((await c.call('bypass_dashboard')).selectedRepository,null);
  assert.equal((await c.call('bypass_auth_login',{provider:'muse-code'})).kind,'host-handoff');
  const protectedInstall=await c.raw('bypass_remove_plugin',{confirmed:false});assert.equal(protectedInstall.result.isError,true);
  fs.writeFileSync(path.join(app,'app.mjs'),'export const app = true;');
  const preview=await c.call('bypass_connect_repository',{repository:app,confirmed:true,plan:true});
  assert.equal(preview.plan,true);assert.deepEqual(preview.fileChanges.map(item=>item.path),['.bypass/','.gitignore','.bypassignore']);
  assert.equal(fs.existsSync(path.join(app,'.bypass')),false);assert.equal((await c.call('bypass_dashboard')).selectedRepository,null);
  await c.call('bypass_connect_repository',{repository:app,confirmed:true});
  const original=fs.readFileSync(path.join(app,'.bypass/state.json'),'utf8');
  const demo=await c.call('bypass_demo_start',{kind:'preview'});fixture=demo.root;assert.equal(demo.session.previousRepository,app);
  assert.equal((await c.call('bypass_dashboard')).selectedRepository,fixture);
  const scan=await c.wait((await c.call('bypass_scan',{mode:'combined'})).runId);
  assert.equal(scan.exitCode,3);const finding=scan.result.findings[0];
  const proof=await c.call('bypass_verify',{id:finding});assert.equal(proof.exitCode,1);assert.equal(proof.status,'confirmed_fixture');
  await c.call('bypass_set_config',{key:'autoSave',value:'false'});
  await c.call('bypass_demo_control',{action:'fix'});
  const fixed=await c.call('bypass_retest',{id:finding});assert.equal(fixed.savedCheck,null);
  const check=(await c.call('bypass_save_test',{id:finding})).check;
  assert.equal((await c.call('bypass_test',{id:check.id})).check.id,check.id);
  await c.call('bypass_disable_test',{id:check.id,reason:'Exercise the explicit saved-check control'});
  assert.equal((await c.call('bypass_test',{id:check.id})).check.enabled,false);
  await c.call('bypass_enable_test',{id:check.id});
  // A relative input file must resolve against the selected app, not the host.
  fs.writeFileSync(path.join(fixture,'binding.json'),JSON.stringify(check.bindings.demo));
  assert.deepEqual((await c.call('bypass_bind_tests',{id:check.id,target:'demo',file:'binding.json'})).bound,[check.id]);
  await c.call('bypass_set_config',{key:'autoSave',value:'true'});
  await c.call('bypass_retest',{id:finding});
  const exported=await c.call('bypass_export_tests',{id:check.id});
  const independent=await execFile(process.execPath,['--test',...exported.files],{timeout:15000,env:{NODE_TEST_CONTEXT:undefined}});assert.equal(independent.code,0,independent.stdout);
  assert.equal((await c.call('bypass_ci',{target:'demo'})).notPublished,true);
  const report=await c.call('bypass_report',{run:scan.id,format:'md',out:'reports/review.md'});assert.ok(fs.readFileSync(report.path,'utf8').includes(scan.id));
  await c.call('bypass_demo_control',{action:'regress'});
  const failed=await c.wait((await c.call('bypass_run_tests',{id:check.id})).runId);assert.equal(failed.exitCode,1);assert.equal(failed.result.modelCalls,0);
  const dashboard=await c.call('bypass_dashboard');assert.equal(dashboard.checks.failed,1);assert.equal(dashboard.latestRun.terminal,true);
  await c.call('bypass_add_monitor',{name:'demo-watch',target:'demo',every:'1h'});
  const tick=await c.call('bypass_monitor_worker',{action:'once'});assert.equal(tick.runs.length,1);
  assert.equal((await c.call('bypass_run_monitor',{name:'demo-watch'})).exitCode,1);
  await c.call('bypass_pause_monitor',{name:'demo-watch'});await c.call('bypass_resume_monitor',{name:'demo-watch'});
  assert.equal((await c.call('bypass_monitor_worker',{action:'start'})).worker.status,'running');
  assert.equal((await c.call('bypass_dashboard')).monitoring.running,true);
  await c.call('bypass_monitor_worker',{action:'stop'});
  for(let i=0;i<30;i++){if((await c.call('bypass_monitors')).worker.status==='stopped')break;await delay(100);}
  assert.equal((await c.call('bypass_monitors')).worker.status,'stopped');
  await c.call('bypass_remove_monitor',{name:'demo-watch'});
  await c.call('bypass_demo_control',{action:'fix'});await c.call('bypass_retest',{id:finding});
  assert.ok((await c.call('bypass_runs')).runs.length>=4);
  assert.ok((await c.call('bypass_context')).latestMonitor);
  const stopped=await c.call('bypass_demo_control',{action:'stop'});fixture=null;assert.equal(stopped.selectedRepository,app);
  assert.equal((await c.call('bypass_dashboard')).selectedRepository,app);
  assert.equal(fs.readFileSync(path.join(app,'.bypass/state.json'),'utf8'),original);
  assert.equal(await c.close(),0);
});

test('plugin management, config import, scope file, output containment and confirmation guards use the selected app',async t=>{
  const host=temp(),app=temp(),outside=temp(),c=await mcpClient(host,{stateDir:temp()});t.after(()=>c.child.kill());
  const config=path.join(host,'setup.json');fs.writeFileSync(config,JSON.stringify({name:'Configured application',model:{name:'local',provider:'custom','secret-env':'BYPASS_UNIT_API_KEY',stream:false,'base-url':'http://127.0.0.1:9999',model:'fixture'}}));
  fs.writeFileSync(path.join(app,'app.mjs'),'export const app = true;');
  await c.call('bypass_connect_repository',{repository:app,confirmed:true,config});
  assert.equal((await c.call('bypass_repository')).repository.path,app);
  assert.equal((await c.call('bypass_config')).project.name,'Configured application');
  await c.call('bypass_add_model',{name:'private',provider:'custom','secret-env':'BYPASS_UNIT_API_KEY',stream:false,'base-url':'https://model.example.com',model:'private','allow-private':true});
  assert.equal(read(app).models.length,0); // Host model configuration is a no-op, including imported config.
  await c.call('bypass_add_target',{name:'local',url:'http://127.0.0.1:45678',environment:'local'});
  await c.call('bypass_verify_target',{name:'local',method:'local'});
  fs.writeFileSync(path.join(app,'scope.json'),JSON.stringify({paths:['/api'],maxRequestsPerSecond:1}));
  assert.equal((await c.raw('bypass_authorize_target',{name:'local','scope-file':'scope.json',accept:false})).result.isError,true);
  await c.call('bypass_authorize_target',{name:'local','scope-file':'scope.json',accept:true});
  assert.equal((await c.call('bypass_target',{name:'local'})).target.authorization.maxRequestsPerSecond,1);
  await c.call('bypass_add_identity',{name:'test',target:'local',type:'bearer','secret-env':'BYPASS_FIXTURE_ONLY'});
  await c.call('bypass_remove_identity',{name:'test'});assert.equal(read(app).identities.length,0);
  fs.symlinkSync(outside,path.join(app,'escape'),'dir');
  assert.equal((await c.raw('bypass_report',{out:'escape/report.json'})).result.isError,true);assert.deepEqual(fs.readdirSync(outside),[]);
  await c.call('bypass_remove_target',{name:'local'});assert.equal(read(app).targets.length,0);
  assert.equal((await c.raw('bypass_demo_control',{action:'fix'})).result.isError,true);
  assert.equal((await c.raw('bypass_demo_start',{kind:'preview',dir:app})).result.isError,true);
  assert.equal((await c.raw('bypass_demo_start',{port:12})).error.code,-32602);
  await c.call('bypass_auth_logout');assert.equal((await c.call('bypass_auth_status')).ai.mode,'muse-host');
  assert.equal(await c.close(),0);
});

test('real plugin fixture starts, edits, and stops portably without invoking a model during setup',async t=>{
  const c=await mcpClient(temp(),{stateDir:temp()});t.after(()=>c.child.kill());let running=false,root;
  t.after(async()=>{if(running)await execute('poc stop',[],{project:root}).catch(()=>{});await c.close().catch(()=>{});});
  const demo=await c.call('bypass_demo_start',{kind:'real'});running=true;root=demo.root;
  assert.equal(read(demo.root).settings.analysisEngine,'docker');assert.equal(read(demo.root).runs.length,0);
  assert.equal((await c.call('bypass_test_probe',{name:'invoice'})).validation.status,'ready');
  const url=demo.url+'/api/invoices/inv-101',headers={Authorization:'Bearer poc-outsider-token'};
  assert.equal((await fetch(url,{headers})).status,200);
  await c.call('bypass_demo_control',{action:'fix'});assert.equal((await fetch(url,{headers})).status,403);
  await c.call('bypass_demo_control',{action:'regress'});assert.equal((await fetch(url,{headers})).status,200);
  await c.call('bypass_demo_control',{action:'stop'});running=false;
  await assert.rejects(fetch(url,{headers}));assert.equal((await c.call('bypass_dashboard')).selectedRepository,null);
  assert.equal(await c.close(),0);
});
