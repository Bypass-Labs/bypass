import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { temp } from './helpers.mjs';
import { execute } from '../src/service.mjs';
import { read } from '../src/store.mjs';
import { appConnection } from '../src/app-connection.mjs';
import { pluginOnboarding } from '../src/plugin-onboarding.mjs';
import { mcpClient } from './mcp-client.mjs';

test('app connection asks for one missing input; never infers a remote environment or authorizes requests',()=>{
  const missing=appConnection();
  assert.equal(missing.input.kind,'text');assert.equal(missing.input.field,'url');
  assert.equal(missing.input.choices,undefined);assert.equal(missing.arguments,undefined);
  for(const url of ['https://staging.example.com','https://production.example.com']){
    const remote=appConnection({url});assert.equal(remote.id,'environment');assert.equal(remote.url,url);
    assert.deepEqual(remote.input.choices.map(c=>c.id),['production','staging','preview','local']);
    assert.equal(remote.input.default,undefined);assert.equal(remote.automatic,undefined);
  }
  for(const url of ['localhost:4173','127.0.0.1:4173','http://[::1]:4173']){
    const local=appConnection({url});assert.equal(local.automatic,true);assert.equal(local.arguments.environment,'local');
    assert.equal(local.question,undefined);
  }
  assert.deepEqual(appConnection({mode:'combined',url:'job-radar.app',environment:'production'}).arguments,{name:'production',url:'https://job-radar.app',environment:'production'});
  assert.equal(appConnection({mode:'combined',url:'https://preview.example.com',environment:'preview'}).arguments.environment,'preview');
  for(const url of ['https://user:secret@example.com','https://example.com?token=private','http://example.com','https://example.com/api'])assert.throws(()=>appConnection({url}));
  assert.throws(()=>appConnection({mode:'combined',url:'https://example.com',environment:'local'}),/loopback/);
  assert.throws(()=>appConnection({mode:'combined',url:'localhost:4173',environment:'production'}),/non-loopback/);
});

test('onboarding ignores README ports, reuses saved apps, and keeps code-only review free of live setup',async()=>{
  const root=temp();fs.writeFileSync(path.join(root,'server.mjs'),'export const app = true;');await execute('init',[root]);
  fs.writeFileSync(path.join(root,'README.md'),'Local app: http://127.0.0.1:4173\n');
  const before=fs.readFileSync(path.join(root,'.bypass/state.json'),'utf8');
  let setup=await pluginOnboarding(root,root,{mode:'combined'});
  assert.equal(setup.nextAction.input.kind,'text');assert.doesNotMatch(JSON.stringify(setup),/4173/);
  setup=await pluginOnboarding(root,root,{mode:'combined',url:'job-radar.app'});
  assert.equal(setup.stage,'environment');assert.equal(setup.nextAction.url,'https://job-radar.app');
  setup=await pluginOnboarding(root,root,{mode:'combined',url:'job-radar.app',environment:'production'});
  assert.equal(setup.nextAction.tool,'bypass_add_target');assert.equal(setup.nextAction.question,undefined);
  assert.equal(fs.readFileSync(path.join(root,'.bypass/state.json'),'utf8'),before,'planning must not save targets, verify ownership, or run tests');
  const a=setup.nextAction.arguments;await execute('target add',[a.name],{project:root,...a});
  const challenge=read(root).targets[0].challenge.token;
  setup=await pluginOnboarding(root,root,{mode:'combined',url:'https://job-radar.app/',environment:'production'});
  assert.equal(setup.stage,'ownership');assert.equal(setup.nextAction.challenge.value,challenge);
  assert.equal(setup.ready.live,false);
  setup=await pluginOnboarding(root,root,{mode:'code'});
  assert.equal(setup.stage,'ready');assert.deepEqual(setup.nextAction.arguments,{mode:'code'});
  assert.equal(setup.nextAction.question,undefined);assert.equal(setup.steps.find(s=>s.id==='ownership').status,'deferred');
  assert.equal(setup.alternatives.length,0);assert.equal(read(root).targets[0].challenge.token,challenge);
  await execute('target add',['local'],{project:root,url:'http://127.0.0.1:4173',environment:'local'});
  await execute('target use',['local'],{project:root});
  setup=await pluginOnboarding(root,root,{mode:'combined',url:'job-radar.app'});
  assert.equal(setup.nextAction.tool,'bypass_use_target');assert.deepEqual(setup.nextAction.arguments,{name:'production'});
  assert.equal(setup.nextAction.question,undefined,'old local ownership question must not leak into the selected production app');
  assert.equal(read(root).activeTarget,'local','planning must not switch the active app');
  await assert.rejects(pluginOnboarding(root,root,{mode:'combined',url:'job-radar.app',environment:'staging'}),/saved as production/);
  setup=await pluginOnboarding(root,root,{mode:'combined',url:'https://another.example.com',environment:'production'});
  assert.equal(setup.nextAction.arguments.name,'production2');assert.equal(read(root).targets.length,2);
  setup=await pluginOnboarding(root,root,{mode:'code'});assert.equal(setup.nextAction.question,undefined);
});

test('packaged MCP follows URL -> audience -> DNS, then code review without a model or app request',async t=>{
  const root=temp();fs.writeFileSync(path.join(root,'server.mjs'),'export const requiresLogin = true;\n');
  fs.writeFileSync(path.join(root,'README.md'),'Development URL: http://127.0.0.1:4173\n');
  const c=await mcpClient(root,{stateDir:temp(),packaged:true});t.after(()=>c.child.kill());
  await c.call('bypass_connect_repository',{repository:root,confirmed:true});
  const empty=await c.call('bypass_onboarding');assert.equal(empty.nextAction.input.kind,'text');
  const remote=await c.call('bypass_onboarding',{mode:'combined',url:'app.example.com'});assert.equal(remote.stage,'environment');
  const choice=await c.call('bypass_onboarding',{mode:'combined',url:'app.example.com',environment:'production'});
  assert.equal(read(root).targets.length,0);assert.equal(choice.nextAction.question,undefined);
  const added=await c.call(choice.nextAction.tool,choice.nextAction.arguments);
  assert.equal(added.target.url,'https://app.example.com');assert.equal(added.target.authorization,null);
  const dns=await c.call(added.nextAction.tool,added.nextAction.arguments);assert.equal(dns.stage,'ownership');assert.equal(dns.nextAction.challenge.record,'_bypass-verification.app.example.com');
  const code=await c.call('bypass_onboarding',{mode:'code'});assert.equal(code.stage,'ready');
  const run=await c.call(code.nextAction.tool,code.nextAction.arguments);assert.equal(run.status,'awaiting_host');
  await c.call('bypass_review_step',{id:run.runId,action:'complete',candidates:[]});
  assert.equal(read(root).targets[0].ownership.status,'pending');assert.equal(read(root).models.length,0);
  const local=await c.call('bypass_onboarding',{mode:'combined',url:'localhost:4173'});
  const localAdded=await c.call(local.nextAction.tool,local.nextAction.arguments);
  assert.equal(localAdded.nextAction.tool,'bypass_use_target');assert.equal(read(root).activeTarget,'production');
  await c.call(localAdded.nextAction.tool,localAdded.nextAction.arguments);
  const localSetup=await c.call('bypass_onboarding');assert.equal(localSetup.nextAction.challenge.method,'local');
  assert.equal(localSetup.steps.find(s=>s.id==='app').url,'http://localhost:4173');
  assert.equal(await c.close(),0);
});
