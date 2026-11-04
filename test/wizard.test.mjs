import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import dns from 'node:dns/promises';
import { onboard } from '../src/onboarding.mjs';
import { execute } from '../src/service.mjs';
import { read, change } from '../src/store.mjs';
import { temp, cli, metaModelFixture } from './helpers.mjs';

async function wizard(t,root, answers, options={}){
  const meta=await metaModelFixture(t,options.metaFixture);
  if(options.flow!=='demo')fs.writeFileSync(path.join(root,'app.mjs'),'export const app = true;');
  const output=[],prompts=[];
  const result=await onboard({flow:'quickstart',project:root,mode:'combined',...options},[],{
    metaBaseUrl:meta.baseUrl,
    filePlanChoice:async items=>items[0],
    write:value=>output.push(value),
    ask:async(label,fallback)=>{
      prompts.push(label);
      assert.ok(answers.length,`Unexpected prompt: ${label}`);
      return answers.shift()||fallback||'';
    }
  });
  assert.equal(answers.length,0,`Unused answers after: ${prompts.join(', ')}`);
  return {result,output:output.join('\n'),prompts};
}

test('wizard defers failed DNS and resumes the same challenge through explicit scope without duplicate setup',async t=>{
  const root=temp();
  await execute('init',[root]);
  await execute('config set',['ownershipVerification','dns'],{project:root});
  t.mock.method(dns,'resolveTxt',async()=>[['wrong challenge']]);
  const first=await wizard(t,root,['1','','https://staging.example.com','2','1','n']);
  const saved=read(root),challenge=saved.targets[0].challenge;
  assert.equal(saved.targets[0].ownership.status,'pending');
  assert.equal(saved.targets[0].authorization,null);
  assert.match(first.output,/DNS pending/);
  assert.match(first.output,/verification pending/);
  assert.equal(first.result.openDashboard,false);
  assert.equal(saved.models[0].lastTest.status,'connected');
  dns.resolveTxt.mock.mockImplementation(async record=>{assert.equal(record,challenge.record);return [[challenge.token]];});
  const second=await wizard(t,root,['1','','2','GET,HEAD,POST,PROPFIND','yes','n']);
  const resumed=read(root);
  assert.equal(resumed.project.id,saved.project.id);
  assert.equal(resumed.targets.length,1);assert.equal(resumed.models.length,1);
  assert.equal(resumed.targets[0].challenge.token,challenge.token);
  assert.equal(resumed.targets[0].ownership.status,'verified');
  assert.deepEqual(resumed.targets[0].authorization.paths,['/']);
  assert.deepEqual(resumed.targets[0].authorization.methods,['GET','HEAD','POST','PROPFIND']);
  assert.match(second.output,/App ownership verified/);
  assert.match(second.output,/Testing scope authorized/);
  assert.doesNotMatch(second.output,/What address do you open/,'saved app must not be asked for again');
});

test('wizard highlights the recommended complete scope and defaults the single approval to yes',async t=>{
  const root=temp();
  const result=await wizard(t,root,['1','','http://127.0.0.1:4317','yes','','','','n']);
  const target=read(root).targets[0];
  assert.equal(target.ownership.status,'verified');
  assert.deepEqual(target.authorization.paths,['/']);
  assert.deepEqual(target.authorization.methods,['GET','HEAD','POST','PUT','PATCH','DELETE','OPTIONS']);
  assert.match(result.output,/Testing scope authorized/);
  assert.equal(result.result.readiness.ready.liveTesting,true);
});

test('wizard production scope uses one explicit confirmation with yes recommended',async t=>{
  const root=temp();await execute('init',[root]);
  await change(root,state=>{delete state.settings.ownershipVerification;});
  await execute('model add',['muse'],{project:root,provider:'meta','secret-env':'BYPASS_UNIT_API_KEY',model:'test-model',stream:false});
  await execute('target add',['production'],{project:root,url:'https://app.example.com',environment:'production'});
  t.mock.method(dns,'resolveTxt',async()=>[[read(root).targets[0].challenge.token]]);
  await change(root,state=>{state.models[0].lastTest={status:'connected'};state.models[0].lastAttempt={status:'connected'};});
  const denied=await wizard(t,root,['1','','no','n']);
  assert.equal(read(root).targets[0].authorization,null);
  assert.equal(denied.prompts.filter(prompt=>/Authorize these checks/.test(prompt)).length,1);
  assert.equal(denied.prompts.some(prompt=>/Do you authorize|Confirm testing/.test(prompt)),false);
  const result=await wizard(t,root,['','','yes','n']);
  assert.equal(read(root).targets[0].authorization.productionAcknowledged,true);
  assert.match(result.output,/No DNS record required/);
  assert.doesNotMatch(result.output,/Add this DNS record/);
});

test('failed mandatory Muse preflight stays in the same step and never creates project state',async t=>{
  const root=temp(),meta=await metaModelFixture(t,{status:503,error:{code:'service_unavailable'}});fs.writeFileSync(path.join(root,'app.mjs'),'export const app = true;');
  const answers=['1','','2'];
  await assert.rejects(onboard({flow:'quickstart',project:root,mode:'code'},[],{metaBaseUrl:meta.baseUrl,write:()=>{},ask:async(_label,fallback)=>answers.shift()||fallback||''}),error=>error.code===130);
  assert.equal(fs.existsSync(path.join(root,'.bypass/state.json')),false);
  assert.equal(meta.calls.filter(call=>call.path==='/v1/responses').length,1);
});

test('wizard can configure account references and does not store or request token values',async t=>{
  const root=temp();
  const result=await wizard(t,root,['1','','','http://127.0.0.1:4317','','yes','','','yes','yes','1','BYPASS_OWNER_TOKEN','','1','BYPASS_OUTSIDER_TOKEN','','n','n'],{flow:'advanced'});
  const identities=read(root).identities;
  assert.equal(identities.length,2);
  assert.deepEqual(identities.map(i=>i.secretEnv),['BYPASS_OWNER_TOKEN','BYPASS_OUTSIDER_TOKEN']);
  assert.ok(identities.every(i=>!i.fixtureValue&&!i.lastTest));
  assert.match(result.output,/Credential not tested/);
});

test('demo onboarding refuses to replace existing project or unrelated files',async t=>{
  const connected=temp();await execute('init',[connected]);
  const previous=fs.readFileSync(path.join(connected,'.bypass/state.json'),'utf8');
  await assert.rejects(wizard(t,connected,[],{flow:'demo',dir:connected}),/empty directory/);
  assert.equal(fs.readFileSync(path.join(connected,'.bypass/state.json'),'utf8'),previous);
  const occupied=temp();fs.writeFileSync(path.join(occupied,'README.md'),'keep this content');
  await assert.rejects(wizard(t,occupied,[],{flow:'demo',dir:occupied}),/empty directory/);
  assert.equal(fs.readFileSync(path.join(occupied,'README.md'),'utf8'),'keep this content');
});

test('wizard accepts a bare domain directly after a typo and defers DNS on Enter',async t=>{
  t.mock.method(dns,'resolveTxt',async()=>assert.fail('Default continuation must not request DNS'));
  const root=temp();
  await execute('init',[root]);
  await execute('config set',['ownershipVerification','dns'],{project:root});
  const result=await wizard(t,root,['1','','bad input','job-radar.app','1','','n'],{flow:undefined});
  assert.equal(read(root).targets[0].url,'https://job-radar.app');
  assert.equal(read(root).targets[0].environment,'production');
  assert.equal(read(root).targets[0].ownership.status,'pending');
  assert.equal(result.prompts.filter(p=>p.startsWith('App URL')).length,2);
  assert.equal(result.prompts.some(p=>p.startsWith('Try again')),false);
  assert.match(result.output,/Source review can continue/);
});

test('wizard accepts code-only selection and never asks for environment or ownership',async t=>{
  const root=temp();
  const result=await wizard(t,root,['1','','n'],{mode:'code'});
  assert.equal(read(root).targets.length,0);
  assert.equal(result.prompts.some(p=>/real users|Paths to test|control|confirm this production/i.test(p)),false);
  assert.ok(result.output.indexOf('Repository file plan')<result.output.indexOf('Repository setup changes'));
  assert.match(result.output,/\.bypassignore.*review and commit/);
  assert.match(result.output,/code-only review available/);
});

test('wizard invalid flow and noninteractive invocation fail before writing setup',async t=>{
  const root=temp();
  await assert.rejects(wizard(t,root,[],{flow:'typo'}),/--flow must/);
  const called=await cli(root,'onboard');
  assert.equal(called.code,2);
  assert.match(called.data.error,/interactive terminal/);
  assert.equal(fs.existsSync(path.join(root,'.bypass/state.json')),false);
});

test('repository setup redirects an accidental tooling checkout to the chosen application',async t=>{
  const tooling=temp(),app=temp();fs.writeFileSync(path.join(tooling,'package.json'),JSON.stringify({name:'@bypass-labs/bypass'}));
  const result=await wizard(t,app,['1','','n',app,'n'],{repo:tooling,mode:'code'});
  assert.equal(result.result.root,app);
  assert.equal(fs.existsSync(path.join(tooling,'.bypass/state.json')),false);
  assert.match(result.output,/Bypass’s own tooling source/);
  assert.match(result.output,/White-box \/ code: ready/);
  assert.match(result.output,/Black-box \/ live app: deferred/);
});
