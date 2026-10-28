import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import dns from 'node:dns/promises';
import http from 'node:http';
import { onboard } from '../src/onboarding.mjs';
import { execute } from '../src/service.mjs';
import { read } from '../src/store.mjs';
import { temp, cli } from './helpers.mjs';

async function wizard(root, answers, options={}){
  const output=[],prompts=[];
  const result=await onboard({flow:'quickstart',project:root,...options},[],{
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
  t.mock.method(dns,'resolveTxt',async()=>[['wrong challenge']]);
  const first=await wizard(root,['1','','','','n','https://staging.example.com','2','1','n']);
  const saved=read(root),challenge=saved.targets[0].challenge;
  assert.equal(saved.targets[0].ownership.status,'pending');
  assert.equal(saved.targets[0].authorization,null);
  assert.match(first.output,/DNS pending/);
  assert.match(first.output,/verification pending/);
  assert.equal(first.result.openDashboard,false);
  assert.equal(saved.models[0].lastTest,undefined);
  assert.equal(saved.settings.analysisEngine,'docker');
  dns.resolveTxt.mock.mockImplementation(async record=>{assert.equal(record,challenge.record);return [[challenge.token]];});
  const second=await wizard(root,['n','1','','yes','n']);
  const resumed=read(root);
  assert.equal(resumed.project.id,saved.project.id);
  assert.equal(resumed.targets.length,1);assert.equal(resumed.models.length,1);
  assert.equal(resumed.targets[0].challenge.token,challenge.token);
  assert.equal(resumed.targets[0].ownership.status,'verified');
  assert.deepEqual(resumed.targets[0].authorization.paths,['/api']);
  assert.match(second.output,/verified and authorized/);
  assert.doesNotMatch(second.output,/What address do you open/,'saved app must not be asked for again');
});

test('wizard never turns local ownership acknowledgment into testing permission by default',async()=>{
  const root=temp();
  const result=await wizard(root,['1','','','','n','http://127.0.0.1:4317','yes','','','n']);
  const target=read(root).targets[0];
  assert.equal(target.ownership.status,'verified');
  assert.equal(target.authorization,null);
  assert.match(result.output,/scope required/);
  assert.equal(result.result.readiness.ready.liveTesting,false);
});

test('wizard production scope requires the separate production confirmation',async t=>{
  const root=temp();await execute('init',[root]);
  await execute('model add',['muse'],{project:root,provider:'meta','secret-env':'BYPASS_UNIT_API_KEY',model:'test-model',stream:false});
  await execute('target add',['production'],{project:root,url:'https://app.example.com',environment:'production'});
  t.mock.method(dns,'resolveTxt',async()=>[[read(root).targets[0].challenge.token]]);
  await wizard(root,['n','1','','yes','no','n']);
  assert.equal(read(root).targets[0].authorization,null);
  await wizard(root,['n','','yes','production','n']);
  assert.equal(read(root).targets[0].authorization.productionAcknowledged,true);
});

test('failed optional model smoke is recoverable and never shown as connected',async t=>{
  let requests=0;
  const server=http.createServer((req,res)=>{requests++;req.resume();res.writeHead(503);res.end('unavailable');});
  await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve));
  t.after(()=>new Promise(resolve=>server.close(resolve)));
  const root=temp();
  const result=await wizard(root,['6','BYPASS_UNIT_API_KEY','test-model',`http://127.0.0.1:${server.address().port}/v1`,'chat','yes','1','','n']);
  assert.equal(requests,1);
  assert.equal(read(root).models[0].lastTest,undefined);
  assert.match(result.output,/HTTP 503/);
  assert.equal(read(root).models[0].lastAttempt.status,'failed');
  assert.match(result.output,/Connection not verified/);
  assert.match(result.output,/API request/);
  assert.equal(result.result.readiness.ready.target,false);
});

test('wizard can configure account references and does not store or request token values',async()=>{
  const root=temp();
  const result=await wizard(root,['1','','','','','n','http://127.0.0.1:4317','','yes','','yes','yes','1','BYPASS_OWNER_TOKEN','','1','BYPASS_OUTSIDER_TOKEN','','n','n'],{flow:'advanced'});
  const identities=read(root).identities;
  assert.equal(identities.length,2);
  assert.deepEqual(identities.map(i=>i.secretEnv),['BYPASS_OWNER_TOKEN','BYPASS_OUTSIDER_TOKEN']);
  assert.ok(identities.every(i=>!i.fixtureValue&&!i.lastTest));
  assert.match(result.output,/Credential not tested/);
});

test('demo onboarding refuses to replace existing project or unrelated files',async()=>{
  const connected=temp();await execute('init',[connected]);
  const previous=fs.readFileSync(path.join(connected,'.bypass/state.json'),'utf8');
  await assert.rejects(wizard(connected,[],{flow:'demo',dir:connected}),/empty directory/);
  assert.equal(fs.readFileSync(path.join(connected,'.bypass/state.json'),'utf8'),previous);
  const occupied=temp();fs.writeFileSync(path.join(occupied,'README.md'),'keep this content');
  await assert.rejects(wizard(occupied,[],{flow:'demo',dir:occupied}),/empty directory/);
  assert.equal(fs.readFileSync(path.join(occupied,'README.md'),'utf8'),'keep this content');
});

test('wizard accepts a bare domain directly after a typo and defers DNS on Enter',async t=>{
  t.mock.method(dns,'resolveTxt',async()=>assert.fail('Default continuation must not request DNS'));
  const root=temp();
  const result=await wizard(root,['1','','','','n','bad input','job-radar.app','1','','n'],{flow:undefined});
  assert.equal(read(root).targets[0].url,'https://job-radar.app');
  assert.equal(read(root).targets[0].environment,'production');
  assert.equal(read(root).targets[0].ownership.status,'pending');
  assert.equal(result.prompts.filter(p=>p.startsWith('App URL')).length,2);
  assert.equal(result.prompts.some(p=>p.startsWith('Try again')),false);
  assert.match(result.output,/Source review can continue/);
});

test('wizard accepts code only as an answer and never asks for environment or ownership',async()=>{
  const root=temp();
  const result=await wizard(root,['1','','','','n','code only','n']);
  assert.equal(read(root).targets.length,0);
  assert.equal(result.prompts.some(p=>/real users|Paths to test|control|confirm this production/i.test(p)),false);
  assert.match(result.output,/code-only review available/);
});

test('wizard invalid flow and noninteractive invocation fail before writing setup',async()=>{
  const root=temp();
  await assert.rejects(wizard(root,[],{flow:'typo'}),/--flow must/);
  const called=await cli(root,'onboard');
  assert.equal(called.code,2);
  assert.match(called.data.error,/interactive terminal/);
  assert.equal(fs.existsSync(path.join(root,'.bypass/state.json')),false);
});

test('repository setup redirects an accidental tooling checkout to the chosen application',async()=>{
  const tooling=temp(),app=temp();fs.writeFileSync(path.join(tooling,'package.json'),JSON.stringify({name:'@bypass-labs/cli-skeleton'}));
  const result=await wizard(app,['n',app,'1','BYPASS_UNIT_API_KEY','','','n','','n'],{repo:tooling});
  assert.equal(result.result.root,app);
  assert.equal(fs.existsSync(path.join(tooling,'.bypass/state.json')),false);
  assert.match(result.output,/Bypass’s own tooling source/);
  assert.match(result.output,/White-box \/ code: ready/);
  assert.match(result.output,/Black-box \/ live app: deferred/);
});
