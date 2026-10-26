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
  const first=await wizard(root,['1','n','https://staging.example.com','1','1','2','n','n']);
  const saved=read(root),challenge=saved.targets[0].challenge;
  assert.equal(saved.targets[0].ownership.status,'pending');
  assert.equal(saved.targets[0].authorization,null);
  assert.match(first.output,/Not verified yet/);
  assert.match(first.output,/verification pending/);
  assert.equal(first.result.openDashboard,false);
  assert.equal(saved.models[0].lastTest,undefined);
  dns.resolveTxt.mock.mockImplementation(async record=>{assert.equal(record,challenge.record);return [[challenge.token]];});
  const second=await wizard(root,['n','1','','yes','n','n','n']);
  const resumed=read(root);
  assert.equal(resumed.project.id,saved.project.id);
  assert.equal(resumed.targets.length,1);assert.equal(resumed.models.length,1);
  assert.equal(resumed.targets[0].challenge.token,challenge.token);
  assert.equal(resumed.targets[0].ownership.status,'verified');
  assert.deepEqual(resumed.targets[0].authorization.paths,['/api']);
  assert.match(second.output,/verified and authorized/);
});

test('wizard never turns local ownership acknowledgment into testing permission by default',async()=>{
  const root=temp();
  const result=await wizard(root,['1','n','http://127.0.0.1:4317','yes','','','n','n']);
  const target=read(root).targets[0];
  assert.equal(target.ownership.status,'verified');
  assert.equal(target.authorization,null);
  assert.match(result.output,/scope required/);
  assert.equal(result.result.readiness.ready.liveTesting,false);
});

test('wizard production scope requires the separate production confirmation',async t=>{
  const root=temp();await execute('init',[root]);
  await execute('model add',['muse'],{project:root,provider:'muse-code'});
  await execute('target add',['production'],{project:root,url:'https://app.example.com',environment:'production'});
  t.mock.method(dns,'resolveTxt',async()=>[[read(root).targets[0].challenge.token]]);
  await wizard(root,['n','1','','yes','no','n','n']);
  assert.equal(read(root).targets[0].authorization,null);
  await wizard(root,['n','','yes','production','n','n','n']);
  assert.equal(read(root).targets[0].authorization.productionAcknowledged,true);
});

test('failed optional model smoke is recoverable and never shown as connected',async t=>{
  let requests=0;
  const server=http.createServer((req,res)=>{requests++;req.resume();res.writeHead(503);res.end('unavailable');});
  await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve));
  t.after(()=>new Promise(resolve=>server.close(resolve)));
  const root=temp();
  const result=await wizard(root,['2',`http://127.0.0.1:${server.address().port}/v1`,'test-model','','yes','n','','n','n']);
  assert.equal(requests,1);
  assert.equal(read(root).models[0].lastTest,undefined);
  assert.match(result.output,/HTTP 503/);
  assert.match(result.output,/not tested/);
  assert.equal(result.result.readiness.ready.target,false);
});

test('wizard can configure account references and does not store or request token values',async()=>{
  const root=temp();
  const result=await wizard(root,['1','n','http://127.0.0.1:4317','yes','','yes','yes','BYPASS_OWNER_TOKEN','','BYPASS_OUTSIDER_TOKEN','','n','n']);
  const identities=read(root).identities;
  assert.equal(identities.length,2);
  assert.deepEqual(identities.map(i=>i.secretEnv),['BYPASS_OWNER_TOKEN','BYPASS_OUTSIDER_TOKEN']);
  assert.ok(identities.every(i=>!i.fixtureValue&&!i.lastTest));
  assert.match(result.output,/Credential not tested/);
});

test('demo onboarding creates a real runnable fixture without replacing an existing project',async t=>{
  const connected=temp();await execute('init',[connected]);
  const previous=fs.readFileSync(path.join(connected,'.bypass/state.json'),'utf8');
  await assert.rejects(wizard(connected,[],{flow:'demo',dir:connected}),/connected project, not a demo/);
  assert.equal(fs.readFileSync(path.join(connected,'.bypass/state.json'),'utf8'),previous);
  const occupied=temp();fs.writeFileSync(path.join(occupied,'README.md'),'keep this content');
  await assert.rejects(wizard(occupied,[],{flow:'demo',dir:occupied}),/empty demo directory/);
  assert.equal(fs.readFileSync(path.join(occupied,'README.md'),'utf8'),'keep this content');
  const root=temp();
  t.after(async()=>{try{await execute('demo stop',[],{project:root});}catch{}});
  const result=await wizard(root,['n'],{flow:'demo',dir:root});
  assert.equal(result.result.root,root);
  assert.ok(read(root).demo);
  assert.equal(result.result.readiness.ready.liveTesting,true);
  assert.equal(read(root).models[0].lastTest,undefined);
  assert.match(result.output,/Open that address in your browser/);
});

test('wizard invalid flow and noninteractive invocation fail before writing setup',async()=>{
  const root=temp();
  await assert.rejects(wizard(root,[],{flow:'typo'}),/--flow must/);
  const called=await cli(root,'onboard');
  assert.equal(called.code,2);
  assert.match(called.data.error,/interactive terminal/);
  assert.equal(fs.existsSync(path.join(root,'.bypass/state.json')),false);
});
