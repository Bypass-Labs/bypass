import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import http from 'node:http';
import dns from 'node:dns/promises';
import { temp, cli } from './helpers.mjs';
import { execute } from '../src/service.mjs';
import { read } from '../src/store.mjs';
import { verifyOwnership, makeChallenge, targetURL, publicIP, pathAllowed, safeRequest } from '../src/network.mjs';
import { parse, help } from '../src/catalog.mjs';

test('repository onboarding is idempotent, never executes source, and holds live scans behind scope',async()=>{
  const root=temp();fs.writeFileSync(path.join(root,'app.mjs'),`throw new Error('Repository code must never run during init');`);
  const first=await cli(root,'init',root);assert.equal(first.code,0);assert.equal(first.data.resumed,false);
  const second=await cli(root,'init',root);assert.equal(second.data.resumed,true);assert.equal(first.data.readiness.project.id,second.data.readiness.project.id);
  assert.equal((await cli(root,'model','add','local','--provider','custom','--base-url','http://127.0.0.1:1234/v1','--model','muse-local')).code,0);
  assert.equal((await cli(root,'target','add','app','--url','http://127.0.0.1:4521','--environment','local')).code,0);
  const blocked=await cli(root,'scan');assert.equal(blocked.code,3);assert.match(blocked.data.run.result.message,/ownership/i);
  assert.equal((await cli(root,'target','verify','app','--method','local')).code,0);
  assert.equal((await cli(root,'scan')).code,3);
  assert.equal((await cli(root,'target','authorize','app','--accept','--paths','/api')).code,0);
  const live=await cli(root,'scan','--mode','live');
  assert.equal(live.data.run.result.inventory.sourceFileCount,0);
  assert.equal(live.data.run.result.plan.whiteBox.status,'skipped');
  assert.equal(live.data.run.result.plan.blackBox.status,'simulated');
  const scan=await cli(root,'scan');assert.equal(scan.code,3);assert.equal(scan.data.run.result.simulation,true);assert.equal(scan.data.run.result.modelCalls,0);
  const finding=read(root).findings[0];assert.equal(finding.status,'simulated_unproven');
  const verify=await cli(root,'verify',finding.id);assert.equal(verify.code,3);assert.equal(verify.data.verification.requests,0);
  assert.equal((await cli(root,'target','revoke','app')).code,0);assert.equal((await cli(root,'scan','--plan')).code,3);
  assert.equal((await cli(root,'scan','--mode','code')).code,3);
});

test('repository setup reports exact file changes, preserves existing exclusions, and respects a whole-directory ignore',async()=>{
  const root=temp();fs.writeFileSync(path.join(root,'.gitignore'),'dist/\n.bypass/\n');fs.writeFileSync(path.join(root,'.bypassignore'),'private-fixture/\n');
  const first=await execute('init',[root]);
  assert.deepEqual(first.fileChanges,[{path:'.bypass/',action:'created',purpose:'private project state and evidence',commit:false}]);
  assert.equal(fs.readFileSync(path.join(root,'.gitignore'),'utf8'),'dist/\n.bypass/\n');
  assert.equal(fs.readFileSync(path.join(root,'.bypassignore'),'utf8'),'private-fixture/\n');
  const second=await execute('init',[root]);assert.deepEqual(second.fileChanges,[]);
});

test('repository file plan is a real dry run and tracked setup files can be skipped or customized',async()=>{
  const skipped=temp();fs.writeFileSync(path.join(skipped,'.gitignore'),'dist/\n');
  const plan=await execute('init',[skipped],{plan:true});
  assert.equal(plan.plan,true);assert.equal(fs.existsSync(path.join(skipped,'.bypass')),false);
  assert.equal(fs.readFileSync(path.join(skipped,'.gitignore'),'utf8'),'dist/\n');
  assert.deepEqual(plan.fileChanges.map(item=>item.path),['.bypass/','.gitignore','.bypassignore']);
  assert.ok(plan.fileChanges.every(item=>item.planned));
  assert.deepEqual(plan.fileChanges.find(item=>item.path==='.gitignore').details.add,['.bypass/state.json','.bypass/.lock/','.bypass/runs/','.bypass/drafts/','.bypass/discovery/','.bypass/demo-state.json','.bypass/worker.json','.bypass/*.log']);
  const connected=await execute('init',[skipped],{'tracked-files':'skip'});
  assert.deepEqual(connected.fileChanges.map(item=>item.path),['.bypass/']);
  assert.equal(fs.readFileSync(path.join(skipped,'.gitignore'),'utf8'),'dist/\n');
  assert.equal(fs.existsSync(path.join(skipped,'.bypassignore')),false);
  assert.deepEqual(connected.filePlan.filter(item=>item.commit).map(item=>item.action),['skipped','skipped']);

  const customized=temp();
  await execute('init',[customized],{bypassIgnoreContent:'vendor/\nprivate-fixtures/\n'});
  assert.equal(fs.readFileSync(path.join(customized,'.bypassignore'),'utf8'),'vendor/\nprivate-fixtures/\n');
});

test('read-only tracked files fail before project state and can be explicitly skipped',async()=>{
  const root=temp(),ignore=path.join(root,'.gitignore');fs.writeFileSync(ignore,'dist/\n');fs.chmodSync(ignore,0o444);
  try{
    const plan=await execute('init',[root],{plan:true});assert.equal(plan.plan,true);
    await assert.rejects(execute('init',[root]),error=>error.details.reason==='repository_read_only');
    assert.equal(fs.existsSync(path.join(root,'.bypass')),false);
    const connected=await execute('init',[root],{'tracked-files':'skip'});assert.deepEqual(connected.fileChanges.map(item=>item.path),['.bypass/']);
    assert.equal(fs.readFileSync(ignore,'utf8'),'dist/\n');
  }finally{fs.chmodSync(ignore,0o644);}
});

test('strict parsing, missing fields, secrets, and scopes remain explicit',async()=>{
  assert.throws(()=>parse(['scan','--mode']),/requires a value/);
  assert.throws(()=>parse(['scan','--bogus']),/requires a value/);
  assert.throws(()=>parse(['test','run','a','b']),/Usage/);
  assert.throws(()=>targetURL('http://example.com','production'),/HTTPS/);
  assert.throws(()=>targetURL('https://user:password@example.com','staging'),/credentials/);
  assert.throws(()=>targetURL('https://example.com/api','staging'),/origin/);
  assert.equal(pathAllowed('/api/invoices',['/api']),true);assert.equal(pathAllowed('/api2',['/api']),false);
  for(const p of ['/api/%2e%2e/admin','/api/%2fadmin','/api/../admin','/api/\\admin'])assert.equal(pathAllowed(p,['/api']),false);
  for(const address of ['127.0.0.1','10.0.0.1','169.254.169.254','100.64.0.1','192.168.1.1','::1','::ffff:127.0.0.1','2001:db8::1'])assert.equal(publicIP(address),false,address);
  assert.equal(publicIP('8.8.8.8'),true);
  const root=temp();await execute('init',[root]);
  const missing=await cli(root,'identity','add','owner','--type','bearer');assert.equal(missing.code,2);assert.match(missing.data.error,/secret-env/);
  assert.equal((await cli(root,'auth','login','--device')).code,3);
  assert.equal((await cli(root,'test','run','--all')).code,3,'an empty suite is incomplete, never passing');
  assert.throws(()=>parse(['--unknown','value']),/Unknown global/);
});

test('standalone help describes host-owned authentication and rejects the removed install no-op',()=>{
  assert.match(help('auth login'),/API key in standalone mode or the official Muse login flow/);
  assert.doesNotMatch(help('integrate muse'),/--install/);
  assert.throws(()=>parse(['integrate','muse','--install']),/Unknown option --install/);
});

test('DNS ownership checks require the complete fresh project-bound challenge; production needs explicit acknowledgment',async t=>{
  const root=temp();await execute('init',[root]);
  await execute('target add',['prod'],{project:root,url:'https://app.example.com',environment:'production'});
  const target=read(root).targets[0];
  t.mock.method(dns,'resolveTxt',async()=>[['wrong-token']]);
  await assert.rejects(verifyOwnership(target,'dns'),/pending/);
  dns.resolveTxt.mock.mockImplementation(async()=>[[target.challenge.token.slice(0,20),target.challenge.token.slice(20)]]);
  await execute('target verify',['prod'],{project:root,method:'dns'});
  await assert.rejects(execute('target authorize',['prod'],{project:root,accept:true}),/Production/);
  await execute('target authorize',['prod'],{project:root,accept:true,production:true});
  await execute('target verify',['prod'],{project:root,renew:true});
  assert.equal(read(root).targets[0].authorization,null);
  assert.notEqual(read(root).targets[0].challenge.token,target.challenge.token);
  target.challenge.expiresAt=new Date(0).toISOString();await assert.rejects(verifyOwnership(target,'dns'),/expired/);
  assert.notEqual(makeChallenge({id:'different'},target).id,target.challenge.id);
});

test('model smoke uses a real compatible endpoint and sends only a synthetic prompt; redirects are not followed',async t=>{
  const requests=[];const server=http.createServer((req,res)=>{let body='';req.on('data',b=>body+=b);req.on('end',()=>{requests.push({url:req.url,body,authorization:req.headers.authorization});if(req.url==='/redirect'){res.writeHead(302,{Location:'/secret'});res.end();}else{res.writeHead(200,{'Content-Type':'application/json'});res.end(JSON.stringify({choices:[{finish_reason:'stop',message:{role:'assistant',content:'BYPASS_MODEL_OK'}}]}));}});});
  await new Promise(res=>server.listen(0,'127.0.0.1',res));t.after(()=>new Promise(res=>server.close(res)));
  const origin=`http://127.0.0.1:${server.address().port}`;const root=temp();await execute('init',[root]);
  process.env.BYPASS_TEST_API_KEY='unique-secret-for-test-only';t.after(()=>delete process.env.BYPASS_TEST_API_KEY);
  await execute('model add',['local'],{project:root,provider:'custom','secret-env':'BYPASS_UNIT_API_KEY',stream:false,'base-url':origin+'/v1',model:'fixture-model','secret-env':'BYPASS_TEST_API_KEY'});
  const check=await execute('model test',['local'],{project:root});assert.equal(check.check.status,'connected');assert.equal(requests[0].url,'/v1/chat/completions');
  assert.equal(JSON.parse(requests[0].body).messages[0].content,'Reply with exactly BYPASS_MODEL_OK.');
  assert.equal(requests[0].authorization,'Bearer unique-secret-for-test-only');
  assert.equal(fs.readFileSync(path.join(root,'.bypass/state.json'),'utf8').includes(process.env.BYPASS_TEST_API_KEY),false);
  const redirected=await safeRequest(origin+'/redirect',{allowLocal:true});assert.equal(redirected.status,302);assert.equal(requests.length,2);
});
