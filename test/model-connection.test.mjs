import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import http from 'node:http';
import dns from 'node:dns/promises';
import { execute, readiness } from '../src/service.mjs';
import { read } from '../src/store.mjs';
import { Fault, delay } from '../src/util.mjs';
import { checkModelConnection } from '../src/model-check.mjs';
import { temp, cli } from './helpers.mjs';

async function fixture(t) {
  const root=temp(),bin=path.join(root,'bin');fs.mkdirSync(bin);
  await execute('init',[root]);await execute('model add',['muse'],{project:root,provider:'muse-code',model:'fixture-model'});
  const script=path.join(bin,'muse');
  fs.writeFileSync(script,`#!${process.execPath}
import fs from 'node:fs';
const args=process.argv.slice(2),scenario=process.env.BYPASS_MUSE_TEST_SCENARIO;
if(args[0]==='--version'){console.log('Muse Code fixture');process.exit(0);}
fs.writeFileSync(process.env.BYPASS_MUSE_TEST_ARGS,JSON.stringify(args));
const emit=payload=>console.log(JSON.stringify({payload}));
if(scenario==='hang'){
  process.on('SIGTERM',()=>{});setInterval(()=>{},1000);
  fs.writeFileSync(process.env.BYPASS_MUSE_TEST_PID,String(process.pid));
}else if(scenario==='auth'){
  console.error('401 invalid token NEVER_PRINT_THIS_PROVIDER_SECRET');process.exitCode=1;
}else if(scenario==='quota'){
  console.error('429 subscription allowance exhausted');process.exitCode=1;
}else if(scenario==='json-auth'){
  emit({kind:'task_lifecycle',event:{kind:'failed',error:{message:'401 unauthorized'}}});
  emit({kind:'run_usage',allowance:null});
  emit({kind:'run_terminal',terminal:'failed',reason:'Task failed'});
}else if(scenario==='prompt-only'){
  emit({kind:'turn_input_user',prompt:'Reply with exactly BYPASS_MODEL_OK'});
  emit({kind:'run_terminal',terminal:'failed',reason:'Provider unavailable'});
}else if(scenario==='echo'){
  emit({kind:'run_terminal',terminal:'completed',text:'echo: BYPASS_MODEL_OK'});
}else{
  emit({kind:'turn_input_user',prompt:'Reply with exactly BYPASS_MODEL_OK'});
  emit({kind:'run_terminal',terminal:'completed',text:'BYPASS_MODEL_OK'});
}
`,{mode:0o755});
  const environment={PATH:bin+path.delimiter+process.env.PATH,BYPASS_MUSE_TEST_SCENARIO:'success',BYPASS_MUSE_TEST_ARGS:path.join(root,'args.json'),BYPASS_MUSE_TEST_PID:path.join(root,'pid')};
  const previous=Object.fromEntries(Object.keys(environment).map(key=>[key,process.env[key]]));Object.assign(process.env,environment);
  t.after(()=>{for(const [key,value] of Object.entries(previous))if(value===undefined)delete process.env[key];else process.env[key]=value;fs.rmSync(root,{recursive:true,force:true});});
  return root;
}

test('Muse check verifies a completed reply, reports progress, and isolates source from the prompt',async t=>{
  const root=await fixture(t),output=[];
  const result=await checkModelConnection(root,'muse',{write:text=>output.push(text)});
  assert.equal(result.check.status,'connected');assert.equal(result.check.repositorySent,false);
  assert.match(output.join('\n'),/Checking that Muse Code is installed/);
  assert.match(output.join('\n'),/Connection verified/);
  const args=JSON.parse(fs.readFileSync(path.join(root,'args.json'),'utf8'));
  const value=flag=>args[args.indexOf(flag)+1];
  assert.equal(value('--provider'),'meta');assert.equal(value('--model'),'fixture-model');assert.equal(value('--contributor-mode'),'off');
  assert.ok(args.includes('--json')&&args.includes('--no-session-log')&&args.includes('--disable-shell')&&args.includes('--disable-write'));
  assert.notEqual(value('--workspace'),root);assert.equal(fs.existsSync(value('--workspace')),false);
  assert.equal(args.includes(root),false);
  assert.equal(read(root).models[0].lastAttempt.status,'connected');
});

test('a prompt echo or incomplete Muse turn never counts as a successful model response',async t=>{
  const root=await fixture(t);
  for(const scenario of ['prompt-only','echo']){
    process.env.BYPASS_MUSE_TEST_SCENARIO=scenario;
    await assert.rejects(execute('model test',['muse'],{project:root}));
    assert.equal(read(root).models[0].lastTest,undefined);
    assert.equal(readiness(root).model.connection,'failed');
  }
});

test('login and quota failures give specific recovery steps without leaking raw provider output',async t=>{
  const root=await fixture(t);
  process.env.BYPASS_MUSE_TEST_SCENARIO='auth';
  const result=await cli(root,'model','test','muse');
  assert.equal(result.code,3);assert.equal(result.data.details.reason,'authentication');
  assert.match(result.data.error,/muse login/);assert.match(result.data.error,/META_API_KEY/);
  assert.equal(JSON.stringify(result).includes('NEVER_PRINT_THIS_PROVIDER_SECRET'),false);
  assert.equal(fs.readFileSync(path.join(root,'.bypass/state.json'),'utf8').includes('NEVER_PRINT_THIS_PROVIDER_SECRET'),false);
  process.env.BYPASS_MUSE_TEST_SCENARIO='quota';
  await assert.rejects(execute('model test',['muse'],{project:root}),error=>error.details.reason==='usage_limit'&&error.message.includes('muse usage'));
  process.env.BYPASS_MUSE_TEST_SCENARIO='json-auth';
  await assert.rejects(execute('model test',['muse'],{project:root}),error=>error.details.reason==='authentication');
});

test('a failed retest supersedes the old success in readiness while retaining its history',async t=>{
  const root=await fixture(t);await execute('model test',['muse'],{project:root});
  process.env.BYPASS_MUSE_TEST_SCENARIO='auth';
  await assert.rejects(execute('model test',['muse'],{project:root}));
  assert.equal(read(root).models[0].lastTest.status,'connected');
  assert.equal(readiness(root).model.connection,'failed');
});

test('missing Muse CLI gives installation guidance and leaves the selected profile saved',async t=>{
  const root=await fixture(t);process.env.PATH=path.join(root,'no-binaries');
  await assert.rejects(execute('model test',['muse'],{project:root}),error=>error.details.reason==='cli_missing'&&error.message.includes('muse --version'));
  assert.equal(read(root).activeModel,'muse');
});

test('skipping a running Muse check stops its process before continuing and saves a skipped status',async t=>{
  const root=await fixture(t);process.env.BYPASS_MUSE_TEST_SCENARIO='hang';
  const controller=new AbortController(),output=[];
  const running=checkModelConnection(root,'muse',{write:message=>output.push(message),run:work=>work(controller.signal)});
  const pidFile=path.join(root,'pid');
  for(let i=0;i<200&&!fs.existsSync(pidFile);i++)await delay(10);
  assert.ok(fs.existsSync(pidFile),'Fixture process started');
  const pid=Number(fs.readFileSync(pidFile,'utf8'));
  controller.abort(new Fault('Connection check skipped.',130,{skipped:true}));
  assert.equal((await running).skipped,true);
  assert.throws(()=>process.kill(pid,0),error=>error.code==='ESRCH');
  assert.equal(readiness(root).model.connection,'skipped');
  assert.match(output.join('\n'),/Press Enter to skip/);
  assert.match(output.join('\n'),/profile is saved/);
});

test('Muse timeout is bounded, stops a process that ignores SIGTERM, and does not claim login failure',async t=>{
  const root=await fixture(t);process.env.BYPASS_MUSE_TEST_SCENARIO='hang';
  const started=Date.now();
  await assert.rejects(execute('model test',['muse'],{project:root},{timeoutMs:800}),error=>error.details.reason==='timeout'&&error.message.includes('does not by itself mean your login is wrong'));
  assert.ok(Date.now()-started<3000,'Hard stop is bounded');
  const pid=Number(fs.readFileSync(path.join(root,'pid'),'utf8'));
  assert.throws(()=>process.kill(pid,0),error=>error.code==='ESRCH');
  assert.equal(readiness(root).model.connection,'failed');
});

test('model timeout covers unresolved DNS, not only the eventual HTTP request',async t=>{
  const root=temp();t.after(()=>fs.rmSync(root,{recursive:true,force:true}));
  await execute('init',[root]);await execute('model add',['server'],{project:root,provider:'endpoint','base-url':'https://model.example.test',model:'fixture'});
  t.mock.method(dns,'lookup',()=>new Promise(()=>{}));
  await assert.rejects(execute('model test',['server'],{project:root},{timeoutMs:30}),error=>error.details.reason==='timeout');
});

test('local server cancellation closes the request and preserves configuration without confirming a connection',async t=>{
  const root=temp();t.after(()=>fs.rmSync(root,{recursive:true,force:true}));
  const controller=new AbortController();
  const server=http.createServer((req,res)=>{req.resume();controller.abort(new Fault('Connection check skipped.',130,{skipped:true}));});
  await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve));
  t.after(()=>{server.closeAllConnections();return new Promise(resolve=>server.close(resolve));});
  await execute('init',[root]);await execute('model add',['local'],{project:root,provider:'local','base-url':`http://127.0.0.1:${server.address().port}`,model:'fixture'});
  await assert.rejects(execute('model test',['local'],{project:root},{signal:controller.signal}),error=>error.details.skipped);
  assert.equal(read(root).models[0].lastAttempt.status,'skipped');assert.equal(read(root).models[0].lastTest,undefined);
});
