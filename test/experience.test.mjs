import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { guidedDemo } from '../src/guided-demo.mjs';
import { onboard } from '../src/onboarding.mjs';
import { terminal, printResult } from '../src/ui.mjs';
import { homeActions } from '../src/experience.mjs';
import { appOriginInput, safeRequest } from '../src/network.mjs';
import { read } from '../src/store.mjs';
import { execute } from '../src/service.mjs';
import { delay } from '../src/util.mjs';
import { temp, cli } from './helpers.mjs';

test('walkthrough advances on Enter through real proof, independent pass/fail, scheduler and cleanup',async()=>{
  const root=temp(),output=[],prompts=[];
  const result=await onboard({flow:'demo',dir:root},[],{
    write:text=>output.push(text),ask:async label=>{prompts.push(label);return '';}
  });
  assert.equal(prompts.length,6);
  assert.equal(result.completed,true);assert.equal(result.openDashboard,false);
  const state=read(root),finding=state.findings[0];
  assert.deepEqual(finding.history.filter(h=>h.controls).map(h=>h.status),['failed','passed','failed','failed','passed']);
  assert.equal(finding.status,'fixed_verified');
  assert.equal(state.checks.length,1);assert.equal(state.checks[0].id,result.checkId);
  assert.equal(state.checks[0].lastResult.status,'passed');
  assert.ok(state.runs.some(r=>r.result?.results?.some(c=>c.status==='failed')));
  assert.ok(state.events.some(e=>e.kind==='monitor-result'&&e.message.includes('regression detected')));
  assert.equal(state.monitors[0].enabled,false);
  assert.ok(result.files.every(file=>fs.existsSync(file)));
  assert.ok(state.runs.every(r=>r.result?.modelCalls===0));
  assert.equal(state.models.length,0);
  assert.match(output.join('\n'),/Independent Node test passed/);
  assert.match(output.join('\n'),/Regression caught by both/);
  assert.match(output.join('\n'),/WALKTHROUGH COMPLETE/);
  await delay(700);
  await assert.rejects(safeRequest(state.demo.url+'/health',{allowLocal:true}));
});

test('leaving a walkthrough preserves partial evidence and stops its server',async()=>{
  const root=temp(),answers=['','q'];
  const result=await guidedDemo({dir:root},{write:()=>{},ask:async()=>answers.shift()});
  assert.equal(result.completed,false);assert.equal(result.paused,true);
  assert.equal(read(root).findings.length,1);assert.equal(read(root).checks.length,0);
  await delay(700);
  await assert.rejects(safeRequest(read(root).demo.url+'/health',{allowLocal:true}));
});

test('bare domains and loopback inputs normalize without loosening scope rules',()=>{
  for(const [input,expected] of [
    ['job-radar.app','https://job-radar.app'],['[app](https://staging.example.com/)','https://staging.example.com'],
    ['localhost:3000','http://localhost:3000'],['127.0.0.1:4317','http://127.0.0.1:4317'],['[::1]:3000','http://[::1]:3000']
  ])assert.equal(appOriginInput(input),expected);
  for(const input of ['bad input','example','http://example.com','https://user:pass@example.com','example.com/api','example.com?token=x'])assert.throws(()=>appOriginInput(input));
});

test('home recommends review, results, then saved checks independently of pending DNS',()=>{
  const state={targets:[{ownership:{status:'pending'}}],findings:[],checks:[]};
  assert.equal(homeActions(state)[0].id,'review');
  state.findings.push({status:'simulated_unproven'});assert.equal(homeActions(state)[0].id,'results');
  state.checks.push({enabled:true});assert.equal(homeActions(state)[0].id,'tests');
});

test('Enter runs review and opens results; help exposes commands; no extra return prompt or Exit 3',async t=>{
  const root=temp();fs.writeFileSync(path.join(root,'app.js'),'export const example = true;');await execute('init',[root]);
  await execute('target add',['production'],{project:root,url:'https://app.example.com',environment:'production'});
  const output=[],answers=['?',`./bypass demo --dir ${root}`,'','0','q'],prompts=[];
  t.mock.method(console,'log',(...args)=>output.push(args.join(' ')));
  await terminal({project:root},{ask:async(label,fallback)=>{prompts.push(label);assert.ok(answers.length);return answers.shift()||fallback||'';}});
  assert.equal(answers.length,0);assert.equal(read(root).findings.length,1);
  assert.equal(read(root).targets[0].ownership.status,'pending');
  const transcript=output.join('\n');
  assert.match(transcript,/Commands you can type here/);assert.match(transcript,/Review preview complete/);
  assert.match(transcript,/It was not discovered in your code/);assert.match(transcript,/Open review results/);
  assert.match(transcript,/empty directory/);
  assert.doesNotMatch(transcript,/Exit 3|Press Enter to return|Unknown operation/);
  assert.deepEqual(prompts,['Choose or type a command','Choose or type a command','Choose or type a command','Choose','Choose or type a command']);
  const scripted=await cli(root,'scan','--mode','code');assert.equal(scripted.code,3);
  assert.equal(scripted.data.run.result.simulation,true);
});

test('a successful preview never hides failed saved-check results',t=>{
  const output=[];t.mock.method(console,'log',text=>output.push(text));
  printResult({run:{kind:'scan',result:{simulation:true,inventory:{sourceFileCount:1},findings:[],regression:[{status:'failed',reason:'Account boundary regressed'}]}}});
  assert.match(output.join('\n'),/Saved check: failed/);
});

test('opening the tooling checkout asks for the application before any review',async t=>{
  const root=temp();fs.writeFileSync(path.join(root,'package.json'),JSON.stringify({name:'@bypass-labs/cli-skeleton'}));
  await execute('init',[root]);const before=fs.readFileSync(path.join(root,'.bypass/state.json'),'utf8'),output=[],prompts=[];
  t.mock.method(console,'log',text=>output.push(text));
  await terminal({project:root},{ask:async label=>{prompts.push(label);return '0';}});
  assert.equal(prompts.length,1);assert.match(output.join('\n'),/Choose my application repository/);
  assert.equal(fs.readFileSync(path.join(root,'.bypass/state.json'),'utf8'),before);
});

async function fakeMuse(t,scenario){
  const root=temp(),bin=path.join(root,'bin'),calls=path.join(root,'calls');fs.mkdirSync(bin);
  const hasExisting=scenario==='existing'||scenario.startsWith('replace');
  fs.writeFileSync(path.join(bin,'muse'),`#!${process.execPath}
const fs=require('fs'),args=process.argv.slice(2);
fs.appendFileSync(${JSON.stringify(calls)},args.join(' ')+'\\n');
if(args[1]==='inspect'){
  console.log(JSON.stringify(${JSON.stringify(hasExisting?{valid:true,active:true,record:{id:'bypass',source:{path:'/other/checkout/plugin'}}}:{error:{message:'not installed'}})}));
  process.exit(${hasExisting?0:1});
}
if(args[1]==='validate'){console.log('{"valid":true}');process.exit(${scenario==='replace-invalid'?1:0});}
if(args[1]==='remove'){console.log('{"removed":true}');process.exit(0);}
if(args[1]==='install'&&(${scenario==='replace-success'}||args[2]==='/other/checkout/plugin')){console.log('{"installed":true}');process.exit(0);}
if(args[1]==='install'&&${scenario==='replace-cancel'}){setInterval(()=>{},1000);}else{
console.log(JSON.stringify({error:{message:'plugin bypass is already installed from a different source'}}));process.exit(1);
}
`,{mode:0o755});
  const previous=process.env.PATH;process.env.PATH=bin+path.delimiter+previous;
  t.after(()=>{process.env.PATH=previous;fs.rmSync(root,{recursive:true,force:true});});
  return {root,calls};
}

test('existing plugin in another checkout is reused without installing, changing or approving it',async t=>{
  const {root,calls}=await fakeMuse(t,'existing');
  const result=await execute('integrate muse',[],{project:root});
  assert.equal(result.alreadyInstalled,true);assert.equal(result.exitCode,0);
  assert.match(result.message,/No second installation/);
  assert.equal(fs.readFileSync(calls,'utf8'),'plugins inspect bypass --json\n');
});

test('native plugin failure includes the actionable native reason',async t=>{
  const {root}=await fakeMuse(t,'failure');
  await assert.rejects(execute('integrate muse',[],{project:root}),/already installed from a different source/);
});

test('explicit plugin replacement validates before removal and installs the bundled package without approving it',async t=>{
  const {root,calls}=await fakeMuse(t,'replace-success');
  const result=await execute('integrate muse',[],{project:root,scope:'user',replace:true});
  assert.equal(result.exitCode,0);
  const commands=fs.readFileSync(calls,'utf8').trim().split('\n');
  assert.deepEqual(commands.map(c=>c.split(' ')[1]),['inspect','validate','remove','install']);
  assert.ok(commands[3].endsWith('--scope user --json'));
  assert.ok(commands[3].includes(result.plugin));
});

test('invalid bundled plugin leaves the existing installation intact',async t=>{
  const {root,calls}=await fakeMuse(t,'replace-invalid');
  await assert.rejects(execute('integrate muse',[],{project:root,replace:true}),/rejected plugin validation/);
  assert.deepEqual(fs.readFileSync(calls,'utf8').trim().split('\n').map(c=>c.split(' ')[1]),['inspect','validate']);
});

test('failed plugin replacement attempts to restore the prior source and reports the installation error',async t=>{
  const {root,calls}=await fakeMuse(t,'replace-failure');
  await assert.rejects(execute('integrate muse',[],{project:root,scope:'user',replace:true}),/already installed from a different source/);
  const commands=fs.readFileSync(calls,'utf8').trim().split('\n');
  assert.deepEqual(commands.map(c=>c.split(' ')[1]),['inspect','validate','remove','install','install']);
  assert.equal(commands[4],'plugins install /other/checkout/plugin --scope user --json');
});

test('interrupted native plugin installation restores the prior source despite the cancelled request',async t=>{
  const {root,calls}=await fakeMuse(t,'replace-cancel'),controller=new AbortController(),progress=[];
  const timer=setInterval(()=>{if(fs.existsSync(calls)&&fs.readFileSync(calls,'utf8').includes('plugins install '))controller.abort();},10);
  try{
    await assert.rejects(execute('integrate muse',[],{project:root,scope:'user',replace:true},{signal:controller.signal,onProgress:step=>progress.push(step.message)}),error=>error.code===130&&error.details.previousPluginRestored===true);
    const commands=fs.readFileSync(calls,'utf8').trim().split('\n');
    assert.deepEqual(commands.map(c=>c.split(' ')[1]),['inspect','validate','remove','install','install']);
    assert.equal(commands[4],'plugins install /other/checkout/plugin --scope user --json');
    assert.ok(progress.some(message=>message.startsWith('Restoring the previous Muse plugin')));
  }finally{clearInterval(timer);}
});
