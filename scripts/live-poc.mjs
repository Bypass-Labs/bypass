// Opt-in: uses real Docker + Muse inference. Only the bundled local fixture is tested.
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import readline from 'node:readline';
import { spawn } from 'node:child_process';
import assert from 'node:assert/strict';
import { fileURLToPath } from 'node:url';
import { startPOC, stopPOC } from '../src/poc.mjs';
import { execFile, delay } from '../src/util.mjs';

const checkout=fileURLToPath(new URL('../',import.meta.url));
const directory=fs.mkdtempSync(path.join(os.tmpdir(),'bypass-live-poc-'));
const root=path.join(directory,'app');
let child,runId,call;
const report={startedAt:new Date().toISOString(),transport:'packaged plugin MCP',inference:'real Muse subscription',mocked:false,root};
try{
  await startPOC({dir:root});
  child=spawn(process.execPath,[path.join(checkout,'plugin/mcp/server.mjs')],{cwd:root,env:{...process.env,BYPASS_PLUGIN_STATE_DIR:path.join(directory,'selection')},stdio:['pipe','pipe','pipe']});
  child.stderr.resume();let sequence=0;const pending=new Map();
  readline.createInterface({input:child.stdout}).on('line',line=>{
    const message=JSON.parse(line),entry=pending.get(message.id);
    if(entry){clearTimeout(entry.timer);pending.delete(message.id);entry.resolve(message);}
  });
  const request=(method,params={})=>new Promise((resolve,reject)=>{
    const id=++sequence,timer=setTimeout(()=>{pending.delete(id);reject(new Error(`MCP ${method} timed out`));},20000);
    pending.set(id,{resolve,reject,timer});child.stdin.write(JSON.stringify({jsonrpc:'2.0',id,method,params})+'\n');
  });
  child.on('close',()=>{for(const item of pending.values()){clearTimeout(item.timer);item.reject(new Error('MCP exited'));}pending.clear();});
  call=async(name,args={})=>{
    const message=await request('tools/call',{name,arguments:args});
    assert.ok(message.result,JSON.stringify(message));
    const result=JSON.parse(message.result.content[0].text);
    assert.equal(message.result.isError,false,JSON.stringify(result));return result;
  };
  await request('initialize',{protocolVersion:'2025-11-25',capabilities:{},clientInfo:{name:'bypass-live-validation',version:'1'}});
  await call('bypass_connect_repository',{repository:root,confirmed:true});
  await call('bypass_test_probe',{name:'invoice'});
  const setup=await call('bypass_onboarding');assert.equal(setup.ready.live,true);report.pluginVersion=setup.pluginVersion;
  const wait=async id=>{
    const end=Date.now()+240000;let shown=0;
    while(Date.now()<end){
      const {run}=await call('bypass_run',{id});
      for(const step of run.steps.slice(shown))console.log(step.message);shown=run.steps.length;
      if(['completed','failed','incomplete','cancelled','interrupted'].includes(run.status))return run;
      await delay(1500);
    }
    await call('bypass_stop_run',{id});throw new Error('Live validation exceeded four minutes; stop requested');
  };
  runId=(await call('bypass_scan',{mode:'combined'})).runId;
  const run=await wait(runId);report.scan={id:run.id,exitCode:run.exitCode,result:run.result,agents:run.agentEvidence};runId=null;
  assert.ok(run.result.confirmed?.length,run.result.message||'No HTTP-confirmed fixture finding');
  const finding=(await call('bypass_finding',{id:run.result.confirmed[0]})).finding;
  assert.equal(finding.sourceEvidence.kind,'source','Live gate requires actual source attribution');
  report.source=finding.sourceEvidence;report.controls=finding.verification.controls;
  fs.writeFileSync(path.join(root,'policy.mjs'),'export function mayReadInvoice(account, invoice) { return account === invoice.ownerId; }\n');
  const retest=await call('bypass_retest',{id:finding.id});assert.equal(retest.status,'fixed_verified');report.savedCheck=retest.savedCheck.id;
  const exported=await call('bypass_export_tests',{all:true});
  const fixed=await execFile(process.execPath,['--test',...exported.files],{timeout:15000,env:{NODE_TEST_CONTEXT:undefined}});assert.equal(fixed.code,0,fixed.stdout+fixed.stderr);
  fs.writeFileSync(path.join(root,'policy.mjs'),'export function mayReadInvoice(account, invoice) { return Boolean(account); }\n');
  runId=(await call('bypass_run_tests',{all:true})).runId;
  const replay=await wait(runId);runId=null;assert.equal(replay.exitCode,1);assert.equal(replay.result.modelCalls,0);
  const broken=await execFile(process.execPath,['--test',...exported.files],{timeout:15000,env:{NODE_TEST_CONTEXT:undefined}});assert.equal(broken.code,1,broken.stdout+broken.stderr);
  fs.writeFileSync(path.join(root,'policy.mjs'),'export function mayReadInvoice(account, invoice) { return account === invoice.ownerId; }\n');
  await call('bypass_retest',{id:finding.id});
  report.passed=true;report.exportedTest={fixedExit:fixed.code,regressedExit:broken.code};report.replay={regressedExit:replay.exitCode,modelCalls:0};
}catch(error){report.passed=false;report.error=error.message;process.exitCode=1;}
finally{
  if(runId&&call)try{await call('bypass_stop_run',{id:runId});await delay(1000);}catch{}
  child?.stdin.end();child?.kill();
  try{await stopPOC(root);}catch{}
  report.finishedAt=new Date().toISOString();
  fs.writeFileSync(path.join(directory,'validation.json'),JSON.stringify(report,null,2)+'\n',{mode:0o600});
  console.log(JSON.stringify({passed:report.passed,evidence:path.join(directory,'validation.json'),error:report.error},null,2));
}
