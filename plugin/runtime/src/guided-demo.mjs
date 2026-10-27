import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import net from 'node:net';
import { execute, PACKAGE_ROOT } from './service.mjs';
import { read } from './store.mjs';
import { need, Fault, execFile, cleanText, redact, outcome } from './util.mjs';

// One self-contained path through the product. Only this newly created fixture is changed.
export async function guidedDemo(options={},io={}) {
  need(io.ask,'The guided walkthrough needs an interactive terminal. Use demo start for scripted setup.');
  const say=value=>(io.write||console.log)(cleanText(redact(String(value))));
  const base=path.join(PACKAGE_ROOT,'.demo');
  let root;
  if(options.dir){
    root=path.resolve(options.dir.startsWith('~/')?path.join(os.homedir(),options.dir.slice(2)):options.dir);
    need(!fs.existsSync(root)||(fs.statSync(root).isDirectory()&&fs.readdirSync(root).length===0),'The guided walkthrough needs an empty directory. Your existing project or demo is unchanged.');
  }else{fs.mkdirSync(base,{recursive:true});root=fs.mkdtempSync(path.join(base,'walkthrough-'));}
  const labels={'scan':'Inventory source and seed an example','verify':'Prove access with two test accounts','demo fix':'Apply the fixture ownership fix','retest':'Retest the fix and save its check','test export':'Export a standalone Node test','demo regress':'Reintroduce the fixture bug','test run':'Replay the saved regression test','monitor add':'Configure the local example schedule','monitor worker':'Run one due scheduler tick','context':'Read the next-session evidence','monitor pause':'Pause the example schedule'};
  const call=(key,args=[],flags={})=>{
    const work=signal=>execute(key,args,{project:root,...flags},{signal,onProgress:step=>say(step.message)});
    return io.activity?io.activity(labels[key]||key,work):work(io.signal);
  };
  let step=-1;
  const tasks=['Review the source · simulated discovery','Prove the issue · real HTTP','Fix and retest · save a check','Export and run an independent test','Reintroduce the bug · catch regression','Record monitor result · restore fixed app'];
  io.setTasks?.('Local walkthrough',tasks);
  const next=async label=>{
    if(step>=0)io.task?.(step,'done');step++;
    io.setNext?.(tasks[step]+' · press Enter');
    while(true){const answer=(await io.ask(label+' (Enter to continue, q to leave)','')).trim().toLowerCase();if(!answer||answer==='y'){io.task?.(step,'running');io.setNext?.(tasks[step+1]||'Save the evidence and stop the local demo server');return;}if(['q','quit','back','n'].includes(answer))throw new Fault('Walkthrough paused. Its evidence is saved; your app is unchanged.',130,{walkthroughLeft:true});say('Press Enter to continue, or q to leave.');}
  };
  let started=false;
  say('\nGUIDED WALKTHROUGH / One issue, one lasting test');
  say('A separate local Ledger app with two public test accounts. No login, DNS, plugin, or model call is needed.\nDiscovery is simulated. HTTP proof, the fix, and saved-test replay are real.');
  try{
    const server=net.createServer();await new Promise((resolve,reject)=>{server.once('error',reject);server.listen(0,'127.0.0.1',resolve);});
    const port=server.address().port;await new Promise(resolve=>server.close(resolve));
    say('\nPreparing the local app…');
    started=true; // Also clean up if startup creates the fixture but fails its health check.
    const launch=()=>execute('demo start',[],{dir:root,port});
    const demo=io.activity?await io.activity('Start the isolated local Ledger app',launch,{cancelable:false}):await launch();
    io.setContext?.({title:'Ledger · isolated walkthrough',engine:'mock',demo:true,repo:root,branch:'',app:`${demo.url} · local fixture`,model:'no model calls · no login needed'});
    say(`Local app: ${demo.url}\nYou can open it in a browser while following the terminal.`);

    await next('\n1 / 6 · Run the example review');
    const scan=await call('scan',[],{mode:'combined'});
    need(scan.run?.result?.findings?.length,'The walkthrough could not create its example finding.',3);
    const finding=read(root).findings.find(f=>f.id===scan.run.result.findings[0]);
    say('✓ Example found: another account may be able to read the owner’s invoice.\nThis is a seeded example; we will now test the actual local HTTP behavior.');

    await next('\n2 / 6 · Prove it with two accounts');
    const proof=await call('verify',[finding.id]);
    need(proof.status==='confirmed_fixture','The local fixture did not reproduce the expected issue.',3);
    say('✓ Proof captured: owner HTTP 200 · other account HTTP 200 · anonymous HTTP 401.\nThe other account can read an invoice it does not own.');

    await next('\n3 / 6 · Apply the fix and retest');
    await call('demo fix');const fixed=await call('retest',[finding.id]);
    need(fixed.status==='fixed_verified'&&fixed.savedCheck,'The fixture fix did not pass the retest.',3);
    say('✓ Fix verified: owner HTTP 200 · other account HTTP 403 · anonymous HTTP 401.\n✓ One regression test saved automatically.');

    await next('\n4 / 6 · Export and run the test without Bypass or a model');
    const exported=await call('test export',[],{all:true});
    const testIndependent=signal=>execFile(process.execPath,['--test',...exported.files],{cwd:root,signal,timeout:15000,killGroup:true,env:{NODE_TEST_CONTEXT:undefined}});
    const independent=io.activity?await io.activity('Run the independent Node test',testIndependent):await testIndependent(io.signal);
    need(independent.code===0,'The exported Node test did not pass.',3);
    say(`✓ Independent Node test passed. No Bypass or model dependency.\nSaved at: ${exported.files[0]}`);

    await next('\n5 / 6 · Bring the bug back and catch it');
    await call('demo regress');const regression=await call('test run',[],{all:true});
    need(regression.exitCode===1&&regression.run.result.results.some(r=>r.status==='failed'),'The regression was not caught by the saved test.',3);
    const independentFailure=io.activity?await io.activity('Confirm the independent test catches the bug',testIndependent):await testIndependent(io.signal);
    need(independentFailure.code===1,'The independent test did not catch the regression.',3);
    say('✓ Regression caught by both Bypass replay and the independent Node test.\nA failed assertion is the expected success in this step. Model calls: 0.');

    await next('\n6 / 6 · Record the monitor result and next-session context');
    await call('monitor add',['walkthrough'],{every:'1h',runner:'local'});
    const scheduled=await call('monitor worker',[],{once:true});
    need(scheduled.runs?.length===1,'The local scheduler did not execute the due check.',3);
    const context=await call('context');
    need(context.recentEvents?.some(e=>e.kind==='monitor-result'&&e.message.includes('regression detected')),'The monitor result was not saved in session context.',3);
    say('✓ A local scheduler tick caught the regression and saved it for the next session.\nThis walkthrough ran one due tick; it did not start an always-on monitoring service.');
    await call('demo fix');await call('retest',[finding.id]);await call('monitor pause',['walkthrough']);
    io.task?.(5,'done');io.setNext?.('Walkthrough complete · evidence saved · return to your project');
    say(`\nWALKTHROUGH COMPLETE\n  Proved an issue → verified the fix → saved a test → caught the regression.\n  Final state: fixture fixed · one saved check · zero model calls.\n  Evidence and exported test: ${root}\n\nYour connected app and its DNS verification were not changed. The local demo server is stopping.`);
    return outcome({root,completed:true,checkId:fixed.savedCheck.id,files:exported.files,modelCalls:0,fixtureOnly:true});
  }catch(error){if(step>=0)io.task?.(step,error.code===130?'cancelled':'failed');if(error.details?.walkthroughLeft||error.details?.cancelled){say(error.message);return outcome({root,completed:false,paused:true,fixtureOnly:true});}throw error;}
  finally{if(started)await execute('demo stop',[],{project:root}).catch(()=>{});}
}
