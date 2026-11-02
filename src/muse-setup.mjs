import fs from 'node:fs';
import tty from 'node:tty';
import readline from 'node:readline/promises';
import { spawn } from 'node:child_process';
import { commandInvocation } from './command.mjs';
import { execFile, Fault, abortFault } from './util.mjs';
import { museInstallState } from './muse-install-state.mjs';
import { createTheme } from './terminal-theme.mjs';

export const setupPrompt='/bypass:start';
const required=['plugin:bypass:hook:session-context','plugin:bypass:mcp_server:security'];
const fallback='In Muse, open /plugins → Installed → Bypass → Runtime. Then start a new session and use /bypass:start.';
const fingerprint=value=>JSON.stringify([value.record?.package_sha256,value.record?.cache_path,value.active,(value.runtime_capabilities||[]).map(row=>row.candidate).sort((a,b)=>a.stable_id.localeCompare(b.stable_id))]);

export async function inspectMuse(cwd,{signal}={}){
  const result=await execFile('muse',['plugins','inspect','bypass','--json'],{cwd,signal,killGroup:true,timeout:120000});
  if(result.code!==0)throw new Fault('Muse could not read the plugin. Run the installer again to repair it.',3);
  return JSON.parse(result.stdout);
}

// Consent is collected by the caller from a real terminal, never piped input,
// an environment variable, or a blanket automatic-approval flag.
export async function finishMuseSetup({cwd,signal,inspect=()=>inspectMuse(cwd,{signal}),approve=async id=>{
  const result=await execFile('muse',['plugins','approve',id,'--json'],{cwd,signal,killGroup:true,timeout:120000});
  if(result.code!==0)throw new Fault('Muse did not approve Bypass. '+fallback,3);
},ask,launch,write=console.log,activity}){
  const runActivity=activity|| (async(label,work)=>{write(label+'…');return work();});
  const step=(label,work)=>runActivity(label,async()=>{
    if(signal?.aborted)throw abortFault(signal);
    const result=await work();
    if(signal?.aborted)throw abortFault(signal);
    return result;
  });
  write('\n03 / START   Open Muse Code');
  const initial=await step('Check Bypass permissions',inspect),state=museInstallState(initial);
  const rows=initial.runtime_capabilities||[];
  const recognized=rows.length===2&&required.every(id=>rows.some(row=>row.candidate?.stable_id===id));
  const allowed=rows.every(row=>['review_needed','modified','trusted_enabled'].includes(row.status));
  if(!initial.valid||!initial.active||!recognized||!allowed){
    write('Bypass installed. Muse needs attention before it can start.');
    if(rows.some(row=>row.status==='trusted_disabled')||initial.active===false)write('Your existing disabled permissions were preserved.');
    write(fallback);return {state:'manual_review',opened:false};
  }
  if(!ask){write('Bypass installed. '+(state.reviewRequired?fallback:'Open a new Muse session in your app folder and use /bypass:start.'));return {state:state.state,opened:false};}
  if(state.reviewRequired){
    const status=id=>rows.find(row=>row.candidate.stable_id===id).status==='trusted_enabled'?'already enabled':'needs permission';
    write(`\nSecurity tools (${status(required[1])}): review selected code, test approved app routes, save evidence/tests.`);
    write(`Security memory (${status(required[0])}): load saved project security context in future sessions.`);
    write('Selected code and evidence are available to your current Muse model.');
    write('You will approve the app and exact testing scope before requests begin.');
    write('\n  1  Enable Bypass and open Muse Code');
    write('  2  Later (default)');
    write('  3  Customize permissions in Muse Code');
  }else{
    write('Security tools and security memory are already enabled.');
    write('  1  Open Muse Code');write('  2  Later (default)');
  }
  const answer=await ask('\nChoose [2]: ');
  if(state.reviewRequired&&answer?.trim()==='3'){write(fallback);return {state:'manual_review',opened:false};}
  if(!/^(1|y|yes)$/i.test(answer?.trim()||'')){
    write('Setup paused. Rerun the same installer whenever you are ready.');return {state:'deferred',opened:false};
  }
  // Re-read immediately before recording consent; never approve a package that
  // changed while the user was deciding or permissions they explicitly rejected.
  const checked=async work=>{
    if(signal?.aborted)throw abortFault(signal);
    const result=await work();
    if(signal?.aborted)throw abortFault(signal);
    return result;
  };
  await step('Enable Bypass',async()=>{
    const current=await checked(async()=>{
      const value=await inspect();
      if(fingerprint(value)!==fingerprint(initial)||value.runtime_capabilities.some(row=>!['review_needed','modified','trusted_enabled'].includes(row.status))){
        throw new Fault('Bypass changed during permission review. Rerun the installer to review the current version.',3);
      }
      return value;
    });
    for(const id of [required[1],required[0]]){
      const row=current.runtime_capabilities.find(row=>row.candidate.stable_id===id);
      if(row.status!=='trusted_enabled')await checked(()=>approve(id));
    }
    await checked(async()=>{
      const verified=await inspect();
      if(fingerprint(verified)!==fingerprint(initial)||museInstallState(verified).state!=='ready_for_new_session')throw new Fault('Muse has not confirmed both permissions. '+fallback,3);
    });
  });
  write('Opening Muse Code. Choose your application there…');
  const exitCode=await launch(setupPrompt);
  if(exitCode)write('Muse exited. Your plugin remains installed. To continue, reopen Muse in this folder and use /bypass:start.');
  return {state:'opened',opened:true,exitCode};
}

export function setupTerminal({cwd=process.cwd(),env=process.env}={}){
  if(env.CI||env.BYPASS_NO_OPEN_MUSE==='1'||!process.stdout.isTTY)return null;
  let input=process.stdin,fd=0,owned=false;
  if(!input.isTTY){
    if(process.platform==='win32')return null;
    try{fd=fs.openSync('/dev/tty','r+');input=new tty.ReadStream(fd);owned=true;}catch{return null;}
  }
  const theme=createTheme({env});
  const rl=readline.createInterface({input,output:process.stdout,terminal:true});
  const controller=new AbortController();
  rl.on('SIGINT',()=>controller.abort());rl.on('close',()=>controller.abort());
  let paused=false;
  const pause=()=>{if(paused)return;paused=true;rl.close();input.pause();input.setRawMode?.(false);};
  return {
    signal:controller.signal,
    ask:async text=>{try{return await rl.question(theme.paint('accent',text),{signal:controller.signal});}catch{return null;}},
    launch:async prompt=>{
      pause();
      let childInput=fd;
      if(owned){
        await new Promise(resolve=>{input.once('close',resolve);input.destroy();});
        // /dev/tty works for the consent reader, but macOS cannot register that
        // alias with kqueue. Muse needs the actual terminal device for its UI.
        // Reopen the known terminal output descriptor as readable input after
        // releasing our reader; never give Muse the installer's script pipe.
        try{childInput=fs.openSync('/dev/fd/1','r+');}
        catch{throw new Fault('Could not hand the terminal to Muse. Run muse in this folder, then /bypass:start.',3);}
      }
      const invocation=commandInvocation('muse',[prompt],env);
      try{return await new Promise((resolve,reject)=>{
        const child=spawn(invocation.command,invocation.args,{cwd,env:{...env,MUSE_NO_AUTO_UPDATE:'1'},stdio:[childInput,'inherit','inherit'],shell:false});
        child.on('error',()=>reject(new Fault('Muse could not open. Run muse in this folder, then /bypass:start.',3)));
        child.on('exit',(code)=>resolve(code??130));
      });}finally{if(owned)fs.closeSync(childInput);}
    },
    close:()=>{pause();if(owned)input.destroy();}
  };
}
