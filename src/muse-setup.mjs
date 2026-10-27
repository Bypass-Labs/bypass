import fs from 'node:fs';
import tty from 'node:tty';
import readline from 'node:readline/promises';
import { spawn } from 'node:child_process';
import { commandInvocation } from './command.mjs';
import { execFile, Fault } from './util.mjs';
import { museInstallState } from './muse-install-state.mjs';

export const setupPrompt='Use Bypass to start setup for this application folder. Read the bypass skill and call bypass_onboarding. Reuse saved setup, ask one question at a time for missing information, and do not start live testing until ownership and scope are configured.';
const required=['plugin:bypass:hook:session-context','plugin:bypass:mcp_server:security'];
const fallback='In Muse, open /plugins → Installed → Bypass → Runtime. Then start a new session and use /bypass:start.';
const fingerprint=value=>JSON.stringify([value.record?.package_sha256,value.record?.cache_path,value.active,(value.runtime_capabilities||[]).map(row=>row.candidate).sort((a,b)=>a.stable_id.localeCompare(b.stable_id))]);

export async function inspectMuse(cwd){
  const result=await execFile('muse',['plugins','inspect','bypass','--json'],{cwd,timeout:120000});
  if(result.code!==0)throw new Fault('Muse could not read the plugin. Run the installer again to repair it.',3);
  return JSON.parse(result.stdout);
}

// Consent is collected by the caller from a real terminal, never piped input,
// an environment variable, or a blanket automatic-approval flag.
export async function finishMuseSetup({cwd,inspect=()=>inspectMuse(cwd),approve=async id=>{
  const result=await execFile('muse',['plugins','approve',id,'--json'],{cwd,timeout:120000});
  if(result.code!==0)throw new Fault('Muse did not approve Bypass. '+fallback,3);
},ask,launch,write=console.log}){
  const initial=await inspect(),state=museInstallState(initial);
  const rows=initial.runtime_capabilities||[];
  const recognized=rows.length===2&&required.every(id=>rows.some(row=>row.candidate?.stable_id===id));
  const allowed=rows.every(row=>['review_needed','modified','trusted_enabled'].includes(row.status));
  if(!initial.valid||!initial.active||!recognized||!allowed){
    write('Bypass installed. Muse needs attention before it can start.');
    if(rows.some(row=>row.status==='trusted_disabled')||initial.active===false)write('Your existing disabled permissions were preserved.');
    write(fallback);return {state:'manual_review',opened:false};
  }
  if(!ask){write('Bypass installed. '+(state.reviewRequired?fallback:'Open a new Muse session in your app folder and use /bypass:start.'));return {state:state.state,opened:false};}
  write('\nProject folder: '+cwd.replace(/[\x00-\x1f\x7f]/g,''));
  if(state.reviewRequired){
    write('Allow these two Bypass permissions in Muse:');
    write('  Security tools: read selected source, run authorized app requests, and save local evidence.');
    write('  Session context: load saved security context when a Muse session starts.');
  }
  write('Muse will open here and begin setup using your current Muse account and model.');
  const answer=await ask(state.reviewRequired?'Allow these permissions and open Muse? [y/N] ':'Open Muse and begin setup? [y/N] ');
  if(!/^(y|yes)$/i.test(answer?.trim()||'')){
    write('Setup paused. Rerun the same installer whenever you are ready.');return {state:'deferred',opened:false};
  }
  // Re-read immediately before recording consent; never approve a package that
  // changed while the user was deciding or permissions they explicitly rejected.
  const current=await inspect();
  if(fingerprint(current)!==fingerprint(initial)||current.runtime_capabilities.some(row=>!['review_needed','modified','trusted_enabled'].includes(row.status))){
    throw new Fault('Bypass changed during permission review. Rerun the installer to review the current version.',3);
  }
  for(const row of current.runtime_capabilities){
    if(row.status!=='trusted_enabled')await approve(row.candidate.stable_id);
  }
  const verified=await inspect();
  if(fingerprint(verified)!==fingerprint(initial)||museInstallState(verified).state!=='ready_for_new_session')throw new Fault('Muse has not confirmed both permissions. '+fallback,3);
  write('\nReady. Opening Muse…');
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
  const rl=readline.createInterface({input,output:process.stdout,terminal:true});
  const controller=new AbortController();
  rl.on('SIGINT',()=>controller.abort());rl.on('close',()=>controller.abort());
  const pause=()=>{rl.close();input.pause();input.setRawMode?.(false);};
  return {
    ask:async text=>{try{return await rl.question(text,{signal:controller.signal});}catch{return null;}},
    launch:async prompt=>{
      pause();
      const invocation=commandInvocation('muse',[prompt],env);
      return new Promise((resolve,reject)=>{
        const child=spawn(invocation.command,invocation.args,{cwd,env:{...env,MUSE_NO_AUTO_UPDATE:'1'},stdio:[fd,'inherit','inherit'],shell:false});
        child.on('error',()=>reject(new Fault('Muse could not open. Run muse in this folder, then /bypass:start.',3)));
        child.on('exit',(code)=>resolve(code??130));
      });
    },
    close:()=>{pause();if(owned)input.destroy();}
  };
}
