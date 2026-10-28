#!/usr/bin/env node
import { execute } from '../src/service.mjs';
import { finishMuseSetup, setupTerminal } from '../src/muse-setup.mjs';
import { redact, Fault } from '../src/util.mjs';
import { createTheme } from '../src/terminal-theme.mjs';
import { createInstallProgress, createSetupActivity } from '../src/install-progress.mjs';
const {paint}=createTheme();
const write=text=>console.log(paint(text.startsWith('\n03')?'brand':/^  [12]\./.test(text)?'title':text.startsWith('  ')?'muted':'normal',text));

let terminal;
try{
  console.log(paint('brand','02 / CONNECT   Bypass for Muse'));
  const progress=createInstallProgress(),controller=new AbortController();
  const cancel=()=>{progress.cancel();controller.abort(new Fault('Plugin setup cancelled.',130));};
  process.on('SIGINT',cancel);process.on('SIGTERM',cancel);
  try{
    const result=await execute('integrate muse',[],{scope:'user',replace:true},{signal:controller.signal,onProgress:progress.update});
    if(controller.signal.aborted)throw controller.signal.reason;
    progress.finish({result});
  }catch(error){progress.finish({error});throw error;}
  finally{process.off('SIGINT',cancel);process.off('SIGTERM',cancel);}
  terminal=setupTerminal();
  const result=await finishMuseSetup({cwd:process.cwd(),ask:terminal?.ask,launch:terminal?.launch,signal:terminal?.signal,activity:createSetupActivity(),write});
  process.exitCode=result.exitCode||0;
}catch(error){
  console.error(paint('error',redact(error.message)));
  console.error('Your installation is saved. Rerun the same installer to continue.');
  process.exitCode=error.code===130?130:3;
}finally{terminal?.close();}
