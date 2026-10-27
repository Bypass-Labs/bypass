#!/usr/bin/env node
import { execute } from '../src/service.mjs';
import { finishMuseSetup, setupTerminal } from '../src/muse-setup.mjs';
import { redact } from '../src/util.mjs';

let terminal;
try{
  console.log('Connecting Bypass to Muse…');
  const started=Date.now();
  const timer=setInterval(()=>console.log(`Still installing the plugin · ${Math.floor((Date.now()-started)/1000)}s elapsed`),20000);
  try{await execute('integrate muse',[],{scope:'user',replace:true});}finally{clearInterval(timer);}
  console.log('✓ Full plugin installed');
  terminal=setupTerminal();
  const result=await finishMuseSetup({cwd:process.cwd(),ask:terminal?.ask,launch:terminal?.launch});
  process.exitCode=result.exitCode||0;
}catch(error){
  console.error(redact(error.message));
  console.error('Your installation is saved. Rerun the same installer to continue.');
  process.exitCode=3;
}finally{terminal?.close();}
