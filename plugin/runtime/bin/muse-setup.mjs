#!/usr/bin/env node
import { execute } from '../src/service.mjs';
import { finishMuseSetup, setupTerminal } from '../src/muse-setup.mjs';
import { redact } from '../src/util.mjs';
import { createTheme } from '../src/terminal-theme.mjs';
const {paint}=createTheme();
const write=text=>console.log(paint(text.startsWith('\n03')?'brand':text.startsWith('  ')?'muted':'normal',text));

let terminal;
try{
  console.log(paint('brand','02 / CONNECT   Installing the Muse plugin…'));
  const started=Date.now();
  const timer=setInterval(()=>console.log(paint('muted',`Still installing the plugin · ${Math.floor((Date.now()-started)/1000)}s elapsed`)),20000);
  try{await execute('integrate muse',[],{scope:'user',replace:true});}finally{clearInterval(timer);}
  console.log(paint('success','✓ Full plugin installed'));
  terminal=setupTerminal();
  const result=await finishMuseSetup({cwd:process.cwd(),ask:terminal?.ask,launch:terminal?.launch,write});
  process.exitCode=result.exitCode||0;
}catch(error){
  console.error(paint('error',redact(error.message)));
  console.error('Your installation is saved. Rerun the same installer to continue.');
  process.exitCode=3;
}finally{terminal?.close();}
