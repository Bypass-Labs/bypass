import { stripVTControlCharacters } from 'node:util';
import { createTheme } from './terminal-theme.mjs';
import { cells, clip } from './terminal-session.mjs';

const frames=['⠋','⠙','⠹','⠸','⠼','⠴','⠦','⠧','⠇','⠏'];
const elapsed=ms=>ms<60000?`${Math.floor(ms/1000)}s`:`${Math.floor(ms/60000)}m${Math.floor(ms/1000)%60?' '+Math.floor(ms/1000)%60+'s':''}`;
const details={inspect:'Looking for an existing Bypass plugin.',validate:'Muse is checking the plugin package.',remove:'Updating the previous plugin installation.',install:'Installing tools, commands and security memory.',disable:'Keeping your existing disabled setting.'};

// Muse reports the result of each operation, not byte progress. Only advance
// the checklist on real service events; never infer completion from a timer.
export function createInstallProgress({output=process.stderr,env=process.env,clock=Date.now}={}){
  const animated=!!output.isTTY&&env.TERM!=='dumb'&&!env.CI&&env.BYPASS_PLAIN!=='1';
  const theme=createTheme({output,env:animated?env:{...env,NO_COLOR:''}});
  const rows=[{id:'check',label:'Check setup',state:'running'},{id:'install',label:'Install plugin',state:'waiting'},{id:'verify',label:'Verify installation',state:'waiting'}];
  const started=clock();
  let phase='check',operation='inspect',operationStarted=started,timeoutMs=120000,finished=false,cancelling=false,frame=0,previous=[],lastPlain=started;
  const width=()=>Math.max(12,(output.columns||80)-1);
  const clear=()=>{
    if(!animated||!previous.length)return;
    // Account for terminal reflow if the window became narrower since drawing.
    const physical=previous.reduce((n,line)=>n+Math.max(1,Math.ceil(cells(line)/(output.columns||80))),0);
    output.write(`\x1b[${physical}A\r\x1b[J`);previous=[];
  };
  const note=()=>phase==='restore'?operation==='inspect'?'Checking the previous plugin before stopping.':'Restoring the previous plugin before stopping.':cancelling?'Stopping Muse; keeping your saved setup.':phase==='verify'?'Checking the installed plugin in Muse.':details[operation]||'Waiting for Muse.';
  const writeLines=lines=>{
    const fitted=[];
    for(const [text,tone='muted'] of lines){
      // Word wrapping preserves the next action in small terminal windows.
      let line='';
      for(const word of text.split(' ')){
        if(line&&cells(line+' '+word)>width()){fitted.push([line,tone]);line='';}
        line+=(line?' ':'')+word;
      }
      fitted.push([clip(line,width()),tone]);
    }
    output.write(fitted.map(([text,tone])=>theme.paint(tone,text)).join('\n')+'\n');
    previous=fitted.map(([text])=>stripVTControlCharacters(text));
  };
  const render=()=>{
    if(finished||!animated)return;
    clear();
    const lines=rows.map(row=>{
      const icon=row.state==='done'?'✓':row.state==='running'?frames[frame%frames.length]:'○';
      const suffix=row.state==='running'?` · ${elapsed(clock()-operationStarted)}`:'';
      return [`  ${icon} ${row.label}${suffix}`,row.state==='running'?'accent':row.state==='done'?'success':'muted'];
    });
    if(phase==='restore')lines.push([`  ${frames[frame%frames.length]} Restore previous plugin · ${elapsed(clock()-operationStarted)}`,'warning']);
    lines.push([''],[note(),phase==='restore'?'warning':'muted']);
    if(clock()-operationStarted>=30000&&!cancelling)lines.push(['Waiting for Muse to return a result.','warning']);
    lines.push([`Ctrl+C cancel · Muse timeout: ${elapsed(timeoutMs)}`],['Next: permissions → open Muse.','info']);
    writeLines(lines);frame++;
  };
  const plain=message=>output.write(message+'\n');
  if(animated)render();
  else plain('Check setup → install plugin → verify installation. Next: permissions, then open Muse.');
  const timer=setInterval(()=>{
    if(animated)render();
    else if(clock()-lastPlain>=20000){plain(`${phase==='restore'?'Restoring previous plugin':rows.find(row=>row.id===phase)?.label||'Connecting to Muse'} · ${elapsed(clock()-started)} elapsed. ${note()}`);lastPlain=clock();}
  },120);
  const resize=()=>render();output.on?.('resize',resize);
  return {
    update(event){
      if(finished||event.status==='waiting'||!['check','install','verify','restore'].includes(event.phase))return;
      const next=event.phase,index=rows.findIndex(row=>row.id===next);
      if(index>=0)for(let i=0;i<rows.length;i++)rows[i].state=i<index?'done':i===index?'running':'waiting';
      else for(const row of rows)if(row.state==='running')row.state='waiting';
      phase=next;operation=event.operation;operationStarted=clock();timeoutMs=event.timeoutMs||120000;
      if(animated)render();else{plain(note());lastPlain=clock();}
    },
    cancel(){cancelling=true;render();if(!animated)plain(note());},
    finish({result,error}={}){
      if(finished)return;clearInterval(timer);output.off?.('resize',resize);clear();finished=true;
      if(error){
        writeLines([[`${error.code===130?'○ Setup cancelled':'! Plugin setup needs attention'} · ${elapsed(clock()-started)}`,error.code===130?'warning':'error']]);
      }else{
        const next=result?.reviewRequired?'Next: review permissions, then open Muse.':result?.state==='ready_for_new_session'?'Next: open Muse in this folder.':'Next: check Muse permissions.';
        writeLines([[`✓ ${result?.alreadyInstalled?'Existing plugin verified':'Plugin installed and verified'} · ${elapsed(clock()-started)}`,'success'],[next,'info']]);
      }
    }
  };
}
