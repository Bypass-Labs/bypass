import { createTheme } from './terminal-theme.mjs';
import { cells, clip } from './terminal-session.mjs';

const frames=['⠋','⠙','⠹','⠸','⠼','⠴','⠦','⠧','⠇','⠏'];
const elapsed=ms=>ms<60000?`${Math.floor(ms/1000)}s`:`${Math.floor(ms/60000)}m${Math.floor(ms/1000)%60?' '+Math.floor(ms/1000)%60+'s':''}`;
const details={inspect:'Looking for an existing Bypass plugin.',validate:'Muse is checking the plugin package.',remove:'Updating the previous plugin installation.',install:'Installing tools, commands and security memory.',disable:'Keeping your existing disabled setting.'};

// A short native operation needs immediate feedback too, especially after a
// permission choice. Keep machine output plain and finish before Muse takes over.
export function createSetupActivity({output=process.stderr,env=process.env,clock=Date.now}={}){
  const animated=!!output.isTTY&&env.TERM!=='dumb'&&!env.CI&&env.BYPASS_PLAIN!=='1';
  const {paint}=createTheme({output,env:animated?env:{...env,NO_COLOR:''}});
  return async(label,work)=>{
    const started=clock();let frame=0,lastPlain=started;
    const render=()=>{
      if(animated){
        const suffix=` · ${elapsed(clock()-started)}`;
        output.write('\r\x1b[2K'+paint('accent',`${frames[frame++%frames.length]} ${clip(label,Math.max(8,(output.columns||80)-cells(suffix)-4))}${suffix}`));
      }else if(clock()-lastPlain>=20000){output.write(`${label} · ${elapsed(clock()-started)} elapsed\n`);lastPlain=clock();}
    };
    if(animated)render();else output.write(label+'…\n');
    const timer=setInterval(render,120);
    try{
      const result=await work();
      clearInterval(timer);
      output.write((animated?'\r\x1b[2K':'')+paint('success',`✓ ${label}`)+'\n');
      return result;
    }catch(error){
      clearInterval(timer);
      output.write((animated?'\r\x1b[2K':'')+paint(error.code===130?'warning':'error',`${error.code===130?'○':'!'} ${label} — ${error.code===130?'cancelled':'not completed'}`)+'\n');
      throw error;
    }
  };
}

// Muse reports the result of each operation, not byte progress. Only advance
// the checklist on real service events; never infer completion from a timer.
export function createInstallProgress({output=process.stderr,env=process.env,clock=Date.now}={}){
  const animated=!!output.isTTY&&env.TERM!=='dumb'&&!env.CI&&env.BYPASS_PLAIN!=='1';
  const theme=createTheme({output,env:animated?env:{...env,NO_COLOR:''}});
  const rows=[{id:'check',label:'Check setup'},{id:'install',label:'Install plugin'},{id:'verify',label:'Verify installation'}];
  const started=clock();
  let phase='check',operation='inspect',operationStarted=started,timeoutMs=120000,finished=false,cancelling=false,frame=0,lastPlain=started;
  const width=()=>Math.max(12,(output.columns||80)-2);
  const clear=()=>{if(animated)output.write('\r\x1b[2K');};
  const note=()=>phase==='restore'?operation==='inspect'?'Checking the previous plugin before stopping.':'Restoring the previous plugin before stopping.':cancelling?'Stopping Muse; keeping your saved setup.':phase==='verify'?'Checking the installed plugin in Muse.':details[operation]||'Waiting for Muse.';
  const render=()=>{
    if(finished||!animated)return;
    clear();
    const label=rows.find(row=>row.id===phase)?.label||'Restore previous plugin';
    const detail=clock()-operationStarted>=30000&&!cancelling?'Waiting for Muse to finish.':note();
    const message=`${frames[frame++%frames.length]} ${label} · ${elapsed(clock()-operationStarted)} · ${detail}`;
    output.write(theme.paint(phase==='restore'?'warning':'accent',clip(message,width())));
  };
  const plain=message=>output.write(message+'\n');
  if(animated){output.write(theme.paint('muted',`Ctrl+C cancel · Muse timeout: ${elapsed(timeoutMs)}`)+'\n');render();}
  else plain('Check setup → install plugin → verify installation. Next: permissions, then open Muse.');
  const timer=setInterval(()=>{
    if(animated)render();
    else if(clock()-lastPlain>=20000){plain(`${phase==='restore'?'Restoring previous plugin':rows.find(row=>row.id===phase)?.label||'Connecting to Muse'} · ${elapsed(clock()-started)} elapsed. ${note()}`);lastPlain=clock();}
  },240);
  // A resize may reflow the previous line. Leave it in scrollback and begin a
  // fresh line rather than trying to move across terminal scroll boundaries.
  const resize=()=>{if(animated&&!finished){output.write('\n');render();}};output.on?.('resize',resize);
  return {
    update(event){
      if(finished||event.status==='waiting'||!['check','install','verify','restore'].includes(event.phase))return;
      const previous=rows.findIndex(row=>row.id===phase),next=rows.findIndex(row=>row.id===event.phase);
      if(animated&&event.phase!==phase){
        clear();
        if(next>previous&&previous>=0){
          for(let i=previous;i<next;i++)output.write(theme.paint('success',`✓ ${rows[i].label}`)+'\n');
        }else if(previous>=0)output.write(theme.paint('warning',`○ ${rows[previous].label}`)+'\n');
      }
      phase=event.phase;operation=event.operation;operationStarted=clock();timeoutMs=event.timeoutMs||120000;
      if(animated)render();else{plain(note());lastPlain=clock();}
    },
    cancel(){cancelling=true;render();if(!animated)plain(note());},
    finish({result,error}={}){
      if(finished)return;clearInterval(timer);output.off?.('resize',resize);clear();finished=true;
      if(error){
        plain(theme.paint(error.code===130?'warning':'error',`${error.code===130?'○ Setup cancelled':'! Plugin setup needs attention'} · ${elapsed(clock()-started)}`));
      }else{
        const next=result?.reviewRequired?'Next: review permissions, then open Muse.':result?.state==='ready_for_new_session'?'Next: open Muse in this folder.':'Next: check Muse permissions.';
        plain(theme.paint('success',`✓ ${result?.alreadyInstalled?'Existing plugin verified':'Plugin installed and verified'} · ${elapsed(clock()-started)}`));
        plain(theme.paint('info',next));
      }
    }
  };
}
