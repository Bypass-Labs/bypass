import readline from 'node:readline';
import { format, stripVTControlCharacters } from 'node:util';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { Fault, redact } from './util.mjs';

export const commands = [
  ['review', 'Review the connected repository'],
  ['demo', 'Walk through proof, fix and regression'],
  ['engine', 'Real Docker agents and HTTP proof setup'],
  ['poc', 'Start a real AI POC with a separate local app'],
  ['results', 'Open results and their next action'],
  ['tests', 'Replay or export saved tests'],
  ['repo', 'Choose your application repository'],
  ['app', 'Connect an app or finish DNS verification'],
  ['models', 'Choose or test a model connection'],
  ['status', 'Show the repository and app pairing'],
  ['history', 'Show saved project activity'],
  ['settings', 'All settings and advanced controls'],
  ['plugin', 'Check or install the Muse plugin'],
  ['help', 'Commands and keyboard shortcuts'],
  ['quit', 'Save this session and exit'],
].map(([id, description]) => ({ id, label: `/${id}`, description }));

// Never interpret terminal controls received from repository names, commands or output.
export const safeText = value => stripVTControlCharacters(String(value)).replace(/[\x00-\x08\x0b-\x1f\x7f-\x9f]/g, '').replace(/\t/g, '  ');
const segments = new Intl.Segmenter(undefined, { granularity: 'grapheme' });
const wide = text => /\p{Extended_Pictographic}/u.test(text) || /[\u1100-\u115f\u2329\u232a\u2e80-\ua4cf\uac00-\ud7a3\uf900-\ufaff\ufe10-\ufe19\ufe30-\ufe6f\uff01-\uff60\uffe0-\uffe6\u{20000}-\u{3ffff}]/u.test(text);
export const cells = text => [...segments.segment(safeText(text))].reduce((n, {segment}) => n + (/^[\p{Mark}\u200d\ufe0f]+$/u.test(segment) ? 0 : wide(segment) ? 2 : 1), 0);
export function clip(text, width) {
  let out='', used=0;
  for (const {segment} of segments.segment(safeText(text))) { const size=cells(segment); if(used+size>width)break; out+=segment;used+=size; }
  return out;
}
export function wrap(text, width) {
  const lines=[];
  for(const paragraph of safeText(text).split('\n')) {
    let line='', used=0;
    for(const {segment} of segments.segment(paragraph)) {const size=cells(segment);if(used+size>width) {lines.push(line);line='';used=0;} line+=segment;used+=size;}
    lines.push(line);
  }
  return lines;
}
const shortPath = value => String(value||'').replace(os.homedir()+'/', '~/');
const duration = ms => ms<60000 ? `${(ms/1000).toFixed(1)}s` : `${Math.floor(ms/60000)}m ${Math.floor(ms/1000)%60}s`;
const icons = {running:'◈',done:'✓',failed:'!',cancelled:'○',attention:'!',waiting:'◇'};

export function transcriptLines(state, width, {expanded=state.expanded, now=Date.now()}={}) {
  const lines=[];
  for(const entry of state.entries) {
    if(entry.type==='operation') {
      lines.push(...wrap(`${icons[entry.status]} ${entry.label} · ${duration((entry.ended||now)-entry.started)}${entry.status==='cancelled'?' · stopped':entry.status==='attention'?' · needs attention':''}`,width));
      if(expanded || entry.status==='running' || entry.status==='failed' || entry.status==='attention') {
        for(const detail of entry.details)lines.push(...wrap(detail,width-2).map(line=>'  '+line));
      }else if(entry.details.length)lines.push(`  ${entry.details.length} detail${entry.details.length===1?'':'s'} · Ctrl+O to expand`);
    }else lines.push(...wrap(entry.text,width));
    lines.push('');
  }
  return lines;
}

// A pure frame builder keeps narrow terminals, scrolling and cursor placement testable.
export function frame(state, columns, rows, now=Date.now()) {
  const width=Math.max(8,columns-2), height=Math.max(6,rows), lines=[];
  const put=(text='',tone='normal')=>lines.push({text:clip(text,width),tone});
  const divider='─'.repeat(width);
  put(`BYPASS  /  ${state.context.title||'Connect your application'}`, 'title');
  if(height>=18) {
    put(state.context.repo?`Repo   ${shortPath(state.context.repo)}${state.context.branch?' · '+state.context.branch:''}`:'Repo   choose the application you want to review','muted');
    put(`App    ${state.context.app||'optional · add a deployed URL during setup'}`, 'muted');
    put(`Model  ${state.context.model||'Muse subscription · local · self-hosted'}`, 'muted');
  }
  put(state.context.engine==='docker'?(width<70?'POC · real Docker agents · bounded scope':'POC · real Docker agents · source hypotheses + observed HTTP proof'):(width<70?'Offline preview · simulated discovery':'Offline preview · simulated discovery; use /engine for real AI'),'warning');
  put(divider,'rule');

  const bottom=[];
  const add=(text='',tone='normal')=>bottom.push({text:clip(text,width),tone});
  if(state.tasks.length&&height>=22) {
    const done=state.tasks.filter(task=>task.status==='done').length;
    add(`${state.taskTitle}  ${done}/${state.tasks.length} completed`,'accent');
    let index=state.tasks.findIndex(task=>task.status==='running');
    if(index<0)index=state.tasks.findIndex(task=>task.status==='waiting');
    if(index<0)index=state.tasks.length-1;
    const visible=height>=34?state.tasks:state.tasks.slice(Math.max(0,index-1),Math.max(0,index-1)+2);
    for(const task of visible)add(` ${icons[task.status]||'◇'} ${task.label}`,task.status==='running'?'accent':'muted');
  }
  if(height>=16) {
    add(`Now   ${state.operation?.label||state.tasks.find(task=>task.status==='running')?.label||(state.pending?.kind==='command'?'Ready for your next action':'Waiting for your choice')}`,state.operation?'accent':'normal');
    add(`Next  ${state.next||'Choose a command below'}`,'muted');
  }
  const menu=state.menu||[];
  if(menu.length) {
    const count=Math.min(height>=28?5:3,menu.length), start=Math.max(0,Math.min(state.selected-1,menu.length-count));
    for(let i=start;i<start+count;i++) {
      const item=menu[i], prefix=i===state.selected?'›':' ';
      add(`${prefix} ${state.pending?.kind==='select'?i+1+'  ':''}${item.label}${item.description?'  '+item.description:''}`,i===state.selected?'selection':'muted');
    }
    if(menu.length>count)add(`  ${state.selected+1}/${menu.length} · ↑↓ browse · Enter select`,'muted');
  }else if(state.input.startsWith('/')&&state.pending?.kind==='command')add('No matching command · Esc clears · /help lists commands','warning');
  add(divider,'rule');
  if(state.pending?.kind==='question' || state.pending?.kind==='select') {
    for(const line of wrap(state.pending.title,width).slice(0,height<20?1:2))add(line,'title');
    if(state.pending.fallback&&height>=20)add(`Enter uses: ${state.pending.fallback}`,'muted');
  }
  const placeholder=state.pending?.kind==='command'?`Enter: ${state.recommended||'/review'}  ·  / commands`:state.pending?.kind==='select'?'↑↓ choose · Enter confirm':state.operation?'Working…':'Type your answer';
  // Horizontal scrolling keeps the caret visible, even on long pasted paths.
  const before=state.input.slice(0,state.cursor), budget=width-3;
  let offset=0;
  while(cells(before.slice(offset))>=budget&&offset<before.length)offset++;
  const shown=clip(state.input.slice(offset),budget);
  const composerRow=bottom.length;
  add(`› ${shown||(!state.input?placeholder:'')}`,state.input?'normal':'muted');
  const hint=state.pending?.kind==='command'?'/ commands':state.pending?.kind==='select'?'↑↓ select':'Enter continue';
  add(state.operation?`${state.operation.cancelable?'Esc stop':'Finishing step'}${state.operation.skipOnEnter?' · Enter skip':''} · Ctrl+C exit`:height<18?'Ctrl+C exit · Esc back':`${hint} · Ctrl+O details${width>=78?' · PgUp/PgDn scroll':''} · Esc back · Ctrl+C exit`,'muted');

  const available=Math.max(0,height-lines.length-bottom.length);
  const transcript=transcriptLines(state,width,{now});
  const maxScroll=Math.max(0,transcript.length-available);
  const scroll=Math.min(state.scroll,maxScroll);
  const end=transcript.length-scroll;
  const visible=transcript.slice(Math.max(0,end-available),end);
  if(scroll&&visible.length)visible[0]=`↑ Earlier activity · ${scroll} lines above latest · PgDn to return`;
  for(const text of visible)put(text,text.startsWith('✓')?'success':text.startsWith('!')?'warning':'normal');
  while(lines.length<height-bottom.length)put();
  const inputRow=lines.length+composerRow+1;
  lines.push(...bottom);
  return {lines:lines.slice(0,height),cursor:{row:Math.min(height,inputRow),column:Math.min(columns,4+cells(before.slice(offset)))},maxScroll};
}

export function createTerminalSession({input=process.stdin,output=process.stdout,captureConsole=true,clock=Date.now}={}) {
  const controller=new AbortController();
  const state={context:{},entries:[],tasks:[],taskTitle:'Progress',next:'Connect your repository, then preview or try /demo',recommended:'/review',input:'',cursor:0,pending:null,operation:null,menu:[],selected:0,expanded:false,scroll:0};
  let closed=false,dirty=true,pasting=false,pasteBuffer='',historyIndex=0,historyDraft='',transcriptPath;
  const history=[],original={log:console.log,error:console.error,warn:console.warn},wasRaw=input.isRaw;
  const mark=()=>{dirty=true;};
  const write=value=>{
    const text=safeText(redact(String(value))).trim();if(!text)return;
    if(state.operation)state.operation.details.push(text);
    else state.entries.push({type:'message',text});
    if(state.entries.length>500)state.entries.splice(0,state.entries.length-500);
    if(state.operation?.details.length>500)state.operation.details.shift();
    state.scroll=0;mark();
  };
  if(captureConsole)for(const key of Object.keys(original))console[key]=(...args)=>write(format(...args));
  const colors={title:'1;38;5;153',accent:'38;5;153',success:'38;5;150',warning:'38;5;222',muted:'90',rule:'38;5;238',selection:'1;38;5;150',normal:'0'};
  const render=()=>{
    if(closed||!dirty&&!state.operation)return;
    dirty=false;
    const view=frame(state,output.columns||80,output.rows||24,clock());
    state.scroll=Math.min(state.scroll,view.maxScroll);
    output.write('\x1b[?25l\x1b[H'+view.lines.map(line=>`\x1b[2K ${process.env.NO_COLOR?'':`\x1b[${colors[line.tone]}m`}${line.text}\x1b[0m`).join('\r\n')+`\x1b[${view.cursor.row};${view.cursor.column}H${state.pending?'\x1b[?25h':''}`);
  };
  const setInput=value=>{state.input=value;state.cursor=value.length;updateMenu();mark();};
  const updateMenu=()=>{
    if(state.pending?.kind==='command'&&state.input.startsWith('/')) {
      const query=state.input.slice(1).toLowerCase();
      state.menu=commands.filter(command=>command.id.startsWith(query));state.selected=0;
    }else if(state.pending?.kind!=='select')state.menu=[];
  };
  const complete=(answer,error)=>{
    const pending=state.pending;if(!pending)return;
    state.pending=null;state.menu=[];setInput('');state.scroll=0;
    if(error)pending.reject(error);
    else {write(`› ${pending.kind==='command'?answer:pending.title+'  '+(pending.items?.find(item=>item.value===answer)?.label||answer||'continue')}`);pending.resolve(answer);}
  };
  const cancel=()=>new Fault('Action stopped. Your saved progress is retained.',130,{cancelled:true});
  const shutdown=()=>{
    if(controller.signal.aborted)return;
    controller.abort(new Fault('Session ended. Your saved progress is retained.',130));
    state.operation?.controller.abort(controller.signal.reason);
    complete(undefined,controller.signal.reason);mark();
  };
  const onKey=(str,key={})=>{
    const sequence=key.sequence||str;
    if(sequence==='\x1b[200~'){pasting=true;pasteBuffer='';return;}
    if(sequence==='\x1b[201~'){pasting=false;insert(pasteBuffer.replace(/[\r\n]+/g,' '));pasteBuffer='';return;}
    if(pasting){if(str)pasteBuffer+=str;return;}
    if(key.ctrl&&key.name==='c'){shutdown();return;}
    if(key.ctrl&&key.name==='o'){state.expanded=!state.expanded;mark();return;}
    if(key.name==='pageup'||key.name==='pagedown'){state.scroll=Math.max(0,state.scroll+(key.name==='pageup'?1:-1)*Math.max(3,(output.rows||24)-12));mark();return;}
    if(key.name==='escape'){
      if(state.operation){if(state.operation.cancelable)state.operation.controller.abort(cancel());else write('This step must finish before leaving.');}
      else if(state.input)setInput('');
      else if(state.pending?.kind==='select'&&state.pending.back)complete(null);
      else if(state.pending?.kind!=='command')complete(undefined,cancel());
      return;
    }
    if(state.operation){if(state.operation.skipOnEnter&&key.name==='return')state.operation.controller.abort(new Fault('Connection check skipped.',130,{skipped:true}));return;}
    if(!state.pending)return;
    if(key.ctrl&&key.name==='d'&&!state.input){shutdown();return;}
    if(key.ctrl&&key.name==='l'){state.scroll=0;mark();return;}
    if(key.name==='up'||key.name==='down'){
      const direction=key.name==='up'?-1:1;
      if(state.menu.length)state.selected=(state.selected+direction+state.menu.length)%state.menu.length;
      else if(state.pending.kind==='command'){
        if(historyIndex===history.length)historyDraft=state.input;
        historyIndex=Math.max(0,Math.min(history.length,historyIndex+direction));setInput(historyIndex===history.length?historyDraft:history[historyIndex]);
      }
      mark();return;
    }
    if(key.name==='tab'){if(state.menu.length){if(state.pending.kind==='select')state.selected=(state.selected+1)%state.menu.length;else setInput(state.menu[state.selected].label);}mark();return;}
    if(key.name==='return') {
      if(state.pending.kind==='select') {
        if(['0','q','back'].includes(state.input)&&state.pending.back){complete(null);return;}
        const selected=state.input?state.menu[Number(state.input)-1]:state.menu[state.selected];
        if(selected){complete(selected.value);return;}write('Use ↑↓ and Enter, or type a listed number.');setInput('');return;
      }
      const value=(state.pending.kind==='command'&&state.menu.length?state.menu[state.selected].label:state.input.trim())||state.pending.fallback;
      if(state.pending.kind==='command'&&value){if(history.at(-1)!==value)history.push(value);historyIndex=history.length;}
      complete(value);return;
    }
    if(key.name==='left'){state.cursor=Math.max(0,state.cursor-([...state.input.slice(0,state.cursor)].at(-1)?.length||1));mark();return;}
    if(key.name==='right'){state.cursor=Math.min(state.input.length,state.cursor+([...state.input.slice(state.cursor)][0]?.length||1));mark();return;}
    if(key.name==='home'||key.ctrl&&key.name==='a'){state.cursor=0;mark();return;}
    if(key.name==='end'||key.ctrl&&key.name==='e'){state.cursor=state.input.length;mark();return;}
    if(key.ctrl&&key.name==='u'){setInput(state.input.slice(state.cursor));state.cursor=0;return;}
    if(key.ctrl&&key.name==='k'){setInput(state.input.slice(0,state.cursor));return;}
    if(key.name==='backspace'){const size=[...state.input.slice(0,state.cursor)].at(-1)?.length||0;state.input=state.input.slice(0,state.cursor-size)+state.input.slice(state.cursor);state.cursor-=size;updateMenu();mark();return;}
    if(key.name==='delete'){state.input=state.input.slice(0,state.cursor)+state.input.slice(state.cursor+([...state.input.slice(state.cursor)][0]?.length||0));updateMenu();mark();return;}
    if(str&&!key.ctrl&&!key.meta&&!str.includes('\x1b'))insert(str);
  };
  function insert(value){if(!state.pending||state.operation)return;const text=safeText(value).replace(/[\r\n]/g,' ').slice(0,8192-state.input.length);state.input=state.input.slice(0,state.cursor)+text+state.input.slice(state.cursor);state.cursor+=text.length;updateMenu();mark();}
  function question(title,fallback='',extra={}) {
    if(closed)return Promise.reject(new Fault('This terminal session has closed.',130));
    if(controller.signal.aborted)return Promise.reject(controller.signal.reason);
    if(state.pending)return Promise.reject(new Error('A terminal question is already active.'));
    return new Promise((resolve,reject)=>{state.pending={kind:'question',title,fallback,resolve,reject,...extra};state.input='';state.cursor=0;state.scroll=0;state.menu=extra.items||[];state.selected=extra.selected||0;mark();render();});
  }
  const ask=(title,fallback='')=>question(title,fallback);
  const select=(title,items,{fallback=0,back=false}={})=>question(title,'',{kind:'select',items:items.map((item,i)=>({...item,label:item.label||item.name||item.id,value:String(i)})),selected:fallback,back}).then(value=>value===null?null:items[Number(value)]);
  ask.select=select;
  async function activity(label,work,{skipOnEnter=false,cancelable=true,verdict}={}) {
    if(controller.signal.aborted)throw controller.signal.reason;
    if(state.operation)return work(state.operation.controller.signal);
    const operation={type:'operation',label,status:'running',started:clock(),details:[],controller:new AbortController(),skipOnEnter,cancelable};
    state.entries.push(operation);state.operation=operation;state.scroll=0;mark();render();
    try {
      const result=await work(operation.controller.signal);
      operation.status=operation.controller.signal.aborted?'cancelled':verdict?verdict(result):'done';
      if(operation.controller.signal.aborted)throw operation.controller.signal.reason;
      return result;
    }catch(error){operation.status=operation.controller.signal.aborted||error.code===130?'cancelled':'failed';operation.details.push(safeText(redact(error.message)));throw error;}
    finally{operation.ended=clock();state.operation=null;mark();render();}
  }
  const onResize=()=>{mark();render();};
  const onEnd=()=>shutdown();
  readline.emitKeypressEvents(input,{escapeCodeTimeout:50});input.setRawMode(true);input.on('keypress',onKey);input.on('end',onEnd);output.on('resize',onResize);
  input.resume();
  output.write('\x1b[?1049h\x1b[?2004h\x1b[2J\x1b[H');
  const interval=setInterval(render,100);
  process.once('SIGTERM',shutdown);
  process.once('SIGINT',shutdown);
  const close=()=>{
    if(closed)return;closed=true;clearInterval(interval);
    input.off('keypress',onKey);input.off('end',onEnd);output.off('resize',onResize);process.off('SIGTERM',shutdown);process.off('SIGINT',shutdown);
    input.setRawMode(Boolean(wasRaw));input.pause();
    output.write('\x1b[0m\x1b[?25h\x1b[?2004l\x1b[?1049l');
    if(captureConsole)Object.assign(console,original);
    if(state.context.repo&&fs.existsSync(path.join(state.context.repo,'.bypass'))) {
      try{const dir=path.join(state.context.repo,'.bypass/sessions');fs.mkdirSync(dir,{recursive:true});transcriptPath=path.join(dir,`session-${new Date().toISOString().replace(/[:.]/g,'-')}.txt`);fs.writeFileSync(transcriptPath,transcriptLines(state,120,{expanded:true}).join('\n'),{mode:0o600});}catch{output.write('Session transcript could not be saved. Project evidence is still stored in .bypass.\n');}
    }
    if(transcriptPath)output.write(`Session transcript: ${transcriptPath}\n`);
  };
  write('Your security workspace\nConnect source + app, review the evidence, and keep fixes as tests.\nType / to browse commands. Enter always shows the suggested next action.');
  render();
  return {rich:true,ask,select,write,activity,run:work=>activity('Check model connection',work,{skipOnEnter:true}),signal:controller.signal,
    command:(fallback)=>{state.recommended='/'+fallback;historyIndex=history.length;return question('Choose your next action',fallback,{kind:'command'});},
    setContext:context=>{state.context={...state.context,...context};mark();},
    setNext:next=>{state.next=next;mark();},
    setTasks:(title,tasks)=>{state.taskTitle=title;state.tasks=tasks.map(label=>({label,status:'waiting'}));mark();},
    task:(index,status)=>{if(state.tasks[index])state.tasks[index].status=status;mark();},
    stopTasks:(status='cancelled')=>{for(const task of state.tasks)if(task.status==='running')task.status=status;mark();},
    close, state,
  };
}
