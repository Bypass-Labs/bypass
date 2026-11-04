import readline from 'node:readline';
import { format, stripVTControlCharacters } from 'node:util';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { Fault, redact, VERSION } from './util.mjs';
import { createTheme } from './terminal-theme.mjs';

export const commands = [
  ['review', 'Review the connected repository'],
  ['demo', 'Walk through proof, fix and regression'],
  ['blackbox', 'Audit an authorized running app'],
  ['engine', 'Real Docker agents and HTTP proof setup'],
  ['poc', 'Start a real AI POC with a separate local app'],
  ['results', 'Open results and their next action'],
  ['tests', 'Replay or export saved tests'],
  ['repo', 'Choose your application repository'],
  ['app', 'Connect an app or finish DNS verification'],
  ['models', 'Choose or test a model connection'],
  ['status', 'Show the repository and app pairing'],
  ['memory', 'Inspect remembered security rules and evidence'],
  ['context', 'Read security context for the next coding session'],
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
function wrapWords(text,width){
  const lines=[];
  for(const paragraph of safeText(text).split('\n')){
    let line='';
    for(const word of paragraph.split(/\s+/)){
      if(line&&cells(line+' '+word)>width){lines.push(line);line='';}
      if(cells(word)>width){const parts=wrap(word,width);if(line){lines.push(line);line='';}lines.push(...parts.slice(0,-1));line=parts.at(-1);}
      else line+=(line?' ':'')+word;
    }
    lines.push(line);
  }
  return lines;
}
const shortPath = value => String(value||'').replace(os.homedir()+'/', '~/');
const duration = ms => ms<60000 ? `${(ms/1000).toFixed(1)}s` : `${Math.floor(ms/60000)}m ${Math.floor(ms/1000)%60}s`;
const icons = {running:'◈',done:'✓',failed:'!',cancelled:'○',attention:'!',waiting:'◇'};

function livePanelLines(status,width,available,now){
  if(!status||available<3)return [];
  const fields=available>=9?[
    ['DONE',status.done],['WORKING',status.working&&`${status.working} · ${duration(now-status.since)}`],
    ['LIVE',status.metrics&&`${status.metrics} · last evidence ${duration(now-status.updatedAt)} ago`],
    ['WHY',status.why],['RECOVERED',status.recovered],['NEXT',status.next]
  ]:[
    ['WORKING',status.working&&`${status.working} · ${duration(now-status.since)}`],
    ['LIVE',status.metrics&&`${status.metrics} · last evidence ${duration(now-status.updatedAt)} ago`],
    ...(status.recovered?[['RECOVERED',status.recovered]]:[])
  ];
  const lines=[`─ LIVE AUDIT ${'─'.repeat(Math.max(0,width-13))}`],limit=Math.min(8,Math.max(3,available-1));
  for(const [label,text] of fields){
    if(!text||lines.length>=limit)continue;
    const wrapped=wrapWords(`${label.padEnd(10)} ${text}`,width).slice(0,available>=9?2:1);
    for(const line of wrapped){if(lines.length<limit)lines.push(line);}
  }
  return lines;
}

export function transcriptLines(state, width, {expanded=state.expanded, now=Date.now()}={}) {
  const lines=[];
  for(const entry of state.entries) {
    if(entry.type==='operation') {
      lines.push(...wrapWords(`${icons[entry.status]} ${entry.label} · ${duration((entry.ended||now)-entry.started)}${entry.status==='cancelled'?' · stopped':entry.status==='attention'?' · needs attention':''}`,width));
      if(expanded || entry.status==='running' || entry.status==='failed' || entry.status==='attention') {
        for(const detail of entry.details)lines.push(...wrapWords(detail,width-2).map(line=>'  '+line));
      }else if(entry.details.length)lines.push(`  ${entry.details.length} detail${entry.details.length===1?'':'s'} · Ctrl+O to expand`);
    }else lines.push(...wrapWords(entry.text,width));
    lines.push('');
  }
  return lines;
}

// A pure frame builder keeps narrow terminals, scrolling and cursor placement testable.
export function frame(state, columns, rows, now=Date.now()) {
  const width=Math.max(8,columns-2),height=Math.max(6,rows),lines=[];
  const row=(text='',tone='normal')=>({text:clip(text,width),tone});
  const put=(text='',tone='normal')=>lines.push(row(text,tone));
  const join=parts=>({text:parts.map(p=>p.text).join(''),parts,tone:'normal'});
  const divider='─'.repeat(width),wideLayout=width>=108&&height>=26;
  const project=state.context.title||'Connect your application';
  const mark=[{text:'▰╲',tone:'brand'},{text:'▰  BYPASS LABS',tone:'title'}];
  const version=`v${VERSION}`;
  if(width>=42)mark.push({text:' '.repeat(Math.max(2,width-16-version.length))+version,tone:'muted'});
  lines.push(width>=16?join(mark):row('BYPASS','brand'));
  const trustBar=state.operation?.label==='Black-box audit'?
    'LIVE REQUESTS · APPROVED SCOPE ONLY · EVIDENCE SAVED CONTINUOUSLY':
    state.operation?'WORKING · EVIDENCE SAVED CONTINUOUSLY · ESC STOPS SAFELY':
      state.pending&&!state.context.repo?'SETUP · CHOICES SAVE AS YOU GO · NO LIVE REQUESTS YET':
        'READY · EVIDENCE STAYS LOCAL · /HELP SHOWS COMMANDS';
  const compactBar=state.operation?.label==='Black-box audit'?'AUDIT LIVE · SCOPE GUARDED':
    state.operation?'WORKING · SAFE TO STOP · EVIDENCE SAVED':
      state.pending&&!state.context.repo?'SETUP · SAVES EACH CHOICE':'READY · LOCAL EVIDENCE · /HELP';
  put(wideLayout?trustBar:width>=72?`${project} · ${compactBar} · EVIDENCE SAVING`:compactBar,'muted');
  if(height>=20)put('─ ACTIVITY '+ '─'.repeat(Math.max(0,width-11)),'rule');

  const bottom=[],add=(text='',tone='normal')=>bottom.push(row(text,tone));
  const activeTask=state.tasks.find(task=>task.status==='running');
  const completed=state.tasks.filter(task=>task.status==='done').length;
  if(!wideLayout&&state.tasks.length&&height>=24&&state.tasksExpanded!==false){
    add(`${state.taskTitle} · ${completed}/${state.tasks.length} done`,'accent');
    const current=activeTask||state.tasks.find(task=>['failed','attention','cancelled'].includes(task.status))||state.tasks.find(task=>task.status==='waiting')||state.tasks.at(-1);
    add(` ${icons[current.status]||'◇'} ${current.label}`,taskTone(current.status));
  }
  if(height>=20){
    const current=state.operation?.label||activeTask?.label||(state.pending?.kind==='command'?'Ready for your next action':'Waiting for your choice');
    add(`NOW   ${current}${state.operation?` · ${duration(now-state.operation.started)}`:''}`,state.operation?'accent':'normal');
    add(`NEXT  ${state.next||'Choose an action below'}`,'info');
  }
  const menu=state.menu||[];
  if(menu.length){
    const count=Math.min(height>=30?5:height>=20?3:2,menu.length),start=Math.max(0,Math.min(state.selected-1,menu.length-count));
    for(let i=start;i<start+count;i++){
      const item=menu[i],selected=i===state.selected;
      add(`${selected?'›':' '} ${state.pending?.kind==='multiselect'?(state.pending.values.includes(item.id)?'[x] ':'[ ] '):state.pending?.kind==='select'?i+1+'  ':''}${item.label}${item.description&&width>=60?'  '+item.description:''}`,selected?'selection':'muted');
    }
    if(menu.length>count)add(`  ${state.selected+1}/${menu.length} · ↑↓ browse · ${state.pending?.kind==='multiselect'?'Space toggle':'Enter select'}`,'muted');
  }else if(state.input.startsWith('/')&&state.pending?.kind==='command')add('No match · Esc clears · /help lists commands','warning');
  add(divider,'rule');
  if(['question','select','multiselect'].includes(state.pending?.kind)){
    for(const line of wrapWords(state.pending.title.trim(),width).slice(0,height>=30?2:1))add(line,'title');
    if(state.pending.kind==='multiselect')add(`Selected: ${state.pending.values.join(', ')||'none'}`,'muted');
    if(state.pending.fallback&&height>=30)add(`Enter uses: ${state.pending.fallback}`,'muted');
  }
  const placeholder=state.pending?.kind==='command'?`Enter: ${state.recommended||'/review'}  ·  / commands`:state.pending?.kind==='multiselect'?'Or type a replacement list: GET,POST,PROPFIND':state.pending?.kind==='select'?(state.pending.allowCustom?'↑↓ choose · or type a custom value':'↑↓ choose · Enter confirm'):state.operation?'Working…':'Type your answer';
  const before=state.input.slice(0,state.cursor),budget=width-3;
  let offset=0;
  while(cells(before.slice(offset))>=budget&&offset<before.length)offset++;
  const visibleInput=state.pending?.secret?'•'.repeat([...state.input].length):state.input;
  const shown=clip(visibleInput.slice(offset),budget),composerRow=bottom.length;
  add(`› ${shown||(!state.input?(state.pending?.secret?'Paste key · input is hidden':placeholder):'')}`,state.input?'title':'muted');
  const hint=state.pending?.kind==='command'?'/ commands':state.pending?.kind==='multiselect'?'↑↓ move · Space toggle · Enter confirm':state.pending?.kind==='select'?'↑↓ select':'Enter continue';
  add(state.operation?`${state.operation.cancelable?'Esc stop':'Finishing step'}${state.operation.skipOnEnter?' · Enter skip':''} · Ctrl+O details · Ctrl+C exit`:height<18?'Ctrl+C exit · Esc back':`${hint} · Ctrl+O details${width>=100?' · Ctrl+T tasks':''} · Esc back · Ctrl+C exit`,'muted');

  const available=Math.max(0,height-lines.length-bottom.length);
  const sideWidth=wideLayout?32:0,mainWidth=wideLayout?width-sideWidth-3:width;
  const livePanel=state.operation?livePanelLines(state.liveStatus,mainWidth,available,now):[];
  const transcriptAvailable=Math.max(0,available-livePanel.length);
  const transcript=transcriptLines(state,mainWidth,{now}),maxScroll=Math.max(0,transcript.length-transcriptAvailable);
  const scroll=Math.min(state.scroll,maxScroll),end=transcript.length-scroll;
  const visible=transcript.slice(Math.max(0,end-transcriptAvailable),end);
  if(scroll&&visible.length)visible[0]=`↑ Earlier activity · PgDn to return to latest`;
  while(visible.length<transcriptAvailable)visible.push('');
  visible.push(...livePanel);
  const sidebar=[];
  const side=(text='',tone='muted')=>wrapWords(text,sideWidth-2).forEach(text=>sidebar.push({text:' '+text,tone}));
  if(wideLayout){
    if(state.tasks.length&&state.tasksExpanded!==false){
      side(state.taskTitle.toUpperCase(),'title');
      const filled=Math.round(completed/state.tasks.length*12);
      side(`${'━'.repeat(filled)}${'─'.repeat(12-filled)}  ${completed}/${state.tasks.length} done`,'accent');
      const index=Math.max(0,state.tasks.findIndex(task=>task.status==='running'));
      const tasks=available>=19?state.tasks:state.tasks.slice(Math.max(0,index-1),Math.max(0,index-1)+3);
      for(const task of tasks)side(`${icons[task.status]||'◇'} ${task.label}`,taskTone(task.status));
      if(tasks.length<state.tasks.length)side('Ctrl+T hide tasks · /status');
      side();
    }
    side('PROJECT','title');
    side(shortPath(state.context.repo)||(state.context.app?'Running app only · no repository needed':'Choose your application source'));
    side();side('LIVE APP','title');side(state.context.app||'Optional · connect with /app');
    side();side('MODEL','title');side(state.context.model||'API key for CLI · /models');
    if(state.context.checks!==undefined){side();side(`${state.context.checks} saved tests · ${state.context.memory||0} memories`,'success');}
    if(!state.tasks.length){side();side('EXPLORE','title');side('/demo     Guided proof loop','info');side('/help     All commands','info');}
  }
  for(let i=0;i<available;i++){
    const text=clip(visible[i],mainWidth),tone=activityTone(text);
    if(wideLayout){
      const right=sidebar[i]||{text:'',tone:'muted'};
      lines.push(join([{text:text+' '.repeat(Math.max(0,mainWidth-cells(text))),tone},{text:' │ ',tone:'rule'},{text:clip(right.text,sideWidth),tone:right.tone}]));
    }else put(text,tone);
  }
  const inputRow=lines.length+composerRow+1;
  lines.push(...bottom);
  const cursorText=state.pending?.secret?'•'.repeat([...before].length):before.slice(offset);
  return {lines:lines.slice(0,height),cursor:{row:Math.min(height,inputRow),column:Math.min(columns,4+cells(cursorText))},maxScroll};
}
const taskTone=status=>status==='done'?'success':status==='running'?'accent':status==='failed'?'error':['attention','cancelled'].includes(status)?'warning':'muted';
const activityTone=text=>/^DONE\s/.test(text)?'success':/^WORKING\s/.test(text)?'accent':/^RECOVERED\s/.test(text)?'info':/^─ LIVE AUDIT/.test(text)?'title':/^LIVE\s/.test(text)?'muted':/^✓/.test(text)?'success':/^!|^Error|failed/i.test(text)?'warning':/^›/.test(text)?'accent':/^Step \d|^BYPASS|^Setup saved/.test(text)?'title':/^  \d+ details?/.test(text)?'muted':'normal';

export function paintFrameLine(line,theme,width){
  const parts=line.parts||[{text:line.text,tone:line.tone}];
  const content=parts.map(part=>theme.paint(part.tone,part.text,{surface:true})).join('');
  return theme.paint('normal',' ',{surface:true})+content+theme.paint(line.tone||'normal',' '.repeat(Math.max(0,width-cells(line.text))),{surface:true});
}

export function createTerminalSession({input=process.stdin,output=process.stdout,captureConsole=true,clock=Date.now,env=process.env}={}) {
  const controller=new AbortController();
  const state={context:{},entries:[],tasks:[],taskTitle:'Progress',next:'Connect your repository, then preview or try /demo',recommended:'/review',input:'',cursor:0,pending:null,operation:null,liveStatus:null,menu:[],selected:0,expanded:false,tasksExpanded:true,scroll:0};
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
  const theme=createTheme({output,env});
  const render=()=>{
    if(closed||!dirty&&!state.operation)return;
    dirty=false;
    const view=frame(state,output.columns||80,output.rows||24,clock());
    state.scroll=Math.min(state.scroll,view.maxScroll);
    output.write('\x1b[?25l\x1b[H'+view.lines.map(line=>'\x1b[2K'+paintFrameLine(line,theme,(output.columns||80)-1)).join('\r\n')+`\x1b[${view.cursor.row};${view.cursor.column}H${state.pending?'\x1b[?25h':''}`);
  };
  const setInput=value=>{state.input=value;state.cursor=value.length;updateMenu();mark();};
  const updateMenu=()=>{
    if(state.pending?.kind==='command'&&state.input.startsWith('/')) {
      const query=state.input.slice(1).toLowerCase();
      state.menu=commands.filter(command=>command.id.startsWith(query));state.selected=0;
    }else if(!['select','multiselect'].includes(state.pending?.kind))state.menu=[];
  };
  const complete=(answer,error)=>{
    const pending=state.pending;if(!pending)return;
    state.pending=null;state.menu=[];setInput('');state.scroll=0;
    if(error)pending.reject(error);
    else {const title=pending.title.trim().replace(/ \(Enter to continue, q to leave\)$/,'');write(`› ${pending.kind==='command'?answer:title+'  '+(pending.secret?'[hidden]':pending.items?.find(item=>item.value===answer)?.label||answer?.value||answer||'continue')}`);pending.resolve(answer);}
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
    if(key.ctrl&&key.name==='t'){state.tasksExpanded=!state.tasksExpanded;mark();return;}
    if(key.name==='pageup'||key.name==='pagedown'){state.scroll=Math.max(0,state.scroll+(key.name==='pageup'?1:-1)*Math.max(3,(output.rows||24)-12));mark();return;}
    if(key.name==='escape'){
      if(state.operation){if(state.operation.cancelable)state.operation.controller.abort(cancel());else write('This step must finish before leaving.');}
      else if(state.input)setInput('');
      else if(state.pending?.kind==='select'&&state.pending.back)complete(null);
      else if(state.pending?.kind!=='command')complete(undefined,cancel());
      return;
    }
    if(state.operation){if(state.operation.skipOnEnter&&['return','enter'].includes(key.name))state.operation.controller.abort(new Fault('Connection check skipped.',130,{skipped:true}));return;}
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
    if(key.name==='tab'){if(state.menu.length){if(['select','multiselect'].includes(state.pending.kind))state.selected=(state.selected+1)%state.menu.length;else setInput(state.menu[state.selected].label);}mark();return;}
    if(state.pending.kind==='multiselect'&&!state.input&&(key.name==='space'||str===' ')){
      const value=state.menu[state.selected]?.id;if(value)state.pending.values=state.pending.values.includes(value)?state.pending.values.filter(v=>v!==value):[...state.pending.values,value];mark();return;
    }
    if(['return','enter'].includes(key.name)) {
      if(state.pending.kind==='multiselect'){
        const values=state.input.trim()?state.input.trim().split(/[,\s]+/).filter(Boolean):state.pending.values;
        if(!values.length){write('Choose at least one method, or type a custom list.');return;}
        complete(values);return;
      }
      if(state.pending.kind==='select') {
        if(['0','q','back'].includes(state.input)&&state.pending.back){complete(null);return;}
        const selected=state.input?state.menu[Number(state.input)-1]:state.menu[state.selected];
        if(!selected&&state.pending.allowCustom&&state.input.trim()){complete({custom:true,value:state.input.trim()});return;}
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
  const secret=title=>question(title,'',{secret:true});
  ask.secret=secret;
  const select=(title,items,{fallback=0,back=false,allowCustom=false}={})=>question(title,'',{kind:'select',items:items.map((item,i)=>({...item,label:item.label||item.name||item.id,value:String(i)})),selected:fallback,back,allowCustom}).then(value=>value===null?null:typeof value==='object'?value:items[Number(value)]);
  ask.select=select;
  const multiselect=(title,items,{selected=[]}={})=>question(title,'',{kind:'multiselect',items,values:[...selected]});
  ask.multiselect=multiselect;
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
    finally{operation.ended=clock();state.operation=null;state.liveStatus=null;mark();render();}
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
  write('Security that stays with your code.\n\nAudit a running app or review a repository. Prove the issue. Keep the fix as a test.\n\n/ commands     /demo guided walkthrough     Ctrl+O activity details');
  render();
  return {rich:true,ask,secret,select,multiselect,write,activity,run:work=>activity('Check model connection',work,{skipOnEnter:true}),signal:controller.signal,
    command:(fallback)=>{state.recommended='/'+fallback;historyIndex=history.length;return question('Choose your next action',fallback,{kind:'command'});},
    setContext:context=>{state.context={...state.context,...context};mark();},
    setNext:next=>{state.next=next;mark();},
    setLiveStatus:status=>{
      if(!status){state.liveStatus=null;mark();return;}
      const previous=state.liveStatus,stamp=clock(),working=safeText(status.working||previous?.working||'Continuing the audit');
      state.liveStatus={...previous,...status,working,
        since:previous?.working===working?previous.since:stamp,updatedAt:stamp};mark();
    },
    setTasks:(title,tasks)=>{state.taskTitle=title;state.tasks=tasks.map(label=>({label,status:'waiting'}));mark();},
    task:(index,status)=>{if(state.tasks[index])state.tasks[index].status=status;mark();},
    stopTasks:(status='cancelled')=>{for(const task of state.tasks)if(task.status==='running')task.status=status;mark();},
    close, state,
  };
}
