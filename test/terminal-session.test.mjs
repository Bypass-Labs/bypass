import test from 'node:test';
import assert from 'node:assert/strict';
import { PassThrough } from 'node:stream';
import { createTerminalSession, frame, transcriptLines, cells, safeText } from '../src/terminal-session.mjs';
import { execute } from '../src/service.mjs';
import { createRun } from '../src/engine.mjs';
import { watchRun } from '../src/jobs.mjs';
import { read } from '../src/store.mjs';
import { Fault } from '../src/util.mjs';
import { createTheme } from '../src/terminal-theme.mjs';
import { temp } from './helpers.mjs';
import { methodChoices, promptMethods } from '../src/http-methods.mjs';
import { promptValue, confirmChoice } from '../src/interaction.mjs';

function terminal(t,columns=90,rows=30) {
  const input=new PassThrough(),output=new PassThrough();let raw=false,bytes='';
  input.setRawMode=value=>{raw=value;input.isRaw=value;};
  Object.assign(output,{columns,rows});output.on('data',data=>{bytes+=data;});
  const ui=createTerminalSession({input,output,captureConsole:false});
  t.after(()=>ui.close());
  return {ui,input,output,key:(name,extra={})=>input.emit('keypress',undefined,{name,...extra}),type:value=>input.write(value),get raw(){return raw;},get bytes(){return bytes;}};
}

test('slash search, arrow selection, completion and command history work with real key parsing',async t=>{
  const tty=terminal(t);
  let answer=tty.ui.command('review');tty.type('/mod');
  assert.deepEqual(tty.ui.state.menu.map(item=>item.id),['models']);
  tty.key('tab');assert.equal(tty.ui.state.input,'/models');tty.key('return');assert.equal(await answer,'/models');
  answer=tty.ui.command('review');tty.key('up');assert.equal(tty.ui.state.input,'/models');tty.key('return');assert.equal(await answer,'/models');
  answer=tty.ui.command('review');tty.type('/');tty.key('down');tty.key('return');assert.equal(await answer,'/demo');
  answer=tty.ui.command('review');tty.key('return');assert.equal(await answer,'review');
});

test('a line-feed Enter selects blackbox without a false no-match warning',async t=>{
  const tty=terminal(t);
  const answer=tty.ui.command('review');tty.type('/blackbox\n');
  assert.equal(await answer,'/blackbox');
  assert.doesNotMatch(transcriptLines(tty.ui.state,100).join('\n'),/No match/);
});

test('bracketed multiline paste fills one answer and never submits extra commands',async t=>{
  const tty=terminal(t);let resolved=false;
  const answer=tty.ui.ask('Repository').then(value=>{resolved=true;return value;});
  tty.type('\x1b[200~https://github.com/org/app\n/quit\x1b[201~');
  await Promise.resolve();assert.equal(resolved,false);assert.equal(tty.ui.state.input,'https://github.com/org/app /quit');
  tty.key('return');assert.equal(await answer,'https://github.com/org/app /quit');
});

test('masked secret input never enters the frame, activity transcript, or terminal bytes',async t=>{
  const tty=terminal(t),raw='LLM_TEST_SECRET_8Qx2';
  const answer=tty.ui.secret('Meta Model API key');tty.type(raw);
  const view=frame(tty.ui.state,90,30).lines.map(line=>line.text).join('\n');
  assert.doesNotMatch(view,new RegExp(raw));assert.match(view,/•{8}/);
  tty.key('return');assert.equal(await answer,raw);
  assert.doesNotMatch(transcriptLines(tty.ui.state,100,{expanded:true}).join('\n'),new RegExp(raw));
  assert.match(transcriptLines(tty.ui.state,100).join('\n'),/Meta Model API key \[hidden\]/);
  assert.doesNotMatch(tty.bytes,new RegExp(raw));
});

test('menus accept arrows, numbers and Escape without abandoning the workspace',async t=>{
  const tty=terminal(t),items=[{label:'First',id:1},{label:'Second',id:2}];
  let answer=tty.ui.select('Choose',items,{back:true});tty.key('down');tty.key('return');assert.equal((await answer).id,2);
  answer=tty.ui.select('Choose',items,{back:true});tty.key('escape');assert.equal(await answer,null);
  answer=tty.ui.select('Choose',items);tty.type('1');tty.key('return');assert.equal((await answer).id,1);
  answer=tty.ui.select('Model',[{name:'local',provider:'custom','secret-env':'BYPASS_UNIT_API_KEY',stream:false}]);assert.equal(tty.ui.state.menu[0].label,'local');tty.key('return');assert.equal((await answer).name,'local');
});

test('suggested-value pickers support arrows, a typed custom value, custom entry and cancellation',async t=>{
  const tty=terminal(t),choices=[{value:'1h',label:'Hourly'},{value:'24h',label:'Daily'}];
  let answer=promptValue(tty.ui.ask,'Monitor interval',choices);tty.key('down');tty.key('return');assert.equal(await answer,'24h');
  answer=promptValue(tty.ui.ask,'Monitor interval',choices);tty.type('45m\r');assert.equal(await answer,'45m');
  assert.doesNotMatch(transcriptLines(tty.ui.state,100).join('\n'),/\[object Object\]/);
  answer=promptValue(tty.ui.ask,'Monitor interval',choices);tty.type('3\r');await new Promise(resolve=>setImmediate(resolve));tty.type('2h\r');assert.equal(await answer,'2h');
  answer=promptValue(tty.ui.ask,'Monitor interval',choices);tty.key('escape');await assert.rejects(answer,e=>e.code===130);
});

test('permission pickers default to defer and custom text cannot grant consent',async t=>{
  const tty=terminal(t);let answer=confirmChoice(tty.ui.ask,'Authorize requests?');tty.key('return');assert.equal(await answer,false);
  answer=confirmChoice(tty.ui.ask,'Authorize requests?');tty.type('maybe later\r');assert.ok(tty.ui.state.pending);tty.key('return');assert.equal(await answer,false);
  answer=confirmChoice(tty.ui.ask,'Authorize requests?');tty.type('1\r');assert.equal(await answer,true);
});

test('HTTP method picker toggles multiple choices with real keys, supports custom input and remains visible on resize',async t=>{
  const tty=terminal(t);let answer=promptMethods(tty.ui.ask,tty.ui.write,['GET','HEAD']);
  assert.match(frame(tty.ui.state,100,30).lines.map(x=>x.text).join('\n'),/Allow all.*Customize/s);
  tty.key('down');tty.key('return');await new Promise(resolve=>setImmediate(resolve));
  tty.type('\x1b[B\x1b[B ');assert.deepEqual(tty.ui.state.pending.values,['GET','HEAD','POST']);
  for(const [columns,rows] of [[100,30],[80,24],[40,15]]){
    const view=frame(tty.ui.state,columns,rows),text=view.lines.map(x=>x.text).join('\n');
    assert.match(text,/\[x\] POST/);assert.match(text,/Selected: GET, HEAD, POST/);
    assert.equal(view.lines.length,rows);assert.ok(view.lines.every(x=>cells(x.text)<=columns-2));
  }
  tty.type('\r');assert.deepEqual(await answer,['GET','HEAD','POST']);
  answer=promptMethods(tty.ui.ask,tty.ui.write,['GET','POST','PROPFIND']);
  tty.key('down');tty.key('return');await new Promise(resolve=>setImmediate(resolve));
  assert.match(frame(tty.ui.state,100,30).lines.map(x=>x.text).join('\n'),/Selected: GET, POST, PROPFIND/);
  tty.type('GET,PATCH,PROPFIND\r');assert.deepEqual(await answer,['GET','PATCH','PROPFIND']);
  answer=tty.ui.multiselect('Methods',methodChoices);tty.type('\r');assert.ok(tty.ui.state.pending,'empty selection cannot silently grant a default');
  tty.key('escape');await assert.rejects(answer,error=>error.code===130);
});

test('a real Escape byte resolves promptly before the next typed command',async t=>{
  const tty=terminal(t),answer=tty.ui.select('Choose',[{label:'One'}],{back:true});
  tty.type('\x1b');await new Promise(resolve=>setTimeout(resolve,90));assert.equal(await answer,null);
  const command=tty.ui.command('review');tty.type('/help\r');assert.equal(await command,'/help');
});

test('Esc cancels an operation, preserves its detail and returns to an operable prompt',async t=>{
  const tty=terminal(t);
  const result=tty.ui.activity('Check endpoint',signal=>new Promise((resolve,reject)=>signal.addEventListener('abort',()=>reject(signal.reason),{once:true})));
  tty.ui.write('Waiting for the endpoint');tty.key('escape');
  await assert.rejects(result,error=>error.details.cancelled);
  assert.equal(tty.ui.signal.aborted,false);assert.equal(tty.ui.state.entries.at(-1).status,'cancelled');
  const answer=tty.ui.command('review');tty.type('/status');tty.key('return');assert.equal(await answer,'/status');
  assert.match(transcriptLines(tty.ui.state,80,{expanded:true}).join('\n'),/Waiting for the endpoint/);
});

test('connection skip stays distinct from exit; terminal restoration is idempotent',async t=>{
  const tty=terminal(t);
  const result=tty.ui.run(signal=>new Promise((resolve,reject)=>signal.addEventListener('abort',()=>reject(signal.reason),{once:true})));
  tty.key('return');await assert.rejects(result,error=>error.details.skipped);
  const answer=tty.ui.ask('Next');tty.key('c',{ctrl:true});await assert.rejects(answer,error=>error.code===130);
  assert.equal(tty.ui.signal.aborted,true);tty.ui.close();tty.ui.close();assert.equal(tty.raw,false);
  assert.equal(tty.bytes.match(/\x1b\[\?1049l/g).length,1);assert.ok(tty.bytes.endsWith('\x1b[?1049l'));
});

test('stopping a foreground watch returns promptly without cancelling the background job',async()=>{
  const root=temp();await execute('init',[root]);const run=await createRun(root,'scan',{mode:'code'});
  const controller=new AbortController(),watch=watchRun(root,run.id,5000,controller.signal);
  controller.abort(new Fault('Watch stopped.',130,{cancelled:true}));
  await assert.rejects(watch,error=>error.details.cancelled);
  assert.equal(read(root).runs[0].status,'queued');assert.equal(read(root).runs[0].cancelRequested,false);
});

test('frames fit resized terminals, keep input visible and strip untrusted control sequences',async t=>{
  const tty=terminal(t);
  tty.ui.setContext({title:'项目 🧪 app',repo:'/tmp/source',app:'https://app.example.com'});
  tty.ui.setTasks('Walkthrough',['Review','Prove','Fix','Export','Regress','Monitor']);tty.ui.task(2,'running');
  for(let i=0;i<40;i++)tty.ui.write(`Completed action ${i} · evidence captured`);
  const answer=tty.ui.ask('Repository path','~/Projects/app');tty.type('/a/very/long/path/'.repeat(10));
  for(const [columns,rows] of [[120,40],[80,24],[60,20],[40,15]]) {
    const view=frame(tty.ui.state,columns,rows);
    assert.equal(view.lines.length,rows);
    assert.ok(view.lines.every(line=>cells(line.text)<=columns-2));
    assert.ok(view.cursor.row<=rows-1);assert.ok(view.cursor.column<=columns);
    assert.match(view.lines[view.cursor.row-1].text,/^› /);
  }
  tty.ui.write('\x1b]52;c;c2VjcmV0\x07\x1b[2Junsafe\x08');
  assert.equal(safeText(tty.ui.state.entries.at(-1).text),'unsafe');
  tty.key('return');await answer;
  tty.key('pageup');assert.ok(tty.ui.state.scroll>0);tty.key('o',{ctrl:true});assert.equal(tty.ui.state.expanded,true);
});

test('wide task panel can be collapsed without losing the project or active command',async t=>{
  const tty=terminal(t,130,38);
  tty.ui.setContext({title:'Application',repo:'/tmp/customer-app',engine:'docker',model:'review · openai'});
  tty.ui.setTasks('Review progress',['Read source','Verify HTTP']);tty.ui.task(0,'done');tty.ui.task(1,'running');
  const answer=tty.ui.command('review');tty.type('/sta');
  let view=frame(tty.ui.state,130,38);
  assert.match(view.lines.map(x=>x.text).join('\n'),/✓ Read source/);
  assert.match(view.lines.map(x=>x.text).join('\n'),/◈ Verify HTTP/);
  tty.key('t',{ctrl:true});
  view=frame(tty.ui.state,130,38);
  assert.doesNotMatch(view.lines.map(x=>x.text).join('\n'),/✓ Read source/);
  assert.match(view.lines.map(x=>x.text).join('\n'),/customer-app/);
  assert.equal(tty.ui.state.input,'/sta');tty.key('return');assert.equal(await answer,'/status');
});

test('a live audit keeps an explanatory evidence card visible and uses the top bar for trust guarantees',async t=>{
  const tty=terminal(t,130,38);let finish;
  tty.ui.setContext({title:'job-radar.app',repo:'/tmp/job-radar',engine:'docker',app:'https://job-radar.app · authorized',model:'muse-spark-1.3 · connected'});
  tty.ui.setTasks('Black-box audit',['Scope and hosts','Assets and source','Routes and responses','Plan and test leads','Replay and assess','Report and coverage']);
  tty.ui.task(0,'done');tty.ui.task(1,'running');
  const audit=tty.ui.activity('Black-box audit',()=>new Promise(resolve=>{finish=resolve;}));
  tty.ui.setLiveStatus({done:'19 assets inspected · 37 route facts retained',
    working:'Muse is reviewing 80 observed test candidates',
    why:'Muse proposes experiments; Bypass validates and executes every HTTP request itself.',
    recovered:'One slow batch was split automatically; completed evidence was preserved.',
    next:'Run accepted candidates with scoped HTTP controls.',
    metrics:'20/80 candidates · 148 HTTP · 12 Muse'});
  const now=tty.ui.state.liveStatus.updatedAt+18000;
  const text=frame(tty.ui.state,130,38,now).lines.map(line=>line.text).join('\n');
  assert.match(text,/LIVE REQUESTS · APPROVED SCOPE ONLY · EVIDENCE SAVED CONTINUOUSLY/);
  assert.doesNotMatch(text,/REAL AI|bounded scope/);
  for(const value of [/LIVE AUDIT/,/DONE\s+19 assets inspected/,/WORKING\s+Muse is reviewing/,/WHY\s+Muse proposes/,/RECOVERED\s+One slow batch/,/NEXT\s+Run accepted/,/LIVE\s+20\/80 candidates · 148 HTTP · 12 Muse · last evidence 18\.0s ago/])assert.match(text,value);
  for(const [columns,rows,status] of [[80,24,'job-radar.app · AUDIT LIVE · SCOPE GUARDED · EVIDENCE SAVING'],[40,15,'AUDIT LIVE · SCOPE GUARDED']]){
    const compact=frame(tty.ui.state,columns,rows,now);
    assert.equal(compact.lines.length,rows);
    assert.ok(compact.lines.every(line=>cells(line.text)<=columns-2));
    assert.match(compact.lines[1].text,new RegExp(status.replace(/[.*+?^${}()|[\]\\]/g,'\\$&')));
  }
  finish({});await audit;
});

test('terminal palette respects NO_COLOR, redirected output and color capability',()=>{
  const output={isTTY:true,getColorDepth:()=>24};
  assert.match(createTheme({output,env:{TERM:'xterm'}}).paint('brand','Bypass'),/38;2;255;74;44/);
  for(const env of [{NO_COLOR:''},{TERM:'dumb'}])assert.equal(createTheme({output,env}).paint('brand','Bypass'),'Bypass');
  assert.equal(createTheme({output:{isTTY:false},env:{}}).paint('brand','Bypass'),'Bypass');
  const fallback=createTheme({output:{isTTY:true,getColorDepth:()=>8},env:{TERM:'xterm-256color'}});
  assert.match(fallback.paint('selection','Choose',{surface:true}),/48;5;202/);
});
