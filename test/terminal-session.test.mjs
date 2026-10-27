import test from 'node:test';
import assert from 'node:assert/strict';
import { PassThrough } from 'node:stream';
import { createTerminalSession, frame, transcriptLines, cells, safeText } from '../src/terminal-session.mjs';
import { execute } from '../src/service.mjs';
import { createRun } from '../src/engine.mjs';
import { watchRun } from '../src/jobs.mjs';
import { read } from '../src/store.mjs';
import { Fault } from '../src/util.mjs';
import { temp } from './helpers.mjs';

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

test('bracketed multiline paste fills one answer and never submits extra commands',async t=>{
  const tty=terminal(t);let resolved=false;
  const answer=tty.ui.ask('Repository').then(value=>{resolved=true;return value;});
  tty.type('\x1b[200~https://github.com/org/app\n/quit\x1b[201~');
  await Promise.resolve();assert.equal(resolved,false);assert.equal(tty.ui.state.input,'https://github.com/org/app /quit');
  tty.key('return');assert.equal(await answer,'https://github.com/org/app /quit');
});

test('menus accept arrows, numbers and Escape without abandoning the workspace',async t=>{
  const tty=terminal(t),items=[{label:'First',id:1},{label:'Second',id:2}];
  let answer=tty.ui.select('Choose',items,{back:true});tty.key('down');tty.key('return');assert.equal((await answer).id,2);
  answer=tty.ui.select('Choose',items,{back:true});tty.key('escape');assert.equal(await answer,null);
  answer=tty.ui.select('Choose',items);tty.type('1');tty.key('return');assert.equal((await answer).id,1);
  answer=tty.ui.select('Model',[{name:'local',provider:'custom','secret-env':'BYPASS_UNIT_API_KEY',stream:false}]);assert.equal(tty.ui.state.menu[0].label,'local');tty.key('return');assert.equal((await answer).name,'local');
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
