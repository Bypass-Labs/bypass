import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import {createServer} from 'node:http';
import {execute} from '../src/service.mjs';
import {terminal} from '../src/ui.mjs';
import {temp} from './helpers.mjs';

test('/blackbox asks for scope and rate, runs, and presents report actions', async t => {
  const app=createServer((request,response)=>{
    response.writeHead(request.url==='/'?200:404,{'content-type':'text/html'});
    response.end(request.url==='/'?'<html><body>Local test app</body></html>':'missing');
  });
  await new Promise(resolve=>app.listen(0,'127.0.0.1',resolve));
  t.after(()=>app.close());
  const url=`http://127.0.0.1:${app.address().port}`,root=temp();
  fs.writeFileSync(path.join(root,'app.mjs'),'export const app = true;\n');
  await execute('init',[root]);
  const answers=['blackbox',url,'/','GET,HEAD,POST,PATCH,DELETE','50','y','q'];
  const questions=[],stages=[],output=[];
  let closed=false;
  const ask=async question=>{questions.push(question);
    assert.ok(answers.length,`unexpected prompt: ${question}`);
    return answers.shift();};
  const io={ask,rich:false,signal:new AbortController().signal,
    setTasks:(_title,items)=>stages.push(...items),task:(index,state)=>output.push(`${index}:${state}`),
    setNext:message=>output.push(message),write:message=>output.push(message),
    close:()=>{closed=true;}};
  await terminal({project:root,'no-model':true,'max-tasks':1,'max-urls':10,minutes:1},io);
  assert.equal(closed,true);
  assert.ok(questions.includes('App URL'));
  assert.ok(questions.includes('Allowed path prefixes'));
  assert.ok(questions.includes('Maximum requests per second'));
  assert.ok(questions.some(item=>item.startsWith('Start black-box audit')));
  assert.ok(stages.includes('Routes and responses'));
  assert.ok(output.some(item=>item.includes('5:done')),'report stage was not completed');
  assert.ok(output.some(item=>/\d+ HTTP · \d+ Muse/.test(item)),'live request count was not shown');
  const runs=fs.readdirSync(path.join(root,'.bypass/runs')).filter(item=>item.startsWith('bx-'));
  assert.equal(runs.length,1);
  assert.ok(fs.existsSync(path.join(root,'.bypass/runs',runs[0],'report.md')));
});

test('terminal model setup selects the new generic-key Meta profile', async t => {
  const root=temp();
  t.after(()=>fs.rmSync(root,{recursive:true,force:true}));
  fs.writeFileSync(path.join(root,'app.mjs'),'export const app = true;\n');
  await execute('init',[root]);
  const answers=['models','1','1','','','','meta-terminal','n','q'];
  const ask=async question=>{
    assert.ok(answers.length,`unexpected prompt: ${question}`);
    return answers.shift();
  };
  await terminal({project:root},{ask,rich:false,signal:new AbortController().signal,
    write:()=>{},close:()=>{}});
  const state=JSON.parse(fs.readFileSync(path.join(root,'.bypass/state.json'),'utf8'));
  assert.equal(state.activeModel,'meta-terminal');
  assert.equal(state.models.find(model=>model.name==='meta-terminal').secretEnv,'LLM_KEY');
});
