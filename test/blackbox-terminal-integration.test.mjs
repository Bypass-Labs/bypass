import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import {createServer} from 'node:http';
import {execute} from '../src/service.mjs';
import {terminal} from '../src/ui.mjs';
import {scopeOutputForOrigin} from '../src/blackbox/setup.mjs';
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

test('/blackbox switches app origins without overwriting or reusing another app scope', async t => {
  const hits=[0,0];
  const apps=hits.map((_,index)=>createServer((request,response)=>{
    hits[index]++;
    response.writeHead(200,{'content-type':'text/html'});
    response.end(`<html><body>App ${index}</body></html>`);
  }));
  for(const app of apps){
    await new Promise(resolve=>app.listen(0,'127.0.0.1',resolve));
    t.after(()=>app.close());
  }
  const [first,second]=apps.map(app=>`http://127.0.0.1:${app.address().port}`);
  const root=temp();
  t.after(()=>fs.rmSync(root,{recursive:true,force:true}));
  fs.writeFileSync(path.join(root,'app.mjs'),'export const app = true;\n');
  await execute('init',[root]);
  const limits={project:root,include:'/',methods:'GET,HEAD,POST,PUT,PATCH,DELETE,OPTIONS',rps:20,
    'model-calls':24,'max-tasks':1,'max-urls':10,minutes:1};
  await execute('blackbox setup',[first],limits);
  const original=fs.readFileSync(path.join(root,'blackbox.scope.json'),'utf8');
  const alternate=scopeOutputForOrigin(root,second).out;
  assert.notEqual(alternate,'blackbox.scope.json');
  const answers=['blackbox',second,'/','GET,HEAD,POST,PATCH,DELETE','20','y',
    'blackbox',first,'/','GET,HEAD,POST,PATCH,DELETE','20','y','q'];
  const questions=[];
  const ask=async question=>{
    questions.push(question);
    assert.ok(answers.length,`unexpected prompt: ${question}`);
    return answers.shift();
  };
  await terminal({project:root,'no-model':true,'max-tasks':1,'max-urls':10,minutes:1},
    {ask,rich:false,signal:new AbortController().signal,write:()=>{},close:()=>{}});
  assert.equal(answers.length,0);
  assert.equal(questions.filter(question=>question.startsWith('Start black-box audit')).length,2);
  assert.equal(fs.readFileSync(path.join(root,'blackbox.scope.json'),'utf8'),original);
  assert.equal(JSON.parse(fs.readFileSync(path.join(root,alternate),'utf8')).target.origin,second);
  assert.ok(hits.every(count=>count>0),`Expected requests to both local apps; got ${hits}`);
  assert.equal(fs.readdirSync(path.join(root,'.bypass/runs')).filter(item=>item.startsWith('bx-')).length,2);
  const direct=await execute('blackbox',[second],{project:root,'no-model':true,
    'max-tasks':1,'max-urls':10,minutes:1});
  assert.equal(direct.origin,second);
  assert.equal(fs.readFileSync(path.join(root,'blackbox.scope.json'),'utf8'),original);
});

test('/blackbox asks for a new deployed app environment and approval before any audit', async t => {
  const root=temp();
  t.after(()=>fs.rmSync(root,{recursive:true,force:true}));
  fs.writeFileSync(path.join(root,'app.mjs'),'export const app = true;\n');
  await execute('init',[root]);
  const original=await execute('blackbox scope',['https://first.example.test'],{project:root});
  await execute('target add',['first'],{project:root,url:'https://first.example.test',
    environment:'production'});
  const originalText=fs.readFileSync(original.file,'utf8');
  const next='https://second.example.test';
  const commands=['blackbox','q'],questions=[];
  const ask=async question=>{throw new Error(`Unexpected text prompt: ${question}`);};
  ask.select=async (title,items)=>{
    questions.push(title);
    if(title==='App URL')return {id:'__custom',custom:true,value:next};
    if(title.startsWith('Do you control'))return items.find(item=>item.id==='no');
    return items[0];
  };
  await terminal({project:root,'no-model':true},
    {ask,rich:true,command:async()=>commands.shift(),setContext:()=>{},setNext:()=>{},
      signal:new AbortController().signal,write:()=>{},close:()=>{}});
  assert.equal(commands.length,0);
  assert.ok(questions.includes(`Which environment is this? App: ${next}`));
  assert.ok(questions.some(question=>question.includes(`Do you control ${next}`)));
  assert.equal(fs.readFileSync(original.file,'utf8'),originalText);
  assert.equal(JSON.parse(fs.readFileSync(path.join(root,scopeOutputForOrigin(root,next).out),'utf8'))
    .target.environment,'production');
  assert.equal(fs.existsSync(path.join(root,'.bypass/runs')),false);
});

test('onboarding handoff starts the approved audit immediately and streams progress', async t => {
  const app=createServer((_request,response)=>{response.writeHead(200,{'content-type':'text/html'});response.end('<html><body>Approved app</body></html>');});
  await new Promise(resolve=>app.listen(0,'127.0.0.1',resolve));t.after(()=>app.close());
  const url=`http://127.0.0.1:${app.address().port}`,root=temp();
  fs.writeFileSync(path.join(root,'app.mjs'),'export const app = true;\n');
  await execute('init',[root]);
  await execute('target add',['local'],{project:root,url,environment:'local'});
  await execute('target verify',['local'],{project:root,method:'local'});
  await execute('target authorize',['local'],{project:root,accept:true,paths:'/',methods:'GET,HEAD',rps:32});
  const answers=['q'],questions=[],stages=[],output=[];
  const ask=async question=>{questions.push(question);assert.ok(answers.length,`unexpected prompt: ${question}`);return answers.shift();};
  await terminal({project:root,startReview:{id:'blackbox'},'no-model':true},{ask,rich:false,signal:new AbortController().signal,
    setTasks:(_title,items)=>stages.push(...items),task:(index,state)=>output.push(`${index}:${state}`),
    setNext:message=>output.push(message),write:message=>output.push(message),close:()=>{}});
  assert.equal(answers.length,0);assert.equal(questions.some(question=>/App URL|Allowed path|Allowed HTTP|Maximum requests|Start black-box/.test(question)),false);
  assert.ok(output.some(item=>item.includes('Starting app audit')));assert.ok(output.some(item=>/\d+ HTTP · \d+ Muse/.test(item)));
  assert.ok(stages.includes('Routes and responses'));
  const scope=JSON.parse(fs.readFileSync(path.join(root,'blackbox.onboarding.scope.json'),'utf8'));
  assert.equal(scope.target.environment,'local');assert.deepEqual(scope.methods,['GET','HEAD']);assert.equal(scope.limits.rps,32);
  assert.equal(scope.limits.modelCalls,24);assert.equal(scope.limits.maxUrls,400);
  assert.equal(scope.limits.tasks,0);assert.equal(scope.limits.minutes,10);
  assert.equal(fs.readdirSync(path.join(root,'.bypass/runs')).filter(item=>item.startsWith('bx-')).length,1);
});

test('terminal model setup selects the Meta profile with its official key variable', async t => {
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
  assert.equal(state.models.find(model=>model.name==='meta-terminal').secretEnv,'MODEL_API_KEY');
});
