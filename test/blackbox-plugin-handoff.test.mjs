import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import {createServer} from 'node:http';
import {execute} from '../src/service.mjs';
import {mcpClient} from './mcp-client.mjs';
import {temp} from './helpers.mjs';

function blank(schema) {
  if (schema?.anyOf) return blank(schema.anyOf[0]);
  if (schema?.enum?.length) return schema.enum[0];
  const type = Array.isArray(schema?.type) ? schema.type.find(item => item !== 'null') : schema?.type;
  if (type === 'array') return [];
  if (type === 'object') return Object.fromEntries((schema.required ?? [])
    .map(key => [key, blank(schema.properties?.[key])]));
  if (type === 'integer' || type === 'number') return schema.minimum ?? 0;
  if (type === 'boolean') return false;
  return '';
}

for(const packaged of [false,true])test(
  `${packaged?'packaged plugin':'source MCP'} blackbox uses host decisions without a Meta key`, async t => {
  const server=createServer((request,response)=>{
    if(request.url==='/'){
      response.writeHead(200,{'content-type':'text/html'});
      response.end('<a href="/api/public">API</a><script src="/app.js"></script>');
    }else if(request.url==='/app.js'){
      response.writeHead(200,{'content-type':'text/javascript'});
      response.end("fetch('/api/public?q=hello')");
    }else if(request.url?.startsWith('/api/public')){
      response.writeHead(200,{'content-type':'application/json'});
      response.end('{"ok":true,"items":[]}');
    }else{response.writeHead(404);response.end('missing');}
  });
  await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve));
  t.after(()=>server.close());
  const url=`http://127.0.0.1:${server.address().port}`, root=temp();
  fs.writeFileSync(path.join(root,'app.mjs'),'export const testApp = true;\n');
  if(!packaged) await execute('init',[root]);
  const client=await mcpClient(root,{stateDir:temp(),packaged,
    env:{META_API_KEY:'',MODEL_API_KEY:''}});
  t.after(()=>client.child.kill());
  const selected=packaged?
    (await client.call('bypass_connect_app',{url,environment:'local'})).root:root;
  const setup=await client.call('bypass_blackbox_setup',{url,include:'/',rps:20,
    'model-calls':6,'max-tasks':2,'max-urls':10,minutes:1});
  assert.equal(setup.ready,true);
  const started=await client.call('bypass_blackbox_start',{url,scope:setup.scopeFile,
    'accept-local':true,rps:20,'model-calls':6,'max-tasks':2,'max-urls':10,minutes:1});
  assert.equal(started.status,'running');
  let count=0, cursor=0, final;
  const deadline=Date.now()+55000;
  while(Date.now()<deadline){
    const state=await client.call('bypass_blackbox_next',{after:cursor});
    cursor=state.cursor;
    for(const pending of state.pending){
      assert.ok(pending.schema && Array.isArray(pending.messages));
      assert.doesNotMatch(JSON.stringify(pending),/META_API_KEY|MODEL_API_KEY/);
      await client.call('bypass_blackbox_submit',{id:pending.id,decision:blank(pending.schema)});
      count++;
    }
    if(state.status!=='running'){final=state;break;}
    await new Promise(resolve=>setTimeout(resolve,100));
  }
  assert.ok(final,'blackbox audit did not finish');
  assert.equal(final.status,'completed',JSON.stringify(final.error));
  assert.ok(count>0,'the active Muse session received no model decisions');
  assert.equal(final.result.kind,'blackbox-audit');
  assert.equal(final.result.stats.model,'muse-code-session');
  assert.ok(fs.existsSync(path.join(selected,'.bypass/runs',final.result.run,'evidence.jsonl')));
  assert.equal(await client.close(),0);
});

test('packaged scope tool accepts custom rate and Muse calls without resetting saved settings', async t => {
  const server=createServer((_request,response)=>{response.writeHead(200);response.end('ok');});
  await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve));
  t.after(()=>server.close());
  const url=`http://127.0.0.1:${server.address().port}`;
  const client=await mcpClient(temp(),{stateDir:temp(),packaged:true});
  t.after(()=>client.child.kill());
  await client.call('bypass_connect_app',{url,environment:'local'});
  const first=await client.call('bypass_blackbox_scope',{url,include:'/',rps:10,'model-calls':120});
  const original=JSON.parse(fs.readFileSync(first.file,'utf8'));
  original.limits.maxUrls=600;
  original.never.push('/keep-excluded');
  fs.writeFileSync(first.file,JSON.stringify(original,null,2)+'\n');

  const slower=await client.call('bypass_blackbox_scope',
    {url,include:'/',rps:7,'model-calls':240,minutes:45});
  assert.match(slower.next,/--rps 7 --model-calls 240 --minutes 45$/);
  assert.deepEqual(JSON.parse(fs.readFileSync(first.file,'utf8')),original);

  const faster=await client.call('bypass_blackbox_scope',{url,include:'/',rps:12,'model-calls':240});
  assert.match(faster.next,/--rps 12 --model-calls 240$/);
  const raised=JSON.parse(fs.readFileSync(first.file,'utf8'));
  assert.equal(raised.limits.rps,12);
  assert.equal(raised.limits.modelCalls,120);
  assert.equal(raised.limits.minutes,original.limits.minutes);
  assert.equal(raised.limits.maxUrls,600);
  assert.ok(raised.never.includes('/keep-excluded'));
  assert.equal(await client.close(),0);
});
