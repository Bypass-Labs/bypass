import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import {createServer} from 'node:http';
import {execute} from '../src/service.mjs';
import {mcpClient} from './mcp-client.mjs';
import {temp} from './helpers.mjs';
import {change,read} from '../src/store.mjs';

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
  assert.ok(Array.isArray(final.result.findings),'app-only findings remain available in the terminal result');
  assert.ok(fs.existsSync(final.result.reportPath),'the full app-only report is available for review');
  assert.ok(fs.existsSync(path.join(selected,'.bypass/runs',final.result.run,'evidence.jsonl')));
  assert.equal(await client.close(),0);
});

test('MCP combined review feeds cited source leads to one full live audit',async t=>{
  const server=createServer((request,response)=>{
    response.writeHead(request.url==='/api/public'?200:404,
      {'content-type':'application/json'});
    response.end(request.url==='/api/public'?'{"ok":true}':'{}');
  });
  await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve));
  t.after(()=>server.close());
  const url=`http://127.0.0.1:${server.address().port}`,root=temp();
  fs.writeFileSync(path.join(root,'routes.mjs'),[
    "app.get('/api/public', handler);",
    "if (method === 'POST' && path === '/api/preview') {",
    '  const body = await readJson(req);',
    '  const sourceUrl = body.sourceUrl;',
    '  return fetch(sourceUrl);',
    '});',
    '',
  ].join('\n'));
  await execute('init',[root]);
  await execute('target add',['app'],{project:root,url,environment:'local'});
  await execute('target verify',['app'],{project:root,method:'local'});
  await execute('target authorize',['app'],{project:root,paths:'/',methods:'GET,HEAD,POST',rps:10,accept:true});
  const client=await mcpClient(root,{stateDir:temp(),env:{META_API_KEY:'',MODEL_API_KEY:''}});
  t.after(()=>client.child.kill());
  const scan=await client.call('bypass_scan',{mode:'combined',modelCalls:6,minutes:1});
  const step=await client.call('bypass_review_step',{id:scan.runId,action:'source',candidates:[{
    title:'Possible anonymous data access',category:'missing-authentication',file:'routes.mjs',line:1,
    quote:"app.get('/api/public', handler);",resourcePath:'/api/public',
    hypothesis:'The route may return private data without a session.',
    recommendation:'Check the caller before returning private data.'},{
    title:'Server fetch from request body',category:'SSRF',file:'routes.mjs',line:5,
    quote:'  return fetch(sourceUrl);',resourcePath:'/api/preview',
    hypothesis:'The client may choose the server fetch destination.',
    recommendation:'Restrict server fetch destinations.'}]});
  assert.equal(step.findings.length,2);
  await change(root,state=>{state.runs.find(run=>run.id===scan.runId).status='completed';});
  const setup=await client.call('bypass_blackbox_setup',{url,include:'/',methods:'GET,HEAD,POST',
    rps:10,'model-calls':6,'max-tasks':2,'max-urls':10,minutes:1});
  const started=await client.call('bypass_blackbox_start',{url,review:scan.runId,
    scope:setup.scopeFile,'accept-local':true,'max-tasks':2,'max-urls':10});
  assert.equal(started.status,'running');
  let cursor=0,final;
  const deadline=Date.now()+55000;
  while(Date.now()<deadline){
    const state=await client.call('bypass_blackbox_next',{after:cursor});cursor=state.cursor;
    for(const pending of state.pending)
      await client.call('bypass_blackbox_submit',{id:pending.id,decision:blank(pending.schema)});
    if(state.status!=='running'){final=state;break;}
    await new Promise(resolve=>setTimeout(resolve,100));
  }
  assert.equal(final?.status,'completed',JSON.stringify(final?.error));
  assert.equal(final.result.combinedReviewId,scan.runId);
  const source=JSON.parse(fs.readFileSync(path.join(final.result.runDir,'source.json'),'utf8'));
  assert.equal(source.securityLeads[0].id,step.findings[0]);
  assert.ok(source.endpoints.some(endpoint => endpoint.path==='/api/preview' &&
    endpoint.method==='POST' && endpoint.bodyFields?.includes('sourceUrl')));
  assert.ok(source.securityLeads.some(lead => lead.id===step.findings[1] &&
    lead.fields.includes('sourceUrl')));
  assert.equal(source.modelCalls,0);
  assert.equal(source.modelCoverage.snippetsAvailable,0);
  assert.doesNotMatch(fs.readFileSync(path.join(final.result.runDir,'report.md'),'utf8'),
    /Muse received 0 of \d+ source route excerpts/);
  const linked=await client.call('bypass_review_step',{id:scan.runId,action:'status'});
  assert.equal(linked.liveAudit.runId,final.result.run);
  assert.equal(linked.nextAction.tool,'bypass_findings');
  assert.equal(read(root).runs.find(run=>run.id===scan.runId).result.blackbox.run,final.result.run);
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
