import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import http from 'node:http';
import os from 'node:os';
import path from 'node:path';
import {runAudit} from '../src/blackbox/index.mjs';

const blank = schema => schema?.type === 'object' ? Object.fromEntries(
  (schema.required ?? []).map(key => [key, blank(schema.properties?.[key])])) :
  schema?.type === 'array' ? [] : schema?.type === 'integer' ||
  schema?.type === 'number' ? 0 : schema?.type === 'boolean' ? false :
  schema?.enum?.[0] ?? '';

test('short audits interpret source while anonymous route reconnaissance is waiting', async t => {
  const root=fs.mkdtempSync(path.join(os.tmpdir(),'bypass-source-overlap-'));
  t.after(()=>fs.rmSync(root,{recursive:true,force:true}));
  fs.writeFileSync(path.join(root,'app.mjs'),
    "app.get('/api/items', (req, res) => res.json({items: []}));\n");
  let rootCompleted=0, sourceStarted=0;
  const server=http.createServer((request,response)=>{
    if(request.url==='/'){
      setTimeout(()=>{rootCompleted=Date.now();response.writeHead(200,
        {'content-type':'text/html'});response.end('<html>App</html>');},350);
      return;
    }
    response.writeHead(404);response.end('missing');
  });
  await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve));
  t.after(()=>new Promise(resolve=>server.close(resolve)));
  const origin=`http://127.0.0.1:${server.address().port}`;
  const scopeFile=path.join(root,'blackbox.scope.json');
  fs.writeFileSync(scopeFile,JSON.stringify({schemaVersion:1,target:{origin},
    include:['/'],limits:{rps:30,minutes:1,modelCalls:12,maxUrls:10}}));
  await runAudit({url:origin,root,scopeFile,sourcePath:root,noDiscovery:true,
    overrides:{acceptLocal:true},infer:async(_profile,messages,{schema}={})=>{
      if(messages[0].content.startsWith('Interpret these redacted source route excerpts'))
        sourceStarted=Date.now();
      return blank(schema);
    }});
  assert.ok(sourceStarted>0,'source interpretation did not run');
  assert.ok(rootCompleted>0,'anonymous route reconnaissance did not run');
  assert.ok(sourceStarted<rootCompleted,
    'source review waited for the independent anonymous HTTP response');
});
