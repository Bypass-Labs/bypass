import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import {createServer} from 'node:http';
import {execute} from '../src/service.mjs';
import {temp} from './helpers.mjs';

test('terminal cancellation interrupts blackbox HTTP and preserves a stopped run', async t => {
  const server=createServer((_request,response)=>{
    setTimeout(()=>{if(!response.destroyed){response.writeHead(200,{'content-type':'text/html'});response.end('slow app');}},2000);
  });
  await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve));
  t.after(()=>server.close());
  const root=temp(),url=`http://127.0.0.1:${server.address().port}`;
  fs.writeFileSync(path.join(root,'app.mjs'),'export const app = true;\n');
  await execute('init',[root]);
  const controller=new AbortController();
  const audit=execute('blackbox',[url],{project:root,'accept-local':true,'no-model':true,
    rps:20,minutes:1},{signal:controller.signal});
  setTimeout(()=>controller.abort(),100);
  await assert.rejects(audit,error=>error.code===130);
  const runs=fs.readdirSync(path.join(root,'.bypass/runs')).filter(item=>item.startsWith('bx-'));
  assert.equal(runs.length,1);
  const stopped=JSON.parse(fs.readFileSync(path.join(root,'.bypass/runs',runs[0],'run-stop.json'),'utf8'));
  assert.equal(stopped.status,'interrupted');
});
