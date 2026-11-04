import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import http from 'node:http';
import os from 'node:os';
import path from 'node:path';
import {runAudit} from '../src/blackbox/index.mjs';
import {Fault} from '../src/util.mjs';

const blank = schema => schema?.type === 'object' ? Object.fromEntries(
  (schema.required ?? []).map(key => [key, blank(schema.properties?.[key])])) :
  schema?.type === 'array' ? [] : schema?.type === 'integer' ||
  schema?.type === 'number' ? 0 : schema?.type === 'boolean' ? false :
  schema?.enum?.[0] ?? '';

test('an explicit model callback wins over the legacy test Muse transport', async t => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'bypass-custom-infer-'));
  t.after(() => fs.rmSync(root, {recursive: true, force: true}));
  const bin = path.join(root, 'bin');
  fs.mkdirSync(bin);
  const invoked = path.join(root, 'legacy-muse-invoked');
  fs.writeFileSync(path.join(bin, 'muse'),
    `#!/bin/sh\nprintf called > '${invoked}'\nexit 9\n`, {mode: 0o700});
  const server = http.createServer((_request, response) => {
    response.writeHead(200, {'content-type': 'text/html'});
    response.end('<html><body>Fixture</body></html>');
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  t.after(() => new Promise(resolve => server.close(resolve)));
  const origin = `http://127.0.0.1:${server.address().port}`;
  const scopeFile = path.join(root, 'blackbox.scope.json');
  fs.writeFileSync(scopeFile, JSON.stringify({schemaVersion: 1,
    target: {origin}, include: ['/'], limits: {rps: 50, modelCalls: 5, minutes: 1}}));
  let calls = 0;
  await runAudit({url: origin, root, scopeFile, dryRun: true, noDiscovery: true,
    offline: true, env: {...process.env, BYPASS_TEST_LEGACY_MUSE: '1',
      PATH: `${bin}${path.delimiter}${process.env.PATH}`},
    infer: async (_profile, _messages, {schema} = {}) => {
      calls++;
      return blank(schema);
    }});
  assert.ok(calls > 0, 'the supplied callback must receive model work');
  assert.equal(fs.existsSync(invoked), false, 'the legacy Muse transport must stay unused');
});

test('black-box repair is one counted model call within the audit budget', async t => {
  const root=fs.mkdtempSync(path.join(os.tmpdir(),'bypass-repair-'));
  t.after(()=>fs.rmSync(root,{recursive:true,force:true}));
  const server=http.createServer((_request,response)=>{
    response.writeHead(200,{'content-type':'text/html'});
    response.end('<html><body>Fixture</body></html>');
  });
  await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve));
  t.after(()=>new Promise(resolve=>server.close(resolve)));
  const origin=`http://127.0.0.1:${server.address().port}`;
  const scopeFile=path.join(root,'blackbox.scope.json');
  fs.writeFileSync(scopeFile,JSON.stringify({schemaVersion:1,target:{origin},include:['/'],
    limits:{rps:50,modelCalls:5,minutes:1}}));
  const calls=[],events=[];
  const result=await runAudit({url:origin,root,scopeFile,dryRun:true,noDiscovery:true,offline:true,
    log:event=>events.push(event),infer:async(_profile,messages,{schema})=>{
      calls.push(messages);
      if(calls.length===1)throw new Fault('Invalid action',3,{reason:'invalid_arguments',
        responseDiagnostics:{jsonStatus:'invalid_json',jsonSource:'content'}});
      return blank(schema);
    }});
  assert.ok(calls.length>=2);
  assert.deepEqual(calls[1][0],calls[0][0]);
  assert.match(calls[1].at(-1).content,/exactly one security_action/);
  assert.equal(result.stats.modelCalls,calls.length);
  assert.ok(events.some(event=>event.type==='activity'&&event.message?.includes('retrying this decision once')));
});
