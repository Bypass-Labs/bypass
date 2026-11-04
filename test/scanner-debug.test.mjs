import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { temp } from './helpers.mjs';
import { openDebugLog } from '../src/scanner/debug-log.mjs';
import { runAPIDriver } from '../src/scanner/api-driver.mjs';
import { apiProfile } from '../src/providers.mjs';
import { Fault } from '../src/util.mjs';
import { parse } from '../src/catalog.mjs';

test('scanner debug logs are private JSONL files with redacted known credentials and unique names',()=>{
  const root=temp(),previous=process.env.BYPASS_DEBUG_TEST_SECRET;
  process.env.BYPASS_DEBUG_TEST_SECRET='sensitive-debug-value';
  try{
    const log=openDebugLog(root,'scan_test',{raw:true});
    log.write({event:'rejected_response',raw:{content:'bad JSON sensitive-debug-value'}});
    log.close();
    const record=JSON.parse(fs.readFileSync(log.filename,'utf8'));
    assert.equal(record.raw.content,'bad JSON [REDACTED]');
    assert.ok(record.timestamp);assert.equal(record.run,'scan_test');
    if(process.platform!=='win32')assert.equal(fs.statSync(log.filename).mode&0o777,0o600);
    const second=openDebugLog(root,'scan_test');second.close();assert.notEqual(log.filename,second.filename);
    assert.equal(parse(['discover','--debug-log','--debug-raw']).options['debug-raw'],true);
  }finally{if(previous===undefined)delete process.env.BYPASS_DEBUG_TEST_SECRET;else process.env.BYPASS_DEBUG_TEST_SECRET=previous;}
});

test('scanner debug log refuses symlinks',()=>{
  const root=temp();fs.mkdirSync(path.join(root,'.bypass'));
  fs.symlinkSync(temp(),path.join(root,'.bypass/debug'),'dir');
  assert.throws(()=>openDebugLog(root,'scan_test'),/symlink/);
});

test('scanner debug log continues beyond 16 MiB without dropping records',()=>{
  const log=openDebugLog(temp(),'scan_test');
  const content='x'.repeat(1024*1024);
  try{
    for(let index=0;index<17;index++)log.write({index,content});
    log.write({event:'finished'});
  }finally{log.close();}
  assert.ok(fs.statSync(log.filename).size>16*1024*1024);
  const records=fs.readFileSync(log.filename,'utf8').trim().split('\n').map(line=>JSON.parse(line));
  assert.equal(records.length,18);
  for(let index=0;index<17;index++){
    assert.equal(records[index].index,index);
    assert.equal(records[index].content,content);
  }
  assert.equal(records.at(-1).event,'finished');
});

test('scanner debug log surfaces filesystem write errors',t=>{
  const log=openDebugLog(temp(),'scan_test');
  const error=Object.assign(new Error('No space left on device'),{code:'ENOSPC'});
  t.mock.method(fs,'writeFileSync',()=>{throw error;});
  try{assert.throws(()=>log.write({event:'request'}),actual=>actual===error);}finally{log.close();}
});

test('scanner debug captures rejected response content only with explicit raw opt-in',async()=>{
  const content='PRIVATE_MODEL_OUTPUT'+'x'.repeat(65536)+'END_OF_RESPONSE';
  const toolArguments=['{"broken":'+'x'.repeat(65536), 'second','third','fourth','fifth'];
  for(const raw of [false,true]){
    const log=openDebugLog(temp(),'scan_test',{raw});
    const profile=apiProfile('test',{provider:'custom','base-url':'http://127.0.0.1:8080/v1',model:'fixture','secret-env':'BYPASS_UNIT_API_KEY'});
    const run={id:'scan_test',status:'awaiting_reasoning'};
    const task={id:'task',kind:'discovery',phase:'mapping',expiresAt:Date.now()/1000+60,resultSchema:{type:'object'}};
    let turns=0;
    try{
      const result=await runAPIDriver({models:[profile],activeModel:'test'},{run,debugLog:log,
        client:{call:async operation=>operation==='next_task'?{run,task}:operation==='submit'?{run:{...run,status:'completed'},status:'completed'}:{run}},
        sessionFactory:()=>({turn:async(_messages,options)=>{
          options.onProgress({kind:'phase',phase:'request'});
          if(++turns===1){
            options.onRejectedResponse({diagnostics:{jsonStatus:'invalid_json'},content,toolArguments});
            throw new Fault('Invalid arguments',3,{reason:'invalid_arguments'});
          }
          return {action:'submit',result:{}};
        }})
      });
      assert.equal(result.status,'completed');
    }finally{log.close();}
    const text=fs.readFileSync(log.filename,'utf8'),records=text.trim().split('\n').map(line=>JSON.parse(line));
    assert.equal(text.includes('PRIVATE_MODEL_OUTPUT'),raw);
    assert.deepEqual(records.find(record=>record.event==='rejected_response').raw,raw?{content,toolArguments}:undefined);
    assert.deepEqual(records.map(r=>r.event),['task','request','rejected_response','correction','request','accepted_action']);
  }
});
