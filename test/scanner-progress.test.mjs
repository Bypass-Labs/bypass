import test from 'node:test';
import assert from 'node:assert/strict';
import { reasoningProgress } from '../src/scanner/progress.mjs';
import { runAPIDriver } from '../src/scanner/api-driver.mjs';
import { apiProfile } from '../src/providers.mjs';
import './helpers.mjs';

test('policy progress separates remaining work from completed and deferred tasks',()=>{
  const progress=reasoningProgress({signalCount:86,policy:{tasks:50,finished:9,deferred:2,modelRequests:76}},'discovery');
  assert.equal(progress.remaining,39);assert.equal(progress.total,50);
  assert.match(progress.message,/9\/50 complete · 39 remaining · 2 deferred/);
  assert.match(progress.message,/86 detector signals · 76 model requests/);
  assert.equal(reasoningProgress({},'discovery'),null);
});

test('evaluation progress distinguishes unfinished tasks from case verdict counts',()=>{
  const progress=reasoningProgress({signalCount:84,evaluationSummary:{tasks:64,finished:3,modelRequests:26,confirmed:1,refuted:2,needs_review:20}},'evaluation');
  assert.equal(progress.remaining,61);
  assert.match(progress.message,/3\/64 complete · 61 unfinished/);
  assert.match(progress.message,/1 source-confirmed · 2 refuted · 20 needs review/);
});

test('driver reports changing totals, refreshes request counts, and clears waiting heartbeat',async t=>{
  let heartbeat,cleared=0;
  t.mock.method(globalThis,'setInterval',(callback,ms)=>{
    assert.equal(ms,15000);heartbeat=callback;return {unref(){}};
  });
  t.mock.method(globalThis,'clearInterval',()=>cleared++);
  const profile=apiProfile('test',{provider:'custom','base-url':'http://127.0.0.1:8080/v1',model:'fixture','secret-env':'BYPASS_UNIT_API_KEY'});
  const run={id:'scan_18aa42c25cc7467c84be5a64',status:'awaiting_reasoning',signalCount:84,
    policy:{tasks:1,finished:0,deferred:0,modelRequests:0}};
  const task={id:'mapping',kind:'discovery',phase:'mapping',expiresAt:Date.now()/1000+60,resultSchema:{type:'object'}};
  const progress=[];let polls=0;
  const result=await runAPIDriver({models:[profile],activeModel:'test'},{run,onProgress:event=>progress.push(event),
    client:{call:async operation=>{
      if(operation==='next_task')return ++polls===1?{run,task}:{run:{...run,status:'completed',policy:{tasks:3,finished:1,deferred:2,modelRequests:1}},status:'completed'};
      if(operation==='submit')return {run:{...run,policy:{tasks:3,finished:1,deferred:0,modelRequests:1}},status:'awaiting_reasoning'};
      return {run:{...run,policy:{...run.policy,modelRequests:1}}};
    }},
    sessionFactory:()=>({turn:async(_messages,options)=>{
      options.onProgress({kind:'phase',phase:'request'});heartbeat();return {action:'submit',result:{}};
    }})
  });
  assert.equal(result.status,'completed');assert.equal(cleared,1);
  assert.ok(progress.some(p=>p.message?.includes('0/1 complete')));
  assert.ok(progress.some(p=>p.message?.includes('1/3 complete · 2 remaining')));
  assert.ok(progress.some(p=>p.message?.includes('1/3 complete · 0 remaining · 2 deferred')));
  assert.ok(progress.some(p=>p.message?.includes('waiting for model · 0s elapsed')));
});

test('waiting heartbeat is cleared if the model fails',async t=>{
  let cleared=0;
  t.mock.method(globalThis,'setInterval',()=>({unref(){}}));
  t.mock.method(globalThis,'clearInterval',()=>cleared++);
  const profile=apiProfile('test',{provider:'custom','base-url':'http://127.0.0.1:8080/v1',model:'fixture','secret-env':'BYPASS_UNIT_API_KEY'});
  const run={id:'scan_18aa42c25cc7467c84be5a64',status:'awaiting_reasoning'};
  const task={id:'failed',kind:'discovery',phase:'mapping',expiresAt:Date.now()/1000+60,resultSchema:{type:'object'}};
  const result=await runAPIDriver({models:[profile],activeModel:'test'},{run,
    client:{call:async operation=>operation==='next_task'?{run,task}:{run:{...run,status:'interrupted'}}},
    sessionFactory:()=>({turn:async()=>{throw new Error('Synthetic failure');}})
  });
  assert.equal(result.status,'interrupted');assert.equal(cleared,1);
});
