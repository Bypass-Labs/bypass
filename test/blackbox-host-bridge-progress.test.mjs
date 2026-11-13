import test from 'node:test';
import assert from 'node:assert/strict';
import { BlackboxHostBridge } from '../src/blackbox/host-bridge.mjs';

test('host bridge summarizes live work without treating planned checks as coverage',async()=>{
  const bridge=new BlackboxHostBridge();
  bridge.start(async({onProgress})=>{
    onProgress({stage:'progress',type:'phase',state:'doing',step:4,total:6,title:'Plan and test leads'});
    onProgress({stage:'progress',type:'request',requests:17});
    onProgress({stage:'progress',type:'model',modelCalls:3});
    onProgress({stage:'progress',type:'task-total',total:5});
    onProgress({stage:'progress',type:'task-done',confirmed:true});
    onProgress({stage:'progress',type:'activity',message:'Checking the login response'});
    return {ok:true};
  });
  await bridge.job.done;
  const result=bridge.status();
  assert.equal(result.status,'completed');
  assert.equal(result.summary.phase.step,4);
  assert.equal(result.summary.requests,17);
  assert.equal(result.summary.modelCalls,3);
  assert.equal(result.summary.knownChecksPercent,20);
  assert.equal(result.summary.confirmedSignals,1);
  assert.equal(result.summary.latestActivity,'Checking the login response');
  assert.match(result.summary.percentMeaning,/not security coverage/);
});

test('host bridge returns complete concurrent decisions one at a time',async()=>{
  const bridge=new BlackboxHostBridge();
  bridge.start(async({infer})=>{
    const prompt='observed route '.repeat(2800);
    return Promise.all([
      infer(null,[{role:'user',content:prompt}],{schema:{type:'object',properties:{flows:{type:'array'}}}}),
      infer(null,[{role:'user',content:prompt}],{schema:{type:'object',properties:{flows:{type:'array'}}}}),
      infer(null,[{role:'user',content:prompt}],{schema:{type:'object',properties:{flows:{type:'array'}}}}),
    ]);
  });
  await Promise.resolve();
  for(let remaining=3;remaining>0;remaining--){
    const status=bridge.status();
    assert.equal(status.pendingCount,remaining);
    assert.equal(status.pending.length,1);
    assert.ok(JSON.stringify(status).length<50_000);
    assert.match(status.pending[0].messages[0].content,/observed route/);
    bridge.submit(status.pending[0].id,{flows:[]});
  }
  await bridge.job.done;
  assert.equal(bridge.status().status,'completed');
});
