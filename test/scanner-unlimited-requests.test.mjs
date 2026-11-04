import test from 'node:test';
import assert from 'node:assert/strict';
import { runAPIDriver } from '../src/scanner/api-driver.mjs';
import { apiProfile } from '../src/providers.mjs';
import './helpers.mjs';

test('zero-timeout discovery and evaluation resume past 256 calls and keep counting requests',async()=>{
  for(const kind of ['discovery','evaluation']){
    const profile=apiProfile('test',{provider:'custom','base-url':'http://127.0.0.1:8080/v1',model:'fixture','secret-env':'BYPASS_UNIT_API_KEY','timeout-ms':0});
    const summary={tasks:1,finished:0,modelRequests:256};
    const run={id:'scan_18aa42c25cc7467c84be5a64',status:'awaiting_reasoning',policy:summary,evaluationSummary:summary};
    const task={id:'resumed',kind,phase:kind,expiresAt:0,stageTimeoutDisabled:true,resultSchema:{type:'object'}};
    let turns=0,receipts=0;
    const result=await runAPIDriver({models:[profile],activeModel:'test'},{run,limits:{maxModelRequests:1},evaluationLimits:{maxModelRequests:1},
      client:{call:async(operation,input)=>{
        if(operation==='next_task')return {run,task};
        if(operation==='submit')return {run:{...run,status:'completed'},status:'completed'};
        if(input.arguments?.modelRequests)receipts++;
        return {run};
      }},
      sessionFactory:()=>({turn:async(_messages,options)=>{
        assert.equal(options.timeoutMs,0);options.onProgress({kind:'phase',phase:'request'});
        return ++turns===3?{action:'submit',result:{}}:{action:'evidence',operation:'inventory',arguments:{}};
      }})
    });
    assert.equal(result.status,'completed');assert.equal(turns,3);assert.equal(receipts,3);
  }
});
