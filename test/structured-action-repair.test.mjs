import test from 'node:test';
import assert from 'node:assert/strict';
import {recoverableStructuredReply, withStructuredRepair} from '../src/inference.mjs';
import {Fault} from '../src/util.mjs';

const invalid = (diagnostics) => new Fault('Invalid structured reply', 3,
  {reason:'invalid_arguments',responseDiagnostics:diagnostics});

test('one counted repair uses the same evidence for every supported provider profile', async () => {
  for (const provider of ['meta','openai','anthropic','moonshot','deepseek','custom']) {
    const evidence=[{role:'user',content:'Fixture route evidence'}], attempts=[];
    const result=await withStructuredRepair(async messages=>{
      attempts.push({provider,messages});
      if(attempts.length===1)throw invalid({jsonStatus:'invalid_json',jsonSource:'content'});
      return {focus:'valid'};
    },evidence);
    assert.deepEqual(result,{focus:'valid'});
    assert.equal(attempts.length,2,provider);
    assert.deepEqual(attempts[1].messages[0],evidence[0]);
    assert.match(attempts[1].messages[1].content,/exactly one security_action/);
    assert.deepEqual(evidence,[{role:'user',content:'Fixture route evidence'}]);
  }
});

test('empty and schema-invalid replies can be repaired; transport failures cannot', async () => {
  for(const diagnostics of [{jsonStatus:'empty_content'},
    {jsonStatus:'parsed',schemaStatus:'invalid'}]){
    let calls=0;
    await withStructuredRepair(async()=>{if(++calls===1)throw invalid(diagnostics);return {};},
      [{role:'user',content:'evidence'}]);
    assert.equal(calls,2);
  }
  for(const error of [new Fault('timeout',3,{reason:'model_timeout'}),
    new Fault('network',3,{reason:'network'}),
    new Fault('multiple',3,{reason:'multiple_actions'}),
    invalid({jsonStatus:'not_attempted',schemaStatus:'valid'})]){
    let calls=0;
    await assert.rejects(withStructuredRepair(async()=>{calls++;throw error;},
      [{role:'user',content:'evidence'}]),reason=>reason===error);
    assert.equal(calls,1);
    assert.equal(recoverableStructuredReply(error),false);
  }
});

test('repair respects the remaining call budget and stops after a second invalid reply', async () => {
  const error=invalid({jsonStatus:'invalid_json'});
  let calls=0;
  await assert.rejects(withStructuredRepair(async()=>{calls++;throw error;},
    [{role:'user',content:'evidence'}],{canRetry:()=>false}),reason=>reason===error);
  assert.equal(calls,1);
  await assert.rejects(withStructuredRepair(async()=>{calls++;throw error;},
    [{role:'user',content:'evidence'}]),reason=>reason===error);
  assert.equal(calls,3);
});
