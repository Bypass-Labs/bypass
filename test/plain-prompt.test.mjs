import test from 'node:test';
import assert from 'node:assert/strict';
import {PassThrough} from 'node:stream';
import {createPrompt} from '../src/ui.mjs';

test('plain terminal masks API keys, resumes normal input, and displays audit progress',async()=>{
  const input=new PassThrough(),output=new PassThrough();
  input.isTTY=true;output.isTTY=true;input.isRaw=false;
  input.setRawMode=value=>{input.isRaw=value;};
  let printed='';output.on('data',chunk=>{printed+=chunk.toString();});
  const prompt=createPrompt({input,output,env:{BYPASS_PLAIN:'1'}});
  try{
    const secret=prompt.secret('Meta Model API key');
    input.write('fake-secret\r');
    assert.equal(await secret,'fake-secret');
    assert.doesNotMatch(printed,/fake-secret|f•a•k•e/);
    assert.match(printed,/Meta Model API key: •{11}/);
    const answer=prompt.ask('Choose','1');
    input.write('2\r');
    assert.equal(await answer,'2');
    prompt.write('PHASE 1/6  Mapping routes');
    assert.match(printed,/PHASE 1\/6  Mapping routes/);
  }finally{prompt.close();}
});
