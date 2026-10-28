import test from 'node:test';
import assert from 'node:assert/strict';
import { choiceInput, promptValue, confirmChoice, accountInput } from '../src/interaction.mjs';
import { promptAPIProfile } from '../src/provider-setup.mjs';
import { reviewInput } from '../src/application-setup.mjs';
import { appConnection } from '../src/app-connection.mjs';
import { registrationStatus } from '../src/registration.mjs';

test('native decisions have custom instructions; only grounded choices receive a recommendation',()=>{
  const inputs=[reviewInput(),appConnection({url:'https://app.example.com'}).input,accountInput({url:'https://app.example.com',environment:'production'})];
  for(const input of inputs){assert.equal(input.hostControl,'request_user_input');assert.equal(input.allowCustom,true);assert.ok(input.customInput);}
  assert.equal(inputs[0].choices.filter(c=>c.recommended).length,1);
  assert.equal(inputs[1].choices.some(c=>c.recommended),false,'Do not guess deployment environment');
  assert.equal(choiceInput('project',[{id:'a',label:'Project A'},{id:'b',label:'Project B'}]).choices.some(c=>c.recommended),false);
  assert.equal(registrationStatus(null).nextAction,null,'No premature account question before app selection');
});

test('plain terminal picks defaults and numbered options while preserving direct custom values',async()=>{
  const output=[],values=['/api','/'],write=s=>output.push(s);
  assert.equal(await promptValue(async(_q,fallback)=>fallback,'Paths',values,{write}),'/api');
  assert.equal(await promptValue(async()=> '2','Paths',values,{write}),'/');
  assert.equal(await promptValue(async()=> '/v2','Paths',values,{write}),'/v2');
  const answers=['3','/custom'];assert.equal(await promptValue(async()=>answers.shift(),'Paths',values,{write}),'/custom');
  assert.match(output.join('\n'),/recommended/);assert.match(output.join('\n'),/custom value/);
  assert.equal(await confirmChoice(async()=> '2','Accept?',{write}),false);
  assert.equal(await confirmChoice(async()=> '1','Accept?',{write}),true);
});

test('provider suggestions and custom values travel to the profile unchanged; secrets are never requested',async()=>{
  const prompts=[],custom=['MY_MODEL_KEY','my-model','https://models.example.com/v1','responses'];
  const ask=async label=>{assert.fail('Preset/custom picker should handle these values: '+label);};
  ask.select=async(title,items,options)=>{prompts.push(title);assert.equal(options.allowCustom,true);assert.equal(items.at(-1).custom,true);return {custom:true,value:custom.shift()};};
  const result=await promptAPIProfile(ask,async(_title,items)=>items.find(x=>x.provider==='openai'));
  assert.equal(result.config['secret-env'],'MY_MODEL_KEY');assert.equal(result.config.model,'my-model');assert.equal(result.config['base-url'],'https://models.example.com/v1');
  assert.match(prompts[0],/NAME.*never paste/);assert.equal(custom.length,1);
});
