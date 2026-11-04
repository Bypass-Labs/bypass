import test from 'node:test';
import assert from 'node:assert/strict';
import { choiceInput, promptValue, confirmChoice, accountInput, scopeSuggestions } from '../src/interaction.mjs';
import { museModelChoices, promptAPIProfile, promptMuseProfile } from '../src/provider-setup.mjs';
import { reviewInput } from '../src/application-setup.mjs';
import { appConnection } from '../src/app-connection.mjs';
import { registrationStatus } from '../src/registration.mjs';
import { metaModelFixture } from './helpers.mjs';

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

test('new app scope defaults to the entire origin while existing grants remain unchanged',()=>{
  assert.deepEqual(scopeSuggestions({authorization:null}).map(item=>item.value),['/','/api']);
  assert.deepEqual(scopeSuggestions({authorization:{paths:['/v1','/public']}}).map(item=>item.value),['/v1,/public','/']);
  assert.deepEqual(scopeSuggestions({authorization:{paths:['/']}}).map(item=>item.value),['/']);
});

test('provider suggestions and custom values travel to the profile unchanged; secrets are never requested',async()=>{
  const prompts=[],custom=['MY_MODEL_KEY','my-model','https://models.example.com/v1','responses'];
  const ask=async label=>{assert.fail('Preset/custom picker should handle these values: '+label);};
  ask.select=async(title,items,options)=>{prompts.push(title);assert.equal(options.allowCustom,true);assert.equal(items.at(-1).custom,true);return {custom:true,value:custom.shift()};};
  const result=await promptAPIProfile(ask,async(_title,items)=>items.find(x=>x.provider==='openai'));
  assert.equal(result.config['secret-env'],'MY_MODEL_KEY');assert.equal(result.config.model,'my-model');assert.equal(result.config['base-url'],'https://models.example.com/v1');
  assert.match(prompts[0],/NAME.*never paste/);assert.equal(custom.length,1);
});

test('Meta onboarding authenticates, discovers only Muse reasoning models, recommends Wonder, and preflights inline',async t=>{
  const meta=await metaModelFixture(t,{models:['muse-image-1.0','muse-spark-1.3-contributor','muse-spark-1.3','muse-wonder-1.0','llama-4']});
  const selections=[],output=[];
  const result=await promptMuseProfile(async()=>assert.fail('Meta setup should not ask for manual profile fields.'),async(title,items)=>{
    selections.push({title,items});return items[0];
  },{metaBaseUrl:meta.baseUrl,write:value=>output.push(value)});
  assert.deepEqual(selections.map(item=>item.title),['Where should Muse inference run?','Choose a Muse model']);
  assert.deepEqual(selections[1].items.map(item=>item.id),['muse-wonder-1.0','muse-spark-1.3','muse-spark-1.3-contributor']);
  assert.match(selections[1].items[0].label,/Muse Wonder 1\.0.*most capable/);
  assert.match(selections[1].items[2].description,/may be used to improve Meta models/);
  assert.equal(result.config.model,'muse-wonder-1.0');
  assert.equal(result.config['secret-env'],'MODEL_API_KEY');
  assert.deepEqual(meta.calls.map(call=>[call.method,call.path]),[['GET','/v1/models'],['POST','/v1/responses']]);
  assert.match(output.join('\n'),/Authenticated with Meta Model API/);
  assert.match(output.join('\n'),/Muse Wonder 1\.0 key authenticated.*billing and inference working/);
  assert.doesNotMatch(JSON.stringify({result,output,selections}),/meta-onboarding-fixture-key/);
});

test('Muse model choices keep Meta naming and do not silently opt into Contributor',()=>{
  const choices=museModelChoices(['muse-spark-1.3-contributor','muse-spark-1.2','muse-image-1.0']);
  assert.deepEqual(choices.map(item=>item.id),['muse-spark-1.2','muse-spark-1.3-contributor']);
  assert.equal(choices[0].id,'muse-spark-1.2');
  assert.match(choices[1].description,/Prompts, code, context, and responses/);
});

test('Contributor onboarding uses bounded fast reasoning for its first audit',async t=>{
  const meta=await metaModelFixture(t,{models:['muse-spark-1.3-contributor']});
  const result=await promptMuseProfile(async()=>assert.fail('No manual profile fields expected.'),
    async(_title,items)=>items[0],{metaBaseUrl:meta.baseUrl,write:()=>{}});
  assert.equal(result.config.model,'muse-spark-1.3-contributor');
  assert.equal(result.config.effort,'minimal');
  assert.equal(result.config['timeout-ms'],120000);
});

test('Meta selection requests a private key immediately when MODEL_API_KEY is absent',async t=>{
  const meta=await metaModelFixture(t,{models:['muse-wonder-1.0']}),raw='inline-meta-key-for-test';delete process.env.MODEL_API_KEY;
  const prompts=[],output=[];
  const result=await promptMuseProfile(async()=>assert.fail('Only the masked secret prompt should collect the key.'),async(_title,items)=>items[0],{
    metaBaseUrl:meta.baseUrl,secret:async title=>{prompts.push(title);return raw;},write:value=>output.push(value)
  });
  assert.deepEqual(prompts,['Meta Model API key']);assert.equal(result.config['secret-env'],'MODEL_API_KEY');
  assert.equal(meta.calls[0].authorization,`Bearer ${raw}`);
  assert.doesNotMatch(JSON.stringify({result,output}),new RegExp(raw));
});
