// Opt-in live provider checks: available environment references only; no agent credential stores.
import { providers, apiProfile } from '../src/providers.mjs';
import { testModel } from '../src/models.mjs';
const results=[];
for(const [provider,preset] of Object.entries(providers)){
  if(provider==='custom'||!process.env[preset.secretEnv]){results.push({provider,status:'not_run',reason:provider==='custom'?'Explicit custom endpoint/model needed':'API key environment variable not set'});continue;}
  try{const profile=apiProfile('smoke',{provider,stream:false});results.push({provider,status:'passed',check:await testModel(profile,undefined,{timeoutMs:45000})});}
  catch(error){results.push({provider,status:'failed',reason:error.details?.reason||'error',message:error.message});process.exitCode=1;}
}
console.log(JSON.stringify({kind:'live provider smoke',syntheticPromptOnly:true,results},null,2));
