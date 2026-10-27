import { apiProfile, ProviderSession } from './providers.mjs';
import { need, now } from './util.mjs';
export const modelProfile=apiProfile;
export const MODEL_CHECK_TIMEOUT_MS=45000;
export async function testModel(profile,root,{signal,onProgress,timeoutMs=MODEL_CHECK_TIMEOUT_MS}={}) {
  const started=Date.now();
  const text=await new ProviderSession({...profile,maxTokens:Math.min(profile.maxTokens||1024,1024)}).turn([{role:'user',content:'Reply with exactly BYPASS_MODEL_OK.'}],{signal,onProgress,timeoutMs});
  need(text.trim()==='BYPASS_MODEL_OK','The provider responded but did not return the expected marker. Connection not confirmed.',3,{reason:'unexpected_response'});
  return {status:'connected',provider:profile.provider,model:profile.model,transport:profile.transport,executionMode:'standalone-api',checkedAt:now(),elapsedMs:Date.now()-started,syntheticPrompt:true,repositorySent:false,billing:'provider API key'};
}
