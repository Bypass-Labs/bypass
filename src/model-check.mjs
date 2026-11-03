import { execute } from './service.mjs';
import { MODEL_CHECK_TIMEOUT_MS } from './models.mjs';
import { read } from './store.mjs';
import { cleanText, redact, named } from './util.mjs';

// Human feedback stays out of the service layer and machine-readable CLI output.
export async function checkModelConnection(root, name, io={}) {
  const say=value=>(io.write||console.log)(cleanText(redact(value)));
  const state=read(root),profile=named(state.models,name||state.activeModel,'Model');
  say(`\nChecking the model connection (${profile.timeoutMs===0?'no timeout; cancel to stop':`up to ${MODEL_CHECK_TIMEOUT_MS/1000} seconds`}). No repository content is sent.`);
  if(io.run)say('Press Enter to skip this check and continue setup. Ctrl+C exits; your choices stay saved.');
  const work=signal=>execute('model test',name?[name]:[],{project:root},{signal,onProgress:progress=>{
    const timing=Number.isFinite(progress.elapsedSeconds)&&Number.isFinite(progress.timeoutSeconds)?` (${progress.elapsedSeconds}s / ${progress.timeoutSeconds}s)`:'';
    say(`  ${progress.message}${timing}`);
  }});
  try {
    const result=io.run?await io.run(work):await work(io.signal);
    say(`✓ Model replied successfully in ${(result.check.elapsedMs/1000).toFixed(1)}s. Connection verified.`);
    return result;
  } catch(error) {
    if(error.details?.skipped||io.rich&&error.details?.cancelled){say('Connection check skipped. Your model profile is saved; you can test it later.');return {skipped:true};}
    throw error;
  }
}
