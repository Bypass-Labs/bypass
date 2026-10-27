import { read, change } from './store.mjs';
import { replay } from './portable-check.mjs';
import { probeConfiguration } from './review-readiness.mjs';
import { named, now, redact } from './util.mjs';
import { credentialEnvironment } from './credentials.mjs';

export async function validateProbe(root,name,{target,signal,env=process.env}={}){
  const state=read(root),app=named(state.targets,target||state.activeTarget,'Target'),probe=named(app.probes||[],name,'Probe');
  let signature,result;
  try{
    env=await credentialEnvironment(state,app,[named(state.identities,probe.binding.owner,'Identity'),named(state.identities,probe.binding.outsider,'Identity')],{env,signal});
    const config=probeConfiguration(state,app,probe,env);signature=config.signature;
    result=await replay(config.spec,{env,signal,positiveOnly:true});
  }catch(error){result={status:'blocked',reason:error.message,requests:0,controls:[],modelCalls:0};}
  const validation=redact({...result,checkedAt:now(),...(signature?{signature}:{})});
  await change(root,s=>{
    const current=named(s.targets,app.name,'Target').probes?.find(p=>p.name===name);
    // A concurrent edit must not inherit the old resource's validation.
    if(current&&JSON.stringify(current.binding)===JSON.stringify(probe.binding))current.validation=validation;
  });
  const {signature:_,...visible}=validation;
  return {name,target:app.name,...visible,securityConclusion:false};
}
