import { promptValue } from './interaction.mjs';
import { apiProfile, listProviderModels, providers } from './providers.mjs';
import { testModel } from './models.mjs';
import { loopback } from './network.mjs';
import { Fault, need, registerSecret } from './util.mjs';

const hostedMuse=/^muse-(?:wonder|spark)-/;
const knownMuse={
  'muse-wonder-1.0':{label:'Muse Wonder 1.0 — most capable',description:'Recommended for deep, long-running security reviews.',rank:0},
  'muse-spark-1.3':{label:'Muse Spark 1.3 — faster and lower cost',description:'Strong fit for responsive reviews and tighter tool loops.',rank:10},
  'muse-spark-1.2':{label:'Muse Spark 1.2',description:'Previous Muse Spark release.',rank:20},
  'muse-spark-1.1':{label:'Muse Spark 1.1',description:'Original Muse Spark release.',rank:30},
  'muse-spark-1.3-contributor':{label:'Muse Spark 1.3 Contributor — lowest cost',description:'Prompts, code, context, and responses may be used to improve Meta models.',rank:120},
  'muse-spark-1.2-contributor':{label:'Muse Spark 1.2 Contributor',description:'Previous release; content may be used to improve Meta models.',rank:140}
};

export function museModelChoices(ids){
  return ids.filter(id=>hostedMuse.test(id)).map(id=>({id,model:id,label:knownMuse[id]?.label||id,description:knownMuse[id]?.description||'Muse reasoning model available to this Meta team.',rank:knownMuse[id]?.rank??100})).sort((a,b)=>a.rank-b.rank||a.id.localeCompare(b.id));
}

// First-run setup intentionally exposes only the two supported Muse routes.
// Existing provider plumbing remains available to explicit/manual profiles.
export async function promptMuseProfile(ask,pick,{secret,write=()=>{},activity,signal,metaBaseUrl=providers.meta.baseUrl,forceSecret=false}={}){
  const selection=await pick('Where should Muse inference run?',[
    {id:'meta',provider:'meta',name:'meta',label:'Meta Model API (recommended)',description:'Hosted Muse Wonder and Muse Spark; pay-as-you-go API key.'},
    {id:'local',provider:'custom',name:'local-muse',label:'Local Muse model',description:'Muse Spark Open or Muse Glimmer on this computer.'}
  ]);
  need(selection,'Choose a Muse inference connection.');
  const run=(label,work)=>activity?activity(label,work,{cancelable:true}):work(signal);
  if(selection.id==='meta'){
    const secretEnv='MODEL_API_KEY';
    if(process.env[secretEnv]&&!forceSecret)write(`Meta Model API authentication · using ${secretEnv} from this terminal.`);
    else{
      need(secret,'Meta Model API authentication needs a masked key prompt. Set MODEL_API_KEY before launching Bypass in a non-interactive environment.',3,{reason:'credential_missing'});
      write('Meta Model API authentication');
      const value=String(await secret('Meta Model API key')).trim();
      need(value,'Enter a Meta Model API key.',3,{reason:'credential_missing'});
      process.env[secretEnv]=value;registerSecret(value);
    }
    const base={provider:'meta','base-url':metaBaseUrl,'secret-env':secretEnv,transport:'responses',model:providers.meta.model};
    const catalog=await run('Authenticate with Meta Model API',async operationSignal=>{
      const ids=await listProviderModels(apiProfile('meta-onboarding',base),{signal:operationSignal});
      const models=museModelChoices(ids);need(models.length,'This Meta team has no supported Muse Wonder or Muse Spark models.',3,{reason:'model_access'});return models;
    });
    write(`✓ Authenticated with Meta Model API · ${catalog.length} Muse model${catalog.length===1?'':'s'} available.`);
    const model=await pick('Choose a Muse model',catalog,0);need(model,'Choose a Muse model.');
    const config={...base,model:model.model};
    write('Testing a small synthetic prompt; no repository content is sent. Meta Model API usage may apply.');
    const check=await run(`Connect ${model.label.split(' — ')[0]}`,operationSignal=>testModel(apiProfile('meta',{...config,stream:false}),null,{signal:operationSignal,onProgress:progress=>write(`  ${progress.message}`)}));
    write(`✓ ${model.label.split(' — ')[0]} key authenticated · billing and inference working.`);
    return {selection,config,check,catalog};
  }

  const baseUrl=await promptValue(ask,'Local Muse server URL',[{value:'http://127.0.0.1:8000/v1',label:'Local OpenAI-compatible server',description:'Muse Spark Open or Muse Glimmer'}],{write});
  let url;try{url=new URL(baseUrl);}catch{throw new Fault('Enter a valid local Muse server URL.',3,{reason:'unsupported_request'});}
  need(loopback(url.hostname),'First-run local Muse setup currently requires a loopback URL. Use model add for a reviewed private or hosted endpoint.');
  const model=await promptValue(ask,'Served Muse model ID',[{value:'meta-models/Muse-Spark-Open-816B-A42B-NVFP4',label:'Muse Spark Open',description:'Use the exact ID exposed by your server'},{value:'Muse-Glimmer-30B',label:'Muse Glimmer',description:'Use the exact ID exposed by your server'}],{write});
  const access=await pick('Does this local Muse server require an API key?',[
    {id:'none',label:'No API key (recommended)',description:'Typical localhost development server.'},
    {id:'key',label:'Use an API key',description:'Authenticate to a protected local endpoint.'}
  ]);
  const secretEnv='BYPASS_LOCAL_MUSE_KEY';
  if(access.id==='key'&&!process.env[secretEnv]){
    need(secret,'Set BYPASS_LOCAL_MUSE_KEY before launching Bypass in a non-interactive environment.',3,{reason:'credential_missing'});
    const value=String(await secret('Local Muse API key')).trim();need(value,'Enter the local Muse API key.',3,{reason:'credential_missing'});process.env[secretEnv]=value;registerSecret(value);
  }else if(access.id==='none'&&!process.env[secretEnv])process.env[secretEnv]='local-muse-no-key';
  const config={provider:'custom','base-url':baseUrl,model,'secret-env':secretEnv,transport:'chat'};
  const check=await run('Connect local Muse model',operationSignal=>testModel(apiProfile('local-muse',{...config,stream:false}),null,{signal:operationSignal,onProgress:progress=>write(`  ${progress.message}`)}));
  write(`✓ Local Muse model authenticated and ready · ${model}`);
  return {selection,config,check,catalog:[]};
}
// Shared by the first-run wizard and the terminal Models screen. Only the
// variable name is collected; never read/persist the secret through a prompt.
export async function promptAPIProfile(ask,pick){
  const selection=await pick('Standalone AI uses your provider API key (separate billing from Muse). Choose provider:',Object.entries(providers).map(([provider,p])=>({provider,name:provider,label:p.label,preset:p})));
  if(!selection)return null;
  const p=selection.preset||providers[selection.provider];
  const config={provider:selection.provider};
  config['secret-env']=await promptValue(ask,'API key environment variable NAME (never paste its value)',
    [...new Set([p.secretEnv,'LLM_KEY',...(selection.provider==='meta'?['META_API_KEY']:[])])]);
  config.model=await promptValue(ask,'Model ID',p.model?[p.model]:[]);
  config['base-url']=await promptValue(ask,'API base URL (press Enter for this provider)',p.baseUrl?[p.baseUrl]:[]);
  config.transport=p.transport;
  if(selection.provider==='custom')config.transport=await promptValue(ask,'API transport: chat or responses',['chat','responses']);
  return {selection,config};
}
