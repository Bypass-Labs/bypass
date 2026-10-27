import { providers } from './providers.mjs';
// Shared by the first-run wizard and the terminal Models screen. Only the
// variable name is collected; never read/persist the secret through a prompt.
export async function promptAPIProfile(ask,pick){
  const selection=await pick('Standalone AI uses your provider API key (separate billing from Muse). Choose provider:',Object.entries(providers).map(([provider,p])=>({provider,name:provider,label:p.label,preset:p})));
  if(!selection)return null;
  const p=selection.preset||providers[selection.provider];
  const config={provider:selection.provider};
  config['secret-env']=await ask('API key environment variable NAME (never paste its value)',p.secretEnv);
  config.model=await ask('Model ID',p.model||'');
  config['base-url']=await ask('API base URL (press Enter for this provider)',p.baseUrl||'');
  config.transport=p.transport;
  if(selection.provider==='custom')config.transport=await ask('API transport: chat or responses','chat');
  return {selection,config};
}
