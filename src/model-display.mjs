const providerName=provider=>provider==='meta'?'Meta Model API':provider==='muse-host'?'Muse Code':provider;

export function modelDisplay(model,{status=true}={}){
  if(!model)return 'not configured';
  const name=model.modelId||model.model||model.name;
  return [name,providerName(model.provider),status?model.connection:null].filter(Boolean).join(' · ');
}
