import { choiceInput } from './interaction.mjs';
import path from 'node:path';
import fs from 'node:fs';
import { read, change, atomic } from './store.mjs';
import { safeRequest, scopeReady } from './network.mjs';
import { need, named, hash, now, delay, registerSecret, redact } from './util.mjs';

// Literal data only: never evaluate a downloaded script or combine values from
// separate config objects. Multiple Firebase apps need an explicit selection.
export function firebaseConfigs(text){
  const found=new Map();
  for(const object of text.matchAll(/\{[^{}]{1,8192}\}/g)){
    const fields={};
    for(const item of object[0].matchAll(/(?:^|[,{\s])(?:["']?)(apiKey|projectId|authDomain|appId|VITE_FIREBASE_API_KEY|VITE_FIREBASE_PROJECT_ID)["']?\s*:\s*(["'])([^"'\\\r\n]{1,256})\2/g))fields[item[1]]=item[3];
    const apiKey=fields.apiKey||fields.VITE_FIREBASE_API_KEY,projectId=fields.projectId||fields.VITE_FIREBASE_PROJECT_ID;
    if(!/^AIza[A-Za-z0-9_-]{20,100}$/.test(apiKey||'')||!/^[a-z][a-z0-9-]{3,62}$/.test(projectId||''))continue;
    if(fields.authDomain?.endsWith('.firebaseapp.com')&&fields.authDomain!==projectId+'.firebaseapp.com')continue;
    found.set(hash({apiKey,projectId}),{apiKey,projectId});
  }
  return [...found.values()];
}
function linkedAssets(body,base){
  const candidates=[];
  for(const match of body.matchAll(/<(?:script|link)\b[^>]*\b(?:src|href)\s*=\s*["']([^"']+)["'][^>]*>/gi))candidates.push(match[1]);
  for(const match of body.matchAll(/(?:\bfrom\s*|\bimport\s*\(?\s*)["']([^"']+\.m?js(?:\?[^"']*)?)["']/g))candidates.push(match[1]);
  return candidates.flatMap(value=>{try{const url=new URL(value,base);return url.origin===new URL(base).origin&&!url.username&&!url.password&&/\.m?js$/.test(url.pathname)&&!url.hash&&!url.search?[url.href]:[];}catch{return [];}});
}
export async function discoverRegistration(root,o={},context={}){
  const state=read(root),target=named(state.targets,o.target||state.activeTarget,'Target');
  scopeReady(target);
  const request=context.request||safeRequest,signal=context.signal;
  const result={kind:'registration-discovery',status:'not_found',provider:'firebase',origin:target.url,requests:0,observations:[],blockedPaths:[],configFile:null,projectId:null,accountCreation:false};
  const start=o.path||'/',queue=[new URL(start,target.url).href];
  if(!o.path)queue.push(target.url+'/index.html');
  const seen=new Set(),candidates=new Map();
  context.onProgress?.({message:'Finding public Firebase configuration in the authorized app pages and linked scripts'});
  while(queue.length&&result.requests<8){
    const url=new URL(queue.shift());if(seen.has(url.href))continue;seen.add(url.href);
    need(url.origin===target.url&&!url.username&&!url.password&&!url.search&&!url.hash,'Discovery URLs must stay on the verified app origin with no query or credentials.');
    const allowed=app=>{scopeReady(app);if(!app.authorization.publicConfigDiscovery)scopeReady(app,url.pathname,'GET');};
    try{allowed(named(read(root).targets,target.name,'Target'));}catch{result.blockedPaths.push(url.pathname);continue;}
    const fingerprint=hash(target.authorization);
    const scheduledAt=await change(root,s=>{const app=named(s.targets,target.name,'Target');allowed(app);need(hash(app.authorization)===fingerprint,'Scope changed during config discovery.',3);const at=Math.max(Date.now(),app.nextDirectRequestAt||0);app.nextDirectRequestAt=at+Math.ceil(1000/app.authorization.maxRequestsPerSecond);return at;});
    await delay(Math.max(0,scheduledAt-Date.now()),undefined,{signal});
    const current=named(read(root).targets,target.name,'Target');allowed(current);need(hash(current.authorization)===fingerprint,'Scope changed before config discovery request.',3);
    if(signal?.aborted)throw signal.reason;
    result.requests++;
    context.onProgress?.({message:`Reading public sign-in setup: ${url.pathname} (${result.requests}/8 maximum requests)`});
    try{
      const response=await request(url.href,{allowLocal:target.environment==='local',method:'GET',headers:{Accept:'text/html,application/javascript,application/json'},maxBytes:4*1024*1024,timeout:Math.min(state.settings.requestTimeoutMs,8000),signal});
      result.observations.push({url:url.href,status:response.status,contentHash:hash(response.body)});
      if(response.status>=300&&response.status<400&&response.headers?.location){const redirect=new URL(response.headers.location,url);if(redirect.origin===target.url&&!redirect.search&&!redirect.hash)queue.unshift(redirect.href);continue;}
      if(response.status<200||response.status>=300)continue;
      for(const config of firebaseConfigs(response.body)){
        registerSecret(config.apiKey);
        const key=hash(config);candidates.set(key,{...config,source:url.href,contentHash:hash(response.body)});
      }
      for(const asset of linkedAssets(response.body,url.href))if(queue.length<32&&!seen.has(asset))queue.push(asset);
    }catch(error){if(signal?.aborted)throw error;result.observations.push({url:url.href,error:redact(error.message)});}
  }
  if(signal?.aborted)throw signal.reason;
  const current=named(read(root).targets,target.name,'Target');scopeReady(current);
  need(hash(current.authorization)===hash(target.authorization),'Scope changed during config discovery.',3);
  const matches=[...candidates.values()].filter(c=>!o['project-id']||c.projectId===o['project-id']);
  if(matches.length===1){
    const config=matches[0],file=path.join(root,'.bypass/discovery',hash(target.url)+'.json');
    const ignore=path.join(root,'.gitignore'),rule='.bypass/discovery/';
    const previous=fs.existsSync(ignore)?fs.readFileSync(ignore,'utf8'):'';
    if(!previous.split('\n').includes(rule))fs.appendFileSync(ignore,`${previous.endsWith('\n')||!previous?'':'\n'}${rule}\n`);
    atomic(file,{VITE_FIREBASE_API_KEY:config.apiKey,VITE_FIREBASE_PROJECT_ID:config.projectId,origin:target.url,source:config.source,contentHash:config.contentHash,discoveredAt:now()});
    Object.assign(result,{status:'found',configFile:file,projectId:config.projectId,source:config.source,message:'Public Firebase config discovered. Continue the already-authorized registration setup; no account was created by discovery.'});
  }else if(matches.length>1)Object.assign(result,{status:'ambiguous',projectIds:[...new Set(matches.map(c=>c.projectId))],message:'Multiple Firebase configurations were observed. Select the intended project before account creation.',nextAction:{tool:'bypass_discover_registration',question:'Which observed Firebase project belongs to this app?',input:choiceInput('project-id',[...new Set(matches.map(c=>c.projectId))].map(id=>({id,label:id,value:id})),{custom:'value'}),requiresAnswer:true}});
  else if(result.blockedPaths.length)Object.assign(result,{status:'scope_required',message:'Public config discovery needs GET access to the listed app pages/assets. Reopen the existing scope picker; do not bypass it with shell requests or ask for config values before trying authorized discovery.',nextAction:{tool:'bypass_onboarding',arguments:{reviewScope:true}}});
  else Object.assign(result,{message:'No complete public Firebase config was found in the bounded app pages and linked scripts. Continue independent checks and offer recovery choices.',nextAction:{question:'How would you like to continue the account checks?',input:choiceInput('registration-recovery',[{id:'continue',label:'Continue other checks',description:'Record signup as a coverage gap.'},{id:'page',label:'Try a known sign-in page',description:'Supply its exact path in the custom field.'},{id:'file',label:'Use a local config file',description:'Supply the file path, not API keys in chat.'}],{recommended:'continue'}),requiresAnswer:true},projectIds:[...new Set([...candidates.values()].map(c=>c.projectId))]});
  await change(root,s=>{named(s.targets,target.name,'Target').registrationDiscovery=result;});
  return result;
}
