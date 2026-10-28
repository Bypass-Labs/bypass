import { choiceInput } from './interaction.mjs';
import path from 'node:path';
import { initStore, read, change } from './store.mjs';
import { inventory } from './repository.mjs';
import { appOriginInput, scopeReady } from './network.mjs';
import { userStateDirectory, rememberProjectOwnership, sharedOwnership } from './ownership-store.mjs';
import { hash, need } from './util.mjs';

export const reviewChoices=[
  {id:'code',label:'Code only',description:'Review your repository for security issues.'},
  {id:'combined',label:'Code + running app (recommended)',description:'Review your code and test the app for vulnerabilities.'},
  {id:'live',label:'Running app only',description:'Test an app using its URL. No repository required.'}
];
export const reviewQuestion='What would you like Bypass to review?';
export const reviewInput=()=>choiceInput('mode',reviewChoices,{recommended:'combined'});
export async function sourceStatus(root){
  if(readableAppProfile(root))return {ready:false,sourceFileCount:0,reason:'This is an app-only profile. Choose a repository to review code.'};
  const inv=await inventory(root);
  return {ready:inv.sourceFileCount>0,sourceFileCount:inv.sourceFileCount,...(!inv.sourceFileCount?{reason:'No eligible application source files were found. Choose the application folder or Git URL before continuing.'}:{})};
}
const readableAppProfile=root=>{try{return read(root).project.repository.kind==='app';}catch{return false;}};
export async function requireSource(root){const source=await sourceStatus(root);need(source.ready,source.reason,2);return source;}
export async function createAppProfile(url){
  const origin=appOriginInput(url),root=path.join(userStateDirectory(),'apps',hash(origin));
  const {resumed}=initStore(root,{kind:'app',path:root,origin,remote:null,branch:null,commit:null},new URL(origin).hostname);
  await change(root,s=>{s.settings.reviewMode='live';s.settings.analysisEngine='docker';});
  return {root,resumed};
}
// Carry only the selected app's exact setup during an explicit checkout switch.
// Findings, probes, credentials and other project evidence remain with their source.
export async function carryAppSetup(previousRoot,root,{url,environment,mode}={}){
  if(!previousRoot||previousRoot===root)return;
  const previous=read(previousRoot);if(previous.demo||previous.poc)return;
  rememberProjectOwnership(previous);
  const source=previous.targets.find(t=>t.name===previous.activeTarget);if(!source)return;
  if(mode==='code')return;
  if(!url&&previous.project.repository.kind!=='app'){
    const remote=previous.project.repository.remote;
    if(!remote||remote!==read(root).project.repository.remote)return;
  }
  if(url&&appOriginInput(url)!==source.url||environment&&environment!==source.environment)return;
  await change(root,state=>{
    let target=state.targets.find(t=>t.url===source.url&&t.environment===source.environment);
    if(!target){
      if(state.targets.length)return;
      target={name:source.name,url:source.url,environment:source.environment,createdAt:source.createdAt,ownership:{status:'pending'},authorization:null};
      if(source.environment!=='local'){
        target.ownership=sharedOwnership(source.url)||{status:'pending'};
        if(source.challenge)target.challenge=structuredClone(source.challenge);
      }else{target.ownership=structuredClone(source.ownership);if(source.challenge)target.challenge=structuredClone(source.challenge);}
      state.targets.push(target);state.activeTarget=target.name;
    }
    if(source.environment!=='local'&&target.ownership.status!=='verified')target.ownership=sharedOwnership(source.url)||target.ownership;
    if(!target.authorization&&source.authorization){
      try{scopeReady({...target,authorization:source.authorization});target.authorization=structuredClone(source.authorization);}catch{/* Expired or revoked permission needs renewal. */}
    }
  });
}

export async function repositoryAction(cwd,root,repository,dir){
  const fs=await import('node:fs');
  const {repositoryInfo}=await import('./repository.mjs');
  const {projectPath}=await import('./project-selection.mjs');
  const value=repository.trim().replace(/^\[[^\]\n]*\]\(([^)\n]+)\)$/,'$1');
  const remote=/^(https:\/\/|ssh:\/\/|git@)/.test(value);
  const key=value=>value?.replace(/^git@([^:]+):/,'https://$1/').replace(/^ssh:\/\/git@/,'https://').replace(/\.git\/?$/,'').replace(/\/$/,'');
  if(!remote){const location=projectPath(value,cwd);return root===location?null:{id:'repository',tool:'bypass_connect_repository',automatic:true,arguments:{repository:location,confirmed:true}};}
  const current=root?await repositoryInfo(root):null;
  if(current?.remote&&key(current.remote)===key(value))return null;
  const name=value.split('/').at(-1).replace(/\.git$/,'').replace(/[^a-zA-Z0-9_-]/g,'-')||'application';
  let destination=dir?projectPath(dir,cwd):path.join(cwd,name);
  if(!dir){
    const candidate=await repositoryInfo(destination);
    if(candidate.gitRoot===destination&&key(candidate.remote)===key(value))return {id:'repository',tool:'bypass_connect_repository',automatic:true,arguments:{repository:destination,confirmed:true},message:'Use the matching existing checkout of the supplied repository.'};
    const base=destination;let n=2;
    while(fs.existsSync(destination))destination=base+'-'+n++;
  }
  return {id:'repository',tool:'bypass_connect_repository',automatic:true,arguments:{repository:value,dir:destination,confirmed:true},message:`Connect the supplied repository before app setup. Clone into ${destination}.`};
}
