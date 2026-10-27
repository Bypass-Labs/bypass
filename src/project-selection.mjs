import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { repositoryInfo } from './repository.mjs';
import { VERSION } from './util.mjs';
import { read, rootFrom, FILE } from './store.mjs';

export const projectPath=(value,base=process.cwd())=>path.resolve(base,value==='~'?os.homedir():value.startsWith('~/')?path.join(os.homedir(),value.slice(2)):value);
export function isBypassSource(root){
  try{return JSON.parse(fs.readFileSync(path.join(root,'package.json'),'utf8')).name==='@bypass-labs/cli-skeleton';}catch{return false;}
}
export async function workspaceInfo(cwd,selectedRoot=null){
  const root=selectedRoot||rootFrom(cwd,false),repository=await repositoryInfo(root);
  const state=fs.existsSync(path.join(root,FILE))?read(root):null;
  return {version:VERSION,availableEngines:['docker','mock'],hostWorkspace:cwd,selectedRepository:selectedRoot,selectionRequired:!selectedRoot,repository,
    isBypassSource:isBypassSource(root),initialized:!!state,
    app:selectedRoot?state?.targets.find(t=>t.name===state.activeTarget)?.url||null:null,
    warning:isBypassSource(root)?'This is Bypass tooling source. Choose the application repository before reviewing its deployed app.':null,
    next:'Call bypass_onboarding for the ordered setup checklist. Ask one plain-language question for its next missing step; perform the tool calls yourself.'};
}
