import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { repositoryInfo } from './repository.mjs';
import { read, rootFrom, FILE } from './store.mjs';

export const projectPath=(value,base=process.cwd())=>path.resolve(base,value==='~'?os.homedir():value.startsWith('~/')?path.join(os.homedir(),value.slice(2)):value);
export function isBypassSource(root){
  try{return JSON.parse(fs.readFileSync(path.join(root,'package.json'),'utf8')).name==='@bypass-labs/cli-skeleton';}catch{return false;}
}
export async function workspaceInfo(cwd,selectedRoot=null){
  const root=selectedRoot||rootFrom(cwd,false),repository=await repositoryInfo(root);
  const state=fs.existsSync(path.join(root,FILE))?read(root):null;
  return {hostWorkspace:cwd,selectedRepository:selectedRoot,selectionRequired:!selectedRoot,repository,
    isBypassSource:isBypassSource(root),initialized:!!state,
    app:state?.targets.find(t=>t.name===state.activeTarget)?.url||null,
    warning:isBypassSource(root)?'This is Bypass tooling source. Choose the application repository before reviewing its deployed app.':null,
    next:selectedRoot?'Read bypass_context, then show the repository and app together.':'Ask which application repository to review. Use bypass_connect_repository with the user-selected local folder or Git URL; do not silently initialize the current folder.'};
}
