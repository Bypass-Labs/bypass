import fs from 'node:fs';
import path from 'node:path';
import { id, now, need, Fault, delay } from './util.mjs';

export const FILE = '.bypass/state.json';
export const DEFAULT_BYPASSIGNORE = '.env\n.env.*\n*.pem\n*.key\nnode_modules/\n.git/\n.bypass/\n';
const BYPASS_GITIGNORE_RULES = ['.bypass/state.json','.bypass/.lock/','.bypass/runs/','.bypass/drafts/','.bypass/discovery/','.bypass/demo-state.json','.bypass/worker.json','.bypass/*.log'];
export function rootFrom(start = process.cwd(), required = true) {
  let dir = path.resolve(start);
  while (true) {
    if (fs.existsSync(path.join(dir, FILE))) return dir;
    const parent = path.dirname(dir); if (parent === dir) break; dir = parent;
  }
  if (required) throw new Fault('No Bypass project found. Run bypass init, or pass --project <directory>.');
  return path.resolve(start);
}
export function atomic(file, data) {
  fs.mkdirSync(path.dirname(file), {recursive:true, mode:0o700});
  const tmp = `${file}.${process.pid}.${id('tmp')}`;
  fs.writeFileSync(tmp, typeof data === 'string' ? data : JSON.stringify(data, null, 2) + '\n', {mode:0o600});
  fs.renameSync(tmp, file);
}
export function read(root) {
  try { const data = JSON.parse(fs.readFileSync(path.join(root, FILE), 'utf8')); need(data.schemaVersion === 1, 'Unsupported project state version.'); return data; }
  catch (e) { if (e instanceof Fault) throw e; throw new Fault(`Cannot read Bypass state in ${root}: ${e.message}`); }
}
export function snapshot(state) {
  return {schemaVersion:1, project:state.project, settings:state.settings, models:state.models, activeModel:state.activeModel,
    targets:state.targets.map(({challenge, authorization, ...t}) => ({...t, ownership:t.ownership?.status, authorization:authorization ? {scope:authorization.paths, methods:authorization.methods, expiresAt:authorization.expiresAt} : null})),
    activeTarget:state.activeTarget, identities:state.identities, note:'Generated portable summary. Use bypass config / target / model to update canonical local state.'};
}
export function save(root, state) {
  state.updatedAt = now(); atomic(path.join(root, FILE), state);
  atomic(path.join(root, '.bypass/project.json'), snapshot(state));
  atomic(path.join(root, '.bypass/checks.json'), state.checks);
}
export async function change(root, fn) {
  const lock = path.join(root, '.bypass/.lock');
  const deadline = Date.now() + 8000;
  while (true) {
    try { fs.mkdirSync(lock); fs.writeFileSync(path.join(lock,'owner'), String(process.pid)); break; }
    catch (e) {
      if (e.code !== 'EEXIST') throw e;
      try {
        const pid = Number(fs.readFileSync(path.join(lock,'owner'),'utf8'));
        try { process.kill(pid,0); } catch (err) { if (err.code === 'ESRCH') { fs.rmSync(lock,{recursive:true}); continue; } }
      } catch { try { if (Date.now() - fs.statSync(lock).mtimeMs > 30000) { fs.rmSync(lock,{recursive:true}); continue; } } catch { continue; } }
      need(Date.now() < deadline, 'Project is busy. Retry shortly.', 3); await delay(40);
    }
  }
  try { const state = read(root); const result = fn(state); need(!result?.then, 'State transactions must be synchronous.'); save(root,state); return result; }
  finally { fs.rmSync(lock,{recursive:true,force:true}); }
}
export function repositoryFilePlan(root,{trackedFiles='apply',bypassIgnore=DEFAULT_BYPASSIGNORE}={}) {
  need(['apply','skip'].includes(trackedFiles),'Tracked repository files must be apply or skip.',3);
  if (fs.existsSync(path.join(root,FILE))) return [];
  const plan=[{path:'.bypass/',action:'created',purpose:'private project state and evidence',commit:false}];
  const ignore=path.join(root,'.gitignore'),previous=fs.existsSync(ignore)?fs.readFileSync(ignore,'utf8'):'';
  const lines=previous.split('\n'),missing=lines.includes('.bypass/')?[]:BYPASS_GITIGNORE_RULES.filter(rule=>!lines.includes(rule));
  if(missing.length)plan.push({path:'.gitignore',action:trackedFiles==='skip'?'skipped':previous?'updated':'created',purpose:'exclude private Bypass runtime state',commit:true,details:{add:missing}});
  if(!fs.existsSync(path.join(root,'.bypassignore')))plan.push({path:'.bypassignore',action:trackedFiles==='skip'?'skipped':'created',purpose:'exclude secrets, dependencies, and local state from source review',commit:true,details:{content:bypassIgnore}});
  return plan;
}
export function initStore(root, repository, name, options={}) {
  fs.mkdirSync(root, {recursive:true});
  if (fs.existsSync(path.join(root,FILE))) return {state:read(root), resumed:true, fileChanges:[], filePlan:[]};
  const filePlan=repositoryFilePlan(root,options),fileChanges=[];
  try{
    fs.accessSync(root,fs.constants.W_OK);
    for(const item of filePlan.filter(item=>item.action!=='skipped'&&item.path!=='.bypass/')){
      const file=path.join(root,item.path);if(fs.existsSync(file))fs.accessSync(file,fs.constants.W_OK);
    }
  }catch{throw new Fault('Repository setup files are read-only. Fix their permissions, choose “Leave tracked files unchanged,” or run bypass init --plan.',3,{reason:'repository_read_only'});}
  const state = {schemaVersion:1, project:{id:id('project'),name:name || path.basename(root),root,repository,createdAt:now()}, settings:{engine:'mock',evidence:'local',autoSave:true,requestTimeoutMs:8000,ownershipVerification:'off'},
    models:[],targets:[],identities:[],findings:[],checks:[],runs:[],monitors:[],events:[],activeModel:null,activeTarget:null,integrations:{},auth:null,demo:null};
  save(root,state);
  for(const item of filePlan){
    if(item.action==='skipped')continue;
    if(item.path==='.gitignore'){
      const file=path.join(root,item.path),previous=fs.existsSync(file)?fs.readFileSync(file,'utf8'):'';
      fs.appendFileSync(file,`${previous.endsWith('\n')||!previous?'':'\n'}\n# Bypass local evidence and runtime state\n${item.details.add.join('\n')}\n`);
    }else if(item.path==='.bypassignore')fs.writeFileSync(path.join(root,item.path),item.details.content);
    fileChanges.push({path:item.path,action:item.action,purpose:item.purpose,commit:item.commit});
  }
  return {state,resumed:false,fileChanges,filePlan};
}
export function event(state, kind, message, data = {}) {
  const item = {id:id('event'),at:now(),kind,message,...data}; state.events.push(item); state.events = state.events.slice(-200); return item;
}
export function writeEvidence(root, run) { atomic(path.join(root,'.bypass/runs',`${run.id}.json`),run); }
