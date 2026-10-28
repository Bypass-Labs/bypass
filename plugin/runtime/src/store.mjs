import fs from 'node:fs';
import path from 'node:path';
import { id, now, need, Fault, delay } from './util.mjs';

export const FILE = '.bypass/state.json';
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
export function initStore(root, repository, name) {
  fs.mkdirSync(root, {recursive:true});
  if (fs.existsSync(path.join(root,FILE))) return {state:read(root), resumed:true};
  const state = {schemaVersion:1, project:{id:id('project'),name:name || path.basename(root),root,repository,createdAt:now()}, settings:{engine:'mock',evidence:'local',autoSave:true,requestTimeoutMs:8000},
    models:[],targets:[],identities:[],findings:[],checks:[],runs:[],monitors:[],events:[],activeModel:null,activeTarget:null,integrations:{},auth:null,demo:null};
  save(root,state);
  const ignore = path.join(root,'.gitignore');
  const previous = fs.existsSync(ignore) ? fs.readFileSync(ignore,'utf8') : '';
  const rules = ['.bypass/state.json','.bypass/.lock/','.bypass/runs/','.bypass/drafts/','.bypass/discovery/','.bypass/demo-state.json','.bypass/worker.json','.bypass/*.log'];
  const missing = rules.filter(r=>!previous.split('\n').includes(r));
  if (missing.length) fs.appendFileSync(ignore, `${previous.endsWith('\n') || !previous ? '' : '\n'}\n# Bypass local evidence and runtime state\n${missing.join('\n')}\n`);
  if (!fs.existsSync(path.join(root,'.bypassignore'))) fs.writeFileSync(path.join(root,'.bypassignore'), '.env\n.env.*\n*.pem\n*.key\nnode_modules/\n.git/\n.bypass/\n');
  return {state,resumed:false};
}
export function event(state, kind, message, data = {}) {
  const item = {id:id('event'),at:now(),kind,message,...data}; state.events.push(item); state.events = state.events.slice(-200); return item;
}
export function writeEvidence(root, run) { atomic(path.join(root,'.bypass/runs',`${run.id}.json`),run); }
