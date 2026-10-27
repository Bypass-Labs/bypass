import fs from 'node:fs';
import path from 'node:path';
import { execFile, need, hash, Fault } from './util.mjs';

export async function connectRepository(location, destination, {signal}={}) {
  if (/^(https:\/\/|ssh:\/\/|git@)/.test(location ?? '')) {
    if (location.startsWith('https://')) { const u=new URL(location); need(!u.username&&!u.password, 'Use your Git credential helper; do not put credentials in a repository URL.'); }
    need(destination, '--dir is required when cloning a repository.');
    const dir=path.resolve(destination);
    need(!fs.existsSync(dir) || (fs.statSync(dir).isDirectory() && fs.readdirSync(dir).length===0), `Clone destination must be a new or empty folder: ${dir}`);
    const r=await execFile('git',['-c','core.hooksPath=/dev/null','clone','--no-recurse-submodules','--',location,dir],{timeout:120000,signal,killGroup:true});
    need(r.code===0, 'Git clone failed. Check the URL and your existing Git credentials.',3);
    return {root:dir,repository:await repositoryInfo(dir)};
  }
  const root=path.resolve(location || destination || process.cwd());
  need(fs.existsSync(root)&&fs.statSync(root).isDirectory(),`Repository directory does not exist: ${root}`);
  return {root,repository:await repositoryInfo(root)};
}
export async function repositoryInfo(root) {
  const result=await execFile('git',['-C',root,'rev-parse','--show-toplevel']);
  if(result.code!==0) return {kind:'directory',path:root,branch:null,commit:null,remote:null};
  const outputs=await Promise.all([['symbolic-ref','--short','-q','HEAD'],['rev-parse','HEAD'],['remote','get-url','origin']].map(args=>execFile('git',['-C',root,...args])));
  let remote=outputs[2].code===0 ? outputs[2].stdout : null;
  if(remote?.startsWith('https://')) { try { const u=new URL(remote);u.username='';u.password='';u.search='';remote=u.toString(); } catch { remote=null; } }
  return {kind:'git',path:root,gitRoot:result.stdout,branch:outputs[0].code===0?outputs[0].stdout:null,commit:outputs[1].code===0?outputs[1].stdout:null,remote};
}
const sourcePattern=/\.(?:[cm]?[jt]sx?|py|go|rb|rs|java|php)$/;
function ignored(file,patterns) {
  const pieces=file.split('/');
  if(file.startsWith('tests/security/bypass/')||/^(?:check_[a-z0-9_-]+\.test|bypass-regression-runtime)\.mjs$/.test(pieces.at(-1)))return true;
  if(pieces.some(p=>['.git','.bypass','node_modules','.next','dist','build','coverage','.venv'].includes(p)))return true;
  if(pieces.some(p=>/^\.env(?:\.|$)/.test(p)||/\.(?:pem|key|p12)$/.test(p)))return true;
  return patterns.some(p=>p.endsWith('/') ? file.includes(p) : p.includes('*') ? new RegExp('(^|/)'+p.split('*').map(s=>s.replace(/[.*+?^${}()|[\]\\]/g,'\\$&')).join('.*')+'$').test(file) : pieces.includes(p)||file===p);
}
export async function inventory(root, base) {
  const patterns=fs.existsSync(path.join(root,'.bypassignore'))?fs.readFileSync(path.join(root,'.bypassignore'),'utf8').split('\n').filter(x=>x&&!x.startsWith('#')):[];
  let files=[];
  const git=await execFile('git',['-C',root,'ls-files','-z','--cached','--others','--exclude-standard']);
  if(git.code===0) files=git.stdout.split('\0').filter(Boolean);
  else {
    const walk=(dir,depth=0)=>{ if(depth>12||files.length>2000)return; for(const entry of fs.readdirSync(dir,{withFileTypes:true})) {const full=path.join(dir,entry.name), rel=path.relative(root,full).split(path.sep).join('/');if(ignored(rel,patterns)||entry.isSymbolicLink())continue;if(entry.isDirectory())walk(full,depth+1);else files.push(rel);} };
    walk(root);
  }
  let changedFiles=null;
  if(base){need(!base.startsWith('-'),'Invalid base reference.'); const r=await execFile('git',['-C',root,'diff','--name-only','-z',base,'--']);need(r.code===0,`Cannot compare against Git reference '${base}'.`);changedFiles=r.stdout.split('\0').filter(Boolean);}
  files=[...new Set(files)].filter(f=>sourcePattern.test(f)&&!ignored(f,patterns)).sort();
  const truncated=files.length>2000; files=files.slice(0,2000);
  const digests=[], routes=new Set(),routeLocations=[];
  for(const file of files){
    const full=path.join(root,file);if(!fs.existsSync(full)||fs.lstatSync(full).isSymbolicLink()||fs.statSync(full).size>1_000_000)continue;
    if(!fs.realpathSync(full).startsWith(fs.realpathSync(root)+path.sep))continue;
    const source=fs.readFileSync(full,'utf8');digests.push([file,hash(source)]);
    for(const m of source.matchAll(/(?:\.get|\.post|\.put|\.delete|\.patch|url\s*===|pathname\s*===)\s*\(?\s*['"`]([^'"`\s]+)['"`]/g))if(m[1].startsWith('/')){routes.add(m[1]);if(routeLocations.length<1000)routeLocations.push({path:m[1],file,line:source.slice(0,m.index).split('\n').length});}
  }
  return {fingerprint:hash(digests),fileHashes:Object.fromEntries(digests),files:digests.map(([file])=>file),sourceFileCount:digests.length,truncated,routes:[...routes],routeLocations,routeDiscovery:'heuristic inventory; not proof of complete coverage',changedFiles};
}
