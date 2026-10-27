import { memorySummary } from './project-memory.mjs';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { atomic, read } from './store.mjs';
import { hash, now, VERSION } from './util.mjs';

// Only remember a repository after an explicit connect operation. No permissions or
// credentials are copied. Project identity prevents silently selecting a replaced folder.
const selectionFile=cwd=>path.join(process.env.BYPASS_PLUGIN_STATE_DIR||path.join(os.homedir(),'.local/state/bypass'),'workspaces',hash(path.resolve(cwd))+'.json');
export function rememberSelection(cwd,root){
  const state=read(root);
  if(state.demo||state.poc)return {remembered:false,reason:'Example projects stay within the current session.'};
  atomic(selectionFile(cwd),{schemaVersion:1,hostWorkspace:path.resolve(cwd),repository:path.resolve(root),projectId:state.project.id,selectedAt:now()});
  return {remembered:true};
}
export function savedSelection(cwd){
  try{
    const selection=JSON.parse(fs.readFileSync(selectionFile(cwd),'utf8'));
    if(selection.schemaVersion!==1||selection.hostWorkspace!==path.resolve(cwd)||!path.isAbsolute(selection.repository))return null;
    const state=read(selection.repository);
    if(state.project.id!==selection.projectId||state.demo||state.poc)return null;
    return selection.repository;
  }catch{return null;}
}
export function monitorSummary(state){
  const run=state.runs.findLast(r=>r.kind==='monitor');
  if(!run)return null;
  const results=run.result?.results||[];
  const historicalFailures=results.filter(r=>['failed','blocked','stale'].includes(r.status));
  const superseded=historicalFailures.length>0&&historicalFailures.every(result=>{
    const check=state.checks.find(c=>c.id===result.id),latest=check?.lastResult;
    return latest?.status==='passed'&&latest.target===(result.target||check.target)&&Date.parse(latest.checkedAt)>Date.parse(run.finishedAt);
  });
  return {id:run.id,finishedAt:run.finishedAt,exitCode:run.exitCode,scope:state.demo||state.poc?'example application':'selected application',
    status:superseded?'superseded_by_passing_retest':run.exitCode===0?'passed':run.exitCode===1?'failed':'incomplete',
    historical:true,superseded,activeSchedules:state.monitors.filter(m=>m.enabled).length,
    message:superseded?'Historical failure was superseded by a later passing retest. Do not present it as a current incident.':'Recorded monitor outcome; compare current saved checks before recommending action.'};
}
export function sessionHint(cwd){
  const selected=savedSelection(cwd);
  if(!selected)return {version:VERSION,hostWorkspace:cwd,selectedRepository:null,selectionRequired:true,
    instruction:'Bypass is available. On a Bypass request, call bypass_onboarding. No application is selected. Do not search .demo folders or summarize example monitor history. Ask one plain-language repository question; never ask the user to type MCP calls.'};
  const state=read(selected);
  return {version:VERSION,hostWorkspace:cwd,selectedRepository:selected,selectionRequired:false,
    memory:memorySummary(state),engine:state.settings.analysisEngine==='docker'?'docker':'mock',app:state.targets.find(t=>t.name===state.activeTarget)?.url||null,
    instruction:'An application explicitly selected earlier is available. Before implementing features or refactors in this selected application, call bypass_feature_context with the task and likely files. Re-read cited source, preserve saved account boundaries and replay authorized checks. No full review onboarding is needed to read memory. For security reviews, call bypass_onboarding to show setup and next action. Do not scan automatically or summarize unrelated example projects.'};
}
