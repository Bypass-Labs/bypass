import fs from 'node:fs';
import path from 'node:path';
import {read} from './store.mjs';

const gate=(id,passed,expected,actual,required=true)=>({id,passed:Boolean(passed),required,
  expected,actual});

/**
 * Evaluate a saved standalone audit against the user-facing audit contract.
 * This reads only durable state and evidence; it never contacts the app or model.
 */
export function evaluateAuditRun(root,runId){
  const state=read(root);
  const run=state.runs.find(item=>item.id===runId);
  if(!run)return {runId,passed:false,score:0,gates:[gate('parent-run',false,
    'a saved parent run',null)]};
  const result=run.result??{},mode=run.options?.mode??result.plan?.mode;
  const live=mode==='live'||mode==='combined',source=mode==='code'||mode==='combined';
  const target=state.targets.find(item=>item.name===(run.options?.target??result.plan?.target));
  const blackbox=result.blackbox;
  const runDir=blackbox?.runDir?(path.isAbsolute(blackbox.runDir)?blackbox.runDir:
    path.resolve(root,blackbox.runDir)):null;
  const scopeFile=path.join(root,'.bypass','runs',`${run.id}.blackbox.scope.json`);
  let scope=null;
  if(fs.existsSync(scopeFile))try{scope=JSON.parse(fs.readFileSync(scopeFile,'utf8'));}catch{}
  const stateFindings=(result.findings??[]).map(id=>state.findings.find(item=>item.id===id));
  const confirmed=stateFindings.filter(item=>item?.status==='confirmed');
  const gates=[
    gate('parent-run',run.kind==='scan','one scan parent run',run.kind),
    gate('canonical-mode',['code','live','combined'].includes(mode),'code, live, or combined',mode),
    gate('durable-result',run.status!=='failed'&&Boolean(run.finishedAt),'a finished or explicitly incomplete durable result',run.status),
    gate('source-engine',!source||Boolean(result.source)||result.engine==='docker-source',
      source?'a formal cited source result':'not selected',result.source?.engine??result.engine),
    gate('live-engine',!live||blackbox?.kind==='blackbox-audit',
      live?'a linked broad black-box run':'not selected',blackbox?.kind??null),
    gate('live-artifacts',!live||Boolean(runDir&&['report.md','coverage.json','evidence.jsonl']
      .every(file=>fs.existsSync(path.join(runDir,file)))),
      live?'report.md, coverage.json, and evidence.jsonl':'not selected',runDir),
    gate('scope-snapshot',!live||Boolean(scope),'an immutable per-run scope snapshot',
      fs.existsSync(scopeFile)?scopeFile:null),
    gate('authorized-paths',!live||Boolean(scope&&target?.authorization&&
      JSON.stringify(scope.include)===JSON.stringify(target.authorization.paths)),
      target?.authorization?.paths??'saved target authorization',scope?.include??null),
    gate('authorized-methods',!live||Boolean(scope&&target?.authorization&&
      JSON.stringify(scope.methods)===JSON.stringify(target.authorization.methods)),
      target?.authorization?.methods??'saved target authorization',scope?.methods??null),
    gate('live-requests',!live||(blackbox?.stats?.requests??0)>0,
      live?'at least one scoped HTTP request':'not selected',blackbox?.stats?.requests??0),
    gate('finding-reconciliation',stateFindings.every(Boolean)&&new Set(result.findings??[]).size===(result.findings??[]).length,
      'unique parent finding IDs present in project state',result.findings??[]),
    gate('confirmed-proof-links',confirmed.every(item=>item.verification?.blackboxRun&&
      item.verification?.blackboxFindingId&&item.verification?.proofId),
      'every confirmed live finding linked to its sealed run, finding, and proof',
      confirmed.map(item=>({id:item.id,run:item.verification?.blackboxRun,
        finding:item.verification?.blackboxFindingId,proof:item.verification?.proofId}))),
    gate('progress-evidence',!live||(run.steps??[]).some(step=>step.stage?.startsWith('blackbox:')),
      live?'durable structured live progress':'not selected',(run.steps??[]).map(step=>step.stage)),
  ];
  const required=gates.filter(item=>item.required),passed=required.every(item=>item.passed);
  return {runId:run.id,mode,status:run.status,passed,
    score:Math.round(100*required.filter(item=>item.passed).length/required.length),gates};
}
