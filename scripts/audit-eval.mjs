#!/usr/bin/env node
import path from 'node:path';
import {rootFrom,read} from '../src/store.mjs';
import {evaluateAuditRun} from '../src/audit-evaluation.mjs';

const args=process.argv.slice(2),option=name=>{
  const index=args.indexOf(name);return index>=0?args[index+1]:null;
};
const project=rootFrom(path.resolve(option('--project')??process.cwd()));
const state=read(project);
const selected=option('--run')??[...state.runs].reverse().find(run=>run.kind==='scan')?.id;
if(!selected)throw Error('No saved security audit found. Supply --run <run-id>.');
const evaluation=evaluateAuditRun(project,selected);
if(args.includes('--json'))console.log(JSON.stringify(evaluation,null,2));
else{
  console.log(`Audit contract · ${evaluation.runId} · ${evaluation.score}/100 · ${evaluation.passed?'PASS':'FAIL'}`);
  for(const item of evaluation.gates)console.log(`${item.passed?'PASS':'FAIL'}  ${item.id} · expected ${JSON.stringify(item.expected)} · actual ${JSON.stringify(item.actual)}`);
}
process.exitCode=evaluation.passed?0:1;
