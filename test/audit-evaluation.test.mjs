import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import {execute} from '../src/service.mjs';
import {change,read} from '../src/store.mjs';
import {evaluateAuditRun} from '../src/audit-evaluation.mjs';
import {temp} from './helpers.mjs';

test('audit evaluator fails missing live evidence and passes a complete reconciled contract',async()=>{
  const root=temp();fs.writeFileSync(path.join(root,'app.mjs'),'export const app=true;\n');
  await execute('init',[root]);
  await execute('target add',['app'],{project:root,url:'http://127.0.0.1:43123',environment:'local'});
  await execute('target verify',['app'],{project:root,method:'local'});
  await execute('target authorize',['app'],{project:root,accept:true,paths:'/',methods:'GET,HEAD,POST',rps:20});
  const runDir=path.join(root,'.bypass/runs/bx-20261103-e1a2b3c4');
  fs.mkdirSync(runDir,{recursive:true});
  const scope={include:['/'],methods:['GET','HEAD','POST']};
  const run={id:'run_contract',kind:'scan',options:{mode:'combined',target:'app'},
    status:'incomplete',createdAt:new Date().toISOString(),finishedAt:new Date().toISOString(),
    steps:[{stage:'white-box',message:'done'},{stage:'blackbox:progress',message:'request'}],
    result:{engine:'combined',source:{engine:'docker-source'},findings:['finding_contract'],
      blackbox:{kind:'blackbox-audit',run:'bx-20261103-e1a2b3c4',runDir,stats:{requests:0}}}};
  await change(root,state=>{state.runs.push(run);state.findings.push({id:'finding_contract',
    status:'confirmed',lastRunId:run.id,verification:{blackboxRun:'bx-20261103-e1a2b3c4',
      blackboxFindingId:'finding-1',proofId:'proof-1'}});});
  let evaluated=evaluateAuditRun(root,run.id);
  assert.equal(evaluated.passed,false);
  assert.deepEqual(evaluated.gates.filter(item=>!item.passed).map(item=>item.id).sort(),
    ['authorized-methods','authorized-paths','live-artifacts','live-requests','scope-snapshot'].sort());
  for(const file of ['report.md','coverage.json','evidence.jsonl'])fs.writeFileSync(path.join(runDir,file),'{}\n');
  fs.writeFileSync(path.join(root,'.bypass/runs',`${run.id}.blackbox.scope.json`),JSON.stringify(scope));
  await change(root,state=>{state.runs.find(item=>item.id===run.id).result.blackbox.stats.requests=12;});
  evaluated=evaluateAuditRun(root,run.id);
  assert.equal(evaluated.passed,true,JSON.stringify(evaluated.gates,null,2));
  assert.equal(evaluated.score,100);
  assert.equal(read(root).runs.filter(item=>item.id===run.id).length,1);
});
