import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { temp } from './helpers.mjs';
import { findingReview, blackboxFindingReview } from '../src/review-report.mjs';

test('completed connected review presents all issues and does not promote a response marker into an exploit',()=>{
  const root=temp(),liveRun='bx-example',runDir=path.join(root,'.bypass','runs',liveRun);
  fs.mkdirSync(path.join(runDir,'poc','f-001'),{recursive:true});
  fs.mkdirSync(path.join(runDir,'poc','f-002'),{recursive:true});
  fs.writeFileSync(path.join(runDir,'report.md'),'# Full live evidence\n');
  fs.writeFileSync(path.join(runDir,'report.json'),JSON.stringify({
    summary:{narrative:'2 confirmed behaviors; 1 blocked and 2 inconclusive.',blocked:1,inconclusive:2},
    coverage:{complete:false},limitations:['No identity endpoint proved the accounts.'],
    findings:[
      {id:'f-001',kind:'rate-limit-auth-gate',severity:'medium',verdict:'confirmed',
        evidence:['ev-1'],confirmation:['ev-2'],proof:path.join(runDir,'poc','f-001','poc.mjs')},
      {id:'f-002',kind:'model-raw-boundary',severity:'unrated',verdict:'confirmed',
        evidence:['ev-3'],confirmation:['ev-4'],proof:path.join(runDir,'poc','f-002','poc.mjs')}
    ]}));
  const exported=path.join(root,'tests','security','blackbox',`${liveRun}-f-001.test.mjs`);
  fs.mkdirSync(path.dirname(exported),{recursive:true});fs.writeFileSync(exported,'// saved proof\n');
  const run={id:'run-example',result:{blackbox:{run:liveRun}}};
  const findings=[
    {id:'rate',lastRunId:run.id,title:'No login throttling',status:'confirmed',severity:'medium',
      category:'authentication',resourcePath:'/login',impact:'Repeated guessing is possible.',
      recommendation:'Limit attempts.',sourceEvidence:{kind:'http'},
      verification:{blackboxFindingId:'f-001'}},
    {id:'effect',lastRunId:run.id,title:'Possible command injection',status:'confirmed',severity:'unrated',
      category:'command-injection',resourcePath:'/uplink',impact:'Command execution is possible.',
      recommendation:'Avoid shell interpolation.',sourceEvidence:{kind:'source',file:'server.ts',line:20},
      verification:{blackboxFindingId:'f-002'}},
    {id:'source',lastRunId:run.id,title:'Possible SQL injection',status:'unproven',severity:'high',
      category:'sql-injection',resourcePath:'/search',recommendation:'Use bound parameters.',
      sourceEvidence:{kind:'source',file:'server.ts',line:40}}
  ];
  const report=findingReview(root,run,findings);
  assert.equal(report.issues.length,3);
  assert.equal(report.coverage.complete,false);
  assert.match(report.presentation,/1 blocked · 2 inconclusive/);
  assert.match(report.presentation,/Full report: \/.*report\.md/);
  assert.ok(report.presentation.indexOf('Full report: ')<report.presentation.indexOf('## 1.'));
  assert.match(report.presentation,/No login throttling[\s\S]*Repeated guessing is possible\.[\s\S]*f-001[\s\S]*bx-example-f-001\.test\.mjs/);
  assert.match(report.presentation,/Possible command injection[\s\S]*response effect confirmed; exploit impact unproven[\s\S]*Security impact not established by this proof/);
  assert.doesNotMatch(report.presentation,/Command execution is possible/);
  assert.match(report.presentation,/Possible SQL injection[\s\S]*Live proof: none/);
  assert.equal(report.paths.liveReport,path.join(runDir,'report.md'));
  const appOnly=blackboxFindingReview(root,{run:liveRun,reportPath:path.join(runDir,'report.md')});
  assert.equal(appOnly.findings,2);
  assert.match(appOnly.presentation,/response effect confirmed; exploit impact unproven/);
  assert.match(appOnly.presentation,/Security impact not established by this proof/);
  assert.match(appOnly.presentation,/Full report: \/.*report\.md/);
});
