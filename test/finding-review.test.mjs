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
      {id:'f-001',kind:'rate-limit-auth-gate',webProof:{mode:'login'},severity:'medium',verdict:'confirmed',
        evidence:['ev-1'],confirmation:['ev-2'],proof:path.join(runDir,'poc','f-001','poc.mjs')},
      {id:'f-002',kind:'model-raw-boundary',title:'Possible command injection',pattern:'/uplink',severity:'unrated',verdict:'confirmed',
        rule:'fresh-positive-marker-controls',
        evidence:['ev-3'],confirmation:['ev-4'],proof:path.join(runDir,'poc','f-002','poc.mjs')},
      {id:'f-003',kind:'model-http-sequence',title:'Changed response on /uplink',pattern:'/uplink',
        severity:'unrated',verdict:'observed',evidence:['ev-5'],confirmation:['ev-6']}
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
      sourceEvidence:{kind:'source',file:'server.ts',line:40}},
    {id:'otp',lastRunId:run.id,title:'OTP verification has no attempt limit',status:'unproven',severity:'high',
      category:'authentication',resourcePath:'/api/auth/verify-2fa',recommendation:'Limit OTP attempts.',
      sourceEvidence:{kind:'source',file:'server.ts',line:55}}
  ];
  const report=findingReview(root,run,findings);
  assert.equal(report.issues.length,4);
  assert.equal(report.coverage.complete,false);
  assert.match(report.presentation,/1 blocked · 2 inconclusive/);
  assert.match(report.presentation,/Full report: \/.*report\.md/);
  assert.ok(report.presentation.indexOf('Full report: ')<report.presentation.indexOf('## 1.'));
  assert.match(report.presentation,/No login throttling[\s\S]*synthetic, nonexistent identity[\s\S]*f-001[\s\S]*bx-example-f-001\.test\.mjs/);
  assert.match(report.presentation,/No login throttling \(real-account or valid-code impact unverified\)/);
  assert.doesNotMatch(report.presentation,/Repeated guessing is possible/);
  assert.match(report.presentation,/Possible command injection[\s\S]*observed response effect; exploitability unverified[\s\S]*Security impact not established by this proof/);
  assert.match(report.presentation,/Response effect on \/uplink \(Possible command injection remains a hypothesis\)/);
  assert.match(report.presentation,/Live effect replay: f-002/);
  assert.match(report.presentation,/Other observed behavior · security impact unverified[\s\S]*f-003 · Changed response on \/uplink/);
  assert.equal(report.summary.otherObservations,1);
  assert.doesNotMatch(report.presentation,/Command execution is possible/);
  assert.match(report.presentation,/Possible SQL injection[\s\S]*Live proof: none/);
  assert.match(report.presentation,/source vulnerability lead; live exploitability unverified/);
  assert.match(report.presentation,/OTP verification has no attempt limit[\s\S]*valid test-account challenge/);
  assert.equal(report.paths.liveReport,path.join(runDir,'report.md'));
  assert.deepEqual(report.nextActions.map(item=>item.id),['inspect','leave']);
  assert.doesNotMatch(report.presentation,/Fix confirmed issues and open a PR/);
  const appOnly=blackboxFindingReview(root,{run:liveRun,reportPath:path.join(runDir,'report.md')});
  assert.equal(appOnly.findings,3);
  assert.equal(appOnly.securityFindings,0);
  assert.equal(appOnly.observedResponseEffects,2);
  assert.equal(appOnly.otherObservations,1);
  assert.match(appOnly.presentation,/observed response effect; exploitability unverified/);
  assert.match(appOnly.presentation,/No visible throttling after synthetic invalid attempts[\s\S]*Severity: unrated/);
  assert.doesNotMatch(appOnly.presentation,/undefined/);
  assert.match(appOnly.presentation,/Response effect on \/uplink \(Possible command injection remains a hypothesis\)/);
  assert.match(appOnly.presentation,/Security impact not established by this proof/);
  assert.match(appOnly.presentation,/Full report: \/.*report\.md/);
  assert.deepEqual(appOnly.nextActions.map(item=>item.id),['inspect','leave']);
});

test('no confirmed security proof offers inspection and leaving findings open, without a fix action',()=>{
  const root=temp(),runDir=path.join(root,'.bypass','runs','bx-empty');
  fs.mkdirSync(runDir,{recursive:true});
  fs.writeFileSync(path.join(runDir,'report.md'),'# Partial coverage\n');
  fs.writeFileSync(path.join(runDir,'report.json'),JSON.stringify({header:{run:'bx-empty'},
    coverage:{complete:false},summary:{blocked:1,inconclusive:2},findings:[]}));
  const review=blackboxFindingReview(root,{run:'bx-empty',reportPath:path.join(runDir,'report.md')});
  assert.deepEqual(review.nextActions.map(item=>item.id),['inspect','leave']);
  assert.doesNotMatch(review.presentation,/Fix confirmed issues/);
});
