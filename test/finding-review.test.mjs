import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { temp } from './helpers.mjs';
import { findingReview, blackboxFindingReview } from '../src/review-report.mjs';
import { execute } from '../src/service.mjs';
import { change } from '../src/store.mjs';
import { mcpClient } from './mcp-client.mjs';

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
  assert.equal(report.summary.issues.find(item=>item.id==='rate')?.status,
    'observed response effect; exploitability unverified');
  assert.match(report.issues.find(item=>item.id==='rate')?.severityBasis??'',
    /Synthetic invalid attempts showed no visible throttling/);
  assert.doesNotMatch(report.issues.find(item=>item.id==='rate')?.severityBasis??'',
    /response marker/);
  assert.doesNotMatch(report.presentation,/Command execution is possible/);
  assert.match(report.presentation,/Possible SQL injection[\s\S]*Live proof: none/);
  assert.match(report.presentation,/source weakness; exploitability unverified/);
  assert.match(report.presentation,/Exploitability: 0 exploitable · 0 not exploitable via tested path · 2 source weaknesses with exploitability unverified · 2 observed response effects/);
  assert.match(report.presentation,/OTP verification has no attempt limit[\s\S]*valid test-account challenge/);
  assert.equal(report.paths.liveReport,path.join(runDir,'report.md'));
  assert.deepEqual(report.nextActions.map(item=>item.id),['inspect','leave']);
  assert.deepEqual(report.inspectable.map(item=>item.id),
    ['rate','effect','source','otp','f-003']);
  assert.deepEqual(report.nextActions[0].picker.choices.map(item=>item.id),
    ['source','other']);
  assert.deepEqual(report.nextActions[0].picker.groups.flatMap(group=>
    group.pages.flatMap(page=>page.choices.filter(item=>!['more','back'].includes(item.id)).map(item=>item.id))).sort(),
    report.inspectable.map(item=>item.id).sort());
  assert.equal(report.inspectable.find(item=>item.id==='source').detailTool,'bypass_finding');
  assert.equal(report.inspectable.find(item=>item.id==='f-003').kind,'observation');
  assert.doesNotMatch(report.presentation,/Fix confirmed issues and open a PR/);
  const appOnly=blackboxFindingReview(root,{run:liveRun,reportPath:path.join(runDir,'report.md')});
  assert.equal(appOnly.findings,3);
  assert.equal(appOnly.securityFindings,0);
  assert.equal(appOnly.unverifiedFindings,0);
  assert.equal(appOnly.observedResponseEffects,2);
  assert.equal(appOnly.otherObservations,1);
  assert.deepEqual(appOnly.inspectable.map(item=>item.id),['f-001','f-002','f-003']);
  assert.deepEqual(appOnly.nextActions[0].picker.groups.flatMap(group=>
    group.pages.flatMap(page=>page.choices.filter(item=>!['more','back'].includes(item.id)).map(item=>item.id))).sort(),
    appOnly.inspectable.map(item=>item.id).sort());
  assert.match(appOnly.presentation,/observed response effect; exploitability unverified/);
  assert.match(appOnly.presentation,/No visible throttling after synthetic invalid attempts[\s\S]*Severity: unrated/);
  assert.doesNotMatch(appOnly.presentation,/undefined/);
  assert.match(appOnly.presentation,/Response effect on \/uplink \(Possible command injection remains a hypothesis\)/);
  assert.match(appOnly.presentation,/Security impact not established by this proof/);
  assert.match(appOnly.presentation,/Full report: \/.*report\.md/);
  assert.deepEqual(appOnly.nextActions.map(item=>item.id),['inspect','leave']);
});

test('a cookie source lead does not receive OTP throttling guidance',()=>{
  const root=temp(),run={id:'run-cookie',result:{findings:['cookie','otp']}};
  const findings=[
    {id:'cookie',title:'Session cookie lacks Secure attribute',status:'unproven',
      category:'authentication',resourcePath:'/api/auth/verify-2fa',severity:'high',
      sourceEvidence:{kind:'source',file:'server.ts',line:20}},
    {id:'otp',title:'Second-factor challenge allows unlimited guessing',status:'unproven',
      category:'authentication',resourcePath:'/api/auth/verify-2fa',severity:'high',
      sourceEvidence:{kind:'source',file:'server.ts',line:21}}
  ];
  const review=findingReview(root,run,findings);
  assert.match(review.issues.find(item=>item.id==='cookie').unprovenReason,/No completed live proof/);
  assert.doesNotMatch(review.issues.find(item=>item.id==='cookie').unprovenReason,/Throttling/);
  assert.match(review.issues.find(item=>item.id==='otp').unprovenReason,/Throttling/);
});

test('empty audit offers coverage inspection with a valid native question',()=>{
  const root=temp();
  const review=findingReview(root,{id:'run-empty',result:{}},[]);
  assert.deepEqual(review.nextActions[0].picker.choices.map(item=>item.id),
    ['coverage','back']);
  assert.equal(review.nextActions[0].picker.groups.length,0);
});

test('packaged Muse findings tool retains every inspect choice after a repeated read',async t=>{
  const root=temp(),liveRun='bx-picker',runId='run-picker';
  fs.writeFileSync(path.join(root,'server.mjs'),'export const app = true;\n');
  await execute('init',[root]);
  const runDir=path.join(root,'.bypass','runs',liveRun);
  fs.mkdirSync(runDir,{recursive:true});
  fs.writeFileSync(path.join(runDir,'report.md'),'# Saved live report\n');
  fs.writeFileSync(path.join(runDir,'report.json'),JSON.stringify({findings:[
    {id:'f-001',title:'Confirmed access issue',verdict:'confirmed',
      proof:path.join(runDir,'poc','f-001','poc.mjs'),confirmation:['ev-fresh']},
    {id:'f-002',title:'Observed response change',verdict:'observed',
      proof:path.join(runDir,'poc','f-002','poc.mjs')}
  ]}));
  await change(root,state=>{
    state.runs.push({id:runId,status:'completed',result:{blackbox:{run:liveRun}}});
    state.findings.push(...[1,2,3,4].map(index=>({id:`finding-${index}`,lastRunId:runId,
      title:`Issue ${index}`,status:index===4?'confirmed':'unproven',
      category:'authorization',resourcePath:`/api/route-${index}`,severity:'high',
      sourceEvidence:{kind:'source',file:'server.mjs',line:1},
      ...(index===4?{verification:{blackboxFindingId:'f-001'}}:{})})));
  });
  const client=await mcpClient(root,{packaged:true,stateDir:temp()});
  t.after(()=>client.child.kill());
  const first=await client.call('bypass_findings',{run:runId});
  const second=await client.call('bypass_findings',{run:runId});
  for(const result of [first,second]){
    const picker=result.review.nextActions[0].picker;
    assert.deepEqual(picker.choices.map(item=>item.id),['exploitable','source','other']);
    assert.deepEqual(picker.groups.flatMap(group=>group.pages.flatMap(page=>
      page.choices.filter(item=>!['more','back'].includes(item.id)).map(item=>item.id))),
    ['finding-4','finding-1','finding-2','finding-3','f-002']);
    assert.ok(picker.choices.length<=3);
    assert.ok(picker.groups.every(group=>group.pages.every(page=>
      page.choices.length>=2&&page.choices.length<=3)));
  }
  assert.equal(await client.close(),0);
});

test('a source weakness blocked by an executed live check is separated from an untested source lead',()=>{
  const root=temp(),liveRun='bx-denied',runDir=path.join(root,'.bypass','runs',liveRun);
  fs.mkdirSync(runDir,{recursive:true});
  fs.writeFileSync(path.join(runDir,'report.md'),'# Live report\n');
  fs.writeFileSync(path.join(runDir,'report.json'),JSON.stringify({findings:[],
    surface:{application:{sourceFindings:[{id:'denied',status:'not exploitable via tested path',
      liveReason:'The request was denied with HTTP 403.'}]}},
    summary:{blocked:1,inconclusive:0},coverage:{complete:false}}));
  const run={id:'run-denied',result:{blackbox:{run:liveRun}}};
  const source=(id,title)=>({id,title,status:'unproven',severity:'high',
    category:'authorization',resourcePath:`/api/${id}`,sourceEvidence:{kind:'source',file:'server.ts',line:10}});
  const review=findingReview(root,run,[source('denied','Private route missing guard'),
    source('untested','Other route missing guard')]);
  assert.equal(review.issues.find(item=>item.id==='denied').status,'not exploitable via tested path');
  assert.equal(review.issues.find(item=>item.id==='untested').status,'source weakness; exploitability unverified');
  assert.equal(review.summary.confirmed,0);
  assert.match(review.presentation,/Exploitability: 0 exploitable · 1 not exploitable via tested path · 1 source weakness with exploitability unverified/);
  assert.match(review.presentation,/The request was denied with HTTP 403/);
});

test('a stale proof reference cannot turn a saved finding into an exploitable report entry',()=>{
  const root=temp(),liveRun='bx-missing-proof',runDir=path.join(root,'.bypass','runs',liveRun);
  fs.mkdirSync(runDir,{recursive:true});
  fs.writeFileSync(path.join(runDir,'report.md'),'# Incomplete live report\n');
  fs.writeFileSync(path.join(runDir,'report.json'),JSON.stringify({findings:[],
    summary:{blocked:0,inconclusive:1},coverage:{complete:false}}));
  const run={id:'run-missing',result:{blackbox:{run:liveRun}}};
  const saved=[{id:'stale',title:'Saved access concern',status:'confirmed',severity:'high',
    category:'authorization',resourcePath:'/api/private',sourceEvidence:{kind:'http'},
    verification:{blackboxFindingId:'f-gone',blackboxRun:liveRun}}];
  const review=findingReview(root,run,saved);
  assert.equal(review.issues[0].status,'live exploitability unverified');
  assert.equal(review.issues[0].liveProof,null);
  assert.equal(review.summary.confirmed,0);
  assert.equal(review.summary.issues[0].status,'live exploitability unverified');
  assert.match(review.issues[0].severityBasis,/severity remains provisional/);
  assert.match(review.presentation,/Linked proof f-gone is missing/);
  assert.deepEqual(review.nextActions.map(item=>item.id),['inspect','leave']);
});

test('a report placeholder for an ungenerated proof cannot certify exploitability',()=>{
  const root=temp(),liveRun='bx-unsealed',runDir=path.join(root,'.bypass','runs',liveRun);
  fs.mkdirSync(runDir,{recursive:true});
  const reportPath=path.join(runDir,'report.md');
  fs.writeFileSync(reportPath,'# Live report\n');
  fs.writeFileSync(path.join(runDir,'report.json'),JSON.stringify({header:{run:liveRun},
    findings:[{id:'f-001',title:'Access warning',verdict:'confirmed',severity:'high',
      proof:'not generated',confirmation:['ev-1']}],
    summary:{blocked:0,inconclusive:1},coverage:{complete:false}}));
  const review=blackboxFindingReview(root,{run:liveRun,reportPath});
  assert.equal(review.securityFindings,0);
  assert.equal(review.unverifiedFindings,1);
  assert.match(review.presentation,/Status: live exploitability unverified/);
  assert.deepEqual(review.nextActions.map(item=>item.id),['inspect','leave']);
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
