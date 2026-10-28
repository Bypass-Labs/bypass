import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import http from 'node:http';
import { temp } from './helpers.mjs';
import { execute } from '../src/service.mjs';
import { read, change } from '../src/store.mjs';
import { mcpClient } from './mcp-client.mjs';
import { workProgress, routeMatches } from '../src/review-worklist.mjs';
import { findingSummary } from '../src/review-report.mjs';

async function setup(t){
  const root=temp(),hits=[];
  const source="app.get('/api/first/:id', () => getWithoutOwner());\napp.get('/api/second/:id', () => requireOwner());\napp.post('/api/paid', () => sendRealEmails());\napp.delete('/api/items/:id', () => deleteItem());\n";
  fs.writeFileSync(path.join(root,'server.mjs'),source);
  const server=http.createServer((q,r)=>{
    hits.push(q.url);const owner=q.headers.authorization==='Bearer assessment-owner-42',outsider=q.headers.authorization==='Bearer assessment-other-42',signed=owner||outsider;
    const status=!signed?401:q.url==='/api/second/one'&&!owner?403:200;
    r.writeHead(status,{'Content-Type':'application/json'});r.end(JSON.stringify(q.url==='/api/me'?{id:owner?'owner':'outsider'}:{id:'one'}));
  });await new Promise(r=>server.listen(0,'127.0.0.1',r));t.after(()=>server.close());
  await execute('init',[root]);const o={project:root};await execute('target add',['app'],{...o,url:`http://127.0.0.1:${server.address().port}`,environment:'local'});await execute('target verify',['app'],{...o,method:'local'});await execute('target authorize',['app'],{...o,accept:true,methods:'GET,HEAD,POST',paths:'/api'});
  await change(root,s=>{s.targets[0].authorization.maxRequestsPerSecond=10;});
  for(const name of ['owner','outsider'])await execute('identity add',[name],{...o,target:'app',type:'bearer','secret-env':name==='owner'?'BYPASS_ASSESS_OWNER':'BYPASS_ASSESS_OTHER','check-path':'/api/me'});
  const clientOptions={packaged:true,stateDir:temp(),env:{BYPASS_ASSESS_OWNER:'assessment-owner-42',BYPASS_ASSESS_OTHER:'assessment-other-42'}};
  const c=await mcpClient(root,clientOptions);t.after(()=>c.close());
  await c.call('bypass_add_probe',{name:'first',path:'/api/first/one','resource-id':'one',owner:'owner',outsider:'outsider'});
  return {root,c,clientOptions,source,hits};
}

test('one finding is interim: finish defers, fresh MCP resumes, new probes run and blocked jobs stay explicit',async t=>{
  const {root,c,clientOptions,source,hits}=await setup(t),run=await c.call('bypass_scan',{mode:'combined'});
  assert.equal(run.assessmentPolicy.applicationEdits,'not_authorized');assert.equal(run.work.routes.total,4);assert.equal(run.work.outOfScope,1);assert.equal(run.work.eta,null);
  const denied=await c.call('bypass_review_step',{id:run.runId,action:'finish'});assert.equal(denied.finishDeferred,true);assert.equal(denied.status,'awaiting_host');assert.equal(hits.length,0);
  const first=await c.call('bypass_review_step',{id:run.runId,action:'complete',candidates:[{title:'Missing owner control',category:'cross-account-access',file:'server.mjs',line:1,quote:source.split('\n')[0],resourcePath:'/api/first/:id',hypothesis:'The route does not check the resource owner.',recommendation:'Require owner authorization before returning data.'}]},{progressToken:'assessment-first'});
  assert.equal(first.probes[0].status,'failed');assert.equal(first.status,'awaiting_host');assert.equal(first.continueRequired,true);assert.equal(first.finishDeferred,true);assert.equal(read(root).checks.length,1);assert.equal(read(root).findings.length,1,'Route template and concrete HTTP evidence are one finding');
  assert.ok(c.notifications.some(n=>n.params?.message?.includes('continuing assessment')));
  await c.close();const next=await mcpClient(root,clientOptions);t.after(()=>next.close());
  const status=await next.call('bypass_review_step',{id:run.runId,action:'status'});assert.equal(status.work.configuredProbes.executed,1);assert.equal(status.work.routes.pending,2);
  await next.call('bypass_add_probe',{name:'second',path:'/api/second/one','resource-id':'one',owner:'owner',outsider:'outsider'});
  const more=await next.call('bypass_review_step',{id:run.runId,action:'complete'});assert.equal(more.probes.length,2);assert.equal(more.probes[1].status,'passed');assert.equal(more.work.routes.pending,1);assert.ok(more.work.eta);assert.match(more.work.eta.covers,/Configured HTTP probes only/);
  const work=await next.call('bypass_review_step',{id:run.runId,action:'coverage'}),paid=work.worklist.find(r=>r.path==='/api/paid');
  const fake=await next.raw('bypass_review_step',{id:run.runId,action:'coverage',dispositions:[{id:paid.id,reasonCode:'tested',reason:'Pretend this route was tested successfully.'}]});assert.ok(fake.error||fake.result?.isError);
  await next.call('bypass_review_step',{id:run.runId,action:'coverage',dispositions:[{id:paid.id,reasonCode:'external_side_effect',reason:'Source invokes real email delivery. POST method permission does not authorize sending real messages; a sandbox delivery provider is required.'}]});
  const done=await next.call('bypass_review_step',{id:run.runId,action:'finish'});assert.equal(done.status,'incomplete');assert.equal(done.work.pending,0);assert.equal(done.work.blocked,1);assert.equal(done.work.scopeExecuted,false);assert.equal(done.outcomes.confirmed.length,1);
  assert.ok(!hits.includes('/api/paid'));assert.equal(fs.readFileSync(path.join(root,'server.mjs'),'utf8'),source);
});

test('a blocker cannot hide independent executable checks; unread routes cannot be dismissed',async t=>{
  const {root,c}=await setup(t);
  for(let n=0;n<4;n++)fs.writeFileSync(path.join(root,`extra-${n}.mjs`),'export const value = true;');
  const run=await c.call('bypass_scan',{mode:'combined'}),work=await c.call('bypass_review_step',{id:run.runId,action:'coverage'}),paid=work.worklist.find(r=>r.path==='/api/paid');
  const blocked=await c.raw('bypass_review_step',{id:run.runId,action:'coverage',dispositions:[{id:paid.id,reasonCode:'external_side_effect',reason:'This needs an isolated mail sink before exercising it.'}]});assert.equal(blocked.result.isError,true);assert.match(blocked.result.content[0].text,/Read the cited route/);
  await c.call('bypass_review_step',{id:run.runId,action:'read',paths:['server.mjs']});
  await c.call('bypass_review_step',{id:run.runId,action:'coverage',dispositions:[{id:paid.id,reasonCode:'external_side_effect',reason:'Source calls a live mail provider. Needs an isolated mail sink.'}]});
  const early=await c.call('bypass_review_step',{id:run.runId,action:'finish'});assert.equal(early.status,'awaiting_host');assert.equal(early.work.configuredProbes.pending,1);
  const continued=await c.call('bypass_review_step',{id:run.runId,action:'complete',candidates:[]});assert.equal(continued.probes[0].status,'failed');assert.equal(continued.status,'awaiting_host');
});

test('application edits after source submission are detected; review does not silently bless remediation',async t=>{
  const {root,c}=await setup(t),run=await c.call('bypass_scan',{mode:'combined'});
  await c.call('bypass_review_step',{id:run.runId,action:'source',candidates:[]});fs.appendFileSync(path.join(root,'server.mjs'),'// external editor changed this source\n');
  const response=await c.raw('bypass_review_step',{id:run.runId,action:'complete'});assert.equal(response.result.isError,true);assert.match(response.result.content[0].text,/Source changed.*do not authorize remediation/);
  assert.equal(read(root).runs[0].status,'awaiting_host');assert.equal(read(root).runs[0].result.probes.length,0);
});

test('a source-operation limit retains incomplete coverage but drains independent configured HTTP controls',async t=>{
  const {root,c,hits}=await setup(t),run=await c.call('bypass_scan',{mode:'combined'});
  await change(root,s=>{s.runs.find(r=>r.id===run.runId).host.operations=128;});
  const response=await c.call('bypass_review_step',{id:run.runId,action:'complete'});
  assert.equal(response.status,'incomplete');assert.equal(response.work.configuredProbes.pending,0);
  assert.equal(response.probes[0].status,'failed');assert.ok(hits.includes('/api/first/one'));
  assert.equal(response.work.scopeExecuted,false);assert.equal(response.outcomes.notRun.source,true);
  assert.ok(response.work.blockers.some(b=>b.kind==='runtime_limit'&&/128 operations/.test(b.reason)));
});

test('progress counts and ETA are evidence-derived; parameter matching is segment bounded',()=>{
  assert.equal(routeMatches('/api/job/:id','/api/job/one'),true);assert.equal(routeMatches('/api/job/:id','/api/job/one/other'),false);assert.equal(routeMatches(null,'/api/job/one'),false);
  const run={host:{mode:'live',bindings:[{name:'a'},{name:'b'},{name:'c'}],visited:[0,1],worklist:[]},result:{probes:[{elapsedMs:2000,status:'passed'},{elapsedMs:4000,status:'failed'}]}};
  const p=workProgress(run,{checks:[]});assert.equal(p.configuredProbes.pending,1);assert.deepEqual([p.eta.minSeconds,p.eta.maxSeconds],[3,6]);assert.equal(p.canFinish,false);
});

test('missing resource is preparation: create a synthetic record, bind a later probe, continue and expose real coverage',async t=>{
  const {root,c,source,hits}=await setup(t);
  fs.appendFileSync(path.join(root,'server.mjs'),"app.post('/api/second', () => createOwnedRecord());\n");
  const run=await c.call('bypass_scan',{mode:'combined'});
  const candidate={title:'Second access hypothesis',category:'cross-account-access',file:'server.mjs',line:2,quote:source.split('\n')[1],resourcePath:'/api/second/:id',hypothesis:'Investigate owner enforcement on this route.',recommendation:'Keep the owner check.'};
  const first=await c.call('bypass_review_step',{id:run.runId,action:'complete',candidates:[candidate]});
  assert.equal(first.probes[0].status,'failed');assert.equal(first.status,'awaiting_host');
  const coverage=await c.call('bypass_coverage',{run:run.runId,target:'app'}),row=coverage.assessment.worklist.find(r=>r.path==='/api/second/:id');
  assert.equal(coverage.assessment.needsContinuation,true);assert.equal(coverage.assessment.work.source.remainingFiles,0);
  assert.equal(row.setupCandidates[0].method,'POST');assert.equal(row.setupCandidates[0].path,'/api/second');
  const disposition={id:row.id,reasonCode:'missing_resource',reason:'No owner resource ID is available for this path yet.'};
  const skipped=await c.raw('bypass_review_step',{id:run.runId,action:'coverage',dispositions:[disposition]});assert.match(skipped.result.content[0].text,/preparation work/);
  const created=await c.call('bypass_request',{target:'app',method:'POST',path:'/api/second',identity:'owner',body:{title:'Bypass synthetic record'},'id-field':'id'});
  assert.equal(created.resourceId,'one');assert.equal(created.securityConclusion,false);assert.equal(created.automaticReplay,false);
  const stillMissing=await c.raw('bypass_review_step',{id:run.runId,action:'coverage',dispositions:[{...disposition,evidenceRunIds:[created.runId]}]});assert.match(stillMissing.result.content[0].text,/returned a resource ID/);
  await c.call('bypass_add_probe',{name:'second',path:`/api/second/${created.resourceId}`,'resource-id':created.resourceId,owner:'owner',outsider:'outsider'});
  const more=await c.call('bypass_review_step',{id:run.runId,action:'complete'});assert.equal(more.probes[1].status,'passed');assert.equal(more.status,'awaiting_host');
  assert.equal(read(root).findings.find(f=>f.resourcePath==='/api/second/:id').status,'not_reproduced');
  assert.ok(hits.includes('/api/second'));assert.ok(hits.includes('/api/second/one'));assert.ok(!hits.includes('/api/paid'));
});

test('a source hypothesis created before its probe becomes the single confirmed finding',async t=>{
  const {root,c,source}=await setup(t);await change(root,s=>{s.targets[0].probes=[];});
  const run=await c.call('bypass_scan',{mode:'combined'});
  await c.call('bypass_review_step',{id:run.runId,action:'source',candidates:[{title:'First access hypothesis',category:'cross-account-access',file:'server.mjs',line:1,quote:source.split('\n')[0],resourcePath:'/api/first/:id',hypothesis:'Any signed-in user can access this resource.',recommendation:'Check resource ownership.'}]});
  const sourceId=read(root).findings[0].id;assert.equal(read(root).findings[0].binding,null);
  await c.call('bypass_add_probe',{name:'first',path:'/api/first/one','resource-id':'one',owner:'owner',outsider:'outsider'});
  await c.call('bypass_review_step',{id:run.runId,action:'complete'});
  const findings=await c.call('bypass_findings',{run:run.runId});assert.equal(findings.findings.length,1);assert.equal(findings.findings[0].id,sourceId);assert.equal(findings.summary.confirmed,1);assert.equal(findings.summary.distinctIssues,1);
  assert.equal(read(root).checks[0].findingId,sourceId);
});

test('source completion requires unread files and ranges, not just one source submission',async t=>{
  const root=temp();fs.writeFileSync(path.join(root,'large.mjs'),Array.from({length:500},(_,i)=>`export const value${i} = ${i};`).join('\n'));
  for(let i=0;i<4;i++)fs.writeFileSync(path.join(root,`extra${i}.mjs`),'export const extra = true;');
  await execute('init',[root]);const c=await mcpClient(root,{packaged:true,stateDir:temp()});t.after(()=>c.close());
  const run=await c.call('bypass_scan',{mode:'code'});
  await c.call('bypass_review_step',{id:run.runId,action:'read',paths:[{path:'large.mjs',startLine:1,endLine:200}]});
  const partial=await c.call('bypass_review_step',{id:run.runId,action:'complete',candidates:[]});assert.equal(partial.status,'awaiting_host');assert.equal(partial.work.source.remainingFiles,5);assert.equal(partial.work.source.filesRead,1);assert.equal(partial.work.source.completeFiles,0);
  assert.equal(partial.nextAction.arguments.action,'read');assert.equal(partial.nextAction.arguments.paths.find(p=>p.path==='large.mjs').startLine,201);
  await c.call(partial.nextAction.tool,partial.nextAction.arguments);
  const done=await c.call('bypass_review_step',{id:run.runId,action:'finish'});assert.equal(done.status,'completed');assert.equal(done.work.source.completeFiles,5);assert.equal(done.work.source.remainingFiles,0);assert.equal(done.coverageComplete,false);
});

test('legacy completed runs expose unfinished work without changing historical state',async t=>{
  const {root,c}=await setup(t),run=await c.call('bypass_scan',{mode:'combined'});
  await c.call('bypass_review_step',{id:run.runId,action:'complete',candidates:[]});
  await change(root,s=>{const r=s.runs.find(r=>r.id===run.runId);delete r.host.worklist;delete r.host.sourceCoverage;delete r.host.scope;r.status='completed';});
  const before=fs.readFileSync(path.join(root,'.bypass/state.json'),'utf8');
  const result=await c.call('bypass_coverage',{run:run.runId,target:'app'});
  assert.equal(result.assessment.legacyWorklist,true);assert.equal(result.assessment.completionClaimSupported,false);assert.equal(result.assessment.needsContinuation,true);assert.ok(result.assessment.work.routes.pending>0);assert.equal(result.assessment.nextAction.tool,'bypass_scan');
  assert.equal(fs.readFileSync(path.join(root,'.bypass/state.json'),'utf8'),before);
});

test('legacy source and HTTP records count as one issue without deleting records',()=>{
  const records=[{id:'source',target:'app',category:'cross-account-access',resourcePath:'/api/jobs/:id',sourceEvidence:{kind:'source'},status:'unproven'},{id:'proof',target:'app',category:'cross-account-access',binding:{resourcePath:'/api/jobs/one'},sourceEvidence:{kind:'http'},status:'confirmed'}];
  const summary=findingSummary(records);assert.equal(summary.records,2);assert.equal(summary.distinctIssues,1);assert.equal(summary.confirmed,1);assert.equal(summary.duplicateRecords,1);assert.equal(records.length,2);
});

test('host source review can finish an application file beyond the old 192 KB cap',async t=>{
  const root=temp();fs.writeFileSync(path.join(root,'large.mjs'),Array.from({length:1800},(_,i)=>`// ${i} ${'source context '.repeat(10)}`).join('\n'));
  await execute('init',[root]);const c=await mcpClient(root,{packaged:true,stateDir:temp()});t.after(()=>c.close());
  const run=await c.call('bypass_scan',{mode:'code'});assert.equal(run.plan.limits.sourceBytes,2000000);
  let progress=await c.call('bypass_review_step',{id:run.runId,action:'status'}),batches=0;
  while(progress.work.source.remainingFiles&&batches++<10){progress=await c.call('bypass_review_step',{id:run.runId,action:'read',paths:progress.work.source.remaining});}
  assert.equal(progress.work.source.remainingFiles,0);assert.equal(progress.work.source.linesRead,1800);
  const done=await c.call('bypass_review_step',{id:run.runId,action:'complete',candidates:[]});assert.equal(done.status,'completed');
});
