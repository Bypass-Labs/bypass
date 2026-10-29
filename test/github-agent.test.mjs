import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { createHash } from 'node:crypto';
import { GitHubAPI, artifactState, restoreGitHubState } from '../src/github-api.mjs';
import { githubPolicy, assessmentConclusion, sourcePath } from '../src/github-policy.mjs';
import { reviewSource } from '../src/github-review.mjs';
import { runGitHubAgent, githubSummary } from '../src/github-agent.mjs';
import { generateGitHubAgent } from '../src/github-setup.mjs';
import { temp, cli } from './helpers.mjs';
import { initStore } from '../src/store.mjs';
import { execFile } from '../src/util.mjs';
import { toolDefinitions } from '../src/mcp.mjs';

const SHA='a'.repeat(40),HEAD='b'.repeat(40),repo={id:7,default_branch:'main',private:true};
const context={repository:'owner/app',repositoryId:7,sha:HEAD,policySha:SHA,kind:'review',pr:2,defaultBranch:'main'};
const prior={version:1,repositoryId:7,findings:[],targets:{}};
function sourceAPI(files){return {tree:async()=>Object.keys(files).map(path=>({path})),pages:async()=>Object.keys(files).map(filename=>({filename,status:'modified'})),file:async file=>files[file],currentPR:async()=>({head:{sha:HEAD}})};}
function candidate(file='auth.js',line=1,quote='return user;'){return {title:'Missing ownership check',category:'cross-account-access',severity:'high',file,line,quote,resourcePath:'/api/jobs/1',hypothesis:'The resource is returned for any authenticated account; confirm the caller enforces ownership.',recommendation:'Enforce resource ownership before returning it.'};}
const json=value=>new Response(JSON.stringify(value),{status:200});

test('PR source runs through all batches, cites exact source, uses only Meta API profile and labels history',async()=>{
  const files=Object.fromEntries(Array.from({length:9},(_,i)=>[`file${i}.js`,'return user;']));let calls=0;
  const model=async(profile,messages)=>{calls++;assert.equal(profile.provider,'meta');assert.equal(profile.secretEnv,'MODEL_API_KEY');assert.equal(profile.executionMode,'standalone-api');const data=JSON.parse(messages[1].content);return {candidates:[candidate(data.source[0].file)]};};
  const result=await reviewSource(sourceAPI(files),context,githubPolicy(),prior,{model});
  assert.equal(calls,3);assert.equal(result.findings.length,3);assert.equal(result.completedFiles.length,9);assert.deepEqual(result.blockers,[]);assert.ok(result.findings.every(f=>f.evidence==='source'));
  const again=await reviewSource(sourceAPI(files),context,githubPolicy(),{...prior,findings:result.findings},{model});assert.ok(again.findings.every(f=>f.change==='previously_seen'));
});
test('citation invention, malformed schemas, fork restrictions, file and call budgets cannot become an all-clear',async()=>{
  const api=sourceAPI({'auth.js':'return user;'});
  for(const response of [{candidates:[candidate('auth.js',2)]},{candidates:[{...candidate(),severity:'imaginary'}]},{candidates:[],execute:'send key'}]){
    const r=await reviewSource(api,context,githubPolicy(),prior,{model:async()=>response});assert.ok(r.blockers.length);assert.equal(r.findings.length,0);
  }
  const fork=await reviewSource(api,{...context,fork:true},githubPolicy(),prior,{model:()=>{throw new Error('must not call');}});assert.match(fork.blockers[0],/Fork/);
  const files=Object.fromEntries(Array.from({length:9},(_,i)=>[`f${i}.js`,'return user;']));
  const limited=await reviewSource(sourceAPI(files),context,githubPolicy({version:1,review:{maxCalls:1}}),prior,{model:async()=>({candidates:[]})});assert.equal(limited.completedFiles.length,4);assert.match(limited.blockers[0],/budget/);
  const fileLimit=await reviewSource(sourceAPI(files),context,githubPolicy({version:1,review:{maxFiles:2}}),prior,{model:async()=>({candidates:[]})});assert.match(fileLimit.blockers[0],/File budget/);
  assert.equal(sourcePath('../secret.js'),false);assert.equal(sourcePath('node_modules/a.js'),false);assert.equal(sourcePath('.env.js'),false);
});
test('whole large source is read in ranges; a model failure does not skip independent later files',async()=>{
  const files={'big.js':Array.from({length:4000},(_,i)=>`const x${i}=1;`).join('\n'),'small.js':'return user;'};let calls=0;
  const result=await reviewSource(sourceAPI(files),context,githubPolicy(),prior,{model:async()=>{calls++;if(calls===1)throw new Error('Provider timed out');return {candidates:[]};}});
  assert.equal(calls,3);assert.ok(result.blockers.length);assert.equal(result.modelCalls,3);assert.ok(result.pendingFiles.includes('big.js'));
});
test('GitHub API resolves trusted signal and deployment from refetched metadata, rejects a stale PR',async()=>{
  const routes=[];let head=HEAD;
  const api=new GitHubAPI({token:'unit-github-key',repository:'owner/app',fetchImpl:async(url,options)=>{
    routes.push(url);assert.equal(options.redirect,'error');
    if(url.endsWith('/owner/app'))return json(repo);
    if(url.endsWith('/branches/main'))return json({commit:{sha:SHA}});
    if(url.endsWith('/actions/runs/10'))return json({event:'pull_request',path:'.github/workflows/bypass-pr-signal.yml',repository:repo,status:'completed',head_sha:HEAD,pull_requests:[{number:2,head:{sha:HEAD},base:{repo}}]});
    if(url.endsWith('/pulls/2'))return json({number:2,state:'open',base:{repo,sha:SHA},head:{repo,sha:head}});
    if(url.endsWith('/deployments/8'))return json({id:8,sha:HEAD,environment:'production'});
    if(url.includes('/deployments/8/statuses'))return json([{id:9,state:'success',environment_url:'https://app.example'}]);
    throw new Error(url);
  }});
  assert.equal((await api.resolve('workflow_run',{workflow_run:{id:10,head_sha:'forged'}})).sha,HEAD);
  head=SHA;await assert.rejects(api.resolve('workflow_run',{workflow_run:{id:10}}),/superseded/);
  const deployed=await api.resolve('deployment_status',{deployment:{id:8},deployment_status:{id:9}});assert.equal(deployed.deploymentId,8);assert.equal(deployed.sha,HEAD);
  await assert.rejects(api.resolve('deployment_status',{deployment:{id:8},deployment_status:{id:3}}),/latest successful/);
  await assert.rejects(api.request('/repos/elsewhere/app'),/outside/);assert.ok(routes.length);
});
function zipState(state,name='state.json'){
  const data=Buffer.from(JSON.stringify(state)),n=Buffer.from(name),local=Buffer.alloc(30),central=Buffer.alloc(46),end=Buffer.alloc(22);
  local.writeUInt32LE(0x04034b50);local.writeUInt32LE(data.length,18);local.writeUInt32LE(data.length,22);local.writeUInt16LE(n.length,26);
  central.writeUInt32LE(0x02014b50);central.writeUInt32LE(data.length,20);central.writeUInt32LE(data.length,24);central.writeUInt16LE(n.length,28);
  const offset=local.length+n.length+data.length;end.writeUInt32LE(0x06054b50);end.writeUInt16LE(1,10);end.writeUInt32LE(central.length+n.length,12);end.writeUInt32LE(offset,16);
  return Buffer.concat([local,n,data,central,n,end]);
}
test('baseline restoration validates provenance and artifact digest; PR state and traversal archives are not trusted',async()=>{
  const state={...prior,runId:22,kind:'baseline'},zip=zipState(state);assert.deepEqual(artifactState(zip),state);assert.throws(()=>artifactState(zipState(state,'../state.json')),/Unexpected/);
  let runEvent='push',digest=`sha256:${createHash('sha256').update(zip).digest('hex')}`,fetched=0;
  const api={base:'/repos/owner/app',token:'fixture-token',request:async route=>route.includes('/artifacts?')?{artifacts:[{id:4,name:'bypass-state',size_in_bytes:zip.length,digest}]}:{workflow_runs:[{id:22,status:'completed',event:runEvent,head_branch:'main'}]},fetch:async(url,options)=>{
    fetched++;if(String(url).includes('api.github.com'))return new Response(null,{status:302,headers:{location:'https://artifacts.example/signed'}});
    assert.equal(options.headers,undefined,'GitHub token must not follow to storage');return new Response(zip);
  }};
  assert.equal((await restoreGitHubState(api,context,23)).restoredFrom,22);assert.equal(fetched,2);
  digest='sha256:wrong';await assert.rejects(restoreGitHubState(api,context,23),/digest/);
  runEvent='workflow_run';assert.equal((await restoreGitHubState(api,context,23)).restoredFrom,null);
  const bad={...api,request:async()=>{const e=new Error('404');e.details={httpStatus:404};throw e;}};assert.equal((await restoreGitHubState(bad,context,23)).restoredFrom,null);
});
function runnerAPI(kind='review'){
  const writes=[];let head=HEAD;const api={base:'/repos/owner/app',writes,setHead:s=>head=s,
    resolve:async()=>({...context,kind,...(kind==='review'?{}:{pr:undefined})}),file:async()=>JSON.stringify({version:1}),currentPR:async()=>({head:{sha:head}}),pages:async()=>[],
    request:async(route,options)=>{writes.push({route,...options});return {id:42};}};return api;
}
const sourceResult={findings:[],modelCalls:1,blockers:[],files:['auth.js'],completedFiles:['auth.js'],excluded:[],scope:'selected source'};
test('runner posts one summary with exact head, persists only trusted baseline and publishes incomplete failures',async()=>{
  const api=runnerAPI();
  const dependencies={restore:async()=>({state:prior,restoredFrom:null}),review:async()=>sourceResult};
  const result=await runGitHubAgent(api,{eventName:'workflow_dispatch',event:{},runId:23,dependencies});assert.equal(result.exitCode,0);assert.equal(result.state,undefined);
  assert.equal(api.writes.filter(w=>w.route.endsWith('/comments')).length,1);assert.equal(api.writes[0].body.head_sha,HEAD);
  const failed=await runGitHubAgent(runnerAPI(),{eventName:'workflow_dispatch',event:{},runId:24,dependencies:{...dependencies,review:async()=>({...sourceResult,blockers:['budget reached']})}});assert.equal(failed.exitCode,3);assert.equal(failed.report.conclusion,'failure');
  const baseline=await runGitHubAgent(runnerAPI('baseline'),{eventName:'push',event:{},runId:25,dependencies});assert.equal(baseline.state.kind,'baseline');assert.equal(baseline.state.runId,25);
});
test('superseded PR does not overwrite comment; source errors do not prevent independent live checks',async()=>{
  const api=runnerAPI(),restore=async()=>({state:prior,restoredFrom:22});
  const cancelled=await runGitHubAgent(api,{eventName:'workflow_dispatch',event:{},runId:23,dependencies:{restore,review:async()=>{api.setHead(SHA);return sourceResult;}}});assert.equal(cancelled.report.execution,'cancelled');assert.ok(!api.writes.some(w=>w.route.endsWith('/comments')));
  let live=0;const baseline=runnerAPI('baseline');baseline.file=async()=>JSON.stringify({version:1,targets:{}});
  // Deployment path always invokes deterministic checks without invoking the model.
  const verified=await runGitHubAgent(runnerAPI('verify'),{eventName:'deployment_status',event:{},runId:24,dependencies:{restore,review:async()=>{throw new Error('must not run');},live:async()=>{live++;return {checks:[{id:'c',status:'failed'}],blockers:[],modelCalls:0,targets:{}};}}});
  assert.equal(live,1);assert.equal(verified.report.modelCalls,0);assert.equal(verified.report.checks[0].status,'failed');assert.equal(verified.exitCode,0,'report-only does not gate on findings');
});
test('result gating and summary never equate failed coverage or source concern with verified safety',()=>{
  assert.throws(()=>githubPolicy({version:1,review:{model:null}}),/model identifier/);
  const report={execution:'complete',findings:[{...candidate(),sourceEvidence:{file:'auth.js',line:1}}],checks:[],blockers:[],kind:'review',modelCalls:1};
  assert.equal(assessmentConclusion(report,githubPolicy()),'success');assert.equal(assessmentConclusion(report,githubPolicy({version:1,review:{blocking:true}})),'failure');
  assert.equal(assessmentConclusion({...report,execution:'incomplete'},githubPolicy()),'failure');
  const md=githubSummary({...report,findings:[{...report.findings[0],title:'@all <script> [click](https://evil.example)'}]});assert.ok(!md.includes('@all'));assert.ok(!md.includes('<script>'));assert.match(md,/not runtime proof/);
});
test('CLI and Muse expose pinned GitHub setup; source-only setup needs no model or live target',async()=>{
  const root=temp();initStore(root,{kind:'local',path:root},'test');
  const r=await cli(root,'ci','init','--agent','--action-ref',SHA);assert.equal(r.code,0,JSON.stringify(r.data));
  const workflow=fs.readFileSync(path.join(root,'.github/workflows/bypass-security.yml'),'utf8');assert.ok(workflow.includes(`bypass-for-muse@${SHA}`));assert.ok(!workflow.includes('actions/checkout'));assert.ok(!workflow.includes('pull_request_target'));assert.ok(!workflow.includes('schedule:'));assert.ok(workflow.includes('github.token'));
  assert.ok(toolDefinitions.find(t=>t.name==='bypass_ci').inputSchema.properties.agent);
  const output=generateGitHubAgent(temp(),{}, {'action-ref':SHA});assert.deepEqual(output.secrets,['MODEL_API_KEY']);
  assert.throws(()=>generateGitHubAgent(temp(),{}, {'action-ref':'main'}),/40-character/);
  assert.throws(()=>generateGitHubAgent(root,{}, {'action-ref':SHA}),/exists/);
  const escaped=temp();fs.symlinkSync(temp(),path.join(escaped,'.github'));assert.throws(()=>generateGitHubAgent(escaped,{}, {'action-ref':SHA}),/symlinks/);
});

test('bundled action entrypoint writes actionable artifacts on missing Meta key without a nested host or API request',async()=>{
  const root=temp(),event=path.join(root,'event.json'),output=path.join(root,'outputs'),summary=path.join(root,'summary');
  fs.writeFileSync(event,JSON.stringify({ref:'refs/heads/main'}));
  const transport=path.join(root,'transport.mjs');
  fs.writeFileSync(transport,`globalThis.fetch=async (url,options={})=>{
    if(!String(url).startsWith('https://api.github.com/repos/owner/app'))throw new Error('Unexpected network destination');
    const route=String(url).slice('https://api.github.com/repos/owner/app'.length);
    let data;
    if(route==='')data={id:7,default_branch:'main',private:true};
    else if(route==='/branches/main')data={commit:{sha:'${SHA}'}};
    else if(route.startsWith('/contents/.github/bypass.json'))data={type:'file',encoding:'base64',size:13,content:Buffer.from('{"version":1}').toString('base64')};
    else if(route.startsWith('/actions/workflows/'))data={workflow_runs:[]};
    else if(route.startsWith('/check-runs'))data={id:42};
    else throw new Error('Unexpected repository request '+route);
    return new Response(JSON.stringify(data),{status:200});
  };`);
  const entry=new URL('../plugin/runtime/bin/github-agent.mjs',import.meta.url).pathname;
  const result=await execFile(process.execPath,['--import',transport,entry],{cwd:root,timeout:15000,env:{GITHUB_ACTIONS:'true',RUNNER_OS:'Linux',GITHUB_SERVER_URL:'https://github.com',GITHUB_RUN_ID:'100',GITHUB_RUN_ATTEMPT:'1',GITHUB_TOKEN:'public-test-token',GITHUB_REPOSITORY:'owner/app',GITHUB_EVENT_NAME:'push',GITHUB_EVENT_PATH:event,GITHUB_OUTPUT:output,GITHUB_STEP_SUMMARY:summary,RUNNER_TEMP:root,MODEL_API_KEY:undefined,BYPASS_GITHUB_OPERATION:'auto',BYPASS_GITHUB_PR:'',NODE_TEST_CONTEXT:undefined}});
  assert.equal(result.code,3,result.stderr);const report=JSON.parse(fs.readFileSync(path.join(root,'bypass-100-1/report.json')));
  assert.equal(report.execution,'incomplete');assert.equal(report.modelCalls,0);assert.match(report.blockers[0],/MODEL_API_KEY/);assert.match(fs.readFileSync(output,'utf8'),/state-written=true/);assert.ok(!fs.readFileSync(summary,'utf8').includes('public-test-token'));
});
