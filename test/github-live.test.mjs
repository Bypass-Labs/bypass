import test from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import fs from 'node:fs';
import path from 'node:path';
import { verifyLive } from '../src/github-live.mjs';
import { replay } from '../src/portable-check.mjs';
import { githubPolicy } from '../src/github-policy.mjs';
import { generateGitHubAgent } from '../src/github-setup.mjs';
import { runGitHubAgent } from '../src/github-agent.mjs';
import { temp } from './helpers.mjs';

const SHA='a'.repeat(40),origin='https://app.example',future=new Date(Date.now()+86400000).toISOString();
const context={kind:'verify',sha:SHA,deploymentId:12,environment:'production',deploymentURL:origin};
const env={BYPASS_DNS_PRODUCTION:'bypass-verification=abcdefghijklmnopqrstuv',OWNER_TOKEN:'owner-fixture',OTHER_TOKEN:'outsider-fixture'};
const base={schemaVersion:1,origin,environment:'production',authorization:{origin,methods:['GET'],paths:['/api'],maxRequestsPerSecond:10,expiresAt:future,productionAcknowledged:true},ownershipExpiresAt:future,resourcePath:'/api/jobs/one',resourceId:'one',idField:'id',identityField:'id',requireIdentityControl:true,owner:{type:'bearer',secretEnv:'OWNER_TOKEN',checkPath:'/api/me'},outsider:{type:'bearer',secretEnv:'OTHER_TOKEN',checkPath:'/api/me'}};
const policy=()=>githubPolicy({version:1,targets:{production:{origin,environment:'production',ownershipTokenEnv:'BYPASS_DNS_PRODUCTION',revision:{path:'/api/version',field:'sha'},checks:[{id:'cross_account',spec:structuredClone(base)},{id:'anonymous',spec:{...base,kind:'anonymous',owner:undefined,outsider:undefined,expected:'private'}}]}}});
const previous={findings:[],targets:{}};

test('real HTTP controls: failure, verified fix, regression; continue through all checks with zero AI',async t=>{
  let vulnerable=true,invalidLogin=false,requests=0;
  const server=http.createServer((req,res)=>{
    requests++;const who=req.headers.authorization;let status=200,body;
    if(req.url==='/api/me'){status=invalidLogin?401:200;body={id:who==='Bearer owner-fixture'?'owner':'outsider'};}
    else if(!who){status=401;body={error:'unauthenticated'};}
    else if(who==='Bearer owner-fixture'||vulnerable)body={id:'one'};
    else{status=403;body={error:'forbidden'};}
    res.writeHead(status,{'Content-Type':'application/json'});res.end(JSON.stringify(body));
  });
  await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve));t.after(()=>new Promise(resolve=>server.close(resolve)));const local=`http://127.0.0.1:${server.address().port}`;
  const deps={env,sleep:async()=>{},resolveTxt:async()=>[[env.BYPASS_DNS_PRODUCTION]],request:async()=>({status:200,body:JSON.stringify({sha:SHA})}),runCheck:spec=>replay({...spec,origin:local,environment:'local',authorization:{...spec.authorization,origin:local}},{env})};
  const failed=await verifyLive({},context,policy(),previous,deps);assert.deepEqual(failed.checks.map(c=>c.status),['failed','passed']);assert.equal(failed.modelCalls,0);assert.equal(failed.checks[0].requests,5);assert.deepEqual(failed.checks[0].controls.map(c=>c.status),[200,200,200,200,401]);assert.equal(requests,6);
  vulnerable=false;const fixed=await verifyLive({},context,policy(),{...previous,targets:failed.targets},deps);assert.equal(fixed.checks[0].transition,'fix_verified');assert.equal(fixed.checks[0].status,'passed');
  vulnerable=true;const regressed=await verifyLive({},context,policy(),{...previous,targets:fixed.targets},deps);assert.equal(regressed.checks[0].transition,'regressed');assert.equal(regressed.checks[1].status,'passed');
  invalidLogin=true;const blocked=await verifyLive({},context,policy(),{...previous,targets:fixed.targets},deps);assert.equal(blocked.checks[0].status,'blocked');assert.equal(blocked.checks[1].status,'passed');assert.ok(blocked.blockers.length);assert.ok(!blocked.checks.some(c=>c.transition==='fix_verified'));
});
test('ownership, expiry, scope, wrong origin and wrong build prevent probes; rollout changes cannot verify a fix',async()=>{
  let probes=0,requests=0,version=SHA;
  const deps={env,sleep:async()=>{},resolveTxt:async()=>[[env.BYPASS_DNS_PRODUCTION]],request:async()=>{requests++;return {status:200,body:JSON.stringify({sha:version})};},runCheck:async()=>{probes++;return {status:'passed',modelCalls:0};}};
  const wrongDNS=await verifyLive({},context,policy(),previous,{...deps,resolveTxt:async()=>[['wrong']]});assert.match(wrongDNS.blockers[0],/DNS/);assert.equal(requests,0);
  const wrongOrigin=await verifyLive({},{...context,deploymentURL:'https://elsewhere.example'},policy(),previous,deps);assert.match(wrongOrigin.blockers[0],/match/);assert.equal(probes,0);
  version='b'.repeat(40);const mismatch=await verifyLive({},context,policy(),previous,deps);assert.match(mismatch.blockers[0],/SHA/);assert.equal(probes,0);
  version=SHA;const expired=policy();for(const c of expired.targets.production.checks)c.spec.authorization.expiresAt='2000-01-01';await verifyLive({},context,expired,previous,deps);assert.equal(probes,0);
  const unscoped=policy();unscoped.targets.production.revision.path='/outside';await verifyLive({},context,unscoped,previous,deps);assert.equal(probes,0);
  requests=0;const rolling=await verifyLive({},context,policy(),previous,{...deps,request:async()=>({status:200,body:JSON.stringify({sha:++requests===1?SHA:'b'.repeat(40)})})});assert.ok(rolling.checks.every(c=>c.status==='blocked'));assert.deepEqual(rolling.targets,{});assert.equal(probes,2);
});
test('smoke resolves the registered deployment, has no model calls and never reports empty coverage as passing',async()=>{
  let calls=0;const api={latestDeployment:async (environment,requestedOrigin)=>{calls++;assert.equal(environment,'production');assert.equal(requestedOrigin,origin);return {id:12,sha:SHA,url:origin};}};
  const result=await verifyLive(api,{kind:'smoke'},policy(),previous,{env,sleep:async()=>{},resolveTxt:async()=>[[env.BYPASS_DNS_PRODUCTION]],request:async()=>({status:200,body:JSON.stringify({sha:SHA})}),runCheck:async()=>({status:'passed',modelCalls:0})});assert.equal(result.modelCalls,0);assert.equal(calls,1);assert.equal(result.checks.length,2);
  const empty=await verifyLive(api,{kind:'smoke'},githubPolicy(),previous,{});assert.ok(empty.blockers.length);
});
test('a deployment selects only the matching app when multiple apps share an environment',async()=>{
  const configured=policy();configured.targets.second={...configured.targets.production,origin:'https://second.example'};
  const result=await verifyLive({},context,configured,previous,{env,sleep:async()=>{},resolveTxt:async()=>[[env.BYPASS_DNS_PRODUCTION]],request:async()=>({status:200,body:JSON.stringify({sha:SHA})}),runCheck:async()=>({status:'passed',modelCalls:0})});
  assert.equal(result.checks.length,2);assert.deepEqual(result.blockers,[]);assert.ok(result.checks.every(c=>c.target==='production'));
});
test('live setup exports only credential references and pinned schedules while preserving expiring permission',()=>{
  const root=temp(),state={settings:{requestTimeoutMs:8000},targets:[{name:'production',url:origin,environment:'production',ownership:{status:'verified',method:'dns',expiresAt:future},authorization:base.authorization}],identities:[{name:'owner',target:'production',...base.owner,credentialRef:'private-secret',lastTest:{token:'never-export'}},{name:'other',target:'production',...base.outsider}],checks:[{id:'check_one',findingId:'finding_one',enabled:true,engine:'host',title:'Account boundary',bindings:{production:{resourcePath:base.resourcePath,resourceId:'one',owner:'owner',outsider:'other',identityField:'id'}}}]};
  const generated=generateGitHubAgent(root,state,{agent:true,'action-ref':SHA,target:'production','revision-path':'/api/version','revision-field':'sha',every:'6h'});
  const config=fs.readFileSync(path.join(root,'.github/bypass.json'),'utf8');assert.ok(!config.includes('private-secret'));assert.ok(!config.includes('never-export'));assert.ok(config.includes(future));assert.ok(generated.secrets.includes('OWNER_TOKEN'));
  const yaml=fs.readFileSync(generated.workflow,'utf8');assert.ok(yaml.includes("17 */6 * * *"));assert.ok(yaml.includes('${{ secrets.OWNER_TOKEN }}'));assert.ok(!yaml.includes('muse login'));
  const parsed=JSON.parse(config);parsed.targets.production.checks[0].spec.owner.secretEnv='MODEL_API_KEY';assert.throws(()=>githubPolicy(parsed),/dedicated app/);
});
test('a model error cannot prevent the independent configured baseline replay',async()=>{
  let live=0;const api={base:'/repos/owner/app',resolve:async()=>({...context,kind:'baseline',repositoryId:7,repository:'owner/app',policySha:SHA}),file:async()=>JSON.stringify(policy()),request:async()=>({id:1})};
  const result=await runGitHubAgent(api,{eventName:'push',event:{},runId:1,dependencies:{restore:async()=>({state:previous}),review:async()=>{throw new Error('Meta unavailable');},live:async()=>{live++;return {checks:[{status:'failed',id:'one'}],blockers:[],modelCalls:0,targets:{}};}}});
  assert.equal(live,1);assert.equal(result.report.checks.length,1);assert.equal(result.report.execution,'incomplete');assert.equal(result.exitCode,3);
});
