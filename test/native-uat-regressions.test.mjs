import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import http from 'node:http';
import {temp} from './helpers.mjs';
import {execute} from '../src/service.mjs';
import {read, change} from '../src/store.mjs';
import {rememberOwnership} from '../src/ownership-store.mjs';
import {inExecutionMode} from '../src/execution-mode.mjs';
import {prepareBlackboxSetup} from '../src/blackbox/setup.mjs';
import {blackboxEnvironment} from '../src/blackbox/accounts.mjs';
import {runAudit} from '../src/blackbox/index.mjs';
import {verifyRun, exportRun} from '../src/blackbox/poc.mjs';
import {mcpClient} from './mcp-client.mjs';

function directory(t) {const root=temp();t.after(()=>fs.rmSync(root,{recursive:true,force:true}));return root;}
function variable(t,key,value){const prior=process.env[key];process.env[key]=value;t.after(()=>{if(prior===undefined)delete process.env[key];else process.env[key]=prior;});}
const host = work => inExecutionMode('muse-host',work);

test('missing explicit blackbox credentials leave setup ready for anonymous checks and authorized signup',async t=>{
 const root=directory(t),url='http://127.0.0.1:1';
 const setup=await host(()=>prepareBlackboxSetup(root,url,{'owner-env':'UAT_MISSING_OWNER','other-env':'UAT_MISSING_OTHER',include:'/','identity-path':'/api/me'}));
 assert.equal(setup.ready,true);assert.equal(setup.accounts.mode,'anonymous-only');assert.equal(setup.accounts.warnings.length,2);
 assert.equal(setup.modelCheck,null);assert.equal(setup.nextAction.tool,'bypass_blackbox_start');assert.equal(setup.steps[0].kind,'run');
 assert.deepEqual(await blackboxEnvironment(root,JSON.parse(fs.readFileSync(setup.scopeFile)),{env:{}}),{});
 assert.match(setup.accounts.warnings[0],/Continue available checks and authorized account creation/);
});

test('new blackbox project reuses valid domain ownership without inheriting scope',async t=>{
 variable(t,'BYPASS_OWNERSHIP_DIR',directory(t));const original=directory(t),next=directory(t),url='https://app.example.test';
 await execute('init',[original]);await execute('target add',['production'],{project:original,url,environment:'production'});
 await change(original,s=>{s.targets[0].ownership={status:'verified',method:'dns',origin:url,verifiedAt:new Date().toISOString(),expiresAt:new Date(Date.now()+86400000).toISOString()};});
 rememberOwnership(read(original),read(original).targets[0]);
 const result=await prepareBlackboxSetup(next,url,{environment:'production'});
 assert.equal(result.targets[0].ownershipReady,true);assert.equal(result.targets[0].challenge,null);
 assert.equal(result.steps.some(s=>s.kind==='ownership'),false);assert.equal(result.targets[0].authorizationReady,false);
 assert.equal(read(next).targets[0].authorization,null);
});

test('deferred source finish remains visibly open with a concrete continuation action',async t=>{
 const root=directory(t);for(let i=0;i<5;i++)fs.writeFileSync(path.join(root,`app${i}.mjs`),`export const value${i} = ${i};\n`);
 await execute('init',[root]);const run=await host(()=>execute('scan',[],{project:root,mode:'code'}));
 await host(()=>execute('host review',[],{project:root,id:run.runId,action:'read',paths:['app0.mjs']}));
 const deferred=await host(()=>execute('host review',[],{project:root,id:run.runId,action:'complete',candidates:[]}));
 assert.equal(deferred.finishDeferred,true);assert.equal(deferred.completion.finalReportAllowed,false);assert.equal(deferred.progress.stage,'continuing');
 assert.equal(deferred.nextAction.arguments.action,'read');assert.equal(deferred.work.source.remainingFiles,4);
 assert.doesNotMatch(deferred.progress.lastCompleted.message,/finish complete|complete complete/);
 const coverage=await execute('coverage',[],{project:root,run:run.runId});assert.doesNotMatch(coverage.assessment.scopeProvenance,/legacy/);
 await host(()=>execute('host review',[],{project:root,id:run.runId,action:'read',paths:deferred.nextAction.arguments.paths}));
 const finished=await host(()=>execute('host review',[],{project:root,id:run.runId,action:'finish'}));
 assert.equal(finished.status,'completed');assert.equal(finished.completion.finalReportAllowed,true);assert.equal(finished.work.source.remainingFiles,0);
});

for(const packaged of [false,true])test(`${packaged?'packaged':'source'} blackbox setup reuses privately imported accounts without environment exports`,async t=>{
 const root=directory(t),vault=directory(t),stateDir=directory(t),privateDir=directory(t),url='http://127.0.0.1:32199';
 fs.writeFileSync(path.join(root,'app.mjs'),'export const app = true;\n');
 const file=path.join(privateDir,'accounts.json');fs.writeFileSync(file,JSON.stringify({OWNER:'synthetic-native-owner-value',OTHER:'synthetic-native-other-value'}),{mode:0o600});
 const c=await mcpClient(root,{stateDir,packaged,env:{BYPASS_CREDENTIAL_DIR:vault,UAT_PRIVATE_OWNER:'',UAT_PRIVATE_OTHER:''}});t.after(()=>c.close());
 await c.call('bypass_connect_repository',{repository:root,confirmed:true});
 await c.call('bypass_add_target',{name:'local',url,environment:'local'});await c.call('bypass_verify_target',{name:'local',method:'local'});
 await c.call('bypass_authorize_target',{name:'local',paths:'/',methods:'GET,HEAD,POST',accept:true});
 for(const [name,field] of [['owner','OWNER'],['outsider','OTHER']])await c.call('bypass_import_identity',{name,target:'local',file,'token-field':field,type:'bearer','secret-env':`UAT_PRIVATE_${field}`,'check-path':'/api/me'});
 const result=await c.call('bypass_blackbox_setup',{url,include:'/',rps:2});
 assert.equal(result.ready,true);assert.equal(result.accounts.mode,'two-accounts');assert.equal(result.modelCheck,null);
 assert.equal(result.nextAction.tool,'bypass_blackbox_start');assert.ok(result.accounts.accounts.every(item=>item.source==='private-store'));
 assert.doesNotMatch(JSON.stringify(result),/synthetic-native-(owner|other)-value/);
 const scope=JSON.parse(fs.readFileSync(result.scopeFile));assert.equal(scope.identities.owner.env,'UAT_PRIVATE_OWNER');assert.equal(scope.identities.outsider.env,'UAT_PRIVATE_OTHER');assert.equal(scope.identities.identityPath,'/api/me');
});

test('real blackbox audit and proof replay use the saved vault pair and preserve origin/revocation gates',async t=>{
 const root=directory(t),vault=directory(t),privateDir=directory(t);variable(t,'BYPASS_CREDENTIAL_DIR',vault);
 let fixed=false;const tokens={owner:'private-uat-owner-token',outsider:'private-uat-outsider-token'},seen=new Set();
 const server=http.createServer((req,res)=>{
  const url=new URL(req.url,'http://local'),who=Object.keys(tokens).find(key=>req.headers.authorization===`Bearer ${tokens[key]}`);if(who)seen.add(who);
  const json=(status,value)=>{res.writeHead(status,{'content-type':'application/json'});res.end(JSON.stringify(value));};
  if(url.pathname==='/openapi.json')return json(200,{openapi:'3.0.0',paths:{'/api/me':{get:{}},'/api/invoices':{get:{}},'/api/invoices/{id}':{get:{}}}});
  if(url.pathname==='/api/me')return json(who?200:401,who?{id:who}:{});
  const records=[{id:'inv-1',ownerId:'owner',balance:17},{id:'inv-2',ownerId:'outsider',balance:33}];
  if(url.pathname==='/api/invoices')return json(who?200:401,who?records.filter(r=>r.ownerId===who):{});
  if(url.pathname.startsWith('/api/invoices/')){const item=records.find(r=>r.id===url.pathname.split('/').at(-1));return json(!who?401:!item||fixed&&item.ownerId!==who?404:200,who&&item&&(!fixed||item.ownerId===who)?item:{});}
  return json(404,{});
 });await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve));t.after(()=>new Promise(resolve=>server.close(resolve)));
 const url=`http://127.0.0.1:${server.address().port}`;await execute('init',[root]);await execute('target add',['local'],{project:root,url,environment:'local'});await execute('target verify',['local'],{project:root,method:'local'});
 const auth=path.join(root,'scope.json');fs.writeFileSync(auth,JSON.stringify({paths:['/'],methods:['GET','HEAD','POST'],maxRequestsPerSecond:10,expiresAt:new Date(Date.now()+86400000).toISOString()}));
 await execute('target authorize',['local'],{project:root,'scope-file':auth,accept:true});
 const anonymousSetup=await prepareBlackboxSetup(root,url,{'owner-env':'UAT_OWNER','other-env':'UAT_OUTSIDER',rps:10,'max-urls':8,'max-tasks':5,minutes:1});
 const anonymousScope=JSON.parse(fs.readFileSync(anonymousSetup.scopeFile));anonymousScope.discovery.sensitivePaths=false;anonymousScope.harvest.sequentialNeighbors=0;anonymousScope.discover=['/openapi.json'];fs.writeFileSync(anonymousSetup.scopeFile,JSON.stringify(anonymousScope));
 const anonymous=await runAudit({root,url,scopeFile:anonymousSetup.scopeFile,noModel:true,env:{}});
 assert.ok(anonymous.stats.requests>0,'missing references do not stop real anonymous HTTP checks');assert.equal(seen.size,0);
 assert.equal(anonymous.findings.some(f=>f.kind==='idor'),false);
 const file=path.join(privateDir,'accounts.json');fs.writeFileSync(file,JSON.stringify(tokens),{mode:0o600});
 for(const name of ['owner','outsider'])await execute('identity import',[name],{project:root,file,'token-field':name,target:'local',type:'bearer','secret-env':`UAT_${name.toUpperCase()}`,'check-path':'/api/me'});
 const setup=await prepareBlackboxSetup(root,url,{rps:10,'max-urls':8,'max-tasks':5,minutes:1});
 const scope=JSON.parse(fs.readFileSync(setup.scopeFile));scope.discovery.sensitivePaths=false;scope.harvest.sequentialNeighbors=0;scope.discover=['/openapi.json'];fs.writeFileSync(setup.scopeFile,JSON.stringify(scope));
 const first=await runAudit({root,url,scopeFile:setup.scopeFile,noModel:true,env:{}});
 assert.deepEqual([...seen].sort(),['outsider','owner']);assert.ok(first.findings.length,JSON.stringify({stats:first.stats,coverage:first.coverage}));
 assert.equal((await verifyRun(root,first.run,{env:{}})).exitCode,1);
 fixed=true;assert.equal((await verifyRun(root,first.run,{env:{}})).exitCode,0);
 const exported=exportRun(root,first.run);assert.ok(exported.files.length);assert.doesNotMatch(fs.readFileSync(exported.files[0],'utf8'),/private-uat-(owner|outsider)-token/);
 await execute('target revoke',['local'],{project:root});await assert.rejects(blackboxEnvironment(root,scope,{env:{}}),/ownership|authorization/);
 const different={...scope,target:{...scope.target,origin:'http://127.0.0.1:32198'}};assert.deepEqual(await blackboxEnvironment(root,different,{env:{}}),{});
});
