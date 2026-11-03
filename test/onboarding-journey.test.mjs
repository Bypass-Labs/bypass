import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import dns from 'node:dns/promises';
import http from 'node:http';
import { temp, metaModelFixture } from './helpers.mjs';
import { execute } from '../src/service.mjs';
import { read, change } from '../src/store.mjs';
import { pluginOnboarding } from '../src/plugin-onboarding.mjs';
import { onboard } from '../src/onboarding.mjs';
import { sharedOwnership, rememberProjectOwnership } from '../src/ownership-store.mjs';
import { scopeReady } from '../src/network.mjs';
import { mcpClient } from './mcp-client.mjs';
import { execFile } from '../src/util.mjs';
import { CLI } from '../src/demo.mjs';
import { carryAppSetup } from '../src/application-setup.mjs';
import { reviewSummary } from '../src/experience.mjs';

const source=()=>{const root=temp();fs.writeFileSync(path.join(root,'app.mjs'),'throw new Error("source must not execute");\n');return root;};
function isolated(t){const state=temp(),ownership=path.join(state,'ownership'),old=process.env.BYPASS_OWNERSHIP_DIR;process.env.BYPASS_OWNERSHIP_DIR=ownership;t.after(()=>{process.env.BYPASS_OWNERSHIP_DIR=old;});return {stateDir:state,packaged:true,env:{BYPASS_OWNERSHIP_DIR:ownership}};}
function blank(schema){
  if(schema?.anyOf)return blank(schema.anyOf[0]);
  const type=Array.isArray(schema?.type)?schema.type.find(item=>item!=='null'):schema?.type;
  if(type==='array')return [];
  if(type==='object')return Object.fromEntries((schema.required??[]).map(key=>[key,blank(schema.properties?.[key])]));
  if(type==='integer'||type==='number')return schema.minimum??0;
  if(type==='boolean')return false;
  return schema?.enum?.[0]??'';
}

test('fresh plugin offers three modes; empty folder is rejected before initialization or DNS',async t=>{
  const host=temp(),c=await mcpClient(host,isolated(t));t.after(()=>c.close());
  const first=await c.call('bypass_onboarding');assert.equal(first.stage,'review-type');assert.equal(first.nextAction.input.hostControl,'request_user_input');
  assert.deepEqual(first.nextAction.input.choices.map(c=>c.id),['code','combined','live']);
  const chosen=await c.call('bypass_onboarding',{mode:'combined',repository:host,url:'https://app.example.com',environment:'production'});
  assert.equal(chosen.stage,'repository');
  const rejected=await c.raw('bypass_connect_repository',{repository:host,confirmed:true});assert.equal(rejected.result.isError,true);assert.match(JSON.stringify(rejected),/No eligible application source/);
  assert.equal(fs.existsSync(path.join(host,'.bypass')),false);
  const app=source();await c.call('bypass_connect_repository',{repository:app,confirmed:true});
  const next=await c.call('bypass_onboarding');assert.equal(next.nextAction.tool,'bypass_add_target');assert.equal(next.nextAction.arguments.url,'https://app.example.com');
  assert.equal(read(app).targets.length,0);
});

test('provided Git URL is an actual connect action before app setup, even with a selected empty parent',async()=>{
  const host=temp();await execute('init',[host]);
  const plan=await pluginOnboarding(host,host,{mode:'combined',repository:'https://github.com/Bypass-Labs/job-finder',url:'https://job-radar.app',environment:'production'});
  assert.equal(plan.stage,'repository');assert.equal(plan.nextAction.automatic,true);assert.equal(plan.nextAction.tool,'bypass_connect_repository');
  assert.equal(plan.nextAction.arguments.repository,'https://github.com/Bypass-Labs/job-finder');assert.equal(plan.nextAction.arguments.dir,path.join(host,'job-finder'));
  assert.equal(read(host).targets.length,0);
});

test('same origin keeps verified ownership and exact scope across checkout switch and fresh MCP session',async t=>{
  const options=isolated(t),host=temp(),app=source();await execute('init',[host]);await execute('config set',['ownershipVerification','dns'],{project:host});
  const o={project:host};await execute('target add',['prod'],{...o,url:'https://APP.example.com/',environment:'production'});
  t.mock.method(dns,'resolveTxt',async()=>[[read(host).targets[0].challenge.token]]);
  await execute('target verify',['prod'],{...o,method:'dns'});await execute('target authorize',['prod'],{...o,accept:true,production:true,paths:'/api',methods:'GET,HEAD,POST'});
  const original=structuredClone(read(host).targets[0]);
  const c=await mcpClient(host,options);
  await c.call('bypass_onboarding',{mode:'combined',repository:app,url:'https://app.example.com',environment:'production'});
  const connected=await c.call('bypass_connect_repository',{repository:app,confirmed:true});assert.equal(connected.onboarding.stage,'ready');
  const copied=read(app).targets[0];assert.equal(copied.ownership.verifiedAt,original.ownership.verifiedAt);assert.equal(copied.ownership.reused,true);assert.deepEqual(copied.authorization,original.authorization);
  assert.equal(dns.resolveTxt.mock.callCount(),1);await c.close();
  const fresh=await mcpClient(host,options);t.after(()=>fresh.close());
  const resumed=await fresh.call('bypass_onboarding');assert.equal(resumed.selectedRepository,app);assert.equal(resumed.stage,'ready');assert.match(resumed.steps.find(s=>s.id==='ownership').message,/already verified/);
  const other=source();await execute('init',[other]);await execute('config set',['ownershipVerification','dns'],{project:other});
  const added=await execute('target add',['prod'],{project:other,url:'https://app.example.com:443/',environment:'production'});
  assert.equal(added.target.challenge,undefined);assert.equal(added.target.ownership.reused,true);assert.equal(added.target.authorization,null,'ownership alone never imports a grant into an independent project');
  const foreign=await execute('target add',['other'],{project:other,url:'https://other.example.com',environment:'production'});assert.equal(foreign.target.ownership.status,'pending');
  await execute('target revoke',['prod'],{project:app});assert.equal(sharedOwnership(original.url),null);assert.throws(()=>scopeReady(original),/ownership/);
  // Simulate an old migration write winning the proof-cache race after revoke.
  const proofFile=fs.readdirSync(process.env.BYPASS_OWNERSHIP_DIR).find(f=>f.endsWith('.json'));
  const cached=JSON.parse(fs.readFileSync(path.join(process.env.BYPASS_OWNERSHIP_DIR,proofFile)));
  cached.proof=original.ownership;cached.revokedAt=null;fs.writeFileSync(path.join(process.env.BYPASS_OWNERSHIP_DIR,proofFile),JSON.stringify(cached));
  assert.equal(sharedOwnership(original.url),null,'separate revocation survives a stale cache write');
  rememberProjectOwnership(read(host));assert.equal(sharedOwnership(original.url),null,'legacy state must not resurrect revoked proof');
  const reverified={...original,ownership:{...original.ownership,verifiedAt:new Date(Date.now()+1000).toISOString()}};
  assert.throws(()=>scopeReady(reverified),/authorization/,'fresh ownership cannot revive a testing grant accepted before revocation');
});

test('expired ownership is not reused and a cached target can renew without an old challenge',async t=>{
  isolated(t);const app=source();await execute('init',[app]);await execute('config set',['ownershipVerification','dns'],{project:app});await execute('target add',['prod'],{project:app,url:'https://expired.example.com',environment:'production'});
  t.mock.method(dns,'resolveTxt',async()=>[[read(app).targets[0].challenge.token]]);await execute('target verify',['prod'],{project:app,method:'dns'});
  const dir=process.env.BYPASS_OWNERSHIP_DIR;for(const file of fs.readdirSync(dir).filter(f=>f.endsWith('.json'))){const p=path.join(dir,file),record=JSON.parse(fs.readFileSync(p));record.proof.expiresAt='2000-01-01T00:00:00Z';fs.writeFileSync(p,JSON.stringify(record));}
  assert.equal(sharedOwnership('https://expired.example.com'),null);
  await change(app,s=>{s.targets[0].ownership.expiresAt='2000-01-01T00:00:00Z';delete s.targets[0].challenge;});
  const setup=await pluginOnboarding(app,app,{mode:'combined'});assert.equal(setup.nextAction.automatic,true);assert.equal(setup.nextAction.arguments.renew,true);
});

test('app-only packaged wizard starts blackbox with a fresh or saved scope',async t=>{
  const calls=[],server=http.createServer((req,res)=>{
    calls.push(req.url);
    if(req.url==='/'){res.setHeader('Content-Type','text/html');res.end('<a href="/api/private">API</a><script src="/app.js"></script>');}
    else if(req.url==='/app.js'){res.setHeader('Content-Type','text/javascript');res.end("fetch('/api/private?q=hello')");}
    else{res.setHeader('Content-Type','application/json');res.end(JSON.stringify({id:'synthetic-private-resource'}));}
  });
  await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve));t.after(()=>new Promise(resolve=>server.close(resolve)));
  const host=temp(),options=isolated(t),c=await mcpClient(host,options);t.after(()=>c.close());const url=`http://127.0.0.1:${server.address().port}`;
  let setup=await c.call('bypass_onboarding',{mode:'live',url});assert.equal(setup.nextAction.tool,'bypass_connect_app');
  const profile=await c.call(setup.nextAction.tool,setup.nextAction.arguments);assert.equal(fs.existsSync(path.join(host,'.bypass')),false);
  assert.equal(read(profile.root).project.repository.kind,'app');assert.equal(calls.length,0);
  const workspace=await c.call('bypass_workspace');assert.equal(workspace.selectedRepository,null);assert.equal(workspace.repository,null);assert.equal(workspace.selectionRequired,false);
  assert.equal((await c.call('bypass_dashboard')).done[0],'App profile connected; source not selected');
  await c.call('bypass_verify_target',{name:'local',method:'local'});
  await c.call('bypass_authorize_target',{name:'local',accept:true,methods:['GET'],paths:'/'});
  fs.writeFileSync(path.join(profile.root,'blackbox.scope.json'),JSON.stringify({target:{origin:'https://another-app.example'}}));
  setup=await c.call('bypass_onboarding');assert.equal(setup.ready.source,false);
  assert.equal(setup.nextAction.tool,'bypass_blackbox_setup');
  assert.match(setup.nextAction.arguments.out,/^blackbox\.[a-f0-9]{12}\.scope\.json$/);
  const {out,...scopeArgs}=setup.nextAction.arguments;
  assert.deepEqual(scopeArgs,{url,include:'/',methods:'GET',rps:2,environment:'local'});
  const limits={'model-calls':6,'max-tasks':2,'max-urls':10,minutes:1};
  const fresh=await c.call(setup.nextAction.tool,{...setup.nextAction.arguments,...limits});
  assert.equal(fresh.ready,true);assert.equal(fresh.created,true);
  const saved=await c.call(setup.nextAction.tool,{...setup.nextAction.arguments,...limits});
  assert.equal(saved.ready,true);assert.equal(saved.created,false);assert.equal(saved.scopeFile,fresh.scopeFile);
  const started=await c.call('bypass_blackbox_start',{url,scope:saved.scopeFile,'accept-local':true,...limits});
  assert.equal(started.status,'running');
  let cursor=0,finished=null,decisions=0;
  const deadline=Date.now()+30000;
  while(Date.now()<deadline){
    const current=await c.call('bypass_blackbox_next',{after:cursor});cursor=current.cursor;
    for(const pending of current.pending){await c.call('bypass_blackbox_submit',{id:pending.id,decision:blank(pending.schema)});decisions++;}
    if(current.status!=='running'){finished=current;break;}
    await new Promise(resolve=>setTimeout(resolve,100));
  }
  assert.equal(finished?.status,'completed');
  assert.ok(decisions>0);assert.ok(calls.length>0);
  assert.ok(fs.existsSync(path.join(profile.root,'.bypass/runs',finished.result.run,'evidence.jsonl')));
  assert.equal(read(profile.root).runs.length,0,'wizard did not call bypass_scan');
});

test('CLI mode and environment use selectors; app-only creates a profile without touching cwd',async t=>{
  const options=isolated(t),old=process.env.BYPASS_PLUGIN_STATE_DIR;process.env.BYPASS_PLUGIN_STATE_DIR=options.stateDir;t.after(()=>{process.env.BYPASS_PLUGIN_STATE_DIR=old;});
  const selections=[],prompts=[],host=temp(),meta=await metaModelFixture(t);
  const result=await onboard({flow:'quickstart',project:host},[],{metaBaseUrl:meta.baseUrl,write:()=>{},select:async(title,items)=>{
    selections.push({title,ids:items.map(i=>i.id)});
    if(items.some(i=>i.id==='live'))return items.find(i=>i.id==='live');
    if(items.some(i=>i.id==='production'))return items.find(i=>i.id==='production');
    if(items.some(i=>i.method===null))return items.find(i=>i.method===null);
    if(items.some(i=>i.id==='no'))return items.find(i=>i.id==='no');
    return items[0];
  },ask:async(label,fallback)=>{prompts.push(label);if(label==='App URL')return 'https://cli.example.com';if(/Try again|Open my project|Check the connection/.test(label))return 'n';return fallback||'';}});
  assert.equal(read(result.root).settings.reviewMode,'live');assert.equal(read(result.root).targets[0].environment,'production');assert.equal(fs.existsSync(path.join(host,'.bypass')),false);
  assert.deepEqual(selections[0].ids,['code','combined','live']);assert.ok(selections.some(s=>s.ids.join(',')==='production,staging,preview,local'));assert.ok(!prompts.some(p=>p.includes('Repository')));
});

test('authorized app-only CLI setup immediately hands off to the audit without another questionnaire',async t=>{
  const options=isolated(t),old=process.env.BYPASS_PLUGIN_STATE_DIR;process.env.BYPASS_PLUGIN_STATE_DIR=options.stateDir;t.after(()=>{process.env.BYPASS_PLUGIN_STATE_DIR=old;});
  const host=temp(),meta=await metaModelFixture(t),output=[],prompts=[];
  const result=await onboard({flow:'quickstart',project:host,mode:'live'},[],{rich:true,metaBaseUrl:meta.baseUrl,
    write:value=>output.push(value),select:async(_title,items)=>items.find(item=>item.id==='yes')||items.find(item=>item.id==='meta')||items[0],
    ask:async(label,fallback)=>{prompts.push(label);if(label==='App URL')return 'http://127.0.0.1:4317';return fallback||'';}});
  const target=read(result.root).targets[0];
  assert.deepEqual(result.startReview,{id:'blackbox'});assert.equal(result.openDashboard,true);assert.ok(target.authorization);
  assert.equal(prompts.filter(label=>label==='App URL').length,1);
  assert.equal(prompts.some(label=>/Open my project|Maximum requests per second|Start black-box audit/.test(label)),false);
  assert.doesNotMatch(output.join('\n'),/Use \/blackbox|Press Enter.*blackbox|choose scope and request rate/i);
  assert.match(output.join('\n'),/Starting the audit now with the approved boundaries/);
});

test('switching to a different app URL never carries the previous app or its scope',async t=>{
  const options=isolated(t),host=source(),other=source();await execute('init',[host]);
  await execute('target add',['local'],{project:host,url:'http://127.0.0.1:4567',environment:'local'});await execute('target verify',['local'],{project:host,method:'local'});await execute('target authorize',['local'],{project:host,accept:true,paths:'/api'});
  const c=await mcpClient(host,options);t.after(()=>c.close());
  await c.call('bypass_onboarding',{mode:'combined',repository:other,url:'https://different.example.com',environment:'staging'});
  const connected=await c.call('bypass_connect_repository',{repository:other,confirmed:true});assert.equal(read(other).targets.length,0);assert.equal(connected.onboarding.nextAction.arguments.url,'https://different.example.com');
});

test('app-only CLI selection survives a fresh invocation without cd or repeating --project',async t=>{
  const options=isolated(t),cwd=temp(),env={...options.env,BYPASS_PLUGIN_STATE_DIR:options.stateDir};
  const call=async(...args)=>{const r=await execFile(process.execPath,[CLI,...args,'--json'],{cwd,env});assert.equal(r.code,0,r.stdout+r.stderr);return JSON.parse(r.stdout);};
  const connected=await call('app','connect','https://resume.example.com','--environment','staging');
  const status=await call('status');assert.equal(status.root,connected.root);assert.equal(status.review.mode,'live');assert.equal(status.ready.repository,false);assert.equal(status.ready.source,false);
  assert.match(reviewSummary(status.review),/Source review: not selected/);
  const explicit=source();await execute('init',[explicit]);assert.equal((await call('status','--project',explicit)).root,explicit);
  assert.equal(fs.existsSync(path.join(cwd,'.bypass')),false);
});

test('a repository switch without an app association never inherits an unrelated deployment grant',async t=>{
  isolated(t);const a=source(),b=source();await execute('init',[a]);await execute('init',[b]);
  await execute('target add',['local'],{project:a,url:'http://127.0.0.1:4567',environment:'local'});await execute('target verify',['local'],{project:a,method:'local'});await execute('target authorize',['local'],{project:a,accept:true,paths:'/api'});
  await carryAppSetup(a,b,{mode:'combined'});assert.equal(read(b).targets.length,0);
  await carryAppSetup(a,b,{mode:'code',url:'http://127.0.0.1:4567'});assert.equal(read(b).targets.length,0);
});
