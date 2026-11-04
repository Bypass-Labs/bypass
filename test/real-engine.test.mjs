import { providerFailure, apiProfile } from '../src/providers.mjs';
import { addTestModel } from './helpers.mjs';
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { runAgent } from '../agents/worker.mjs';
import { containerArgs } from '../src/agent-runtime.mjs';
import { parseModelJSON, modelResponseSchema } from '../src/inference.mjs';
import { sourceReader, groundCandidates, executeSourceReview } from '../src/real-engine.mjs';
import { executeStandaloneAudit } from '../src/audit-engine.mjs';
import { createRun, verifyFinding, executeRun } from '../src/engine.mjs';
import { execute } from '../src/service.mjs';
import { startPOC, stopPOC } from '../src/poc.mjs';
import { read, change } from '../src/store.mjs';
import { specFor, runChecks, exportChecks } from '../src/checks.mjs';
import { replay, jsonField } from '../src/portable-check.mjs';
import { inventory } from '../src/repository.mjs';
import { execFile } from '../src/util.mjs';
import { temp } from './helpers.mjs';

// Inference is deliberately scripted here; separate live validation uses real Muse + Docker.
function controlledRuntime(){
  const calls=[];
  return {calls,
    prepareAgents:async()=>({image:'test-image'}),
    runContainer:async(role,task,rpc)=>({result:await runAgent(role,task,rpc),container:{role,image:'test-image'}}),
    infer:async(profile,messages)=>{
      calls.push({profile:structuredClone(profile),messages});
      const system=messages[0].content;
      if(system.startsWith('Plan a bounded'))return {focus:'Inspect authentication and ownership.'};
      if(system.startsWith('Review the actual')){
        if(messages.length===2)return {action:'read_files',paths:['policy.mjs']};
        return {action:'finish',candidates:[{title:'Account ownership is not checked',category:'cross-account-access',file:'policy.mjs',line:2,quote:'  return Boolean(account);',resourcePath:'/api/invoices/inv-101',hypothesis:'Any authenticated account can read the invoice.',recommendation:'Compare account to invoice.ownerId.'}]};
      }
      if(messages.length===2)return {action:'probe',bindingIndex:0};
      return {action:'finish',summary:'Use observed controls.'};
    }
  };
}

test('combined engine starts broad live work in parallel, hands off source leads and reconciles one parent result',async()=>{
  const root=path.join(temp(),'app');await startPOC({dir:root});await addTestModel(root);
  try{
    const source=controlledRuntime();let liveStarted=false,releaseSource;
    const sourceGate=new Promise(resolve=>{releaseSource=resolve;}),sourceInfer=source.infer;
    source.infer=async(profile,messages,options)=>{
      if(messages[0].content.startsWith('Plan a bounded'))await sourceGate;
      return sourceInfer(profile,messages,options);
    };
    const run=await createRun(root,'scan',{mode:'combined'});
    const result=await executeStandaloneAudit(root,run.id,{mode:'combined'},{runtime:{source,
      runBlackbox:async options=>{
        liveStarted=true;
        const scope=JSON.parse(fs.readFileSync(options.scopeFile,'utf8'));
        assert.deepEqual(scope.include,read(root).targets[0].authorization.paths);
        assert.deepEqual(scope.methods,read(root).targets[0].authorization.methods);
        assert.equal(scope.identities.auth,'bearer');
        assert.equal(scope.identities.identityPath,'/api/me');
        releaseSource();
        const context=await options.sourceContext;
        assert.equal(context.securityLeads.length,1);
        const lead=context.securityLeads[0];
        return {kind:'blackbox-audit',run:'bx-20261103-a1b2c3d4',runDir:path.join(root,'.bypass/runs/bx-20261103-a1b2c3d4'),
          projectRoot:root,origin:read(root).targets[0].url,exitCode:1,stats:{modelCalls:2,
            finishedAt:new Date().toISOString(),requests:12},coverage:{tested:1},
          findings:[{id:'live-proof',verdict:'confirmed',kind:'missing-auth',severity:'high',
            proof:path.join(root,'.bypass/runs/bx-20261103-a1b2c3d4/poc/proof-1/poc.mjs'),
            title:lead.title,pattern:lead.path,evidence:['ev-1'],confirmation:['ev-2'],
            sourceFinding:{id:lead.id,source:lead.source,hypothesis:lead.hypothesis},
            assessment:{remediation:lead.remediation}}],sourceFindings:[{id:lead.id,
              status:'confirmed live',liveReason:'Fresh owner and anonymous controls reproduced it.'}]};
      }} ,report:async()=>{}});
    assert.equal(liveStarted,true);assert.equal(result.simulation,false);
    assert.equal(result.confirmed.length,1);assert.equal(result.blackbox.run,'bx-20261103-a1b2c3d4');
    assert.deepEqual(result.source.containers.map(container=>container.role),['white-box']);
    assert.equal(read(root).findings.find(item=>item.id===result.confirmed[0]).status,'confirmed');
    assert.equal(read(root).findings.find(item=>item.id===result.confirmed[0]).verification.proofId,'proof-1');
    assert.equal(read(root).findings.filter(item=>item.lastRunId===run.id).length,1,
      'the live proof enriches the source finding instead of duplicating it');
  }finally{await stopPOC(root);}
});
test('combined review continues source analysis when accounts and resource probes are not configured',async()=>{
  const root=temp();fs.writeFileSync(path.join(root,'app.mjs'),'export const publicRoute = true;\n');
  await execute('init',[root]);await execute('engine use',['docker'],{project:root});await addTestModel(root);
  await execute('target add',['app'],{project:root,url:'http://127.0.0.1:45679',environment:'local'});
  await execute('target verify',['app'],{project:root,method:'local'});
  await execute('target authorize',['app'],{project:root,accept:true,paths:'/',methods:'GET'});
  assert.equal(Object.hasOwn(read(root).targets[0],'probes'),false);
  const source={
    prepareAgents:async()=>({image:'test-image'}),
    infer:async()=>({focus:'Review the available source without configured account probes.'}),
    runContainer:async role=>({result:{knowledge:[],candidates:[]},container:{role,image:'test-image'}})
  };
  const run=await createRun(root,'scan',{mode:'combined'});
  const result=await executeStandaloneAudit(root,run.id,{mode:'combined'},{runtime:{source,
    runBlackbox:async options=>{assert.equal(await options.sourceContext!==null,true);return {
      kind:'blackbox-audit',run:'bx-20261103-b1b2c3d4',runDir:path.join(root,'.bypass/runs/bx-20261103-b1b2c3d4'),
      projectRoot:root,origin:read(root).targets[0].url,exitCode:3,stats:{modelCalls:0},
      coverage:{},findings:[],sourceFindings:[]};}},report:async()=>{}});
  assert.deepEqual(result.source.containers.map(container=>container.role),['white-box']);
  assert.equal(result.modelCalls,1);assert.equal(result.executionFailures.length,0);
});
test('source citations cannot invent files or lines, and source reads cannot follow escaping symlinks',()=>{
  const root=temp(),outside=temp();fs.writeFileSync(path.join(root,'app.mjs'),'const actual = true;\n');
  fs.writeFileSync(path.join(outside,'secret.mjs'),'secret');fs.symlinkSync(outside,path.join(root,'linked'));
  const inv={files:['app.mjs','linked/secret.mjs'],fingerprint:'source-hash'},reader=sourceReader(root,inv);
  assert.throws(()=>reader.read(['.env']),/outside eligible/);
  assert.throws(()=>reader.read(['linked/secret.mjs']),/escapes/);
  reader.read(['app.mjs']);
  const candidate={category:'cross-account-access',file:'app.mjs',line:1,quote:'made up',title:'A',hypothesis:'B',recommendation:'C'};
  assert.throws(()=>groundCandidates([candidate],reader,inv),/did not match/);
  candidate.quote='const actual = true;';candidate.category='command-injection';
  assert.equal(groundCandidates([candidate],reader,inv)[0].category,'command-injection');
  assert.equal(modelResponseSchema('white-box').properties.candidates.items.properties.category.enum,undefined);
});

test('citation diagnostics distinguish unread evidence, invalid quotes, and formatting without source disclosure',()=>{
  const reader={readFiles:new Map([['app.js',new Map([[1,'  sensitiveSource();']])]])};
  const base={category:'authorization',file:'app.js',line:1,quote:'sensitiveSource();',title:'A',hypothesis:'B',recommendation:'C'};
  for(const [fields,issue] of [[{file:'unread.js'},'file_not_read'],[{line:2},'line_not_read'],[{line:0},'line_not_read'],[{quote:null},'invalid_quote'],[{quote:'1: sensitiveSource();'},'quote_mismatch'],[{quote:'sensitiveSource();\nmoreSource();'},'quote_mismatch']]){
    assert.throws(()=>groundCandidates([{...base,...fields}],reader,{fingerprint:'test'}),error=>{
      assert.equal(error.details.citation.issue,issue);
      if(issue==='quote_mismatch'||issue==='invalid_quote'){
        assert.equal(error.details.citation.includesLineNumber,!!fields.quote?.startsWith('1:'));
        assert.equal(error.details.citation.multiline,!!fields.quote?.includes('\n'));
      }
      assert.doesNotMatch(error.message+JSON.stringify(error.details),/sensitiveSource|moreSource/);
      return true;
    });
  }
  assert.equal(groundCandidates([base],reader,{fingerprint:'test'})[0].sourceEvidence.quote,base.quote);
});

test('large application files are paged and only delivered lines can support a hypothesis',async()=>{
  const root=temp(),lines=Array.from({length:900},(_,i)=>`// line ${i+1}: ${'context '.repeat(15)}`);
  lines[650]="app.get('/api/run/:id', async () => getRun(id));";
  fs.writeFileSync(path.join(root,'server.js'),lines.join('\n'));
  const inv=await inventory(root),reader=sourceReader(root,inv);
  assert.deepEqual(inv.routeLocations.find(r=>r.path==='/api/run/:id'),{path:'/api/run/:id',method:'GET',file:'server.js',line:651});
  const first=reader.read(['server.js'])[0];
  assert.equal(first.endLine,200);assert.equal(first.nextStartLine,201);assert.equal(first.totalLines,900);
  const candidate={category:'cross-account-access',file:'server.js',line:651,quote:lines[650],title:'Ownership hypothesis',hypothesis:'Inspect the route owner check',recommendation:'Enforce ownership'};
  assert.throws(()=>groundCandidates([candidate],reader,inv),/actually read/);
  const page=reader.read([{path:'server.js',startLine:640,endLine:670}])[0];
  assert.match(page.source,/651: app.get/);assert.equal(page.startLine,640);
  assert.equal(groundCandidates([candidate],reader,inv)[0].sourceEvidence.line,651);
  for(const range of [{startLine:0,endLine:4},{startLine:10,endLine:1},{startLine:901,endLine:1000}])assert.throws(()=>reader.read([{path:'server.js',...range}]),/valid inclusive range/);
  assert.equal(reader.read([{path:'server.js',startLine:201,endLine:900}])[0].endLine,600);
  assert.equal(reader.read([{path:'server.js',startLine:800,endLine:999}])[0].endLine,900);
  lines[650]='// changed';fs.writeFileSync(path.join(root,'server.js'),lines.join('\n'));
  assert.throws(()=>reader.read([{path:'server.js',startLine:651,endLine:651}]),/changed during review/);
});

test('rejected read batches cannot ground unseen lines and a worker can repair an invalid read',async()=>{
  const root=temp();fs.writeFileSync(path.join(root,'app.js'),'const line = true;\n');
  const inv={files:['app.js'],fingerprint:'hash'},reader=sourceReader(root,inv);
  assert.throws(()=>reader.read(['app.js','not-eligible.js']),/outside eligible/);assert.equal(reader.readFiles.size,0);
  let calls=0;const result=await runAgent('white-box',{},async(method,params)=>{
    if(method==='read_files')return reader.read(params.paths);
    calls++;
    if(calls===1)return {action:'read_files',paths:['wrong.js']};
    if(calls===2){assert.match(params.messages.at(-1).content,/outside eligible/);return {action:'read_files',paths:[{path:'app.js',startLine:1,endLine:200}]};}
    assert.match(params.messages.at(-1).content,/const line = true/);return {action:'finish',candidates:[]};
  });assert.deepEqual(result.candidates,[]);assert.equal(calls,3);
});

test('JSON selectors traverse own data fields without expressions or inherited properties',()=>{
  const data=JSON.parse('{"run":{"id":7},"owner_uid":"alice","a/b":{"~key":"value"},"items":[{"id":9}]}');
  assert.equal(jsonField(data,'run.id'),7);assert.equal(jsonField(data,'/run/id'),7);
  assert.equal(jsonField(data,'owner_uid'),'alice');assert.equal(jsonField(data,'/a~1b/~0key'),'value');
  assert.equal(jsonField(data,'items.0.id'),9);
  for(const selector of ['run.constructor','run.id.toString','run[id]','/a~2b','run.*',''])assert.equal(jsonField(data,selector),undefined);
  assert.equal(jsonField(Object.create({id:'inherited'}),'id'),undefined);
});

test('nested resource and identity controls survive exported replay and detect real HTTP regression',async()=>{
  const http=await import('node:http');let vulnerable=true;
  const server=http.createServer((req,res)=>{
    const token=req.headers.authorization;res.setHeader('Content-Type','application/json');
    if(!['Bearer owner','Bearer outsider'].includes(token)){res.writeHead(401);res.end('{}');return;}
    if(req.url==='/api/profile'){res.end(JSON.stringify({account:{uid:token==='Bearer owner'?'alice':'bob'}}));return;}
    if(token==='Bearer outsider'&&!vulnerable){res.writeHead(403);res.end('{}');return;}
    res.end(JSON.stringify({run:{id:'run-1'}}));
  });
  await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve));
  try{
    const origin=`http://127.0.0.1:${server.address().port}`,expires=new Date(Date.now()+60000).toISOString();
    const spec={origin,environment:'local',authorization:{origin,paths:['/api'],methods:['GET'],maxRequestsPerSecond:100,expiresAt:expires},ownershipExpiresAt:expires,resourcePath:'/api/run/run-1',resourceId:'run-1',idField:'run.id',identityField:'account.uid',requireIdentityControl:true,owner:{type:'bearer',secretEnv:'OWNER',checkPath:'/api/profile'},outsider:{type:'bearer',secretEnv:'OUTSIDER',checkPath:'/api/profile'}};
    const env={OWNER:'owner',OUTSIDER:'outsider'};
    const failed=await replay(spec,{env});assert.equal(failed.status,'failed');assert.equal(failed.requests,5);
    vulnerable=false;assert.equal((await replay(spec,{env})).status,'passed');
    const root=temp();fs.copyFileSync(new URL('../src/portable-check.mjs',import.meta.url),path.join(root,'runner.mjs'));
    fs.writeFileSync(path.join(root,'test.mjs'),`import {replay} from './runner.mjs'; const r=await replay(${JSON.stringify(spec)}); console.log(JSON.stringify(r)); process.exitCode=r.status==='passed'?0:1;`);
    let exported=await execFile(process.execPath,[path.join(root,'test.mjs')],{env});assert.equal(exported.code,0,exported.stdout+exported.stderr);
    vulnerable=true;exported=await execFile(process.execPath,[path.join(root,'test.mjs')],{env});assert.equal(exported.code,1);assert.match(exported.stdout,/Another account/);
    spec.idField='run';assert.equal((await replay(spec,{env})).status,'blocked');
  }finally{await new Promise(resolve=>server.close(resolve));}
});

test('model output is data: reject executable/non-JSON output and unsupported worker capabilities',async()=>{
  assert.throws(()=>parseModelJSON('run shell rm -rf ...'),/JSON object/);
  assert.deepEqual(parseModelJSON('```json\n{"action":"finish"}\n```'),{action:'finish'});
  await assert.rejects(runAgent('white-box',{},async()=>({action:'shell',command:'anything'})),/Unsupported/);
  await assert.rejects(runAgent('black-box',{},async()=>{}),/Unknown agent role/);
  const args=containerArgs('named','sha256:abc','white-box');
  for(const flag of ['--network','none','--read-only','--cap-drop','ALL','no-new-privileges','--memory','128m'])assert.ok(args.includes(flag));
  assert.ok(!args.includes('-v')&&!args.includes('--privileged'));
});

test('real source-only planning is available without DNS; HTTP proof needs approved resource and model',async()=>{
  const root=temp();await execute('init',[root],{});await execute('engine use',['docker'],{project:root});
  let plan=(await execute('scan',[],{project:root,mode:'code',plan:true})).plan;
  assert.match(plan.blockers.join(' '),/API-key profile/);
  await execute('model add',['local'],{project:root,provider:'custom','secret-env':'BYPASS_UNIT_API_KEY',stream:false,'base-url':'http://127.0.0.1:1234',model:'test-model'});
  plan=(await execute('scan',[],{project:root,mode:'code',plan:true})).plan;
  assert.deepEqual(plan.blockers,[]);assert.equal(plan.simulation,false);assert.equal(plan.blackBox.status,'not_run');
  const combined=(await execute('scan',[],{project:root,mode:'combined',plan:true})).plan;
  assert.ok(combined.blockers.length>=1);
});

test('Docker worker protocol completes and cancellation removes the actual container',{skip:process.env.BYPASS_DOCKER_TESTS!=='1'},async()=>{
  const {prepareAgents,runContainer}=await import('../src/agent-runtime.mjs');
  const setup=await prepareAgents();
  let attempts=0;const repaired=await runContainer('white-box',{},async(method,params)=>{
    if(method==='read_files')throw new Error('Invalid source range');
    if(++attempts===1)return {action:'read_files',paths:['app.js']};
    assert.match(params.messages.at(-1).content,/Invalid source range/);return {action:'finish',candidates:[]};
  },setup);
  assert.deepEqual(repaired.result.candidates,[]);assert.equal(attempts,2);
  let name;const controller=new AbortController();
  const running=runContainer('white-box',{files:[]},async(_method,_params,signal)=>new Promise((resolve,reject)=>{signal.addEventListener('abort',()=>reject(new Error('Cancelled')),{once:true});}),{...setup,timeoutMs:0,signal:controller.signal,onProgress:p=>{name=p.message.match(/bypass-white-box-[a-f0-9]+/)[0];}});
  setTimeout(()=>controller.abort(),600);
  await assert.rejects(running);
  const listed=await execFile('docker',['ps','-a','--filter',`name=${name}`,'--format','{{.Names}}']);assert.equal(listed.stdout,'');
});

test('anonymous exposure is confirmed independently of a correctly denied outsider',async()=>{
  const http=await import('node:http');
  const server=http.createServer((req,res)=>{
    const token=req.headers.authorization;res.setHeader('Content-Type','application/json');
    if(req.url==='/api/me'){res.end(JSON.stringify({id:token==='Bearer owner'?'alice':'bob'}));return;}
    if(token==='Bearer outsider'){res.writeHead(403);res.end('{}');return;}
    res.end(JSON.stringify({id:'resource-1'}));
  });
  await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve));
  try{
    const origin=`http://127.0.0.1:${server.address().port}`,expires=new Date(Date.now()+60000).toISOString();
    const spec={origin,environment:'local',authorization:{origin,paths:['/api'],methods:['GET'],maxRequestsPerSecond:100,expiresAt:expires},ownershipExpiresAt:expires,resourcePath:'/api/item',resourceId:'resource-1',requireIdentityControl:true,owner:{type:'bearer',secretEnv:'OWNER',checkPath:'/api/me'},outsider:{type:'bearer',secretEnv:'OUTSIDER',checkPath:'/api/me'}};
    const result=await replay(spec,{env:{OWNER:'owner',OUTSIDER:'outsider'}});
    assert.equal(result.status,'failed');assert.match(result.reason,/Unauthenticated/);assert.deepEqual(result.controls.map(c=>c.status),[200,200,200,403,200]);
  }finally{await new Promise(resolve=>server.close(resolve));}
});
