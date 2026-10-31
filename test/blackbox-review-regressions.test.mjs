import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import http from 'node:http';
import dns from 'node:dns/promises';
import {EventEmitter} from 'node:events';
import {Readable} from 'node:stream';
import {temp} from './helpers.mjs';
import {mcpClient} from './mcp-client.mjs';
import {execute} from '../src/service.mjs';
import {hash} from '../src/util.mjs';
import {safeRequest} from '../src/network.mjs';
import {createLedger} from '../src/blackbox/ledger.mjs';
import {lookupAdvisories} from '../src/blackbox/advisories.mjs';
import {verifyRun, exportRun} from '../src/blackbox/poc.mjs';
import {check, validModelHttpSequence, modelExperimentReason, MAX_SEQUENCE_STEPS} from '../src/blackbox/poc-runtime.mjs';
import {runSessionChains} from '../src/blackbox/session-chain.mjs';
import {runAudit} from '../src/blackbox/index.mjs';

const temporary = t => {const root=temp();t.after(()=>fs.rmSync(root,{recursive:true,force:true}));return root;};

test('clean OSV empty-object responses are checked evidence, malformed objects remain errors', async t => {
  const summaries={files:[{url:'https://app.example.test/app.js',libraries:[{name:'react',version:'19.0.0'}]}]};
  for(const [body,errors] of [['{}',0],['{"vulns":[]}',0],['[]',1],['null',1],['{"vulns":{}}',1]]){
    const ledger=createLedger(temporary(t));
    const result=await lookupAdvisories(summaries,{enabled:true,ledger,query:async()=>({status:200,body})});
    assert.equal(result.stats.errors,errors,body);
    assert.equal(result.stats.checked,1-errors,body);
    assert.equal(result.incomplete,Boolean(errors));
    assert.equal(result.records[0].status,errors?'error':'checked');
  }
});

test('4096-byte ranged exposure proof confirms, then clears after the fixture is secured', async t => {
  let exposed=true, requests=0;
  const server=http.createServer((req,res)=>{
    requests++;assert.equal(req.headers.range,'bytes=0-4095');
    if(!exposed){res.writeHead(403);return res.end();}
    res.writeHead(206,{'content-type':'text/plain','content-range':'bytes 0-4095/8192'});
    res.end('PRIVATE_CONFIG=synthetic-fixture-value\n');
  });
  await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve));
  t.after(()=>new Promise(resolve=>server.close(resolve)));
  const origin=`http://127.0.0.1:${server.address().port}`;
  const spec={kind:'exposure',origin,include:['/'],never:[],rps:100,
    request:{method:'GET',url:origin+'/.env',as:'anonymous'},signature:'environment key-value lines',rangeHeader:'bytes=0-4095'};
  assert.equal((await check(spec,{})).verdict,'confirmed');
  exposed=false;
  assert.equal((await check(spec,{})).verdict,'not_reproduced');
  assert.equal(requests,4);
});

const sequence = () => ({kind:'model-http-sequence',origin:'http://127.0.0.1:4329',include:['/'],never:[],rps:100,
  identities:{},auth:'bearer',targetEnvironment:'local',as:'anonymous',prelude:[],observe:[],
  subject:{method:'GET',path:'/api/read',placement:'query',key:'term',fixedFields:[],bodyTemplate:'',headers:[]},
  controlValue:'plain',firstValue:'hex:'+Buffer.from('bx123456789abc').toString('hex'),
  secondValue:'hex:'+Buffer.from('bxabcdef123456').toString('hex'),marker:'bx123456789abc',secondMarker:'bxabcdef123456',
  assertion:{step:'subject',index:0,location:'body',name:''}});

test('model HTTP sequences reject oversized step lists before issuing requests',async()=>{
  const spec=sequence();assert.equal(validModelHttpSequence(spec),true);
  for(const key of ['prelude','observe']){
    const bounded={...spec,[key]:Array.from({length:MAX_SEQUENCE_STEPS},()=>({method:'GET',path:'/api/read',headers:[]}))};
    assert.equal(validModelHttpSequence(bounded),true);
    const oversized={...bounded,[key]:[...bounded[key],...bounded[key]]};
    assert.equal(validModelHttpSequence(oversized),false);
    assert.equal((await check(oversized,{})).verdict,'inconclusive');
  }
});

test('read experiments preserve valid HTTP headers',()=>{
  const spec=sequence();const values={...spec,parameter:'term',headers:[]};
  assert.equal(modelExperimentReason(values),null);
  assert.equal(modelExperimentReason({...values,headers:[{name:'Content-Type',value:'application/json'}]}),null);
  assert.equal(modelExperimentReason({...values,headers:[{name:'Accept',value:'application/json'}]}),null);
});

function sealedRun(root,scripts){
  const run='bx-20261030-abcdef12',dir=path.join(root,'.bypass/runs',run),ledger=createLedger(dir);
  fs.mkdirSync(path.join(dir,'poc'),{recursive:true});fs.writeFileSync(path.join(dir,'run.json'),'{}');
  const runtime=path.join(dir,'poc/runtime.mjs');fs.writeFileSync(runtime,'// test sealed runtime\n');
  scripts.forEach((body,index)=>{
    const proofDir=path.join(dir,'poc',`f-00${index+1}`);fs.mkdirSync(proofDir);
    const spec=path.join(proofDir,'spec.json'),script=path.join(proofDir,'poc.mjs');
    fs.writeFileSync(spec,JSON.stringify({kind:'exposure'}));fs.writeFileSync(script,body);
    ledger.append({step:'poc',proof:{path:script,specHash:hash(fs.readFileSync(spec)),
      scriptHash:hash(fs.readFileSync(script)),runtimeHash:hash(fs.readFileSync(runtime))}});
  });return {run,dir};
}

test('oversized proof output is inconclusive and later proofs still run with a saved retest',async t=>{
  const root=temporary(t);const {run,dir}=sealedRun(root,[
    "process.stdout.write('x'.repeat(2100000));setTimeout(()=>{},1000);",
    "console.log(JSON.stringify({verdict:'not_reproduced'}));"]);
  const result=await verifyRun(root,run,{env:{}});
  assert.equal(result.exitCode,3);assert.deepEqual(result.proofs.map(p=>p.verdict),['inconclusive','not_reproduced']);
  assert.equal(JSON.parse(fs.readFileSync(path.join(dir,'retest.json'))).proofs.length,2);
});

test('sealed proof replay accepts equivalent symlink roots and still rejects modified artifacts',async t=>{
  const base=temporary(t),root=path.join(base,'application'),alias=path.join(base,'alias');fs.mkdirSync(root);
  fs.symlinkSync(root,alias,'dir');
  const {run,dir}=sealedRun(alias,["console.log(JSON.stringify({verdict:'not_reproduced'}));"]);
  assert.equal((await verifyRun(fs.realpathSync(root),run,{env:{}})).exitCode,0);
  const exported=exportRun(root,run,{out:'regression'});assert.ok(exported.files.every(file=>file.startsWith(root+path.sep)));
  fs.appendFileSync(path.join(dir,'poc/f-001/poc.mjs'),'// modified');
  await assert.rejects(verifyRun(root,run),/sealed ledger artifact/);
});

test('short exposed account tokens do not abort remaining session-chain checks',async()=>{
  const token='short',scope={identities:{owner:{env:'OWNER'}}};let replayed=0;
  const requester=async request=>{
    if(request.derivedBearer===token){replayed++;throw Error('unsupported token must not be replayed');}
    const source=request.url==='/public';
    return {status:source||request.identity==='owner'?200:401,type:'application/json',cached:false,
      hash:'owner-data',headers:{},rawBody:source?JSON.stringify({token}):'{}'};
  };
  const lead={path:'/public',sourcePath:'/public',privatePath:'/private',tokenPointer:'/token',family:'session'};
  const result=await runSessionChains([lead,lead],scope,{requester,env:{OWNER:token}});
  assert.equal(replayed,0);assert.equal(result.findings.length,0);assert.equal(result.results.length,2);
  assert.ok(result.results.every(item=>item.verdict==='inconclusive'&&/replay format/.test(item.reason)));
});

test('explicit anonymous HTTP preserves DNS pinning and never allows private or credentialed requests',async t=>{
  let calls=0;
  t.mock.method(dns,'lookup',async()=>[{address:'8.8.8.8',family:4}]);
  t.mock.method(http,'request',(_url,options,callback)=>{
    calls++;assert.equal(options.method,'GET');
    options.lookup('audit.example.test',{},(error,address)=>{assert.equal(error,null);assert.equal(address,'8.8.8.8');});
    const req=new EventEmitter();req.setTimeout=()=>{};req.end=()=>{
      const response=Readable.from([Buffer.from('ok')]);response.statusCode=200;response.headers={};callback(response);
    };return req;
  });
  await assert.rejects(safeRequest('http://audit.example.test/'),/require HTTPS/);
  assert.equal((await safeRequest('http://audit.example.test/',{allowRemoteHttp:true})).status,200);
  for(const options of [{headers:{Authorization:'Bearer synthetic'}},{headers:{Cookie:'session=synthetic'}},{method:'POST'}])
    await assert.rejects(safeRequest('http://audit.example.test/',{allowRemoteHttp:true,...options}),/require HTTPS/);
  t.mock.method(dns,'lookup',async()=>[{address:'10.0.0.1',family:4}]);
  await assert.rejects(safeRequest('http://audit.example.test/',{allowRemoteHttp:true}),/private network/);
  assert.equal(calls,1);
});

for(const packaged of [false,true])test(`${packaged?'packaged':'source'} blackbox refuses symlink output before starting`,async t=>{
  const root=temporary(t),outside=temporary(t);fs.writeFileSync(path.join(root,'app.mjs'),'export const app=true;');
  await execute('init',[root]);fs.symlinkSync(outside,path.join(root,'escape'),'dir');
  const client=await mcpClient(root,{packaged,stateDir:temporary(t)});t.after(()=>client.child.kill());
  const result=await client.raw('bypass_blackbox_start',{url:'http://127.0.0.1:4329',out:'escape/evidence','accept-local':true});
  assert.equal(result.result.isError,true);assert.match(result.result.content[0].text,/symbolic link/);
  assert.deepEqual(fs.readdirSync(outside),[]);assert.equal(await client.close(),0);
});

test('relative audit output stays under selected project when process cwd differs',async t=>{
  const root=temporary(t);const result=await runAudit({url:'http://127.0.0.1:4329',root,out:'evidence',
    noModel:true,dryRun:true,overrides:{acceptLocal:true}});
  assert.equal(fs.realpathSync(result.runDir),path.join(fs.realpathSync(root),'evidence'));
});
