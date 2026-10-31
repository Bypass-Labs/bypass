import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawnSync } from 'node:child_process';
import { manifest, scannerCapabilities, protocolVersion, unavailable, resolveManifest } from '../src/scanner/contracts.mjs';
import { ScannerClient } from '../src/scanner/client.mjs';
import { scannerContainerArgs, scannerPackageFiles, scannerDirectory, scannerDoctor, prepareScanner, connectScanner, defaultResources } from '../src/scanner/runtime.mjs';
import { runAPIDriver } from '../src/scanner/api-driver.mjs';
import { inExecutionMode } from '../src/execution-mode.mjs';
import { validateJSON } from '../src/schema.mjs';
import { parse } from '../src/catalog.mjs';
import { execute } from '../src/service.mjs';
import { closeScannerSessions } from '../src/scanner/service.mjs';
import { temp, addTestModel, cli } from './helpers.mjs';
import { mcpClient } from './mcp-client.mjs';

const python = process.env.BYPASS_TEST_PYTHON || 'python3';
const pythonAvailable = spawnSync(python, ['--version']).status === 0;
const pythonEnv = { ...process.env, PYTHONPATH: path.join(scannerDirectory, 'src'), PYTHONDONTWRITEBYTECODE: '1' };

function fakeScanner(t, mode, settings = {}) {
  const directory = temp(), script = path.join(directory, 'scanner.mjs');
  fs.writeFileSync(script, `
import readline from 'node:readline';
const caps=${JSON.stringify(scannerCapabilities())};
const mode=${JSON.stringify(mode)};
readline.createInterface({input:process.stdin}).on('line',line=>{
 const m=JSON.parse(line); if(m.id===undefined)return;
 let result=m.method==='initialize'?{protocolVersion:'2025-11-25',capabilities:{tools:{}},serverInfo:{name:'fixture'}}:{content:[{type:'text',text:JSON.stringify(caps)}],isError:false};
 if(mode==='handshake')result.protocolVersion='unknown';
 if(m.method!=='initialize'){
   if(mode==='hang')return;
   if(mode==='malformed'){process.stdout.write('not json\\n');return;}
   if(mode==='huge'){process.stdout.write('x'.repeat(20000)+'\\n');return;}
   if(mode==='bad-result')result={content:[],isError:false};
   if(mode==='wrong-version')result.content[0].text=JSON.stringify({...caps,protocolVersion:'unknown'});
   if(mode==='invalid-error'){process.stdout.write(JSON.stringify({jsonrpc:'2.0',id:m.id,error:{code:'bad'}})+'\\n');return;}
   if(mode==='rpc-error'){process.stdout.write(JSON.stringify({jsonrpc:'2.0',id:m.id,error:{code:-32602,message:'invalid'}})+'\\n');return;}
   if(mode==='exit'){process.exit(1);return;}
 }
 process.stdout.write(JSON.stringify({jsonrpc:'2.0',id:mode==='wrong-id'&&m.method!=='initialize'?999:m.id,result})+'\\n');
});`);
  const client = new ScannerClient(process.execPath, [script], { timeoutMs: 2000, ...settings });
  t.after(async () => { await client.close(); fs.rmSync(directory, { recursive: true, force: true }); });
  return client;
}

test('scanner schemas and command family expose the agreed contract', () => {
  assert.equal(protocolVersion, 'bypass-scanner.v3');
  assert.deepEqual(defaultResources,manifest.resourceDefaults);
  assert.ok(defaultResources.timeoutSeconds>0);
  for(const name of ['capabilities','config','response','evaluation','evidence','run','signal','task'])assert.ok(manifest.schemas[name]);
  validateJSON(manifest.schemas.capabilities, scannerCapabilities());
  for (const name of Object.keys(manifest.operations)) validateJSON(manifest.schemas.error, unavailable(name));
  assert.deepEqual(manifest.schemas.evaluation.properties.outcome.enum, ['confirmed', 'refuted', 'needs_review']);
  assert.throws(() => validateJSON(manifest.operations.status.inputSchema, { run: '' }));
  for (const words of [['discover','--plan'], ['discover','--sarif','input.sarif','--config','scanner.json'], ['discover','status','r'], ['discover','resume','r'], ['discover','cancel','r'], ['discover','report','r','--format','md'], ['scanner','doctor'], ['scanner','prepare']]) assert.ok(parse(words).key);
  assert.throws(() => parse(['discover','status']));
  assert.throws(() => parse(['discover','--model','secret']));
  const options=parse(['discover','--include-tests','--include-examples','--include-generated']).options;
  assert.equal(options['include-tests'],true);assert.equal(options['include-examples'],true);assert.equal(options['include-generated'],true);
  for(const key of ['includeTests','includeExamples','includeGenerated'])assert.equal(manifest.schemas.config.properties[key].type,'boolean');
});

test('scanner contract expands shared definitions into self-contained wire schemas',()=>{
  const raw=JSON.parse(fs.readFileSync(path.join(scannerDirectory,'protocol/v3.json')));
  assert.deepEqual(raw.operations.start.inputSchema.properties.config,{$ref:'#/schemas/config'});
  assert.deepEqual(manifest.operations.start.inputSchema.properties.config,manifest.schemas.config);
  assert.deepEqual(manifest.schemas.response.properties.run,manifest.schemas.run);
  assert.deepEqual(manifest.schemas.error,manifest.schemas.response);
  assert.deepEqual(manifest.schemas.signal.properties.evidence.items,manifest.schemas.evidence);
  assert.equal(JSON.stringify(manifest).includes('"$ref"'),false);
  for(const schema of Object.values(manifest.schemas.config.properties.builds.properties))assert.deepEqual(schema,manifest.schemas.build);
});

test('scanner contract references cannot load external data or form cycles',()=>{
  for(const value of [{$ref:'https://example.invalid/schema'},{$ref:'file:///etc/hosts'},{$ref:'#/missing'},
    {a:{$ref:'#/a'}}, {a:{$ref:'#/b'},b:{$ref:'#/a'}}, {a:{type:'string'},b:{$ref:'#/a',description:'sibling'}},
    {a:[],b:{$ref:'#/a'}}, {a:'text',b:{$ref:'#/a'}}])assert.throws(()=>resolveManifest(value));
  assert.deepEqual(resolveManifest({'a/b':{type:'string'},schema:{$ref:'#/a~1b'}}).schema,{type:'string'});
});

test('Python MCP and Node read identical capabilities and operation schemas', { skip: !pythonAvailable }, async t => {
  const client = new ScannerClient(python, ['-m', 'bypass_scanner'], { env: pythonEnv });
  t.after(() => client.close());
  assert.deepEqual(await client.initialize(), scannerCapabilities());
  const listed = await client.request('tools/list');
  assert.equal(listed.tools.length, Object.keys(manifest.operations).length);
  for (const tool of listed.tools) assert.deepEqual(tool.inputSchema, manifest.operations[tool.name.slice(8)].inputSchema);
  for (const [operation, args] of [['next_task',{run:'r'}], ['evidence',{run:'r',task:'t',operation:'read'}], ['submit',{run:'r',task:'t',sourceRevision:'s',result:{}}]]) {
    assert.equal((await client.call(operation,args)).code,'scanner_error');
  }
  const error=await client.call('status',{run:'r'});
  assert.equal(error.code,'scanner_error');
  assert.equal(error.modelCalls,0);
  await client.close();
  assert.notEqual(client.child.exitCode, undefined);
});

test('scanner client bounds malformed responses and cleans up processes', async t => {
  for (const mode of ['handshake','malformed','huge','bad-result','wrong-version','wrong-id','invalid-error','rpc-error','exit']) {
    await t.test(mode, async t => {
      let cleaned = false;
      const client = fakeScanner(t, mode, { maxBytes: 10000, onClose: () => { cleaned = true; } });
      await assert.rejects(client.initialize());
      await client.close();
      assert.equal(cleaned, true);
      assert.ok(client.child.exitCode !== null || client.child.signalCode !== null);
    });
  }
});

test('scanner client enforces timeouts and cancellation and closes pending work', async t => {
  const timed = fakeScanner(t, 'hang', { timeoutMs: 100 });
  await assert.rejects(timed.initialize(), /timed out/);
  await timed.close();
  const client = fakeScanner(t, 'hang');
  const controller = new AbortController();
  const initialized = client.initialize({ signal: controller.signal });
  controller.abort();
  await assert.rejects(initialized, error => error.code === 130);
  await client.close();
  assert.equal(client.pending.size, 0);
});

test('default containers have no mounts/network and package only allowlisted files', async () => {
  const args = scannerContainerArgs('fixture', 'sha256:' + 'a'.repeat(64));
  assert.equal(args[args.indexOf('--network') + 1], 'none');
  for (const flag of ['--read-only','--cap-drop','--security-opt','--memory','--pids-limit']) assert.ok(args.includes(flag));
  for (const flag of ['--mount','--volume','--privileged']) assert.equal(args.includes(flag), false);
  const mounted = scannerContainerArgs('fixture','sha256:'+'a'.repeat(64),{root:'/project',output:'/project/.bypass/scanner'});
  assert.ok(mounted.includes('type=bind,src=/project,dst=/inputs/source,readonly'));
  assert.ok(mounted.includes('type=bind,src=/project/.bypass/scanner,dst=/outputs'));
  assert.equal(mounted[mounted.indexOf('--network')+1],'none');
  const helper = scannerContainerArgs('helper','sha256:'+'a'.repeat(64),{network:'bridge',worker:{run:'r',job:'j'}});
  assert.equal(helper[helper.indexOf('--network')+1],'bridge');
  assert.deepEqual(helper.slice(-4),['-m','bypass_scanner.worker','r','j']);
  const files = scannerPackageFiles();
  assert.ok(files.includes('protocol/v3.json'));
  assert.equal(files.includes('protocol/v1.json'),false);
  assert.ok(files.includes('src/bypass_scanner/transports/mcp.py'));
  assert.ok(files.every(file => !file.includes('__pycache__') && !file.startsWith('tests/')));
  const calls = [];
  let built = false;
  const runner = async (command, args) => {
    calls.push([command, ...args]);
    if (args[0] === 'version') return {code:0, stdout:'fixture'};
    if (args[0] === 'build') { built = true; return {code:0}; }
    return built ? {code:0, stdout:'sha256:'+'a'.repeat(64)} : {code:1, stdout:''};
  };
  assert.equal((await scannerDoctor({runner})).status, 'blocked');
  assert.equal(calls.some(call => call.includes('build')), false);
  assert.equal((await prepareScanner({runner})).status, 'ready');
  assert.equal(calls.filter(call => call.includes('build')).length, 1);
});

test('planning works before initialization and never creates project state', async () => {
  const root = temp();
  const before = fs.readdirSync(root);
  const result = await cli(root, 'discover', '--plan');
  assert.equal(result.code, 0);
  assert.deepEqual(result.data.plan.implementedStages,['discovery']);
  assert.equal(result.data.plan.executionMode, 'standalone-api');
  assert.equal(result.data.plan.modelCalls, 0);
  assert.equal(result.data.plan.scope.includeTests,false);
  assert.equal(result.data.plan.scope.includeExamples,false);
  assert.equal(result.data.plan.scope.includeGenerated,false);
  const opted=await cli(root,'discover','--plan','--include-tests');
  assert.equal(opted.data.plan.scope.includeTests,true);
  assert.equal(opted.data.plan.scope.includeGenerated,false);
  assert.deepEqual(fs.readdirSync(root), before);
  for (const command of [['discover','status','r'], ['discover','cancel','r'], ['discover','report','r','--format','json']]) {
    const response = await cli(root, ...command);
    assert.equal(response.code, 2);
  }
  assert.deepEqual(fs.readdirSync(root), before);
});

test('container creation failure still removes the known daemon-side container', async () => {
  const calls = [];
  const runner = async (command, args) => {
    calls.push(args);
    if (args[0] === 'version') return {code:0,stdout:'fixture'};
    if (args[0] === 'image') return {code:0,stdout:'sha256:'+'a'.repeat(64)};
    if (args[0] === 'create') throw new Error('creation timed out');
    return {code:0,stdout:''};
  };
  await assert.rejects(connectScanner({runner}), /creation timed out/);
  assert.equal(calls.at(-1)[0], 'rm');
  const created = calls.find(args => args[0] === 'create');
  assert.equal(calls.at(-1)[2], created[created.indexOf('--name') + 1]);
});

function deterministicClient(root, calls) {
  const id='scan_'+'a'.repeat(24);
  const run={id,status:'completed',stage:'discovery',phase:'done',sourceRevision:'abc',executionMode:'standalone-api',modelCalls:0,signalCount:1,sourceReads:1,languages:[],coverageComplete:false,evaluation:'not_run',message:'Unevaluated signals',createdAt:'now',updatedAt:'now'};
  return {
    close:async()=>{}, pumpBuild:async()=>{},
    call:async(operation,input)=>{
      calls.push({operation,input});
      const directory=path.join(root,'.bypass/scanner',id);fs.mkdirSync(directory,{recursive:true});
      fs.writeFileSync(path.join(directory,'manifest.json'),JSON.stringify({config:input.config||{}}));
      return {protocolVersion,operation,status:run.status,modelCalls:0,message:run.message,run};
    }
  };
}

test('CodeQL discovery bypasses API settings in both CLI and Muse execution modes', async t => {
  const root=temp();await execute('init',[root]);
  const filename=path.join(root,'.bypass/state.json');
  const state=JSON.parse(fs.readFileSync(filename));
  state.models=[{name:'broken',provider:'invalid',secretEnv:'THIS_MUST_NOT_BE_READ'}];state.activeModel='broken';
  fs.writeFileSync(filename,JSON.stringify(state));
  const before=fs.readFileSync(filename,'utf8'), calls=[];
  const OpenAI=(await import('openai')).default;
  t.mock.method(OpenAI.prototype,'makeRequest',()=>{throw new Error('Unexpected LLM request');});
  for(const mode of ['standalone-api','muse-host']){
    const result=await inExecutionMode(mode,()=>execute('discover',[],{project:root,detector:'codeql',rule:'js/sql-injection','exclude-rule':'js/other'},{scannerConnect:async()=>deterministicClient(root,calls)}));
    assert.equal(result.modelCalls,0);assert.equal(result.run.signalCount,1);assert.equal(result.run.evaluation,'not_run');
    assert.deepEqual(calls.at(-1).input.config.includeRules,['js/sql-injection']);
    assert.deepEqual(calls.at(-1).input.config.excludeRules,['js/other']);
    assert.equal(fs.readFileSync(filename,'utf8'),before);
    await closeScannerSessions();
  }
  await assert.rejects(inExecutionMode('muse-host',async()=>runAPIDriver(state)),error=>error.details.reason==='host_owned_inference');
});

test('analysis-scope flags override config identically in CLI and Muse modes',async()=>{
  const root=temp();await execute('init',[root]);
  fs.writeFileSync(path.join(root,'scanner.json'),JSON.stringify({includeTests:false,includeExamples:true,includeGenerated:true}));
  for(const mode of ['standalone-api','muse-host']){
    const calls=[];
    const plan=await inExecutionMode(mode,()=>execute('discover',[],{project:root,plan:true,config:'scanner.json','include-tests':true,'include-generated':false}));
    assert.equal(plan.plan.scope.includeTests,true);assert.equal(plan.plan.scope.includeExamples,true);assert.equal(plan.plan.scope.includeGenerated,false);
    await inExecutionMode(mode,()=>execute('discover',[],{project:root,config:'scanner.json','include-tests':true,'include-generated':false},
      {scannerConnect:async()=>deterministicClient(root,calls)}));
    assert.equal(calls[0].input.config.includeTests,true);
    assert.equal(calls[0].input.config.includeExamples,true);
    assert.equal(calls[0].input.config.includeGenerated,false);
    await closeScannerSessions();
  }
});

test('standalone driver validates its API boundary and requires a scanner run before requests', async t => {
  assert.throws(()=>runAPIDriver({models:[]}),error=>error.details.reason==='model_configuration_required');
  const root=temp();await execute('init',[root]);await addTestModel(root);
  const state=JSON.parse(fs.readFileSync(path.join(root,'.bypass/state.json')));
  const OpenAI=(await import('openai')).default;
  const request=t.mock.method(OpenAI.prototype,'makeRequest',()=>{throw new Error('Unexpected model request');});
  assert.throws(()=>runAPIDriver(state),/scanner client and run are required/);
  assert.equal(request.mock.callCount(),0);
  const result=await execute('discover',[],{project:root},{scannerConnect:async()=>deterministicClient(root,[])});
  assert.equal(result.modelCalls,0);assert.equal(request.mock.callCount(),0);
});

test('concurrent Muse operations share a container and SARIF status reuses its input mount', async () => {
  const root=temp();await execute('init',[root]);
  fs.writeFileSync(path.join(root,'input.sarif'),'{}');
  let connections=0, closed=0;
  const calls=[];
  const context={scannerConnect:async()=>{
    connections++;await new Promise(resolve=>setTimeout(resolve,20));
    return {...deterministicClient(root,calls),close:async()=>{closed++;}};
  }};
  try{
    await inExecutionMode('muse-host',()=>Promise.all([
      execute('discover',[],{project:root,sarif:'input.sarif'},context),
      execute('discover',[],{project:root,sarif:'input.sarif'},context),
    ]));
    assert.equal(connections,1);
    await inExecutionMode('muse-host',()=>execute('discover status',['scan_'+'a'.repeat(24)],{project:root},context));
    assert.equal(connections,1);
  }finally{await closeScannerSessions();}
  assert.equal(closed,1);
});

test('a status-only observer never launches another process owner\'s network build', async () => {
  const root=temp();await execute('init',[root]);
  const calls=[],client=deterministicClient(root,calls);
  const initial=await client.call('status',{});
  let pumped=0;
  const context={scannerConnect:async()=>({...client,pumpBuild:async()=>{pumped++;},call:async(operation,input)=>{
    const result=await client.call(operation,input);
    result.status=result.run.status='running';result.run.networkJob={id:'b'.repeat(32),language:'python'};
    return result;
  }})};
  try{
    await inExecutionMode('muse-host',()=>execute('discover status',[initial.run.id],{project:root},context));
    assert.equal(pumped,0);
  }finally{await closeScannerSessions();}
});

test('read and cancel operations reuse the active session despite older resource settings',async()=>{
  const root=temp();await execute('init',[root]);
  fs.writeFileSync(path.join(root,'scanner.json'),JSON.stringify({resources:{cpus:1,timeoutSeconds:60}}));
  const activeId='scan_'+'a'.repeat(24),oldId='scan_'+'b'.repeat(24),calls=[],stops=[];
  const old=path.join(root,'.bypass/scanner',oldId);fs.mkdirSync(old,{recursive:true});
  fs.writeFileSync(path.join(old,'manifest.json'),JSON.stringify({config:{resources:{cpus:2,timeoutSeconds:30}}}));
  let connections=0,closed=0;
  const context={scannerConnect:async()=>{
    connections++;
    const client=deterministicClient(root,calls);
    return {...client,close:async()=>{closed++;},stopBuilds:async run=>stops.push(run),call:async(op,input)=>{
      if(op==='start'){
        const result=await client.call(op,input);result.status=result.run.status='running';return result;
      }
      calls.push({operation:op,input});
      return {protocolVersion,operation:op,status:'completed',modelCalls:0,message:''};
    }};
  }};
  try{
    await inExecutionMode('muse-host',()=>execute('discover',[],{project:root,config:'scanner.json'},context));
    for(const operation of ['status','report','signals','artifact','cancel']){
      await inExecutionMode('muse-host',()=>execute('discover '+operation,[oldId],{project:root,...(operation==='artifact'?{path:'report.md'}:{})},context));
    }
    assert.equal(connections,1);assert.equal(closed,0);
    assert.deepEqual(stops,[oldId]);
    assert.notEqual(stops[0],activeId);
    // Starting/resuming with different limits still cannot replace the owner.
    await assert.rejects(inExecutionMode('muse-host',()=>execute('discover resume',[oldId],{project:root},context)),/different input\/resource/);
  }finally{await closeScannerSessions();}
});

test('capabilities inspect current image readiness without building or selecting source',async()=>{
  for(const available of [false,true]){
    const calls=[];
    const runner=async(_command,args)=>{
      calls.push(args);
      if(args[0]==='version')return {code:0,stdout:'fixture'};
      assert.equal(args[0],'image');
      return available?{code:0,stdout:'sha256:'+'a'.repeat(64)}:{code:1,stdout:''};
    };
    const result=await inExecutionMode('muse-host',()=>execute('discover capabilities',[],{}, {runner}));
    assert.equal(result.features.codeqlReady,available);
    assert.equal(result.independentModelRequests,0);
    assert.equal(calls.length,2);
  }
});

test('report continuation reads its artifact and finishes after the last page', async () => {
  const root=temp();await execute('init',[root]);
  const client=deterministicClient(root,[]), initial=await client.call('status',{});
  const context={scannerConnect:async()=>({...client,call:async(operation,input)=>{
    if(operation==='artifact')return {protocolVersion,operation,status:'ready',modelCalls:0,message:'',text:'report',nextOffset:input.offset? -1:12000};
    return {...await client.call(operation,input),artifacts:[{path:'report.md',bytes:12006}]};
  }})};
  const report=await execute('discover report',[initial.run.id],{project:root,format:'md'},context);
  assert.deepEqual(report.nextAction,{tool:'bypass_discover_artifact',arguments:{run:initial.run.id,path:'report.md',offset:0}});
  const first=await execute('discover artifact',[initial.run.id],{project:root,path:'report.md'},context);
  assert.equal(first.nextAction.arguments.offset,12000);
  const last=await execute('discover artifact',[initial.run.id],{project:root,path:'report.md',offset:12000},context);
  assert.equal(last.nextAction,undefined);
});

test('Muse can inspect capabilities without provider setup and rejects task calls for unknown runs',async t=>{
  const root=temp(),stateDir=temp(),client=await mcpClient(root,{stateDir});t.after(()=>client.close());
  fs.writeFileSync(path.join(root,'app.js'),'export const app = true;');
  const plan=await client.call('bypass_discover',{plan:true});
  assert.equal(plan.plan.executionMode,'muse-host');assert.equal(plan.plan.modelCalls,0);
  const withTests=await client.call('bypass_discover',{plan:true,'include-tests':true,'include-examples':true,'include-generated':true});
  assert.equal(withTests.plan.scope.includeTests,true);assert.equal(withTests.plan.scope.includeExamples,true);assert.equal(withTests.plan.scope.includeGenerated,true);
  const caps=await client.call('bypass_scanner_capabilities');assert.equal(caps.features.codeqlDiscovery,true);assert.equal(caps.features.evaluation,false);
  const unselected=await client.raw('bypass_discover',{});assert.equal(unselected.result.isError,true);
  await client.call('bypass_connect_repository',{repository:root,confirmed:true});
  const filename=path.join(root,'.bypass/state.json'), before=fs.readFileSync(filename,'utf8');
  for(const [tool,args] of [['bypass_discover_next_task',{run:'r'}],['bypass_discover_evidence',{run:'r',task:'t',operation:'read'}],['bypass_discover_submit',{run:'r',task:'t',sourceRevision:'s',result:{}}]]){
    const response=await client.raw(tool,args), result=JSON.parse(response.result.content[0].text);
    assert.equal(response.result.isError,true);assert.match(result.error,/Invalid scanner run ID/);
  }
  assert.equal(fs.readFileSync(filename,'utf8'),before);
});

test('packaged scanner includes only allowlisted files and initializes Python MCP', {skip:!pythonAvailable}, async t => {
  const packaged = fileURLToPath(new URL('../plugin/runtime/scanner/', import.meta.url));
  const list = root => fs.readdirSync(root, {withFileTypes:true}).flatMap(entry => entry.isDirectory() ? list(path.join(root,entry.name)).map(name => `${entry.name}/${name}`) : [entry.name]);
  assert.deepEqual(list(packaged).sort(), scannerPackageFiles().sort());
  for (const relative of scannerPackageFiles()) assert.deepEqual(fs.readFileSync(path.join(packaged, relative)), fs.readFileSync(path.join(scannerDirectory,relative)));
  const client = new ScannerClient(python, ['-m','bypass_scanner'], {env:{...pythonEnv,PYTHONPATH:path.join(packaged,'src')}});
  t.after(() => client.close());
  assert.deepEqual(await client.initialize(), scannerCapabilities());
});
