import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawnSync } from 'node:child_process';
import { manifest, scannerCapabilities, protocolVersion, unavailable } from '../src/scanner/contracts.mjs';
import { ScannerClient } from '../src/scanner/client.mjs';
import { scannerContainerArgs, scannerPackageFiles, scannerDirectory, scannerDoctor, prepareScanner, connectScanner } from '../src/scanner/runtime.mjs';
import { runAPIDriver } from '../src/scanner/api-driver.mjs';
import { inExecutionMode } from '../src/execution-mode.mjs';
import { validateJSON } from '../src/schema.mjs';
import { parse } from '../src/catalog.mjs';
import { execute } from '../src/service.mjs';
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
  assert.equal(protocolVersion, 'bypass-scanner.v1');
  assert.deepEqual(Object.keys(manifest.schemas).sort(), ['capabilities','error','evaluation','evidence','run','signal','task']);
  validateJSON(manifest.schemas.capabilities, scannerCapabilities());
  for (const name of Object.keys(manifest.operations)) validateJSON(manifest.schemas.error, unavailable(name));
  assert.deepEqual(manifest.schemas.evaluation.properties.outcome.enum, ['confirmed', 'refuted', 'needs_review']);
  assert.throws(() => validateJSON(manifest.operations.status.inputSchema, { run: '' }));
  for (const words of [['discover','--plan'], ['discover','--sarif','input.sarif','--config','scanner.json'], ['discover','status','r'], ['discover','resume','r'], ['discover','cancel','r'], ['discover','report','r','--format','md'], ['scanner','doctor'], ['scanner','prepare']]) assert.ok(parse(words).key);
  assert.throws(() => parse(['discover','status']));
  assert.throws(() => parse(['discover','--model','secret']));
});

test('Python MCP and Node read identical capabilities and operation schemas', { skip: !pythonAvailable }, async t => {
  const client = new ScannerClient(python, ['-m', 'bypass_scanner'], { env: pythonEnv });
  t.after(() => client.close());
  assert.deepEqual(await client.initialize(), scannerCapabilities());
  const listed = await client.request('tools/list');
  assert.equal(listed.tools.length, Object.keys(manifest.operations).length);
  for (const tool of listed.tools) assert.deepEqual(tool.inputSchema, manifest.operations[tool.name.slice(8)].inputSchema);
  for (const [operation, args] of [['start', {sarif:'/missing.sarif'}], ['status',{run:'r'}], ['next_task',{run:'r'}], ['evidence',{run:'r',task:'t',operation:'read'}], ['submit',{run:'r',task:'t',sourceRevision:'s',result:{}}], ['resume',{run:'r'}], ['cancel',{run:'r'}], ['report',{run:'r',format:'md'}]]) {
    assert.deepEqual(await client.call(operation, args), unavailable(operation));
  }
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

test('container packaging excludes caches and never grants source, network, or credential access', async () => {
  const args = scannerContainerArgs('fixture', 'sha256:' + 'a'.repeat(64));
  assert.equal(args[args.indexOf('--network') + 1], 'none');
  for (const flag of ['--read-only','--cap-drop','--security-opt','--memory','--pids-limit']) assert.ok(args.includes(flag));
  for (const flag of ['--mount','--volume','--env','--privileged']) assert.equal(args.includes(flag), false);
  const files = scannerPackageFiles();
  assert.ok(files.includes('protocol/v1.json'));
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
  assert.equal((await prepareScanner({runner})).status, 'scaffold');
  assert.equal(calls.filter(call => call.includes('build')).length, 1);
});

test('planning works before initialization and never creates project state', async () => {
  const root = temp();
  const before = fs.readdirSync(root);
  const result = await cli(root, 'discover', '--plan');
  assert.equal(result.code, 0);
  assert.equal(result.data.plan.analysisImplemented, false);
  assert.equal(result.data.plan.executionMode, 'standalone-api');
  assert.equal(result.data.plan.modelCalls, 0);
  assert.deepEqual(fs.readdirSync(root), before);
  for (const command of [['discover','status','r'], ['discover','cancel','r'], ['discover','report','r','--format','json']]) {
    const response = await cli(root, ...command);
    assert.equal(response.code, 3);
    assert.equal(response.data.code, 'not_implemented');
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

test('standalone discovery requires API settings and never constructs an LLM request', async t => {
  const root = temp();
  await assert.rejects(execute('discover', [], {project:root}), error => error.details.reason === 'model_configuration_required');
  await execute('init', [root]);
  await addTestModel(root);
  const filename = path.join(root, '.bypass/state.json');
  const state = JSON.parse(fs.readFileSync(filename));
  const profile = state.models.find(model => model.name === state.activeModel);
  const saved = process.env[profile.secretEnv];
  delete process.env[profile.secretEnv];
  try { await assert.rejects(execute('discover', [], {project:root}), error => error.details.reason === 'credential_missing'); }
  finally { process.env[profile.secretEnv] = saved; }
  // Any SDK request fails immediately instead of reaching an external endpoint.
  const OpenAI = (await import('openai')).default;
  t.mock.method(OpenAI.prototype, 'makeRequest', () => { throw new Error('Unexpected SDK request'); });
  const before = fs.readFileSync(filename, 'utf8');
  for (const command of ['discover','discover resume']) {
    const result = await execute(command, command === 'discover' ? [] : ['r'], {project:root});
    assert.equal(result.code, 'not_implemented');
    assert.equal(result.modelCalls, 0);
  }
  assert.equal(fs.readFileSync(filename, 'utf8'), before);
  await assert.rejects(inExecutionMode('muse-host', async () => runAPIDriver(state)), error => error.details.reason === 'host_owned_inference');
});

test('Muse discovery never consults API profiles or changes source/state', async t => {
  const root = temp(), stateDir = temp();
  fs.writeFileSync(path.join(root, 'app.mjs'), 'export const app = true;\n');
  const client = await mcpClient(root, {stateDir});
  t.after(() => client.close());
  const plan = await client.call('bypass_discover', {plan:true});
  assert.equal(plan.plan.executionMode, 'muse-host');
  assert.equal(plan.plan.modelCalls, 0);
  assert.deepEqual(fs.readdirSync(root), ['app.mjs']);
  await client.call('bypass_connect_repository', {repository:root, confirmed:true});
  const stateFile = path.join(root,'.bypass/state.json');
  const state = JSON.parse(fs.readFileSync(stateFile));
  state.models = [{name:'broken', executionMode:'standalone-api', provider:'invalid', secretEnv:'THIS_MUST_NEVER_BE_READ'}];
  state.activeModel = 'broken';
  fs.writeFileSync(stateFile, JSON.stringify(state));
  const before = fs.readFileSync(stateFile, 'utf8');
  const caps = await client.call('bypass_scanner_capabilities');
  assert.equal(caps.analysisImplemented, false);
  for (const [tool, args] of [['bypass_discover', {}], ['bypass_discover_status',{run:'r'}], ['bypass_discover_resume',{run:'r'}], ['bypass_discover_cancel',{run:'r'}], ['bypass_discover_report',{run:'r',format:'md'}], ['bypass_discover_next_task',{run:'r'}], ['bypass_discover_evidence',{run:'r',task:'t',operation:'read'}], ['bypass_discover_submit',{run:'r',task:'t',sourceRevision:'s',result:{}}]]) {
    const response = await client.raw(tool, args);
    assert.equal(response.result.isError, true);
    const result = JSON.parse(response.result.content[0].text);
    assert.equal(result.code, 'not_implemented');
    assert.equal(result.modelCalls, 0);
    assert.equal(result.ai.mode, 'muse-host');
  }
  assert.equal(fs.readFileSync(stateFile, 'utf8'), before);
  assert.equal(fs.readFileSync(path.join(root,'app.mjs'),'utf8'), 'export const app = true;\n');
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
