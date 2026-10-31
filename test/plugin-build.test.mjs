import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { execFile } from '../src/util.mjs';

test('a source-only checkout builds a self-contained plugin and removes stale output', {timeout:120000}, async t=>{
  const source=fileURLToPath(new URL('../',import.meta.url));
  const root=fs.mkdtempSync(path.join(os.tmpdir(),'bypass-source-build-'));
  t.after(()=>fs.rmSync(root,{recursive:true,force:true}));
  const generated=path.join(source,'plugin/runtime');
  const authored=['package.json','package-lock.json','src','bin','agents','scanner','examples','docs','scripts','test','infra','plugin'];
  for(const name of authored)fs.cpSync(path.join(source,name),path.join(root,name),{recursive:true,filter:file=>
    file!==generated&&!['node_modules','__pycache__','.venv','.bypass','.demo','.tmp','.env'].includes(path.basename(file))});
  const runtime=path.join(root,'plugin/runtime');
  assert.equal(fs.existsSync(runtime),false,'source copy must not depend on an existing runtime');
  fs.mkdirSync(runtime,{recursive:true});
  fs.writeFileSync(path.join(runtime,'stale-file'),'obsolete generated output');
  fs.symlinkSync(path.join(source,'node_modules'),path.join(root,'node_modules'),process.platform==='win32'?'junction':'dir');
  // npm check must build first on a fresh checkout, not import tracked copies.
  const checked=await execFile(process.platform==='win32'?'npm.cmd':'npm',['run','check'],{cwd:root,timeout:90000});
  assert.equal(checked.code,0,checked.stderr||checked.stdout);
  assert.equal(fs.existsSync(path.join(runtime,'stale-file')),false);
  assert.deepEqual(fs.readFileSync(path.join(root,'scanner/protocol/v3.json')),fs.readFileSync(path.join(runtime,'scanner/protocol/v3.json')));
  assert.equal(fs.existsSync(path.join(runtime,'scanner/protocol/v1.json')),false);

  // The built plugin must launch with no development dependency tree present.
  fs.renameSync(path.join(root,'node_modules'),path.join(root,'development-dependencies'));
  const app=path.join(root,'app');fs.mkdirSync(app);
  const {mcpClient}=await import(pathToFileURL(path.join(root,'test/mcp-client.mjs')).href);
  const client=await mcpClient(app,{packaged:true,stateDir:path.join(root,'plugin-state')});
  try{
    const listed=await client.request('tools/list');
    assert.ok(listed.result.tools.some(tool=>tool.name==='bypass_discover'));
    const capabilities=await client.call('bypass_scanner_capabilities');
    assert.equal(capabilities.protocolVersion,'bypass-scanner.v3');
    assert.equal(capabilities.features.codeqlDiscovery,true);
    assert.equal(capabilities.independentModelRequests,0);
  }finally{await client.close();}
});
