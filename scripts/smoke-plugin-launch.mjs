import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import assert from 'node:assert/strict';
import {spawnSync} from 'node:child_process';

const [bundle,workspace]=process.argv.slice(2),plugin=path.resolve(bundle,'plugin');
const manifest=JSON.parse(fs.readFileSync(path.join(plugin,'.muse-plugin/plugin.json')));
const state=fs.mkdtempSync(path.join(os.tmpdir(),'bypass-launch-state-'));
// Muse resolves the declared source (the bundled executable) against the plugin,
// while the process keeps the customer's cwd. Do not rewrite other argv here:
// that would hide a broken relative server path in the release manifest.
function launch(capability,input){
  const [binary,...args]=capability.command;
  assert.ok(binary.startsWith('./runtime/node'));
  const result=spawnSync(path.resolve(plugin,binary),args,{cwd:workspace,env:{...process.env,BYPASS_PLUGIN_STATE_DIR:state},input,encoding:'utf8',timeout:15000,maxBuffer:2_000_000});
  assert.equal(result.status,0,`${capability.id} failed: ${result.error?.message||result.stderr}`);
  return result.stdout.trim();
}
try{
  const hook=JSON.parse(launch(manifest.capabilities.hooks[0],JSON.stringify({cwd:workspace})));
  assert.equal(JSON.parse(hook.hookSpecificOutput.additionalContext).version,manifest.version);
  const messages=[
    {id:1,method:'initialize',params:{protocolVersion:'2025-11-25',capabilities:{},clientInfo:{name:'installed-manifest-test',version:'1'}}},
    {method:'notifications/initialized'},
    {id:2,method:'tools/list'},
    {id:3,method:'tools/call',params:{name:'bypass_help',arguments:{query:'monitor worker'}}},
    {id:4,method:'tools/call',params:{name:'bypass_dashboard',arguments:{}}}
  ];
  const output=launch(manifest.capabilities.mcpServers[0],messages.map(m=>JSON.stringify({jsonrpc:'2.0',...m})).join('\n')+'\n');
  const rows=output.split('\n').map(JSON.parse),tools=rows.find(r=>r.id===2).result.tools;
  assert.equal(tools.length,77);
  for(const id of [3,4]){
    const result=rows.find(r=>r.id===id).result;
    assert.equal(result.isError,false,JSON.stringify(result));
    assert.equal(JSON.parse(result.content[0].text).pluginVersion,manifest.version);
  }
  const guide=JSON.parse(rows.find(r=>r.id===3).result.content[0].text);
  assert.equal(guide.capabilities[0].tool,'bypass_monitor_worker');
  console.log(`Installed manifest launches hook and all ${tools.length} MCP tools from the application cwd (${manifest.version}).`);
}finally{fs.rmSync(state,{recursive:true,force:true});}
