import fs from 'node:fs';
import path from 'node:path';
import assert from 'node:assert/strict';
import {pathToFileURL} from 'node:url';
import {spawn} from 'node:child_process';
import readline from 'node:readline';
const [bundle,app]=process.argv.slice(2),runtime=path.join(bundle,'plugin/runtime');
const manifest=JSON.parse(fs.readFileSync(path.join(bundle,'plugin/.muse-plugin/plugin.json')));
assert.ok([...manifest.capabilities.mcpServers,...manifest.capabilities.hooks].every(c=>c.command[0]==='./runtime/node.exe'));
const fake=path.join(path.dirname(app),'fake Muse'),savedPath=process.env.Path;fs.mkdirSync(fake);
fs.writeFileSync(path.join(fake,'muse.cmd'),'@exit /b 97\r\n');
fs.writeFileSync(path.join(fake,'.muse-launcher.ps1'),`[Console]::OutputEncoding = New-Object Text.UTF8Encoding($false)
if ($args[0] -eq '--version') { Write-Output 'Windows Muse fixture'; exit 0 }
$marker = Join-Path $PSScriptRoot 'installed.json'
switch ($args[1]) {
  'inspect' { if (Test-Path $marker) { Get-Content $marker -Raw; exit 0 }; Write-Output '{"error":{"message":"not installed"}}'; exit 1 }
  'validate' { Write-Output '{"valid":true}'; exit 0 }
  'install' { '{"valid":true,"active":true,"record":{"id":"bypass","version":"${manifest.version}"}}' | Set-Content $marker; @{installed=$true; source=$args[2]} | ConvertTo-Json -Compress; exit 0 }
  default { throw 'Unexpected native Muse operation' }
}
`);
try{
  process.env.Path=fake+path.delimiter+savedPath;
  const {execFile}=await import(pathToFileURL(path.join(runtime,'src/util.mjs')));
  assert.equal((await execFile('muse',['--version'])).stdout,'Windows Muse fixture');
  const {execute}=await import(pathToFileURL(path.join(runtime,'src/service.mjs')));
  const installed=await execute('integrate muse',[],{project:app,scope:'user'});
  assert.equal(installed.exitCode,0);assert.equal(installed.installed.source,path.join(bundle,'plugin'));
}finally{process.env.Path=savedPath;}
const server=manifest.capabilities.mcpServers[0];
const child=spawn(path.resolve(bundle,'plugin',server.command[0]),server.command.slice(1),{cwd:app,env:{...process.env,BYPASS_PLUGIN_STATE_DIR:path.join(path.dirname(app),'plugin-state')},stdio:['pipe','pipe','pipe']});
let sequence=0;const pending=new Map();let stderr='';child.stderr.on('data',chunk=>stderr+=chunk);
readline.createInterface({input:child.stdout}).on('line',line=>{const result=JSON.parse(line),p=pending.get(result.id);if(p){clearTimeout(p.timer);pending.delete(result.id);p.resolve(result);}});
const closed=new Promise(resolve=>child.once('close',(code,signal)=>{for(const p of pending.values()){clearTimeout(p.timer);p.reject(new Error(`Installed MCP closed during ${p.label} (code ${code}, signal ${signal}): ${stderr}`));}pending.clear();resolve(code);}));
child.stdin.on('error',()=>{});
const request=(method,params={})=>new Promise((resolve,reject)=>{const id=++sequence,label=params.name||method,timer=setTimeout(()=>{pending.delete(id);reject(new Error(`Installed MCP timed out during ${label}: ${stderr}`));},30000);pending.set(id,{resolve,reject,timer,label});child.stdin.write(JSON.stringify({jsonrpc:'2.0',id,method,params})+'\n');});
try{
  assert.equal((await request('initialize',{protocolVersion:'2025-11-25',capabilities:{},clientInfo:{name:'windows-release-test',version:'1'}})).result.protocolVersion,'2025-11-25');
  child.stdin.write(JSON.stringify({jsonrpc:'2.0',method:'notifications/initialized'})+'\n');
  const tools=await request('tools/list');assert.ok(tools.result.tools.find(t=>t.name==='bypass_feature_context'));
  const connected=await request('tools/call',{name:'bypass_connect_repository',arguments:{repository:app,confirmed:true}});assert.equal(connected.result.isError,false);
  const context=await request('tools/call',{name:'bypass_feature_context',arguments:{task:'Add invoices & reports'}});assert.equal(context.result.isError,false);assert.equal(JSON.parse(context.result.content[0].text).kind,'feature-security-context');
  const call=async(name,args={})=>{const response=await request('tools/call',{name,arguments:args});assert.equal(response.result.isError,false,JSON.stringify(response));return JSON.parse(response.result.content[0].text);};
  assert.equal((await call('bypass_dashboard')).selectedRepository,app);
  const guide=await call('bypass_help',{query:'monitor worker'});assert.equal(guide.capabilities[0].tool,'bypass_monitor_worker');
  const fixture=await call('bypass_demo_start',{kind:'real',dir:path.join(path.dirname(app),'plugin fixture')});
  try{
    assert.equal((await call('bypass_test_probe',{name:'invoice'})).validation.status,'ready');
    await call('bypass_demo_control',{action:'fix'});
    assert.equal((await fetch(fixture.url+'/api/invoices/inv-101',{headers:{Authorization:'Bearer poc-outsider-token'}})).status,403);
  }finally{await call('bypass_demo_control',{action:'stop'});}
  assert.equal((await call('bypass_dashboard')).selectedRepository,app);
  console.log('Installed Windows MCP and native Muse launcher adapter passed (Muse account/model calls not exercised).');
}finally{child.stdin.end();await closed;}
