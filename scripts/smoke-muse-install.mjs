// Real native Muse install/approval/reinstall, confined to temporary XDG stores.
// Does not authenticate, invoke a model, or use the user's plugin installation.
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { finishMuseSetup, setupPrompt } from '../src/muse-setup.mjs';
import { toolDefinitions } from '../src/mcp.mjs';

const [bundle]=process.argv.slice(2);
assert.ok(bundle,'Usage: node scripts/smoke-muse-install.mjs <release-bundle>');
const root=fs.mkdtempSync(path.join(os.tmpdir(),'bypass-native-setup-'));
const app=path.join(root,'app'),copy=path.join(root,'bundle');fs.mkdirSync(app);
const env={...process.env,XDG_CONFIG_HOME:path.join(root,'config'),XDG_DATA_HOME:path.join(root,'data'),XDG_STATE_HOME:path.join(root,'state'),XDG_CACHE_HOME:path.join(root,'cache'),BYPASS_PLUGIN_STATE_DIR:path.join(root,'bypass-state'),MUSE_NO_AUTO_UPDATE:'1'};
const run=(command,args)=>JSON.parse(execFileSync(command,args,{cwd:app,env,encoding:'utf8',timeout:180000,maxBuffer:4_000_000}));
try{
  fs.cpSync(bundle,copy,{recursive:true,dereference:true});
  assert.deepEqual(run('muse',['plugins','list','--json']).plugins,[],'Refusing to operate in a nonempty plugin store');
  const runtime=path.join(copy,'plugin/runtime'),node=path.join(runtime,process.platform==='win32'?'node.exe':'node'),cli=path.join(runtime,'bin/bypass.mjs');
  const install=()=>run(node,[cli,'integrate','muse','--scope','user','--replace','--json']);
  const first=install();assert.equal(first.state,'review_required');assert.equal(first.reviewRequired,true);
  let inspected=run('muse',['plugins','inspect','bypass','--json']);
  assert.ok(inspected.record.cache_path.startsWith(root+path.sep));
  const expectedCommands=JSON.parse(fs.readFileSync(path.join(copy,'plugin/.muse-plugin/plugin.json'))).capabilities.commands.length;
  assert.equal(inspected.plugin.capabilities.commands.length,expectedCommands);
  assert.equal(inspected.runtime_capabilities.length,2);
  assert.ok(inspected.runtime_capabilities.every(row=>row.status==='review_needed'));
  const installedAt=inspected.record.installed_at;
  // Exercise the consent handoff against the real native manager, exclusively
  // in this isolated fixture store. The launch boundary makes no model call.
  const handoff=await finishMuseSetup({cwd:app,inspect:async()=>run('muse',['plugins','inspect','bypass','--json']),approve:async id=>run('muse',['plugins','approve',id,'--json']),ask:async()=>'yes',launch:async prompt=>{assert.equal(prompt,setupPrompt);return 0;},write:()=>{}});
  assert.equal(handoff.opened,true);
  const repeated=install();assert.equal(repeated.alreadyInstalled,true);assert.equal(repeated.state,'ready_for_new_session');
  inspected=run('muse',['plugins','inspect','bypass','--json']);
  assert.equal(inspected.record.installed_at,installedAt);
  assert.ok(inspected.runtime_capabilities.every(row=>row.status==='trusted_enabled'));
  run('muse',['plugins','reject','bypass:hook:session-context','--json']);
  assert.equal(install().state,'review_required');
  inspected=run('muse',['plugins','inspect','bypass','--json']);
  assert.ok(inspected.runtime_capabilities.some(row=>row.status==='trusted_disabled'));
  run('muse',['plugins','disable','bypass','--json']);
  assert.equal(install().state,'enable_required');
  run('muse',['plugins','enable','bypass','--json']);
  fs.appendFileSync(path.join(copy,'plugin/skills/bypass/SKILL.md'),'\nNative installation test: changed package.\n');
  const changed=install();assert.equal(changed.state,'review_required');assert.ok(!changed.alreadyInstalled);
  inspected=run('muse',['plugins','inspect','bypass','--json']);
  assert.ok(inspected.runtime_capabilities.every(row=>row.status==='review_needed'));
  execFileSync(node,[path.resolve('scripts/smoke-plugin-launch.mjs'),copy,app],{cwd:process.cwd(),env,stdio:'inherit',timeout:30000});
  console.log(JSON.stringify({nativeMuse:'passed',firstInstall:'review_required',identicalRerun:'approval_preserved',rejection:'preserved',disabled:'preserved',changedPackage:'review_required',tools:toolDefinitions.length,commands:inspected.plugin.capabilities.commands.length,modelCalls:0,isolatedStore:true}));
}finally{
  // Every path removed was created by this script. No user store is touched.
  fs.rmSync(root,{recursive:true,force:true});
}
