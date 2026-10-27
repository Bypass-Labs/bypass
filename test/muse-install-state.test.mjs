import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { samePluginPackage, museInstallState } from '../src/muse-install-state.mjs';

test('plugin readiness requires both approved runtime capabilities, not merely active=true',()=>{
  const capability=(id,status)=>({candidate:{stable_id:id},status});
  const rows=['plugin:bypass:hook:session-context','plugin:bypass:mcp_server:security'].map(id=>capability(id,'trusted_enabled'));
  assert.equal(museInstallState({valid:true,active:true}).state,'review_required');
  const inspected={valid:true,active:true,runtime_capabilities:rows};
  assert.equal(museInstallState(inspected).state,'ready_for_new_session');
  for(const status of ['review_needed','modified','trusted_disabled','invalid','blocked']){
    assert.equal(museInstallState({...inspected,runtime_capabilities:[rows[0],capability(rows[1].candidate.stable_id,status)]}).state,'review_required');
  }
  assert.equal(museInstallState({...inspected,active:false}).state,'enable_required');
  assert.equal(museInstallState({...inspected,valid:false}).state,'repair_required');
});

test('same-version source changes, added files and executable changes invalidate package reuse',t=>{
  const root=fs.mkdtempSync(path.join(os.tmpdir(),'bypass-package-compare-'));t.after(()=>fs.rmSync(root,{recursive:true,force:true}));
  const a=path.join(root,'a'),b=path.join(root,'b');fs.mkdirSync(a);fs.mkdirSync(b);
  for(const dir of [a,b]){fs.writeFileSync(path.join(dir,'manifest.json'),'{"version":"1"}');fs.writeFileSync(path.join(dir,'hook.mjs'),'original',{mode:0o644});}
  assert.equal(samePluginPackage(a,b),true);
  fs.writeFileSync(path.join(b,'hook.mjs'),'changed');assert.equal(samePluginPackage(a,b),false);
  fs.writeFileSync(path.join(b,'hook.mjs'),'original');fs.writeFileSync(path.join(b,'extra'),'extra');assert.equal(samePluginPackage(a,b),false);
  fs.unlinkSync(path.join(b,'extra'));fs.chmodSync(path.join(b,'hook.mjs'),0o755);assert.equal(samePluginPackage(a,b),false);
  assert.equal(samePluginPackage(a,path.join(root,'missing')),false);
});

test('package comparison cannot confuse file contents with another file entry',t=>{
  const root=fs.mkdtempSync(path.join(os.tmpdir(),'bypass-package-boundaries-'));t.after(()=>fs.rmSync(root,{recursive:true,force:true}));
  const a=path.join(root,'a'),b=path.join(root,'b');fs.mkdirSync(a);fs.mkdirSync(b);
  fs.writeFileSync(path.join(a,'first'),'start'+JSON.stringify(['second','file',0])+'end',{mode:0o644});
  fs.writeFileSync(path.join(b,'first'),'start',{mode:0o644});
  fs.writeFileSync(path.join(b,'second'),'end',{mode:0o644});
  assert.equal(samePluginPackage(a,b),false);
});
