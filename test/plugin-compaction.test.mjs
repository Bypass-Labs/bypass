import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import {spawnSync} from 'node:child_process';
import {temp} from './helpers.mjs';
import {execute} from '../src/service.mjs';
import {change} from '../src/store.mjs';

test('Muse compaction restores an active source review through tool search and saved arguments', async t => {
  const root=temp();
  t.after(()=>fs.rmSync(root,{recursive:true,force:true}));
  fs.writeFileSync(path.join(root,'app.mjs'),'export const app = true;\n');
  await execute('init',[root]);
  await change(root,state=>{state.runs.push({id:'run_deadbeef',kind:'scan',
    executionMode:'muse-host',status:'awaiting_host'});});
  const hook=source=>{
    const result=spawnSync(process.execPath,['plugin/mcp/context-hook.mjs'],{
      cwd:path.resolve('.'),encoding:'utf8',input:JSON.stringify({cwd:root,source})});
    assert.equal(result.status,0,result.stderr);
    return JSON.parse(result.stdout).hookSpecificOutput.additionalContext;
  };
  const compact=hook('compact');
  assert.match(compact,/FIRST use Muse tool search for bypass_review_step/);
  assert.match(compact,/"id":"run_deadbeef","action":"status"/);
  assert.match(compact,/Never construct an mcp__plugin_bypass_security/);
  assert.doesNotMatch(hook('startup'),/FIRST use Muse tool search/);
  await change(root,state=>{state.runs.at(-1).status='cancelled';});
  assert.doesNotMatch(hook('compact'),/run_deadbeef is still/,
    'a user-cancelled review must not restart after compaction');
  await change(root,state=>{state.runs.at(-1).status='completed';});
  assert.doesNotMatch(hook('compact'),/run_deadbeef is still/);
});
