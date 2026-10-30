import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import {fileURLToPath} from 'node:url';

const root=fileURLToPath(new URL('../',import.meta.url));
const list=dir=>fs.readdirSync(dir,{withFileTypes:true}).flatMap(item=>
  item.isDirectory()?list(path.join(dir,item.name)).map(name=>path.join(item.name,name)):[item.name]).sort();

test('plugin runtime has the exact blackbox engine and vulnerability reference',()=>{
  const source=path.join(root,'src/blackbox'),runtime=path.join(root,'plugin/runtime/src/blackbox');
  const files=list(source);
  assert.deepEqual(list(runtime),files);
  for(const file of files)assert.deepEqual(fs.readFileSync(path.join(runtime,file)),
    fs.readFileSync(path.join(source,file)),file);
  assert.deepEqual(fs.readFileSync(path.join(root,'plugin/runtime/docs/muse_spark_bug_bounty_tier_1_tier_2.md')),
    fs.readFileSync(path.join(root,'docs/muse_spark_bug_bounty_tier_1_tier_2.md')));
  const manifest=JSON.parse(fs.readFileSync(path.join(root,'plugin/.muse-plugin/plugin.json'),'utf8'));
  assert.ok(manifest.capabilities.commands.some(item=>item.id==='blackbox'&&
    fs.existsSync(path.join(root,'plugin',item.path))));
});
