import fs from 'node:fs';
import assert from 'node:assert/strict';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { VERSION } from '../src/util.mjs';
import { VERSION as pluginVersion } from '../plugin/runtime/src/util.mjs';
const root=path.resolve(path.dirname(fileURLToPath(import.meta.url)),'..');
const metadata=file=>JSON.parse(fs.readFileSync(path.join(root,file),'utf8'));
const version=metadata('package.json').version;
for(const [label,value] of [
  ['CLI runtime',VERSION],['plugin runtime',pluginVersion],
  ['plugin manifest',metadata('plugin/.muse-plugin/plugin.json').version],
  ['plugin package',metadata('plugin/runtime/package.json').version],
  ['lockfile',metadata('package-lock.json').version],
  ['lockfile root package',metadata('package-lock.json').packages[''].version]
])assert.equal(value,version,`${label} must match package.json (${version}). Update release metadata and rebuild the plugin.`);
console.log(`Release version ${version} matches CLI, plugin and lockfile metadata.`);
let count=0;
function modules(directory){
  return fs.readdirSync(directory,{withFileTypes:true}).flatMap(entry=>{
    const file=path.join(directory,entry.name);
    return entry.isDirectory()?modules(file):entry.isFile()&&entry.name.endsWith('.mjs')?[file]:[];
  });
}
for(const directory of ['src','bin','scripts','test','agents','examples/poc-api','infra/releases']){
  for(const file of modules(path.join(root,directory))){
    const r=spawnSync(process.execPath,['--check',file],{encoding:'utf8'});
    if(r.status!==0){console.error(r.stderr);process.exit(r.status||1);}count++;
  }
}
console.log(`Syntax checked ${count} JavaScript modules.`);
