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
// A local esbuild binary can hide an omitted platform package in the lockfile.
// Check every advertised binary so Linux checks also protect clean Mac/Windows builds.
const packages=metadata('package-lock.json').packages;
for(const [name,expected] of Object.entries(packages['node_modules/esbuild'].optionalDependencies)){
  const locked=packages['node_modules/'+name];
  assert.ok(locked,`${name} is missing from package-lock.json; restore its pinned optional dependency entry.`);
  assert.equal(locked.version,expected,`${name} must match the pinned esbuild version.`);
  assert.match(locked.integrity,/^sha512-/,`${name} must have a locked integrity hash.`);
}
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
