import { build } from 'esbuild';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { scannerPackageFiles } from '../src/scanner/runtime.mjs';
const root=path.resolve(path.dirname(fileURLToPath(import.meta.url)),'..');
const runtime=path.join(root,'plugin/runtime');
fs.mkdirSync(runtime,{recursive:true});
for(const directory of ['src','bin','agents','examples/poc-api']){
  const destination=path.join(runtime,directory);
  fs.rmSync(destination,{recursive:true,force:true});
  fs.cpSync(path.join(root,directory),destination,{recursive:true});
}
fs.mkdirSync(path.join(runtime,'docs'),{recursive:true});
fs.copyFileSync(path.join(root,'docs/muse_spark_bug_bounty_tier_1_tier_2.md'),
  path.join(runtime,'docs/muse_spark_bug_bounty_tier_1_tier_2.md'));
fs.rmSync(path.join(runtime,'scanner'),{recursive:true,force:true});
for(const relative of scannerPackageFiles(path.join(root,'scanner'))){
  const destination=path.join(runtime,'scanner',relative);
  fs.mkdirSync(path.dirname(destination),{recursive:true});
  fs.copyFileSync(path.join(root,'scanner',relative),destination);
}
// Bundle the official SDK to keep native Muse install hashing/copying bounded.
fs.rmSync(path.join(runtime,'node_modules'),{recursive:true,force:true});
fs.mkdirSync(path.join(runtime,'vendor'),{recursive:true});
await build({stdin:{contents:"export {default} from 'openai';",resolveDir:root},bundle:true,platform:'node',format:'esm',target:'node22',outfile:path.join(runtime,'vendor/openai.mjs'),minify:true});
fs.copyFileSync(path.join(root,'node_modules/openai/LICENSE'),path.join(runtime,'vendor/OPENAI_SDK_LICENSE'));
const providerFile=path.join(runtime,'src/providers.mjs');
fs.writeFileSync(providerFile,fs.readFileSync(providerFile,'utf8').replace("from 'openai'","from '../vendor/openai.mjs'"));
fs.copyFileSync(path.join(root,'package.json'),path.join(runtime,'package.json'));
console.log(JSON.stringify({built:true,plugin:path.join(root,'plugin'),runtimeDependencies:1}));
