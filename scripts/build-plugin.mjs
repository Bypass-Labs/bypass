import { build } from 'esbuild';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { scannerPackageFiles } from '../src/scanner/runtime.mjs';
const root=path.resolve(path.dirname(fileURLToPath(import.meta.url)),'..');
const runtime=path.join(root,'plugin/runtime');
// This directory is generated and ignored by Git. Recreate it from authored
// sources so removed files cannot linger in an installable plugin package.
fs.rmSync(runtime,{recursive:true,force:true});
fs.mkdirSync(runtime,{recursive:true});
for(const name of ['LICENSE','NOTICE','THIRD_PARTY_NOTICES.md'])
  fs.copyFileSync(path.join(root,name),path.join(runtime,name));
for(const directory of ['src','bin','agents','examples/poc-api']){
  const destination=path.join(runtime,directory);
  fs.cpSync(path.join(root,directory),destination,{recursive:true});
}
fs.mkdirSync(path.join(runtime,'docs'),{recursive:true});
fs.copyFileSync(path.join(root,'docs/muse_spark_bug_bounty_tier_1_tier_2.md'),
  path.join(runtime,'docs/muse_spark_bug_bounty_tier_1_tier_2.md'));
for(const relative of scannerPackageFiles(path.join(root,'scanner'))){
  const destination=path.join(runtime,'scanner',relative);
  fs.mkdirSync(path.dirname(destination),{recursive:true});
  fs.copyFileSync(path.join(root,'scanner',relative),destination);
}
// Bundle the official SDK to keep native Muse install hashing/copying bounded.
fs.mkdirSync(path.join(runtime,'vendor'),{recursive:true});
await build({stdin:{contents:"export {default} from 'openai'; export {APIPromise} from 'openai/core/api-promise';",resolveDir:root},bundle:true,platform:'node',format:'esm',target:'node22',outfile:path.join(runtime,'vendor/openai.mjs'),minify:true});
fs.copyFileSync(path.join(root,'node_modules/openai/LICENSE'),path.join(runtime,'vendor/OPENAI_SDK_LICENSE'));
// The SDK contains vendored dependencies with their own attribution obligations.
// Keep all upstream license/notice files, including those whose code is bundled.
function copySDKNotices(directory,relative=''){
  for(const entry of fs.readdirSync(directory,{withFileTypes:true})){
    const name=path.join(relative,entry.name),source=path.join(directory,entry.name);
    if(entry.isDirectory())copySDKNotices(source,name);
    else if(entry.isFile()&&/^(LICENSE|NOTICE|COPYING)(\.|$)/i.test(entry.name)){
      const target=path.join(runtime,'vendor/openai-licenses',name);
      fs.mkdirSync(path.dirname(target),{recursive:true});fs.copyFileSync(source,target);
    }
  }
}
copySDKNotices(path.join(root,'node_modules/openai'));
const providerFile=path.join(runtime,'src/providers.mjs');
fs.writeFileSync(providerFile,fs.readFileSync(providerFile,'utf8').replace("from 'openai'","from '../vendor/openai.mjs'").replace("from 'openai/core/api-promise'","from '../vendor/openai.mjs'"));
fs.copyFileSync(path.join(root,'package.json'),path.join(runtime,'package.json'));
console.log(JSON.stringify({built:true,plugin:path.join(root,'plugin'),runtimeDependencies:1}));
