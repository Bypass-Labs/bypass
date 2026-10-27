import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
const root=path.resolve(path.dirname(fileURLToPath(import.meta.url)),'..');
const runtime=path.join(root,'plugin/runtime');
fs.mkdirSync(runtime,{recursive:true});
for(const directory of ['src','bin','agents','examples/poc-api'])fs.cpSync(path.join(root,directory),path.join(runtime,directory),{recursive:true});
fs.copyFileSync(path.join(root,'package.json'),path.join(runtime,'package.json'));
console.log(JSON.stringify({built:true,plugin:path.join(root,'plugin'),runtimeDependencies:0}));
