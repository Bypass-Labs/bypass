import fs from 'node:fs';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
const root=path.resolve(path.dirname(fileURLToPath(import.meta.url)),'..');
let count=0;
for(const directory of ['src','bin','scripts','test','agents','examples/poc-api','infra/releases']){
  for(const name of fs.readdirSync(path.join(root,directory)).filter(x=>x.endsWith('.mjs'))){
    const r=spawnSync(process.execPath,['--check',path.join(root,directory,name)],{encoding:'utf8'});
    if(r.status!==0){console.error(r.stderr);process.exit(r.status||1);}count++;
  }
}
console.log(`Syntax checked ${count} JavaScript modules.`);
