import fs from 'node:fs';
import path from 'node:path';
import { randomUUID } from 'node:crypto';
import { need, redact } from '../util.mjs';

export function openDebugLog(root,run,{raw=false}={}) {
  const directory=path.join(root,'.bypass','debug');
  fs.mkdirSync(directory,{recursive:true,mode:0o700});
  need(!fs.lstatSync(directory).isSymbolicLink(),'Scanner debug directory must not be a symlink.',3);
  const filename=path.join(directory,`${run}-${randomUUID()}.jsonl`);
  const fd=fs.openSync(filename,'wx',0o600);
  let bytes=0;
  return {filename,raw,
    write(record){
      const line=JSON.stringify(redact({timestamp:new Date().toISOString(),run,...record}))+'\n';
      need(bytes+Buffer.byteLength(line)<=16777216,'Scanner debug log reached its 16 MiB limit; disable logging or start a new run.',3,{reason:'debug_log_limit'});
      fs.writeFileSync(fd,line);bytes+=Buffer.byteLength(line);
    },
    close(){fs.closeSync(fd);}
  };
}
