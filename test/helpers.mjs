import { execute } from '../src/service.mjs';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import net from 'node:net';
import { execFile } from '../src/util.mjs';
import { CLI } from '../src/demo.mjs';
export const temp=()=>fs.mkdtempSync(path.join(os.tmpdir(),'bypass-test-'));
export async function port(){const server=net.createServer();await new Promise((res,rej)=>{server.once('error',rej);server.listen(0,'127.0.0.1',res);});const p=server.address().port;await new Promise(res=>server.close(res));return p;}
export async function cli(root,...args){const r=await execFile(process.execPath,[CLI,...args,'--project',root,'--json','--non-interactive'],{cwd:root,timeout:30000});let data;try{data=JSON.parse(r.stdout);}catch{throw new Error(`Invalid CLI JSON: ${r.stdout}\n${r.stderr}`);}return {code:r.code,data,stderr:r.stderr};}

// Public synthetic key for local/mock transport contracts only.
process.env.BYPASS_UNIT_API_KEY='unit-fixture-key';
export const addTestModel=root=>execute('model add',['test-api'],{project:root,provider:'meta',model:'test-model','secret-env':'BYPASS_UNIT_API_KEY',stream:false});
