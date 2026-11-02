import { execute } from '../src/service.mjs';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import net from 'node:net';
import http from 'node:http';
import { execFile } from '../src/util.mjs';
import { CLI } from '../src/demo.mjs';
export const temp=()=>fs.mkdtempSync(path.join(os.tmpdir(),'bypass-test-'));
export async function port(){const server=net.createServer();await new Promise((res,rej)=>{server.once('error',rej);server.listen(0,'127.0.0.1',res);});const p=server.address().port;await new Promise(res=>server.close(res));return p;}
export async function metaModelFixture(t,{models=['muse-spark-1.3','muse-image-1.0','muse-wonder-1.0'],status=200,error={code:'billing_not_configured',type:'billing_error'}}={}){
  const calls=[];
  const server=http.createServer(async(req,res)=>{let body='';for await(const chunk of req)body+=chunk;calls.push({method:req.method,path:req.url,authorization:req.headers.authorization,body});res.setHeader('content-type','application/json');
    if(req.method==='GET'&&req.url==='/v1/models'){res.end(JSON.stringify({object:'list',data:models.map((id,index)=>({id,object:'model',created:index}))}));return;}
    res.writeHead(status);if(status>=400){res.end(JSON.stringify({error}));return;}
    res.end(JSON.stringify({status:'completed',output:[{type:'message',content:[{type:'output_text',text:'BYPASS_MODEL_OK'}]}]}));
  });
  await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve));
  const previous=process.env.MODEL_API_KEY;process.env.MODEL_API_KEY='meta-onboarding-fixture-key';
  t.after(()=>{if(previous===undefined)delete process.env.MODEL_API_KEY;else process.env.MODEL_API_KEY=previous;server.closeAllConnections();server.close();});
  return {baseUrl:`http://127.0.0.1:${server.address().port}/v1`,calls};
}
export async function cli(root,...args){const r=await execFile(process.execPath,[CLI,...args,'--project',root,'--json','--non-interactive'],{cwd:root,timeout:30000});let data;try{data=JSON.parse(r.stdout);}catch{throw new Error(`Invalid CLI JSON: ${r.stdout}\n${r.stderr}`);}return {code:r.code,data,stderr:r.stderr};}

// Public synthetic key for local/mock transport contracts only.
process.env.BYPASS_UNIT_API_KEY='unit-fixture-key';
export const addTestModel=root=>execute('model add',['test-api'],{project:root,provider:'meta',model:'test-model','secret-env':'BYPASS_UNIT_API_KEY',stream:false});

// Tests never write reusable app ownership proof to the operator's real profile.
process.env.BYPASS_PLUGIN_STATE_DIR ||= temp();
process.env.BYPASS_OWNERSHIP_DIR ||= path.join(temp(),'ownership');
