import { spawn } from 'node:child_process';
import readline from 'node:readline';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import assert from 'node:assert/strict';
const checkout=fileURLToPath(new URL('../',import.meta.url));
export async function mcpClient(cwd,{stateDir,packaged=false,env={}}={}){
  const child=spawn(process.execPath,[path.join(checkout,packaged?'plugin/mcp/server.mjs':'bin/bypass.mjs'),...(packaged?[]:['mcp','serve'])],{cwd,env:{...process.env,BYPASS_PLUGIN_STATE_DIR:stateDir,...env},stdio:['pipe','pipe','pipe']});
  let sequence=0,stderr='';const pending=new Map(),notifications=[];child.stderr.on('data',chunk=>stderr+=chunk);
  const lines=readline.createInterface({input:child.stdout});
  lines.on('line',line=>{const message=JSON.parse(line),item=pending.get(message.id);if(item){clearTimeout(item.timer);pending.delete(message.id);item.resolve(message);}else notifications.push(message);});
  const closed=new Promise(resolve=>child.once('close',code=>{for(const item of pending.values()){clearTimeout(item.timer);item.reject(new Error('MCP closed: '+stderr));}pending.clear();resolve(code);}));
  const request=(method,params={})=>new Promise((resolve,reject)=>{const id=++sequence,timer=setTimeout(()=>{pending.delete(id);reject(new Error(`MCP ${method} timed out: ${stderr}`));},30000);pending.set(id,{resolve,reject,timer});child.stdin.write(JSON.stringify({jsonrpc:'2.0',id,method,params})+'\n');});
  const raw=(name,args={},meta)=>request('tools/call',{name,arguments:args,...(meta?{_meta:meta}:{})});
  const call=async(name,args={},meta)=>{const message=await raw(name,args,meta);assert.ok(message.result,JSON.stringify(message));assert.equal(message.result.isError,false,JSON.stringify(message));return JSON.parse(message.result.content[0].text);};
  const wait=async id=>{let after=0;const deadline=Date.now()+30000;while(Date.now()<deadline){const result=await call('bypass_watch_run',{id,after,timeout:'2s'});if(result.terminal)return (await call('bypass_run',{id})).run;after=result.cursor;}throw new Error('Run exceeded test deadline');};
  await request('initialize',{protocolVersion:'2025-11-25',capabilities:{},clientInfo:{name:'plugin-journey-test',version:'1'}});
  child.stdin.write(JSON.stringify({jsonrpc:'2.0',method:'notifications/initialized'})+'\n');
  return {child,request,raw,call,wait,notifications,close:async()=>{child.stdin.end();return closed;}};
}
