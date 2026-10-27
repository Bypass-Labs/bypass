import fs from 'node:fs';
import path from 'node:path';
import http from 'node:http';
import { randomBytes } from 'node:crypto';
import { spawn } from 'node:child_process';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { initStore, read, change, atomic, event } from './store.mjs';
import { execFile, need, now, delay, hash, Fault } from './util.mjs';
import { makeChallenge, authorization, safeRequest } from './network.mjs';
import { repositoryInfo } from './repository.mjs';

export const DEMO_OWNER='demo-acme-token';
export const DEMO_OUTSIDER='demo-globex-token';
export const CLI=fileURLToPath(new URL('../bin/bypass.mjs',import.meta.url));
const fixtureSource=`// Deliberately vulnerable training fixture. Not production code.\n// Edit this file in Muse: the running demo reloads it when its contents change.\nexport const enforceOwnership = false;\nexport const exportRoute = null;\nexport const enforceExportOwnership = false;\n\nexport function canReadInvoice(account, route) {\n  const enforced = route === 'export' ? enforceExportOwnership : enforceOwnership;\n  return !enforced || account === 'acme';\n}\n`;

export function demoConfig(root){
  const state=JSON.parse(fs.readFileSync(path.join(root,'.bypass/demo-state.json'),'utf8'));
  const source=fs.readFileSync(path.join(root,'app.mjs'),'utf8');
  return {...state,fixed:/export const enforceOwnership\s*=\s*true\s*;/.test(source),exportEnabled:/export const exportRoute\s*=\s*['"]\/api\/exports\//.test(source),exportFixed:/export const enforceExportOwnership\s*=\s*true\s*;/.test(source)};
}

export async function startDemo(location,{port=4317}={}){
  const root=path.resolve(location);fs.mkdirSync(root,{recursive:true});
  if(!fs.existsSync(path.join(root,'.bypass/state.json'))){
    need(!fs.existsSync(path.join(root,'app.mjs')),'Demo destination contains app.mjs. Choose an empty directory.');
    fs.writeFileSync(path.join(root,'app.mjs'),fixtureSource);
    fs.writeFileSync(path.join(root,'README.md'),'# Ledger demo\n\nAn isolated two-account invoice fixture for the Bypass walkthrough. Public demo credentials only.\n');
    await execFile('git',['init','--quiet',root]);
    initStore(root,await repositoryInfo(root),'Ledger · Bypass walkthrough');
  }
  const state=read(root);need(state.demo||state.targets.length===0,'This project is not a demo. Choose an empty demo directory.');
  if(state.demo){
    try{const r=await safeRequest(state.demo.url+'/health',{allowLocal:true});const data=JSON.parse(r.body);if(data.instanceId===state.demo.instanceId)return {root,url:state.demo.url,alreadyRunning:true,next:`bypass --project '${root}'`};}catch{}
  }
  port=Number(port);need(Number.isInteger(port)&&port>=1024&&port<=65535,'Demo port must be between 1024 and 65535.');
  const instanceId=randomBytes(20).toString('hex');const demo={target:'demo',url:`http://127.0.0.1:${port}`,port,instanceId,fixed:false,exportEnabled:false,exportFixed:false,createdAt:now()};
  atomic(path.join(root,'.bypass/demo-state.json'),demo);
  await change(root,s=>{
    s.demo=demo;
    let target=s.targets.find(t=>t.name==='demo');
    if(!target){target={name:'demo',url:demo.url,environment:'local',createdAt:now()};s.targets.push(target);}
    target.url=demo.url;target.challenge=makeChallenge(s.project,target);target.ownership={status:'verified',method:'local-fixture',verifiedAt:now(),expiresAt:new Date(Date.now()+30*86400000).toISOString()};
    target.authorization=authorization(target,{paths:['/api','/health'],methods:['GET','HEAD'],maxRequestsPerSecond:10},'explicit demo start');
    s.activeTarget='demo';
    for(const [name,secretEnv,fixtureValue] of [['demo-owner','BYPASS_DEMO_OWNER_TOKEN',DEMO_OWNER],['demo-outsider','BYPASS_DEMO_OUTSIDER_TOKEN',DEMO_OUTSIDER]]){
      const identity={name,target:'demo',type:'bearer',secretEnv,fixtureValue,checkPath:'/api/me',createdAt:now()};
      s.identities=s.identities.filter(x=>x.name!==name);s.identities.push(identity);
    }
    event(s,'demo-start','Created isolated Ledger fixture. All credentials are public demo values.');
  });
  const log=fs.openSync(path.join(root,'.bypass/demo.log'),'a',0o600);
  const child=spawn(process.execPath,[CLI,'_demo-serve','--project',root],{stdio:['ignore',log,log],detached:true,env:process.env});child.unref();fs.closeSync(log);
  let ready=false;
  for(let i=0;i<50;i++){
    await delay(100);
    try{const r=await safeRequest(demo.url+'/health',{allowLocal:true});if(JSON.parse(r.body).instanceId===instanceId){ready=true;break;}}catch{}
  }
  need(ready,`Demo server could not start on port ${port}. See ${path.join(root,'.bypass/demo.log')} or choose --port.`,3);
  await change(root,s=>{s.demo.pid=child.pid;});
  return {root,url:demo.url,pid:child.pid,fixture:'Two accounts, one invoice, deliberately missing ownership check.',credentials:'Public fixture values; no real customer data.',next:`bypass --project '${root}'`,steps:['scan','verify <finding-id>','demo fix','retest <finding-id>','test export --all','demo regress','test run --all']};
}
export async function updateDemo(root,action){
  const state=read(root);need(state.demo,'Run demo start first.');
  const data=demoConfig(root);
  if(action==='fix'){data.fixed=true;data.exportFixed=true;}
  if(action==='regress'){data.fixed=false;}
  if(action==='add-route'){data.exportEnabled=true;data.exportFixed=false;}
  if(action==='reset'){data.fixed=false;data.exportEnabled=false;data.exportFixed=false;}
  if(action==='stop'){data.stop=true;}
  atomic(path.join(root,'.bypass/demo-state.json'),data);
  // Source really changes, allowing the saved-check freshness path to be exercised.
  if(action!=='stop'){
    const file=path.join(root,'app.mjs');let source=fs.readFileSync(file,'utf8');
    for(const [name,value] of Object.entries({enforceOwnership:String(data.fixed),exportRoute:data.exportEnabled?JSON.stringify('/api/exports/invoice-acme-001'):'null',enforceExportOwnership:String(data.exportFixed)})){
      const pattern=new RegExp(`export const ${name}\\s*=\\s*[^;]+;`);
      source=pattern.test(source)?source.replace(pattern,`export const ${name} = ${value};`):source+`\nexport const ${name} = ${value};\n`;
    }
    // Upgrade only old, task-created demo fixtures from early skeleton revisions.
    if(!source.includes('export function canReadInvoice'))source+='\nexport function canReadInvoice(account, route) { return !(route === "export" ? enforceExportOwnership : enforceOwnership) || account === "acme"; }\n';
    fs.writeFileSync(file,source);
  }
  await change(root,s=>{Object.assign(s.demo,data);event(s,'demo-change',`Fixture ${action}.`);});
  return {action,url:data.url,fixed:data.fixed,exportEnabled:data.exportEnabled,exportFixed:data.exportFixed,message:action==='stop'?'Demo server will stop within one second.':'Fixture updated. Use retest or test run to observe the result.'};
}
export async function serveDemo(root){
  const initial=read(root).demo;need(initial,'Missing demo configuration.');
  const dataFile=path.join(root,'.bypass/demo-state.json');
  let loadedHash=null,application=null;
  const server=http.createServer(async(req,res)=>{
    let data;
    try{data=demoConfig(root);}catch{res.writeHead(500,{'Content-Type':'application/json'});res.end(JSON.stringify({error:'Fixture source or state is unavailable.'}));return;}
    const url=new URL(req.url,initial.url);
    const account=req.headers.authorization===`Bearer ${DEMO_OWNER}`?'acme':req.headers.authorization===`Bearer ${DEMO_OUTSIDER}`?'globex':null;
    res.setHeader('Cache-Control','no-store');res.setHeader('Content-Type','application/json');
    const send=(code,body)=>{res.writeHead(code);res.end(JSON.stringify(body));};
    try{
      const source=fs.readFileSync(path.join(root,'app.mjs'),'utf8'),digest=hash(source);
      if(digest!==loadedHash){application=await import(pathToFileURL(path.join(root,'app.mjs')).href+'?version='+digest);loadedHash=digest;}
      need(typeof application.canReadInvoice==='function','Fixture app.mjs must export canReadInvoice.');
    }catch{return send(500,{error:'Fixture source cannot load. Fix app.mjs before retesting.'});}
    if(req.method!=='GET'&&req.method!=='HEAD')return send(405,{error:'Read-only fixture'});
    if(url.pathname==='/health')return send(200,{ok:true,fixture:true,instanceId:initial.instanceId,fixed:data.fixed,exportEnabled:data.exportEnabled});
    if(url.pathname==='/api/me')return account?send(200,{account}):send(401,{error:'Sign in required'});
    if(url.pathname==='/api/invoices/invoice-acme-001'||(data.exportEnabled&&url.pathname==='/api/exports/invoice-acme-001')){
      if(!account)return send(401,{error:'Sign in required'});
      let allowed;try{allowed=application.canReadInvoice(account,url.pathname.startsWith('/api/exports')?'export':'invoice');}catch{return send(500,{error:'Fixture authorization code threw an error'});}
      if(!allowed)return send(403,{error:'This invoice belongs to another account'});
      return send(200,{id:'invoice-acme-001',account:'acme',amount:4200,description:'Demo invoice · fixture data only'});
    }
    if(url.pathname==='/'){
      res.setHeader('Content-Type','text/html; charset=utf-8');res.writeHead(200);res.end(demoHTML(data));return;
    }
    send(404,{error:'Not found'});
  });
  await new Promise((resolve,reject)=>{server.once('error',reject);server.listen(initial.port,'127.0.0.1',resolve);});
  const timer=setInterval(()=>{try{const d=JSON.parse(fs.readFileSync(dataFile,'utf8'));if(d.stop||d.instanceId!==initial.instanceId){clearInterval(timer);server.close();}}catch{clearInterval(timer);server.close();}},500);
  process.on('SIGTERM',()=>{clearInterval(timer);server.close();});process.on('SIGINT',()=>{clearInterval(timer);server.close();});
}
function demoHTML(data){return `<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Ledger · Bypass demo</title><style>
*{box-sizing:border-box}body{margin:0;background:#101510;color:#f0f4e8;font:16px/1.55 system-ui,sans-serif}main{max-width:1080px;margin:auto;padding:52px 28px}.brand{font-size:14px;letter-spacing:.16em;color:#a4c595}header{display:flex;justify-content:space-between;gap:24px;align-items:center;border-bottom:1px solid #33412e;padding-bottom:24px}h1{font-size:64px;line-height:1.05;letter-spacing:-.06em;margin:40px 0 18px}h2{font-size:24px;letter-spacing:-.03em}.muted{color:#adb8a7}.status{color:${data.fixed?'#c5f393':'#ffbd80'};border:1px solid currentColor;border-radius:99px;padding:7px 14px;font-size:13px}.grid{display:grid;grid-template-columns:1fr 1fr;gap:24px;margin-top:36px}.panel{border:1px solid #3a4733;border-radius:16px;padding:28px;background:#192017}button{background:#d0f2a2;color:#15200e;border:0;border-radius:7px;padding:12px 16px;font:600 15px system-ui;cursor:pointer;width:100%;margin-top:18px}button:hover{background:#e4ffc0}pre{white-space:pre-wrap;word-break:break-word;min-height:130px;color:#d6e3cb;font-size:13px}.value{font-size:42px;font-weight:600;letter-spacing:-.05em;margin:8px 0}.badge{font-size:12px;color:#a4c595}footer{border-top:1px solid #33412e;margin-top:36px;padding-top:20px;color:#87977f;font-size:13px}@media(max-width:650px){h1{font-size:44px}.grid{grid-template-columns:1fr}header{align-items:flex-start;flex-direction:column}}
</style><main><header><div class="brand">LEDGER / BYPASS LABS</div><span class="status">${data.fixed?'Ownership check enabled':'Deliberately vulnerable fixture'}</span></header><h1>Same invoice.<br>Two different accounts.</h1><p class="muted">A real local HTTP app for testing the complete Bypass journey.<br>The credentials and invoice below are public demo data.</p><div class="grid"><section class="panel"><span class="badge">ACCOUNT 01 · ACME · OWNER</span><h2>Invoice #ACME-001</h2><p class="value">$4,200.00</p><p class="muted">This account should always have access.</p><button onclick="loadInvoice('owner')">Read as the owner</button><pre id="owner">Ready to request the invoice.</pre></section><section class="panel"><span class="badge">ACCOUNT 02 · GLOBEX · NON-OWNER</span><h2>Try the same invoice</h2><p class="value">Access check</p><p class="muted">This account should receive a denial.</p><button onclick="loadInvoice('outsider')">Read as another account</button><pre id="outsider">Ready to test the account boundary.</pre></section></div><footer>Local fixture only · No real customer data · ${data.exportEnabled?'New export route is enabled · ':''}Refresh after running bypass demo fix or bypass demo regress.</footer></main><script>async function loadInvoice(who){const el=document.getElementById(who);el.textContent='Requesting…';try{const r=await fetch('/api/invoices/invoice-acme-001',{headers:{Authorization:'Bearer '+(who==='owner'?'demo-acme-token':'demo-globex-token')}});el.textContent='HTTP '+r.status+'\\n'+JSON.stringify(await r.json(),null,2)}catch(e){el.textContent=e.message}}</script></html>`;}
