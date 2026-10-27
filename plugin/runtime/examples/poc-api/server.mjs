import http from 'node:http';
import fs from 'node:fs';
import { pathToFileURL } from 'node:url';
import { createHash } from 'node:crypto';
const port=Number(process.env.PORT||4329);
const tokens=new Map([['poc-owner-token','account-alice'],['poc-outsider-token','account-bob']]);
const invoice={id:'inv-101',ownerId:'account-alice',amount:120};
const policy=new URL('./policy.mjs',import.meta.url);
http.createServer(async(req,res)=>{
  res.setHeader('Content-Type','application/json');res.setHeader('Cache-Control','no-store');
  const send=(status,value)=>{res.writeHead(status);res.end(JSON.stringify(value));};
  const account=tokens.get((req.headers.authorization||'').replace(/^Bearer /,''));
  if(req.method!=='GET')return send(405,{error:'Read only'});
  if(req.url==='/api/me')return account?send(200,{id:account}):send(401,{error:'Sign in'});
  if(req.url==='/api/invoices/inv-101'){
    if(!account)return send(401,{error:'Sign in'});
    try{
      const source=fs.readFileSync(policy,'utf8'),version=createHash('sha256').update(source).digest('hex');
      const {mayReadInvoice}=await import(policy.href+'?v='+version);
      return mayReadInvoice(account,invoice)?send(200,invoice):send(403,{error:'Not your invoice'});
    }catch{return send(500,{error:'Cannot load policy'});}
  }
  return send(404,{error:'Not found'});
}).listen(port,'127.0.0.1',()=>console.log(`POC API http://127.0.0.1:${port}`));
