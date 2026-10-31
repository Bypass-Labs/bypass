import fs from 'node:fs';
import path from 'node:path';
import { createHash } from 'node:crypto';
import {releaseInventory,readReleaseFile,verifyChecksums} from './release-files.mjs';
const base='https://bypasslabs.ai/downloads/bypass',dist=path.resolve('dist/releases');
// Keep automated writes separate from the marketing site's browser/WAF rules.
// The audience and strict GitHub workflow identity checks are unchanged.
const publisher='https://bypass-distribution.maksim-b26.workers.dev/downloads/bypass';
const {manifest:release,files}=releaseInventory(fs.readFileSync(path.join(dist,'release.json')),process.env.GITHUB_SHA);
if(!process.env.GITHUB_SHA)throw new Error('Publishing requires the CI commit identity');
async function token(){
  const url=new URL(process.env.ACTIONS_ID_TOKEN_REQUEST_URL);url.searchParams.set('audience',base);
  const response=await fetch(url,{headers:{Authorization:`Bearer ${process.env.ACTIONS_ID_TOKEN_REQUEST_TOKEN}`},signal:AbortSignal.timeout(15000)});
  if(!response.ok)throw new Error('GitHub OIDC token unavailable');
  const result=await response.json();if(typeof result.value!=='string')throw new Error('Missing GitHub OIDC identity');return result.value;
}
if(process.argv.includes('--promote')){
  const response=await fetch(publisher+'/_publish/promote',{method:'POST',body:JSON.stringify({releaseId:release.releaseId}),headers:{Authorization:`Bearer ${await token()}`,'Content-Type':'application/json'},signal:AbortSignal.timeout(30000)});
  if(!response.ok)throw new Error(`Promotion failed: HTTP ${response.status}: ${(await response.text()).slice(0,200)}`);
  console.log(await response.text());
}else{
  for(const file of files){
    const bytes=readReleaseFile(dist,file);
    if(file.file==='SHASUMS256.txt')verifyChecksums(bytes,release);
  }
  for(const metadata of files){
    const file=metadata.file,bytes=readReleaseFile(dist,metadata),sha256=createHash('sha256').update(bytes).digest('hex');
    const response=await fetch(`${publisher}/_publish/releases/${release.releaseId}/${file}`,{method:'PUT',body:bytes,headers:{Authorization:`Bearer ${await token()}`,'Content-Length':String(bytes.length),'Content-Type':file.endsWith('.json')?'application/json':'application/octet-stream','X-Bypass-Sha256':sha256},signal:AbortSignal.timeout(180000)});
    if(!response.ok)throw new Error(`Upload ${file} failed: HTTP ${response.status}: ${(await response.text()).slice(0,200)}`);
    console.log(`Uploaded ${file} (${bytes.length} bytes)`);
  }
}
