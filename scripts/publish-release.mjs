import fs from 'node:fs';
import path from 'node:path';
import { createHash } from 'node:crypto';
const base='https://bypasslabs.ai/downloads/bypass',dist=path.resolve('dist/releases');
// Keep automated writes separate from the marketing site's browser/WAF rules.
// The audience and strict GitHub workflow identity checks are unchanged.
const publisher='https://bypass-distribution.maksim-b26.workers.dev/downloads/bypass';
const release=JSON.parse(fs.readFileSync(path.join(dist,'release.json')));
if(release.commit!==process.env.GITHUB_SHA)throw new Error('Release does not match this CI commit');
async function token(){
  const url=new URL(process.env.ACTIONS_ID_TOKEN_REQUEST_URL);url.searchParams.set('audience',base);
  const response=await fetch(url,{headers:{Authorization:`Bearer ${process.env.ACTIONS_ID_TOKEN_REQUEST_TOKEN}`},signal:AbortSignal.timeout(15000)});
  if(!response.ok)throw new Error('GitHub OIDC token unavailable');
  const result=await response.json();if(typeof result.value!=='string')throw new Error('Missing GitHub OIDC identity');return result.value;
}
const files=[...release.assets.map(a=>a.file),'install.sh','SHASUMS256.txt','release.json'];
if(process.argv.includes('--promote')){
  const response=await fetch(publisher+'/_publish/promote',{method:'POST',headers:{Authorization:`Bearer ${await token()}`},signal:AbortSignal.timeout(30000)});
  if(!response.ok)throw new Error(`Promotion failed: HTTP ${response.status}: ${(await response.text()).slice(0,200)}`);
  console.log(await response.text());
}else{
  for(const file of files){
    const location=path.join(dist,file),bytes=fs.readFileSync(location),sha256=createHash('sha256').update(bytes).digest('hex');
    const response=await fetch(`${publisher}/_publish/releases/${release.releaseId}/${file}`,{method:'PUT',body:bytes,headers:{Authorization:`Bearer ${await token()}`,'Content-Length':String(bytes.length),'Content-Type':file.endsWith('.json')?'application/json':'application/octet-stream','X-Bypass-Sha256':sha256},signal:AbortSignal.timeout(180000)});
    if(!response.ok)throw new Error(`Upload ${file} failed: HTTP ${response.status}: ${(await response.text()).slice(0,200)}`);
    console.log(`Uploaded ${file} (${bytes.length} bytes)`);
  }
}
