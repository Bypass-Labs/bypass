import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { authorizePublisher } from '../infra/releases/auth.mjs';
import { createHandler, platforms } from '../infra/releases/worker.mjs';
const env={GITHUB_REPOSITORY:'Bypass-Labs/bypass-for-muse',GITHUB_REPOSITORY_ID:'123',GITHUB_OWNER_ID:'456',PUBLISH_AUDIENCE:'https://bypasslabs.ai/downloads/bypass'};
const now=Math.floor(Date.now()/1000),commit='a'.repeat(40);
const claims={iss:'https://token.actions.githubusercontent.com',aud:env.PUBLISH_AUDIENCE,sub:'repo:Bypass-Labs@456/bypass-for-muse@123:ref:refs/heads/main',repository:env.GITHUB_REPOSITORY,repository_id:'123',repository_owner_id:'456',ref:'refs/heads/main',ref_type:'branch',workflow_ref:env.GITHUB_REPOSITORY+'/.github/workflows/release.yml@refs/heads/main',workflow_sha:commit,sha:commit,event_name:'push',runner_environment:'github-hosted',run_id:'1234',run_number:'2',run_attempt:'1',exp:now+300,iat:now,nbf:now-5};
const encode=value=>Buffer.from(typeof value==='string'?value:JSON.stringify(value)).toString('base64url');
const digest=value=>createHash('sha256').update(value).digest('hex');
const releaseId=`main-${commit}-1234-1`;
class Bucket{
  values=new Map();
  async put(key,value,options={}){
    const old=this.values.get(key),condition=options.onlyIf;
    if(condition?.etagDoesNotMatch==='*'&&old||condition?.etagMatches&&old?.etag!==condition.etagMatches)return null;
    const bytes=Buffer.from(await new Response(value).arrayBuffer());
    if(options.sha256&&digest(bytes)!==options.sha256)throw new Error('R2 checksum mismatch');
    const object={bytes,size:bytes.length,etag:digest(bytes),customMetadata:options.customMetadata};this.values.set(key,object);return object;
  }
  async get(key){const o=this.values.get(key);return o?{...o,httpEtag:'"'+o.etag+'"',body:o.bytes,json:async()=>JSON.parse(o.bytes),text:async()=>o.bytes.toString()}:null;}
  async head(key){return this.get(key);}
}
test('publishing accepts only a signed, unexpired identity for the exact main workflow and immutable repository IDs',async()=>{
  const pair=await crypto.subtle.generateKey({name:'RSASSA-PKCS1-v1_5',modulusLength:2048,publicExponent:new Uint8Array([1,0,1]),hash:'SHA-256'},true,['sign','verify']);
  const jwk={...await crypto.subtle.exportKey('jwk',pair.publicKey),kid:'test-key',use:'sig',alg:'RS256'};
  async function request(changes={}){const unsigned=encode({kid:'test-key',alg:'RS256'})+'.'+encode({...claims,...changes});const signature=Buffer.from(await crypto.subtle.sign('RSASSA-PKCS1-v1_5',pair.privateKey,new TextEncoder().encode(unsigned))).toString('base64url');return new Request('https://bypasslabs.ai/downloads/bypass/_publish/promote',{headers:{Authorization:`Bearer ${unsigned}.${signature}`}});}
  const options={now,fetchKeys:async()=>[jwk]};assert.equal((await authorizePublisher(await request(),env,options)).releaseId,releaseId);
  for(const change of [{repository_id:'999'},{repository_owner_id:'999'},{sub:`repo:${env.GITHUB_REPOSITORY}:ref:refs/heads/main`},{sub:claims.sub.replace('@123','@999')},{ref:'refs/pull/1/merge'},{workflow_ref:env.GITHUB_REPOSITORY+'/.github/workflows/evil.yml@refs/heads/main'},{exp:now-1},{aud:'another-service'},{event_name:'pull_request_target'},{workflow_sha:'b'.repeat(40)}])await assert.rejects(authorizePublisher(await request(change),env,options));
  const forged=await request();forged.headers.set('authorization',forged.headers.get('authorization').slice(0,-8)+'xxxxxxxx');await assert.rejects(authorizePublisher(forged,env,options));
});
test('R2 uploads are immutable, promotion requires every verified asset, and old runs cannot replace main',async()=>{
  const bucket=new Bucket(),identity={...claims,releaseId},handler=createHandler(async()=>identity),bindings={RELEASES:bucket};
  const upload=async(file,bytes)=>handler(new Request(`https://bypasslabs.ai/downloads/bypass/_publish/releases/${releaseId}/${file}`,{method:'PUT',body:bytes,headers:{'content-length':String(bytes.length),'x-bypass-sha256':digest(bytes)}}),bindings);
  const assets=[];
  for(const platform of platforms){const file=`bypass-${platform}`+(platform.startsWith('win-')?'.zip':'.tar.gz'),bytes=Buffer.from(platform);assert.equal((await upload(file,bytes)).status,201);assets.push({file,sha256:digest(bytes),size:bytes.length});}
  assert.equal((await upload(assets[0].file,Buffer.from('changed'))).status,409);
  const installer=Buffer.from('#!/bin/bash\necho install\n'),checksums=Buffer.from(assets.map(a=>`${a.sha256}  ${a.file}`).join('\n')+'\n');
  const windowsInstaller=Buffer.from('Write-Host "Windows install"\n');
  const release={schemaVersion:1,releaseId,commit,version:'0.3.3',assets,installer:{file:'install.sh',sha256:digest(installer),size:installer.length},windowsInstaller:{file:'install.ps1',sha256:digest(windowsInstaller),size:windowsInstaller.length},checksums:{file:'SHASUMS256.txt',sha256:digest(checksums),size:checksums.length}};
  const bootstrap=[['museInstaller','install-muse.sh'],['museWindowsInstaller','install-muse.ps1'],['installSkill','install-muse.md']];
  for(const [key,file] of bootstrap){const bytes=Buffer.from('bootstrap '+file);release[key]={file,sha256:digest(bytes),size:bytes.length};}
  await upload('release.json',Buffer.from(JSON.stringify(release)));
  const promote=()=>handler(new Request('https://bypasslabs.ai/downloads/bypass/_publish/promote',{method:'POST'}),bindings);
  assert.equal((await promote()).status,409);assert.equal(await bucket.get('channels/main.json'),null);
  await upload('install.sh',installer);await upload('SHASUMS256.txt',checksums);assert.equal((await promote()).status,409);
  await upload('install.ps1',windowsInstaller);assert.equal((await promote()).status,409);
  for(const [,file] of bootstrap)await upload(file,Buffer.from('bootstrap '+file));
  assert.equal((await promote()).status,200);
  for(const [route,file] of [['/install/muse','install-muse.sh'],['/install/muse.ps1','install-muse.ps1'],['/install/muse.md','install-muse.md']]){
    const response=await handler(new Request('https://bypasslabs.ai'+route),bindings);
    assert.equal(response.status,200);assert.equal(await response.text(),'bootstrap '+file);assert.equal(response.headers.get('cache-control'),'no-store');
    assert.equal((await handler(new Request('https://bypasslabs.ai'+route,{method:'HEAD'}),bindings)).status,200);
  }
  const installed=await handler(new Request('https://bypasslabs.ai/install'),bindings);assert.equal(await installed.text(),installer.toString());assert.equal(installed.headers.get('cache-control'),'no-store');
  const windows=await handler(new Request('https://bypasslabs.ai/install.ps1'),bindings);assert.equal(await windows.text(),windowsInstaller.toString());assert.match(windows.headers.get('content-type'),/text\/plain/);
  const promotion=releaseId=>handler(new Request('https://bypasslabs.ai/downloads/bypass/_publish/promote',{method:'POST',body:JSON.stringify({releaseId})}),bindings);
  assert.equal((await promotion(`main-${commit}-9999-1`)).status,403);assert.equal((await promotion(`main-${commit}-1234-2`)).status,403);
  identity.run_attempt='2';assert.equal((await promotion(releaseId)).status,200);
  assert.equal(await (await handler(new Request('https://bypasslabs.ai/downloads/bypass/channels/main.txt'),bindings)).text(),releaseId+'\n');
  const publicAsset=await handler(new Request(`https://bypasslabs.ai/downloads/bypass/releases/${releaseId}/${assets[0].file}`),bindings);assert.match(publicAsset.headers.get('cache-control'),/immutable/);
  identity.run_number='1';assert.equal((await promote()).status,409);
  assert.equal((await handler(new Request('https://bypasslabs.ai/downloads/bypass/private-key'),bindings)).status,404);
  assert.equal((await handler(new Request('https://bypasslabs.ai/install',{method:'POST'}),bindings)).status,405);
});
test('anonymous callers cannot upload or promote, and an empty bucket returns an actionable error',async()=>{
  const handler=createHandler(),bindings={RELEASES:new Bucket()};
  assert.equal((await handler(new Request('https://bypasslabs.ai/downloads/bypass/_publish/promote',{method:'POST'}),bindings)).status,401);
  assert.equal((await handler(new Request('https://bypasslabs.ai/install'),bindings)).status,503);
});
