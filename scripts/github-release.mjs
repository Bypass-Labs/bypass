import fs from 'node:fs';
import path from 'node:path';
import {pathToFileURL} from 'node:url';
import {parseArgs} from 'node:util';
import {releaseInventory,releasePattern,verifyBytes,readReleaseFile,verifyChecksums} from './release-files.mjs';

export const downloadBase='https://bypasslabs.ai/downloads/bypass';
const need=(ok,message)=>{if(!ok)throw new Error(message);};
const pause=ms=>new Promise(resolve=>setTimeout(resolve,ms));

async function boundedBytes(response,limit){
  need(response.ok,`Release download failed: HTTP ${response.status}`);
  need(Number(response.headers.get('content-length')||0)<=limit,'Release download is too large');
  const reader=response.body.getReader(),chunks=[];let size=0;
  try{
    while(true){
      const {done,value}=await reader.read();if(done)break;
      size+=value.length;need(size<=limit,'Release download is too large');chunks.push(Buffer.from(value));
    }
  }finally{await reader.cancel();reader.releaseLock();}
  return Buffer.concat(chunks);
}

export async function loadRelease({dist='dist/releases',releaseId,expectedCommit,fetchImpl=fetch}={}){
  need(!releaseId||releasePattern.test(releaseId),'Invalid R2 release ID');
  const download=async(file,limit)=>boundedBytes(await fetchImpl(`${downloadBase}/releases/${releaseId}/${file}`,{redirect:'error',signal:AbortSignal.timeout(180000)}),limit);
  const bytes=releaseId?await download('release.json',16384):fs.readFileSync(path.join(dist,'release.json'));
  const inventory=releaseInventory(bytes,expectedCommit);
  need(!releaseId||inventory.manifest.releaseId===releaseId,'R2 manifest identity mismatch');
  return {...inventory,read:async file=>file.file==='release.json'?bytes:releaseId?verifyBytes(await download(file.file,file.size),file):readReleaseFile(dist,file)};
}

/** Tokens go only to fixed GitHub API origins, never to R2 or redirect targets. */
export function githubAPI(token,fetchImpl=fetch){
  need(typeof token==='string'&&token.length>0,'Set GH_TOKEN to a GitHub token with contents:write');
  return async(method,route,{body,bytes,missing=false,upload=false}={})=>{
    need(route.startsWith('/repos/')&&!route.includes('..'),'Invalid GitHub route');
    const response=await fetchImpl(`https://${upload?'uploads':'api'}.github.com${route}`,{
      method,redirect:'error',signal:AbortSignal.timeout(180000),
      headers:{Authorization:`Bearer ${token}`,Accept:'application/vnd.github+json','X-GitHub-Api-Version':'2022-11-28',
        ...(bytes?{'Content-Type':'application/octet-stream'}:body?{'Content-Type':'application/json'}:{})},
      ...(bytes?{body:bytes}:body?{body:JSON.stringify(body)}:{})
    });
    if(missing&&response.status===404)return null;
    need(response.ok,`GitHub ${method} ${route.split('?')[0]} failed: HTTP ${response.status}`);
    return response.status===204?null:response.json();
  };
}

export async function mirrorRelease({source,repository,api,mode='archive',fetchImpl=fetch,log=console.log,wait=pause}){
  need(/^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/.test(repository),'Invalid GitHub repository');
  need(['archive','verify','publish'].includes(mode),'Invalid release operation');
  const {manifest,files}=source,base=`/repos/${repository}`,tag=encodeURIComponent(manifest.releaseId);
  if(mode==='archive'){
    // Validate all inputs before creating or modifying a remote release.
    for(const file of files){
      const bytes=verifyBytes(await source.read(file),file);
      if(file.file==='SHASUMS256.txt')verifyChecksums(bytes,manifest);
    }
  }
  // A mismatched tag must never cause the download to point at unrelated source.
  const ref=await api('GET',`${base}/git/ref/tags/${tag}`,{missing:true});
  if(ref)need(ref.object?.type==='commit'&&ref.object.sha===manifest.commit,'Existing release tag does not match the source commit');
  let release=await api('GET',`${base}/releases/tags/${tag}`,{missing:true});
  // The tag endpoint only finds published releases. Drafts have pending tags.
  if(!release){
    for(let page=1;page<=100;page++){
      const candidates=await api('GET',`${base}/releases?per_page=100&page=${page}`);
      need(Array.isArray(candidates),'Invalid GitHub release list');
      const matches=candidates.filter(item=>item.tag_name===manifest.releaseId);
      need(matches.length<=1,'Duplicate pending release tags');
      if(matches.length){release=matches[0];break;}
      if(candidates.length<100)break;
      need(page<100,'Release lookup limit reached; refusing to create a possible duplicate');
    }
  }
  const marker=`Release manifest: \`${manifest.releaseId}\``;
  if(!release){
    need(mode==='archive','GitHub release has not been archived');
    await api('GET',`${base}/commits/${manifest.commit}`);
    release=await api('POST',`${base}/releases`,{body:{tag_name:manifest.releaseId,target_commitish:manifest.commit,
      name:`Bypass ${manifest.version} for Muse Code · ${manifest.commit.slice(0,12)}`,draft:true,prerelease:true,make_latest:'false',
      body:`Native security-testing plugin for Muse Code, with a standalone CLI.\n\n${marker}\nSource commit: \`${manifest.commit}\`\n\nThese are the exact platform archives and installer assets uploaded to R2, not rebuilt packages. Each archive includes the plugin, CLI, and pinned Node.js runtime.\n\nVerify platform archives with SHASUMS256.txt. release.json records SHA-256 and size for every archive and installer. Main snapshots are prereleases; their version number may repeat across distinct commit/run tags.\n\n[Installation and release process](https://github.com/${repository}/blob/${manifest.commit}/docs/RELEASES.md). Each archive retains the license notices present when it was built.\n`}});
  }
  need(release.tag_name===manifest.releaseId&&release.target_commitish===manifest.commit&&release.body?.includes(marker),'Existing GitHub release identity/metadata does not match');
  need(Number.isSafeInteger(release.id)&&release.id>0,'Invalid GitHub release ID');
  const list=async()=>{
    const assets=await api('GET',`${base}/releases/${release.id}/assets?per_page=100`);
    need(Array.isArray(assets)&&assets.length<100,'Unexpected GitHub release asset inventory');
    need(assets.every(a=>files.some(f=>f.file===a.name)),'GitHub release contains unexpected assets');
    need(new Set(assets.map(a=>a.name)).size===assets.length,'GitHub release contains duplicate asset names');
    return assets;
  };
  let assets=await list();
  if(mode==='archive'){
    for(const file of files){
      let existing=assets.find(a=>a.name===file.file);
      if(existing?.state==='starter'&&existing.size===0&&release.draft){
        await api('DELETE',`${base}/releases/assets/${existing.id}`);existing=null;
      }
      if(!existing){
        need(release.draft,'Refusing to modify a published release with missing assets');
        await api('POST',`${base}/releases/${release.id}/assets?name=${encodeURIComponent(file.file)}`,{upload:true,bytes:verifyBytes(await source.read(file),file)});
        log(`Archived ${file.file}`);
      }else need(existing.state==='uploaded'&&existing.size===file.size&&existing.digest===`sha256:${file.sha256}`,`Existing GitHub asset differs; refusing to overwrite ${file.file}`);
    }
  }
  // Check the server-reported digest and size, including release.json itself.
  for(let attempt=0;attempt<4;attempt++){
    assets=await list();
    if(files.every(f=>assets.some(a=>a.name===f.file&&a.state==='uploaded'&&a.size===f.size&&a.digest===`sha256:${f.sha256}`)))break;
    if(attempt===3)throw new Error('GitHub release is incomplete or has a size/checksum mismatch');
    await wait(1000);
  }
  if(mode==='publish'){
    const current=JSON.parse((await boundedBytes(await fetchImpl(`${downloadBase}/channels/main.json`,{redirect:'error',signal:AbortSignal.timeout(30000)}),16384)).toString());
    need(current.releaseId===manifest.releaseId&&current.commit===manifest.commit,'Publish only after this exact release is promoted on R2');
    if(release.draft)release=await api('PATCH',`${base}/releases/${release.id}`,{body:{draft:false,prerelease:true,make_latest:'false'}});
    const published=await api('GET',`${base}/git/ref/tags/${tag}`);
    need(published.object?.type==='commit'&&published.object.sha===manifest.commit,'Published tag does not match the release source');
    need(release.draft===false,'GitHub release is still a draft');
  }
  return {releaseId:manifest.releaseId,url:release.html_url,draft:release.draft,verifiedAssets:files.length};
}

async function main(){
  const {values}=parseArgs({options:{'from-r2':{type:'string'},dist:{type:'string'},verify:{type:'boolean'},publish:{type:'boolean'}}});
  need(!(values.verify&&values.publish),'Choose verify or publish');
  const repository=process.env.GITHUB_REPOSITORY||'Bypass-Labs/bypass-for-muse';
  if(process.env.GITHUB_ACTIONS==='true')need(process.env.GITHUB_REF==='refs/heads/main'&&process.env.GITHUB_SHA,'Release writes require the main workflow');
  const source=await loadRelease({dist:values.dist,releaseId:values['from-r2'],expectedCommit:process.env.GITHUB_SHA});
  const result=await mirrorRelease({source,repository,api:githubAPI(process.env.GH_TOKEN||process.env.GITHUB_TOKEN),mode:values.publish?'publish':values.verify?'verify':'archive'});
  console.log(JSON.stringify(result));
}
if(process.argv[1]&&import.meta.url===pathToFileURL(path.resolve(process.argv[1])).href)main().catch(error=>{console.error(error.message);process.exitCode=1;});
