import { authorizePublisher } from './auth.mjs';
export const platforms=['darwin-arm64','darwin-x64','linux-arm64','linux-x64'];
const prefix='/downloads/bypass/';
const releasePattern=/^main-[a-f0-9]{40}-[1-9][0-9]{0,15}-[1-9][0-9]{0,15}$/;
const filePattern=/^(bypass-(?:darwin|linux)-(?:arm64|x64)\.tar\.gz|SHASUMS256\.txt|release\.json|install\.sh)$/;
const digestPattern=/^[a-f0-9]{64}$/;
const headers={'X-Content-Type-Options':'nosniff','Cache-Control':'no-store','Strict-Transport-Security':'max-age=31536000; includeSubDomains'};
const reply=(message,status=200,extra={})=>new Response(message,{status,headers:{...headers,...extra}});
const contentType=file=>file.endsWith('.tar.gz')?'application/gzip':file.endsWith('.json')?'application/json; charset=utf-8':'text/plain; charset=utf-8';
const validRelease=(release,claims)=>release.schemaVersion===1&&release.releaseId===claims.releaseId&&release.commit===claims.sha&&/^\d+\.\d+\.\d+(?:[-+][a-zA-Z0-9.-]+)?$/.test(release.version);
export async function promote(bucket,claims){
  const base=`releases/${claims.releaseId}/`,manifest=await bucket.get(base+'release.json');
  if(!manifest||manifest.size>16384)return reply('Release manifest missing or too large',409);
  const release=await manifest.json();
  if(!validRelease(release,claims)||!Array.isArray(release.assets)||release.assets.length!==4)return reply('Invalid release manifest',409);
  const expected=platforms.map(platform=>`bypass-${platform}.tar.gz`);
  if(!expected.every(file=>release.assets.filter(a=>a.file===file).length===1)||release.installer?.file!=='install.sh'||release.checksums?.file!=='SHASUMS256.txt')return reply('Incomplete platform set',409);
  for(const asset of [...release.assets,release.installer,release.checksums]){
    if(!digestPattern.test(asset.sha256)||!Number.isInteger(asset.size)||asset.size<1||asset.size>100000000)return reply('Invalid asset metadata',409);
    const object=await bucket.head(base+asset.file);
    if(!object||object.size!==asset.size||object.customMetadata?.sha256!==asset.sha256)return reply('Release asset missing or checksum mismatch',409);
  }
  const checksumFile=await bucket.get(base+'SHASUMS256.txt');
  if(checksumFile.size>2048)return reply('Invalid checksum file',409);
  const checksums=await checksumFile.text();
  if(!release.assets.every(a=>checksums.split('\n').includes(`${a.sha256}  ${a.file}`)))return reply('Checksum list does not match release',409);
  const currentObject=await bucket.get('channels/main.json'),current=currentObject?await currentObject.json():null;
  const incoming=[Number(claims.run_number),Number(claims.run_attempt)],previous=[Number(current?.runNumber||0),Number(current?.runAttempt||0)];
  if(incoming[0]<previous[0]||(incoming[0]===previous[0]&&incoming[1]<previous[1]))return reply('A newer CI run is already published',409);
  const value={...release,runNumber:incoming[0],runAttempt:incoming[1],publishedAt:new Date().toISOString()};
  const written=await bucket.put('channels/main.json',JSON.stringify(value),{httpMetadata:{contentType:'application/json'},onlyIf:currentObject?{etagMatches:currentObject.etag}:{etagDoesNotMatch:'*'}});
  if(!written)return reply('Release changed concurrently; retry promotion',409);
  return reply(JSON.stringify({published:true,releaseId:claims.releaseId}),200,{'Content-Type':'application/json'});
}
export function createHandler(authorize=authorizePublisher){return async(request,env)=>{
  try{
    const url=new URL(request.url),pathname=url.pathname;
    if(pathname.startsWith(prefix+'_publish/')){
      if(!['PUT','POST'].includes(request.method))return reply('Method not allowed',405,{Allow:'PUT, POST'});
      let claims;try{claims=await authorize(request,env);}catch{return reply('Publisher authentication failed',401);}
      if(request.method==='POST'&&pathname===prefix+'_publish/promote')return await promote(env.RELEASES,claims);
      const match=pathname.match(/^\/downloads\/bypass\/_publish\/releases\/([^/]+)\/([^/]+)$/);
      if(request.method!=='PUT'||!match||match[1]!==claims.releaseId||!filePattern.test(match[2]))return reply('Upload outside this CI run',403);
      const digest=request.headers.get('x-bypass-sha256'),length=Number(request.headers.get('content-length'));
      const maximum=match[2].endsWith('.tar.gz')?100000000:65536;
      if(!digestPattern.test(digest||'')||!Number.isInteger(length)||length<1||length>maximum)return reply('Invalid artifact size or digest',400);
      const key=`releases/${match[1]}/${match[2]}`,existing=await env.RELEASES.head(key);
      if(existing)return existing.customMetadata?.sha256===digest&&existing.size===length?reply('Already uploaded'):reply('Immutable artifact already exists',409);
      const written=await env.RELEASES.put(key,request.body,{sha256:digest,onlyIf:{etagDoesNotMatch:'*'},customMetadata:{sha256:digest,commit:claims.sha},httpMetadata:{contentType:contentType(match[2])}});
      return written?reply('Uploaded',201):reply('Artifact changed concurrently',409);
    }
    if(!['GET','HEAD'].includes(request.method))return reply('Method not allowed',405,{Allow:'GET, HEAD'});
    let key,cache='public, max-age=31536000, immutable';
    if(pathname==='/install'||pathname==='/install/'||pathname===prefix+'channels/main.txt'||pathname===prefix+'channels/main.json'){
      const latest=await env.RELEASES.get('channels/main.json');if(!latest)return reply('The first Bypass release is not published yet. Retry shortly.',503,{'Retry-After':'30'});
      const current=await latest.json();if(!releasePattern.test(current.releaseId))return reply('Release metadata unavailable',503);
      if(pathname.endsWith('main.txt'))return reply(request.method==='HEAD'?null:current.releaseId+'\n',200,{'Content-Type':'text/plain; charset=utf-8'});
      if(pathname.endsWith('main.json'))return reply(request.method==='HEAD'?null:JSON.stringify(current),200,{'Content-Type':'application/json; charset=utf-8'});
      key=`releases/${current.releaseId}/install.sh`;cache='no-store';
    }else{
      const match=pathname.match(/^\/downloads\/bypass\/releases\/([^/]+)\/([^/]+)$/);
      if(!match||!releasePattern.test(match[1])||!filePattern.test(match[2]))return reply('Not found',404);
      key=`releases/${match[1]}/${match[2]}`;
    }
    const object=await env.RELEASES.get(key);if(!object)return reply('Not found',404);
    const responseHeaders=new Headers({...headers,'Cache-Control':cache,'Content-Type':contentType(key),'Content-Length':String(object.size),ETag:object.httpEtag});
    if(request.headers.get('if-none-match')===object.httpEtag)return new Response(null,{status:304,headers:responseHeaders});
    return new Response(request.method==='HEAD'?null:object.body,{headers:responseHeaders});
  }catch{return reply('Release service unavailable; retry shortly',503,{'Retry-After':'10'});}
};}
export default {fetch:createHandler()};
