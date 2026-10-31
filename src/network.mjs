import http from 'node:http';
import https from 'node:https';
import dns from 'node:dns/promises';
import net from 'node:net';
import { randomBytes } from 'node:crypto';
import { need, Fault, now, duration, delay, hash, abortable, abortFault } from './util.mjs';
import { ownershipReady, authorizationRevoked } from './ownership-store.mjs';
import { httpMethods } from './http-methods.mjs';

export const loopback = h => ['localhost','127.0.0.1','::1','[::1]'].includes(h.toLowerCase());
export function appOriginInput(value) {
  const text=value.trim().replace(/^\[[^\]\n]*\]\(([^)\n]+)\)$/,'$1');
  const candidate=/^[a-z][a-z0-9+.-]*:\/\//i.test(text)?text:`${/^(localhost|127\.0\.0\.1|\[::1\])(?::\d+)?(?:\/|$)/i.test(text)?'http':'https'}://${text}`;
  let url;try{url=new URL(candidate);}catch{throw new Fault('Enter a domain such as job-radar.app, or a local URL such as http://localhost:3000.');}
  need(url.hostname.includes('.')||loopback(url.hostname),'Enter a complete domain, such as job-radar.app.');
  return targetURL(url.href,loopback(url.hostname)?'local':'staging');
}
export function publicIP(address) {
  if (net.isIP(address) === 4) {
    const [a,b,c] = address.split('.').map(Number);
    return !(a===0 || a===10 || a===127 || a>=224 || (a===100 && b>=64 && b<=127) || (a===169 && b===254) || (a===172 && b>=16 && b<=31) || (a===192 && (b===168 || b===0 || (b===88 && c===99))) || (a===198 && (b===18 || b===19 || (b===51 && c===100))) || (a===203 && b===0 && c===113));
  }
  return net.isIP(address) === 6 && /^[23][0-9a-f]{3}:/i.test(address) && !/^(2001:(db8|0|10|20):|2002:)/i.test(address);
}
export function targetURL(value, environment) {
  let url; try { url = new URL(value); } catch { throw new Fault('Enter a complete URL, e.g. https://staging.example.com.'); }
  need(!url.username && !url.password && !url.search && !url.hash, 'Target URLs cannot contain credentials, queries, or fragments.');
  need(url.pathname === '/', 'Use an origin URL. Restrict paths with target authorize.');
  need(['local','preview','staging','production'].includes(environment), 'Environment must be local, preview, staging, or production.');
  if (environment === 'local') need(loopback(url.hostname) && ['http:','https:'].includes(url.protocol), 'Local targets must use a loopback host.');
  else need(url.protocol === 'https:' && !loopback(url.hostname), 'Deployed targets require HTTPS and a non-loopback hostname.');
  return url.origin;
}
export function makeChallenge(project, target) {
  const token = randomBytes(24).toString('base64url');
  const challengeId = hash(`${project.id}:${target.url}:${token}`).slice(0,24);
  return {id:challengeId, token:`bypass-verification=${token}`, projectId:project.id, origin:target.url,
    record:`_bypass-verification.${new URL(target.url).hostname}`, httpPath:`/.well-known/bypass-verification/${challengeId}`, createdAt:now(),expiresAt:new Date(Date.now()+86400000).toISOString()};
}
export function pathAllowed(urlPath, paths) {
  // Reject encoded separators/traversal rather than allowing URL normalization to widen scope.
  if (/%(?:2f|5c|2e|25)/i.test(urlPath) || urlPath.includes('\\') || urlPath.split('/').includes('..')) return false;
  return paths.some(p => p === '/' || urlPath === p || urlPath.startsWith(p.endsWith('/') ? p : p+'/'));
}
export function scopeReady(target, pathname, method) {
  need(target.url&&ownershipReady(target), 'Target ownership is missing or expired. Verify ownership, or explicitly authorize the scope when project verification is off.', 3);
  const auth = target.authorization;
  need(auth && !authorizationRevoked(target) && auth.origin === target.url && Date.parse(auth.expiresAt) > Date.now(), 'Target authorization is missing, expired or revoked. Run target authorize.', 3);
  const required=method||(pathname?'GET':null);
  const exactXmlPost=required==='POST' && typeof pathname==='string' &&
    auth.xmlPostPaths?.includes(pathname);
  if(required)need(auth.methods.includes(required)||exactXmlPost, `Method ${required} is outside the authorized scope. Allowed: ${auth.methods.join(', ')}. Update testing permission to include ${required} before retrying.`, 3);
  if (pathname) need(pathAllowed(pathname,auth.paths), `Path ${pathname} is outside the authorized scope.`, 3);
  return true;
}
export async function safeRequest(value, {allowLocal=false,allowPrivate=false,allowRemoteHttp=false,method='GET',headers={},body,timeout=8000,maxBytes=131072,signal,onHeaders,onChunk} = {}) {
  if(signal?.aborted)throw abortFault(signal);
  const url = new URL(value);
  need(!url.username && !url.password, 'URL credentials are not allowed.');
  const host = url.hostname.replace(/^\[|\]$/g,'');
  need(['http:','https:'].includes(url.protocol), 'Only HTTP(S) is supported.');
  const local = loopback(host);
  const anonymousHttp = allowRemoteHttp === true && ['GET','HEAD'].includes(method) &&
    body == null && !Object.keys(headers).some(name => /^(authorization|proxy-authorization|cookie)$/i.test(name));
  need((local && allowLocal) || (!local && (url.protocol === 'https:' || anonymousHttp)), 'Remote requests require HTTPS unless explicitly scoped anonymous HTTP reads; local requests require explicit local scope.', 3);
  let addresses;
  try { addresses = net.isIP(host) ? [{address:host,family:net.isIP(host)}] : await abortable(dns.lookup(host,{all:true}),signal); }
  catch { if(signal?.aborted)throw abortFault(signal);throw new Fault(`DNS lookup failed for ${host}.`,3); }
  if(signal?.aborted)throw abortFault(signal);
  need(addresses.length && addresses.every(a=>local ? loopback(a.address) : publicIP(a.address) || (allowPrivate && !loopback(a.address) && a.address!=='169.254.169.254')), 'Destination resolves to a blocked or private network address.', 3);
  const chosen = addresses[0];
  return new Promise((resolve,reject) => {
    const client = url.protocol === 'https:' ? https : http;
    const requestHeaders={Accept:'application/json','User-Agent':'Bypass-Skeleton/0.1',...headers};
    if(body!=null&&!Object.keys(requestHeaders).some(name=>/^(content-length|transfer-encoding)$/i.test(name)))
      requestHeaders['Content-Length']=Buffer.byteLength(body);
    const request = client.request(url, {method,headers:requestHeaders,
      agent:false, family:chosen.family, servername:net.isIP(host) ? undefined : host,
      lookup:(_host,opts,cb)=>opts?.all ? cb(null,[chosen]) : cb(null,chosen.address,chosen.family), signal}, response => {
      onHeaders?.({status:response.statusCode,headers:response.headers});
      let bytes=0; const chunks=[];
      response.on('data',chunk=>{ bytes+=chunk.length; if(bytes>maxBytes) request.destroy(new Error('Response exceeds size limit')); else if(onChunk)onChunk(chunk); else chunks.push(chunk); });
      response.on('end',()=>{const data=Buffer.concat(chunks);
        resolve({status:response.statusCode,body:data.toString('utf8'),
          prefixHex:data.subarray(0,16).toString('hex'),headers:response.headers});});
      response.on('error',()=>reject(new Fault('Response interrupted.',3)));
    });
    request.setTimeout(timeout,()=>request.destroy(new Error('Request timeout')));
    request.on('error', e=>reject(new Fault(e.name==='AbortError' ? 'Request cancelled.' : `Request failed: ${e.code || e.message}`,3)));
    request.end(body);
  });
}
export async function verifyOwnership(target, method, {wait,signal} = {}) {
  if (target.environment==='local') {
    need(method==='local', 'For loopback use --method local to acknowledge local ownership.');
    return {status:'verified',method:'local',verifiedAt:now(),expiresAt:new Date(Date.now()+30*86400000).toISOString(),origin:target.url};
  }
  need(['dns','http'].includes(method), 'Choose --method dns or --method http.');
  const c=target.challenge;
  need(c && c.origin===target.url && Date.parse(c.expiresAt)>Date.now(), 'Ownership challenge expired. Renew it, publish the new TXT value, then verify again.',3,{challenge:c,expired:true,alternative:{tool:'bypass_scan',arguments:{mode:'code'}}});
  const deadline=Date.now()+(wait ? duration(wait) : 0);
  do {
    let match=false;
    if(method==='dns') {
      try { match=(await dns.resolveTxt(c.record)).some(parts=>parts.join('')===c.token); } catch { /* pending DNS is an expected state */ }
    } else {
      try { const r=await safeRequest(target.url+c.httpPath,{signal}); match=r.status===200 && r.body.trim()===c.token; } catch { /* remain pending */ }
    }
    if(match) return {status:'verified',method,verifiedAt:now(),expiresAt:new Date(Date.now()+30*86400000).toISOString(),origin:target.url};
    if (Date.now()>=deadline) break;
    await delay(Math.min(2000,deadline-Date.now()),undefined,{signal});
  } while (!signal?.aborted);
  throw new Fault('Ownership is still pending. Publish the exact TXT record or HTTP challenge and retry.',3,{challenge:c,alternative:{tool:'bypass_scan',arguments:{mode:'code'},command:'scan --mode code',message:'Review source now while DNS propagates; no live requests will be made.'}});
}
export function authorization(target, scope, acceptedBy = 'local operator') {
  need(ownershipReady(target),'Verify control before authorizing testing.',3);
  need(Array.isArray(scope.paths) && scope.paths.length && scope.paths.every(p=>typeof p==='string' && p.startsWith('/') && !/[?#*\\]/.test(p) && pathAllowed(p,[p])), 'Scope requires explicit path prefixes, e.g. ["/api"].');
  const methods=httpMethods(scope.methods);
  const exactPath = p => typeof p==='string' && p.startsWith('/') &&
    !/[?#%\\;*]/.test(p) && !p.split('/').some(segment=>segment==='.'||segment==='..') &&
    pathAllowed(p,scope.paths);
  const loginPaths=scope.loginPaths ?? [];
  need(Array.isArray(loginPaths) && loginPaths.every(exactPath),
    'loginPaths must list exact non-query paths inside the authorized paths.');
  const xmlPostPaths=scope.xmlPostPaths ?? [];
  need(Array.isArray(xmlPostPaths) && xmlPostPaths.length<=20 && xmlPostPaths.every(exactPath),
    'xmlPostPaths must list at most 20 exact non-query paths inside the authorized paths.');
  const writeOperations=scope.writeOperations ?? [];
  need(Array.isArray(writeOperations) && writeOperations.length<=100 &&
    writeOperations.every(item=>item && typeof item==='object' &&
      ['POST','PUT','PATCH','DELETE','OPTIONS'].includes(item.method) &&
      ['json','form','xml','query','header'].includes(item.placement) &&
      (item.method!=='OPTIONS'||['query','header'].includes(item.placement)) &&
      methods.includes(item.method) && typeof item.path==='string' &&
      /^\/[A-Za-z0-9/_.-]{1,200}$/.test(item.path) && !item.path.endsWith('/') &&
      !item.path.split('/').some(segment=>segment==='.'||segment==='..') &&
      pathAllowed(item.path,scope.paths)),
    'writeOperations must list at most 100 exact method, path, and placement contracts inside the authorized paths.');
  const rps=scope.maxRequestsPerSecond ?? 2;
  need(Number.isFinite(rps)&&rps>0&&rps<=32,'maxRequestsPerSecond must be between 0 and 32.');
  const expiresAt=scope.expiresAt ?? new Date(Date.now()+7*86400000).toISOString();
  need(Date.parse(expiresAt)>Date.now() && Date.parse(expiresAt)<=Date.now()+30*86400000, 'Authorization expiry must be within 30 days.');
  need(target.environment!=='production' || scope.productionAcknowledged===true, 'Production scope requires productionAcknowledged: true.');
  return {...(scope.publicConfigDiscovery===true?{publicConfigDiscovery:true}:{}),origin:target.url,paths:[...new Set(scope.paths)],methods,
    ...(loginPaths.length?{loginPaths:[...new Set(loginPaths)]}:{}),
    ...(xmlPostPaths.length?{xmlPostPaths:[...new Set(xmlPostPaths)]}:{}),
    ...(writeOperations.length?{writeOperations:[...new Map(writeOperations.map(item=>
      [`${item.method} ${item.path} ${item.placement}`,
        {method:item.method,path:item.path,placement:item.placement}])).values()]}:{}),
    maxRequestsPerSecond:rps,expiresAt,acceptedAt:now(),acceptedBy,productionAcknowledged:!!scope.productionAcknowledged};
}
