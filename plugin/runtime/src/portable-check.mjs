// This file is copied into exported suites. Node built-ins only; no Bypass runtime or model.
import http from 'node:http';
import https from 'node:https';
import dns from 'node:dns/promises';
import net from 'node:net';

const localHost=h=>['localhost','127.0.0.1','::1','[::1]'].includes(h);
const publicAddress=address=>{
  if(net.isIP(address)===4){const[a,b,c]=address.split('.').map(Number);return !(a===0||a===10||a===127||a>=224||(a===100&&b>=64&&b<=127)||(a===169&&b===254)||(a===172&&b>=16&&b<=31)||(a===192&&(b===168||b===0||(b===88&&c===99)))||(a===198&&(b===18||b===19||(b===51&&c===100)))||(a===203&&b===0&&c===113));}
  return net.isIP(address)===6&&/^[23][0-9a-f]{3}:/i.test(address)&&!/^(2001:(db8|0|10|20):|2002:)/i.test(address);
};
function assert(value,message){if(!value)throw new Error(message);}
async function request(url,headers,local,signal,timeout=8000){
  const host=url.hostname.replace(/^\[|\]$/g,'');
  const addresses=net.isIP(host)?[{address:host,family:net.isIP(host)}]:await dns.lookup(host,{all:true});
  assert(addresses.length&&addresses.every(a=>local?localHost(a.address):publicAddress(a.address)),'DNS destination is outside the permitted network');
  const chosen=addresses[0];
  return new Promise((resolve,reject)=>{
    const req=(url.protocol==='https:'?https:http).request(url,{method:'GET',headers,signal,agent:false,family:chosen.family,servername:net.isIP(host)?undefined:host,lookup:(_h,o,cb)=>o?.all?cb(null,[chosen]):cb(null,chosen.address,chosen.family)},res=>{
      let body='',bytes=0;res.on('data',b=>{bytes+=b.length;if(bytes>131072)req.destroy(new Error('Response exceeds limit'));else body+=b;});
      res.on('end',()=>resolve({status:res.statusCode,body,contentType:res.headers['content-type']||''}));res.on('error',reject);
    });
    req.setTimeout(timeout,()=>req.destroy(new Error('Request timed out')));req.on('error',reject);req.end();
  });
}
function identityHeaders(identity,env,fixture){
  const value=env[identity.secretEnv] || (fixture?identity.fixtureValue:null);
  assert(value,`Missing account credential ${identity.secretEnv}. In Bypass, import the private account file; in an exported standalone test, supply this variable through CI secrets. Keep tokens out of chat.`);
  assert(!/[\r\n]/.test(value),'Invalid credential value');
  if(identity.type==='bearer')return {Authorization:`Bearer ${value}`};
  if(identity.type==='cookie')return {Cookie:value};
  assert(/^[A-Za-z][A-Za-z0-9-]*$/.test(identity.header)&&!['host','connection','content-length','transfer-encoding'].includes(identity.header.toLowerCase()),'Invalid identity header');
  return {[identity.header]:value};
}
// Data selectors only: no expression evaluation, wildcards or inherited properties.
export function jsonField(data,selector='id'){
  if(typeof selector!=='string'||!selector||selector.length>256)return undefined;
  if(data&&typeof data==='object'&&Object.hasOwn(data,selector))return data[selector];
  let parts;
  if(selector.startsWith('/')){
    if(/~(?![01])/u.test(selector))return undefined;
    parts=selector.slice(1).split('/').map(p=>p.replace(/~1/g,'/').replace(/~0/g,'~'));
  }else{parts=selector.split('.');if(parts.some(p=>!/^[A-Za-z0-9_$-]+$/.test(p)))return undefined;}
  if(parts.length>16)return undefined;
  let value=data;
  for(const part of parts){if(!value||typeof value!=='object'||!Object.hasOwn(value,part))return undefined;value=value[part];}
  return value;
}
function resourceMatches(response,spec){
  if(spec.response==='html')return /text\/html/i.test(response.contentType)&&typeof spec.matchText==='string'&&spec.matchText.length>=8&&response.body.includes(spec.matchText);
  try{const value=jsonField(JSON.parse(response.body),spec.idField||'id');return ['string','number'].includes(typeof value)&&String(value)===String(spec.resourceId);}catch{return false;}
}
export async function replay(spec,{env=process.env,signal,positiveOnly=false}={}){
  const started=Date.now();let requests=0;const controls=[];
  try{
    const url=new URL(env.BYPASS_TARGET_URL || spec.origin);
    assert(url.origin===spec.origin&&url.pathname==='/'&&!url.search&&!url.hash&&!url.username&&!url.password,'Target must match the bound origin exactly');
    const local=spec.environment==='local';
    assert(local?localHost(url.hostname):url.protocol==='https:'&&!localHost(url.hostname),'Invalid target transport');
    assert(Date.parse(spec.authorization.expiresAt)>Date.now(),'Testing authorization expired; reauthorize and re-export');
    assert(Date.parse(spec.ownershipExpiresAt)>Date.now(),'Ownership verification expired; reverify and re-export');
    assert(spec.authorization.origin===url.origin,'Authorization origin mismatch');
    assert(!/%(?:2f|5c|2e|25)/i.test(spec.resourcePath)&&!/[?#\\]/.test(spec.resourcePath)&&!spec.resourcePath.split('/').includes('..'),'Unsafe resource path');
    assert(spec.authorization.paths.some(p=>p==='/'||spec.resourcePath===p||spec.resourcePath.startsWith(p.endsWith('/')?p:p+'/')),'Resource is outside authorized paths');
    assert(spec.authorization.methods.includes('GET'),'GET is not authorized');
    const fixture=!!spec.fixture&&local;
    if(spec.kind==='unverified-account-access'){
      const headers=identityHeaders(spec.owner,env,fixture),p=spec.owner.checkPath;
      assert(typeof p==='string'&&p.startsWith('/')&&!p.startsWith('//')&&!/[?#\\]/.test(p)&&!/%(?:2f|5c|2e|25)/i.test(p)&&!p.split('/').includes('..'),'Invalid identity path');
      assert(spec.authorization.paths.some(prefix=>prefix==='/'||p===prefix||p.startsWith(prefix.endsWith('/')?prefix:prefix+'/')),'Identity control is outside scope');
      requests++;const identity=await request(new URL(p,url),headers,local,signal,spec.timeoutMs||8000);controls.push({label:'unverified account identity',status:identity.status});
      assert(identity.status===200,'Unverified account login control failed; refresh credentials or use a separate identity endpoint. A login failure cannot verify a fix.');
      const profile=JSON.parse(identity.body);assert(String(jsonField(profile,spec.identityField||'id'))===String(spec.resourceId),'Identity no longer matches the generated test account');
      let verified=jsonField(profile,spec.verifiedField);
      if(spec.verificationSource==='firebase-token'){const claims=JSON.parse(Buffer.from((env[spec.owner.secretEnv]||'').split('.')[1],'base64url').toString('utf8'));assert(claims.sub===String(spec.resourceId)&&claims.aud===spec.firebaseProject&&claims.iss===`https://securetoken.google.com/${spec.firebaseProject}`&&claims.exp*1000>Date.now(),'Firebase identity binding changed or expired');verified=claims.email_verified;}
      assert(verified===false,'Test account must still be explicitly unverified; a verified account cannot establish this fix');
      await new Promise(resolve=>setTimeout(resolve,Math.ceil(1000/spec.authorization.maxRequestsPerSecond)));
      requests++;const access=await request(new URL(spec.resourcePath,url),headers,local,signal,spec.timeoutMs||8000);controls.push({label:'unverified protected access',status:access.status});
      if(access.status===200&&resourceMatches(access,spec))return {status:'failed',reason:'An unverified account can access a route explicitly requiring verified email.',controls,requests,modelCalls:0,durationMs:Date.now()-started};
      assert([401,403].includes(access.status),'Protected access is inconclusive; response does not identify the expected account resource');
      return {status:'passed',reason:'The account is valid and unverified; its access to the protected route is denied.',controls,requests,modelCalls:0,durationMs:Date.now()-started};
    }
    if(spec.kind==='anonymous'){
      assert(['private','public'].includes(spec.expected),'Anonymous checks require an explicit public/private expectation');
      const resource=new URL(spec.resourcePath,url);assert(resource.origin===url.origin,'Resource escapes target origin');
      requests++;const response=await request(resource,{Accept:spec.response==='html'?'text/html':'application/json','User-Agent':'Bypass-Regression/0.1'},local,signal,spec.timeoutMs||8000);
      controls.push({label:'unauthenticated access',status:response.status});
      const matches=response.status===200&&resourceMatches(response,spec);
      if(matches&&spec.expected==='private')return {status:'failed',reason:'Unauthenticated request can read the explicitly private resource.',controls,requests,modelCalls:0,durationMs:Date.now()-started};
      if(spec.expected==='private'&&[401,403].includes(response.status))return {status:'passed',reason:'Anonymous access to the explicitly private resource is denied.',controls,requests,modelCalls:0,durationMs:Date.now()-started};
      if(matches&&spec.expected==='public')return {status:'observed',reason:'Expected public content is accessible; this is an observation, not a vulnerability or security clearance.',controls,requests,modelCalls:0,durationMs:Date.now()-started};
      assert(false,'Anonymous check is inconclusive: resource marker missing, login page, missing resource, redirect or server error.');
    }
    const owner=identityHeaders(spec.owner,env,fixture), outsider=identityHeaders(spec.outsider,env,fixture);
    assert(JSON.stringify(owner)!==JSON.stringify(outsider),'Owner and non-owner credentials must be different');
    const resource=new URL(spec.resourcePath,url);
    assert(resource.origin===url.origin,'Resource escapes target origin');
    const gap=Math.ceil(1000/spec.authorization.maxRequestsPerSecond);
    const send=async(headers,label,requestURL=resource)=>{if(requests)await new Promise((resolve,reject)=>{const t=setTimeout(resolve,gap);if(signal){const onAbort=()=>{clearTimeout(t);reject(new Error('Cancelled'));};signal.addEventListener('abort',onAbort,{once:true});setTimeout(()=>signal.removeEventListener('abort',onAbort),gap);}});requests++;const r=await request(requestURL,{Accept:spec.response==='html'?'text/html, application/json':'application/json','User-Agent':'Bypass-Regression/0.1',...headers},local,signal,spec.timeoutMs||8000);controls.push({label,status:r.status});return r;};
    if(spec.requireIdentityControl){
      const identityURL=identity=>{
        const p=identity.checkPath;
        assert(typeof p==='string'&&p.startsWith('/')&&!p.startsWith('//')&&!/[?#\\]/.test(p)&&!/%(?:2f|5c|2e|25)/i.test(p)&&!p.split('/').includes('..'),'Invalid identity positive-control path');
        assert(spec.authorization.paths.some(prefix=>prefix==='/'||p===prefix||p.startsWith(prefix.endsWith('/')?prefix:prefix+'/')),'Identity control is outside authorized paths');
        const result=new URL(p,url);assert(result.origin===url.origin,'Identity control escapes target');return result;
      };
      const own=await send(owner,'owner identity',identityURL(spec.owner));
      const other=await send(outsider,'outsider identity',identityURL(spec.outsider));
      assert(own.status===200&&other.status===200,'Both account login controls must return HTTP 200. Refresh or reconnect the failing test account; preserve the saved repository, DNS and scope. A failed login is not a passing security result.');
      const field=spec.identityField||'id';let a,b;
      try{a=jsonField(JSON.parse(own.body),field);b=jsonField(JSON.parse(other.body),field);}catch{}
      assert(['string','number'].includes(typeof a)&&['string','number'].includes(typeof b)&&String(a)!==String(b),'Identity controls must identify two different accounts; check identityField');
    }
    const ownerResponse=await send(owner,'owner access');
    assert(ownerResponse.status===200&&resourceMatches(ownerResponse,spec),'Owner positive control failed: use an existing resource owned by this account and its exact JSON ID selector. Placeholder or deleted IDs cannot be tested.');
    if(positiveOnly)return {status:'ready',reason:'Two distinct accounts and owner resource validated. No cross-account or anonymous test has run yet.',controls,requests,modelCalls:0,durationMs:Date.now()-started};
    const outsiderResponse=await send(outsider,'cross-account access');
    const unauthenticated=await send({},'unauthenticated access');
    const exposed=outsiderResponse.status===200&&resourceMatches(outsiderResponse,spec);
    const publicExposure=unauthenticated.status===200&&resourceMatches(unauthenticated,spec);
    const denied=r=>[401,403,404].includes(r.status);
    if(exposed||publicExposure)return {status:'failed',reason:exposed?'Another account can read the owner’s resource.':'Unauthenticated request can read the owner’s resource.',controls,requests,modelCalls:0,durationMs:Date.now()-started};
    assert(denied(outsiderResponse)&&denied(unauthenticated),'Negative controls are inconclusive (redirect, server error, or unexpected body)');
    return {status:'passed',reason:'Owner can access the resource; another account and an anonymous request are denied.',controls,requests,modelCalls:0,durationMs:Date.now()-started};
  }catch(e){return {status:signal?.aborted?'cancelled':'blocked',reason:e.message,controls,requests,modelCalls:0,durationMs:Date.now()-started};}
}
