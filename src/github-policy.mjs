import { need, hash } from './util.mjs';

export const GITHUB_POLICY_PATH='.github/bypass.json';
export const sha=value=>typeof value==='string'&&/^[a-f0-9]{40}$/.test(value);
export const sourcePath=value=>typeof value==='string'&&value.length<500&&!value.startsWith('/')&&!value.includes('\\')&&!value.split('/').some(p=>!p||p==='.'||p==='..')&&!value.split('/').some(p=>/^\.env(?:\.|$)|^(?:node_modules|vendor|dist|build|\.git|\.bypass)$/.test(p))&&/\.(?:[cm]?[jt]sx?|py|go|rb|rs|java|php)$/.test(value);
const object=value=>value&&typeof value==='object'&&!Array.isArray(value);
const keys=(value,allowed,label)=>{need(object(value),`${label} must be an object.`);for(const key of Object.keys(value))need(allowed.includes(key),`Unknown ${label} option: ${key}`);};
const integer=(value,min,max,label)=>{need(Number.isInteger(value)&&value>=min&&value<=max,`${label} must be ${min}–${max}.`);return value;};
const apiPath=value=>typeof value==='string'&&value.startsWith('/')&&!value.startsWith('//')&&!/[?#\\\r\n]/.test(value)&&!/%(?:2e|2f|5c|25)/i.test(value)&&!value.split('/').includes('..');
const credentialRef=value=>typeof value==='string'&&/^[A-Z_][A-Z0-9_]*$/.test(value)&&!/^(?:GITHUB_|ACTIONS_|RUNNER_|MODEL_API_KEY$)/.test(value);
export function githubPolicy(input={version:1}){
  input=structuredClone(input);
  keys(input,['version','review','smoke','targets'],'policy');need(input.version===1,'Unsupported GitHub agent policy version.');
  const review={model:'muse-spark-1.3',allowForks:false,blocking:false,failOn:'high',maxFiles:40,maxBytes:256000,maxCalls:12,maxOutputTokens:4096,...input.review};
  keys(review,['model','allowForks','blocking','failOn','maxFiles','maxBytes','maxCalls','maxOutputTokens'],'review');
  need(typeof review.model==='string'&&/^[\w.:-]{1,120}$/.test(review.model),'Invalid Meta model identifier.');
  need(typeof review.allowForks==='boolean'&&typeof review.blocking==='boolean','Review toggles must be boolean.');
  need(['critical','high','medium','low'].includes(review.failOn),'Invalid finding threshold.');
  integer(review.maxFiles,1,200,'maxFiles');integer(review.maxBytes,1000,2000000,'maxBytes');integer(review.maxCalls,1,100,'maxCalls');integer(review.maxOutputTokens,512,8192,'maxOutputTokens');
  const smoke={enabled:true,...input.smoke};keys(smoke,['enabled'],'smoke');need(typeof smoke.enabled==='boolean','smoke.enabled must be boolean.');
  const targets=input.targets||{};need(object(targets)&&Object.keys(targets).length<=8,'At most eight named targets.');
  for(const [name,target] of Object.entries(targets)){
    need(/^[a-zA-Z][a-zA-Z0-9_-]{0,63}$/.test(name),'Invalid target name.');
    keys(target,['origin','environment','ownershipTokenEnv','revision','checks'],'target');
    const url=new URL(target.origin);need(url.origin===target.origin&&url.protocol==='https:'&&!url.username&&!url.password,'CI targets require an exact HTTPS origin.');
    need(['production','staging','preview'].includes(target.environment),'Choose production, staging or preview.');
    need(credentialRef(target.ownershipTokenEnv),'Specify the dedicated DNS verification secret reference.');
    keys(target.revision,['path','field'],'revision');need(apiPath(target.revision.path)&&typeof target.revision.field==='string'&&target.revision.field.length<200,'Specify a scoped JSON build-revision endpoint and field.');
    need(Array.isArray(target.checks)&&target.checks.length<=64,'At most 64 saved checks per target.');
    const ids=new Set();
    for(const check of target.checks){
      keys(check,['id','findingId','spec'],'check');need(typeof check.id==='string'&&/^[a-zA-Z0-9_-]{1,100}$/.test(check.id)&&!ids.has(check.id),'Unique check IDs are required.');ids.add(check.id);
      const s=check.spec;need(object(s)&&s.origin===target.origin&&s.environment===target.environment&&!s.fixture,'Checks must bind this exact non-fixture target.');
      keys(s,['schemaVersion','title','origin','environment','authorization','ownershipExpiresAt','timeoutMs','kind','response','matchText','expected','resourcePath','resourceId','idField','requireIdentityControl','identityField','owner','outsider','fixture','verifiedField','verificationSource','firebaseProject'],'saved check');
      need(apiPath(s.resourcePath),'Invalid resource path.');
      need(['anonymous','unverified-account-access','cross-account-resource',undefined].includes(s.kind),'Unsupported saved-check kind.');
      need(s.kind==='anonymous'||s.kind==='unverified-account-access'||s.requireIdentityControl===true,'Account-boundary checks require login controls.');
      const a=s.authorization;need(object(a)&&a.origin===target.origin&&Array.isArray(a.methods)&&a.methods.includes('GET'),'Saved checks need GET authorization for this origin.');
      need(target.environment!=='production'||a.productionAcknowledged===true,'Production checks require an explicitly acknowledged production scope.');
      need(Array.isArray(a.paths)&&a.paths.length>0&&a.paths.every(apiPath),'Invalid scope paths.');
      need(Number.isFinite(a.maxRequestsPerSecond)&&a.maxRequestsPerSecond>=0.1&&a.maxRequestsPerSecond<=10,'CI request rate must be between 0.1 and 10/s.');
      if(s.timeoutMs!==undefined)integer(s.timeoutMs,100,30000,'HTTP timeoutMs');
      need(Number.isFinite(Date.parse(a.expiresAt))&&Number.isFinite(Date.parse(s.ownershipExpiresAt)),'Checks need explicit scope and ownership expiry.');
      need(Date.parse(a.expiresAt)<=Date.now()+30*86400000&&Date.parse(s.ownershipExpiresAt)<=Date.now()+30*86400000,'CI exports retain bounded permission; renew grants explicitly, at most 30 days ahead.');
      for(const key of ['owner','outsider'])if(s[key]){
        keys(s[key],['type','header','secretEnv','checkPath'],'identity');
        need(['bearer','cookie','header'].includes(s[key].type)&&credentialRef(s[key].secretEnv)&&apiPath(s[key].checkPath),'Use dedicated app CI secret references and an identity control path; never runner or model credentials.');
      }
    }
  }
  return {version:1,review,smoke,targets};
}
export function assessmentConclusion(report,policy){
  if(report.execution==='cancelled')return 'cancelled';
  if(report.execution!=='complete')return 'failure';
  const level={low:1,medium:2,high:3,critical:4};
  const securityFailed=report.checks.some(c=>c.status==='failed')||report.findings.some(f=>level[f.severity]>=level[policy.review.failOn]);
  return securityFailed&&policy.review.blocking?'failure':'success';
}
export const findingKey=f=>'gh_'+hash([f.category,f.sourceEvidence.file,f.sourceEvidence.quote,f.resourcePath]).slice(0,20);
