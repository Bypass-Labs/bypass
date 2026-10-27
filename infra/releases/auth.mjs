const issuer='https://token.actions.githubusercontent.com';
let cachedKeys,keysUntil=0;
const decode=value=>Uint8Array.from(atob(value.replace(/-/g,'+').replace(/_/g,'/')),c=>c.charCodeAt(0));
const parse=value=>JSON.parse(new TextDecoder().decode(decode(value)));
export async function authorizePublisher(request,env,{fetchKeys,now=Math.floor(Date.now()/1000)}={}){
  const token=request.headers.get('authorization')?.match(/^Bearer ([A-Za-z0-9_.-]+)$/)?.[1];
  if(!token||token.length>16000)throw new Error('Publisher authentication required');
  const parts=token.split('.');if(parts.length!==3)throw new Error('Invalid publisher token');
  const header=parse(parts[0]),claims=parse(parts[1]);
  if(header.alg!=='RS256'||typeof header.kid!=='string')throw new Error('Invalid signing algorithm');
  const keys=fetchKeys?await fetchKeys():await githubKeys();
  const jwk=keys.find(k=>k.kid===header.kid&&k.kty==='RSA'&&k.use==='sig'&&k.alg==='RS256');
  if(!jwk)throw new Error('Unknown publisher signing key');
  const key=await crypto.subtle.importKey('jwk',jwk,{name:'RSASSA-PKCS1-v1_5',hash:'SHA-256'},false,['verify']);
  if(!await crypto.subtle.verify('RSASSA-PKCS1-v1_5',key,decode(parts[2]),new TextEncoder().encode(parts[0]+'.'+parts[1])))throw new Error('Invalid publisher signature');
  const repository=env.GITHUB_REPOSITORY,ref='refs/heads/main';
  const [owner,name]=repository.split('/');
  const subject=`repo:${owner}@${env.GITHUB_OWNER_ID}/${name}@${env.GITHUB_REPOSITORY_ID}:ref:${ref}`;
  if(claims.iss!==issuer||claims.aud!==env.PUBLISH_AUDIENCE||claims.repository!==repository||claims.repository_id!==env.GITHUB_REPOSITORY_ID||claims.repository_owner_id!==env.GITHUB_OWNER_ID||claims.ref!==ref||claims.ref_type!=='branch'||claims.workflow_ref!==`${repository}/.github/workflows/release.yml@${ref}`||claims.sub!==subject||!['push','workflow_dispatch'].includes(claims.event_name)||claims.runner_environment!=='github-hosted')throw new Error('Publisher workflow is not allowed');
  if(![claims.exp,claims.iat,claims.nbf].every(Number.isInteger)||claims.exp<=now||claims.nbf>now+30||claims.iat>now+30||claims.iat<now-600||claims.exp>now+900)throw new Error('Publisher token expired or not yet valid');
  if(!/^[a-f0-9]{40}$/.test(claims.sha)||claims.workflow_sha!==claims.sha||!['run_id','run_number','run_attempt'].every(k=>/^[1-9][0-9]{0,15}$/.test(String(claims[k]))))throw new Error('Invalid publisher run identity');
  return {...claims,releaseId:`main-${claims.sha}-${claims.run_id}-${claims.run_attempt}`};
}
async function githubKeys(){
  if(cachedKeys&&keysUntil>Date.now())return cachedKeys;
  const response=await fetch(issuer+'/.well-known/jwks',{signal:AbortSignal.timeout(10000)});
  if(!response.ok)throw new Error('Publisher identity service unavailable');
  const value=await response.json();if(!Array.isArray(value.keys))throw new Error('Invalid signing keys');
  cachedKeys=value.keys;keysUntil=Date.now()+300000;return cachedKeys;
}
