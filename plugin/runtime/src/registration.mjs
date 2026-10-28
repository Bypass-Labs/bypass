import { accountInput, syntheticEmailDomain } from './interaction.mjs';
import { discoverRegistration } from './registration-discovery.mjs';
import { randomUUID, randomBytes } from 'node:crypto';
import path from 'node:path';
import { read, change, event } from './store.mjs';
import { scopeReady, safeRequest, pathAllowed } from './network.mjs';
import { saveGeneratedCredential, removeCredential, credentialFields } from './credentials.mjs';
import { jsonField } from './portable-check.mjs';
import { executeProbe } from './security-execution.mjs';
import { need, named, now, hash, registerSecret, delay, redact } from './util.mjs';

const exactPath=p=>typeof p==='string'&&p.startsWith('/')&&!p.startsWith('//')&&!/[?#\\]/.test(p)&&pathAllowed(p,[p]);
const field=p=>typeof p==='string'&&/^[A-Za-z_][A-Za-z0-9_]{0,63}$/.test(p)&&!['constructor','prototype','__proto__'].includes(p);
export function registrationStatus(target){
  if(!target)return {status:'not_selected',reason:'Connect an app before choosing live account checks.',nextAction:null};
  const decision=target?.accountChoice;
  if(decision&&decision.mode!=='create')return {status:decision.mode==='skip'?'skipped':'existing_accounts',choice:decision,reason:decision.mode==='skip'?'Continue source and anonymous checks. Signed-in account coverage was skipped.':'Use connected identities or import a private test-account file. Automatic signup is not selected.',nextAction:null};
  if(decision?.mode==='create'&&!target.registration){
    const valid=decision.authorizationFingerprint===hash(target.authorization);
    if(valid&&target.registrationDiscovery?.nextAction)return {status:'setup_needed',choice:decision,permissionSaved:true,reason:'Account creation permission is saved. Resolve the recorded discovery blocker; do not repeat discovery without changed input or access.',discovery:target.registrationDiscovery,nextAction:target.registrationDiscovery.nextAction};
    if(valid)return {status:'setup_needed',choice:decision,reason:'Account creation permission is already saved. Discover signup configuration and continue without asking again.',nextAction:{tool:'bypass_configure_registration',automatic:true,requiresAnswer:false}};
  }
  if(!target?.registration)return {status:'not_configured',reason:'Discover signup from source or authorized app observations. For Firebase, use registration discover before asking the user for public config. Credentials are optional; creating accounts requires explicit permission.',next:'registration configure',nextAction:{question:'How should Bypass test signed-in account access?',input:accountInput(target),requiresAnswer:true}};
  return {status:target.registration.lastResult?'recorded':'ready',path:target.registration.path,lastResult:target.registration.lastResult||null};
}
export async function chooseAccounts(root,o){
  const state=read(root),target=named(state.targets,o.target||state.activeTarget,'Target');
  need(['create','existing','skip'].includes(o.mode),'Choose create, existing or skip.');
  if(o.mode==='create'){scopeReady(target);need(o.accept===true,'Explicit permission is required to create up to two test accounts.');}
  if(o['email-domain'])need(/^(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z]{2,63}$/i.test(o['email-domain']),'Use a dedicated synthetic email domain.');
  return change(root,s=>{const app=named(s.targets,target.name,'Target');
    app.accountChoice={mode:o.mode,selectedAt:now(),...(o.mode==='create'?{authorizationFingerprint:hash(app.authorization),maxAccounts:2,emailDomain:o['email-domain']||syntheticEmailDomain(app)}:{})};
    return {target:app.name,...registrationStatus(app)};
  });
}
export async function configureRegistration(root,o,context={}){
  o={...o};
  const state=read(root),target=named(state.targets,o.target||state.activeTarget,'Target');scopeReady(target,o['check-path']);
  const saved=target.accountChoice;
  need(o.accept===true||o.accept!==false&&saved?.mode==='create'&&saved.authorizationFingerprint===hash(target.authorization),'Account creation permission is required. Choose how to handle test accounts.',2,{nextAction:registrationStatus(target).nextAction||{input:accountInput(target)}});
  o['email-domain']??=saved?.mode==='create'?saved.emailDomain:syntheticEmailDomain(target);
  // Remember explicit consent even if discovery needs recovery; never ask for it again on retry.
  if(o.accept===true)await chooseAccounts(root,{target:target.name,mode:'create',accept:true,'email-domain':o['email-domain']});
  const provider=o.provider||'json';need(['json','firebase'].includes(provider),'Registration supports json or firebase.');
  need(exactPath(o['check-path'])&&(provider==='firebase'||exactPath(o.path)),'Registration and protected-control paths must be exact paths on the verified application.');
  if(provider==='json')scopeReady(target,o.path,'POST');
  let configKeyHash;
  if(provider==='firebase'){
    let fields;
    if(o['config-file'])try{fields=credentialFields(path.resolve(root,o['config-file']),{privateFile:false});}catch{/* Source templates are not resolved config; try bounded discovery. */}
    o['project-id'] ||= fields?.VITE_FIREBASE_PROJECT_ID||fields?.projectId;
    if(!fields?.[o['api-key-field']||'VITE_FIREBASE_API_KEY']||!o['project-id']){
      const discovery=await discoverRegistration(root,{target:o.target,'project-id':o['project-id']},context);
      if(discovery.status!=='found')return {kind:'setup-needed',registrationConfigured:false,discovery,nextAction:discovery.nextAction,message:discovery.message};
      o['config-file']=discovery.configFile;o['project-id']=discovery.projectId;o['api-key-field']='VITE_FIREBASE_API_KEY';
      fields=credentialFields(discovery.configFile,{privateFile:false});
    }
    need(/^[a-z0-9][a-z0-9-]{3,62}$/.test(o['project-id']||''),'Firebase config must contain the exact project ID.');
    const configuredProject=fields.VITE_FIREBASE_PROJECT_ID||fields.projectId;
    need(!configuredProject||configuredProject===o['project-id'],'The selected Firebase project differs from the resolved app config.');
    configKeyHash=hash(fields[o['api-key-field']||'VITE_FIREBASE_API_KEY']);

  }
  need(typeof o['email-domain']==='string'&&/^(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z]{2,63}$/i.test(o['email-domain']),'Choose an authorized test email domain. No customer or guessed addresses.');
  for(const key of ['email-field','password-field'])need(field(o[key]||(key==='email-field'?'email':'password')),'Email/password fields must be simple JSON property names.');
  need(o['email-field']!==o['password-field']||!o['email-field'],'Email and password fields must differ.');
  need(provider==='firebase'||o['token-field']&&o['verified-field'],'Specify the signup token selector and the protected endpoint email-verification selector from source.');
  if(o['access-path']){need(exactPath(o['access-path']),'Protected access path must be exact.');scopeReady(target,o['access-path']);}
  const config={provider,accessPath:o['access-path']||o['check-path'],path:provider==='firebase'?'https://identitytoolkit.googleapis.com/v1/accounts:signUp':o.path,...(provider==='firebase'?{configKeyHash,configFile:path.resolve(root,o['config-file']),apiKeyField:o['api-key-field']||'VITE_FIREBASE_API_KEY',projectId:o['project-id']} :{}),checkPath:o['check-path'],emailDomain:o['email-domain'],emailField:o['email-field']||'email',passwordField:o['password-field']||'password',tokenField:provider==='firebase'?'idToken':o['token-field'],verifiedField:o['verified-field'],identityField:o['identity-field']||'id',requireVerification:!!o['require-verification'],acceptedAt:now(),authorizationFingerprint:hash(target.authorization),maxAccounts:2};
  return change(root,s=>{const app=named(s.targets,target.name,'Target');
    need(!app.registration?.attempts?.length,'Registration has already been attempted. Reuse the saved accounts; a new target/setup is required for another creation budget.',3);
    app.registration=config;return {target:app.name,registration:config,message:'Up to two synthetic signup attempts authorized. Credentials stay private and are optional for other review stages.'};});
}
const active=new Set();
export async function testRegistration(root,{target:targetName,signal,request=safeRequest}={}){
  const state=read(root),target=named(state.targets,targetName||state.activeTarget,'Target'),config=target.registration;
  if(target.accountChoice&&target.accountChoice.mode!=='create')return {kind:'registration',...registrationStatus(target),requests:0,modelCalls:0};
  if(!config)return {kind:'registration',...registrationStatus(target),requests:0,modelCalls:0};
  const key=`${root}:${target.name}`;need(!active.has(key),'Registration is already in progress.',3);active.add(key);
  const result={kind:'registration',status:'incomplete',findings:[],probes:[],accounts:[],observations:[],requests:0,modelCalls:0,startedAt:now(),coverage:'JSON signup on the verified origin; no CAPTCHA bypass, email delivery, social login or arbitrary browser automation.'};
  try{
    scopeReady(target,config.checkPath);
    // A completed or interrupted creation budget is historical. Reusing its
    // accounts sends no signup request and must survive a later scope change.
    if(config.attempts?.length)return {...config.lastResult||result,reused:true,currentProof:false,reason:'Registration attempts are already recorded. Existing identities are reused; no duplicate users created.',attempts:config.attempts,requests:0};
    if(config.provider==='json')scopeReady(target,config.path,'POST');
    need(hash(target.authorization)===config.authorizationFingerprint,'Testing scope changed. Registration permission must be reviewed again.',3);
    for(let index=0;index<config.maxAccounts;index++){
      const current=read(root),app=named(current.targets,target.name,'Target');scopeReady(app,config.checkPath);
      need(hash(app.authorization)===config.authorizationFingerprint,'Registration permission changed.',3);
      const nonce=randomUUID().slice(0,12),name=`signup_${index?'outsider':'owner'}_${nonce.replaceAll('-','')}`,email=`bypass-${nonce}@${config.emailDomain}`,password=randomBytes(24).toString('base64url')+'aA1!';registerSecret(password);
      // Reserve the attempt before network I/O. A timeout/crash never retries a
      // possibly completed creation, including after a new MCP process starts.
      await change(root,s=>{const c=named(s.targets,app.name,'Target').registration;c.attempts??=[];need(c.attempts.length<config.maxAccounts,'Account creation budget exhausted.',3);c.attempts.push({name,email,at:now(),status:'reserved'});});
      if(index)await delay(Math.ceil(1000/app.authorization.maxRequestsPerSecond),undefined,{signal});
      const firebase=config.provider==='firebase',apiKey=firebase?credentialFields(config.configFile,{privateFile:false})[config.apiKeyField]:null;registerSecret(apiKey);
      if(firebase)need(typeof apiKey==='string'&&apiKey&&hash(apiKey)===config.configKeyHash,'Public Firebase config changed. No signup request was sent; review the configured project.',3);
      const live=named(read(root).targets,app.name,'Target');scopeReady(live,config.checkPath);
      if(!firebase)scopeReady(live,config.path,'POST');
      need(hash(live.authorization)===config.authorizationFingerprint,'Registration permission changed before the request.',3);
      result.requests++;
      const response=await request(firebase?config.path+'?key='+encodeURIComponent(apiKey):app.url+config.path,{allowLocal:app.environment==='local',method:'POST',headers:{'Content-Type':'application/json',...(firebase?{Referer:app.url+'/'}:{})},body:JSON.stringify({[config.emailField]:email,[config.passwordField]:password,...(firebase?{returnSecureToken:true}:{})}),signal,timeout:state.settings.requestTimeoutMs,maxBytes:32768});
      let data;try{data=JSON.parse(response.body);}catch{}
      const token=jsonField(data,config.tokenField);registerSecret(token);
      if(firebase)registerSecret(data?.refreshToken);
      const account={name,email,signupStatus:response.status,created:response.status>=200&&response.status<300,connected:false};result.accounts.push(account);
      if(account.created&&typeof token==='string'&&token){
        const identity={name,target:app.name,type:'bearer',secretEnv:`BYPASS_SIGNUP_${nonce.replaceAll('-','').toUpperCase()}`,header:null,checkPath:config.checkPath,createdAt:now(),generated:true};
        const ref=saveGeneratedCredential(current,app,identity,token,firebase?{provider:'firebase',apiKey,projectId:config.projectId,refreshToken:data.refreshToken}:{});identity.credentialRef=ref;
        try{await change(root,s=>{s.identities.push(identity);});}catch(error){removeCredential(current,ref);throw error;}
        account.connected=true;
        await delay(Math.ceil(1000/app.authorization.maxRequestsPerSecond),undefined,{signal});
        scopeReady(named(read(root).targets,app.name,'Target'),config.checkPath);
        result.requests++;
        const control=await request(app.url+config.checkPath,{allowLocal:app.environment==='local',headers:{Authorization:`Bearer ${token}`},signal,timeout:state.settings.requestTimeoutMs,maxBytes:32768});
        let profile;try{profile=JSON.parse(control.body);}catch{}
        let claims={};if(firebase)try{claims=JSON.parse(Buffer.from(token.split('.')[1],'base64url').toString('utf8'));}catch{}
        const verified=firebase?claims.email_verified:jsonField(profile,config.verifiedField),subject=jsonField(profile,config.identityField);
        if(firebase)need(String(subject)===claims.sub,'The app control did not identify the generated Firebase account.',3);
        account.controlStatus=control.status;account.emailVerified=typeof verified==='boolean'?verified:null;account.subject=['string','number'].includes(typeof subject)?String(subject):null;
        if(control.status===200&&verified===false&&account.subject)result.observations.push({kind:'unverified-account-access',account:name,path:config.checkPath,policyViolation:config.requireVerification&&config.accessPath===config.checkPath,message:config.requireVerification&&config.accessPath===config.checkPath?'An account with emailVerified=false accessed a route explicitly requiring verified email.':'An unverified account accessed this route; confirm whether verified email is required before treating this as a vulnerability.'});
      }
      await change(root,s=>{Object.assign(named(s.targets,app.name,'Target').registration.attempts.find(a=>a.name===name),account,{status:'completed'});});
      // CAPTCHA/rate limits or unsupported input should be repaired, not retried.
      if(!account.created)break;
    }
    const unverified=result.accounts.find(a=>a.controlStatus===200&&a.emailVerified===false&&a.subject);
    if(config.requireVerification&&unverified){
      const binding={kind:'unverified-account-access',owner:unverified.name,resourcePath:config.accessPath,resourceId:unverified.subject,idField:config.identityField,identityField:config.identityField,verifiedField:config.verifiedField,verificationSource:config.provider==='firebase'?'firebase-token':'json-identity',firebaseProject:config.projectId};
      const proof=await executeProbe(root,{binding,rawBinding:{name:'registration-email-verification'},bindingIndex:0,targetName:target.name,sourceFingerprint:null,runId:null,engine:'host',candidateIds:result.findings,probes:result.probes,signal});result.requests+=proof.requests;
    }
    result.status=result.probes.some(p=>p.status==='failed')?'failed':result.accounts.some(a=>a.created)?'observed':'blocked';
    result.reason=result.status==='failed'?'Observed unverified account access violates the recorded route policy.':result.status==='observed'?'Registration observed; account creation alone is not a vulnerability.': 'Signup was rejected; inspect the recorded status and source requirements. This is not a passing security result.';
  }catch(error){result.status=signal?.aborted?'cancelled':'blocked';result.reason=redact(error.message);}
  finally{active.delete(key);}
  result.finishedAt=now();result.cleanup=(named(read(root).targets,target.name,'Target').registration.attempts||[]).filter(a=>a.created||a.status==='reserved').map(a=>({account:a.name,email:a.email,subject:a.subject||null,creation:a.status==='reserved'?'unknown; interrupted after reserving attempt':'observed',action:'Delete this dedicated account through the application when testing is complete. Credentials remain private until identity remove.'}));
  await change(root,s=>{named(s.targets,target.name,'Target').registration.lastResult=redact(result);event(s,'registration',`Registration: ${result.status}`,{target:target.name});});
  return redact(result);
}
