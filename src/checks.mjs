import { consolidateMemory } from './project-memory.mjs';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { replay } from './portable-check.mjs';
import { read, change, atomic, event } from './store.mjs';
import { named, need, id, now, hash, aggregate, Fault } from './util.mjs';
import { inventory } from './repository.mjs';
import { scopeReady, pathAllowed } from './network.mjs';
import { replayEnvironment } from './credentials.mjs';

export function specFor(state,check,targetName){
  const target=named(state.targets,targetName||check.target,'Target');scopeReady(target);
  const b=check.bindings[target.name];need(b,`Check ${check.id} has no binding for ${target.name}. Run test bind.`,3);
  need(pathAllowed(b.resourcePath,target.authorization.paths),'Check resource is outside the authorized scope.',3);
  const base={schemaVersion:1,title:check.title,origin:target.url,environment:target.environment,authorization:target.authorization,ownershipExpiresAt:target.ownership.expiresAt,timeoutMs:state.settings.requestTimeoutMs,kind:b.kind,response:b.response,matchText:b.matchText,expected:b.expected,resourcePath:b.resourcePath,resourceId:b.resourceId,idField:b.idField||'id'};
  if(b.kind==='anonymous')return base;
  if(b.kind==='unverified-account-access'){
    const owner=named(state.identities,b.owner,'Identity');need(owner.target===target.name,'Identity belongs to another target.',3);
    return {...base,owner,identityField:b.identityField,verifiedField:b.verifiedField,verificationSource:b.verificationSource,firebaseProject:b.firebaseProject};
  }
  const owner=named(state.identities,b.owner,'Identity'),outsider=named(state.identities,b.outsider,'Identity');
  need(owner.target===target.name&&outsider.target===target.name,'Identities belong to a different target.',3);
  return {...base,
    requireIdentityControl:['docker','host'].includes(check.engine),identityField:b.identityField||'id',resourcePath:b.resourcePath,resourceId:b.resourceId,idField:b.idField||'id',owner,outsider,fixture:!!(check.fixture&&((state.demo&&state.demo.target===target.name)||(state.poc&&target.pocFixture)))};
}
export async function runChecks(root,{checkId,all=false,target,signal,runId}={}){
  let state=read(root);const checks=state.checks.filter(c=>c.enabled&&(all||c.id===checkId||c.findingId===checkId));
  if(!all)need(checks.length,'Check not found or disabled.');
  const current=await inventory(root);const results=[];
  for(const check of checks){
    if(signal?.aborted){results.push({id:check.id,status:'cancelled',reason:'Cancelled',modelCalls:0});break;}
    state=read(root); // honor revocation and credential changes between checks
    let result;
    try{const spec=specFor(state,check,target);result=await replay(spec,{signal,env:await replayEnvironment(state,spec,{signal})});}catch(e){result={status:'blocked',reason:e.message,modelCalls:0,requests:0};}
    const stale=result.status==='passed'&&check.sourceFingerprint!==current.fingerprint;
    results.push({id:check.id,title:check.title,target:target||check.target,origin:state.targets.find(t=>t.name===(target||check.target))?.url||null,bindingFingerprint:hash(check.bindings[target||check.target]||{}),resourcePath:check.bindings[target||check.target]?.resourcePath,...result,assertionStatus:result.status,status:stale?'stale':result.status,reason:stale?'HTTP assertions passed, but source changed since verification; review before counting coverage.':result.reason,checkedAt:now(),runId:runId||null});
    await change(root,s=>{
      const c=named(s.checks,check.id,'Check');c.lastResult=results.at(-1);
      const finding=s.findings.find(f=>f.id===c.findingId);
      const exact=finding&&finding.target===(target||check.target)&&hash(finding.binding)===hash(c.bindings[target||check.target])&&c.verifiedOrigins?.[target||check.target]===state.targets.find(t=>t.name===(target||check.target))?.url;
      if(result.status==='failed'&&exact){
        finding.status=['docker','host'].includes(finding.engine)?'confirmed':finding.fixture?'confirmed_fixture':'regression_failed';
        finding.history.push({at:now(),action:'regression',...results.at(-1)});
      }
      if(result.status==='passed'&&exact&&['docker','host'].includes(finding.engine)&&['confirmed','regression_failed'].includes(finding.status)&&finding.history.some(h=>h.status==='failed')){
        finding.status='fixed_verified';finding.sourceFingerprint=current.fingerprint;
        finding.verification={...result,at:now(),origin:c.verifiedOrigins[target||check.target],simulation:false};
        finding.history.push({action:'regression-retest',...finding.verification});
        c.sourceFingerprint=current.fingerprint;c.baseline='fixed_verified';
        Object.assign(c.lastResult,{status:'passed',reason:result.reason,findingStatus:'fixed_verified'});
      }
      event(s,'regression',`${check.title}: ${results.at(-1).status}`,{checkId:check.id,target:target||check.target});
    });
  }
  if(checks.some(c=>['docker','host'].includes(c.engine)))await consolidateMemory(root);
  return {results,exitCode:checks.length?aggregate(results):3,modelCalls:0,empty:checks.length===0,message:checks.length?'Saved tests replayed without a model.':'No enabled saved tests. No coverage has been established.'};
}
export async function saveCheck(root,findingId){
  const snapshot=read(root),finding=named(snapshot.findings,findingId,'Finding');
  need(['confirmed','confirmed_fixture','fixed_verified'].includes(finding.status)&&finding.binding&&['failed','passed'].includes(finding.verification?.status),'Save a check from observed HTTP proof or a verified fix; source hypotheses alone are not executable regressions.',3);
  const inv=await inventory(root);
  return change(root,s=>{
    const existing=s.checks.find(c=>c.findingId===findingId);if(existing)return existing;
    const check={id:id('check'),findingId,title:finding.title,kind:finding.binding.kind||'cross-account-resource',baseline:finding.status==='fixed_verified'?'fixed_verified':'failing_reproduction',target:finding.target,fixture:!!finding.fixture,engine:finding.engine||'mock',enabled:true,createdAt:now(),sourceFingerprint:inv.fingerprint,bindings:{[finding.target]:finding.binding},verifiedOrigins:{[finding.target]:finding.verification?.origin||null},verifiedBindings:{[finding.target]:finding.binding},lastResult:{...finding.verification,target:finding.target,checkedAt:finding.verification.at,source:'finding-proof'}};
    s.checks.push(check);event(s,'check-saved',`Saved regression: ${check.title}`,{checkId:check.id});return check;
  });
}
export async function bindCheck(root,checkId,targetName,binding){
  need(typeof binding.resourcePath==='string'&&binding.resourcePath.startsWith('/')&&!/[?#\\]/.test(binding.resourcePath),'Binding requires a resourcePath without query strings.');
  const anonymous=binding.kind==='anonymous',email=binding.kind==='unverified-account-access';
  need((binding.response==='html'?typeof binding.matchText==='string'&&binding.matchText.length>=8:binding.resourceId)&&(anonymous?binding.expected==='private':binding.owner&&(email||binding.outsider)),'Binding needs an exact resource marker and the account controls required by its check kind.');
  return change(root,s=>{
    const target=named(s.targets,targetName,'Target');scopeReady(target,binding.resourcePath);
    for(const key of anonymous?[]:email?['owner']:['owner','outsider'])need(named(s.identities,binding[key],'Identity').target===targetName,'Identity belongs to another target.');
    const checks=checkId==='all'?s.checks:[named(s.checks,checkId,'Check')];
    for(const c of checks){need(c.kind===(binding.kind||'cross-account-resource'),'New binding must preserve the saved check kind.');const accepted={resourcePath:binding.resourcePath,resourceId:binding.resourceId===undefined?undefined:String(binding.resourceId),idField:binding.idField||'id',owner:binding.owner,outsider:binding.outsider,identityField:binding.identityField||'id'};for(const key of ['kind','expected','response','matchText','verifiedField','verificationSource','firebaseProject'])if(binding[key]!==undefined)accepted[key]=binding[key];c.bindings[targetName]=accepted;specFor(s,c,targetName);}
    return {bound:checks.map(c=>c.id),target:targetName};
  });
}
export function exportChecks(root,{checkId,all,target,out,force=false}){
  const state=read(root), checks=state.checks.filter(c=>all||c.id===checkId||c.findingId===checkId);need(checks.length,'No saved check matches that check/finding ID. Inspect test list; source hypotheses need HTTP confirmation before export.');
  const directory=path.resolve(root,out||'tests/security/bypass');fs.mkdirSync(directory,{recursive:true});
  const generated=[];
  const runner=path.join(directory,'bypass-regression-runtime.mjs');
  const runtimeSource=fs.readFileSync(fileURLToPath(new URL('./portable-check.mjs',import.meta.url)),'utf8');
  if(fs.existsSync(runner)&&fs.readFileSync(runner,'utf8')!==runtimeSource&&!force)throw new Fault('Export runtime already exists with different content. Review it, then pass --force to replace.');
  atomic(runner,runtimeSource);
  for(const check of checks){
    const spec=specFor(state,check,target);
    // Credential references only. fixtureValue is a public demo token, never a real secret.
    for(const key of ['owner','outsider'])if(spec[key]){spec[key]={...spec[key]};delete spec[key].lastTest;delete spec[key].credentialRef;if(!spec.fixture)delete spec[key].fixtureValue;}
    const file=path.join(directory,`${check.id}.test.mjs`);
    const source=`// Generated by Bypass. Independent Node 22 test; zero model calls.\nimport test from 'node:test';\nimport assert from 'node:assert/strict';\nimport { replay } from './bypass-regression-runtime.mjs';\nconst spec = ${JSON.stringify(spec,null,2)};\ntest(${JSON.stringify(check.title)}, async () => {\n  const result = await replay(spec);\n  assert.equal(result.status, 'passed', JSON.stringify(result));\n});\n`;
    if(fs.existsSync(file)&&fs.readFileSync(file,'utf8')!==source&&!force)throw new Fault(`Export ${file} differs. Review it, then pass --force to replace.`);
    atomic(file,source);generated.push(file);
  }
  return {directory,files:generated,runtime:runner,command:`node --test '${directory}'/*.test.mjs`,modelRequired:false,bypassRequired:false,credentials:'Independent tests use the named account environment variables supplied by CI. Private local credentials and refresh tokens are never exported.',scopeExpiry:'Export carries current ownership and authorization expiry. Re-export after reauthorization.'};
}
