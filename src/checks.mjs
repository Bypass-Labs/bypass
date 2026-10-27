import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { replay } from './portable-check.mjs';
import { read, change, atomic, event } from './store.mjs';
import { named, need, id, now, aggregate, Fault } from './util.mjs';
import { inventory } from './repository.mjs';
import { scopeReady, pathAllowed } from './network.mjs';

export function specFor(state,check,targetName){
  const target=named(state.targets,targetName||check.target,'Target');scopeReady(target);
  const b=check.bindings[target.name];need(b,`Check ${check.id} has no binding for ${target.name}. Run test bind.`,3);
  need(pathAllowed(b.resourcePath,target.authorization.paths),'Check resource is outside the authorized scope.',3);
  const owner=named(state.identities,b.owner,'Identity'),outsider=named(state.identities,b.outsider,'Identity');
  need(owner.target===target.name&&outsider.target===target.name,'Identities belong to a different target.',3);
  return {schemaVersion:1,title:check.title,origin:target.url,environment:target.environment,authorization:target.authorization,ownershipExpiresAt:target.ownership.expiresAt,timeoutMs:state.settings.requestTimeoutMs,
    requireIdentityControl:check.engine==='docker',identityField:b.identityField||'id',resourcePath:b.resourcePath,resourceId:b.resourceId,idField:b.idField||'id',owner,outsider,fixture:!!(check.fixture&&((state.demo&&state.demo.target===target.name)||(state.poc&&target.pocFixture)))};
}
export async function runChecks(root,{checkId,all=false,target,signal,runId}={}){
  let state=read(root);const checks=state.checks.filter(c=>c.enabled&&(all||c.id===checkId));
  if(!all)need(checks.length,'Check not found or disabled.');
  const current=await inventory(root);const results=[];
  for(const check of checks){
    if(signal?.aborted){results.push({id:check.id,status:'cancelled',reason:'Cancelled',modelCalls:0});break;}
    state=read(root); // honor revocation and credential changes between checks
    let result;
    try{result=await replay(specFor(state,check,target),{signal});}catch(e){result={status:'blocked',reason:e.message,modelCalls:0,requests:0};}
    const stale=result.status==='passed'&&check.sourceFingerprint!==current.fingerprint;
    results.push({id:check.id,title:check.title,target:target||check.target,...result,assertionStatus:result.status,status:stale?'stale':result.status,reason:stale?'HTTP assertions passed, but source changed since verification; review before counting coverage.':result.reason,checkedAt:now(),runId:runId||null});
    await change(root,s=>{
      const c=named(s.checks,check.id,'Check');c.lastResult=results.at(-1);
      const finding=s.findings.find(f=>f.id===c.findingId);
      if(result.status==='failed'&&finding&&finding.target===(target||check.target)){
        finding.status=finding.engine==='docker'?'confirmed':finding.fixture?'confirmed_fixture':'regression_failed';
        finding.history.push({at:now(),action:'regression',...results.at(-1)});
      }
      event(s,'regression',`${check.title}: ${results.at(-1).status}`,{checkId:check.id,target:target||check.target});
    });
  }
  return {results,exitCode:checks.length?aggregate(results):3,modelCalls:0,empty:checks.length===0,message:checks.length?'Saved tests replayed without a model.':'No enabled saved tests. No coverage has been established.'};
}
export async function saveCheck(root,findingId){
  const snapshot=read(root),finding=named(snapshot.findings,findingId,'Finding');
  need(finding.status==='fixed_verified','A check is saved after a fix passes positive and negative controls.',3);
  const inv=await inventory(root);
  return change(root,s=>{
    const existing=s.checks.find(c=>c.findingId===findingId);if(existing)return existing;
    const check={id:id('check'),findingId,title:finding.title,kind:'cross-account-resource',target:finding.target,fixture:!!finding.fixture,engine:finding.engine||'mock',enabled:true,createdAt:now(),sourceFingerprint:inv.fingerprint,bindings:{[finding.target]:finding.binding},lastResult:null};
    s.checks.push(check);event(s,'check-saved',`Saved regression: ${check.title}`,{checkId:check.id});return check;
  });
}
export async function bindCheck(root,checkId,targetName,binding){
  need(typeof binding.resourcePath==='string'&&binding.resourcePath.startsWith('/')&&!/[?#\\]/.test(binding.resourcePath),'Binding requires a resourcePath without query strings.');
  need(binding.resourceId&&binding.owner&&binding.outsider,'Binding requires resourceId, owner, and outsider identity names.');
  return change(root,s=>{
    const target=named(s.targets,targetName,'Target');scopeReady(target,binding.resourcePath);
    for(const key of ['owner','outsider'])need(named(s.identities,binding[key],'Identity').target===targetName,'Identity belongs to another target.');
    const checks=checkId==='all'?s.checks:[named(s.checks,checkId,'Check')];
    for(const c of checks)c.bindings[targetName]={resourcePath:binding.resourcePath,resourceId:String(binding.resourceId),idField:binding.idField||'id',owner:binding.owner,outsider:binding.outsider,identityField:binding.identityField||'id'};
    return {bound:checks.map(c=>c.id),target:targetName};
  });
}
export function exportChecks(root,{checkId,all,target,out,force=false}){
  const state=read(root), checks=state.checks.filter(c=>all||c.id===checkId);need(checks.length,'No matching saved checks.');
  const directory=path.resolve(root,out||'tests/security/bypass');fs.mkdirSync(directory,{recursive:true});
  const generated=[];
  const runner=path.join(directory,'bypass-regression-runtime.mjs');
  const runtimeSource=fs.readFileSync(fileURLToPath(new URL('./portable-check.mjs',import.meta.url)),'utf8');
  if(fs.existsSync(runner)&&fs.readFileSync(runner,'utf8')!==runtimeSource&&!force)throw new Fault('Export runtime already exists with different content. Review it, then pass --force to replace.');
  atomic(runner,runtimeSource);
  for(const check of checks){
    const spec=specFor(state,check,target);
    // Credential references only. fixtureValue is a public demo token, never a real secret.
    for(const identity of [spec.owner,spec.outsider]){delete identity.lastTest;if(!spec.fixture)delete identity.fixtureValue;}
    const file=path.join(directory,`${check.id}.test.mjs`);
    const source=`// Generated by Bypass. Independent Node 22 test; zero model calls.\nimport test from 'node:test';\nimport assert from 'node:assert/strict';\nimport { replay } from './bypass-regression-runtime.mjs';\nconst spec = ${JSON.stringify(spec,null,2)};\ntest(${JSON.stringify(check.title)}, async () => {\n  const result = await replay(spec);\n  assert.equal(result.status, 'passed', JSON.stringify(result));\n});\n`;
    if(fs.existsSync(file)&&fs.readFileSync(file,'utf8')!==source&&!force)throw new Fault(`Export ${file} differs. Review it, then pass --force to replace.`);
    atomic(file,source);generated.push(file);
  }
  return {directory,files:generated,runtime:runner,command:`node --test '${directory}'/*.test.mjs`,modelRequired:false,bypassRequired:false,scopeExpiry:'Export carries current ownership and authorization expiry. Re-export after reauthorization.'};
}
