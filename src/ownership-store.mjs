import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { atomic } from './store.mjs';
import { hash, now, id, need } from './util.mjs';

export const userStateDirectory=()=>process.env.BYPASS_PLUGIN_STATE_DIR||path.join(os.homedir(),'.local/state/bypass');
const directory=()=>process.env.BYPASS_OWNERSHIP_DIR||path.join(userStateDirectory(),'ownership');
const originOf=value=>new URL(value).origin;
const fileFor=origin=>path.join(directory(),hash(origin)+'.json');
function recordFor(origin){
  try{const record=JSON.parse(fs.readFileSync(fileFor(origin),'utf8'));need(record.version===1&&record.origin===origin,'Saved ownership record is invalid. Repair it before testing.',3);return record;}catch(error){if(error.code==='ENOENT')return null;throw error;}
}
// Revocations are immutable and separate from the reusable proof. A concurrent
// migration of old project state cannot overwrite or resurrect a revoked proof.
function revokedAtFor(origin,record){
  let latest=record?.revokedAt?Date.parse(record.revokedAt):0;
  const dir=path.join(directory(),'revocations',hash(origin));
  let files;try{files=fs.readdirSync(dir);}catch(error){if(error.code==='ENOENT')return latest;throw error;}
  for(const file of files.filter(f=>f.endsWith('.json'))){
    const item=JSON.parse(fs.readFileSync(path.join(dir,file),'utf8'));
    need(item.version===1&&item.origin===origin&&Number.isFinite(Date.parse(item.revokedAt)),'Saved ownership revocation is invalid. Repair it before testing.',3);
    latest=Math.max(latest,Date.parse(item.revokedAt));
  }
  return latest;
}
function valid(proof,origin){return proof?.status==='verified'&&proof.origin===origin&&['dns','http'].includes(proof.method)&&Number.isFinite(Date.parse(proof.verifiedAt))&&Date.parse(proof.expiresAt)>Date.now();}
export function ownershipRevoked(target){
  if(target.environment==='local')return false;
  const record=recordFor(originOf(target.url));
  const revoked=revokedAtFor(originOf(target.url),record);
  return !!revoked&&(!target.ownership?.verifiedAt||Date.parse(target.ownership.verifiedAt)<=revoked);
}
export function authorizationRevoked(target){
  if(target.environment==='local')return false;
  const origin=originOf(target.url),revoked=revokedAtFor(origin,recordFor(origin));
  return !!revoked&&(!target.authorization?.acceptedAt||Date.parse(target.authorization.acceptedAt)<=revoked);
}
export function sharedOwnership(url){
  const origin=originOf(url),record=recordFor(origin);
  if(!record||!valid(record.proof,origin)||Date.parse(record.proof.verifiedAt)<=revokedAtFor(origin,record))return null;
  return {...record.proof,reused:true,provenance:record.provenance};
}
export function rememberOwnership(state,target){
  if(state.demo||state.poc||target.environment==='local'||!valid(target.ownership,originOf(target.url)))return false;
  const origin=originOf(target.url),previous=recordFor(origin);
  if(Date.parse(target.ownership.verifiedAt)<=revokedAtFor(origin,previous))return false;
  if(previous&&valid(previous.proof,origin)&&Date.parse(previous.proof.verifiedAt)>=Date.parse(target.ownership.verifiedAt))return true;
  const {status,method,origin:verifiedOrigin,verifiedAt,expiresAt}=target.ownership;
  atomic(fileFor(origin),{version:1,origin,proof:{status,method,origin:verifiedOrigin,verifiedAt,expiresAt},revokedAt:previous?.revokedAt||null,
    provenance:{projectId:state.project.id,verifiedAt,method},savedAt:now()});
  return true;
}
export function rememberProjectOwnership(state){for(const target of state.targets)rememberOwnership(state,target);}
export function revokeOwnership(target){
  if(target.environment==='local')return;
  const origin=originOf(target.url);
  atomic(path.join(directory(),'revocations',hash(origin),id('revocation')+'.json'),{version:1,origin,revokedAt:now()});
}
