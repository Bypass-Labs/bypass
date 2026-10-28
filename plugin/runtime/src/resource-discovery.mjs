import { read } from './store.mjs';
import { scopeReady, safeRequest, pathAllowed } from './network.mjs';
import { credentialEnvironment } from './credentials.mjs';
import { jsonField } from './portable-check.mjs';
import { named, need, delay, hash } from './util.mjs';
import { execute } from './service.mjs';

// Read only the user's chosen collection. Return identifiers, never object
// contents; accept only entries explicitly attributed to the signed-in account.
export async function discoverResources(root,o,{signal}={}){
  const state=read(root),target=named(state.targets,o.target||state.activeTarget,'Target'),owner=named(state.identities,o.owner,'Identity');
  need(owner.type==='bearer','Automatic collection discovery currently supports bearer accounts; cookie/header probes can be configured directly.',3);
  for(const p of [o.path,o['resource-prefix'],owner.checkPath]){need(typeof p==='string'&&p.startsWith('/')&&!p.startsWith('//')&&!/[?#\\]/.test(p)&&pathAllowed(p,[p]),'Use exact safe collection, identity and resource paths.');scopeReady(target,p);}
  need(o['items-field']&&o['owner-field'],'Derive collection and ownership selectors from source.');
  const env=await credentialEnvironment(state,target,[owner],{signal});need(env[owner.secretEnv],'Connect the owner account or run the authorized registration check first.',3);
  const headers={Authorization:`Bearer ${env[owner.secretEnv]}`},options={headers,allowLocal:target.environment==='local',signal,timeout:state.settings.requestTimeoutMs};
  const profile=await safeRequest(target.url+owner.checkPath,options);need(profile.status===200,'Owner login control failed. Reconnect the account.',3);
  let subject;try{subject=jsonField(JSON.parse(profile.body),o['identity-field']||'id');}catch{}
  need(['string','number'].includes(typeof subject),'Owner identity selector did not match.',3);
  await delay(Math.ceil(1000/target.authorization.maxRequestsPerSecond),undefined,{signal});
  scopeReady(named(read(root).targets,target.name,'Target'),o.path);
  const response=await safeRequest(target.url+o.path,options);need(response.status===200,'Collection is unavailable; no resource was guessed or created.',3);
  let items;try{items=jsonField(JSON.parse(response.body),o['items-field']);}catch{}
  need(Array.isArray(items),'Collection selector must identify a JSON array.',3);
  const ids=[...new Set(items.filter(item=>String(jsonField(item,o['owner-field']))===String(subject)).map(item=>jsonField(item,o['id-field']||'id')).filter(value=>['string','number'].includes(typeof value)&&/^[A-Za-z0-9_-]{1,160}$/.test(String(value))).map(String))].slice(0,Math.max(0,6-(target.probes||[]).length));
  const probes=[];
  for(const resourceId of ids){
    const resourcePath=o['resource-prefix'].replace(/\/$/,'')+'/'+resourceId;
    const result=await execute('probe add',[`owned_${hash(resourcePath).slice(0,12)}`],{project:root,target:target.name,path:resourcePath,'resource-id':resourceId,owner:o.owner,outsider:o.outsider,'id-field':o['resource-id-field']||o['id-field']||'id','identity-field':o['identity-field']||'id'},{signal});
    probes.push({name:result.probe.name,resourcePath,resourceId});
  }
  return {status:probes.length?'configured':'needs_resource',probes,requests:2,modelCalls:0,bodyStored:false,message:probes.length?'Owned resources selected from the authorized collection. Review executes all identity/resource controls.':'No suitable owned test resource found. Continue other checks; create test data only with authorization.'};
}
