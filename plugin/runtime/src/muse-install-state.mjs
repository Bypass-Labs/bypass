import fs from 'node:fs';
import path from 'node:path';
import { createHash } from 'node:crypto';

// Compare every installed byte, not just the version or manifest. Identical
// reruns should preserve Muse's decisions; changed packages need a new review.
export function samePluginPackage(left,right){
  if(!left||!right)return false;
  const digest=root=>{
    const hash=createHash('sha256');
    function visit(relative=''){
      for(const name of fs.readdirSync(path.join(root,relative)).sort()){
        const entry=path.join(relative,name),file=path.join(root,entry),stat=fs.lstatSync(file);
        if(stat.isSymbolicLink())throw new Error('Cannot compare a linked package');
        hash.update(JSON.stringify([entry,stat.isDirectory()?'directory':'file',stat.mode&0o111]));
        if(stat.isDirectory())visit(entry);
        else if(stat.isFile())hash.update(createHash('sha256').update(fs.readFileSync(file)).digest('hex'));
        else throw new Error('Unsupported package entry');
      }
    }
    visit();return hash.digest('hex');
  };
  try{return digest(left)===digest(right);}catch{return false;}
}

export function museInstallState(inspected){
  const capabilities=(inspected?.runtime_capabilities||[]).map(row=>({id:row.candidate?.stable_id,status:row.status}));
  const required=['plugin:bypass:hook:session-context','plugin:bypass:mcp_server:security'];
  const approved=required.every(id=>capabilities.some(row=>row.id===id&&row.status==='trusted_enabled'));
  const active=inspected?.valid===true&&inspected?.active===true;
  const state=!inspected?.valid?'repair_required':!active?'enable_required':approved?'ready_for_new_session':'review_required';
  const next=state==='repair_required'?'Repair the installation before starting a review.':state==='enable_required'?'In Muse, open /plugins → Installed → Bypass and enable it. Review its runtime permissions, then start a new Muse session and use /bypass:start.':state==='ready_for_new_session'?'Start a new Muse session in your application folder and use /bypass:start.':'In Muse, open /plugins → Installed → Bypass → Runtime. Review and approve its MCP server and session hook, then start a new Muse session and use /bypass:start.';
  return {state,active,reviewRequired:!approved,capabilities,next};
}
