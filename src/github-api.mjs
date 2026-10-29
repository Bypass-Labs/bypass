import { inflateRawSync } from 'node:zlib';
import { createHash } from 'node:crypto';
import { need, Fault } from './util.mjs';
import { sha, sourcePath } from './github-policy.mjs';

async function bounded(response,max=4000000){
  if(!response.ok)throw new Fault(`GitHub request failed (HTTP ${response.status}).`,3,{httpStatus:response.status});
  const chunks=[];let length=0;
  for await(const part of response.body){length+=part.length;need(length<=max,'GitHub response exceeds limit.',3);chunks.push(part);}
  return Buffer.concat(chunks);
}
export class GitHubAPI{
  constructor({token,repository,fetchImpl=fetch}){need(token,'GitHub token is missing.',3);need(/^[\w.-]+\/[\w.-]+$/.test(repository),'Invalid repository.');this.token=token;this.repository=repository;this.fetch=fetchImpl;this.base=`/repos/${repository}`;}
  async request(route,{method='GET',body}={}){
    need(route.startsWith(this.base+'/')||route===this.base,'GitHub request outside selected repository.');
    const response=await this.fetch('https://api.github.com'+route,{method,headers:{Accept:'application/vnd.github+json',Authorization:`Bearer ${this.token}`,'X-GitHub-Api-Version':'2022-11-28','Content-Type':'application/json'},body:body===undefined?undefined:JSON.stringify(body),redirect:'error',signal:AbortSignal.timeout(30000)});
    return JSON.parse((await bounded(response)).toString());
  }
  async pages(route,{cap=2000}={}){
    const values=[];
    for(let page=1;;page++){
      const list=await this.request(`${this.base}${route}${route.includes('?')?'&':'?'}per_page=100&page=${page}`);
      need(Array.isArray(list),'Invalid GitHub list response.');values.push(...list);need(values.length<=cap,'GitHub listing exceeded the review limit.',3);if(list.length<100)return values;
    }
  }
  async file(file,ref){
    need(sha(ref)&&typeof file==='string'&&!file.startsWith('/')&&!file.split('/').includes('..'),'Invalid source reference.');
    const response=await this.request(`${this.base}/contents/${file.split('/').map(encodeURIComponent).join('/')}?ref=${ref}`);
    need(response.type==='file'&&response.encoding==='base64'&&response.size<=1000000,'Unsupported or oversized source file.',3);
    const content=Buffer.from(response.content,'base64');need(content.length<=1000000&&!content.includes(0),'Source file is binary or oversized.',3);return content.toString('utf8');
  }
  async tree(ref){
    need(sha(ref),'Invalid tree revision.');const data=await this.request(`${this.base}/git/trees/${ref}?recursive=1`);
    need(!data.truncated,'Repository tree was truncated; narrow the review before retrying.',3);
    return data.tree.filter(e=>e.type==='blob'&&['100644','100755'].includes(e.mode)&&sourcePath(e.path));
  }
  async currentPR(number){need(Number.isInteger(number)&&number>0,'Invalid PR number.');return this.request(`${this.base}/pulls/${number}`);}
  async resolve(eventName,event,operation='auto',prNumber){
    need(['auto','review','smoke'].includes(operation),'Choose auto, review or smoke.');
    need(!(prNumber&&operation==='smoke'),'Clear the PR number when requesting smoke; smoke never invokes AI.');
    const repo=await this.request(this.base),branch=await this.request(`${this.base}/branches/${encodeURIComponent(repo.default_branch)}`);
    const context={repository:this.repository,repositoryId:repo.id,private:repo.private,defaultBranch:repo.default_branch,policySha:branch.commit.sha,sha:branch.commit.sha,kind:'baseline'};
    need(sha(context.sha),'Missing default-branch revision.');
    if(eventName==='workflow_run'){
      const run=await this.request(`${this.base}/actions/runs/${Number(event.workflow_run?.id)}`);
      need(run.event==='pull_request'&&run.path==='.github/workflows/bypass-pr-signal.yml'&&run.repository.id===repo.id,'Unexpected PR signal workflow.');
      need(run.status==='completed','PR signal is not complete.');
      const prs=run.pull_requests?.length?run.pull_requests:await this.pages(`/commits/${run.head_sha}/pulls`,{cap:100});
      const candidate=prs.find(p=>(p.head?.sha||run.head_sha)===run.head_sha&&(p.base?.repo?.id||repo.id)===repo.id);
      need(candidate,'Could not bind PR signal to a pull request; rerun manually with its number.',3);
      prNumber=candidate.number;context.signalSha=run.head_sha;
    }
    if(prNumber){
      const pr=await this.currentPR(Number(prNumber));need(pr.base.repo.id===repo.id&&pr.state==='open','PR is not open in this repository.');
      need(sha(pr.head.sha)&&sha(pr.base.sha),'PR must have immutable source revisions.');
      need(!context.signalSha||context.signalSha===pr.head.sha,'PR signal is superseded; the newer commit needs its own run.',3);
      need(!pr.draft,'Draft PRs are not automatically reviewed.',3);
      return {...context,kind:'review',pr:pr.number,sha:pr.head.sha,baseSha:pr.base.sha,changedFiles:pr.changed_files,fork:pr.head.repo?.id!==repo.id};
    }
    if(eventName==='deployment_status'){
      const deployment=await this.request(`${this.base}/deployments/${Number(event.deployment?.id)}`);
      const statuses=await this.request(`${this.base}/deployments/${deployment.id}/statuses?per_page=1`);
      need(statuses[0]?.state==='success'&&Number(event.deployment_status?.id)===statuses[0].id,'Deployment is not the latest successful status.',3);
      need(sha(deployment.sha),'Deployment must identify its source commit.');
      return {...context,kind:'verify',sha:deployment.sha,deploymentId:deployment.id,environment:deployment.environment,deploymentURL:statuses[0].environment_url};
    }
    if(eventName==='schedule'||operation==='smoke')return {...context,kind:'smoke'};
    need(['push','workflow_dispatch'].includes(eventName),'Use the trusted PR signal, push, deployment, schedule or manual workflow.',3);
    if(eventName==='push')need(event.ref===`refs/heads/${repo.default_branch}`,'Baseline must come from the default branch.');
    need(operation==='auto'||operation==='review','Choose a PR for review, or smoke for the configured deployments.');
    return context;
  }
  async latestDeployment(environment,origin){
    const deployments=await this.request(`${this.base}/deployments?environment=${encodeURIComponent(environment)}&per_page=20`);
    for(const d of deployments){
      const statuses=await this.request(`${this.base}/deployments/${d.id}/statuses?per_page=1`);
      if(statuses[0]?.state!=='success')continue;
      if(origin){try{if(new URL(statuses[0].environment_url).origin!==origin)continue;}catch{continue;}}
      return {...d,url:statuses[0].environment_url};
    }
    throw new Error('No active successful deployment is registered for this environment.');
  }
}

// Read exactly one bounded JSON member; never extract or execute downloaded files.
export function artifactState(zip){
  need(zip.length<=4000000,'State archive exceeds limit.');let end=-1;
  for(let i=zip.length-22;i>=Math.max(0,zip.length-65557);i--)if(zip.readUInt32LE(i)===0x06054b50){end=i;break;}
  need(end>=0,'Invalid state archive.');const count=zip.readUInt16LE(end+10);let at=zip.readUInt32LE(end+16),found;
  need(count<=10,'Unexpected state archive members.');
  for(let n=0;n<count;n++){
    need(at+46<=zip.length&&zip.readUInt32LE(at)===0x02014b50,'Invalid archive directory.');
    const method=zip.readUInt16LE(at+10),size=zip.readUInt32LE(at+20),plain=zip.readUInt32LE(at+24),length=zip.readUInt16LE(at+28),extra=zip.readUInt16LE(at+30),comment=zip.readUInt16LE(at+32),offset=zip.readUInt32LE(at+42);
    const name=zip.subarray(at+46,at+46+length).toString();at+=46+length+extra+comment;
    need(name==='state.json'&&!found,'Unexpected or duplicate state archive member.');
    need(plain<=2000000&&offset+30<=zip.length&&zip.readUInt32LE(offset)===0x04034b50,'Invalid archive member.');
    const start=offset+30+zip.readUInt16LE(offset+26)+zip.readUInt16LE(offset+28);need(start+size<=zip.length,'Truncated archive member.');
    const compressed=zip.subarray(start,start+size);need([0,8].includes(method),'Unsupported archive compression.');
    const output=method===8?inflateRawSync(compressed,{maxOutputLength:2000000}):compressed;need(output.length===plain,'Invalid archive size.');found=JSON.parse(output.toString());
  }
  need(found?.version===1&&Array.isArray(found.findings)&&found.findings.length<=500&&found.targets&&typeof found.targets==='object','Invalid persisted agent state.');return found;
}
export async function restoreGitHubState(api,context,currentRun){
  const empty=()=>({state:{version:1,repositoryId:context.repositoryId,findings:[],targets:{}},restoredFrom:null});
  let runs;try{runs=await api.request(`${api.base}/actions/workflows/bypass-security.yml/runs?per_page=30`);}catch(error){if(error.details?.httpStatus===404)return empty();throw error;}
  for(const run of runs.workflow_runs||[]){
    if(run.id===Number(currentRun)||run.status!=='completed'||run.event==='workflow_run'||run.head_branch!==context.defaultBranch||!['push','schedule','workflow_dispatch','deployment_status'].includes(run.event))continue;
    const listing=await api.request(`${api.base}/actions/runs/${run.id}/artifacts?per_page=100`);
    const artifact=listing.artifacts.find(a=>a.name==='bypass-state'&&!a.expired&&a.size_in_bytes<=4000000);if(!artifact)continue;
    const response=await api.fetch(`https://api.github.com${api.base}/actions/artifacts/${artifact.id}/zip`,{headers:{Authorization:`Bearer ${api.token}`},redirect:'manual',signal:AbortSignal.timeout(30000)});
    need(response.status===302,'Could not retrieve state artifact.',3);const location=new URL(response.headers.get('location'));need(location.protocol==='https:'&&!location.username&&!location.password,'Invalid artifact destination.');
    const zip=await bounded(await api.fetch(location,{redirect:'error',signal:AbortSignal.timeout(30000)}));
    if(artifact.digest)need(artifact.digest===`sha256:${createHash('sha256').update(zip).digest('hex')}`,'State artifact digest mismatch.',3);
    const state=artifactState(zip);need(state.repositoryId===context.repositoryId&&state.runId===run.id,'State provenance mismatch.',3);
    if(state.kind==='review')continue;
    need(['baseline','verify','smoke'].includes(state.kind),'Untrusted memory provenance.',3);
    return {state,restoredFrom:run.id};
  }
  return empty();
}
