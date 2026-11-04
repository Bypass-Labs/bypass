import fs from 'node:fs';
import path from 'node:path';
import {atomic, read} from './store.mjs';
import {scopeReady, safeRequest} from './network.mjs';
import {verifyRun} from './blackbox/poc.mjs';
import {need} from './util.mjs';

const receiptFile = (root, review) => path.join(root, '.bypass', 'runs', `remediation-${review}.json`);
const proofRun = value => /^bx-\d{8}-[0-9a-f]{8}$/.test(value);
const reviewRun = value => /^run_[0-9a-f]{8}$/.test(value);
const revision = value => typeof value === 'string' && /^[0-9a-f]{40,64}$/i.test(value);

function load(root, review) {
  need(reviewRun(review), 'Provide the saved source-review run ID.');
  const file = receiptFile(root, review);
  need(fs.existsSync(file), `No remediation checkpoint exists for ${review}.`);
  return JSON.parse(fs.readFileSync(file, 'utf8'));
}

export function latestRemediation(root) {
  const dir = path.join(root, '.bypass', 'runs');
  if (!fs.existsSync(dir)) return null;
  const receipts = fs.readdirSync(dir).filter(name => /^remediation-run_[0-9a-f]{8}\.json$/.test(name))
    .map(name => { try { return JSON.parse(fs.readFileSync(path.join(dir, name), 'utf8')); } catch { return null; } })
    .filter(item => item && ['pending_merge', 'pending_deployment', 'inconclusive',
      'still_vulnerable'].includes(item.status))
    .sort((a, b) => Date.parse(b.updatedAt) - Date.parse(a.updatedAt));
  return receipts[0] ?? null;
}

function nextAction(receipt) {
  if (receipt.status === 'pending_merge') return {waitFor: 'pull_request_merge',
    message: 'Check the PR and its required checks. After the user merges it, call replay with the full merge revision. The deployment has not been retested.'};
  if (receipt.status === 'pending_deployment') return {waitFor: 'deployment',
    message: receipt.deployment?.status === 'unavailable' ?
      `The deployment revision could not be checked: ${receipt.deployment.reason}. Restore the target connection or scope, then retry replay.` :
      'Wait for the merged build to deploy, then call replay again. Do not claim the finding fixed before fresh proof replay.'};
  if (receipt.status === 'inconclusive') return {waitFor: 'replay_repair',
    message: 'One or more fresh proofs could not reach a verdict. Inspect their reasons and retry after fixing the test environment.'};
  if (receipt.status === 'still_vulnerable') return {waitFor: 'additional_remediation',
    message: 'At least one original proof still reproduces on the deployed build. Keep it open and prepare another fix.'};
  return null;
}

function summary(receipt) {
  return {kind: 'remediation-checkpoint', review: receipt.review, pr: receipt.pr,
    branch: receipt.branch, target: receipt.target, proofRuns: receipt.proofRuns,
    sourceFindings: receipt.sourceFindings, revisionPath: receipt.revisionPath,
    revisionField: receipt.revisionField,
    status: receipt.status, mergeRevision: receipt.mergeRevision,
    deployment: receipt.deployment, results: receipt.results,
    nextAction: nextAction(receipt)};
}

function save(root, receipt) {
  receipt.updatedAt = new Date().toISOString();
  atomic(receiptFile(root, receipt.review), receipt);
  return summary(receipt);
}

function revisionPath(value, origin) {
  if (value == null || value === '') return null;
  need(typeof value === 'string' && value.startsWith('/'),
    'The revision endpoint must be an in-scope app path.');
  const url = new URL(value, origin);
  need(url.origin === origin && url.search === '' && url.hash === '',
    'The revision endpoint must be an in-scope app path without a query.');
  return url.pathname;
}

async function deployedRevision(root, receipt, signal, request) {
  if (!receipt.revisionPath) return {status: 'unverified', reason: 'No deployed revision endpoint was supplied.'};
  const target = read(root).targets.find(item => item.url === receipt.target);
  const url = new URL(receipt.revisionPath, receipt.target);
  try {
    need(target, 'The saved target is no longer connected.');
    scopeReady(target, url.pathname, 'GET');
    const response = await request(url.href, {method: 'GET', allowLocal: target.environment === 'local',
      allowRemoteHttp: true, signal});
    let document;
    try { document = JSON.parse(response.body); } catch { /* Missing JSON is an unverified deployment. */ }
    const value = receipt.revisionField.split('.').reduce((entry, key) => entry?.[key], document);
    return {status: response.status === 200 && revision(value) ?
      value === receipt.mergeRevision ? 'matched' : 'mismatched' : 'unverified',
      path: receipt.revisionPath, field: receipt.revisionField,
      liveRevision: revision(value) ? value : null, httpStatus: response.status};
  } catch (error) {
    return {status: 'unavailable', path: receipt.revisionPath, reason: error.message};
  }
}

export async function remediationCheckpoint(root, input, {signal, request = safeRequest, verify = verifyRun} = {}) {
  const {action, review} = input;
  need(['open', 'status', 'replay'].includes(action), 'Choose open, status, or replay.');
  need(reviewRun(review), 'Provide the saved source-review run ID.');
  if (action === 'open') {
    const state = read(root), run = state.runs.find(item => item.id === review);
    need(run?.host?.mode === 'combined' && ['completed', 'incomplete'].includes(run.status),
      'Select a completed combined source-review run.');
    const target = state.targets.find(item => item.name === run.host.target);
    need(target?.url, 'The review has no connected app target.');
    need(typeof input.pr === 'string', 'Provide the opened pull-request URL.');
    let pr;
    try { pr = new URL(input.pr); } catch { need(false, 'Provide a valid pull-request URL.'); }
    need(pr.protocol === 'https:' && !pr.username && !pr.password,
      'Provide the opened HTTPS pull-request URL.');
    need(typeof input.branch === 'string' && input.branch.trim(), 'Provide the PR branch.');
    need(Array.isArray(input.runs) && input.runs.length > 0 && input.runs.every(proofRun),
      'Provide the confirmed blackbox proof run IDs.');
    const proofRuns = [...new Set(input.runs)].sort(), sourceFindings = [];
    for (const id of proofRuns) {
      const file = path.join(root, '.bypass', 'runs', id, 'run.json');
      need(fs.existsSync(file), `Proof run ${id} is missing.`);
      const saved = JSON.parse(fs.readFileSync(file, 'utf8'));
      const focused=run.result?.findings?.includes(saved.focus?.findingId);
      const connected=saved.combinedReviewId===review;
      need((focused||connected) &&
        (saved.origin ?? saved.scope?.target?.origin) === target.url,
        `Proof run ${id} does not belong to this review and target.`);
      const poc = path.join(root, '.bypass', 'runs', id, 'poc');
      need(fs.existsSync(poc) && fs.readdirSync(poc).some(name =>
        fs.existsSync(path.join(poc, name, 'spec.json'))),
        `Proof run ${id} has no saved proof to replay.`);
      if(focused){
        const finding = state.findings.find(item => item.id === saved.focus.findingId);
        sourceFindings.push({run: id, finding: saved.focus.findingId,
          title: finding?.title ?? saved.focus.findingId});
      }else{
        let proofs=[];
        try{proofs=JSON.parse(fs.readFileSync(path.join(root,'.bypass','runs',id,'findings.json'),'utf8'));}
        catch{ /* The proof requirement below reports the missing evidence. */ }
        const proofRoot=path.resolve(poc)+path.sep;
        const confirmed=proofs.filter(item=>item.verdict==='confirmed'&&item.id&&item.proof&&
          path.resolve(item.proof).startsWith(proofRoot)&&
          path.basename(item.proof)==='poc.mjs'&&fs.existsSync(item.proof)&&
          fs.existsSync(path.join(path.dirname(item.proof),'spec.json')));
        need(confirmed.length>0,`Connected run ${id} has no sealed confirmed proof to replay.`);
        for(const item of confirmed){
          const linked=state.findings.find(finding=>finding.id===item.sourceFinding?.id||
            finding.verification?.blackboxRun===id&&finding.verification?.blackboxFindingId===item.id);
          sourceFindings.push({run:id,finding:linked?.id??null,title:linked?.title??item.title,
            proof:item.id});
        }
      }
    }
    const file = receiptFile(root, review);
    if (fs.existsSync(file)) {
      const previous = load(root, review);
      need(previous.pr === pr.href && previous.branch === input.branch.trim() &&
        previous.target === target.url &&
        JSON.stringify(previous.proofRuns) === JSON.stringify(proofRuns),
        `A different remediation checkpoint already exists for ${review}; read it with status.`);
      return summary(previous);
    }
    const receipt = {version: 1, review, pr: pr.href, branch: input.branch.trim(), target: target.url,
      proofRuns, sourceFindings, revisionPath: revisionPath(input.revisionPath, target.url),
      revisionField: input.revisionField ?? 'revision',
      status: 'pending_merge', mergeRevision: null, deployment: null, results: [],
      createdAt: new Date().toISOString()};
    return save(root, receipt);
  }
  const receipt = load(root, review);
  if (action === 'status') return summary(receipt);
  if (input.mergeRevision != null) {
    need(revision(input.mergeRevision), 'Provide the full merged commit SHA.');
    need(!receipt.mergeRevision || receipt.mergeRevision === input.mergeRevision,
      'This checkpoint is linked to a different merge revision. Inspect the PR before replay.');
    receipt.mergeRevision = input.mergeRevision;
  }
  need(receipt.mergeRevision, 'Check the PR merge and provide its full merged commit SHA before replay.');
  if (input.revisionPath != null) receipt.revisionPath = revisionPath(input.revisionPath, receipt.target);
  if (input.revisionField != null) receipt.revisionField = input.revisionField;
  receipt.deployment = await deployedRevision(root, receipt, signal, request);
  if (receipt.revisionPath && receipt.deployment.status !== 'matched') {
    receipt.status = 'pending_deployment';
    return save(root, receipt);
  }
  if (!receipt.revisionPath && input.deploymentObserved !== true) {
    receipt.status = 'pending_deployment';
    return save(root, receipt);
  }
  const results = [];
  for (const id of receipt.proofRuns) {
    try {
      const replay = await verify(root, id);
      const proofs = replay.proofs.map(proof => ({id: proof.id, verdict: proof.verdict,
        reason: proof.reason ?? null}));
      const linked=receipt.sourceFindings.filter(item=>item.run===id);
      for(const item of linked){
        const matching=item.proof?proofs.filter(proof=>proof.id===item.proof):proofs;
        const verdict=replay.integrity?.ok!==true?'inconclusive':
          matching.some(proof=>proof.verdict==='confirmed')?'still_vulnerable':
          matching.length&&matching.every(proof=>proof.verdict==='not_reproduced')?'not_reproduced':'inconclusive';
        results.push({run:id,...item,status:verdict,proofs:matching,
          ...(replay.integrity?.ok!==true?{reason:'Saved evidence integrity was not verified.'}:{}),
          ...(!matching.length?{reason:'Saved proof was absent from replay results.'}:{})});
      }
    } catch (error) {
      for(const item of receipt.sourceFindings.filter(item=>item.run===id))
        results.push({run:id,...item,status:'inconclusive',proofs:[],reason:error.message});
    }
  }
  receipt.results = results;
  receipt.status = results.some(item => item.status === 'inconclusive') ? 'inconclusive' :
    results.some(item => item.status === 'still_vulnerable') ? 'still_vulnerable' : 'retested';
  return save(root, receipt);
}
