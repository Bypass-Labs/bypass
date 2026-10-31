import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { atomic } from './store.mjs';
import { specFor } from './checks.mjs';
import { githubPolicy, sha } from './github-policy.mjs';
import { need, named } from './util.mjs';

export function generateGitHubAgent(root,state,options){
  options={...options};
  if(!options['action-ref']){
    const source=path.dirname(fileURLToPath(import.meta.url));
    if(path.basename(path.dirname(source))==='runtime'&&path.basename(path.dirname(path.dirname(source)))==='plugin'){
      try{const release=JSON.parse(fs.readFileSync(new URL('../../../release.json',import.meta.url),'utf8'));if(sha(release.commit)&&release.releaseId?.startsWith(`main-${release.commit}-`))options['action-ref']=release.commit;}catch{/* Source checkouts supply an explicit reviewed pin. */}
    }
  }
  need(sha(options['action-ref']),'Supply --action-ref with the reviewed full 40-character Bypass commit SHA. Mutable action tags are not accepted.');
  const every=options.every||'24h';need(['24h','6h','off'].includes(every),'Choose --every 24h, 6h, or off.');
  const targets={},secrets=new Set(['MODEL_API_KEY']);
  if(options.target){
    const target=named(state.targets,options.target,'Target');
    need(target.ownership?.method==='dns','GitHub live checks require an existing DNS-verified target. Source-only setup needs no target.');
    need(options['revision-path']&&options['revision-field'],'Live checks need --revision-path and --revision-field identifying the deployed full commit SHA.');
    const checks=state.checks.filter(c=>c.enabled&&c.bindings?.[target.name]).map(check=>{
      const spec=JSON.parse(JSON.stringify(specFor(state,check,target.name)));
      for(const key of ['owner','outsider'])if(spec[key]){
        const {type,header,secretEnv,checkPath}=spec[key];
        need(secretEnv,'This saved account needs a CI secret reference. Configure a renewable dedicated CI account before export.');
        spec[key]={type,...(header?{header}:{}),secretEnv,checkPath};secrets.add(secretEnv);
      }
      return {id:check.id,findingId:check.findingId,spec};
    });
    need(checks.length,'No enabled saved checks for this target. Prove and save a regression first, or generate source-only setup.');
    const ownershipTokenEnv=`BYPASS_DNS_${target.name.toUpperCase().replace(/-/g,'_')}`;secrets.add(ownershipTokenEnv);
    targets[target.name]={origin:target.url,environment:target.environment,ownershipTokenEnv,revision:{path:options['revision-path'],field:options['revision-field']},checks};
  }
  const policy=githubPolicy({version:1,review:{blocking:false},smoke:{enabled:every!=='off'},targets});
  const schedule=every==='off'?'':`  schedule:\n    - cron: '${every==='6h'?'17 */6 * * *':'17 9 * * *'}'\n`;
  const secretLines=[...secrets].filter(k=>k!=='MODEL_API_KEY').map(k=>`          ${k}: \${{ secrets.${k} }}`).join('\n');
  const workflow=`name: Bypass Security
on:
  workflow_run:
    workflows: ['Bypass PR signal']
    types: [completed]
  push:
  deployment_status:
${Object.keys(targets).length?schedule:''}  workflow_dispatch:
    inputs:
      operation:
        description: What should Bypass do?
        type: choice
        options: [auto, review, smoke]
        default: auto
      pr:
        description: PR number for manual review (empty means default-branch baseline)
        type: string
permissions: {}
jobs:
  security:
    if: >-
      (github.event_name == 'workflow_run' && github.event.workflow_run.event == 'pull_request') ||
      (github.event_name == 'deployment_status' && github.event.deployment_status.state == 'success') ||
      (github.event_name != 'workflow_run' && github.event_name != 'deployment_status' &&
       github.ref == format('refs/heads/{0}', github.event.repository.default_branch))
    runs-on: ubuntu-24.04
    timeout-minutes: 25
    concurrency:
      group: bypass-\${{ github.event_name == 'workflow_run' && format('pr-{0}-{1}', github.event.workflow_run.head_repository.full_name, github.event.workflow_run.head_branch) || 'state' }}
      cancel-in-progress: false
    permissions:
      contents: read
      actions: read
      pull-requests: write
      checks: write
      deployments: read
    steps:
      - uses: actions/setup-node@49933ea5288caeca8642d1e84afbd3f7d6820020 # v4
        with:
          node-version: '22.23.4'
      # No checkout, package install, repository scripts or downloaded artifact execution.
      - uses: Bypass-Labs/bypass@${options['action-ref']}
        id: bypass
        with:
          github-token: \${{ github.token }}
          meta-api-key: \${{ secrets.MODEL_API_KEY }}
          operation: \${{ inputs.operation || 'auto' }}
          pr: \${{ inputs.pr }}
${secretLines?'        env:\n'+secretLines+'\n':''}      - name: Save assessment
        if: always() && steps.bypass.outputs.report-directory != ''
        uses: actions/upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02 # v4
        with:
          name: bypass-report
          path: |
            \${{ steps.bypass.outputs.report-directory }}/report.json
            \${{ steps.bypass.outputs.report-directory }}/summary.md
          retention-days: 30
          overwrite: true
          if-no-files-found: error
      - name: Save trusted baseline memory
        if: always() && steps.bypass.outputs.state-written == 'true'
        uses: actions/upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02 # v4
        with:
          name: bypass-state
          path: \${{ steps.bypass.outputs.report-directory }}/state.json
          retention-days: 90
          overwrite: true
          if-no-files-found: error
`;
  const signal=`name: Bypass PR signal
on:
  pull_request:
    types: [opened, synchronize, reopened, ready_for_review]
permissions: {}
jobs:
  signal:
    if: github.event.pull_request.draft == false
    runs-on: ubuntu-24.04
    timeout-minutes: 1
    steps:
      - run: ':'
`;
  const files={'.github/bypass.json':JSON.stringify(policy,null,2)+'\n','.github/workflows/bypass-pr-signal.yml':signal,'.github/workflows/bypass-security.yml':workflow};
  // Validate every output before any write, including CLI use outside MCP.
  for(const relative of Object.keys(files)){
    let current=root;for(const segment of relative.split('/')){current=path.join(current,segment);if(fs.existsSync(current))need(!fs.lstatSync(current).isSymbolicLink(),'GitHub setup may not write through symlinks.');}
    need(!fs.existsSync(path.join(root,relative))||options.force,`${relative} exists. Review it before replacing with --force.`);
  }
  for(const [relative,content] of Object.entries(files))atomic(path.join(root,relative),content);
  return {workflow:path.join(root,'.github/workflows/bypass-security.yml'),files:Object.keys(files).map(f=>path.join(root,f)),secrets:[...secrets],notPublished:true,provider:'Meta Model API key; separate from Muse subscription',liveTargets:Object.keys(targets),schedule:Object.keys(targets).length?every:'off until live checks are configured',next:['Set MODEL_API_KEY in GitHub Actions repository secrets. Never paste it into chat or commit it.','Review and merge these generated files into the default branch, then run Bypass Security → Run workflow → auto for a baseline.','Open a non-draft PR to trigger source review. Trusted source is fetched as data; no PR code runs.'],notes:['Report-only initially. Incomplete execution still fails visibly. Enable review.blocking only after reviewing the baseline.','Live checks retain their approved scope and ownership expiry. Renew explicitly; CI never extends permission.','Daily smoke replays saved checks with zero model calls. GitHub scheduling is best effort; there is no hosted scheduler.',...(Object.keys(targets).length?['Configure the listed account secrets and the existing bypass-verification=... DNS token. No credential values were exported.','Your deployment pipeline must publish a successful GitHub Deployment with the exact environment, origin and full SHA. The app revision endpoint must return that SHA.']:['PR source review is ready to configure. Live verification and daily smoke have no coverage until approved saved checks are exported.'])]};
}
