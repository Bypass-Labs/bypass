import { activeFindings } from './review-readiness.mjs';
// The next useful action follows evidence, not unfinished optional configuration.
export function homeActions(state) {
  const results=activeFindings(state).length>0,checks=state.checks.some(check=>check.enabled);
  const latest=state.runs?.at(-1),model=state.models?.find(m=>m.name===state.activeModel);
  const active=latest&&['queued','running'].includes(latest.status);
  const needsConnection=['connection','orchestrator','white-box','black-box'].includes(latest?.result?.details?.stage)&&(Date.parse(model?.lastAttempt?.checkedAt)||0)<=(Date.parse(latest.finishedAt)||0);
  return [
    active?{id:`run watch ${latest.id}`,label:'Watch the active review'}:needsConnection?{id:'model test',label:'Check model connection before retrying'}:checks?{id:'tests',label:'Replay saved tests'}:results?{id:'results',label:'Open review results'}:{id:'review',label:state.settings?.analysisEngine==='docker'?'Run my first real AI review':'Run my first review preview'},
    {id:'walkthrough',label:'Walk through prove → fix → retest → regression'},
    {id:'settings',label:'Settings & optional connections'}
  ];
}
export function previewRun(run) {return run?.kind==='scan'&&run.result?.simulation===true&&!!run.result.inventory;}
export function reviewSummary(plan){
  return `Repository: ${plan.repository.path}${plan.repository.branch?` (${plan.repository.branch})`:''}\nGit remote: ${plan.repository.remote||'local folder; no remote configured'}\nApp: ${plan.app?.url||'not connected; code preview is available'}\nWhite-box / code: ${plan.whiteBox.status}\nBlack-box / live app: ${plan.blackBox.status}\n${plan.blackBox.description}`;
}
export const quickCommands=`Commands you can type here (no IDs needed; / prefix optional):
  repo       Choose or change the application repository
  review     Run the selected analysis engine on this repository
  engine     Enable real Docker agents and configure HTTP proof
  poc        Create a separate local app for real AI testing
  results    Open findings and their next step
  demo       Follow the complete local walkthrough
  tests      Replay saved regression tests
  app        Connect an app or resume DNS verification
  models     Manage model connections
  plugin     Check or install the Muse plugin
  status     Show the source / app pairing and analysis scope
  history    Read saved project activity
  settings   Open all configuration and advanced controls
  back       Return to the project home
  q          Exit with your progress saved

Press Enter for the suggested next action. Type / to browse commands.
↑↓ select or recall commands · Tab complete · Esc back / stop current action
Ctrl+O expand details · PgUp/PgDn scroll · Ctrl+C exit
Use BYPASS_PLAIN=1 ./bypass for a plain scrolling interface.
Use help all for the full CLI command reference. You can also type raw commands such as target list or model test muse.`;
