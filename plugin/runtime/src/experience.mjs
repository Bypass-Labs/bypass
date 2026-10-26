// The next useful action follows evidence, not unfinished optional configuration.
export function homeActions(state) {
  const results=state.findings.length>0,checks=state.checks.some(check=>check.enabled);
  return [
    checks?{id:'tests',label:'Replay saved tests'}:results?{id:'results',label:'Open review results'}:{id:'review',label:'Run my first review preview'},
    {id:'walkthrough',label:'Walk through prove → fix → retest → regression'},
    {id:'settings',label:'Settings & optional connections'}
  ];
}
export function previewRun(run) {return run?.kind==='scan'&&run.result?.simulation===true&&!!run.result.inventory;}
export function reviewSummary(plan){
  return `Repository: ${plan.repository.path}${plan.repository.branch?` (${plan.repository.branch})`:''}\nGit remote: ${plan.repository.remote||'local folder; no remote configured'}\nApp: ${plan.app?.url||'not connected; code preview is available'}\nWhite-box / code: ${plan.whiteBox.status}\nBlack-box / live app: ${plan.blackBox.status}\n${plan.blackBox.description}`;
}
export const quickCommands=`Commands you can type here (no IDs needed):
  repo       Choose or change the application repository
  review     Run a review preview of this repository
  results    Open findings and their next step
  demo       Follow the complete local walkthrough
  tests      Replay saved regression tests
  app        Connect an app or resume DNS verification
  models     Manage model connections
  plugin     Check or install the Muse plugin
  settings   Open all configuration and advanced controls
  back       Return to the project home
  q          Exit with your progress saved

Press Enter on the home screen to take action 1.
Use help all for the full CLI command reference. You can also type raw commands such as target list or model test muse.`;
