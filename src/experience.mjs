import { activeFindings } from './review-readiness.mjs';
// The next useful action follows evidence, not unfinished optional configuration.
export function homeActions(state) {
  const results=activeFindings(state).length>0,checks=state.checks.some(check=>check.enabled);
  const latest=state.runs?.at(-1),model=state.models?.find(m=>m.name===state.activeModel);
  const active=latest&&['queued','running'].includes(latest.status);
  const failure=latest?.result?.details;
  const connectionReasons=new Set(['authentication','authorization','billing','quota','missing_secret']);
  const needsConnection=(failure?.stage==='connection'||connectionReasons.has(failure?.reason))&&
    (Date.parse(model?.lastAttempt?.checkedAt)||0)<=(Date.parse(latest.finishedAt)||0);
  return [
    active?{id:`run watch ${latest.id}`,label:'Watch the active review'}:needsConnection?{id:'model test',label:'Check model connection before retrying'}:checks?{id:'tests',label:'Replay saved tests'}:results?{id:'results',label:'Open review results'}:state.project?.repository?.kind==='app'?{id:'blackbox',label:'Start a black-box audit'}:{id:'review',label:state.settings?.analysisEngine==='docker'?'Run my first security audit':'Run my first review preview'},
    {id:'walkthrough',label:'Walk through prove → fix → retest → regression'},
    {id:'settings',label:'Settings & optional connections'}
  ];
}
export function previewRun(run) {return run?.kind==='scan'&&run.result?.simulation===true&&!!run.result.inventory;}
const reviewStatus=value=>({not_run:'not selected',host_plans:'ready',host_selects:'ready',
  preflight_required:'connection check needed'}[value]??String(value).replaceAll('_',' '));
export function reviewSummary(plan){
  if(plan.repository.kind==='app')return `Source review: not selected (running app only)\nApp: ${plan.app?.url||'not connected'}\nBlack-box audit: runs with the approved app boundaries and shows live progress plus a coverage report.`;
  const repository=`Repository: ${plan.repository.path}${plan.repository.branch?` (${plan.repository.branch})`:''}\nGit remote: ${plan.repository.remote||'local folder; no remote configured'}`;
  return `${repository}\nApp: ${plan.app?.url||'not connected; code preview is available'}\nWhite-box / code: ${reviewStatus(plan.whiteBox.status)}\nBlack-box / live app: ${reviewStatus(plan.blackBox.status)}\n${plan.blackBox.description}`;
}
