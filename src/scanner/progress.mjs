export function reasoningProgress(run,stage) {
  const evaluation=stage==='evaluation',summary=evaluation?run.evaluationSummary:run.policy;
  if(!summary||!Number.isInteger(summary.tasks))return null;
  const finished=summary.finished||0,deferred=summary.deferred;
  const remaining=Math.max(0,summary.tasks-finished-(deferred||0));
  const parts=[`${evaluation?'Evaluation':'Policy'} tasks: ${finished}/${summary.tasks} complete`,
    `${remaining} ${evaluation&&deferred===undefined?'unfinished':'remaining'}`];
  if(deferred!==undefined)parts.push(`${deferred} deferred`);
  parts.push(`${run.signalCount||0} detector signals`,`${summary.modelRequests||0} model requests`);
  if(evaluation)parts.push(`${summary.confirmed||0} source-confirmed`,`${summary.refuted||0} refuted`,`${summary.needs_review||0} needs review`);
  return {stage,finished,total:summary.tasks,remaining,...(deferred!==undefined?{deferred}:{}),message:parts.join(' · ')};
}
