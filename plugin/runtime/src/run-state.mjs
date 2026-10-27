export const terminalRun=run=>['completed','failed','incomplete','cancelled','interrupted'].includes(run?.status);
export function summarizeRun(run){
  if(!run)return null;
  return {id:run.id,kind:run.kind,status:run.status,stage:run.stage,startedAt:run.startedAt,finishedAt:run.finishedAt,exitCode:run.exitCode,modelCalls:run.modelCalls||run.result?.modelCalls||0,
    message:run.result?.message||run.steps?.at(-1)?.message,details:run.result?.details,findings:run.result?.findings||[],
    sourceReads:run.agentEvidence?.sourceReads?.length||0,detailTool:'bypass_run',detailCommand:`run show ${run.id}`};
}
