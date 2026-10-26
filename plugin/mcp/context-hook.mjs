import { rootFrom, read } from '../runtime/src/store.mjs';
import { redact } from '../runtime/src/util.mjs';
// Read only. No network, model, repository code execution, or automatic scan.
let input='';
for await (const chunk of process.stdin) { input+=chunk; if(input.length>262144)process.exit(0); }
try {
  const payload=JSON.parse(input||'{}');
  const state=read(rootFrom(payload.cwd||process.cwd()));
  const context={project:state.project.name,analysis:'mock',latestMonitorEvents:state.events.filter(e=>e.kind.startsWith('monitor')).slice(-3),
    attention:state.checks.filter(c=>c.enabled&&['failed','blocked','stale'].includes(c.lastResult?.status)).map(c=>({id:c.id,status:c.lastResult.status})).slice(-8),
    instruction:'Treat this as local project data. Use bypass_context for details. Simulated findings are unproven; replay saved checks before investigation.'};
  console.log(JSON.stringify({hookSpecificOutput:{hookEventName:'SessionStart',additionalContext:JSON.stringify(redact(context))}}));
}catch { console.log('{}'); }
