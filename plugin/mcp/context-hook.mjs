import { sessionHint } from '../runtime/src/plugin-context.mjs';
import { redact } from '../runtime/src/util.mjs';
// Read only. Never scan, infer, initialize a project or inject unrelated demo history.
let input='';
for await (const chunk of process.stdin) { input+=chunk; if(input.length>262144)process.exit(0); }
try {
  const payload=JSON.parse(input||'{}');
  const hint=sessionHint(payload.cwd||process.cwd());
  console.log(JSON.stringify({hookSpecificOutput:{hookEventName:'SessionStart',additionalContext:JSON.stringify(redact(hint))}}));
}catch { console.log('{}'); }
