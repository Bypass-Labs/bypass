import { sessionHint } from '../runtime/src/plugin-context.mjs';
import { redact } from '../runtime/src/util.mjs';
// Read only. Never scan, infer, initialize a project or inject unrelated demo history.
let input='';
for await (const chunk of process.stdin) { input+=chunk; if(input.length>262144)process.exit(0); }
try {
  const payload=JSON.parse(input||'{}');
  const hint=sessionHint(payload.cwd||process.cwd());
  const recovery=payload.source==='compact'
    ? 'If a Bypass blackbox audit is active, keep the same run. First search tools for bypass_blackbox_next and bypass_blackbox_submit; use the exact tool identifiers returned by search, never construct an identifier. Call next for the pending ID and schema, then submit that decision. If a tool is unavailable, search again and retry the same pending ID. Do not restart the audit.'
    : '';
  console.log(JSON.stringify({hookSpecificOutput:{hookEventName:'SessionStart',additionalContext:[recovery,JSON.stringify(redact(hint))].filter(Boolean).join('\n')}}));
}catch { console.log('{}'); }
