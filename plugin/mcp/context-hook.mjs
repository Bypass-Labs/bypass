import { sessionHint } from '../runtime/src/plugin-context.mjs';
import { redact } from '../runtime/src/util.mjs';
// Read only. Never scan, infer, initialize a project or inject unrelated demo history.
let input='';
for await (const chunk of process.stdin) { input+=chunk; if(input.length>262144)process.exit(0); }
try {
  const payload=JSON.parse(input||'{}');
  const hint=sessionHint(payload.cwd||process.cwd());
  const review=hint.activeReview;
  const recovery=payload.source==='compact'
    ? review
      ? `Bypass source review ${review.id} is still ${review.status}. Plugin tool identifiers may need reloading after compaction. FIRST use Muse tool search for bypass_review_step and select the exact tool identifier and schema returned. Call it with ${JSON.stringify(review.resume.arguments)} to recover the saved next action, then follow that action's exact arguments. Never construct an mcp__plugin_bypass_security.* identifier, call the tool with empty arguments, restart the review, or use a no-op command to keep this turn alive. If a tool is unavailable, search again and retry the same run.`
      : 'If a Bypass blackbox audit is active, keep the same run. First search tools for bypass_blackbox_next and bypass_blackbox_submit; use the exact tool identifiers returned by search, never construct an identifier. Call next for the pending ID and schema, then submit that decision. If a tool is unavailable, search again and retry the same pending ID. Do not restart the audit.'
    : '';
  console.log(JSON.stringify({hookSpecificOutput:{hookEventName:'SessionStart',additionalContext:[recovery,JSON.stringify(redact(hint))].filter(Boolean).join('\n')}}));
}catch { console.log('{}'); }
