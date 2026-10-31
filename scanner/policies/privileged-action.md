# Privileged actions

Invariant: sensitive administrative operations must enforce the caller's authority
on the server before changing roles, credentials, tenant membership, configuration,
or other protected state. Trace the entrypoint, installed identity, authorization
decision, and effect, including service and asynchronous callers.

UI visibility and client-provided roles are not enforcement. Check route groups,
middleware, decorators, service checks, capability grants, and trusted-only callers.
An administrator's intended access is not a vulnerability. An internal deployment
claim is an assumption until supported; missing source for a guard is a proof gap.

Preserve the exact path and root control in citations, describe plausible actor
capabilities and impact, and record the strongest counterevidence. Findings are
unevaluated discovery candidates; do not execute the action or invent a PoC.
