# Workflow and state-transition integrity

Invariant: security- or value-sensitive workflows must enforce valid transition
order, actor binding, uniqueness, and atomic invariants at the authoritative
state change. Trace multi-step flows, callbacks, jobs, retries, approvals,
payments, invitations, quotas, and recovery operations.

Inspect replay and idempotency controls, transaction boundaries, check/use gaps,
concurrent updates, duplicate delivery, amount or identity binding, step skipping,
negative and overflow states, approval separation, and compensation logic. A UI
sequence or earlier validation does not protect a directly reachable later step.
Database uniqueness, conditional updates, locks, and server-derived immutable
values can be strong counterevidence.

Candidates must describe the starting authority, invalid transition or race,
protected invariant, and final effect with citations. State concurrency and
integration delivery assumptions explicitly. Do not execute a workflow, create
transactions, or claim a race without a plausible interleaving in source.
