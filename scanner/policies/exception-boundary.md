# Fail-safe exceptional conditions

Invariant: timeouts, malformed input, dependency failure, cancellation, partial
success, resource exhaustion, duplicate delivery, and unexpected state must not
grant access, skip validation, expose internals, repeat effects, corrupt security
state, or silently fall back to a more privileged behavior.

Trace exceptions and alternate returns across authentication, authorization,
transactions, queues, retries, cleanup, locks, caches, external calls, and
multi-step effects. Inspect broad catches, ignored promises, default-success
values, stale results, watchdog completion, parse repair, rollback, retry
idempotency, circuit breakers, and error responses. Availability fallbacks must
not weaken confidentiality or integrity. Explicit failure states, atomic commit,
bounded retry, and compensation verified before success are counterevidence.

Candidates must cite the exceptional trigger, handling branch, and protected
property lost. Give a plausible failure sequence rather than assuming every
catch is unsafe. Do not induce failures or interrupt services.
