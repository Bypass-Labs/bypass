# Identity lineage through derived and deferred state

Invariant: every asynchronous work item, cached result, generated artifact, and
derived record must retain the security-relevant identity and source lineage of
the operation that created it. Retrieval and effects must reauthorize that
identity rather than relying on an opaque job, cache, or correlation identifier.

Trace user, tenant, delegated principal, source object, authorization version,
and purpose through queues, promises, subprocesses, callbacks, caches, polling
endpoints, and materialized AI or analytics output. High-entropy identifiers are
not ownership checks. Global caches require an explicit public/shared input
contract, while user-influenced derivatives require partitioned keys and
revocation behavior. Correctly bound composite keys and authorization on both
creation and retrieval are strong counterevidence.

Candidates must cite the identity-bearing entrypoint, where lineage is retained
or lost, and the later read or effect. Distinguish unauthorized access from mere
cost misattribution. Record process-local, queue, retry, and deployment
assumptions; do not guess identifiers or execute background work.
