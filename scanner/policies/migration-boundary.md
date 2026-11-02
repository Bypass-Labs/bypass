# Security invariants across data migrations

Invariant: schema changes, backfills, imports, deduplication, global-cache
conversion, tenant moves, and cleanup must preserve ownership, authorization,
retention, uniqueness, and referential security invariants throughout partial,
repeated, concurrent, and rollback execution.

Trace old identities and object relationships into their new representation and
every dependent table, cache, index, materialized view, artifact, and cleanup
step. Inspect default or sentinel principals, fingerprint collisions, merge
precedence, conflict handling, skipped rows, transaction boundaries, resumability,
dual-read periods, cascade effects, and batches that leave mixed models. An
idempotent query is not necessarily authorization-preserving. Explicit mapping
tables, tenant-qualified keys, reconciliations, and invariant checks are strong
counterevidence.

Candidates must cite the pre-migration security property, transformation, and a
specific lost, aliased, or stale relationship. Record data-shape and deployment
assumptions. Do not run migrations or modify data.
