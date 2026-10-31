# Object access

Invariant: protected object reads and mutations must bind the requested object to
the authenticated principal, tenant, or an explicit sharing grant before the effect.
Trace identifiers from routes, request bodies, GraphQL arguments, and queued jobs
through handlers, service helpers, queries, and serializers. Include bulk/export
and nested-resource paths; a safe sibling does not establish protection here.

Look for ownership/tenant checks on the exact path. Authentication alone is not
object authorization. Check middleware, service guards, scoped ORM queries, and
database row-level policies before suggesting a missing guard. Public resources,
authorized administrators, and explicit sharing are possible counterevidence.
Do not infer deployment access or claim a missing external control is disproved.

Candidates must identify the actor-controlled reference, a reachable code path,
the sensitive read/write, and supporting evidence. Record controls inspected and
unknown deployment or policy assumptions. Emit hypotheses, never confirmed bugs.
