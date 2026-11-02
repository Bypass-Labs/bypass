# Reserved and service principals

Invariant: externally established identities must never alias reserved values
used for system, global, anonymous, default, test, migration, or service scope.
Reserved principals must have a disjoint namespace and must not inherit ordinary
user creation, lookup, fallback, or authorization behavior.

Inspect sentinel IDs, default tenant keys, empty-value fallbacks, environment
bypass identities, service accounts, shared-cache owners, migration users, and
queries that combine reserved and end-user rows. Validate the identity provider's
allowed namespace and every import or administrative creation path. A value that
is improbable is not reserved. Typed identities, namespace prefixes enforced at
the trust boundary, and separate storage or credentials are counterevidence.

Candidates must identify the reserved value, an external or fallback path that
can select it, and the additional data or authority obtained. Preserve identity-
provider and deployment assumptions. Do not create accounts or attempt to claim
a reserved identifier.
