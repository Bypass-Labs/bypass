# Third-party response trust

Invariant: data and control metadata received from partner APIs, webhooks,
identity providers, feeds, package services, and other integrations must be
treated as attacker-influenceable until its source, structure, bounds, and
security-relevant fields are validated for the downstream use.

Trace responses, redirects, callbacks, errors, pagination, files, and embedded
URLs into databases, templates, queries, parsers, authorization, and subsequent
requests. Inspect TLS and peer verification, signature and replay controls,
timeouts, response-size and page limits, redirect policy, schema validation,
content types, identifier canonicalization, and whether remote error text reaches
logs or clients. Provider reputation is not validation; a pinned authenticated
source plus strict schema and bounded processing is counterevidence.

Candidates must identify the upstream influence, trusted downstream operation,
and missing validation with citations. Distinguish compromise of the provider
from an ordinary malformed response assumption. Do not contact the integration.
