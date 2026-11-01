# HTTP authority, proxy, and cache boundaries

Invariant: security decisions derived from HTTP authority, client identity,
routing metadata, or cached representations must use values established by the
intended trusted proxy and parser chain. Trace Host and forwarded headers,
scheme, path, method, duplicate headers, and cache inputs through middleware,
URL generation, routing, and response storage.

Inspect trusted-proxy configuration, forwarded-header selection, absolute reset
or recovery links, tenant selection, signature base strings, method overrides,
redirect construction, cache keys and variation, and disagreements between
front-end and back-end parsing. Merely running behind a proxy is not a control.
An explicit proxy allowlist, canonical authority configuration, shared parser
contract, and complete cache key can be strong counterevidence.

Candidates must identify the attacker-controlled protocol value, the component
that trusts or parses it, and the security decision, poisoned representation, or
cross-tenant effect. Record topology and intermediary assumptions. Do not send
ambiguous requests, poison a cache, or infer a parser discrepancy without a
source-supported mismatch.
