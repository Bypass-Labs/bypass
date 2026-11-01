# Unsafe parsing and object reconstruction

Invariant: untrusted serialized or structured data must not instantiate unsafe
types, mutate privileged object structure, resolve external resources, or cause
code execution during parsing. Trace cookies, tokens, uploads, messages, cache
entries, and integration responses into parsers and object merge or hydrate
operations.

Inspect serializer type controls, class allowlists, YAML modes, XML entity and
network settings, archive or document parsers, recursive merge behavior,
prototype-sensitive keys, and schema validation before privileged use. A signed
blob is safe only if verification precedes parsing and the signer is trusted for
the represented capability. Generic JSON parsing is usually counterevidence
unless dangerous keys or downstream reconstruction restore executable behavior.

Candidates must cite the attacker-controlled representation, parser or merge
configuration, resulting privileged behavior, and strongest counterevidence.
Keep parser denial of service separate from code execution or trust-boundary
impact. Do not parse supplied artifacts or create exploit objects.
