# Deployment security mode and fail-safe configuration

Invariant: production security must not depend on permissive defaults, optional
configuration, debug or test flags, initialization order, or silent fallback to
a weaker mode. Missing, malformed, or conflicting security configuration must
fail closed before serving protected operations.

Inspect authentication initialization, proxy and origin trust, CORS, TLS,
cookies, debug handlers, test identities, feature flags, default credentials,
storage permissions, error verbosity, environment selection, and startup health
checks. Trace configuration from declaration and deployment manifests to the
actual branch guarding the sensitive operation. A warning is not enforcement.
Validated production profiles, mutually exclusive modes, and startup refusal on
missing security dependencies are strong counterevidence.

Candidates must cite the configuration source, reachable weaker branch, and
protected operation or disclosure. Record deployment assumptions and distinguish
developer-only behavior that cannot ship. Do not change environment variables or
start the application.
