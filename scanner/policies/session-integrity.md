# Authentication and session integrity

Invariant: security-sensitive identity must come from a server-validated
authentication flow, and sessions must remain bound to the intended principal,
client context, and lifecycle. Trace login, callback, token parsing, session
creation, renewal, logout, recovery, and account-linking paths.

Inspect signature and issuer/audience checks, state and nonce binding, credential
comparison, session rotation, expiry, revocation, cookie attributes, and recovery
token use. Decoding is not verification. A client-supplied identity, stale
session, or reusable one-time token must not become trusted merely because its
shape is valid. Framework defaults are counterevidence only when the configured
path is visible or an explicit deployment assumption is recorded.

Candidates must identify the attacker-controlled credential or transition, the
identity established, the closest control, and the protected effect. Distinguish
account enumeration and availability concerns from authentication bypass. Do not
attempt login, mint tokens, or assume runtime configuration absent from source.
