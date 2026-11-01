# Credential and secret exposure

Invariant: credentials, signing material, tokens, and other reusable secrets must
not be embedded in distributed source or exposed through logs, errors, responses,
artifacts, process arguments, or lower-trust integrations. Trace secret origins,
transformations, storage, and every disclosure boundary.

Inspect hard-coded production values, client bundles, debug endpoints, exception
serialization, structured logging, telemetry, build output, CI variables,
command lines, URLs, and outbound headers. Names and test-shaped placeholders are
not secrets without evidence of use; secret-manager references and redaction are
counterevidence. Hashes may still be sensitive when reusable for authentication
or offline recovery.

Candidates must cite the secret-like value or source and a path to a lower-trust
consumer, while avoiding unnecessary reproduction of the value. State why it is
likely live or reusable and record rotation or environment assumptions. Never
read excluded secret files, contact a service, or validate a credential.
