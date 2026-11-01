# Sensitive data exposure

Invariant: personal, tenant, financial, operational, and security-sensitive data
must be returned, logged, cached, exported, or sent to integrations only at the
minimum scope authorized for that destination. Trace complete objects and derived
fields through serializers, errors, observability, exports, and third parties.

Inspect default serializers, wildcard field selection, nested relationships,
debug output, stack traces, analytics payloads, cache keys and sharing, download
exports, metadata endpoints, and response differences that reveal protected
state. Encryption in transit does not authorize the recipient. Explicit field
projection, redaction, audience-specific schemas, and documented public data are
relevant counterevidence.

Candidates must cite the sensitive fields or object class, lower-trust audience,
disclosure path, and closest minimization or authorization control. Avoid copying
actual secrets or personal data into the finding. Record classification and
deployment assumptions rather than declaring all metadata confidential.
