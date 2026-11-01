# Cryptographic trust decisions

Invariant: cryptographic verification used for identity, integrity,
confidentiality, or authorization must bind the intended data and trust context
with suitable algorithms, keys, nonces, and failure handling. Trace signed or
encrypted inputs through key selection and verification to the privileged
decision.

Inspect fail-open paths, verification order, algorithm or key confusion,
attacker-selected keys, incomplete field coverage, nonce and replay handling,
constant-time secret comparison, predictable security tokens, password hashing,
and encryption authentication. Encoding, hashing without a secret, and TLS to an
unverified peer are not equivalent controls. Established library primitives with
fixed safe parameters are strong counterevidence when used on the actual path.

Candidates must identify the security property, attacker capability, verification
or generation path, and downstream decision. Distinguish outdated primitives
from exploitable trust failures and preserve runtime key-management assumptions.
Do not derive keys, crack values, or generate attack material.
