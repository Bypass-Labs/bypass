# Delegated capability envelope

Invariant: a token, agent, integration, API client, or background worker acting
for a user must receive only the operations, resources, audience, lifetime, and
cost authority explicitly delegated to it. The target service must enforce this
envelope on every consequential action.

Trace credential issuance and storage through protocol authentication, tool or
route dispatch, downstream credentials, and revocation. Inspect read versus
write scopes, tenant and resource constraints, token audience, expiry, approval
binding, reauthentication, external communication, administrative operations,
and paid side effects. A descriptive tool schema or UI hiding is not enforcement.
Short-lived target-enforced scopes and per-action authorization are strong
counterevidence.

Candidates must compare the delegator's intended authority with the effective
reachable capability and cite a sensitive operation outside the intended
envelope. Record whether broad authority is an explicit product decision. Do not
invoke tools, mint tokens, or perform an external side effect.
