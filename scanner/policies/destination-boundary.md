# Outbound destination boundaries

Invariant: attacker-controlled destinations must not reach protected network
resources or receive privileged credentials through server-side requests. Trace
URL import, webhook, preview, proxy, redirect, DNS resolution, and credential
forwarding paths to the actual network client.

Inspect canonicalization, resolved-address controls, redirects, accepted schemes,
and origin binding at each request. A check before redirect or re-resolution may
not protect the destination used. Intended unrestricted fetching, documented
operator authority, pinned connections, and separately enforced egress controls
are relevant counterevidence; record prerequisites rather than assuming them.

Identify the untrusted source, trust boundary, control and sink using source
citations. Do not contact endpoints. Missing runtime reachability is an explicit
question, not proof of safety or automatic confirmation.
