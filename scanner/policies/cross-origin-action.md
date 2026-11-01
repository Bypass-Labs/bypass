# Cross-origin actions and messages

Invariant: a foreign origin must not trigger authenticated state changes or read
protected responses unless an explicit, narrowly scoped trust decision permits
it. Trace state-changing HTTP routes, cross-origin configuration, browser
credentials, postMessage traffic, and window or frame integrations.

Inspect anti-CSRF tokens and their session binding, SameSite and origin checks,
simple-request exposure, CORS origin matching with credentials, preflight
handling, JSONP, message origin and source validation, and wildcard subdomain
logic. Requiring authentication or POST alone is not CSRF protection. CORS is
not an authorization control, while a correctly scoped token or origin-bound
message contract can be strong counterevidence.

Candidates must identify the foreign-origin capability, authenticated context,
protected action or disclosure, and exact missing or bypassable control. Record
cookie and deployment assumptions explicitly. Do not send requests or interact
with browser windows.
