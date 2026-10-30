# Bug Bounty Vulnerability Types — Tier 1 & Tier 2

**Purpose:** Prioritized vulnerability classes for the Meta Muse Spark Hackathon security-testing agent, with estimated LLM testing effort and concrete verification criteria.

> **Note:** Testing effort refers to how difficult it is for an LLM-assisted agent to formulate, execute, and interpret a *candidate* test when it has appropriate access and fixtures. It does not mean a vulnerability is likely to exist or that discovery will be easy. Tests should be conducted only against authorized targets using non-destructive checks and controlled resources.

## Tier 1 — Fast to Test and Verify

These should form the core of the MVP.

| # | Vulnerability | LLM Testing Effort | How Verification Can Be Done |
|---|---|---|---|
| 1 | Path Traversal | Very easy | Confirm that a traversal attempt retrieves the exact contents of a known, controlled test file outside the intended directory. |
| 2 | Local File Inclusion (LFI) | Very easy | Confirm that the application includes or returns content from a controlled file that should not be accessible through the requested path. |
| 3 | SQL Injection — Error-Based | Easy | Compare baseline and test responses; look for reproducible database-specific error evidence linked to the tested input, rather than a generic server error. |
| 4 | SQL Injection — Boolean-Based | Easy | Confirm repeatable, input-dependent differences between logically true and false conditions with stable controls. |
| 5 | OS Command Injection | Easy | Confirm a harmless, unique execution marker produced by an injected command in an authorized test environment. |
| 6 | Remote Code Execution (RCE) | Easy–Medium* | Observe controlled execution evidence (for example, a harmless unique marker) and rule out simple reflection or simulated output. |
| 7 | Server-Side Template Injection (SSTI) | Easy | Confirm that a test expression is evaluated server-side and produces the expected computed result, not merely echoed. |
| 8 | XML External Entity (XXE) | Easy | Confirm that the XML parser resolves a controlled entity, through a known local test resource or a uniquely tagged callback to an approved endpoint. |
| 9 | Reflected XSS | Easy | Confirm that a harmless marker executes as script in a real browser within the relevant origin; simple HTML reflection is not sufficient. |
| 10 | HTML Injection | Very easy | Confirm that controlled HTML is interpreted and rendered as markup instead of escaped text. |
| 11 | Open Redirect | Very easy | Inspect the redirect destination and confirm the application redirects to a controlled external origin without a required restriction. |
| 12 | CRLF Injection | Easy | Confirm that controlled input causes a new HTTP response header or other unambiguous response-structure change. |
| 13 | NoSQL Injection | Easy–Medium | Confirm reproducible query-behavior changes caused by controlled input, with comparison against clean baseline requests. |
| 14 | CORS Misconfiguration | Easy | Test controlled origins and credentialed browser access; verify whether a disallowed origin can actually read a protected response. |
| 15 | IDOR / BOLA | Easy with fixtures | Use two authorized test identities and confirm that one can access the other's nonpublic object when policy should forbid it. |
| 16 | Broken Function Level Authorization | Easy with fixtures | Compare permitted and restricted roles; confirm that a lower-privileged identity can successfully execute a restricted function. |
| 17 | Mass Assignment | Easy | Supply a normally non-user-editable property to an authorized test object and confirm the server persists an unauthorized change. |
| 18 | Excessive Data Exposure | Very easy | Inspect responses for sensitive fields that the test identity is not entitled to receive; validate against the application's field-level policy. |
| 19 | Missing API Authentication | Very easy | Request a known protected endpoint without credentials and confirm it returns protected content or performs a protected action. |
| 20 | Sensitive File Exposure | Very easy | Confirm that an access-controlled, known test file is reachable through an unintended publicly accessible path. |

*RCE is primarily an **impact**, not a single vulnerability mechanism. Command injection and SSTI can produce RCE, but general RCE discovery is harder than verifying a suspected execution sink.*

## Tier 2 — Still Practical for an LLM Agent

These typically need additional context, a browser, multiple identities, or controlled callback/test infrastructure.

| # | Vulnerability | LLM Testing Effort | How Verification Can Be Done |
|---|---|---|---|
| 21 | Server-Side Request Forgery (SSRF) | Easy–Medium | Observe a uniquely tagged request received by a controlled callback server, and attribute it to the target server rather than the testing browser. |
| 22 | Stored XSS | Medium | Submit a harmless test marker, reload or visit the stored content through a real browser, and confirm script execution from persisted data. |
| 23 | DOM-Based XSS | Medium | Confirm browser-side execution triggered by controlled input and trace the input to the relevant DOM sink. |
| 24 | Remote File Inclusion (RFI) | Medium | Confirm that the application includes or processes a benign resource hosted at a controlled origin, beyond merely fetching its URL. |
| 25 | Unrestricted File Upload | Medium | Upload a harmless test file and verify that a prohibited type or destination is accepted and exposed in violation of the intended upload policy. |
| 26 | Arbitrary File Read | Easy–Medium | Verify that a test identity can read a controlled file outside its authorized file set, with an exact content match. |
| 27 | Arbitrary File Write | Medium | Verify that a controlled file outside the intended writable scope is created or modified, using a harmless sentinel and cleanup. |
| 28 | LDAP Injection | Medium | Confirm repeatable, input-driven changes to directory query behavior, with expected true/false or scoped-search controls. |
| 29 | XPath Injection | Medium | Confirm repeatable changes to XML query results attributable to controlled input, compared with baseline requests. |
| 30 | Host Header Injection | Easy–Medium | Show that an untrusted Host or forwarded-host value is used in a security-relevant generated URL, link, or decision, not merely reflected. |
| 31 | JWT Verification Bypass | Medium | Confirm that a deliberately invalid test token grants access to a protected test resource that rejects the same request without a valid token. |
| 32 | Cross-Site Request Forgery (CSRF) | Medium | In a controlled browser session, demonstrate that a cross-site request causes an unauthorized state-changing action without the intended anti-CSRF protection. |
| 33 | GraphQL BOLA / IDOR | Easy with fixtures | Use distinct test identities and show that a GraphQL query or mutation can access or modify another user's protected object. |
| 34 | API Rate Limit Bypass | Medium | Under an approved low-volume test plan, demonstrate a reproducible violation of a documented quota or enforcement rule without stressing the service. |
| 35 | Webhook Signature Verification Bypass | Easy–Medium | Deliver a benign test event with an invalid or absent signature and confirm the receiver processes it as authenticated. |

## Verification Standard for the Agent

A finding should only be labeled **Confirmed** if the agent records:

1. **Expected security behavior** — why the operation, resource, or result should be blocked or handled differently.
2. **Baseline / control** — what happens with a legitimate, ordinary request.
3. **Test observation** — the changed input and the actual observed behavior.
4. **Independent verification** — replay or secondary evidence that differentiates the issue from reflection, noise, caching, or test-harness error.
5. **Reproducibility** — enough request/response or browser evidence to repeat the finding with the same authorized fixtures.
6. **Impact** — the concrete security boundary crossed and the affected resource or operation.

**Suggested labels:** `Confirmed`, `Likely`, `Needs Manual Review`, `Not Reproduced`.

**Implementation note:** Use the LLM for application understanding, selecting hypotheses, and interpreting observations; use deterministic HTTP/browser/test-fixture checks to decide whether a result is truly verified.
