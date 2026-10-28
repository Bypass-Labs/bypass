# Bypass 0.7.1 — onboarding and UAT fixes

Credentials are optional. A review can combine source investigation, anonymous JSON/HTML checks, supported registration tests, and account-boundary probes as their inputs become available. Missing accounts or test data limit the affected check instead of restarting setup or blocking the source review.

## Changes

- Registration is always represented in live review coverage. Authorized JSON or Firebase email/password signup creates at most two dedicated accounts and connects their credentials privately. An attempt ledger prevents duplicate creation on retry, including uncertain POSTs. No email-verification bypass is claimed merely because signup succeeds: a policy violation needs an unverified account and observed access to a route requiring verified email. The resulting confirmed HTTP proof can save a failing test.
- Muse can discover exact owned IDs from an authorized collection. HTML probes require a specific content marker and an explicit intended access policy. Generic 200 pages, missing IDs, blocked logins and redirects remain inconclusive.
- Small source inventories are supplied with the initial scan. Batched completion submits grounded source conclusions and runs remaining approved probes. All identity/resource controls remain. Short replays return results directly; slower jobs retain durable progress and cancellation.
- Confirmed HTTP issues save failing reproductions immediately. Export accepts a saved-check ID or its finding ID. Matching passing replay closes the same previously confirmed finding; unrelated bindings do not.
- Secret masking preserves object structure and quoted source. Packaged MCP memory retrieval and a second source review pass with the quoted-Bearer reproduction.
- Interrupted real fixtures restart their recorded instance, preserving source edits, findings and check IDs. Only known bundled server/policy forms are eligible; occupied ports and custom executable files are not replaced or run. Deliberate stops require explicit resume.
- Pending/expired DNS is setup state. Native version checks have an eight-second bound and short cache, and distinguish timeout from missing installation. CLI help is concise; `bypass --help --reference` retains the complete catalog.

## Observed validation

The local full suite passed 145 tests with two Docker-only tests skipped. A subsequent 13-case targeted suite also passed, including an additional scope-revocation test: 146 unique passing tests. Release CI runs the Docker checks and platform packaging.

An actual Muse session completed source investigation → real HTTP proof → failing regression export → fix → passing replay → deliberate regression → failed replay → restore → passing replay → one monitor tick → feature memory → shutdown. Its final run used **22 host model calls**, versus **31** in the earlier 0.7.0 fixture UAT. It took **2m31s**, with **zero tool failures** and **zero independent plugin model calls**. A 59-second host response shows why fewer calls do not guarantee a fixed completion time. The earlier iteration took 1m41s but exposed an export-ID UX error that was fixed before the final run.

The final finding was fixed-verified, its saved check passed, the monitor was paused and the fixture stopped. HTTP controls remained owner identity 200, other-account identity 200, owner resource 200, outsider 200 before the fix / 403 afterward, and anonymous 401. Independent exported Node tests were exercised separately through packaged MCP tests; the native Muse run exported them with shell disabled.

[Machine-readable evidence](evidence/uat-reliability-0.7.1.json).

## Still bounded

This is not complete application security coverage. No new JobRadar production requests or production account creation were performed for this release. Firebase signup transport was contract-tested; a fresh production trial remains outstanding. CAPTCHA, social login and arbitrary browser workflows remain unsupported and visible as gaps. Host inference latency and UI updates during a host model turn remain controlled by Muse.
