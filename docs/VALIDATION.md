# Verification record

Validated locally on 2026-10-26 with Node v22.14.0 and Muse Code 1.4.13.

## Automated checks

`npm run check` passed for 22 source, CLI, script, and test modules. `npm test` passed **7 integration tests, 0 failures**, with these exercised behaviors:

1. Complete fixture journey: Git setup, simulated discovery, real HTTP proof, normal source edit, hot reload, positive/negative retest controls, automatic saved-test creation, independent Node export, regression failure, scheduled replay, next-session context, new-route investigation, and revocation.
2. Invalid positive controls become blocked; source changes become stale; detached jobs can be cancelled and return exit 130.
3. MCP initialization, typed tool discovery, strict argument validation, shared CLI state, resources, prompts, progress notifications, malformed-message handling, and clean EOF shutdown.
4. Idempotent repository onboarding, no repository-code execution during init, ownership/scope gates, code-only fallback, and mock deployed-app verification with zero exploit requests.
5. Strict CLI parsing, required credential references, production/URL rules, private-address and traversal rejection, and empty-suite incompleteness.
6. Exact DNS challenge matching, split TXT-string handling, challenge renewal/expiry, and explicit production acknowledgment. DNS responses are controlled test doubles in this test; no real public DNS record was changed.
7. A real loopback chat-completions fixture receives only the synthetic model prompt, with credential headers kept out of stored state. HTTP redirects are not followed.

The exported regression was separately executed from the walkthrough repository using `node --test` and passed. The automated journey also proves that this independent test fails after the vulnerability is reintroduced. Nested test processes explicitly clear Node's inherited test-runner context so the exported test genuinely executes.

## Native Muse integration

- Native `muse plugins validate` returned `valid: true` with no diagnostics.
- Installed the authored plugin via Muse's native installer using project scope for the walkthrough repository.
- Both the MCP server and SessionStart hook report `trusted_enabled` for the installed definitions.
- A fresh echo-only Muse TUI session's **`/mcp` screen showed `plugin:bypass:security` connected**, listing all 29 typed tools.
- Native `muse plugins hook test` completed successfully and added the latest local monitor result as session context.
- A separate **real Muse Code subscription smoke check succeeded** using a synthetic prompt in an empty temporary workspace. Contributor mode was off for that invocation, no repository content was included, and the result is recorded on the demo's `muse` model profile.
- Echo-only host smoke checks incurred no remote model request. The real subscription smoke check was the one intentional provider connectivity test.

## Interactive and browser checks

- Operated the real terminal menu through a PTY: dashboard, review mode selection, plan confirmation, persisted finding, and clean exit.
- Opened the local Ledger app in the Codex browser. Both accounts visibly received HTTP 200 in the vulnerable fixture.
- After the fix, the owner visibly received HTTP 200 and the other account received HTTP 403.
- Source editing is covered by the automated journey: changing `enforceOwnership` in `app.mjs` changes live HTTP behavior without restarting the fixture server.
- Started the local monitor worker detached. Its first scheduled check passed, was persisted, and appeared in the native Muse context hook.

## Current handoff state

- Demo repository: `.demo/ledger`
- App: `http://127.0.0.1:4317`
- Finding: `finding_60d2e945`, with local proof and verified-fix history
- Saved test: `check_f699676e`
- Export: `.demo/ledger/tests/security/bypass/check_f699676e.test.mjs`
- Model profile: `muse`, real connection check succeeded
- Monitor: `walkthrough`, every hour, local worker running

These IDs are specific to this prepared walkthrough. A newly created demo generates new IDs.

## Not claimed by this verification

No customer repository or deployed-app URL was supplied during implementation. No customer domain was verified, external repository cloned, or production target scanned. A local/self-hosted real model server was not supplied; its supported HTTP contract was exercised against a controlled server. White-box and black-box engines remain mocked. Hosted account/device auth, cloud scheduling, and deployment attestation remain unconfigured and return explicit incomplete outcomes.
