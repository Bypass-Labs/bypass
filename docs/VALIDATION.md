# Verification record

Validated locally on 2026-10-26 with Node v22.14.0 and Muse Code 1.4.13.

## Latest: model connection recovery

The connection and onboarding update passed **31 integration tests, 0 failures**, with syntax checks for **28 modules**. New coverage includes completed Muse replies versus echoed prompts, progress feedback, login and allowance diagnostics without raw provider output, an unavailable CLI, failed retests superseding old success in readiness, cancellation of a running process, a hard timeout for a process ignoring SIGTERM, DNS lookup timeout, cancellation of a local HTTP request, and explicit selection of a local checkout with a different origin. Fake Muse executables exercise failure paths without provider requests.

A real Muse Code subscription check against an existing local project profile returned the expected assistant reply in **9.3 seconds** and saved a connected result. It used an empty temporary workspace, contributor mode off, no repository content, and no persisted Muse session log. An initial diagnostic call also completed successfully; the reported login failure was not reproduced. The confirmed UX defect was the old silent wait and generic error handling.

Real terminal checks verified visible progress, Enter stopping a waiting check and continuing to app setup, and Ctrl+C cancelling an active check with exit 130. The README and walkthrough now explain optional checks, recovery, and resuming the exact local clone folder. The rebuilt native Muse plugin validated successfully.

## Previous: repository folder guidance

The clone-folder fix passed **21 integration tests, 0 failures**, including seven new repository-wizard checks. These use real Git clones from temporary local fixtures through controlled Git URL rewrites; they do not contact GitHub. They cover accepting the suggested folder, entering an occupied parent, avoiding occupied folders/files, reusing a matching checkout without losing edits or saved setup, SSH URLs, tilde expansion, pasted Markdown links, returning to repository selection, and failed-clone retry/cancellation. Noninteractive init still refuses an occupied destination.

Syntax checks passed for **26 modules**, and the rebuilt Muse plugin validated successfully. A real terminal session showed `~/Projects/job-finder` for the supplied GitHub URL, suggested a child folder after an occupied parent was entered, and exited cleanly with Ctrl+C. No customer repository was cloned during this check. The full suite required permission to bind its loopback fixture servers; the first sandboxed run could not start those servers.

## Previous: guided onboarding

The simplified `onboard` experience passed **14 integration tests, 0 failures**: the seven existing workflow checks below plus seven new wizard checks. The new checks cover pending DNS and resumption without duplicate settings, separate ownership/scope consent, explicit production acknowledgment, recovery from a failed model test, account credential references, a real local demo, and rejection of invalid/noninteractive onboarding before state is written.

Syntax checks passed for **24 modules**, and the rebuilt native Muse plugin validated successfully. A real terminal session also exercised QuickStart, deferred app setup, opening the dashboard, the code-only review default, the readable review plan, and a mock review. Ctrl+C returned exit 130 both in the terminal and in resumed onboarding; saved settings and findings remained intact.

The short README and walkthrough link to the preserved advanced script. Documentation checks covered 30 Bash blocks, 67 CLI examples against the real parser, and 11 local links. Public DNS verification was tested with controlled resolver responses, not a customer domain. No live model call was made during this onboarding update.

## Existing engine and workflow checks

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

## Earlier manual-walkthrough rehearsal

The expanded customer journey and presenter script were checked on 2026-10-26:

- All 36 Bash blocks passed shell syntax checks; 88 CLI examples matched the actual command parser; eight relative documentation links resolved.
- A fresh temporary Git repository was connected through the CLI. Adding a staging origin generated its unique TXT challenge. The review plan and scope authorization correctly remained blocked before ownership verification. No public DNS record was published or changed.
- The DNS ownership integration test passed again, including exact/split TXT values, expiry, renewal, and production acknowledgment. Its DNS responses were controlled test doubles.
- A separate fresh Ledger rehearsal proved the invoice issue, fixed it through source editing, saved one regression, and ran its exported Node test independently.
- The real detached worker first recorded a scheduled pass, then automatically caught a deliberate regression on a later scheduled run with zero model calls. The failed result appeared in a new CLI context read, and the standalone test also failed. No manual `monitor run` was substituted for the scheduled catch.
- After adding the export route, the original standalone HTTP assertions still passed while Bypass marked source evidence stale. The export issue was proved and fixed, both findings were retested, and the library finished with two passing saved checks and two independently passing Node tests.

Temporary rehearsal workers and apps were stopped. The prior Muse integration and provider checks above were not repeated for this documentation update. Presentation timings in the walkthrough are a run sheet, not a performance benchmark.

## Original local handoff snapshot

- Demo repository: `.demo/ledger`
- App: `http://127.0.0.1:4317`
- Finding: `finding_60d2e945`, with local proof and verified-fix history
- Saved test: `check_f699676e`
- Export: `.demo/ledger/tests/security/bypass/check_f699676e.test.mjs`
- Model profile: `muse`, real connection check succeeded
- Monitor: `walkthrough`, every hour, local worker running

These IDs are specific to this prepared walkthrough. A newly created demo generates new IDs.

## Not claimed by this verification

No customer domain was verified, external repository cloned, or production target scanned. The supplied `job-finder` GitHub URL was used to check the interactive folder prompt without starting a clone. A local/self-hosted real model server was not supplied; its supported HTTP contract was exercised against a controlled server. White-box and black-box engines remain mocked. Hosted account/device auth, cloud scheduling, and deployment attestation remain unconfigured and return explicit incomplete outcomes.
