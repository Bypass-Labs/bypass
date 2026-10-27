# Verification record

## v0.2.3 — plugin-first startup and live reliability checks, 2026-10-27

The README now starts with terminal installation → native approval → a fresh Muse session → `/bypass:start`. Standalone CLI setup follows separately. Fresh CLI onboarding selects real Docker agents; source review proceeds when live resource setup is incomplete. Model failures display the failed stage and a concrete recovery action instead of inviting blind review retries.

The Muse adapter uses strict structured responses and explicit minimal reasoning by default, streams sanitized transport status, resolves the model ID, and checks an untested/stale connection before source upload. Preflight is bounded to 30 seconds; each review response to 60 seconds. These bounds expose failures sooner; they do not guarantee provider availability. Small repositories can supply source in the first worker turn. Cancellation now waits for Docker creation acknowledgement before cleanup to avoid leaving a container after a create/start race.

**78/78 automated tests passed, zero skipped, with real Docker tests enabled.** Syntax checked 47 modules. Controlled inference in these tests is distinct from the real Muse runs below.

**Two final real proof loops passed through the packaged plugin MCP transport**, with the actual Muse subscription and two Docker worker containers: a source citation in `policy.mjs` → observed unauthorized cross-account HTTP 200 → ownership fix verified → exported Node test passes → deliberately reintroduced bug fails both exported and saved tests with zero model calls. Each loop restored the fixture fix and stopped its app. Two earlier development attempts failed (an inference timeout and an initially invalid structured-output schema); they are retained in the [evidence record](evidence/plugin-reliability-2026-10-27.json). This is a local fixture, not production evidence.

**Native Muse startup was also tested, with mixed latency.** Updating the plugin invalidated its tool-server approval even though the plugin remained listed as installed. Reapproval restored the callable tools. A fresh direct onboarding request completed in 48.8 seconds and returned version 0.2.3 plus the repository-selection question; the actual onboarding tool had succeeded at 14.4 seconds. A preceding start-template request timed out at 120 seconds. The README uses the tested per-session minimal setting and includes explicit reapproval after updates. Full conversational onboarding is not claimed consistently reliable.

Production Job Radar proof still requires the two authorized test-account references and an owner-owned resource. No production vulnerability, fix, or complete coverage is claimed by these checks.

## v0.2.2 — actual Job Radar plugin integration, 2026-10-26

Validated the installed plugin against `Bypass-Labs/job-finder` at commit `1f5684f9d1b051187ec6be40e981ba489d6240a8` and the real production origin `https://job-radar.app`. Reused `/Users/maksim/Projects/job-finder-3`; no new clone or application-source edits. The published DNS TXT matched this checkout's challenge and passed the plugin's actual ownership verification. A bounded scope was recorded from the user's production testing request. One anonymous `GET /api/profile` returned 401; this is an authentication-gate observation, not account-isolation proof.

An actual fresh Muse session from the Downloads tooling folder restored the selected application, version, real Docker engine, existing model, verified ownership and authorized scope, then identified accounts as the next missing step. A preceding longer native session successfully called setup/context tools but did not finish its final reply within 180 seconds. The host model still used “Top finding” for setup readiness despite plugin guidance; setup gaps are not security findings.

Actual repository integration exposed three source/response handling gaps: the main server exceeds 64 KB, requested line ranges may extend beyond a file or page, and resource IDs are nested. The fixes provide bounded source pages with route locations, atomic citation bookkeeping, recoverable read errors across the real Docker RPC boundary, and dot-path/JSON-Pointer selectors in both live and exported checks. Provider failures now have sanitized diagnostic categories rather than always suggesting login problems.

**72 automated tests passed, zero failed/skipped**, including real Docker startup/recovery/cancellation, actual local HTTP controls, and standalone regression replay. Inference in automated suites is scripted or served by a controlled endpoint; actual Muse attempts are recorded separately. Syntax checks cover 45 modules. Authored, bundled and installed runtime contents match across 34 files.

Real Muse/Docker source-review attempts read actual source but encountered intermittent inference failures/timeouts. A separate real inference diagnostic on the same source excerpts completed successfully. Reported Muse allowance was not exhausted. See the individual attempts and their final outcomes in the [machine-readable Job Radar record](evidence/job-radar-plugin-2026-10-26.json); none of these errors is a security finding.

**Production end-to-end proof is still pending.** No two dedicated test-account token references or existing private resource ID were supplied. No production vulnerability, fix, or saved production regression is claimed. Domain ownership does not attest the deployed commit. Follow the [exact Job Radar plugin journey](JOB_RADAR.md) to finish those steps.

## v0.2 real Docker-agent POC — 2026-10-26

Verified with the installed Muse subscription CLI and a local Docker VM. Both workers ran in separate containers using the same immutable model profile as the orchestrator. The live scan used **4 real model calls**, took **45 seconds**, read actual `policy.mjs` / `server.mjs`, cited `policy.mjs:2`, and reproduced unauthorized invoice access.

| Check | Observed result |
| --- | --- |
| Owner / outsider login controls | HTTP 200 / 200, distinct account IDs |
| Vulnerable resource | Owner 200, outsider 200, anonymous 401 |
| Fixed resource | Owner 200, outsider 403, anonymous 401 |
| Independent exported Node test on fixed app | Exit 0 |
| Reintroduced defect: saved replay / exported suite / scheduler | Exit 1 / 1 / 1 |
| Replay and scheduler inference | 0 model calls |
| Final fixture state | Fixed, app stopped, schedule paused |
| Automated suite including real Docker startup/cancellation | 59/59 passing |
| Native Muse plugin validation | v0.2.0 valid, no diagnostics |

[Machine-readable live evidence](evidence/real-poc-2026-10-26.json). The controlled unit/integration tests use explicitly scripted inference to test failure cases; the evidence above comes from actual Muse inference. An initial live run retained real proof but timed out on a redundant final model summary. Removing that extra round-trip and using bounded low-effort inference produced the completed run recorded here.

Scope: the supplied local example API, not a customer production system. External DNS setup and real customer account credentials still need to be supplied per application. Docker cancellation removed its worker container; invalid outsider credentials were blocked; fabricated source citations and path escapes were rejected. This does not establish coverage for unsupported vulnerability classes.

The records below describe the earlier offline skeleton and remain historical.


Validated locally on 2026-10-26 with Node v22.14.0 and Muse Code 1.4.13.

## Latest: a persistent terminal workspace

The terminal workspace update passed **51 tests, 0 failures**, with syntax checks for **34 modules**. The bundled Muse runtime was rebuilt and native plugin validation returned `valid: true`, with no diagnostics. No new runtime dependencies are required.

A real PTY rehearsal completed application selection → model choice → deferred DNS → command palette → source preview → all six local walkthrough stages → clean exit. Setup history stayed in the same workspace. The walkthrough used real local HTTP controls, exported Node pass/fail, saved replay and a scheduler tick; its fixture finished fixed, with the schedule paused and server stopped. It did not send requests to the example deployed domain or call a model.

Actual terminal output was rendered and visually inspected at 100×36 and 60×20. Frame tests cover 120×40, 80×24, 60×20 and 40×15. Checks cover slash filtering, arrows, Tab, history, editing long input, bracketed multiline paste, Unicode widths, control-sequence sanitization, detail expansion, scrolling, Escape, Ctrl+C and restoring the normal terminal. An early rehearsal exposed lost setup history and the default delayed Escape decoding; both were fixed before the successful rehearsal.

A second PTY rehearsal used a deliberately waiting local model endpoint. Escape stopped its request, saved a skipped connection status and returned to an operable command bar. The model menu displayed the saved profile by name. `/app` opened the existing DNS record directly without repeating repository/model setup or making a DNS request. An invalid command recovered inside the workspace. JSON output remained valid and contained no terminal control sequences. Stopping a run watcher is tested to leave its background job intact.

The real `job-finder-2` workspace was opened and its status read: `job-radar.app` remains DNS-pending and its Muse connection remains connected. Its `.bypass/state.json` was byte-for-byte unchanged by that check. The UI retains honest mock-engine labels. This work did not install a new native Muse package, change capability approvals, call an external model, or claim an end-to-end Muse conversation was retested. Muse continues to render its own interface.

## Previous: choose the application before reviewing it

The repository-selection update passed **43 tests, 0 failures**, with syntax checks for **32 modules**. The rebuilt plugin validated with no diagnostics. Checks also passed for 32 Bash blocks, 35 CLI examples, nine local documentation links, and exact source/runtime equality.

A real stdio MCP integration test starts from a Bypass tooling workspace, rejects implicit initialization and scans before selection, requires an explicit application path, and routes all later operations to that application. The resulting source inventory contains only the application's file; the host tooling state remains byte-for-byte unchanged. The test covers a relative repository path resolved against the host workspace, both stage statuses, a readable combined plan with pending ownership, successful code-only preview, selected-project context, and zero model calls. CLI tests cover the tooling-folder guard and choosing a different application without initializing the tooling folder. Live-only mode is verified to skip source inventory.

A terminal check against the existing application displayed its exact folder, Git remote, app origin, and white-box/black-box statuses before any action. This check did not run another customer scan. Basic setup skips test-account questions; advanced setup retains them. Source fixes in Muse must use the selected application's editor workspace.

Native `muse plugins update bypass` refreshed the installed package, and its cached skill, command, hook, and MCP runtime match the authored files. Native inspection reports the package valid and active, but the updated MCP capability is **modified** and requires native review because its definition hash changed. No capability was auto-approved. Start a new Muse session after reviewing and approving that changed capability. The deterministic MCP routing was tested; an end-to-end model-driven Muse conversation was not rerun.

## Previous: a complete guided journey

The simplified experience passed **40 tests, 0 failures**, with syntax checks for **31 modules**. The Muse plugin runtime was rebuilt and native validation returned `valid: true` with no diagnostics.

New coverage follows the default onboarding recommendation through all six walkthrough stages using Enter, including real local HTTP proof, a verified fixture fix, independent Node test pass/fail, saved replay, a due scheduler tick, recorded context, final restoration, and server shutdown. It also covers leaving early, refusing occupied demo directories, bare-domain normalization, retrying an invalid app address in place, default DNS deferral, results-first navigation, command help, preserving scripted mock exit codes, and displaying failed saved checks. Fake native Muse commands verify that an existing installation is reused without reinstalling or approving it, and that installation failures expose the native reason.

A real terminal rehearsal completed `./bypass demo` with six presses of Enter and exited 0. Actual owner/other-account/anonymous controls changed from 200/200/401 to 200/403/401. Both exported Node execution and Bypass replay caught the deliberate regression. The scheduler recorded the regression for next-session context. The fixture ended fixed with one saved check, its schedule paused, and its server stopped.

Opening the existing customer project displayed three home choices and immediately opened its existing result on Enter, despite pending DNS. No new customer scan or DNS request was needed. A native plugin check correctly recognized Bypass already installed from a different checkout and returned success without reinstalling it or changing capability approval. The user's supplied terminal transcript had already shown a successful Muse model connection in 7.8 seconds; this update made no additional model requests.

Repository previews remain explicitly simulated and do not constitute discovered or verified customer vulnerabilities. Scripted mock scans still return incomplete exit code 3; the interactive screen explains completion of the preview separately from a security verdict. The guided scheduler demonstration is one real due tick, not an always-on hosted service.

## Previous: model connection recovery

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
