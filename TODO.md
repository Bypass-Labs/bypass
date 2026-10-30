# UAT bugs and release gates

## October 30 integration acceptance

Current merge, defect fixes, validation status and next actions are tracked in [the integration UAT report](docs/MERGE_UAT_2026_10_30.md). Historical acceptance items below remain historical; fixture passes do not close native Muse or production gates.

- [x] **UAT-24 / P2 — Optional account coverage clarity.** Reuse available saved accounts. Missing credentials must not block anonymous checks or authorized account-creation discovery; fallback is expected behavior, not a defect. PR #5 removes missing-credential blocking and discloses authenticated coverage limits. Automated anonymous-request and packaged tests pass. Native saved-account proof/replay passed; original anonymous fallback remains expected behavior.
- [ ] **UAT-25 / P1 — Honest source completion and recovery.** Native Muse ended with 88 unread files despite `continueRequired`. Added an explicit final-report gate and continuing-stage wording; actual continuation delivered all 144 files before the UAT controller restarted the session for final reporting. Muse event timestamps were stale, so no provider-stall duration is established. Complete native recovery; deterministic worklist gates alone cannot force the host to continue.
- [x] **UAT-26 / P2 — Black-box onboarding parity.** Implemented a read-only plan with selected-app confirmation, recommended/saved vs custom native picker, custom notes and retained scope. Existing authorization is never silently expanded. Source, packaged and installed native picker contracts pass. A rendered keyboard/arrow-key smoke is still a manual acceptance item.
- [ ] **UAT-27 / P2 — Usage and export-location clarity.** Engine model decisions are fewer than total Muse host turns; an app-only export lives in the app profile, not a repository. Added budget-unit disclosure. Native production also required repeated no-work progress polls, consuming host turns. Acceptance: bounded long-poll or event-driven tool waits, show both counts where observable, explain app-profile artifact placement before export, and show billing/privacy guidance once rather than repeating it in every result.
- [x] **UAT-28 / P2 — Scope-rate control in chat.** Implemented `rps` on `bypass_authorize_target` and CLI `--rps`; accepts a finite rate greater than 0 and at most 10. Omitted fields preserve existing scope, including methods, paths, advanced contracts and expiry. Invalid changes leave authorization unchanged. Source, packaged MCP and actual CLI validation pass. Native Muse changed production 2 → 1 → 2 RPS while preserving all other scope fields. A rate picker now accompanies the method/path permission controls.
- [ ] **UAT-29 / P2 — Black-box decision and report handoff.** Native host supplied nine access-task kinds rejected by validation; the decision schema allows a generic string. Legacy `bypass_report` also rejected a `bx-...` run ID although its report existed. Acceptance: expose supported task kinds in the decision schema and route black-box report requests to the correct artifact/tool. Preserve actual baseline proof; dropped model tasks are untested.

- [ ] **UAT-30 / P2 — Cross-workflow finding linkage and durable replay data.** A source hypothesis and the later concrete HTTP proof can remain separate records for the same analysis-job owner-check issue. Its synthetic job expires after about 30 minutes. Acceptance: link the proof to the source issue, count one root cause, and support approved test-data setup or explicit rebinding; an expired owner resource must remain inconclusive, never fixed.

- [ ] **UAT-31 / P1 — Finish asset analysis or retain exact continuation work.** Production broad audit returned incomplete after 3/5 asset pages (12/19 files), with 15/20 decisions used and about four minutes left. Two crawl leads remained unvisited, but pending research checkpoints were zero. Acceptance: execute every authorized planned page or return a concrete blocker/continuation item; do not strand available budget.

## 0.7.7 release

Includes the October 28 choices-first onboarding, correct repository selection, same-origin ownership reuse, public signup-config discovery and assessment-continuation fixes. Final local suite: 208 passed, zero failed, two opt-in Docker tests skipped. Native interactive acceptance items below remain open; publishing does not turn fixture results into production UAT evidence.

Open issues observed in the October 27, 2026 fresh-install UAT of Bypass 0.7.0
(`e87d042`). Muse reviewed `Bypass-Labs/job-finder` at `1f5684f`.
The original observations below are preserved; implementation status for 0.7.1 follows. The first production black-box attempt was blocked by
DNS verification; the rerun below completed the configured production probes.
Local-fixture results are not production evidence.

## 0.7.1 implementation status

- [x] UAT-01: Structural redaction; quoted-source memory and second-review packaged tests pass.
- [x] UAT-02: Batched review and fast replay reduce host calls; elapsed/last-action and cancel/resume state exposed. Actual final Muse run: 22 calls, 2m31s, zero tool errors. Host inference waits remain a limitation.
- [x] UAT-03: Known real fixtures recover after process loss in a new MCP session without changing finding/check identity.
- [x] UAT-04: Pending/expired DNS is a setup response, preserving the ownership gate and source-only alternative.
- [x] UAT-05: Concrete read-schema correction plus initial source and batched completion; final native source review had no argument errors.
- [x] UAT-06: Native inspection bound increased to eight seconds, cached briefly; slow/unavailable/missing states distinguished.
- [x] UAT-07: Installed `bypass` help has a small starting menu and an explicit full reference.
- [x] UAT-08: Only matching verified HTTP replay closes a linked previously confirmed finding; unrelated passing binding test retains the open finding.
- [x] UAT-09: Removed hardcoded host-version billing wording; billing remains unattested.
- [x] Optional credentials, bounded JSON/Firebase signup, owned-resource discovery, anonymous JSON/HTML checks, and immediate failing regressions available through both CLI and plugin.

Validation and limits: [0.7.1 reliability report](docs/RELIABILITY_0_7_1.md).

## Remaining validation / scope

- [ ] **UAT-23: Do not confuse three chosen probes with the full assessment.** Local follow-up adds unread source-range tracking, a 2 MB plugin budget, authorized resource-preparation suggestions with request-backed blockers, late-bound finding deduplication, real run-aware coverage, direct continuation actions and independent HTTP controls after reasoning-stage failures. Historical five records group into four issues, one confirmed. Final suite: 208 passed, zero failed, two opt-in Docker skips; native package validation passed. See the [follow-up audit](docs/CONTINUATION_AUDIT_2026_10_28.md). Fresh native-session continuation and production acceptance remain open; no plugin update or app changes were made.

- [ ] **UAT-21: Continue the agreed assessment after the first finding.** Implemented locally: durable source/route/probe worklist, early-finish deferral, automatic inclusion of newly configured probes, specific source-grounded blocker reasons, progress counts and measured HTTP-only ETA. Independent configured controls continue after a source-operation limit or an early/failed standalone black-box reasoning step. Full suite: 201 passed, zero failed, two opt-in Docker skips. Native Muse continuation and visible progress acceptance remain pending. [Session audit](docs/ASSESSMENT_FLOW_AUDIT_2026_10_28.md).
- [ ] **UAT-22: Assessment must not become unrequested remediation.** Confirmed in the October 28 session: Muse interpreted “keep working” as permission to edit application source, then admitted the error. Local command/skill/session/tool guidance now specifies testing, recommendations and regression artifacts only; a separate explicit request authorizes fixes. Source changes are detected before continuing review. This is not a host-editor sandbox. Verify in a fresh native session that a first finding followed by “keep working” continues checks and leaves application source unchanged. Existing job-finder edits were preserved for user review.

- [ ] **UAT-20: Choices-first interaction throughout the product.** Local implementation covers shared CLI suggestions/custom values; native plugin choices with custom notes; saved create/existing/skip account decisions; automatic public-config discovery; bounded recovery pickers; and numbered installer permissions with native customization. Automated validation: **196 passed, zero failed, two opt-in Docker tests skipped** in 93.5 seconds; native Muse package validation passed. Details are in the [interaction audit](docs/INTERACTION_AUDIT_2026_10_28.md). Still requires manual acceptance in a new Muse session and a visible terminal before publication. Do not ask for permission, Firebase project ID and email domain in a single free-text prompt.


October 28 local implementation: [session audit and changes](docs/ONBOARDING_AUDIT_2026_10_28.md). These changes are uncommitted, unpublished and not installed. Items remain open until native interactive acceptance is completed.

Previous onboarding validation (before the interaction audit): **187 passed, zero failed, two opt-in Docker tests skipped** in 91.8 seconds. Syntax checks passed for 107 JavaScript modules; all 93 public commands/options map to 87 typed plugin tools; native Muse plugin validation returned valid with no diagnostics. The new parser recovered one Firebase config from the existing job-radar bundle without making network requests. The final CLI ownership-message follow-up also passed all 13 wizard/app-connection checks. This is local automated validation, not a new production or visual UAT.

- [ ] **UAT-15: Start with the approved review-type picker.** Replace the free-text
  app-address-or-"code only" question with **Code only**, **Code + running app
  (recommended)**, and **Running app only**, each with a short explanation. Use
  the native Muse selection UI and an equivalent CLI picker. Code only chooses
  a repository and skips all live setup; combined chooses a repository and then
  the app URL; app-only accepts a URL without requiring a repository. Request
  the URL only after an app option is selected. Credentials remain optional.
  Show billing/privacy guidance once at the relevant model step before review,
  separate from this choice. Acceptance: exercise all three paths through the
  installed plugin and CLI; verify app-only works without repository state and
  live requests still require ownership and scope. UI approved October 28;
  implemented locally with CLI and packaged-MCP regression coverage; native interactive acceptance and deployment remain pending.
- [ ] **UAT-16: Choose the app environment with the approved picker.** Replace
  "Do real users use this app, or is it only for testing?" with **Production**
  (live deployment), **Staging** (separate test deployment), **Preview**
  (temporary branch/PR deployment), and **Local development** (on this computer).
  Show the supplied app URL above the options and use the native Muse selection
  UI plus the CLI equivalent. Retain an environment explicitly supplied by the
  user; production does not require existing real users. After selection,
  continue to ownership and testing permissions without asking the same
  confirmation again. Acceptance: each option saves its exact environment;
  origin/environment validation and live-request gates remain enforced.
  UI approved October 28; implemented locally with CLI and packaged-MCP regression coverage; native interactive acceptance and deployment remain pending.
- [ ] **UAT-17: Keep ownership verification attached to the app URL across
  repository changes.** Ownership belongs to the verified app origin, not the
  selected checkout or a newly generated project ID. Reuse the same user's
  valid, unexpired verification for the exact normalized origin when connecting,
  cloning, or switching repositories, including app-only to combined review.
  Do not issue a new TXT challenge or ask the user to replace a DNS record just
  because the repository changed. Observed October 28: verification and scope
  succeeded for `https://job-radar.app` under `Development`; selecting the supplied
  `Bypass-Labs/job-finder` source then created a separate project and unnecessarily
  requested DNS verification again for the unchanged origin. Persist ownership
  independently of checkout state, retain its provenance and expiry, and keep
  testing authorization separate; ownership reuse must not broaden methods,
  paths, or other approved limits. Acceptance: verify once, switch checkout,
  reopen Muse and continue without another DNS prompt; trailing-slash variants
  reuse the same origin, while different origins, expired or revoked proof do
  not reuse it. Record the reused verification in the UI. Requirement confirmed
  October 28; implemented locally with CLI and packaged-MCP regression coverage; native interactive acceptance and deployment remain pending.

- [ ] **UAT-18: Resolve public Firebase configuration before asking the user.**
  Audited October 28: Muse asked for a project ID at 09:36, then independently
  found the deployed client configuration at 09:39 and configured registration
  at 09:40. Implemented locally: bounded same-origin discovery, automatic fallback
  from source templates/missing values, private generated configuration instead
  of app `.env` edits, synthetic email-domain default, and discovery progress.
  Existing creation permission and attempt budgets are reused. Scope still
  applies; include public config reads in the initial scope summary to avoid
  a separate permission question. Tests cover landing page → SPA → bundle,
  ambiguity, revocation, cancellation and request limits. Native interactive
  acceptance and deployment remain pending.
- [ ] **UAT-19: Connect the supplied repository before app setup.** Implemented
  locally: pass the Git URL into a real connection action, validate source before
  initializing, reject an empty parent directory before DNS, and resume the
  selected checkout instead of the old initialized parent. App-only needs no
  repository and resumes across CLI/MCP processes. Preserve same-app ownership
  and exact scope on an explicit checkout switch; never pair an unrelated app
  silently. Regression coverage passes; native interactive acceptance and
  deployment remain pending.

- [ ] Complete production UAT on the latest installed release, including real supported signup and suitable dedicated resources. Local fixture proof and the focused scope-update test are not production review evidence.
- [ ] Observe a first-time user complete the production journey without operator-prepared fields/data.
- [ ] Host inference delay remains variable; Bypass cannot render during Muse's own model turn. Do not promise a latency bound from one run.
- [ ] Arbitrary browser signup, social login, CAPTCHA and unsupported resource provisioning remain explicitly out of scope.

## Scope/update recovery — 0.7.6

Reverified October 28 against the public installed package: [verification report](docs/VERIFICATION_0_7_6.md). The real Muse picker accepted the JSON-encoded method list with zero errors; all 32 installed-package checks passed. The open production and cleanup gates below remain open.

- [x] UAT-10: Scope editing was attempted on installed/loaded 0.7.1 after 0.7.5 was published. Onboarding now distinguishes loaded, installed and published versions and provides the public installer or fresh-session action. Failures carry the loaded version. Native installation must confirm the requested version before reporting success. Offline metadata checks remain unavailable, not current.
- [x] UAT-11: The exact approved scope-file payload (all seven common methods, `/`, 2 requests/second, production acknowledgment) succeeds through the installed 0.7.5 plugin in a fresh native Muse session. Saved scope and reopened picker match. [Focused evidence](docs/evidence/muse-scope-update-2026-10-27.json). This was a headless native conversation; the interactive picker and whole production journey are not established by it.
- [x] UAT-12: Changing scope no longer invalidates reuse of an already-recorded account-creation budget. Current identity-path permission still applies; no duplicate signup is attempted.
- [x] UAT-13: Interactive native Muse sent the custom method list as a JSON-encoded string before retrying with CSV. Accept that exact representation with the same method validation; invalid lists leave authorization unchanged. Keyboard selection and final saved methods passed on a local target; the first attempt required recovery, so this was not an error-free journey.
- [x] UAT-14: Muse sometimes printed the method list instead of opening its available picker. The tool now supplies an explicit three-choice fallback and the plugin requires the host question tool. A fresh native conversation opened the picker without a follow-up and saved POST, PATCH and a custom method with zero tool errors. [Interactive evidence](docs/evidence/muse-076-interactive-picker.json). Host inference delay and broader production UAT remain open.
- [ ] Interactive upgrade UAT: keep an old Muse session open, install an update, exit/open a fresh session, adjust methods in the actual picker, and complete the production review. A passing MCP suite does not close this gate.
- [ ] Cleanup workflow: detect active Muse/MCP sessions before resetting project state. The prior manual reset moved state while Muse remained open; its exact setup was restored from backup for scope recovery.

## Archived 0.7.0 observations

### Rerun update — October 27, 2026 (Pacific)

DNS verification and the bounded production black-box review have now completed.
The real Muse production workflow took 8m54s (27 host model calls, zero failed
tool calls). It exercised all three configured owner/outsider/anonymous probes,
verification and retest. The private UAT report contains the application-specific
evidence; these results are not a claim of complete application coverage.

The uninterrupted local Muse fix/regression/export/monitor journey passed in
3m13s, including pass → fail → pass, final finding retest, monitor pause, worker
stop, and fixture shutdown. Independently executed exported Node tests reproduced
pass/fail/pass in 7.5s; the installed CLI replay also passed. These local results
do not establish a deployed production fix.

Production memory retrieval passed with ten records, and a fresh Muse coding
session retrieved that context without onboarding or app requests. **UAT-01 is
still open:** the installed release still throws on the quoted-Bearer minimal
reproduction. The second production review was only started and cancelled;
full repeat analysis and interrupted-fixture recovery are not closed by this
rerun. Long model waits and unavailable installed-version metadata also remain.

## P1 — blocks a complete plugin journey

- [x] **UAT-01: Preserve JSON structure during secret redaction.** After a real
  source review, `bypass_memory`, `bypass_feature_context`, and a second
  `bypass_scan` fail with JSON parsing errors. Nine memory records were saved
  intact; equivalent CLI context retrieval succeeded. `src/util.mjs` serializes
  objects, edits the JSON string, and parses it again. The Bearer matcher can
  consume a JSON escape character. Minimal nonsecret reproduction:
  `redact({quote:'if (header.startsWith("Bearer ")) { return true; }'})`.
  Redact string values while preserving the object structure. Acceptance:
  source review → retrieve memory → retrieve feature context → second review
  succeeds through the installed Muse plugin, including quoted Bearer source
  text, escaped strings, and actual-secret masking. Evidence: `mcp-context.json`,
  `mcp-repeat.json`, `cli-context.json` from the UAT report.

- [x] **UAT-02: Make long host-model waits visible and recoverable.** One source
  interval took about 147 seconds without advancing product state. The real Muse
  fixture journey had repeated long waits and was manually interrupted after
  8m42s, before retesting the applied fix. A same-model synthetic connection
  check succeeded in 14 seconds. Root cause is not established; do not report
  this as a login failure or a product timeout. Acceptance: display the current
  stage, last completed action, elapsed wait, and a useful cancel/resume path;
  rerun the entire Muse journey without operator MCP intervention and report
  host model calls separately from deterministic plugin model calls. Evidence:
  `source-host.jsonl`, `fixture-host.jsonl`, `fixture-interruption.json`,
  `latency-timing.json`.

- [x] **UAT-03: Recover the local demo after its server stops.** Interrupting the
  Muse process group also stopped its descendant fixture server. A fresh Muse
  session spent 65 seconds attempting retests and fixture controls, received
  `ECONNREFUSED`, and could not restart the saved fixture. The operator had to
  restart it before the deterministic loop could pass. Acceptance: detect the
  dead fixture, restart only the recorded local fixture safely, preserve its
  finding/check identity, and complete retest → export → pass/fail/pass without
  manual process commands. Cover interruption and a new Muse session. Evidence:
  `fixture-resume-host.jsonl`, `fixture-operator-restart.json`,
  `mcp-fixture-finish.json`.

## P2 — misleading state and onboarding friction

- [x] **UAT-04: Render pending DNS as a setup state.** Missing ownership is an
  expected onboarding step, but the plugin presents it as a failed tool call.
  Preserve the live-request gate and expose the exact record, expiry, retry
  action, and source-only option. Acceptance: pending and verified flows remain
  understandable in Muse; a retry or reinstall preserves a current challenge;
  an expired challenge is clearly renewed without silently accepting old proof.

- [x] **UAT-05: Align source-read tool arguments and host guidance.** Muse made
  an invalid `bypass_review_step.paths` call before recovering. Inspect the
  schema, examples, and tool response guidance; the observed error alone does
  not establish a schema defect. Acceptance: a fresh installed-plugin source
  review reads files successfully on its first valid call, and malformed input
  returns a concrete correction. Evidence: `source-host.jsonl`.

- [x] **UAT-06: Avoid false unavailable plugin-version diagnostics.**
  `src/runtime-identity.mjs` bounds native inspection at 2 seconds, while a
  successful native inspection took approximately 3.7 seconds in UAT. The
  installed plugin consequently reported its installed-version check as
  unavailable. Acceptance: report the actual version, distinguish a slow check
  from a missing installation, and keep the status interaction bounded.

- [x] **UAT-07: Make installed CLI help a short starting point.** The installed
  executable's help begins with clone-style `./bypass` examples and exposes 85
  commands at once. Acceptance: installed help uses `bypass`, prioritizes the
  plugin and guided start, shows a few next actions, and keeps the complete
  command reference available on demand.

- [x] **UAT-08: Explain finding state after regression replay.** A deliberate
  fixture regression reopened a confirmed finding. Restoring the fix made the
  saved check pass but left the finding confirmed until an explicit retest.
  This is a state/UX ambiguity, not evidence that replay failed. Acceptance:
  show both the passing check and finding verification state with an explicit
  next action; test the documented closure semantics through Muse. Do not close
  findings based on unrelated passing checks. Evidence: `mcp-fixture-finish.json`
  and the final fixture finding history.

## P3 — diagnostic accuracy

- [x] **UAT-09: Remove misleading hardcoded host-version wording.** Billing
  guidance in `src/execution-mode.mjs` names Muse 1.4.13 while the UAT host was
  1.4.14. Acceptance: distinguish the observed host version from compatibility
  history; keep billing mode explicitly unknown when the host does not attest
  it. Successful model calls do not prove subscription billing.

## Full UAT rerun gates

- [ ] Fresh public plugin installation, native permission/startup flow, PATH,
  and correct repository selection. Preserve the newly issued DNS challenge
  when installing, so the published record stays tied to this test project.
- [ ] Verify ownership of `https://job-radar.app` and record explicit, bounded
  read-only production scope. Pending DNS is an external prerequisite, not a
  passing black-box test or a confirmed product defect.
- [ ] Import the two existing dedicated test accounts privately in the same
  Muse session; refresh credentials and verify they identify different users.
- [ ] Complete real source review plus live owner/outsider/anonymous controls
  on owned test resources. Investigate the three source hypotheses (run status,
  discovery-job status, daily reports) only where authorized resources and
  scope allow; record any remaining coverage gaps.
- [ ] Record real HTTP evidence, confirmed versus unproven findings, timestamps,
  request/model counts, duration, and any operator assistance. Source inventory
  size must not be presented as complete source coverage.
- [ ] Exercise saved regression creation, export, replay, memory retrieval, and
  a second review. Validate actual fix/regression transitions in a disposable
  local target; production fixed-build verification requires an actual deployed
  fix and must not be replaced by local-fixture results.
- [ ] Exercise the supported monitor lifecycle and fresh-session recovery;
  report unsupported or blocked steps as such, not as passes.
- [ ] Stop test processes and archive local installation/test state after the
  completed rerun so the user can perform a fresh manual trial.

The prior UAT's three application findings are source-only hypotheses, not
confirmed production vulnerabilities. The prior assisted local regression loop
passed in 10.1 seconds; independent exported tests reproduced pass/fail/pass in
7.9 seconds. Those component results do not close these end-to-end release gates.
