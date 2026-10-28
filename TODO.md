# UAT bugs and release gates

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

- [ ] Complete production UAT on the latest installed release, including real supported signup and suitable dedicated resources. Local fixture proof and the focused scope-update test are not production review evidence.
- [ ] Observe a first-time user complete the production journey without operator-prepared fields/data.
- [ ] Host inference delay remains variable; Bypass cannot render during Muse's own model turn. Do not promise a latency bound from one run.
- [ ] Arbitrary browser signup, social login, CAPTCHA and unsupported resource provisioning remain explicitly out of scope.

## Scope/update recovery — 0.7.6

- [x] UAT-10: Scope editing was attempted on installed/loaded 0.7.1 after 0.7.5 was published. Onboarding now distinguishes loaded, installed and published versions and provides the public installer or fresh-session action. Failures carry the loaded version. Native installation must confirm the requested version before reporting success. Offline metadata checks remain unavailable, not current.
- [x] UAT-11: The exact approved scope-file payload (all seven common methods, `/`, 2 requests/second, production acknowledgment) succeeds through the installed 0.7.5 plugin in a fresh native Muse session. Saved scope and reopened picker match. [Focused evidence](docs/evidence/muse-scope-update-2026-10-27.json). This was a headless native conversation; the interactive picker and whole production journey are not established by it.
- [x] UAT-12: Changing scope no longer invalidates reuse of an already-recorded account-creation budget. Current identity-path permission still applies; no duplicate signup is attempted.
- [x] UAT-13: Interactive native Muse sent the custom method list as a JSON-encoded string before retrying with CSV. Accept that exact representation with the same method validation; invalid lists leave authorization unchanged. Keyboard selection and final saved methods passed on a local target; the first attempt required recovery, so this was not an error-free journey.
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
