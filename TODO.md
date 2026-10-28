# UAT bugs and release gates

Open issues observed in the October 27, 2026 fresh-install UAT of Bypass 0.7.0
(`e87d042`). Muse reviewed `Bypass-Labs/job-finder` at `1f5684f`.
These items are not fixed. The first production black-box attempt was blocked by
DNS verification; the rerun below completed the configured production probes.
Local-fixture results are not production evidence.

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

- [ ] **UAT-01: Preserve JSON structure during secret redaction.** After a real
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

- [ ] **UAT-02: Make long host-model waits visible and recoverable.** One source
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

- [ ] **UAT-03: Recover the local demo after its server stops.** Interrupting the
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

- [ ] **UAT-04: Render pending DNS as a setup state.** Missing ownership is an
  expected onboarding step, but the plugin presents it as a failed tool call.
  Preserve the live-request gate and expose the exact record, expiry, retry
  action, and source-only option. Acceptance: pending and verified flows remain
  understandable in Muse; a retry or reinstall preserves a current challenge;
  an expired challenge is clearly renewed without silently accepting old proof.

- [ ] **UAT-05: Align source-read tool arguments and host guidance.** Muse made
  an invalid `bypass_review_step.paths` call before recovering. Inspect the
  schema, examples, and tool response guidance; the observed error alone does
  not establish a schema defect. Acceptance: a fresh installed-plugin source
  review reads files successfully on its first valid call, and malformed input
  returns a concrete correction. Evidence: `source-host.jsonl`.

- [ ] **UAT-06: Avoid false unavailable plugin-version diagnostics.**
  `src/runtime-identity.mjs` bounds native inspection at 2 seconds, while a
  successful native inspection took approximately 3.7 seconds in UAT. The
  installed plugin consequently reported its installed-version check as
  unavailable. Acceptance: report the actual version, distinguish a slow check
  from a missing installation, and keep the status interaction bounded.

- [ ] **UAT-07: Make installed CLI help a short starting point.** The installed
  executable's help begins with clone-style `./bypass` examples and exposes 85
  commands at once. Acceptance: installed help uses `bypass`, prioritizes the
  plugin and guided start, shows a few next actions, and keeps the complete
  command reference available on demand.

- [ ] **UAT-08: Explain finding state after regression replay.** A deliberate
  fixture regression reopened a confirmed finding. Restoring the fix made the
  saved check pass but left the finding confirmed until an explicit retest.
  This is a state/UX ambiguity, not evidence that replay failed. Acceptance:
  show both the passing check and finding verification state with an explicit
  next action; test the documented closure semantics through Muse. Do not close
  findings based on unrelated passing checks. Evidence: `mcp-fixture-finish.json`
  and the final fixture finding history.

## P3 — diagnostic accuracy

- [ ] **UAT-09: Remove misleading hardcoded host-version wording.** Billing
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
