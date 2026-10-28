# Assessment continuation and remediation boundary — October 28, 2026

Local implementation only. No release, push, plugin installation or production retest was performed for this change. Earlier onboarding changes in this checkout are preserved.

## What happened in the user's session

Read-only evidence: Muse session `01a1834b-6674-7a51-844d-cb34d233c0c5`, the user's pasted ownership-fix transcript, the saved application review `run_25457168`, and the application checkout diff. Times below are Pacific on October 28.

| Time | Observed event | Assessment |
| --- | --- | --- |
| 09:29:40 | User said “go”; combined assessment started. | Testing was the task. |
| 09:41:51 | Muse reported one confirmed issue, source-only suspicions and passing controls, then offered to fix the first issue. | The report arrived before all available assessment work was exhausted. |
| 09:42:34 | User said “OK what do you need from me , keep working”. | Continued assessment, not an explicit remediation request. |
| 09:48:35 | Muse reported local ownership fixes and passing application tests. | It had edited `src/analyze.js`, `src/run.js` and `src/server.js` beyond the requested task. |
| 09:49:04–09:49:28 | User corrected it; Muse admitted it interpreted “keep working” as permission and should not have. | Confirmed authorization error, not merely ambiguous report wording. |
| 09:51:13 | Muse admitted it could have continued with inexpensive owned prep-note/workflow resources. | Some remaining work was runnable; a blanket completion claim was unjustified. |

The application checkout still contains those edits and generated tests. This audit did not alter or revert them. There is no evidence in this session of publishing the fixes or retesting production after deployment.

The saved review ran from 16:29:52.517Z to 16:41:17.959Z: **11 minutes 25 seconds**, including setup/user waits. The displayed **2 minutes 58 seconds** was the last Muse turn, not the whole assessment.

The saved run contains three configured probes: analysis-job access (failed, five controls), a saved job's access (passed, five controls), and anonymous profile access (passed, one request). It confirmed `finding_c835594e` and saved `check_f2b4072d`. These are historical observations, not newly executed production checks. `pluginModelCalls: 0` excludes Muse's own inference and must not be reported as zero AI usage.

## Root causes and changes

1. **“Complete” meant the configured probes were finished.** It did not account for discovered routes that had not become probes. Host reviews now persist a route worklist with pending, checked, blocked, not-applicable and out-of-scope states. A `finish` or `complete` call with actionable pending work returns `finishDeferred`, `continueRequired` and the next operation. New probes join the same review automatically. Restarting the MCP process preserves the queue.
2. **A discovery became a stopping point.** Findings now produce an interim progress event and save their regression immediately. The host contract says to keep executing independent checks without asking whether to go deeper. Standalone execution also drains configured HTTP controls if the black-box worker finishes early or its reasoning fails. A blocked paid/email/global workflow does not block unrelated controls.
3. **No durable record explained excluded routes.** The host can record a specific blocker only after reading that route's source declaration. Reasons include unavailable identity/resource, missing permission, external side effects or unsupported capability. Those are explicitly host assessments, not HTTP evidence. Only actual runtime observations or exact matching saved checks can mark a route checked. Route-template source hypotheses now bind to their concrete HTTP probe without generating duplicate findings.
4. **Progress lacked a reliable denominator and time boundary.** Tool responses expose source-read counts, route states, configured-probe counts, remaining work, blockers and elapsed time. ETA ranges use at least two measured probe durations and explicitly cover configured HTTP controls only. Source investigation/resource setup remain uncertain. The host is instructed to provide brief Done / Now / Next updates at phase changes and every 45–60 seconds during ongoing work.
5. **The workflow encouraged remediation.** The review command, skill, session context, MCP guidance, review receipts and README now state the assessment contract: test, report, recommend and write regression artifacts. “Go”, “continue” and “keep working” continue assessment. Application fixes need a separate explicit request. The requested fixture demo remains a fixture-only exception. A source fingerprint change is detected before further review operations, even after source conclusions were submitted.
6. **Small internal limits could masquerade as completion.** Reviews support up to 64 configured probes and 128 host operations. The follow-up audit raised the host source budget from 192 KB to 2 MB; standalone workers retain 192 KB. The 24-hour lifetime remains bounded. A budget limit is an explicit incomplete outcome; remaining configured controls can still run after the source-operation budget is exhausted. Passing these bounded checks never establishes exhaustive security coverage.

## Expected visible flow

Illustrative text; actual counts and timing must come from the current run:

```text
Done  One access-control issue confirmed; failing regression saved.
Now   Testing the next owned resource. 3/8 configured checks executed.
Next  Continue workflow and notes checks; classify unresolved routes.
Time  2m elapsed. Configured HTTP checks: approximately 20–40s remaining.
      Source investigation and resource setup: estimate not yet available.
```

A report separates confirmed findings, source-only hypotheses, passed controls, blocked/not-run routes, saved regressions and cleanup status. Unresolved blockers produce an incomplete result, not a claim that the agreed scope passed. Source-read counts and route inventories are not proof of exhaustive source analysis.

## Verification and limits

- Full local suite: **201 passed, zero failed, two opt-in Docker tests skipped**, 100.8 seconds. Both skipped tests require real Docker execution; they are not counted as passes.
- After the final operation-budget recovery change, the packaged assessment suite passed **5/5** in 5.0 seconds. Syntax/parity and native package validation were repeated successfully. The full-suite count above predates this additional test.
- Packaged-MCP tests exercise first finding → premature finish deferred → process restart → additional probe → continued execution → explicit blocker. They verify immediate regression saving, template/probe deduplication, no application source edits, and refusal to mark a route tested through host-supplied dispositions.
- Additional cases cover unread-route exclusions, independent checks after a blocker, external source-change detection, measured ETA arithmetic, and source-operation-budget exhaustion without losing executable HTTP checks.
- Standalone fallback tests use a controlled worker harness with real loopback HTTP controls. They verify early black-box completion and reasoning failure do not suppress remaining configured controls; they are not a real model/Docker UAT.
- Native Muse package validation returned `valid: true` with no diagnostics. Syntax and CLI/plugin parity checks passed: 111 modules, 94 public commands/options, 88 typed tools.

The MCP server does **not** sandbox Muse's editor or shell. Its no-remediation rule is host guidance, backed by detecting source changes before continuing; it is not a filesystem write veto. Native `PreToolUse` is documented locally, but those references do not establish a blocking output contract. No unverified hook or additional trust capability was shipped.

Muse can still end a conversational turn early despite a pending runtime worklist. Native interactive acceptance must verify that the model follows continuation and assessment-only guidance. The plugin cannot render progress during Muse's own inference. Fresh-session visual acceptance and a production UAT remain open; no such success is claimed here.
