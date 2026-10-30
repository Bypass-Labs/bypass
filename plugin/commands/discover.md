---
description: Run CodeQL discovery on selected source and preserve unevaluated signals.
---

First call bypass_scanner_capabilities through MCP to verify that this session
has loaded the scanner tools. If the tool is unavailable, report the native MCP
activation blocker and stop. An enabled plugin or visible slash command does not
establish runtime approval. Explain that the user can review Bypass's runtime
permissions and run `MUSE_NO_AUTO_UPDATE=1 muse plugins approve bypass` in their
terminal, then inspect with `MUSE_NO_AUTO_UPDATE=1 muse plugins inspect bypass --json`.
The security MCP server must show trusted_enabled; a new Muse session is required
after approval. Do not grant approval on the user's behalf or substitute a shell
CLI scan for this Muse MCP operation.

Use bypass_discover with plan=true to explain scope/prerequisites when requested.
For a scan, select an explicit source repository using Bypass project tools, then
call bypass_discover with detector=codeql and any requested languages, rule,
exclude-rule, or config. App-only profiles cannot run source scans. Docker must
be installed/running. Plugin installation ships the recipe; first use prepares
the pinned local image automatically. bypass_scanner_prepare can prewarm it.
No repository clone, host Python/CodeQL, or LLM settings are required.

Analysis excludes tests/fixtures, examples/demos/benchmarks, and generated/vendor
copies (including plugin/runtime) by default. Pass include-tests, include-examples,
or include-generated as booleans when the user requests those sources; JSON config
uses includeTests, includeExamples, and includeGenerated. Keep explicit ignore
rules respected. Report scope.analysisFiles separately from scope.contextFiles /
sourceReads: build inputs are retained, while analysis filters and primary alert
locations determine candidate scope. Use analysis-scope.json and filtered-signals
artifacts to explain exclusions; raw SARIF remains available. Existing runs retain
their original scope, so changed inclusion options require a new run.

Use bypass_scanner_rules to resolve requested queries to exact, case-sensitive
CodeQL @id values. rule/exclude-rule accept comma-separated IDs. Inclusion replaces
the default upstream security-extended suite; exclusions win. No glob, CWE, or
filename matching. Do not invent IDs. Custom Scratch rules are not available.

Starting/resuming returns a run. Poll bypass_discover_status at sensible intervals,
report phase changes and signal counts, and continue until a terminal status.
Use bypass_discover_signals to page candidates, bypass_discover_report to obtain
JSON/Markdown artifact references, and bypass_discover_artifact to read bounded
pages (follow nextOffset). Raw SARIF, diagnostics and logs retain full evidence.
Use resume for interrupted work and cancel when requested. Changed source/image
requires a new run. Preserve independent language failures and coverage gaps.

Build network is off unless a supplied config explicitly enables it; enabled
extraction runs in a separate helper. Query analysis stays offline. The original
source is read-only. Report detector candidates as unevaluated, never confirmed
vulnerabilities. No alerts does not establish complete coverage. Keep scanner
state separate from the existing source/HTTP assessment workflow.

CodeQL makes zero model calls in both interfaces. AI discovery/evaluation and the
next-task/evidence/submission loop are not implemented: explain that limitation
and stop unavailable calls. Future reasoning belongs to this active Muse session
and its settings; never configure an external LLM, access an API profile, read
Muse credentials, or launch a nested AI worker. Future standalone CLI reasoning
will require explicit API settings. MCP cannot attest subscription billing.
