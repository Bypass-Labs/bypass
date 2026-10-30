---
description: Inspect the whitebox scanner scaffold and its implementation boundaries.
---

Use bypass_discover with plan=true to inspect the whitebox scanner design and prerequisites.
Muse owns every reasoning step through this active session and its settings. Never configure
an external LLM, access an API profile, read Muse credentials, or start a nested AI worker.
Subscription billing depends on the active Muse configuration and is not attested by MCP.

This is a scaffold: analysis, detectors, evidence reads, persisted tasks, and report generation
are not implemented. Explain the returned limitation and stop; do not repeat unsupported
calls, fabricate findings, or substitute the existing source/HTTP review workflow.

When task execution is implemented, the intended loop is: start/resume a selected run,
obtain its next task, follow scanner-supplied instructions using its permitted evidence
tools, submit the typed result, handle validation feedback, and continue until finished,
blocked, or cancelled. Security policies and stage transitions belong to the Python scanner.
The direct Bypass CLI will require its own explicitly configured LLM API settings.
