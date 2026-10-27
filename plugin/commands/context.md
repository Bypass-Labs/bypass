---
description: Resume the selected application's setup, evidence and current saved-check status.
---

Use the bypass skill. Call bypass_onboarding first. If no application is selected, ask its one repository question; do not search .demo folders, initialize the tooling repository, or summarize example history. For the selected application, call bypass_context and show repository, app, engine and current readiness. Show current failed/blocked/stale saved checks before historical monitor outcomes. If latestMonitor.superseded is true, explain that a later passing retest superseded the historical failure. Never describe a disabled schedule as running. If setup is incomplete, guide the next missing step in plain language and perform tools yourself after the answer. A context request alone does not authorize a scan. Do not end with raw MCP function syntax for the user to execute.
