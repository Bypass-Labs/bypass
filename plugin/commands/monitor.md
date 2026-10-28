---
description: Configure and control saved-check monitoring inside Muse.
---

Follow the bypass skill’s choices-first interaction rules: reuse known answers, use native pickers with grounded recommendations and a custom-answer/note field for missing decisions, and discover configuration before asking. Read-only commands must remain read-only.


Read bypass_monitors and bypass_dashboard. If I request monitoring, reuse the existing named schedule; when cadence is missing, offer Hourly (recommended), Every 15 minutes, Daily, and a custom interval before creating one with bypass_add_monitor, then start the local worker with bypass_monitor_worker action start. Confirm its actual running state. The machine must remain awake and authorized account credentials must be available; this is not a cloud service. For one immediate run use bypass_run_monitor; for one due scheduler tick use bypass_monitor_worker action once. Use bypass_pause_monitor, bypass_resume_monitor, bypass_remove_monitor and worker action stop as requested. Show current results with bypass_context; distinguish historical failures superseded by a later passing retest. Do not suggest a standalone CLI command for these operations.
