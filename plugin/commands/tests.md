---
description: Inspect, replay, bind, export and manage saved security regressions.
---

Follow the bypass skill’s choices-first interaction rules: reuse known answers, use native pickers with grounded recommendations and a custom-answer/note field for missing decisions, and discover configuration before asking. Read-only commands must remain read-only.


Use bypass_dashboard and bypass_tests to identify the selected app and saved checks. Perform the requested action with bypass_test, bypass_save_test, bypass_run_tests, bypass_bind_tests, bypass_export_tests, bypass_disable_test or bypass_enable_test. Use existing check/target names as picker options for a missing selection or environment binding. For an audit reason, reuse a reason the user gave; otherwise ask for their actual reason without inventing one. Follow detached replay with bypass_watch_run until terminal. Confirmed regressions are security results, not tool failures. Generated tests have no model dependency. Binding to another environment requires that environment's ownership, explicit authorization and account references; never copy permissions from the old target. Use bypass_ci for a requested GitHub Actions workflow and bypass_report for a requested evidence export. Do not push files or configure repository secrets unless asked.
