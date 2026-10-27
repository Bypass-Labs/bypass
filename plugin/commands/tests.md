---
description: Inspect, replay, bind, export and manage saved security regressions.
---

Use bypass_dashboard and bypass_tests to identify the selected app and saved checks. Perform the requested action with bypass_test, bypass_save_test, bypass_run_tests, bypass_bind_tests, bypass_export_tests, bypass_disable_test or bypass_enable_test. Ask only for a missing selection, environment binding or audit reason. Follow detached replay with bypass_watch_run until terminal. Confirmed regressions are security results, not tool failures. Generated tests have no model dependency. Binding to another environment requires that environment's ownership, explicit authorization and account references; never copy permissions from the old target. Use bypass_ci for a requested GitHub Actions workflow and bypass_report for a requested evidence export. Do not push files or configure repository secrets unless asked.
