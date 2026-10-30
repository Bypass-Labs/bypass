---
description: Run an authorized black-box audit with the active Muse session.
---

For a bare `/bypass:blackbox`, ask in chat using these exact labels:

- Target URL
- Allowed paths
- Request rate (RPS)
- Muse calls (default 120)
- Time limit in minutes (default 30)

Copy the label **Muse calls** verbatim. If the user supplied some values, ask only for the missing ones. Accept a custom positive number for RPS or minutes, a positive whole number for Muse calls, or `default` for either default.

Use the bypass skill. Before calling any blackbox setup or start tool, get the exact target URL, allowed paths, request rate, Muse-call cap and time limit from this invocation. If any are missing, ask once in ordinary chat for the missing values and wait for the user's reply. Accept user-entered positive numeric rates and minutes and positive whole-number call caps. Offer 120 Muse calls and 30 minutes as separate defaults; the user can say "default" for either. Always label the call cap "Muse calls", never another model's name. Include a short example such as `http://127.0.0.1:3002, /, 7 rps, 240 Muse calls, 45 minutes`. Do not use the native multiple-choice picker for these values: its custom answer can return a label instead of the number. A previously selected application is a suggestion only, never the target for a new audit. Do not silently use its saved URL. If the user supplied a value, use it without asking again. Show the selected values before starting. If no app is selected for the chosen target, call `bypass_connect_app` for an app-only profile; use `local` for a loopback URL and ask for the environment for a deployed URL. Use `bypass_blackbox_setup` for both new and existing scopes, including a setup-only request. Do not use `bypass_blackbox_scope`, `force`, or direct file edits to change rate, Muse calls or time: they can replace unrelated saved scope settings. Review the returned scope and complete any ownership or authorization steps it requires before testing.

Pass the target, allowed paths and exact request rate to setup. Setup reuses an existing higher-rate scope when the user chooses a lower rate, and updates only the rate when the user chooses a higher one; preserve every other saved setting. Pass the chosen rate, Muse-call cap and time limit in minutes to `bypass_blackbox_start`. Pass other user-specified execution limits such as URL count, tasks and worker counts to start too. For a resume request, pass the user's new limits to `bypass_blackbox_resume`. Do not replace supplied values with defaults, and show the effective run limits. If the user asked only to prepare scope, do not start an audit. Continue with `bypass_blackbox_next`, carrying its progress cursor. Each pending request contains a bounded evidence prompt and JSON schema. Reason in this active Muse session and send one schema-shaped decision through `bypass_blackbox_submit` for each request ID. Continue until the audit is terminal. Never launch the standalone CLI, a nested Muse process, or an external model call. Bypass executes every scoped request and independently verifies findings.

Give concise progress updates with actual counts. At completion inspect findings and coverage, then call `bypass_blackbox_verify` and `bypass_blackbox_export` for confirmed findings. If saved research remains, use `bypass_blackbox_resume` when the user wants it continued. State untested work and failed proofs plainly. Keep credentials out of messages and artifacts.
