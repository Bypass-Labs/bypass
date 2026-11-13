# First security audit

Use the [standalone CLI](../README.md#standalone-cli) or the Muse Code plugin. Both keep project state and evidence local, but they use different model connections: the CLI connects to a Muse model API or local Muse model, while the plugin uses the active Muse session.

## Standalone CLI

1. Install Bypass, then run `bypass onboard` from your application checkout. You can also enter a local folder or Git URL in the wizard.
2. Choose **Code only**, **Code + running app**, or **Running app only**. On a saved checkout, the wizard shows the previous choice and asks again. For a combined audit, select the saved app or enter another URL before live requests start.
3. Choose **Meta Model API** or a local Muse model. Meta Model API asks for its key in the same step, offers available Muse models, and checks the connection. Muse Spark 1.3 Contributor is the lowest-cost guided choice.
4. For live testing, review the app origin, environment, allowed paths and HTTP methods, then authorize that scope once. DNS or HTTPS ownership proof is an optional project setting. Accounts are optional for anonymous checks.
5. The first audit starts after setup. Watch the completed phases, HTTP checks, Muse calls, proof replay and coverage. A cited source concern stays unproven until fresh live controls confirm it.
6. Open `/results` for impact and remediation, `/memory` for saved knowledge, and `/context` for relevant evidence and exact local file locations. `bypass blackbox verify <run-id>` replays sealed live proofs; `bypass blackbox export <run-id>` saves standalone regression tests.

Project memory is in `<checkout>/.bypass/state.json`. Audit reports, coverage, request evidence and proofs are in `<checkout>/.bypass/runs/`. The CLI prints the exact paths for each run. See [CLI commands](COMMANDS.md) and [security memory](SECURITY_MEMORY.md).

## Muse Code plugin

1. Run the Muse plugin installer and choose **Enable Bypass and open Muse Code**. It opens a new Muse session with `/bypass:start`; if you deferred launch, start Muse and type that command. Choose the review type. For live testing, provide any missing repository path/Git URL and app URL together, then answer one grouped question form for environment when needed, duration (10, 30 or 60 minutes), and Entire app or Customize.
2. Muse connects the selected source or app profile. For a running app, approve the displayed testing paths, methods, rate and expiry once. The Entire app plan proposes `/`, all supported HTTP methods and 20 RPS. The plugin uses its current Muse session for reasoning; it does not require a separate Meta API key. Source review can proceed while optional ownership verification is pending.
3. Onboarding starts the selected audit after setup. **Code only** reviews source without live requests. **Code + running app** completes source review, then passes cited leads to one full live audit with a shared time budget; choose the ten-minute quick test for partial coverage. **Running app only** starts the full live audit without source. `/bypass:review` and `/bypass:blackbox` let you run those workflows later. At completion, Muse reads every distinct finding and shows status, severity, impact, evidence or unproved reason, saved regression and recommendation before offering any fix choice. You can inspect individual proofs and the full report without editing code.
4. Use `/bypass:context` or `/bypass:build` for remembered findings and source citations. Their tools return the local memory file and available report/proof paths. Old observations are historical; current behavior needs fresh checks.

The [plugin command map](PLUGIN_COMMANDS.md) lists all operations. A review request produces evidence and recommendations; application fixes require a separate request.

## Optional local fixture

`/bypass:demo` in Muse runs a separate sample invoice app to demonstrate a proof, fixture fix and regression replay. It does not assess your application. The fixture is useful for training and product validation; the first customer audit starts with `/bypass:start` or `bypass onboard`.

Older manual fixture scripts and integration checklists are available in Git history if an investigation needs them; they are not current onboarding instructions.
