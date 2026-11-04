# Running-app security audit

Bypass tests one authorized app origin under an explicit scope. The standalone CLI uses a selected Muse model API or local Muse model for planning. The Muse Code plugin uses its active session. Both call the same guarded HTTP runner and save local evidence.

## Start

The shortest standalone path is `bypass onboard`: choose **Running app only** or **Code + running app**, select the app URL, review paths and methods, and approve the displayed scope. A resumed combined project asks you to select the saved app or enter another URL before live testing. The first audit starts after setup; `bypass blackbox <url>` is the direct command for an already configured app. In Muse Code, combined review completes source work first, then passes cited leads to one full live audit. Its ten-minute choice is a quick pass with explicit untested coverage.

In Muse Code, `/bypass:start` connects the application and `/bypass:blackbox` starts a running-app audit with the active Muse session. The plugin does not ask for a separate Meta API key.

The scope records the exact origin, environment, allowed path prefixes, HTTP methods, request rate and expiry. DNS or HTTPS ownership proof is optional unless enabled for the project. Approval of one app does not authorize another. Accounts are optional for anonymous checks; account-boundary checks need valid, distinct test identities.

## What the run does

1. Save the effective scope and limits with the run.
2. Read reachable public pages and assets, collect observed routes and response shapes, and incorporate cited source leads when a combined review selected code.
3. Execute bounded checks within the saved HTTP scope. Muse can suggest tests from observed facts; Bypass validates each request before sending it.
4. Replay supported positive signals with fresh controls. Source interpretations and model suggestions alone do not confirm a vulnerability.
5. Write confirmed findings, inconclusive results, untested work and coverage to the report. A time or model-call cutoff remains incomplete, even when no finding was confirmed.

Progress shows the current phase, HTTP and Muse activity, completed checks, positive signals and remaining work. The guided first audit uses a 10-minute and 24-Muse-call budget; direct commands accept explicit `--minutes`, `--model-calls`, `--rps`, `--max-urls`, `--max-tasks`, `--agents` and `--http-workers` values. The effective values are saved with the run.

## Evidence and replay

Each `bx-*` run stores `report.md`, `coverage.json`, `evidence.jsonl` and any sealed proofs under `<project>/.bypass/runs/<run-id>/`. The parent `run_*` record for a combined audit links the source result and live evidence. `/results` or `bypass finding show <id>` shows impact, severity, proof status and recommended fix. `/memory` and `/context` show exact local file locations and treat prior results as historical evidence.

`/results` puts saved confirmed HTTP findings before provisional source leads. A source-only lead still shows its citation, possible impact and suggested fix, but offers no proof replay until approved HTTP controls produce one. If Muse times out during source review, the combined result names that pause and retains the partial source evidence while reporting live coverage separately.

```bash
bypass blackbox verify <bx-run-id> --project /path/to/app
bypass blackbox export <bx-run-id> --project /path/to/app
```

`verify` repeats the saved proof with current scoped requests. `export` writes standalone Node regression tests under `tests/security/blackbox/`. Those tests fail while a confirmed vulnerability remains present and should pass after its fix. They carry no model key. A confirmed vulnerability returns exit 1; an incomplete or inconclusive audit returns exit 3, rather than a clean result.

For exact flags, use [CLI commands](COMMANDS.md) and the [generated CLI reference](CLI_REFERENCE.md). The [audit evaluation contract](AUDIT_EVALUATION.md) checks that a combined run linked its source, live report, scope, findings and proof IDs.
