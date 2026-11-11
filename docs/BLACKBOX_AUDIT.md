# Running-app security audit

Bypass tests one authorized app origin under an explicit scope. The standalone CLI uses a selected Muse model API or local Muse model for planning. The Muse Code plugin uses its active session. Both call the same guarded HTTP runner and save local evidence.

## Start

The shortest standalone path is `bypass onboard`: choose **Running app only** or **Code + running app**, select the app URL, review paths and methods, and approve the displayed scope. A resumed combined project asks you to select the saved app or enter another URL before live testing. The first audit starts after setup; `bypass blackbox <url>` is the direct command for an already configured app. In Muse Code, combined review completes source work first, then passes cited leads to one full live audit. Its ten-minute choice is a quick pass with explicit untested coverage.

In Muse Code, `/bypass:start` connects the application and `/bypass:blackbox` starts a running-app audit with the active Muse session. The plugin does not ask for a separate Meta API key.

The scope records the exact origin, environment, allowed path prefixes, HTTP methods, request rate and expiry. DNS or HTTPS ownership proof is optional unless enabled for the project. Approval of one app does not authorize another. Accounts are optional for anonymous checks; account-boundary checks need valid, distinct test identities.

## What the run does

1. Save the effective scope and limits with the run.
2. Read reachable public pages and assets, collect observed routes and response shapes, and incorporate cited source leads when a combined review selected code. The standalone CLI overlaps independent source interpretation with anonymous route and asset reconnaissance. The native plugin carries bounded source-extracted route methods and request fields into the live run without another model source pass. Bounded source review sends likely server handlers before client call sites and includes a small same-file authentication helper when a handler calls it.
3. Execute bounded checks within the saved HTTP scope. Muse can suggest tests from observed facts; Bypass validates each request before sending it.
4. Replay supported positive signals with fresh controls. Source interpretations and model suggestions alone do not confirm a vulnerability.
5. Write confirmed findings, inconclusive results, untested work and coverage to the report. A time or model-call cutoff remains incomplete, even when no finding was confirmed.

When a focused source lead cannot be linked to the current source revision or the proposed HTTP route, Bypass may still run its authorized request but drops the source attribution. A model-supplied candidate without complete proof controls runs only as an observation; it cannot become a confirmed finding until fresh controls and replay support it. In audits of ten minutes or less, Bypass prioritizes security-sensitive server handlers within its bounded source batches and limits anonymous response-hint review to one batch. If Muse cites an authentication-bypass gate with a literal fallback, Bypass retains that full masked source line in the local lead so later scoped controls can test the exact candidate. The source reader also retains a narrow, unproven access-gate lead when Muse omits a cited environment fallback entirely. When a source tree is supplied with at most ten model calls, one call is reserved for source review so cited routes can still drive checks. The remaining model allowance can plan and execute route and method checks, including when login follow-ups keep returning negative results.

After the primary checks finish, Bypass can start up to two bounded related pivots from positive web signals and one from a source-informed task finding within the remaining research budget. Muse sees measured controls, nearby observed routes and relevant cited source leads, then proposes one scoped follow-up at a time. Bypass validates and executes it separately. The original finding still needs independent proof replay. This follow-up runs only while the model and time budgets have room; it does not turn a response difference into a finding.

Identity discovery retries transient failures on the configured read-only identity endpoint before treating test accounts as unavailable. When recon already recorded an anonymous denial and no working test identity, injection checks cite that observation instead of repeating every baseline request. A denied injection baseline is reported as **blocked: reachable control or identity needed** rather than as an ambiguous inconclusive test. Genuine timeouts, unstable responses and missing proof controls stay inconclusive. Safe read-only Muse requests get one fresh attempt after a transport timeout; writes are never automatically repeated. An app that sends login or registration through an external identity provider remains outside the app-origin audit unless that provider is separately authorized.

For a cross-account list check, a route with no observed owner-exclusive record is blocked until a suitable test record exists. If an owner-exclusive record is present and the checked outsider response is empty while anonymous access is denied, that exact check is **not reproduced**; other pages, filters and records remain untested. If the outsider receives different records, the check stays **inconclusive** so Muse can test other observed list filters before closing it.

A cited GET injection lead moves the matching observed input earlier in the proof queue. A direct `LIKE '%${input}%'` citation selects a matching SQL search quote shape; otherwise the existing search shape remains available. A short audit may derive a benign search baseline from a non-sensitive field in an anonymous JSON response when its name matches the cited `LIKE` column. SQL search checks still require identifiable records, two randomized boolean pairs and fresh replay. If a generic Muse request independently proves the same cited SQL input, its sealed proof corroborates the SQL finding rather than appearing as another access-control issue. Callback proofs allow a stable error from a harmless invalid URL control, while both audit-owned callback requests must succeed and be fetched again during replay.

For a local combined audit, Bypass can also turn two narrow source citations into immediate HTTP checks before optional planning: a literal client identity header used by an authentication helper on an observed denied GET route, and a `fetch(field)` call on an observed JSON POST URL field. The header check compares anonymous, invalid-header and candidate-header reads. The fetch check uses two audit-owned callback bodies and proves that each body appears only in its matching app response. Both still require a fresh sealed replay; source text alone remains unproven. A login throttling check uses 20 synthetic invalid attempts against one nonexistent user when the observed POST contract and scope permit it. On a local target its finding describes only the local app layer; deployed edge controls and real-account lockout behavior remain untested.

Progress shows the current phase, HTTP and Muse activity, completed checks, positive signals and remaining work. First access, web and HTTP-sequence planning pages overlap under one shared scope, request limiter, model-call budget and evidence ledger. Accepted sequence proofs wait for the independent first-page checkpoints before execution; bounded HTTP workers continue in parallel. When a quick audit has more than 16 observed routes, its first HTTP-sequence page asks for one source-prioritized, bounded request check among at most four routes using a compact model response schema. Later pages retain the full set of investigation shapes. The guided first audit uses a 10-minute and 24-Muse-call budget; direct commands accept explicit `--minutes`, `--model-calls`, `--rps`, `--max-urls`, `--max-tasks`, `--agents` and `--http-workers` values. The effective values are saved with the run.

## Evidence and replay

Each `bx-*` run stores `report.md`, `coverage.json`, `evidence.jsonl` and any sealed proofs under `<project>/.bypass/runs/<run-id>/`. The parent `run_*` record for a combined audit links the source result and live evidence. `/results` or `bypass finding show <id>` shows impact, severity, proof status and recommended fix. `/memory` and `/context` show exact local file locations and treat prior results as historical evidence.

Standalone API audits record provider-reported input, output and total token counts in `report.md` and `run.json`. The report states how many model calls supplied usage. If the provider or Muse Code session omits usage, the counts are unavailable or partial; model-call count alone is not a token-spend measurement.

`/results` puts saved confirmed HTTP findings before provisional source leads. A source-only lead still shows its citation, possible impact and suggested fix, but offers no proof replay until approved HTTP controls produce one. If Muse times out during source review, the combined result names that pause and retains the partial source evidence while reporting live coverage separately.

```bash
bypass blackbox verify <bx-run-id> --project /path/to/app
bypass blackbox export <bx-run-id> --project /path/to/app
```

`verify` repeats the saved proof with current scoped requests. `export` writes standalone Node regression tests under `tests/security/blackbox/`. Those tests fail while a confirmed vulnerability remains present and should pass after its fix. They carry no model key. A confirmed vulnerability returns exit 1; an incomplete or inconclusive audit returns exit 3, rather than a clean result.

For exact flags, use [CLI commands](COMMANDS.md) and the [generated CLI reference](CLI_REFERENCE.md). The [audit evaluation contract](AUDIT_EVALUATION.md) checks that a combined run linked its source, live report, scope, findings and proof IDs.
