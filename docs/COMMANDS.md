# Command and workflow guide

Use this guide for behavior, safety boundaries and common workflows. The [exact generated CLI reference](CLI_REFERENCE.md) lists every public command and every accepted option directly from the parser catalog; CI fails when it becomes stale. Add `--help` to any command for terminal help.

**Muse is the primary experience.** Use `/bypass:help` to discover these operations conversationally. Every public CLI command and option has an explicit [plugin mapping](PLUGIN_COMMANDS.md), checked by CI. `/bypass:demo` runs the complete real demonstration inside Muse; `/bypass:status` shows Done / Now / Next.

Global: --project <path>, --json, --non-interactive, --help, --version.

## Interactive shortcuts

Run `./bypass --project /path/to/your/app` to open the persistent workspace. Press Enter for the suggested action. Type `/` for a searchable command list: `/review`, `/blackbox`, `/engine`, `/repo`, `/app`, `/models`, `/results`, `/tests`, `/status`, `/memory`, `/context`, `/history`, `/plugin`, `/settings`, `/help`, and `/quit`. The slash is optional. `?`, `back`, and `q` still work. `/help all` shows the complete public catalog.

Use ↑↓ and Enter in menus, Tab to complete a slash command, ↑↓ on an empty command bar to recall session commands, Ctrl+O to show or hide the activity log, Ctrl+T to toggle the task panel, PgUp/PgDn to scroll, and Esc to clear a draft, go back, or stop a running operation. Ctrl+C exits with saved project state retained. Enter skips a running model connection check.

`/app` opens the current app's authorization and next action. DNS ownership proof is optional and feature flagged off in the default CLI flow; when enabled, it remains a separate step. Expired challenges are renewed before presenting their record. `/history` reads persisted project events. Session transcripts are saved locally under `.bypass/sessions/` on exit; command recall is limited to the current session.

These shortcuts belong to the interactive screen; shell commands use the catalog below. Raw catalog commands also work inside the workspace, except processes that need their own terminal (`auth login`, `mcp serve`, internal server commands). A foreground monitor worker requested in the workspace starts detached; `monitor worker --once` runs a single tick. Stopping `run watch` stops watching, not the background job; use `run stop <id>` to request job cancellation.

For a scrolling interface or screen reader, use `BYPASS_PLAIN=1 ./bypass`. `TERM=dumb` also selects the plain interface. `NO_COLOR=1` disables color. JSON and noninteractive output never use the full-screen renderer.

## blackbox

`bypass blackbox <url>` audits an authorized running app. For loopback targets it creates a reviewable `blackbox.scope.json` when needed; `--accept-local` confirms the local target. A deployed target needs `blackbox setup <url>`, scope review and testing authorization. DNS/HTTPS ownership proof is feature-flagged off by default; when a project explicitly enables `ownershipVerification` or requests discovered apex domains, setup also returns the required ownership step. `blackbox scope <url>` writes the scope file without registering the target.

The standalone audit uses the selected API model profile or the Meta default (`META_API_KEY`, then `LLM_KEY`, then `MODEL_API_KEY`). New terminal profiles suggest the generic `LLM_KEY` name while keeping existing provider-specific variable names available. The key value stays in the launching environment. The interactive standalone wizard gives the first audit a 10-minute wall-clock and 24 Muse-call budget, then reports remaining coverage for a deeper run or resume. Direct setup commands retain their documented scope defaults. `--no-model` runs the code-only path. `--rps` limits shared HTTP rate; `--agents` controls concurrent Muse decisions and `--http-workers` controls concurrent HTTP tasks. `--model-calls`, `--max-urls`, `--max-tasks`, `--minutes` and `--dom-script-bytes` set the recorded limits; zero means unlimited only for URL and task counts. Optional `--source <dir>` supplies source for hypothesis generation, while HTTP behavior remains the proof boundary.

`blackbox resume <run-id>` continues saved model research, `blackbox verify <run-id>` replays generated proofs, and `blackbox export <run-id>` writes standalone Node regressions. Runs save `report.md`, `coverage.json`, `evidence.jsonl` and PoCs under `.bypass/runs/<run-id>/`. A confirmed finding returns exit 1; incomplete coverage remains explicit. In Muse Code, `/bypass:blackbox` uses the active Muse session through the same runner and needs no separate API key. [Detailed scope and current limits](BLACKBOX_AUDIT.md).

## engine use <docker|mock> / engine doctor / engine prepare

Select the real audit or offline preview. `engine doctor` checks Docker and the selected model profile; `engine prepare` builds the isolated source-worker image. Source excerpts go to that provider. The Docker worker has no network, credentials or repository mount. Live HTTP is executed only by the scoped black-box runner. No mock fallback occurs on failure.

## probe add <name> / probe list

Configure one exact owner-owned JSON resource for HTTP proof. Options: `--target`, `--path`, `--resource-id`, `--owner`, `--outsider`, `--id-field` (default `id`), `--identity-field` (default `id`). Both selectors support nested fields (`run.id`) and JSON Pointer (`/run/id`). Both identities need an authorized `--check-path` returning distinct account IDs. Credentials stay in environment variables. Up to six probes per target. Reusing a probe name updates that binding. `probe list` shows configured probes.

## onboard [path]

Connect source code, a running app, or both, select a Muse model connection, authorize the live scope when applicable, and start the selected security audit. Requires an interactive terminal. `--flow quickstart` or `--flow advanced` skips the opening choice. Supplying a repository path, `--repo`, or `--project` defaults to QuickStart. Existing settings and evidence are retained. App fields accept bare domains. For automation, use `init --non-interactive` and explicit commands below.

Options: --repo, --dir, --flow, --mode.

## init [path]

Connect a repository and configure a project.

Options: --repo, --dir, --config, --name, --plan, --tracked-files.

## repo show

Inspect the connected repository.

## repo connect <path-or-url>

Connect or clone a repository.

Options: --dir, --name, --plan, --tracked-files.

## status

Show project readiness, results, and next actions.

## doctor

Check Node, Git, Muse, configuration, and worker health.

## config show

Show nonsecret project configuration.

## config set <key> <value>

Set autoSave, requestTimeoutMs, or project.name.

## auth login

Explain the supported authentication path: an API key in standalone mode or the official Muse login flow.

Options: --provider, --device.

## auth status

Show whether authentication is owned by the standalone API profile or the active Muse session.

## auth logout

Clear legacy Bypass-local account metadata; this does not sign out of Muse.

## integrate muse

Reuse an existing valid Muse plugin, including one from another checkout, or install the bundled native plugin if missing. Does not approve capabilities or change the existing installation source. For a newer public release, rerun `curl -fsSL https://bypasslabs.ai/install/muse | bash` (Windows: `irm https://bypasslabs.ai/install/muse.ps1 | iex`). Native `muse plugins update bypass` refreshes the recorded local source; an installer source may be pinned to an old release. Native installation failures include their diagnostic reason.

Options: --scope, --replace. `--replace` validates the new bundled plugin, replaces the old source, and attempts restoration if installation fails. Native approval and a new Muse session are still required.

## integrate status

Inspect the Muse plugin installation.

## integrate remove <muse>

Remove the native Muse plugin.

## target add <name>

Add a local or HTTPS deployed target.

Options: --url, --environment.

## target list

List targets and ownership state.

## target show [name]

Show target, challenge, and scope.

## target use <name>

Select an active target.

## target verify [name]

Check DNS/HTTP control, or acknowledge local ownership.

Options: --method, --wait, --renew.

## target authorize [name]

Record explicit, expiring testing scope.

Options: --scope-file, --paths, --methods, --rps, --accept, --production, --public-config.

The interactive `/app` → **Edit allowed methods & paths** picker supports GET, HEAD, POST, PUT, PATCH, DELETE, OPTIONS and custom comma-separated input. Use ↑↓ and Space to select, Enter to confirm. Plain terminals accept names or numbers separated by commas. Existing grants are retained until explicitly changed. Methods apply to every listed path prefix.

```bash
bypass target authorize app --paths /api/runs,/api/me --methods GET,HEAD,POST --accept --production
```

Omitted methods default to GET/HEAD. Scope files can specify `methods` as an array. CONNECT tunnels and HTTP/2 prefaces are not supported.

Fresh onboarding recommends GET, HEAD, POST, PUT, PATCH, DELETE and OPTIONS so Muse can review complete observed workflows. The full set is displayed before approval, write-capable methods are called out, and production still requires an additional explicit confirmation. Existing grants are preserved instead of being widened automatically; the GET/HEAD fallback above applies to direct commands that omit `--methods`.

## request

Send one request within current ownership, method and path permissions. For example, after authorizing POST and connecting the owner account:

```bash
bypass request --method POST --path /api/runs --identity owner --body-file test-run.json --id-field run.id
```

Options: --target, --method, --path, --identity, --body-file, --id-field. JSON body files are limited to 64 KiB. Paths are exact, without queries. Returns status, evidence run ID and an optional response resource ID; request/response bodies and credentials are not saved. Muse calls `bypass_request` directly and can supply a synthetic JSON object.

Use the returned resource ID to configure a normal access probe. Requests are never retried automatically, followed across redirects, or included in saved-test replay. If interrupted after sending, the result is unknown: inspect the app before repeating a possible write. This follows [HTTP retry semantics](https://www.rfc-editor.org/rfc/rfc9110.html#section-9.2.2). A one-off response is an observation, not security proof. Existing saved access regressions use GET; they do not recreate resources or test arbitrary mutation workflows. Cleanup requires its own allowed method/path.

## target revoke <name>

Revoke testing and pause target monitors.

## target remove <name>

Disconnect a target while retaining historical evidence.

## identity add <name>

Reference a bearer token, cookie, or header in an environment variable.

Options: --target, --type, --secret-env, --header, --check-path.

## identity list

List credential references, never values.

Options: --target.

## identity test <name>

Make one authorized request to the configured identity-check path.

## identity update <name>

Update a credential reference.

Options: --secret-env, --check-path.

## identity remove <name>

Remove an identity reference; dependent tests become blocked.

## model add <name>

Add local, self-hosted endpoint, or Muse Code provider.

Options: --provider, --base-url, --model, --secret-env, --allow-private, --effort, --transport, --max-output-tokens, --timeout-ms, --stream, --workspace-env. Muse effort defaults to minimal; accepts minimal, low, medium, high.

## model list

List model profiles and inference destinations.

## model use <name>

Select the model profile.

## model test [name]

Send a synthetic smoke prompt, without repository content.

Human-readable mode shows progress and a 45-second limit. In an interactive terminal, press Enter to skip the check or Ctrl+C to exit; both stop the active check. Onboarding continues after a skip; a standalone skipped test exits with code 130. `--json` emits only the final machine-readable result. `--non-interactive` does not listen for keyboard input.

Muse checks require a completed assistant response, not an echoed prompt. The latest failed or skipped attempt is shown in readiness even when an earlier test passed. Login, allowance, missing-CLI, and endpoint errors include recovery instructions without exposing provider output or credentials.

## model remove <name>

Remove a model profile.

## scan

Run the canonical security audit. `--mode code` performs cited source review and makes no app request. `--mode live` invokes the full broad black-box runner and skips source. `--mode combined` starts source review and live reconnaissance together, hands cited hypotheses into live planning, and returns one parent result linked to the sealed black-box report. The saved target authorization supplies paths, HTTP methods and rate; compatible owner/outsider references are reused automatically. Confirmation returns exit 1; incomplete, blocked or no-confirmation coverage returns exit 3. The optional mock engine remains explicitly simulated.

Options: --mode, --target, --base, --full, --plan, --detach, --agents, --http-workers, --model-calls, --max-urls, --max-tasks, --minutes.

## finding list

List findings, with simulation and evidence labels.

Options: --target, --run, --status, --severity.

## finding show <id>

Show evidence, history, and remediation context.

## verify <finding-id>

Reproduce a real finding with its bound HTTP controls. Source hypotheses need a matching approved probe. Offline samples cannot become deployed proof.

Options: --target.

## retest <finding-id>

Check a deployed fix and save a standalone regression.

Options: --target, --build.

## test list

List saved regression checks.

Options: --target.

## test show <id>

Show a check and environment bindings.

## test save <finding-id>

Save a portable regression after a verified fix, or export a confirmed black-box proof immediately. Use `--out` to choose the export directory.

## test run [id]

Replay deterministic checks with zero model calls.

Options: --all, --target, --detach.

## test bind [id]

Bind a saved check to an authorized environment.

Options: --all, --target, --file.

## test export [id]

Write ordinary Node tests with no Bypass dependency.

Options: --all, --target, --out, --force.

## test disable <id>

Disable a saved check with an audit reason.

Options: --reason.

## test enable <id>

Enable a saved check.

## coverage

Show behavior-level checks, gaps, stale, and blocked evidence.

## context

Read current session evidence. Add `--task "Add invoice export"` and optionally `--files "src/routes.js,src/auth.js"` / `--target staging` for feature-specific security context. No model call, Docker or app request. Use `--json` to pass the packet to a coding agent. Source knowledge, prior investigations, saved behavior requirements and freshness are explicit. The host agent implements the feature; new routes need new tests.

Options: --finding, --task, --files, --target.

## memory / memory list

Inspect local memory, including disabled memory. Filter with `--query` or inspect target applicability with `--target`. Records show citations, provenance and freshness. Automatic retrieval excludes another origin and source now outside the eligible inventory.

## memory show <id> / memory forget <id>

Read a single record or forget it. Forgetting excludes that record identity from relearning but preserves original findings, checks and run logs.

## memory use <on|off>

Enable or disable recording and automatic retrieval. Disabling retains inspectable records and does not disable saved-test replay. See [Security memory](SECURITY_MEMORY.md).

## report

Export a run as JSON or Markdown.

Options: --run, --format, --out.

## run list

List durable runs.

## run show <id>

Inspect one run.

## run watch <id>

Wait for completion and return the final exit code.

Options: --timeout.

## run stop <id>

Request cancellation of a running worker.

## monitor add <name>

Schedule saved regression replay.

Options: --target, --every, --runner.

## monitor list

Show schedules and local worker health.

## monitor run <name>

Run a schedule immediately.

## monitor pause <name>

Pause a monitor.

## monitor resume <name>

Resume a monitor.

## monitor remove <name>

Remove a monitor; retain run evidence.

## monitor worker

Run the real local scheduler (machine must remain awake).

Options: --detach, --once, --stop.

## ci init

Generate a GitHub Actions workflow for exported Node tests, or use --agent for Meta API PR review, deployment verification and scheduled replay. Setup generates files only. See [GitHub agent setup](GITHUB_AGENT.md).

Options: --provider, --target, --force, --agent, --action-ref, --every, --revision-path, --revision-field. The action reference is a reviewed full Bypass commit SHA, optionally taken from bundled release identity. Cadence choices are 24h, 6h and off.

## mcp serve

Start the typed stdio MCP server.

## demo start

Create the Ledger Git fixture and start its HTTP server.

Options: --dir, --port.

## demo status

Show the fixture state.

## demo fix

Enable ownership enforcement in the local fixture.

## demo regress

Reintroduce the local fixture defect.

## demo add-route

Add an uncovered export route to the fixture.

## demo reset

Reset fixture behavior while retaining evidence.

## demo stop

Stop the local fixture server.

## Exact syntax and flags

See the [generated CLI reference](CLI_REFERENCE.md). It is checked against the same catalog used for strict parsing and terminal help, including boolean/value distinctions.

## Exit codes

0: operation succeeded (detached means accepted). 1: confirmed fixture failure or failed regression. 2: usage/configuration error. 3: incomplete, blocked, no checks, or mock analysis without a real verdict. 130: cancelled.

## Account/resource preflight

`bypass probe test <name> --project /path/to/app` checks the two signed-in account IDs and owner resource with three authorized GET requests and no model calls. The plugin performs this through `bypass_test_probe`. Status `ready` means those exact positive controls succeeded; it is not a security verdict. The broad live audit independently validates any compatible account references it uses; a configured legacy probe is not a prerequisite for starting a live or combined audit.

Run status is `failed` for execution errors, `incomplete` for blocked/bounded results with exit 3, `cancelled` for cancellation and `completed` when the requested execution finished with a conclusive behavior result. `run watch` exits for all terminal statuses. `status` and `context` return a compact latest-run summary; `run show <id>` / `bypass_run` returns the detailed evidence.

## Optional accounts and faster review (0.7.1)

`bypass --help` shows a short starting menu; `bypass --help --reference` shows every command. The primary plugin flow is `/bypass:start` inside Muse.

- `registration configure`, `registration test`, `registration status`: authorize bounded JSON/Firebase signup, privately connect generated accounts, inspect evidence and cleanup needs.
- `probe discover`: derive exact owned IDs from an authorized collection, using selectors from source.
- `probe add --kind anonymous`: test an exact JSON resource without credentials. Use `--response html --match-text 'specific content marker'` for HTML. Set `--expected private` only for an established private-content requirement; public content is an observation.
- `test save <finding-id>` and `test export <check-or-finding-id>`: preserve failing reproductions immediately after observed confirmation.
- `poc resume`: restart the recorded generated fixture; source edits, finding/check IDs and evidence are retained. Known fixture forms only.

All have typed Muse tools; see [the generated capability reference](PLUGIN_COMMANDS.md) and [account/signup contracts](ACCOUNTS.md). Source and anonymous checks do not require imported accounts. Authenticated checks still require valid positive controls.
