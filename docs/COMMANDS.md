# Command reference

Generated from the parser catalog. Add --help to any command. Values are required for flags unless listed as booleans below.

**Muse is the primary experience.** Use `/bypass:help` to discover these operations conversationally. Every public CLI command and option has an explicit [plugin mapping](PLUGIN_COMMANDS.md), checked by CI. `/bypass:demo` runs the complete real demonstration inside Muse; `/bypass:status` shows Done / Now / Next.

Global: --project <path>, --json, --non-interactive, --help, --version.

## Interactive shortcuts

Run `./bypass --project /path/to/your/app` to open the persistent workspace. Press Enter for the suggested action. Type `/` for a searchable command list: `/engine`, `/poc`, `/repo`, `/review`, `/results`, `/demo`, `/tests`, `/app`, `/models`, `/status`, `/memory`, `/context`, `/history`, `/plugin`, `/settings`, `/help`, and `/quit`. The slash is optional. `?`, `back`, and `q` still work. `/help all` shows the complete catalog.

Use ↑↓ and Enter in menus, Tab to complete a slash command, ↑↓ on an empty command bar to recall session commands, Ctrl+O to expand operation details, PgUp/PgDn to scroll, and Esc to clear a draft, go back, or stop a running operation. Ctrl+C exits with saved project state retained. Enter skips a running model connection check. A local fixture startup finishes its short setup before cleanup; its footer says when it cannot be interrupted.

`/app` opens the current app's ownership challenge and next action directly. DNS ownership and testing authorization remain separate. Expired challenges are renewed before presenting their record. `/history` reads persisted project events. Session transcripts are saved locally under `.bypass/sessions/` on exit; command recall is limited to the current session.

These shortcuts belong to the interactive screen; shell commands use the catalog below. Raw catalog commands also work inside the workspace, except processes that need their own terminal (`auth login`, `mcp serve`, internal server commands). A foreground monitor worker requested in the workspace starts detached; `monitor worker --once` runs a single tick. Stopping `run watch` stops watching, not the background job; use `run stop <id>` to request job cancellation.

For a scrolling interface or screen reader, use `BYPASS_PLAIN=1 ./bypass`. `TERM=dumb` also selects the plain interface. `NO_COLOR=1` disables color. JSON and noninteractive output never use the full-screen renderer.

## poc / poc start / poc stop

`poc` creates a separate local app and opens the workspace with real Docker agents selected. Docker and a configured model are required for review. The fixture uses two public accounts; model calls analyze actual source, and HTTP controls determine the findings. `--dir` must be empty; `--model` selects a Muse model ID. Existing active project profiles are reused when `--project` is supplied. `poc start` is the scriptable setup and also supports `--port`; it returns the project root. `poc stop --project <root>` stops the fixture app and preserves evidence.

## engine use <docker|mock> / engine doctor / engine prepare

Select real agents or offline preview. `engine doctor` checks Docker and the shared model profile; `engine prepare` builds the image. All three roles share one model profile. Source excerpts go to that provider. Docker services have no direct network, credentials or repository mounts. No mock fallback occurs on failure.

## probe add <name> / probe list

Configure one exact owner-owned JSON resource for HTTP proof. Options: `--target`, `--path`, `--resource-id`, `--owner`, `--outsider`, `--id-field` (default `id`), `--identity-field` (default `id`). Both selectors support nested fields (`run.id`) and JSON Pointer (`/run/id`). Both identities need an authorized `--check-path` returning distinct account IDs. Credentials stay in environment variables. Up to six probes per target. Reusing a probe name updates that binding. `probe list` shows configured probes.

## demo

Run the complete guided local walkthrough. Press Enter through review, HTTP proof, fix/retest, independent Node export, deliberate regression, and a local scheduler tick. Discovery is simulated; proof and replay are real fixture requests. No model, DNS, or plugin is needed. Creates a fresh isolated fixture, saves evidence, and stops its server on completion or when you leave. `--dir` must name an empty directory. Interactive only; use `demo start` for scripts.

Options: --dir.

## onboard [path]

Application repository and app setup (recommended opening choice), guided local walkthrough, or advanced setup. Requires an interactive terminal. `--flow quickstart`, `--flow advanced`, or `--flow demo` skips the opening choice. Supplying a repository path, `--repo`, or `--project` defaults to QuickStart. Existing settings and evidence are retained. App fields accept bare domains; pending DNS defaults to continuing the review preview. For automation, use `init --non-interactive` and explicit commands below.

Options: --repo, --dir, --flow.

## init [path]

Connect a repository and configure a project.

Options: --repo, --dir, --config, --name.

## repo show

Inspect the connected repository.

## repo connect <path-or-url>

Connect or clone a repository.

Options: --dir, --name.

## status

Show project readiness, results, and next actions.

## doctor

Check Node, Git, Muse, configuration, and worker health.

## config show

Show nonsecret project configuration.

## config set <key> <value>

Set autoSave, requestTimeoutMs, or project.name.

## auth login

Use local mode or launch official Muse account login.

Options: --provider, --device.

## auth status

Show local mode and Muse account integration status.

## auth logout

Clear Bypass-local account metadata; Muse account is separate.

## integrate muse

Reuse an existing valid Muse plugin, including one from another checkout, or install the bundled native plugin if missing. Does not approve capabilities or change the existing installation source. Refresh an existing installation with `muse plugins update bypass`. Native installation failures include their diagnostic reason.

Options: --scope, --install, --replace. `--replace` validates the new bundled plugin, replaces the old source, and attempts restoration if installation fails. Native approval and a new Muse session are still required.

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

Options: --scope-file, --paths, --accept, --production.

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

Options: --provider, --base-url, --model, --secret-env, --allow-private, --effort. Muse effort defaults to minimal; accepts minimal, low, medium, high.

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

Replay saved checks, then run the selected engine. Real mode uses shared-model Docker agents and scoped HTTP controls. Code-only review does not make HTTP requests. Confirmation and failed regressions return exit 1; bounded/no-confirmation and blocked reviews return exit 3. Human-readable output calls a completed mock scan a review preview and explicitly marks the example as unverified. Scripted exit code 3 is retained because mocked discovery provides no real security verdict. Saved-check failures remain visible separately.

Options: --mode, --target, --base, --full, --plan, --detach.

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

Save a regression after a verified fix.

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

Generate a GitHub Actions workflow for exported Node tests.

Options: --provider, --target, --force.

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

## Boolean flags

--json, --help, --version, --non-interactive, --plan, --full, --detach, --all, --force, --accept, --production, --renew, --once, --stop, --device, --install, --replace, --allow-private.

## Exit codes

0: operation succeeded (detached means accepted). 1: confirmed fixture failure or failed regression. 2: usage/configuration error. 3: incomplete, blocked, no checks, or mock analysis without a real verdict. 130: cancelled.

## Account/resource preflight

`~/bypass-for-muse/bypass probe test <name> --project /path/to/app` checks the two signed-in account IDs and owner resource with three authorized GET requests, no model calls. The plugin performs this through `bypass_test_probe`. Status `ready` means those positive controls succeeded; it is not a security verdict. Every combined/live scan repeats this check before AI.

Run status is `failed` for execution errors, `incomplete` for blocked/bounded results with exit 3, `cancelled` for cancellation and `completed` when the requested execution finished with a conclusive behavior result. `run watch` exits for all terminal statuses. `status` and `context` return a compact latest-run summary; `run show <id>` / `bypass_run` returns the detailed evidence.
