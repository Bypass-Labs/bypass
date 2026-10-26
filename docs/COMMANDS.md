# Command reference

Generated from the parser catalog. Add --help to any command. Values are required for flags unless listed as booleans below.

Global: --project <path>, --json, --non-interactive, --help, --version.

## Interactive shortcuts

Run `./bypass --project /path/to/your/app` to open the project screen. Press Enter for the first recommended action. Type `?` to show shortcuts: `review`, `results`, `demo`, `tests`, `app`, `models`, `plugin`, `settings`, `back`, and `q`. These shortcuts belong to the interactive screen; shell commands use the catalog below. `help all` shows the complete catalog inside the screen.

## demo

Run the complete guided local walkthrough. Press Enter through review, HTTP proof, fix/retest, independent Node export, deliberate regression, and a local scheduler tick. Discovery is simulated; proof and replay are real fixture requests. No model, DNS, or plugin is needed. Creates a fresh isolated fixture, saves evidence, and stops its server on completion or when you leave. `--dir` must name an empty directory. Interactive only; use `demo start` for scripts.

Options: --dir.

## onboard [path]

Guided local walkthrough (recommended opening choice), repository setup, or advanced setup. Requires an interactive terminal. `--flow quickstart`, `--flow advanced`, or `--flow demo` skips the opening choice. Supplying a repository path, `--repo`, or `--project` defaults to QuickStart. Existing settings and evidence are retained. App fields accept bare domains; pending DNS defaults to continuing the review preview. For automation, use `init --non-interactive` and explicit commands below.

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

Options: --scope, --install.

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

Options: --provider, --base-url, --model, --secret-env, --allow-private.

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

Replay saved checks, then run simulated analysis. Human-readable output calls a completed mock scan a review preview and explicitly marks the example as unverified. Scripted exit code 3 is retained because mocked discovery provides no real security verdict. Saved-check failures remain visible separately.

Options: --mode, --target, --base, --full, --plan, --detach.

## finding list

List findings, with simulation and evidence labels.

Options: --target, --run, --status, --severity.

## finding show <id>

Show evidence, history, and remediation context.

## verify <finding-id>

Verify a fixture candidate; deployed-app engine remains mocked.

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

Save a regression after a verified fixture fix.

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

Show history and monitor results for the next coding session.

Options: --finding.

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

--json, --help, --version, --non-interactive, --plan, --full, --detach, --all, --force, --accept, --production, --renew, --once, --stop, --device, --install, --allow-private.

## Exit codes

0: operation succeeded (detached means accepted). 1: confirmed fixture failure or failed regression. 2: usage/configuration error. 3: incomplete, blocked, no checks, or mock analysis without a real verdict. 130: cancelled.
