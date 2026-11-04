# Exact CLI command reference

This file is generated from the parser catalog, so every public command and accepted option is listed exactly as the installed CLI parses it. Use [COMMANDS.md](COMMANDS.md) for workflow explanations and `bypass <command> --help` for terminal help. Regenerate intentionally with `node scripts/check-cli-reference.mjs --write`.

Global options: `--project <value>`, `--json`, `--help`, `--version`, `--non-interactive`, `--reference`.

## `bypass blackbox <url>`

Run a scoped black-box audit and save evidence under .bypass/runs/.

Options: `--scope <value>`, `--include <value>`, `--domains <value>`, `--audit-domains <value>`, `--owner-env <value>`, `--other-env <value>`, `--auth <value>`, `--identity-path <value>`, `--model <value>`, `--agents <value>`, `--http-workers <value>`, `--rps <value>`, `--model-calls <value>`, `--max-urls <value>`, `--max-tasks <value>`, `--minutes <value>`, `--dom-script-bytes <value>`, `--out <value>`, `--source <value>`, `--finding <value>`, `--focus-path <value>`, `--revision-path <value>`, `--revision-field <value>`, `--accept-local`, `--no-model`, `--dry-run`, `--no-discovery`, `--offline`

## `bypass blackbox scope <url>`

Write a reviewable blackbox.scope.json.

Options: `--include <value>`, `--methods <value>`, `--domains <value>`, `--audit-domains <value>`, `--credential-origins <value>`, `--never <value>`, `--owner-env <value>`, `--other-env <value>`, `--auth <value>`, `--identity-path <value>`, `--identity-cookie-name <value>`, `--environment <value>`, `--agents <value>`, `--http-workers <value>`, `--rps <value>`, `--model-calls <value>`, `--max-urls <value>`, `--max-tasks <value>`, `--minutes <value>`, `--dom-script-bytes <value>`, `--out <value>`, `--force`

## `bypass blackbox setup <url>`

Prepare scope and authorization; --plan previews the approval picker without changes.

Options: `--plan`, `--include <value>`, `--methods <value>`, `--domains <value>`, `--audit-domains <value>`, `--credential-origins <value>`, `--never <value>`, `--owner-env <value>`, `--other-env <value>`, `--auth <value>`, `--identity-path <value>`, `--identity-cookie-name <value>`, `--environment <value>`, `--agents <value>`, `--http-workers <value>`, `--rps <value>`, `--model-calls <value>`, `--max-urls <value>`, `--max-tasks <value>`, `--minutes <value>`, `--dom-script-bytes <value>`, `--out <value>`, `--force`

## `bypass blackbox verify <run-id>`

Re-execute generated proofs and check ledger integrity.

Options: None.

## `bypass blackbox export <run-id>`

Write Node regression tests for confirmed findings.

Options: `--out <value>`

## `bypass blackbox resume <run-id>`

Continue saved Muse research in a fresh scoped audit.

Options: `--scope <value>`, `--model <value>`, `--offline`, `--agents <value>`, `--http-workers <value>`, `--rps <value>`, `--model-calls <value>`, `--max-urls <value>`, `--max-tasks <value>`, `--minutes <value>`, `--dom-script-bytes <value>`

## `bypass discover`

Discover SAST/policy signals and evaluate them against source by default.

Options: `--detector <value>`, `--languages <value>`, `--rule <value>`, `--exclude-rule <value>`, `--policy <value>`, `--exclude-policy <value>`, `--include-tests`, `--include-examples`, `--include-generated`, `--sarif <value>`, `--config <value>`, `--plan`, `--discovery-only`

## `bypass discover evaluate <run>`

Evaluate saved detector signals against their source snapshot; no runtime reproduction.

Options: None.

## `bypass discover status <run>`

Read durable SAST/policy progress and coverage.

Options: None.

## `bypass discover resume <run>`

Resume discovery/evaluation after identity checks; standalone reasoning requires an API profile.

Options: None.

## `bypass discover cancel <run>`

Cancel discovery and retain accepted artifacts.

Options: None.

## `bypass discover report <run>`

Write a discovery report and return its artifact reference.

Options: `--format <value>`

## `bypass discover signals <run>`

Read a bounded page of unevaluated SAST/policy signals.

Options: `--cursor <value>`, `--limit <value>`

## `bypass discover artifact <run>`

Read a bounded page of a recorded discovery artifact.

Options: `--path <value>`, `--offset <value>`

## `bypass scanner rules`

Browse exact rule IDs from the pinned upstream packs.

Options: `--language <value>`, `--query <value>`, `--cursor <value>`, `--limit <value>`

## `bypass scanner policies`

List exact bundled policy IDs without Docker or inference.

Options: `--query <value>`

## `bypass scanner doctor`

Inspect the selected detector runtime and image readiness; no inference.

Options: `--detector <value>`

## `bypass scanner prepare`

Prepare the lightweight policy or pinned SAST runtime.

Options: `--detector <value>`

## `bypass poc`

Open an isolated two-container security POC with a local test app.

Options: `--dir <value>`, `--model <value>`

## `bypass poc start`

Create a separate POC app with public accounts and containerized audit workers.

Options: `--dir <value>`, `--port <value>`, `--model <value>`

## `bypass poc resume`

Restart the saved generated local fixture; preserve findings and tests.

Options: None.

## `bypass poc stop`

Stop this POC fixture app; preserve its evidence.

Options: None.

## `bypass demo`

Guided local walkthrough: prove, fix, retest, and catch a regression.

Options: `--dir <value>`

## `bypass onboard [path]`

Guided QuickStart, resumable app verification, or local demo.

Options: `--repo <value>`, `--dir <value>`, `--flow <value>`, `--mode <value>`

## `bypass init [path]`

Connect a repository and configure a project.

Options: `--repo <value>`, `--dir <value>`, `--config <value>`, `--name <value>`, `--plan`, `--tracked-files <value>`

## `bypass app connect <url>`

Connect a running app without a source repository.

Options: `--environment <value>`

## `bypass repo show`

Inspect the connected repository.

Options: None.

## `bypass repo connect <path-or-url>`

Connect or clone a repository.

Options: `--dir <value>`, `--name <value>`, `--plan`, `--tracked-files <value>`

## `bypass status`

Show project readiness, results, and next actions.

Options: None.

## `bypass doctor`

Check Node, Git, Muse, configuration, and worker health.

Options: None.

## `bypass config show`

Show nonsecret project configuration.

Options: None.

## `bypass config set <key> <value>`

Set project settings, including ownershipVerification (off, dns, http).

Options: None.

## `bypass auth login`

Explain the supported authentication path: an API key in standalone mode or the official Muse login flow.

Options: `--provider <value>`, `--device`

## `bypass auth status`

Show whether authentication is owned by the standalone API profile or the active Muse session.

Options: None.

## `bypass auth logout`

Clear legacy Bypass-local account metadata; this does not sign out of Muse.

Options: None.

## `bypass integrate muse`

Reuse an existing Muse plugin or install the bundled plugin.

Options: `--scope <value>`, `--replace`

## `bypass integrate status`

Inspect the Muse plugin installation.

Options: None.

## `bypass integrate remove <muse>`

Remove the native Muse plugin.

Options: None.

## `bypass target add <name>`

Add a local or HTTPS deployed target.

Options: `--url <value>`, `--environment <value>`

## `bypass target list`

List targets and ownership state.

Options: None.

## `bypass target show [name]`

Show target, challenge, and scope.

Options: None.

## `bypass target use <name>`

Select an active target.

Options: None.

## `bypass target verify [name]`

Check DNS/HTTP control, or acknowledge local ownership.

Options: `--method <value>`, `--wait <value>`, `--renew`

## `bypass target authorize [name]`

Record explicit paths, HTTP methods and expiring testing scope.

Options: `--scope-file <value>`, `--paths <value>`, `--methods <value>`, `--rps <value>`, `--accept`, `--production`, `--public-config`

## `bypass request`

Send one scoped HTTP request; record status and an optional resource ID without replaying writes.

Options: `--target <value>`, `--method <value>`, `--path <value>`, `--identity <value>`, `--body-file <value>`, `--id-field <value>`

## `bypass target revoke <name>`

Revoke testing and pause target monitors.

Options: None.

## `bypass target remove <name>`

Disconnect a target while retaining historical evidence.

Options: None.

## `bypass identity add <name>`

Reference a bearer token, cookie, or header in an environment variable.

Options: `--target <value>`, `--type <value>`, `--secret-env <value>`, `--header <value>`, `--check-path <value>`

## `bypass identity import <name>`

Connect a test account from a private file, available immediately. Firebase refreshes automatically.

Options: `--file <value>`, `--token-field <value>`, `--provider <value>`, `--refresh-token-field <value>`, `--config-file <value>`, `--api-key-field <value>`, `--project-id <value>`, `--target <value>`, `--type <value>`, `--secret-env <value>`, `--header <value>`, `--check-path <value>`

## `bypass identity refresh <name>`

Refresh a privately connected Firebase account without restarting.

Options: None.

## `bypass identity list`

List credential references, never values.

Options: `--target <value>`

## `bypass identity test <name>`

Make one authorized request to the configured identity-check path.

Options: None.

## `bypass identity update <name>`

Update a credential reference.

Options: `--secret-env <value>`, `--check-path <value>`

## `bypass identity remove <name>`

Remove an identity reference; dependent tests become blocked.

Options: None.

## `bypass model add <name>`

Add a standalone API-key provider profile.

Options: `--provider <value>`, `--base-url <value>`, `--model <value>`, `--secret-env <value>`, `--allow-private`, `--effort <value>`, `--transport <value>`, `--max-output-tokens <value>`, `--timeout-ms <value>`, `--stream <value>`, `--workspace-env <value>`

## `bypass model list`

List model profiles and inference destinations.

Options: None.

## `bypass model use <name>`

Select the model profile.

Options: None.

## `bypass model test [name]`

Send a synthetic smoke prompt, without repository content.

Options: None.

## `bypass model remove <name>`

Remove a model profile.

Options: None.

## `bypass engine use <docker|mock>`

Select the containerized security audit or offline mocked preview.

Options: None.

## `bypass engine doctor`

Check Docker and the shared inference profile.

Options: None.

## `bypass engine prepare`

Build the isolated source-review worker image.

Options: None.

## `bypass registration discover`

Find public Firebase config in authorized app pages and linked scripts. No accounts created.

Options: `--target <value>`, `--path <value>`, `--project-id <value>`

## `bypass registration choose`

Save the test-account choice: create, existing or skip. Creating accounts requires explicit permission.

Options: `--target <value>`, `--mode <value>`, `--accept`, `--email-domain <value>`

## `bypass registration configure`

Authorize up to two dedicated JSON signup attempts on the verified app.

Options: `--target <value>`, `--provider <value>`, `--config-file <value>`, `--api-key-field <value>`, `--project-id <value>`, `--path <value>`, `--check-path <value>`, `--access-path <value>`, `--email-domain <value>`, `--email-field <value>`, `--password-field <value>`, `--token-field <value>`, `--verified-field <value>`, `--identity-field <value>`, `--require-verification`, `--accept`

## `bypass registration test`

Attempt signup, privately connect generated accounts and check unverified access.

Options: `--target <value>`

## `bypass registration status`

Show registration coverage and created account cleanup information.

Options: `--target <value>`

## `bypass probe add <name>`

Configure an exact authorized JSON resource and account controls.

Options: `--target <value>`, `--path <value>`, `--resource-id <value>`, `--owner <value>`, `--outsider <value>`, `--id-field <value>`, `--identity-field <value>`, `--kind <value>`, `--response <value>`, `--match-text <value>`, `--expected <value>`

## `bypass probe discover`

Select owned test IDs from an authorized JSON collection without exposing contents.

Options: `--target <value>`, `--path <value>`, `--resource-prefix <value>`, `--items-field <value>`, `--owner-field <value>`, `--id-field <value>`, `--resource-id-field <value>`, `--identity-field <value>`, `--owner <value>`, `--outsider <value>`

## `bypass probe test <name>`

Validate both logins and the exact owner resource with three GET requests; zero model calls.

Options: `--target <value>`

## `bypass probe list`

List approved resources for live agent probes.

Options: `--target <value>`

## `bypass scan`

Run code, live, or combined security auditing through the canonical engines.

Options: `--mode <value>`, `--target <value>`, `--base <value>`, `--full`, `--plan`, `--detach`, `--agents <value>`, `--http-workers <value>`, `--model-calls <value>`, `--max-urls <value>`, `--max-tasks <value>`, `--minutes <value>`

## `bypass finding list`

List findings, with simulation and evidence labels.

Options: `--target <value>`, `--run <value>`, `--status <value>`, `--severity <value>`

## `bypass finding show <id>`

Show evidence, history, and remediation context.

Options: None.

## `bypass verify <finding-id>`

Reproduce a finding using its scoped HTTP controls.

Options: `--target <value>`

## `bypass retest <finding-id>`

Check a deployed fix and save a standalone regression.

Options: `--target <value>`, `--build <value>`

## `bypass test list`

List saved regression checks.

Options: `--target <value>`

## `bypass test show <id>`

Show a check and environment bindings.

Options: None.

## `bypass test save <finding-id>`

Save a portable check or export a confirmed black-box proof as a standalone regression.

Options: `--out <value>`

## `bypass test run [id]`

Replay deterministic checks with zero model calls.

Options: `--all`, `--target <value>`, `--detach`

## `bypass test bind [id]`

Bind a saved check to an authorized environment.

Options: `--all`, `--target <value>`, `--file <value>`

## `bypass test export [id]`

Write ordinary Node tests with no Bypass dependency.

Options: `--all`, `--target <value>`, `--out <value>`, `--force`

## `bypass test disable <id>`

Disable a saved check with an audit reason.

Options: `--reason <value>`

## `bypass test enable <id>`

Enable a saved check.

Options: None.

## `bypass coverage`

Show assessment work remaining, source ranges, actual controls and specific blockers.

Options: `--run <value>`, `--target <value>`

## `bypass context`

Get security context for feature work, or general session history.

Options: `--finding <value>`, `--task <value>`, `--files <value>`, `--target <value>`

## `bypass memory`

Inspect local security memory and its evidence.

Options: `--query <value>`, `--target <value>`

## `bypass memory list`

Inspect or search security memory.

Options: `--query <value>`, `--target <value>`

## `bypass memory show <id>`

Read one memory record and its provenance.

Options: None.

## `bypass memory forget <id>`

Forget a memory record; retain original audit evidence.

Options: None.

## `bypass memory use <on|off>`

Enable or disable memory recording and agent retrieval.

Options: None.

## `bypass report`

Export a run as JSON or Markdown.

Options: `--run <value>`, `--format <value>`, `--out <value>`

## `bypass run list`

List durable runs.

Options: None.

## `bypass run show <id>`

Inspect one run.

Options: None.

## `bypass run watch <id>`

Wait for completion and return the final exit code.

Options: `--timeout <value>`

## `bypass run stop <id>`

Request cancellation of a running worker.

Options: None.

## `bypass monitor add <name>`

Schedule saved regression replay.

Options: `--target <value>`, `--every <value>`, `--runner <value>`

## `bypass monitor list`

Show schedules and local worker health.

Options: None.

## `bypass monitor run <name>`

Run a schedule immediately.

Options: None.

## `bypass monitor pause <name>`

Pause a monitor.

Options: None.

## `bypass monitor resume <name>`

Resume a monitor.

Options: None.

## `bypass monitor remove <name>`

Remove a monitor; retain run evidence.

Options: None.

## `bypass monitor worker`

Run the real local scheduler (machine must remain awake).

Options: `--detach`, `--once`, `--stop`

## `bypass ci init`

Generate GitHub saved checks, or a Meta API security agent with --agent.

Options: `--provider <value>`, `--target <value>`, `--force`, `--agent`, `--action-ref <value>`, `--every <value>`, `--revision-path <value>`, `--revision-field <value>`

## `bypass mcp serve`

Start the typed stdio MCP server.

Options: None.

## `bypass demo start`

Create the Ledger Git fixture and start its HTTP server.

Options: `--dir <value>`, `--port <value>`

## `bypass demo status`

Show the fixture state.

Options: None.

## `bypass demo fix`

Enable ownership enforcement in the local fixture.

Options: None.

## `bypass demo regress`

Reintroduce the local fixture defect.

Options: None.

## `bypass demo add-route`

Add an uncovered export route to the fixture.

Options: None.

## `bypass demo reset`

Reset fixture behavior while retaining evidence.

Options: None.

## `bypass demo stop`

Stop the local fixture server.

Options: None.
## Exit codes

- `0`: operation succeeded.
- `1`: a confirmed finding or failed regression was produced.
- `2`: command usage or configuration is invalid.
- `3`: the operation is incomplete, blocked, or has no conclusive result.
- `130`: cancelled.
