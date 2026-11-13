# Muse plugin capability reference

The Muse plugin is the primary experience. Use ordinary requests or its slash commands; Muse calls these tools for you. You do not need to learn MCP syntax or leave Muse for project operations.

Standalone model setup has a deliberate mode boundary: plugin model tools explain host ownership and cannot configure or invoke API inference. This reference is generated from the CLI catalog and plugin definitions. CI checks all 100 public CLI commands and their options; there are 114 typed tools. Regenerate with `node scripts/check-plugin-parity.mjs --write` after intentionally changing the catalog.

## Start inside Muse

Use /bypass:blackbox to audit an authorized running app through the active Muse session, then replay proofs and export regressions. The same approval picker shows the selected app and saved/proposed scope: Approve, Decline, or Custom instructions. Advanced limits are optional. Domain proof appears only when required by project settings; existing scope is never silently expanded.

The start wizard collects remote environment when needed, duration (10, 30 or 60 minutes), and Entire app or Customize in one native question form, then shows one exact scope approval. Entire app proposes `/`, all supported HTTP methods and 20 RPS. The ten-minute option is a quick test with partial coverage. After Muse finishes cited source review, it starts one full live audit with the source run ID in the review argument to bypass_blackbox_start; live-only routes are tested too. Code only ends after source work, while Running app only starts the full live audit without a source run. Progress summaries count currently planned checks and elapsed work; they do not claim security coverage. Muse loads each Bypass tool by its current-session ID before calling it; a logical nextAction.tool value is not an executable MCP ID.

- `/bypass:start`: reuse your repository and active Muse reasoning, and finish missing app and scope setup; accounts are optional.
- `/bypass:demo`: a real local Muse-directed demonstration, through proof, fixture fix, saved test, deliberate regression, one monitor tick and security context. Ask for an offline preview explicitly to use seeded discovery.
- `/bypass:status`: Done / Now / Next, progress, evidence and actual worker health.
- `/bypass:review`, `/bypass:tests`, `/bypass:monitor`, `/bypass:build`, `/bypass:context`, `/bypass:help`: the remaining workflows.

## Shared behavior and deliberate UI differences

The plugin calls the same application services and reads/writes the same project state as the CLI. An initialized application workspace is reused; other repository selection is explicit. Host reviews use durable read/source/probe/finish steps directed by Muse. Short deterministic replays return completed controls directly; pending runs use bounded progress calls. Monitor workers run detached, or for one tick. Demo creation selects a separate fixture, and stopping it restores the prior application selection while retaining evidence.

An observed vulnerability or failed regression retains CLI exit code 1 but is a successful MCP operation with a security result. Execution errors, blocked requests and incomplete reviews stay explicit. A configured model, accepted job or saved monitor schedule is never shown as a successful review or running monitor.

Muse owns interactive sign-in, plugin capability approval and session restart. Bypass provides an explicit handoff for official login instead of collecting credentials or claiming sign-in succeeded. The already-approved MCP server is started by Muse, so `mcp serve` is transport lifecycle. For optional test accounts, Muse can perform authorized bounded JSON/Firebase registration or import an existing private account file through `bypass_import_identity`; Firebase tokens refresh automatically without environment exports or session restarts. DNS publication and initial app sign-in may need user access; reuse authorized host integrations where available. Installation/update/removal tools require an explicit user request and do not approve themselves.

CLI global `--project` maps to the selected repository; `--json` maps to structured tool results; `--help`/`--version` map to the guide and runtime identity. Terminal rendering/keyboard flags are represented by the conversational UI. Output paths stay in the selected repository and may not traverse symlinks.

## Complete operation mapping

| CLI command | Muse tool | Behavior |
| --- | --- | --- |
| `blackbox` | `bypass_blackbox_start` | Run a scoped black-box audit and save evidence under .bypass/runs/. |
| `blackbox scope` | `bypass_blackbox_scope` | Write a reviewable blackbox.scope.json. |
| `blackbox setup` | `bypass_blackbox_setup` | Prepare scope and authorization; --plan previews the approval picker without changes. |
| `blackbox verify` | `bypass_blackbox_verify` | Re-execute generated proofs and check ledger integrity. |
| `blackbox export` | `bypass_blackbox_export` | Write Node regression tests for confirmed findings. |
| `blackbox resume` | `bypass_blackbox_resume` | Continue saved Muse research in a fresh scoped audit. |
| `discover` | `bypass_discover` | Discover SAST/policy signals and evaluate them against source by default. |
| `discover evaluate` | `bypass_discover_evaluate` | Evaluate saved detector signals against their source snapshot; no runtime reproduction. |
| `discover status` | `bypass_discover_status` | Read durable SAST/policy progress and coverage. |
| `discover resume` | `bypass_discover_resume` | Resume discovery/evaluation after identity checks; standalone reasoning requires an API profile. |
| `discover cancel` | `bypass_discover_cancel` | Cancel discovery and retain accepted artifacts. |
| `discover report` | `bypass_discover_report` | Write a discovery report and return its artifact reference. |
| `discover signals` | `bypass_discover_signals` | Read a bounded page of unevaluated SAST/policy signals. |
| `discover artifact` | `bypass_discover_artifact` | Read a bounded page of a recorded discovery artifact. |
| `scanner rules` | `bypass_scanner_rules` | Browse exact rule IDs from the pinned upstream packs. |
| `scanner policies` | `bypass_scanner_policies` | List exact bundled policy IDs without Docker or inference. |
| `scanner doctor` | `bypass_scanner_doctor` | Inspect the selected detector runtime and image readiness; no inference. |
| `scanner prepare` | `bypass_scanner_prepare` | Prepare the lightweight policy or pinned SAST runtime. |
| `onboard` | `bypass_onboarding` | Conversational checklist, with bypass_connect_repository for repository and config input. |
| `init` | `bypass_connect_repository` | Connect a repository and configure a project. |
| `app connect` | `bypass_connect_app` | Connect a running app without a source repository. |
| `repo show` | `bypass_repository` | Inspect the connected repository. |
| `repo connect` | `bypass_connect_repository` | Connect or clone a repository. |
| `status` | `bypass_status` | Show project readiness, results, and next actions. |
| `doctor` | `bypass_doctor` | Check Node, Git, Muse, configuration, and worker health. |
| `config show` | `bypass_config` | Show nonsecret project configuration. |
| `config set` | `bypass_set_config` | Set project settings, including ownershipVerification (off, dns, http). |
| `auth login` | `bypass_auth_login` | Explain the supported authentication path: an API key in standalone mode or the official Muse login flow. |
| `auth status` | `bypass_auth_status` | Show whether authentication is owned by the standalone API profile or the active Muse session. |
| `auth logout` | `bypass_auth_logout` | Clear legacy Bypass-local account metadata; this does not sign out of Muse. |
| `integrate muse` | `bypass_install_plugin` | Reuse an existing Muse plugin or install the bundled plugin. |
| `integrate status` | `bypass_integration_status` | Inspect the Muse plugin installation. |
| `integrate remove` | `bypass_remove_plugin` | Remove the native Muse plugin. |
| `target add` | `bypass_add_target` | Add a local or HTTPS deployed target. |
| `target list` | `bypass_targets` | List targets and ownership state. |
| `target show` | `bypass_target` | Show target, challenge, and scope. |
| `target use` | `bypass_use_target` | Select an active target. |
| `target verify` | `bypass_verify_target` | Check DNS/HTTP control, or acknowledge local ownership. |
| `target authorize` | `bypass_authorize_target` | Record explicit paths, HTTP methods and expiring testing scope. |
| `request` | `bypass_request` | Send one scoped HTTP request; record status and an optional resource ID without replaying writes. |
| `target revoke` | `bypass_revoke_target` | Revoke testing and pause target monitors. |
| `target remove` | `bypass_remove_target` | Disconnect a target while retaining historical evidence. |
| `identity add` | `bypass_add_identity` | Reference a bearer token, cookie, or header in an environment variable. |
| `identity import` | `bypass_import_identity` | Connect a test account from a private file, available immediately. Firebase refreshes automatically. |
| `identity refresh` | `bypass_refresh_identity` | Refresh a privately connected Firebase account without restarting. |
| `identity list` | `bypass_identities` | List credential references, never values. |
| `identity test` | `bypass_test_identity` | Make one authorized request to the configured identity-check path. |
| `identity update` | `bypass_update_identity` | Update a credential reference. |
| `identity remove` | `bypass_remove_identity` | Remove an identity reference; dependent tests become blocked. |
| `model add` | `bypass_add_model` | Explains host-owned reasoning; cannot configure API inference inside Muse. API profiles are standalone-only. |
| `model list` | `bypass_models` | Inspect saved standalone profiles; these are not used for plugin reasoning. |
| `model use` | `bypass_use_model` | Explains host-owned reasoning; choose the active Muse model through host settings. |
| `model test` | `bypass_test_model` | Explains host-owned reasoning without sending an independent model request. |
| `model remove` | `bypass_remove_model` | Remove a model profile. |
| `engine use` | `bypass_engine` | Set the standalone engine preference. Real plugin reviews remain Muse-directed. |
| `engine doctor` | `bypass_engine_doctor` | Explain native host execution; no Docker or API profile is needed in Muse. |
| `engine prepare` | `bypass_prepare_engine` | Optional preparation of standalone Docker workers; unnecessary for native plugin reviews. |
| `registration discover` | `bypass_discover_registration` | Find public Firebase config in authorized app pages and linked scripts. No accounts created. |
| `registration choose` | `bypass_choose_accounts` | Save the test-account choice: create, existing or skip. Creating accounts requires explicit permission. |
| `registration configure` | `bypass_configure_registration` | Authorize up to two dedicated JSON signup attempts on the verified app. |
| `registration test` | `bypass_test_registration` | Attempt signup, privately connect generated accounts and check unverified access. |
| `registration status` | `bypass_registration` | Show registration coverage and created account cleanup information. |
| `probe add` | `bypass_add_probe` | Configure an exact authorized JSON resource and account controls. |
| `probe discover` | `bypass_discover_resources` | Select owned test IDs from an authorized JSON collection without exposing contents. |
| `probe test` | `bypass_test_probe` | Validate both logins and the exact owner resource with three GET requests; zero model calls. |
| `probe list` | `bypass_probes` | List approved resources for live agent probes. |
| `scan` | `bypass_scan` | Prepare a durable host source review. In combined mode, Muse then starts one full live audit with cited leads and the remaining budget. |
| `finding list` | `bypass_findings` | List findings, with simulation and evidence labels. |
| `finding show` | `bypass_finding` | Show evidence, history, and remediation context. |
| `verify` | `bypass_verify` | Reproduce a finding using its scoped HTTP controls. |
| `retest` | `bypass_retest` | Check a deployed fix and save a standalone regression. |
| `test list` | `bypass_tests` | List saved regression checks. |
| `test show` | `bypass_test` | Show a check and environment bindings. |
| `test save` | `bypass_save_test` | Save a portable check or export a confirmed black-box proof as a standalone regression. |
| `test run` | `bypass_run_tests` | Replay deterministic checks with zero model calls. |
| `test bind` | `bypass_bind_tests` | Bind a saved check to an authorized environment. |
| `test export` | `bypass_export_tests` | Write ordinary Node tests with no Bypass dependency. |
| `test disable` | `bypass_disable_test` | Disable a saved check with an audit reason. |
| `test enable` | `bypass_enable_test` | Enable a saved check. |
| `coverage` | `bypass_coverage` | Show assessment work remaining, source ranges, actual controls and specific blockers. |
| `context` | `bypass_feature_context` | Get security context for feature work, or general session history. |
| `memory` | `bypass_memory` | Inspect local security memory and its evidence. |
| `memory list` | `bypass_memory` | Inspect or search security memory. |
| `memory show` | `bypass_memory_record` | Read one memory record and its provenance. |
| `memory forget` | `bypass_forget_memory` | Forget a memory record; retain original audit evidence. |
| `memory use` | `bypass_memory_mode` | Enable or disable memory recording and agent retrieval. |
| `report` | `bypass_report` | Export a run as JSON or Markdown. |
| `run list` | `bypass_runs` | List durable runs. |
| `run show` | `bypass_run` | Inspect one run. |
| `run watch` | `bypass_watch_run` | Bounded progress for deterministic replay. For awaiting_host reviews use bypass_review_step status, then let Muse continue. |
| `run stop` | `bypass_stop_run` | Request cancellation of a running worker. |
| `monitor add` | `bypass_add_monitor` | Schedule saved regression replay. |
| `monitor list` | `bypass_monitors` | Show schedules and local worker health. |
| `monitor run` | `bypass_run_monitor` | Run a schedule immediately. |
| `monitor pause` | `bypass_pause_monitor` | Pause a monitor. |
| `monitor resume` | `bypass_resume_monitor` | Resume a monitor. |
| `monitor remove` | `bypass_remove_monitor` | Remove a monitor; retain run evidence. |
| `monitor worker` | `bypass_monitor_worker` | Run the real local scheduler (machine must remain awake). |
| `ci init` | `bypass_ci` | Generate GitHub saved checks, or a Meta API security agent with --agent. |
| `mcp serve` | Muse starts the approved server | Muse starts this already-approved server. Starting a second stdio server is a transport action, not an application operation. |

Use `bypass_help` with a query for live option discovery. Tool schemas include the corresponding CLI options; presentation aliases above explain intentional differences. Source hypotheses, fixture proof, real HTTP evidence and historical results keep their original labels in both interfaces.
