# Bypass for Muse Code

**Bypass helps teams building with coding agents find real vulnerabilities, verify their fixes, and turn those findings into reusable security tests. As the application grows, its security checks grow with it. The initial experience lives inside Muse, with a standalone CLI and MCP interface. Bypass reviews code changes, tests suspected vulnerabilities against the running application, and brings verified findings back into the developer’s workflow.**

[Quick start](#start-in-muse-code) · [White-box](#white-box-source-review) · [Black-box](#black-box-audit) · [CLI](#standalone-cli) · [GitHub agent](#github-security-agent) · [Docs](#documentation)

## Choose your experience

| Experience | What you need | Install |
| --- | --- | --- |
| **Standalone CLI** | A Meta Model API key, or a local server running Muse Spark Open or Muse Glimmer. Muse Code is not required. | `curl -fsSL https://bypasslabs.ai/install \| bash` |
| **Muse Code plugin** | Muse Code installed, opened, and signed in first. | `curl -fsSL https://bypasslabs.ai/install/muse \| bash` |

Windows uses the matching `install.ps1` or `install/muse.ps1` URL. The standalone wizard connects Meta Model API authentication and a Muse model before it asks for your application.

## Overview

Bypass is a native plugin for **[Muse Code](https://dev.meta.ai/docs/muse-code)**, Meta's coding agent. It adds security skills, slash commands, MCP tools, and saved security context to your existing coding session. Muse Code investigates and explains; Bypass runs scoped operations and keeps the evidence.

Start with the Muse Code plugin. A **standalone CLI** is also available for terminal workflows, and the GitHub integration brings reviews and saved checks into CI. Assessments report findings, recommend fixes, and create supported regression tests; editing application code requires a separate request.

### Key benefits

- **Work inside Muse Code.** Use your active Muse Code account and model, with no separate API key for plugin reasoning.
- **Inspect code and test behavior.** Choose CodeQL SAST, AI policy discovery, or both; investigate source evidence and use black-box testing to validate supported vulnerabilities against a running app.
- **Keep the test.** Replay saved HTTP proofs after a fix and export supported checks to Node tests. Regression replay needs no model calls.
- **Carry security context into feature work.** Retrieve past findings, source citations, and saved behavior requirements with `/bypass:build`. Changed source marks knowledge stale.
- **Choose where inference runs.** Standalone AI reviews support provider APIs and API-key-protected local or self-hosted compatible endpoints. Evidence is saved locally; selected source and observations are available to the model you choose.
- **Bring checks into GitHub.** Review PR source, verify saved checks after deployment, and schedule daily regression replay.

## Use cases

- **Before shipping:** scan a repository and investigate authentication, access-control, and other source concerns.
- **Against a running app:** discover exposed routes and test supported vulnerability classes within an approved scope.
- **After a fix or deployment:** replay the same security behavior and retain the result for future development.

<a id="start-in-muse"></a>

## Start in Muse Code

**Requires Muse Code installed, opened, and signed in first.** Install Muse Code from [Meta's official guide](https://dev.meta.ai/docs/muse-code), then run the Bypass plugin installer. You can select your application during setup; you do not need to start in its folder.

<a id="docker-prerequisite"></a>

**Prerequisite for SAST/policy discovery: a running Docker daemon.** The CodeQL/policy scanner runs inside a container, so `/bypass:discover`, `bypass discover`, `bypass scanner doctor`, standalone policy discovery, and standalone Docker-engine source review need Docker installed **and running** before the scan starts. Running-app testing, saved regression replay, discovery plans (`--plan`), and policy listing need no Docker. Bypass never auto-starts a Docker VM; when the daemon is unreachable, `scanner doctor` now reports why (`cli-missing`, `daemon-stopped`, `wrong-context`, or `daemon-unreachable`) with the exact commands to run.

On macOS, the `docker` CLI alone is not enough — a Linux VM provides the daemon. With Colima (Homebrew):

```bash
brew install colima docker
colima start                 # or: colima start <profile>
docker context use colima    # named profile: docker context use colima-<profile>
docker version               # must print a Server version
```

Docker Desktop also works: install it, open it, and wait until it reports running. On Linux, start Docker Engine (for example `sudo systemctl start docker`). Keep several GB of free disk for the first scanner image build. If `docker version` prints only client info, check `docker context ls` and `colima list` before retrying; a stopped profile or a context pointed at a missing socket blocks the scan even though Docker is "installed".

**1. Install the plugin.**

macOS / Linux:

```bash
curl -fsSL https://bypasslabs.ai/install/muse | bash
```

Windows PowerShell:

```powershell
irm https://bypasslabs.ai/install/muse.ps1 | iex
```

**2. Choose the option to enable Bypass's permissions and open Muse Code (`1` or `y`).**

The installer explains the security-tools and security-memory permissions, registers the plugin, and opens Muse Code with setup started. It includes the runtime and CLI; no GitHub clone, npm, or separate model key is needed. Docker is needed for SAST/policy discovery and standalone Docker review.

**3. Tell Muse Code what to review.** For example:

```text
Review the source at https://github.com/YOUR-ORG/YOUR-APP.
Use code-only mode. Report findings with file/line evidence and fix
recommendations. Do not edit application code.
```

Setup offers **Code only**, **Code + running app**, or **Running app only**. Supply a local source folder or Git URL for code; supply an app URL for live testing. To return later, use `/bypass:start`.

For a running app, supply its URL and choose its environment if unknown. Bypass shows one compact testing plan with **Approve**, **Decline**, and **Custom instructions**. Approve confirms that you control the app and authorize the displayed paths, methods, request rate and expiry. The audit then starts immediately with that exact plan and shows live progress; there is no second scope questionnaire or start confirmation. Custom instructions lets you change the plan before approval. Accounts are optional for anonymous checks; authenticated checks need usable test identities.

<details>
<summary>Project setting: domain ownership verification</summary>

Domain verification is **off** unless a project explicitly enables it. Explicit app-control and scope approval is still required. To require proof, tell Muse Code “Require DNS ownership verification for this project” or “Use HTTPS-file verification.” Bypass updates the project setting and shows only the required extra step. In the CLI, use **Settings → Domain ownership verification**, or:

```bash
bypass config set ownershipVerification dns   # off | dns | http
```

Changing the setting clears saved testing permission so the next run can review it again. Existing projects retain their verification requirements; valid DNS/HTTPS proof is reused for the same origin. An acknowledgment is recorded as operator authorization, never verified ownership. Apex-domain expansion and GitHub live automation still require DNS proof.

</details>

**Choose the next command in Muse Code:** `/bypass:discover` for SAST, policy discovery, or both, `/bypass:review` for Muse Code-assisted source review, or `/bypass:blackbox` for running-app discovery. See the examples below.

<details>
<summary>Updating, permissions, and model privacy</summary>

Rerun the installer to update or repair, then start a **new Muse Code session**. An open session keeps its loaded package. `muse plugins update bypass` only refreshes the recorded local source and may not download a newer public release.

If permissions remain pending, open `/plugins` → **Installed → Bypass for Muse Code → Runtime**, review the MCP server and session hook, then start a new session.

Muse Code owns plugin reasoning and billing. Bypass cannot verify subscription billing through MCP; check Muse Code account/settings. For confidential or personal content, use Standard mode with Contributor mode off. Bypass does not change these settings. [Model and privacy details](docs/AI_MODES.md).

</details>

## Ways to run Bypass

| Workflow | In Muse Code | Standalone | Requirements |
| --- | --- | --- | --- |
| Whitebox discovery and evaluation | `/bypass:discover` → SAST / Policy / Both | `bypass discover --detector <mode>` | Source + Docker; reasoning uses Muse Code or a CLI API profile; SAST discovery-only needs no model |
| AI-assisted source review | `/bypass:review` | `bypass scan --mode code` | Muse Code session; CLI needs a provider key + Docker |
| Running-app discovery and testing | `/bypass:blackbox` | `bypass blackbox <url>` | Approved target + scope; CLI needs an API key, Meta by default |
| Combined source + running-app audit | `/bypass:review` after selecting both | `bypass scan --mode combined` | Connected repository, approved target, API profile, and Docker for source isolation |
| Saved regression replay | `/bypass:tests` | `bypass test run --all` | Saved checks and valid target setup; no model calls |
| GitHub PR review and smoke tests | Ask Muse Code to generate setup | `bypass ci init --agent` | GitHub Actions; Meta API key for source review |

With **Code + running app**, standalone `scan --mode combined` starts the cited source review and broad scoped live reconnaissance together. In Muse Code, the plugin completes its host-directed source worklist, then starts one full scoped black-box audit with those cited source leads and the remaining combined budget. Both paths link source evidence, live coverage, findings, and proof IDs in one review. Only replayed HTTP evidence becomes confirmed.

## White-box source review

### Discover source security signals

Connect your source through `/bypass:start`, choose **Code only** or **Code + running app**, then run:

```text
/bypass:discover
```

Choose **SAST**, **Policy**, or **Both** in Muse Code:

| Mode | What it checks | AI usage |
| --- | --- | --- |
| **SAST** | CodeQL security rules across supported languages | Discovery: no model calls; evaluation: active Muse session |
| **Policy** | Source paths against broad policies for identity and delegation, authorization, injection, AI and protocol boundaries, data lineage, integrations, reliability, workflows, and trusted execution | Your active Muse Code session |
| **Both** | CodeQL rules and AI policy discovery, with independent selections and evidence | Your active Muse Code session for policy tasks |

SAST/Both use GitHub CodeQL under its [separate usage terms](https://github.com/github/codeql-cli-binaries/blob/main/LICENSE.md); Bypass's license does not grant CodeQL rights for private or commercial code.

Docker must be running (see [Docker prerequisite](#docker-prerequisite)). First use prepares the selected image: Policy uses a lightweight Python runtime; SAST/Both download the pinned CodeQL toolchains. Later scans reuse the image. No host Python, host CodeQL, or separate plugin API key is required. If `bypass scanner doctor` reports blocked, follow its `docker.remediation` commands — for Colima that is typically `colima start <profile>` plus `docker context use colima-<profile>` — then re-run the doctor.

From the CLI, after [installation](#standalone-cli):

```bash
bypass init /path/to/app
bypass discover --detector sast --project /path/to/app
```

Default scans evaluate candidates against source after discovery. For the CLI,
first [configure an API profile](#model-configuration). Use `--discovery-only` to
skip evaluation; SAST discovery-only requires no model profile. The CLI defaults
to SAST when no detector is specified. `bypass discover evaluate <run-id>` evaluates
a saved discovery run.

CodeQL language detection covers C/C++, C#, Go, Java/Kotlin, JavaScript/TypeScript, Python, Ruby, Rust, and GitHub Actions. Tests, examples, fixtures, and generated/vendor copies are excluded by default.

<details>
<summary>Select rules and policies, include test code, and inspect reports</summary>

Run from your connected application, or add `--project /path/to/app`:

```bash
bypass scanner doctor
bypass scanner prepare --detector policy  # Optional: prepare the lightweight image
bypass scanner rules --language javascript --query injection
bypass scanner policies
bypass discover --detector sast --languages javascript --rule js/command-line-injection
bypass discover --detector both --languages javascript \
  --rule js/command-line-injection --policy authz/object-access
bypass discover --include-tests
bypass discover signals <run-id> --limit 20
bypass discover report <run-id> --format md
bypass discover resume <run-id>
```

Use exact CodeQL IDs from `scanner rules` and policy IDs from `scanner policies`. `--rule` replaces the default CodeQL `security-extended` selection; `--policy` selects policies independently. `--exclude-rule` and `--exclude-policy` remove exact IDs from their respective detectors. `--include-examples` and `--include-generated` are separate options. Reports, policy evidence/coverage, and available CodeQL SARIF are saved under `.bypass/scanner/<run-id>/`.

</details>

**Read the result correctly:** original detector signals remain unchanged.
Separate evaluation cases record `confirmed`, `refuted`, or `needs_review`,
with cited evidence, severity reasoning, prerequisites, and open questions.
**Confirmed means source-supported, not runtime-reproduced.** Muse Code continues
the bounded discovery/evaluation queue until completion or a blocker. Unresolved
cases remain visible; completion does not prove exhaustive coverage. Runtime
reproduction and patching remain unimplemented in this scanner.
[Scanner usage and limits](scanner/README.md) · [Policy workflow](docs/POLICY_SIGNAL_DISCOVERY.md).

### Investigate source with Muse Code

With **Code only** selected, run:

```text
/bypass:review
```

Muse Code reads bounded source and reports cited hypotheses and recommendations. This is a separate workflow from SAST/policy discovery. With **Code + running app**, it can also configure supported HTTP controls and save regressions after proof. Code-only review makes no live-app requests and cannot establish runtime exploitability.

## Black-box audit

Use this entry point when you have a running app, including when you have **no repository**.

### In Muse Code

Replace the URL with your app and provide the five run settings together:

```text
/bypass:blackbox Audit https://app.example.com; allow /; use 20 rps, 120 Muse Code calls, 30 minutes.
```

Muse Code connects the app, completes missing ownership/scope setup, and drives the black-box engine in the active session. Once the testing plan is approved, it uses the default bounded budgets and begins without another question. Bypass discovers public pages, scripts, and API leads, executes permitted tests, records evidence, and independently checks supported proofs. No separate API key or Docker is needed for this path. Browser-based proof families need Chrome/Chromium; missing prerequisites are reported as coverage gaps.

The URL and paths are run inputs, not permission by themselves. Review the exact scope before testing. The request rate, engine-decision cap, and time limit bound the audit; the displayed “Muse calls” cap does not include every surrounding host turn.

The wizard's **Running app only** choice starts this full audit automatically after scope approval. Its **Code + running app** choice first completes the Muse-directed source review, then hands its cited leads to one full live audit. The wizard offers a **5-minute test** for a quick pass; it reports any remaining coverage as untested. `/bypass:blackbox` remains the explicit app-only command; `--finding` remains an explicit focused-validation command. Muse loads each Bypass tool by its current-session ID, so a logical tool name in a review result is never called as a synthesized MCP identifier.

### From the CLI

Load your Meta Model API key privately as `MODEL_API_KEY` in your shell or secret manager. This is an API key, not a Muse Code subscription/login token. Existing `META_API_KEY` or `LLM_KEY` variables are also supported.

For a local app you control:

```bash
bypass blackbox http://127.0.0.1:3000 --accept-local --rps 20 --model-calls 120 --minutes 30
```

To validate one finding already saved by source review, add `--finding <finding-id>`. For apps with a JSON build endpoint, `--revision-path /version --revision-field revision` compares the deployed full commit SHA to the checkout. Without that endpoint, the report marks the source/live revision unverified.

For a deployed app:

```bash
bypass blackbox setup https://app.example.com --include / --rps 20
```

Complete the ownership and authorization steps printed by setup, then run the audit command it prints. Do not use `--accept-local` for a deployed app.

Inside the interactive CLI, type `/blackbox` to choose an app, review its methods, paths and rate, and start the audit. A newly selected deployed app also asks whether it is production, staging or preview and requests one approval for that app's testing scope. Each app gets its own scope file, so switching apps leaves earlier scope files and approvals intact.

<details>
<summary>Authenticated tests, proof replay, and regression export</summary>

Anonymous testing can run without credentials. For authenticated black-box checks on current `main`, supply explicit private credential references and the identity endpoint. The guided setup's “Create two test accounts” choice does not automatically provision accounts for this separate audit engine.

With `BYPASS_OWNER_TOKEN` and `BYPASS_OUTSIDER_TOKEN` already loaded privately, add these settings when preparing scope; replace `/api/me` with your app's actual identity endpoint:

```bash
bypass blackbox setup https://app.example.com --include / --rps 20 \
  --owner-env BYPASS_OWNER_TOKEN --other-env BYPASS_OUTSIDER_TOKEN \
  --identity-path /api/me
```

After a run, use its printed ID:

```bash
bypass blackbox verify <run-id>
bypass blackbox export <run-id>
bypass blackbox resume <run-id>
```

In Muse Code, ask it to replay the black-box proofs, export tests for confirmed findings, or resume the named run. These operations use the `bypass_blackbox_*` tools. Black-box run IDs are separate from guided-review `run_*` IDs and their saved checks.

</details>

**Results:** inspect confirmed proofs, inconclusive/blocked tasks, and `coverage.json` under the run's `.bypass/runs/` directory. Missing credentials, budget limits, or zero executed probes do not mean the app passed. Current families include bounded access-control, exposure, redirect, injection, and browser checks; availability varies by target and permissions. [Exact coverage and limitations](docs/BLACKBOX_AUDIT.md).

## Standalone CLI

Prefer a separate terminal workflow? Use the standalone CLI. It connects either **Meta Model API** for hosted Muse Wonder and Muse Spark, or an existing local/self-hosted server for **Muse Spark Open** or **Muse Glimmer**. It does not require Muse Code or use a Muse Code subscription. Install without opening Muse Code:

```bash
curl -fsSL https://bypasslabs.ai/install | bash
```

```powershell
irm https://bypasslabs.ai/install.ps1 | iex
```

The installer includes Node and configures PATH. On macOS/Linux, open a new terminal or use its printed activation command. Start the interactive workspace with:

```bash
bypass
```

Choose **Connect my application**. In the first step, onboarding asks where Muse inference runs. Selecting **Meta Model API** immediately opens a masked API-key prompt, discovers the Muse models available to your team, recommends Muse Wonder for the deepest reviews, and verifies one synthetic request before continuing. Muse Spark 1.3 Contributor is an explicit lowest-cost choice and starts with minimal reasoning for a responsive first audit. After code, a running app, or both are connected, onboarding starts that security audit directly. For live testing, approving the displayed boundaries starts the audit and streams progress—there is no `/blackbox` handoff or repeated URL, path, method, rate, or start prompt. The guided first audit allows up to 24 Muse planning calls and 10 minutes; it still runs scoped HTTP checks and reports any untested work. Use `bypass scan --model-calls 120` or resume a run when you want deeper research. The key is retained only in the running process; project state stores its environment-variable name, never its value. Type `/` to browse commands; **Ctrl+O** opens activity details and **Ctrl+T** toggles tasks. `bypass onboard` opens setup directly. Use `NO_COLOR=1` to disable color or `BYPASS_PLAIN=1` for a scrolling interface.

Run `bypass onboard` from your application folder, or enter the folder when prompted. When you resume a saved project, the CLI shows its previous review type and asks what to audit this time. For **Code + running app**, it also asks you to select the saved app or enter a different URL before live testing starts. Saved setup remains in that checkout's `.bypass/state.json`; starting from a new checkout creates separate project state. Domain verification is optional: the default flow confirms app control together with explicit testing permissions, while DNS TXT and HTTPS-file proof remain configurable under **Settings → Domain ownership verification**.

Before repository initialization, Bypass shows the exact `.gitignore`, `.bypassignore`, and local `.bypass/` file plan. You can apply it, customize source-review exclusions, or leave tracked files unchanged. For scripts, `bypass init . --plan --json` reports the same structured `fileChanges` without creating Bypass project files; `--tracked-files skip` initializes only local state.

### Model configuration

SAST, reports, and saved regression replay need no model key. Standalone policy discovery and AI source review need Docker and a Muse connection. The guided wizard uses a masked prompt. For noninteractive setup, load the Meta key privately and configure its environment-variable **name**, never its value:

```bash
bypass model add review --provider meta --model muse-wonder-1.0 --secret-env MODEL_API_KEY --project /path/to/app
bypass model use review --project /path/to/app
bypass discover --detector policy --project /path/to/app
```

For the separate guided source-review workflow, use `bypass engine use docker --project /path/to/app`, then `bypass scan --mode code --project /path/to/app`.

For **local Muse Glimmer without authentication**, see the [complete local source-review setup](docs/AI_MODES.md#local-muse-glimmer-source-review). It covers the localhost endpoint, placeholder token, explicit model-profile selection, real Docker engine, and a 180-second per-request timeout. For slower generation, [disable the timeout explicitly](docs/AI_MODES.md#disable-the-model-timeout) with `--timeout-ms 0`; cancellation remains available. Bypass connects directly to the local model server; Muse Code is not involved.

If a no-timeout review reports a connection interruption, try the [buffered-mode diagnostic](docs/AI_MODES.md#connection-interrupted-despite-no-timeout) with `--stream false`. Streaming overhead can hit the separate response-size limit; server failures can produce the same error.

For slow local Glimmer reasoning or reasoning-only responses, [select minimal reasoning explicitly](docs/AI_MODES.md#select-minimal-reasoning-for-local-glimmer) with `--effort minimal`. Custom profiles keep the server default unless an effort is selected.

For CodeQL and bundled policy checks, use [local Glimmer discovery](docs/AI_MODES.md#codeql-and-policy-discovery-with-local-glimmer) with `bypass discover --detector both --project /path/to/app`. Unlike `scan --mode code`, this runs the scanner detectors and source-only evaluation by default; it does not reproduce vulnerabilities against a running app.

The three canonical standalone audit modes are:

```bash
bypass scan --mode code --project /path/to/app      # cited source hypotheses; no app requests
bypass scan --mode live --project /path/to/app      # full scoped black-box audit; source skipped
bypass scan --mode combined --project /path/to/app  # source + full live audit; one parent result
```

`scan` accepts the live budget controls `--model-calls`, `--minutes`, `--max-urls`, `--max-tasks`, `--agents`, and `--http-workers`. It snapshots the saved target paths, methods, request rate, and compatible test-account references into the run. It never silently narrows a first audit to a five-minute preset.

Run `bypass init /path/to/app` first if the application is not connected. The first-run experience supports **Meta Model API** and local OpenAI-compatible servers running **Muse Spark Open** or **Muse Glimmer**. Explicit legacy provider profiles remain available through advanced commands but are not offered during onboarding. Bypass never changes billing paths or enables Muse Spark Contributor without an explicit model selection. [Provider examples and migration](docs/AI_MODES.md).

## Optional Muse demo

```text
/bypass:demo
```

Muse Code investigates an isolated invoice app. Bypass proves cross-account access, saves a failing regression, and retests the fixture fix. This is a training fixture, separate from your application; start a customer audit with `bypass onboard` or `/bypass:start`. See the [first audit walkthrough](docs/WALKTHROUGH.md).

## GitHub security agent

Review PR source with a **Meta Model API key**, then replay saved security checks after deployment or every 24 hours. The GitHub runner uses Actions and does not require Docker or a Muse Code subscription.

**1. Generate setup in your application repository.** Ask Muse Code:

```text
Set up Bypass GitHub security reviews for this repository.
Start with source-only, report-only PR reviews. Generate the setup files.
```

Or run `bypass ci init --agent` from an initialized app. Both generate:

```text
.github/bypass.json
.github/workflows/bypass-pr-signal.yml
.github/workflows/bypass-security.yml
```

**2. Add the API key.** In your app repository, open **Settings → Secrets and variables → Actions → New repository secret**:

| Name | Value |
| --- | --- |
| `MODEL_API_KEY` | Your Meta Model API key. Required for PR source review. |
| `GITHUB_TOKEN` | Supplied automatically by GitHub. Do not create it yourself. |

Alternatively, run `gh secret set MODEL_API_KEY` and enter the key privately. Store it as a **Secret**, not a Variable.

**3. Review and merge the three generated files into your app's default branch.** Open **Actions → Bypass Security** for the baseline. You can also choose **Run workflow → operation: auto**, with `pr` empty.

**4. Open or update a non-draft PR.** Bypass updates one review comment and the **Bypass / PR review** check. Findings are report-only by default; incomplete execution still fails visibly. Reports are downloadable from **Artifacts → bypass-report**. No application fixes are applied automatically.

<details>
<summary>Add deployment verification and daily smoke tests</summary>

First connect a DNS-verified app and save the live regression checks to replay. Then ask Muse Code:

```text
Add our verified production target and its saved security checks to the
GitHub integration. Replay them after deployment and every 24 hours.
Show me the exact extra secrets and deployment requirements.
```

Add the generated `BYPASS_DNS_<TARGET>` secret (for example, `BYPASS_DNS_PRODUCTION`) with the existing full TXT value, plus the exact test-account secret names printed by setup when needed. Keep the DNS record published.

Your deployment pipeline must record a successful GitHub Deployment with the full app commit SHA, environment, and URL. An approved app endpoint such as `/api/version` must return that SHA. A push alone is not deployment proof.

Review and merge the updated files, then use **Run workflow → operation: smoke** to check setup. Daily replay makes zero model calls. Keep credentials, test resources, ownership, and scope valid; CI does not refresh the plugin's private account vault. GitHub schedules are best effort.

</details>

[Full setup, deployment contracts, merge gates, fork handling, and limits](docs/GITHUB_AGENT.md).

## Commands to keep handy

| In Muse Code | What it does |
| --- | --- |
| `/bypass:start` | Connect/select an app or repository and resume setup |
| `/bypass:discover` | Choose SAST, AI policy discovery, or both; inspect source signals |
| `/bypass:review` | Investigate source and supported configured HTTP checks |
| `/bypass:blackbox` | Discover and test a running app |
| `/bypass:status` | Show setup, progress, and evidence |
| `/bypass:tests` | Replay/export guided-review saved checks |
| `/bypass:build` / `/bypass:context` | Retrieve security context for feature work |
| `/bypass:monitor` | Configure saved-test schedules and a local worker |
| `/bypass:help` | Browse commands and tools |

For CLI help, use `bypass --help` or `bypass <command> --help`. A local monitor requires a running worker and an awake machine. See the [exact generated CLI reference](docs/CLI_REFERENCE.md) and [full plugin/CLI command map](docs/PLUGIN_COMMANDS.md).

## Documentation

- [Documentation index: current guides](docs/README.md)
- [Source scanner: languages, rules, scope, reports, and recovery](scanner/README.md)
- [AI policy discovery: policies, evidence, coverage, and custom context](docs/POLICY_SIGNAL_DISCOVERY.md)
- [Black-box audit: supported checks and evidence limits](docs/BLACKBOX_AUDIT.md)
- [Accounts: signup, private imports, and token refresh](docs/ACCOUNTS.md)
- [AI modes: Muse Code, provider APIs, and local/self-hosted models](docs/AI_MODES.md)
- [Security memory and feature context](docs/SECURITY_MEMORY.md)
- [GitHub agent setup](docs/GITHUB_AGENT.md)
- [Architecture](docs/ARCHITECTURE.md) · [Installation](docs/RELEASES.md)

## Downloads and releases

Use the installers above for the latest tested build. [GitHub Releases](https://github.com/Bypass-Labs/bypass/releases) preserves the same six platform archives, installers, `release.json`, and `SHASUMS256.txt` published to R2. Each main build has a unique commit/run tag; it is published as a prerelease after installation checks and R2 promotion pass. [Release process and pinned installs](docs/RELEASES.md).

## License

Bypass code is licensed under [Apache-2.0](LICENSE), allowing commercial use, modification, and redistribution subject to its terms, with an explicit contributor patent grant. Bundled dependencies and downloaded tools retain their own licenses; see [third-party notices](THIRD_PARTY_NOTICES.md). Bypass is an independent Bypass Labs project, not an official Meta product.

## Contributing

Open an issue with reproduction steps, runtime/release details, and redacted evidence, or submit a focused pull request. For local development (Node 22+):

```bash
npm ci --ignore-scripts
npm run plugin:build
npm run check
npm test
```

Author changes in `src/`, `scanner/`, and the plugin's commands, skill, manifest, hooks, and MCP entry points. `plugin/runtime/` is generated build output. Build it before installing the plugin from source. See [scanner development](scanner/README.md) for Docker/CodeQL checks; `npm run test:live` is an opt-in real Muse Code fixture run and uses your host allowance/billing.

Use Bypass only on applications you own or are authorized to test. Source signals, confirmed HTTP proofs, blocked work, and untested coverage are different outcomes; none is a blanket security clearance.
