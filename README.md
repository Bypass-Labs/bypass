# Bypass for Muse

**Security testing for your code and running app. Evidence for the finding. A regression test for the fix. Security context for the next feature.**

[Quick start](#start-in-muse) · [White-box](#white-box-source-review) · [Black-box](#black-box-audit) · [CLI](#standalone-cli) · [GitHub agent](#github-security-agent) · [Docs](#documentation)

## Overview

Bypass brings source scanning, live application testing, and reusable security checks into **Muse Code** and a standalone CLI. Muse investigates and explains; Bypass runs scoped operations and keeps the evidence. Reviews produce findings, fix recommendations, and supported regression tests. Changing your application requires a separate request.

### Key benefits

- **Work inside Muse.** Use your active Muse account and model, with no separate API key for plugin reasoning.
- **Inspect code and test behavior.** Run CodeQL against source, investigate with Muse, and use black-box testing to validate supported vulnerabilities against a running app.
- **Keep the test.** Replay saved HTTP proofs after a fix and export supported checks to Node tests. Regression replay needs no model calls.
- **Carry security context into feature work.** Retrieve past findings, source citations, and saved behavior requirements with `/bypass:build`. Changed source marks knowledge stale.
- **Choose where inference runs.** Standalone AI reviews support provider APIs and API-key-protected local or self-hosted compatible endpoints. Evidence is saved locally; selected source and observations are available to the model you choose.
- **Bring checks into GitHub.** Review PR source, verify saved checks after deployment, and schedule daily regression replay.

## Use cases

- **Before shipping:** scan a repository and investigate authentication, access-control, and other source concerns.
- **Against a running app:** discover exposed routes and test supported vulnerability classes within an approved scope.
- **After a fix or deployment:** replay the same security behavior and retain the result for future development.

## Start in Muse

**Requires Muse Code installed and signed in.** You can select your application during setup; you do not need to start in its folder.

**1. Install the plugin.**

macOS / Linux:

```bash
curl -fsSL https://bypasslabs.ai/install/muse | bash
```

Windows PowerShell:

```powershell
irm https://bypasslabs.ai/install/muse.ps1 | iex
```

**2. Choose “Enable these permissions and open Muse” (`1` or `y`).**

The installer explains the security-tools and security-memory permissions, registers the plugin, and opens Muse with setup started. It includes the runtime and CLI; no GitHub clone, npm, or separate model key is needed. Docker is needed only if you use the CodeQL scanner or standalone Docker review.

**3. Tell Muse what to review.** For example:

```text
Review the source at https://github.com/YOUR-ORG/YOUR-APP.
Use code-only mode. Report findings with file/line evidence and fix
recommendations. Do not edit application code.
```

Setup offers **Code only**, **Code + running app**, or **Running app only**. Supply a local source folder or Git URL for code; supply an app URL for live testing. To return later, use `/bypass:start`.

For an app, setup also asks for its environment, verifies control with DNS TXT or an HTTPS verification file, and records allowed paths, HTTP methods, request rate, and expiry. Valid ownership is reused for the same app origin. Accounts are optional for anonymous checks; authenticated checks need usable test identities.

**Choose the next command:** `/bypass:discover` for CodeQL, `/bypass:review` for Muse-assisted source review, or `/bypass:blackbox` for running-app discovery. See the examples below.

<details>
<summary>Updating, permissions, and model privacy</summary>

Rerun the installer to update or repair, then start a **new Muse session**. An open session keeps its loaded package. `muse plugins update bypass` only refreshes the recorded local source and may not download a newer public release.

If permissions remain pending, open `/plugins` → **Installed → Bypass → Runtime**, review the MCP server and session hook, then start a new session.

Muse owns plugin reasoning and billing. Bypass cannot verify subscription billing through MCP; check Muse account/settings. For confidential or personal content, use Standard mode with Contributor mode off. Bypass does not change these settings. [Model and privacy details](docs/AI_MODES.md).

</details>

## Ways to run Bypass

| Workflow | In Muse | Standalone | Requirements |
| --- | --- | --- | --- |
| CodeQL source scan | `/bypass:discover` | `bypass discover` | Source + Docker; scanner makes zero model calls |
| AI-assisted source review | `/bypass:review` | `bypass scan --mode code` | Muse session; CLI needs a provider key + Docker |
| Running-app discovery and testing | `/bypass:blackbox` | `bypass blackbox <url>` | Verified target + scope; CLI needs an API key, Meta by default |
| Saved regression replay | `/bypass:tests` | `bypass test run --all` | Saved checks and valid target setup; no model calls |
| GitHub PR review and smoke tests | Ask Muse to generate setup | `bypass ci init --agent` | GitHub Actions; Meta API key for source review |

## White-box source review

### Scan with CodeQL

Connect your source through `/bypass:start`, choose **Code only** or **Code + running app**, then run:

```text
/bypass:discover
```

Docker must be running. First use prepares the pinned scanner image and downloads its toolchains; later scans reuse it. No host Python, host CodeQL installation, or LLM API key is required.

From the CLI, after [installation](#standalone-cli):

```bash
bypass init /path/to/app
bypass discover --project /path/to/app
```

Language detection covers C/C++, C#, Go, Java/Kotlin, JavaScript/TypeScript, Python, Ruby, Rust, and GitHub Actions. Tests, examples, fixtures, and generated/vendor copies are excluded by default.

<details>
<summary>Select rules, include test code, and inspect reports</summary>

Run from your connected application, or add `--project /path/to/app`:

```bash
bypass scanner doctor
bypass scanner prepare                 # Optional: prepare the image in advance
bypass scanner rules --language javascript --query injection
bypass discover --languages javascript --rule js/command-line-injection
bypass discover --include-tests
bypass discover signals <run-id> --limit 20
bypass discover report <run-id> --format md
bypass discover resume <run-id>
```

Use exact CodeQL rule IDs from `scanner rules`. `--rule` replaces the default `security-extended` selection; `--exclude-rule` removes exact IDs. `--include-examples` and `--include-generated` are separate options. Reports and raw SARIF are saved under `.bypass/scanner/<run-id>/`.

</details>

**Read the result correctly:** CodeQL produces unevaluated signals with source locations, detector severity, and extraction diagnostics. These are not confirmed live vulnerabilities. The scanner's integrated AI evaluation, reproduction, and patching stages are not implemented. [Scanner usage and limits](scanner/README.md).

### Investigate source with Muse

With **Code only** selected, run:

```text
/bypass:review
```

Muse reads bounded source and reports cited hypotheses and recommendations. This is a separate workflow from the CodeQL scanner. With **Code + running app**, it can also configure supported HTTP controls and save regressions after proof. Code-only review makes no live-app requests and cannot establish runtime exploitability.

## Black-box audit

Use this entry point when you have a running app, including when you have **no repository**.

### In Muse

Replace the URL with your app and provide the five run settings together:

```text
/bypass:blackbox Audit https://app.example.com; allow /; use 2 rps, 120 Muse calls, 30 minutes.
```

Muse connects the app, completes missing ownership/scope setup, and drives the black-box engine in the active session. Bypass discovers public pages, scripts, and API leads, executes permitted tests, records evidence, and independently checks supported proofs. No separate API key or Docker is needed for this path. Browser-based proof families need Chrome/Chromium; missing prerequisites are reported as coverage gaps.

The URL and paths are run inputs, not permission by themselves. Review the exact scope before testing. The request rate, engine-decision cap, and time limit bound the audit; the displayed “Muse calls” cap does not include every surrounding host turn.

**Current entry-point distinction:** use `/bypass:blackbox` explicitly for app-only discovery. Generic “Start review” or `/bypass:review` can enter the configured-probe workflow and finish with zero probes; it does not automatically launch this engine.

### From the CLI

Load your Meta Model API key privately as `MODEL_API_KEY` in your shell or secret manager. This is an API key, not a Muse subscription/login token. Existing `META_API_KEY` or `LLM_KEY` variables are also supported.

For a local app you control:

```bash
bypass blackbox http://127.0.0.1:3000 --accept-local --rps 2 --model-calls 120 --minutes 30
```

For a deployed app:

```bash
bypass blackbox setup https://app.example.com --include / --rps 2
```

Complete the ownership and authorization steps printed by setup, then run the audit command it prints. Do not use `--accept-local` for a deployed app.

<details>
<summary>Authenticated tests, proof replay, and regression export</summary>

Anonymous testing can run without credentials. For authenticated black-box checks on current `main`, supply explicit private credential references and the identity endpoint. The guided setup's “Create two test accounts” choice does not automatically provision accounts for this separate audit engine.

With `BYPASS_OWNER_TOKEN` and `BYPASS_OUTSIDER_TOKEN` already loaded privately, add these settings when preparing scope; replace `/api/me` with your app's actual identity endpoint:

```bash
bypass blackbox setup https://app.example.com --include / --rps 2 \
  --owner-env BYPASS_OWNER_TOKEN --other-env BYPASS_OUTSIDER_TOKEN \
  --identity-path /api/me
```

After a run, use its printed ID:

```bash
bypass blackbox verify <run-id>
bypass blackbox export <run-id>
bypass blackbox resume <run-id>
```

In Muse, ask it to replay the black-box proofs, export tests for confirmed findings, or resume the named run. These operations use the `bypass_blackbox_*` tools. Black-box run IDs are separate from guided-review `run_*` IDs and their saved checks.

</details>

**Results:** inspect confirmed proofs, inconclusive/blocked tasks, and `coverage.json` under the run's `.bypass/runs/` directory. Missing credentials, budget limits, or zero executed probes do not mean the app passed. Current families include bounded access-control, exposure, redirect, injection, and browser checks; availability varies by target and permissions. [Exact coverage and limitations](docs/BLACKBOX_AUDIT.md).

## Standalone CLI

Install without opening Muse:

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

Choose **Connect my application**, or **See the full local walkthrough**. Type `/` to browse commands; **Ctrl+O** opens activity details and **Ctrl+T** toggles tasks. `bypass onboard` opens setup directly. Use `NO_COLOR=1` to disable color or `BYPASS_PLAIN=1` for a scrolling interface.

### Model configuration

CodeQL, reports, and saved regression replay need no model key. Standalone AI source review needs Docker and an explicit provider profile. Load the key privately, then configure its environment-variable **name**, never its value:

```bash
bypass model add review --provider meta --secret-env MODEL_API_KEY --project /path/to/app
bypass model use review --project /path/to/app
bypass engine use docker --project /path/to/app
bypass scan --mode code --project /path/to/app
```

Run `bypass init /path/to/app` first if the application is not connected. Presets include **Meta, OpenAI, Anthropic, Moonshot, DeepSeek, and custom**. For a local or self-hosted model, use `custom` with an explicit endpoint, model ID, API-key variable, and transport. Bypass does not switch providers or billing paths automatically. [Provider examples and migration](docs/AI_MODES.md).

## See the complete demo

```text
/bypass:demo
```

Muse investigates an isolated invoice app. Bypass proves cross-account access, saves a failing regression, and retests the fixture fix. Reintroducing the bug makes that regression fail again without model calls for replay. This demo explicitly includes fixture remediation; ordinary assessments only report and recommend.

<details>
<summary>Preview the standalone walkthrough</summary>

![Bypass CLI showing proof, fix verification, regression, and next steps](docs/images/cli-workspace.png)

This screenshot is from the local walkthrough: discovery is seeded; HTTP proof, fix verification, and regression replay are real. [Walkthrough](docs/WALKTHROUGH.md).

</details>

## GitHub security agent

Review PR source with a **Meta Model API key**, then replay saved security checks after deployment or every 24 hours. The GitHub runner uses Actions and does not require Docker or a Muse subscription.

**1. Generate setup in your application repository.** Ask Muse:

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

First connect a DNS-verified app and save the live regression checks to replay. Then ask Muse:

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

| In Muse | What it does |
| --- | --- |
| `/bypass:start` | Connect/select an app or repository and resume setup |
| `/bypass:discover` | Run CodeQL and inspect unevaluated signals |
| `/bypass:review` | Investigate source and supported configured HTTP checks |
| `/bypass:blackbox` | Discover and test a running app |
| `/bypass:status` | Show setup, progress, and evidence |
| `/bypass:tests` | Replay/export guided-review saved checks |
| `/bypass:build` / `/bypass:context` | Retrieve security context for feature work |
| `/bypass:monitor` | Configure saved-test schedules and a local worker |
| `/bypass:help` | Browse commands and tools |

For CLI help, use `bypass --help` or `bypass <command> --help`. A local monitor requires a running worker and an awake machine. [Full plugin/CLI command map](docs/PLUGIN_COMMANDS.md).

## Documentation

- [CodeQL scanner: languages, rules, scope, reports, and recovery](scanner/README.md)
- [Black-box audit: supported checks and evidence limits](docs/BLACKBOX_AUDIT.md)
- [Accounts: signup, private imports, and token refresh](docs/ACCOUNTS.md)
- [AI modes: Muse, provider APIs, and local/self-hosted models](docs/AI_MODES.md)
- [Security memory and feature context](docs/SECURITY_MEMORY.md)
- [GitHub agent setup](docs/GITHUB_AGENT.md)
- [Architecture](docs/ARCHITECTURE.md) · [Installation](docs/RELEASES.md) · [UAT evidence and open issues](docs/MERGE_UAT_2026_10_30.md)

## Contributing

Open an issue with reproduction steps, runtime/release details, and redacted evidence, or submit a focused pull request. For local development (Node 22+):

```bash
npm ci --ignore-scripts
npm run plugin:build
npm run check
npm test
```

Author changes in `src/`, `scanner/`, and the plugin's commands, skill, manifest, hooks, and MCP entry points. `plugin/runtime/` is generated build output. Build it before installing the plugin from source. See [scanner development](scanner/README.md) for Docker/CodeQL checks; `npm run test:live` is an opt-in real Muse fixture run and uses your host allowance/billing.

Use Bypass only on applications you own or are authorized to test. Source signals, confirmed HTTP proofs, blocked work, and untested coverage are different outcomes; none is a blanket security clearance.
