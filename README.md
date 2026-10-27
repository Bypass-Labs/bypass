# Bypass for Muse

**Find an account-access bug. Keep the fix as a test. Give your coding agent that security context for the next feature.**

Use Bypass inside **Muse Code**, or in its standalone CLI. A source-review agent and an HTTP-testing agent run in separate Docker containers and share one model profile.

**POC status:** real model requests, source citations, HTTP controls and exported tests. Coverage is limited to missing authentication and cross-account access on configured JSON resources. Model/provider failures can interrupt a review; an incomplete run is never a clean bill of health.

## Start with the Muse plugin

The installer supports **Windows, macOS and glibc Linux, x64 and arm64**, and includes Node.js. Windows requires Windows 10/11 or Server 2016+ and PowerShell 5.1 or 7. For reviews, you also need **Git**, **Muse Code**, and running **Docker Desktop** (Linux containers on Windows), or Colima on macOS. Sign in to Muse with `muse login` if needed.

### 1. Install Bypass — one terminal command

**Windows — PowerShell:**

```powershell
irm https://bypasslabs.ai/install.ps1 | iex
```

**macOS / Linux — terminal:**

```bash
curl -fsSL https://bypasslabs.ai/install | bash
```

This downloads the tested `main` build from Cloudflare R2, verifies its SHA-256 checksum, and installs it locally. No GitHub access, clone, npm install, system Node or administrator rights are needed. **PATH is configured automatically**: Windows updates the current PowerShell session and your user PATH; Bash and Zsh receive startup-file entries. Repeated installs do not add duplicate entries.

On Windows, `bypass` works immediately in the same PowerShell session. On macOS/Linux, open a new terminal or run the printed activation command; a `curl | bash` child process cannot change its parent terminal's PATH.

### 2. Connect the Muse plugin — in your terminal

```bash
bypass integrate muse --scope user --replace
muse plugins inspect bypass
muse plugins approve bypass
```

If PATH setup is restricted, use `~/.local/bin/bypass` on macOS/Linux, or `& "$env:LOCALAPPDATA\Bypass\bin\bypass.cmd"` in Windows PowerShell. `--replace` switches an existing plugin to the bundled version; application settings and evidence stay in their project folders. `inspect` and `approve` use Muse's native capability review. Open a new Muse session after installing or updating.

### 3. Open Muse, then start Bypass

In your terminal:

```bash
muse --reasoning-effort minimal
```

This optional setting applies only to this Muse session. It was used in the live POC checks; it is not a demonstrated fix for provider delays or timeouts.

**Inside Muse**, type:

```text
/bypass:start
```

Bypass asks for **your application folder or Git URL**. The installed tool is separate from your application; Bypass does not automatically select a repository.

You can also use one ordinary prompt:

> Use Bypass to review my application. Help me connect its repository and running app, one step at a time. Use my Muse subscription for inference.

**For the demo, stay in Muse:**

```text
/bypass:demo
```

Muse creates and selects a separate local app with two public accounts. It guides **real Docker/AI review → HTTP proof → fixture fix → verified regression → exported test → deliberate regression → one monitor tick → security context**, then stops the fixture and restores your application selection. Your app is untouched. The configured model is shared across the orchestrator and both agents; model usage applies. Ask for an **offline preview** explicitly if you want seeded discovery with zero Bypass analysis calls; the Muse conversation still uses its own provider.

During the journey, Muse shows **Done / Now / Next**, actual stages and model-call counts. A confirmed vulnerability or caught regression is shown as a security result; a provider failure is shown as an incomplete review. `/bypass:status` shows the current state at any time.

| Inside Muse | What it does |
| --- | --- |
| `/bypass:start` | Connect your repository and finish missing model/app/DNS/account setup |
| `/bypass:demo` | Run the complete isolated demonstration inside Muse |
| `/bypass:status` | Show completed work, active progress, evidence and next steps |
| `/bypass:review` | Start or resume a review |
| `/bypass:tests` | Inspect, replay, bind, export, enable or disable saved tests |
| `/bypass:monitor` | Configure schedules and start, stop or inspect the local worker |
| `/bypass:build` / `/bypass:context` | Use or inspect saved security context |
| `/bypass:help` | Discover all operations, including reports, CI and configuration |

The plugin uses the same services and project state as the CLI. CI checks coverage of **all public CLI commands and their options**. Muse sign-in, native capability approval and restarting the host remain explicit Muse steps. [Complete capability mapping](docs/PLUGIN_COMMANDS.md).

### 4. Follow the conversation

| Bypass asks | Your answer | What happens next |
| --- | --- | --- |
| Which repository? | Your app's local folder or Git URL | Connects it; offers an existing checkout or a new clone folder |
| Where should AI run? | Muse subscription, local model or your self-hosted endpoint | Saves one profile for all three roles; shows where source excerpts will go |
| Source only, or running app too? | **Review source now**, or your app URL and environment | Source review can start without DNS or test accounts |
| Verify the deployed app | Add the exact **TXT name and value** shown in chat, then say “check DNS” | Verifies domain control; local apps use an ownership acknowledgment |
| Which paths may we test? | Authorized paths, such as `/api`, and production acknowledgment if applicable | Saves bounded GET/HEAD permission, with rate and expiry limits |
| Which two test accounts? | Credential **environment-variable names** and the signed-in JSON endpoint | Configures the owner and another account; never asks for token values in chat |
| Which resource belongs to the owner? | One existing GET path and its expected JSON ID | Validates both logins and owner access with three GETs, before AI; a placeholder ID stops here |

For DNS, copy the generated value exactly. If your DNS provider appends your domain, enter only the record-name prefix it needs. Say **“review source while DNS propagates”** to keep going.

For authenticated HTTP proof, load both test-account credentials into the terminal **before launching Muse**. If they are missing, Bypass saves your progress and explains which variables to load; restart Muse after loading them. See [Job Radar's concrete setup](docs/JOB_RADAR.md) for an application example.

### What you should see during a review

```text
Done     Repository connected · model selected · Docker ready
Now      Validating two accounts + owner resource — three GETs, no AI
Next     Checking model connection — one small prompt, no source sent
Then     Source review → HTTP controls → evidence
```

For a live review, account/resource validation runs before AI. Missing tokens, expired logins or a nonexistent resource stop there with zero model calls. Source-only review skips those HTTP requests.

The model preflight has a **30-second limit**; each review response has a **60-second limit**. Muse transport status, the resolved model, source reads and HTTP controls appear as the work progresses. A recent successful connection check is reused for 15 minutes. A passing preflight proves only that a small prompt worked.

When a finding is confirmed, ask Muse to help fix it in your application folder, then say:

> Retest the fix and export the saved regression test.

An observed failure followed by a passing fix creates a reusable check. Saved and exported checks replay with **zero model calls**.

**Return later:** `/bypass:review` starts or resumes a review; `/bypass:context` shows saved setup, findings and tests. You do not need to reset or reclone.

## Build your next feature with security context

Open Muse in your connected application folder and describe the feature:

> Use Bypass's security context while adding invoice export. Check relevant past findings, preserve the account-access rules, and run the relevant regression tests.

Or use **`/bypass:build`**, then describe the feature. The coding agent retrieves relevant memory, checks current source, implements the change, and tests it. Reading memory needs **no Docker, model connection, DNS or test accounts**; live replay still needs valid authorization and credentials. If you open Muse from a different folder, select the application again when asked.

You should see something like this (illustrative, not a result for your app):

```text
Building   Invoice export
Remembered Owner access must work; other accounts must be denied
Evidence   Saved invoice-read regression + cited ownership policy
Recheck    policy.mjs changed since the previous source review
Next       Read current policy → implement export → test new route
           → replay the existing invoice-read regression
```

What Bypass retains:

- **Application knowledge:** authentication, ownership, routing and data-model interpretations, anchored to lines actually read during a real review.
- **Security history:** hypotheses, observed HTTP controls, verified fixes, incomplete investigations and saved tests, with provenance.
- **Context for new work:** relevant records ranked by the feature and files, with changed source marked for revalidation. An existing test does not cover a newly added endpoint automatically.
- **Your model choice:** compatible local Muse/local inference for enhanced privacy, your self-hosted endpoint, or your Muse Code subscription. Memory stays in the project locally; retrieved content follows the model using it. A hosted coding session can receive memory even if Bypass's review model is local.

`/memory` in the CLI or “show Bypass memory” in Muse lets you inspect it. You can disable it or forget individual records. Source interpretations are not verified guarantees; past passes never become current passes without replay. There is no cross-project or cloud memory service. See [how security memory works](docs/SECURITY_MEMORY.md).

## Standalone CLI

Use this if you prefer Bypass's own terminal interface. **Plugin installation is not required.**

```bash
bypass onboard
```

1. Choose **Connect my application**.
2. Enter your app's folder or Git URL; accept the suggested clone folder if needed.
3. Choose Muse, a local model, or a self-hosted endpoint.
4. Enter your running app URL, or press Enter to add it later.
5. Open the project and type **`/review`**. New setups select real Docker agents automatically. Source review can proceed while live setup is pending.

Inside the Bypass workspace:

| Type | Purpose |
| --- | --- |
| `/review` | Start a review; automatically check an untested/stale model connection |
| `/app` | Connect your app or finish DNS verification |
| `/engine` | Configure the two accounts and JSON resource for real HTTP proof |
| `/results` | Inspect findings and retest a fix |
| `/tests` | Replay or export saved regression tests |
| `/memory` | Inspect security knowledge, citations and freshness |
| `/context` | Read context for the next coding session |
| `/models` | Choose or test a model connection |
| `/` | Browse commands |
| `/quit` | Exit with progress saved |

Reopen with `bypass --project "/path/to/your/app"` (on Windows, use your application's Windows path). Existing offline-preview projects keep their selected engine; use `/engine` to switch them. [Full CLI reference](docs/COMMANDS.md).

## Why use Bypass?

- **Work inside Muse or the CLI.** Both use the same application settings, evidence and saved tests.
- **Choose your model and privacy boundary.** Use a compatible **local Muse/local model server for greater privacy**, **bring your own self-hosted model**, or **use your Muse Code subscription**. No model weights are bundled and there is no automatic cloud fallback. A local Bypass profile does not change Muse chat's own provider.
- **Separate suspicion from proof.** Source citations are hypotheses. Actual HTTP account controls establish confirmed findings.
- **Keep a verified fix as a test.** Replay saved checks before AI; export ordinary Node tests without a model dependency.
- **Resume your work.** Repository selection, DNS progress and evidence survive a new session. Local monitoring requires an awake machine and running worker.

The Muse subscription adapter uses native `muse exec`; it does not extract your login credentials. It uses Muse's configured default unless you select an exact model ID. This is not automatic inheritance of the open chat's model. Bypass requests default to `minimal` reasoning; the model and provider are unchanged. Source excerpts go to the chosen inference destination during real reviews.

## If the model stops responding

**Do not keep restarting the review or reinstalling the plugin.** Your setup is saved.

- **Inside Muse:** say “Check Bypass's model connection and tell me the failing step.”
- **Inside Bypass CLI:** type `model test`. If it fails, use `/models` to choose another connection; after it passes, use `/review`.
- **In your terminal:** `muse usage` checks allowance. Use `muse login` when the error actually reports authentication failure.

A timeout means **review incomplete**. The screen shows the failed stage and evidence location. Bypass does not silently substitute mocked findings. Ask Muse to **“Run Bypass diagnostics”**; its doctor tool distinguishes missing executables, an unavailable Docker daemon and denied Docker socket access. A daemon can be running while a sandboxed process cannot reach it. CLI users can run `bypass doctor --project /path/to/your/app`.

## Update an existing installation

Run the installer again (`irm https://bypasslabs.ai/install.ps1 | iex` on Windows, or the curl command below on macOS/Linux), then refresh the Muse integration if you use it:

```bash
curl -fsSL https://bypasslabs.ai/install | bash
bypass integrate muse --scope user --replace
muse plugins inspect bypass
muse plugins approve bypass
```

Restart Muse. The installer keeps previous versions and does not touch application repositories, model settings, ownership records or security memory. Check the active CLI with `bypass --version`. No cleanup or reclone is needed.

For source development instead of an installed release:

```bash
git clone https://github.com/Bypass-Labs/bypass-for-muse.git
cd bypass-for-muse
./bypass doctor
```

An existing source checkout can use `git pull --ff-only` and `npm run plugin:build`. [Release and installer details](docs/RELEASES.md) cover CI, platform support, custom install paths and rollback.

## Optional examples and technical details

- **Real AI example:** `/bypass:demo` inside Muse, or `bypass poc` in a terminal. [Prove → fix → retest walkthrough](docs/REAL_POC.md).
- **Offline example:** ask Muse for the offline Bypass preview, or run `bypass demo`. HTTP checks and regression replay are real; discovery is seeded.
- [Architecture and boundaries](docs/ARCHITECTURE.md) · [DNS walkthrough](docs/WALKTHROUGH.md) · [Validation record](docs/VALIDATION.md)

Developers: `npm run check` and `npm test` run local checks. `npm run plugin:build` refreshes the bundled runtime. **`npm run test:live` is opt-in and uses your Muse allowance:** it exercises the packaged plugin over MCP, real Docker/model source discovery, HTTP proof, fix verification, exported tests and deliberate regression against the local fixture. It reports failure if any required step fails and retains its evidence. It does not validate the whole conversational Muse interface or a production app.

For feature-specific context in the CLI (or JSON for another coding agent):

```bash
bypass context --project /path/to/your/app \
  --task "Add invoice export" --files "src/routes.js,src/auth.js" --json
```

The standalone CLI returns context; your coding agent performs the implementation.
