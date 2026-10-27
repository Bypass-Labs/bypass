# Bypass for Muse

**Find an account-access bug. Verify the fix. Keep the test and security context for your next feature.**

Inside **Muse Code**, Muse plans the investigation and fixes; Bypass reads bounded source, executes approved HTTP tests, and preserves evidence. No separate model key or Docker is needed for the plugin. The **standalone CLI** uses your explicit provider API key and isolated Docker workers.

This is a working POC for missing authentication and cross-account access to configured JSON resources. Source citations are hypotheses; actual HTTP controls establish confirmation. Passing these checks is not a complete security assessment.

## Start in Muse

**1. Open Muse in your application folder and paste:**

```text
Read https://bypasslabs.ai/install/muse.md and install Bypass for Muse.
```

Muse follows the installation skill: downloads the full package, configures PATH and registers the native plugin. You need Muse Code installed and signed in. No GitHub clone, npm, system Node, Docker or separate model key is required to install and use the plugin. Git is needed when connecting a Git repository.

**2. Review permissions in Muse.** Open `/plugins` → **Installed** → **Bypass** → **Runtime**. Approve its local tool server and session-context hook. Start a **new Muse session** in your application folder so those capabilities load.

**3. Type `/bypass:start`, or ask:**

> Use Bypass to review this application. Inspect its source, help me connect its running app, prove any account-access issue, and help fix and save a regression test. Keep me informed about what is done and what comes next.

Muse reuses saved setup. When needed, it guides repository → app URL → exact DNS TXT ownership record → testing scope → two account credential references → one owned resource. Source review can start while live setup is pending. Never paste app credentials into chat.

<details>
<summary>Prefer a terminal install?</summary>

macOS / Linux:

```bash
curl -fsSL https://bypasslabs.ai/install/muse | bash
```

Windows PowerShell:

```powershell
irm https://bypasslabs.ai/install/muse.ps1 | iex
```

Then complete steps 2 and 3 above. Rerun the same command to update or repair. Reinstalling identical bytes preserves your approval; changed packages need a new review. The installer bundles Node and supports macOS, glibc Linux and Windows on x64/arm64 (PowerShell 5.1+ on Windows).

</details>

<details>
<summary>Already use npx skills?</summary>

From your application folder, with Node 22.20+:

```bash
npx skills add https://bypasslabs.ai/install/muse.md -a universal
```

This puts the **installation skill** in the project's `.agents/skills`, which Muse reads. In Muse, run `/skills reload`, then ask “Install Bypass for Muse.” The skill installs the complete native plugin; it is not a substitute for its tools. Use project scope here: `universal -g` uses a different global directory from Muse. The one-prompt path above needs neither Node nor this extra step.

</details>

**Account/privacy boundary:** Bypass uses the active Muse session and makes no independent model requests. The current MCP interface does not attest session billing, so Bypass cannot verify subscription usage. Confirm subscription mode in Muse; if the host shows API billing, switch to subscription mode. For confidential/personal code, turn Contributor mode off in Muse `/settings` and use Standard mode. Bypass does not change those settings. [Meta's requirements](https://dev.meta.ai/help/subscriptions/muse-code-contributor-mode).

## See the complete demo

Inside Muse:

```text
/bypass:demo
```

Muse creates an isolated public fixture, reads its actual source and finds the missing invoice ownership check. It chooses the approved probe; Bypass observes owner **200**, other account **200**, anonymous **401**. Muse interprets that evidence, applies the fixture fix and retests: owner **200**, other account **403**, anonymous **401**. Bypass saves and exports the regression. Reintroducing the bug makes replay fail with **zero plugin model calls**. The fixture is restored and stopped; evidence remains available.

Muse drives every reasoning step. You do not copy JSON, configure a second model, or move to another terminal for the test loop. The fixture demo tests only its generated app. [Detailed walkthrough](docs/WALKTHROUGH.md).

## What you keep

- **Observed proof:** cited source plus scoped HTTP controls; suspected, confirmed, blocked and not-run states stay distinct.
- **Reusable regressions:** fixed behavior becomes an independent Node test, replayed without AI or provider credentials.
- **Security context for coding:** `/bypass:build` retrieves cited application knowledge, prior investigations and saved behavior requirements before a new feature. Changed source marks knowledge stale; history is not current proof.
- **Local evidence and control:** evidence stays in `.bypass/`. Muse controls plugin reasoning/privacy; CLI users explicitly choose a provider or their own API-key-protected compatible endpoint.
- **One execution engine:** plugin and CLI share source grounding, account-boundary proof, evidence, retest, export and monitoring operations.

| In Muse | Purpose |
| --- | --- |
| `/bypass:start` | Resume missing setup |
| `/bypass:review` | Muse-directed investigation and fix verification |
| `/bypass:status` | Done / Now / Next and evidence |
| `/bypass:tests` | Replay, export and manage saved checks |
| `/bypass:build` / `/bypass:context` | Security context for feature work |
| `/bypass:monitor` | Saved-test schedules and local worker |
| `/bypass:help` | Discover tools, reports, CI and settings |

A monitor needs a running worker and an awake machine. A single tick is not an always-on service. [All operations and mode differences](docs/PLUGIN_COMMANDS.md).

## Standalone CLI

Install once (includes Node and PATH setup):

```bash
curl -fsSL https://bypasslabs.ai/install | bash
```

On Windows: `irm https://bypasslabs.ai/install.ps1 | iex`. On macOS/Linux, open a new terminal or use the activation command printed by the installer. Windows updates the current PowerShell session and user PATH.

AI review requires Docker and **your provider API key**. Coding-agent subscriptions and login tokens are never used. Repository setup, reports, memory and saved tests do not require an AI key.

```bash
bypass onboard
```

The wizard asks for provider → API-key **environment-variable name** → model → endpoint → optional connection check. It never asks for a secret value. Load the variable privately using your shell or secret manager; do not put the value in a command argument or project file.

Example with `OPENAI_API_KEY` already loaded:

```bash
bypass init /path/to/app
bypass model add review --provider openai --secret-env OPENAI_API_KEY --project /path/to/app
bypass model use review --project /path/to/app
bypass model test review --project /path/to/app
bypass engine use docker --project /path/to/app
bypass scan --mode code --project /path/to/app
```

For live proof, complete the app/scope/account/resource steps in onboarding, then use `scan --mode combined`. Use `finding list`, `finding show <id>`, edit the app, and `retest <id>`. `test run --all` replays saved checks; `test export --all` creates independent Node tests. Run `bypass help` or launch `bypass` for the interactive workspace.

Presets: **Meta/Muse, OpenAI, Anthropic/Claude, Moonshot/Kimi, DeepSeek, custom**. Models remain configurable. No automatic provider, credential, model, protocol or billing fallback. [Provider examples, capability matrix and migration](docs/AI_MODES.md).

## Existing installations

Version 0.5 separates host reasoning from CLI API billing. Existing `muse-code`, `local` and `endpoint` profiles remain on disk but cannot run standalone AI. Create/select a new explicit API profile, or use the Muse plugin without any model setup. Targets, findings, memory and saved regressions are retained. Use the same Muse installer above to update, review the changed package in `/plugins`, and start a fresh Muse session.

## Develop and verify

```bash
npm ci --ignore-scripts
npm run plugin:build
npm run check
npm test
BYPASS_DOCKER_TESTS=1 npm test
```

`npm run test:live` is an opt-in **actual Muse host** fixture test: it installs a temporary candidate plugin under a distinct ID, uses normal host approvals, exercises the full reasoning/test/fix loop, retains evidence, then removes the candidate. It uses the host account's allowance or billing; the test does not attest subscription billing. `node scripts/provider-smoke.mjs` tests only explicitly available provider API-key environment variables with synthetic prompts.

[Architecture and provider limits](docs/AI_MODES.md) · [POC execution details](docs/REAL_POC.md) · [Job Radar setup](docs/JOB_RADAR.md) · [Verification results](docs/AI_VALIDATION.md)

[Installation design and comparison with Strix, Superpowers and Context7](docs/INSTALLATION_DESIGN.md)
