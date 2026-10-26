# Bypass for Muse

**Prove the fix. Keep the test.**

Bring application source, a running app, and saved security checks into one workflow—in **Muse Code** or a **guided terminal workspace**. Keep the evidence and the next step with your project.

[Muse plugin](#use-with-muse-code) · [CLI quick start](#use-the-cli) · [Try the demo](#try-the-complete-demo) · [Documentation](#documentation)

> **Prototype status:** source discovery and deployed-app investigation are mocked. Repository connection, model checks, DNS ownership, local fixture proof, exported tests, and local scheduling work today. The demo walks through the complete proof-to-regression journey.

## Why Bypass

- **Work where you already code.** Give Muse one prompt, or use the CLI. Both share your application's saved Bypass settings and evidence.
- **Choose where inference runs.** Use a compatible **local Muse / local model server for greater privacy**, **bring your own self-hosted model**, or **use your existing Muse Code subscription**. The plugin uses your current Muse session by default.
- **Keep verified fixes as tests.** The local demo saves a check after a verified fix. Export ordinary Node tests; replay with **zero model calls**.
- **See what is happening.** Keep repository/app/model context, completed steps, elapsed time, expandable activity, and the next action visible.
- **Resume without starting over.** Reopen saved results or finish DNS later. Local schedules replay checks while their worker and machine remain running.

## Get Bypass

Requires **Node.js 22+**, **Git**, and repository access. Add Muse Code for the plugin or subscription model option. No `npm install` or separate Bypass account is needed.

```bash
git clone https://github.com/Bypass-Labs/bypass-for-muse.git ~/bypass-for-muse
```

Already cloned it? Keep that checkout and use its path in place of `~/bypass-for-muse` below. Choose either experience:

## Use with Muse Code

**1. Install the plugin once.** Inspect its capabilities, then approve them through Muse's native controls:

```bash
muse plugins install ~/bypass-for-muse/plugin --scope user
muse plugins inspect bypass
muse plugins approve bypass
```

Already installed? Use the [update steps](#updating) instead. Sign in with `muse login` if needed.

**2. Start Muse in your application repository.** Replace the example path with your app's folder:

```bash
cd /path/to/your/app
muse
```

**3. Paste this prompt.** Replace the example URL with your staging app:

> Use Bypass to review this repository and its staging app at https://staging.example.com. Walk me through setup and show me what to do next.

Bypass uses this repository and your current Muse model, guides ownership and scope setup, then shows the source/app pairing and review preview. Code preview can continue while DNS is pending. White-box/source and black-box/app stages show their actual prototype status.

Or start with **`/bypass:review`**. Use **`/bypass:context`** for saved evidence and monitor results in a later session.

## Use the CLI

Run guided setup from any directory:

```bash
~/bypass-for-muse/bypass onboard
```

Press Enter for **Connect my application**. Bypass guides you through:

1. **Repository** — choose an existing app folder or paste its Git URL.
2. **Model** — choose Muse Code, a compatible local server, or your own endpoint. The connection test is optional.
3. **Running app** — enter its URL and environment, or add it later. Publish the generated DNS TXT record now or continue the preview while DNS propagates. Authorize testing scope separately after verification.

The workspace opens automatically. **Press Enter for your first review preview**, or type **`/`** to browse commands. This path needs no finding IDs or memorized commands.

| Command inside Bypass | What it does |
| --- | --- |
| `/review` · `/results` | Preview this repository and open its results |
| `/repo` · `/app` | Change the source repository or resume app/DNS setup |
| `/models` | Choose a model connection or test it |
| `/tests` | Replay or export saved regression tests |
| `/status` · `/history` | See review scope and saved project activity |
| `/demo` | Start the complete isolated walkthrough |
| `/help` · `/quit` | Show controls or exit with progress saved |

Use **↑↓ + Enter** to choose, **Ctrl+O** for details, **PgUp/PgDn** to scroll, and **Esc** to go back or stop. Slash commands belong inside Bypass.

Reopen the same application later:

```bash
~/bypass-for-muse/bypass --project /path/to/your/app
```

For a scrolling interface or screen reader, use `BYPASS_PLAIN=1 ~/bypass-for-muse/bypass`. Scripts can use `--json` and `--non-interactive`; see the [full command reference](docs/COMMANDS.md).

## Try the complete demo

**No model login, DNS record, or customer test accounts needed.** Run:

```bash
~/bypass-for-muse/bypass demo
```

Press Enter through **example review → HTTP proof → fix and retest → standalone test export → deliberate regression → monitor result**.

In the local Ledger app, the other account's invoice access changes from **HTTP 200 to 403** while the owner keeps access. Bypass saves and exports a regression test. Bringing the bug back fails both saved replay and the independent test; one scheduler tick records it for the next session.

Discovery is seeded; HTTP proof, the fix, and replay execute for real. The demo leaves the fixture fixed, evidence saved, its schedule paused and server stopped. Your app is unchanged.

<details>
<summary>See the actual terminal walkthrough</summary>

![Bypass terminal showing verified local HTTP controls, a saved regression test, three completed steps, and the next action](docs/assets/cli-walkthrough.png)

[Explore the workspace and keyboard controls](docs/CLI_EXPERIENCE.md).

</details>

## Model choice and privacy

| Connection | Benefit | What you provide |
| --- | --- | --- |
| **Local Muse / local model** | Keep Bypass model requests on this machine for greater privacy; no cloud fallback | A running compatible local model server and its model ID |
| **Your self-hosted model** | Use inference infrastructure your team controls | A compatible HTTPS endpoint, model ID, and optional credential reference |
| **Muse Code subscription** | Use your existing coding account and provider | Installed Muse CLI and your existing login |

Model weights are not bundled. Optional connection checks send a synthetic prompt and may use provider allowance. Mock discovery and replay make zero model calls. Credentials use environment-variable references; evidence and transcripts are stored in your project's `.bypass/` folder.

**Inside Muse, its configured model and privacy settings apply.** Selecting a local profile in the standalone CLI does not change a separate Muse session's provider.

## Current scope

Customer-app discovery and live investigation remain mocked; DNS and credentials do not enable those engines. The complete proof loop works in the isolated fixture. Hosted scheduling and deployment attestation are not connected. See [architecture](docs/ARCHITECTURE.md) and [validation](docs/VALIDATION.md) for details.

## Updating

```bash
git -C ~/bypass-for-muse pull --ff-only
```

If you installed the Muse plugin, also refresh it and start a **new Muse session**:

```bash
muse plugins update bypass
muse plugins inspect bypass
```

If Muse requests renewed capability approval, review the changes and run `muse plugins approve bypass`. Restart Muse to load the updated tools and instructions.

## Documentation

- [Application setup and DNS walkthrough](docs/WALKTHROUGH.md)
- [Interactive workspace and controls](docs/CLI_EXPERIENCE.md)
- [CLI commands and automation flags](docs/COMMANDS.md)
- [Advanced presenter script and exported tests](docs/ADVANCED_WALKTHROUGH.md)
- [Architecture and current boundaries](docs/ARCHITECTURE.md)
- [Verification record](docs/VALIDATION.md)

For development, run these from the Bypass checkout: `npm run check`, `npm test`, `npm run plugin:build`, and `npm run plugin:validate`.
