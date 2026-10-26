# Bypass for Muse

Connect your application's source and running app, review both, and keep proven fixes as regression tests.

**Working prototype:** repository connection, model checks, DNS ownership, local HTTP proof, exported tests, and local scheduling work. White-box discovery and black-box investigation are mocked. A preview is not a security verdict.

## Start with your application

Requires **Node 22+**, Git, and access to this repository. No dependency installation is needed.

```bash
git clone https://github.com/Bypass-Labs/bypass-for-muse.git
cd bypass-for-muse
./bypass onboard
```

Press Enter for **Connect my application**, then:

1. **Choose the application repository.** Paste its local folder or Git URL. Bypass's own checkout is the tool, not automatically your application. Existing checkouts can be reused.
2. **Choose your model.** Muse Code subscription, compatible local Muse/local model server, or your own self-hosted endpoint. Connection testing is optional.
3. **Connect the app deployed from that repository.** Enter a domain such as `job-radar.app` or a full URL, and choose staging or production. Add its DNS TXT record now or press Enter to continue the code preview. Authorize live testing separately after verification.
4. **Review the pairing and press Enter to preview.** Both analysis stages are shown explicitly; results open immediately.

```text
Repository: /Users/you/Projects/job-finder (main)
Git remote: https://github.com/your-org/job-finder.git
App: https://your-app.example.com
White-box / code: simulated
Black-box / live app: deferred
App investigation is deferred. Code preview can run now.
```

When app ownership and scope are ready, the black-box stage changes to **simulated** and authorized saved checks can replay. Neither mocked engine claims to have tested your deployed app for new vulnerabilities.

Type `repo` to change the application, `app` to resume verification, `?` to see commands, or `q` to exit. Reopen the exact selected application with:

```bash
./bypass --project /path/to/your/application
```

## Use the Muse plugin

Install or check it from the CLI's `plugin` shortcut, review its native capabilities in Muse, and start a new Muse session. Run **`/bypass:review`**.

The plugin asks which application repository to use, then asks for its app if missing. It shows the same repository/app pairing and stage status. It uses your current Muse model/account; choosing a second standalone model is optional. Pending DNS leaves code preview available.

If Muse was opened in the Bypass tooling folder, the plugin asks for your application's path or Git URL. Every Bypass tool then uses that selected application for this session. Source fixes still require opening Muse's editor in the application folder.

After updating an existing installation, run `muse plugins update bypass` and start a **new Muse session**. A running session can retain old instructions and tools.

If Muse reports that the MCP definition changed, review it with `muse plugins inspect bypass` and approve the changed capability with `muse plugins approve plugin:bypass:mcp_server:security` before starting that new session.

## See the complete proof-to-regression loop

```bash
./bypass demo
```

Press Enter through six steps: **review → HTTP proof → fix/retest → independent test export → deliberate regression → monitor result**.

This creates a separate local Ledger app. Discovery is seeded; proof, the fixture fix, exported Node test, and regression catch execute for real. No model login, DNS, plugin, or customer test accounts are needed. It finishes with the fixture fixed, evidence saved, and its server stopped. Type `q` at a step to leave early.

The current deployed-app engine cannot prove a real customer finding. Account credentials do not unlock that missing engine. Basic setup therefore does not request test accounts; advanced settings retain that option for later integration work.

## Model choice and privacy

| Choice | What you need | Where inference runs |
| --- | --- | --- |
| Muse Code subscription | Installed Muse CLI and your existing login | Your configured Muse provider |
| Local Muse / local model | A compatible running server and model ID | This machine; no cloud fallback |
| Self-hosted model | Your compatible HTTPS endpoint and optional credential reference | Your infrastructure |

No weights are bundled. Optional connection checks send only a synthetic prompt and may use your provider allowance. Mock analysis and saved-test replay make zero model calls. A Bypass profile does not change a separate Muse session's provider. Evidence stays local; credentials use environment-variable references.

## More detail

- [Application setup and walkthrough](docs/WALKTHROUGH.md)
- [Interactive commands and CLI reference](docs/COMMANDS.md)
- [Advanced presenter script](docs/ADVANCED_WALKTHROUGH.md)
- [Architecture and current boundaries](docs/ARCHITECTURE.md)
- [Verification record](docs/VALIDATION.md)

For development: `npm run check`, `npm test`, `npm run plugin:build`, and `npm run plugin:validate`.
