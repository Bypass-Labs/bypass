# Bypass for Muse

Find a security issue, verify the fix, and keep a regression test that runs without a model.

**Runnable skeleton:** onboarding, the local demo, exported tests, and monitoring work. White-box discovery and black-box investigation are mocked.

## Get started

You need **Node 22+**, Git, and access to this repository. No dependency installation is needed.

```bash
git clone https://github.com/Bypass-Labs/bypass-for-muse.git
cd bypass-for-muse
./bypass onboard
```

Choose **QuickStart** to connect your project, or **Try the demo** to explore with a local app.

```text
BYPASS / Get started

  1  QuickStart (recommended) — connect your project
  2  Try the demo — a local app with two test accounts
  3  Advanced setup — more configuration choices
```

The wizard walks you through:

1. **Repository** — use a local checkout or clone a Git URL.
2. **Model** — use your Muse Code subscription, a compatible local Muse/local model, or your own self-hosted endpoint.
3. **App** — enter its URL, copy the generated DNS TXT record, and verify it right there. Review and authorize the paths to test.
4. **Optional connections** — add test-account references and install the Muse plugin now or later.

For a Git URL, the wizard suggests a folder such as `~/Projects/job-finder`. **Press Enter to accept it.** If you enter an occupied parent folder like `~/Projects`, it suggests a new subfolder and keeps your repository URL.

Then open Bypass and choose **Run a review**. If you skipped the app, the menu defaults to code-only review. DNS still pending? Your progress is saved; rerun onboarding with the same repository to continue.

```bash
./bypass onboard /path/to/your/app
```

## Try the full demo

Choose **Try the demo** in onboarding, open the URL it prints, and keep the terminal beside the browser.

**Review → prove the invoice issue → fix → retest → export the test → reintroduce the bug → catch it without a model.**

The [short walkthrough](docs/WALKTHROUGH.md) explains the wizard and demo menu. The [detailed presenter script](docs/ADVANCED_WALKTHROUGH.md#4-begin-the-proof-demo-one-ledger-app-two-accounts) includes the scheduled catch and a second saved check.

## Model choice and privacy

| Choice | What you need | Where inference runs |
| --- | --- | --- |
| Muse Code subscription | Installed Muse CLI and your existing login | Your configured Muse provider |
| Local Muse / local model | A compatible running server and model ID | This machine; no cloud fallback |
| Self-hosted model | Your compatible HTTPS endpoint and optional credential reference | Your infrastructure |

No model weights are bundled. Model testing is optional and sends only a synthetic prompt. The mock analysis engine does not call the selected model. A local Bypass profile does not change the provider of a separate Muse session. Evidence stays local; real credentials are referenced by environment-variable name.

For Muse, select plugin installation in the wizard, review and approve its native capabilities, then start a new session in your repository and run **`/bypass:review`**.

## More detail

- [Onboarding and short walkthrough](docs/WALKTHROUGH.md)
- [Manual commands and full demo script](docs/ADVANCED_WALKTHROUGH.md)
- [Command reference](docs/COMMANDS.md)
- [Architecture and current boundaries](docs/ARCHITECTURE.md)
- [Verification record](docs/VALIDATION.md)

For development: `npm run check`, `npm test`, `npm run plugin:build`, and `npm run plugin:validate`.
