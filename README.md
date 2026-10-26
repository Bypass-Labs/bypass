# Bypass for Muse · runnable skeleton

Connect a repository and a running app, review a security candidate, verify a fixture issue, fix it, save a regression, and replay that regression without a model.

**The setup, CLI, terminal menu, Muse MCP plugin, local HTTP fixture, exported tests, durable jobs, and local scheduler are implemented. The white-box discovery and black-box investigation engines are explicitly mocked.** No mock result is evidence about a real deployed app.

Node 22 or newer is the only runtime dependency. There is no npm dependency installation step.

## Start with the full customer journey

**[Open the full walkthrough and presenter script](docs/WALKTHROUGH.md).** It starts with a fresh repository connection and the exact DNS TXT record the customer must publish, then covers scope, all three model options, test accounts, CLI/Muse usage, and the complete proof → fix → saved test → scheduled regression → second test demo.

```text
Connect repository → Add app → Verify DNS TXT → Authorize scope
→ Choose model → Connect test accounts → Review and prove
→ Fix and retest → Export test → Catch regression → Grow the library
```

Quick start for your own repository (replace the path; the wizard asks for the app origin):

```bash
git clone https://github.com/Bypass-Labs/bypass-for-muse.git
cd bypass-for-muse
./bypass init /absolute/path/to/your/app-repository
```

The wizard connects the repository, asks for the model, and offers to add the app. For a deployed app it prints a real ownership challenge. Follow [the DNS verification steps](docs/WALKTHROUGH.md#2-connect-the-live-app-and-verify-its-dns-txt-record), publish the exact generated TXT value, verify ownership, and authorize scope before live requests. The walkthrough gives every explicit command and expected result, including the Muse plugin path.

The setup works with your repository and live app. Actual proof/fix demonstrations use the separate local Ledger fixture while analysis engines are mocked.

## Immediate fixture rehearsal

This shortcut preconfigures a local app, accounts, and scope. Use the full walkthrough above to demonstrate customer onboarding first. From your Bypass checkout:

```bash
./bypass demo start
./bypass --project .demo/ledger
```

Open **http://127.0.0.1:4317** to see the real two-account Ledger fixture. The terminal menu is the primary product surface. Choose **4 → Run a review**, then **5 → Findings**. You can also type any command directly into the menu.

If port 4317 is occupied, use `./bypass demo start --port 4327`. The fixture binds to loopback only.

For a fully automated, independently asserted walkthrough:

```bash
npm test
```

See [the guided walkthrough](docs/WALKTHROUGH.md), [all commands](docs/COMMANDS.md), [architecture and boundaries](docs/ARCHITECTURE.md), and [verification record](docs/VALIDATION.md).

## Command-line walkthrough

Run these from the package directory. Replace IDs with those printed by the preceding command.

```bash
./bypass --project .demo/ledger scan
# Exit 3 is intentional: discovery is simulated, not a security verdict.

./bypass --project .demo/ledger finding list
FINDING_ID='finding_REPLACE_WITH_PRINTED_ID'
./bypass --project .demo/ledger verify "$FINDING_ID"
# Exit 1: a real HTTP request proves the local fixture exposes another account's invoice.

./bypass --project .demo/ledger demo fix
./bypass --project .demo/ledger retest "$FINDING_ID" --build demo-fixed
# Owner still gets 200; the other account gets 403; anonymous requests get 401.
# A saved regression is created automatically.

./bypass --project .demo/ledger test export --all
node --test .demo/ledger/tests/security/bypass/*.test.mjs
# These are ordinary Node tests. They do not import Bypass or call a model.

./bypass --project .demo/ledger demo regress
./bypass --project .demo/ledger test run --all
# Exit 1: catches the regression without a model.

./bypass --project .demo/ledger monitor add hourly --target demo --every 1h
./bypass --project .demo/ledger monitor worker --detach
./bypass --project .demo/ledger context
```

The worker runs independently of Muse, but this machine must remain awake. Stop it with `monitor worker --stop`; stop the fixture with `demo stop`. `demo reset` resets fixture behavior and retains findings and history.

## Connect your own repository and deployed app

Interactive setup:

```bash
./bypass init /absolute/path/to/your/repository
```

Or clone using your existing Git credentials:

```bash
./bypass init --repo https://github.com/YOUR-ORG/YOUR-REPO.git \
  --dir /absolute/path/to/new-checkout --non-interactive
```

No package scripts, application code, Git hooks, or submodules are run during onboarding. Existing edits are preserved. Repository credentials must come from your Git credential helper; do not embed them in a URL.

```bash
./bypass --project /path/to/repo target add staging \
  --url https://staging.example.com --environment staging
```

Bypass prints a unique TXT challenge at `_bypass-verification.staging.example.com`, plus an alternative HTTPS challenge path. Publish the exact value, then:

```bash
./bypass --project /path/to/repo target verify staging --method dns --wait 30s
./bypass --project /path/to/repo target authorize staging \
  --scope-file /path/to/reviewed-scope.json
```

The example [scope file](examples/scope.json) authorizes read-only `/api` testing. Ownership and authorization expire separately. Production requires a separate acknowledgment. Redirects do not expand scope. A pending challenge blocks live operations while code-only mock review remains available.

The deployed-app analysis/verification engines do not issue exploit probes in this skeleton. Saved deterministic checks and configured identity smoke tests can make real requests only after scope is established. There is no hosted verification authority; these are local operator guardrails.

## Choose inference

All three choices are represented in setup and share the same profile API:

```bash
# Existing Muse Code subscription, through the official installed Muse CLI.
./bypass --project /path/to/repo model add muse --provider muse-code

# A compatible local model server; no remote fallback.
./bypass --project /path/to/repo model add local --provider local \
  --base-url http://127.0.0.1:1234/v1 --model YOUR_LOCAL_MODEL_ID

# Your compatible self-hosted endpoint.
./bypass --project /path/to/repo model add private --provider endpoint \
  --base-url https://models.example.com/v1 --model YOUR_MODEL_ID \
  --secret-env BYPASS_MODEL_TOKEN

./bypass --project /path/to/repo model use local
./bypass --project /path/to/repo model test local
```

`model test` sends only a synthetic prompt and checks the response contract. The mock analysis engine does not call any selected model. Local-model support requires a running compatible server and a model your hardware can run; this package does not download model weights. `--allow-private` explicitly permits an internal HTTPS inference endpoint for a self-hosted profile and never widens app-testing scope.

**Privacy:** evidence stays local; source inventory is hashed locally; real credentials are environment references. Muse-hosted sessions still use their own configured provider. Selecting a local Bypass profile does not make an independently cloud-hosted Muse session local. Bypass-launched Muse smoke checks turn contributor mode off for that invocation only and do not extract subscription credentials.

## Native Muse plugin

```bash
./bypass integrate muse --project /path/to/repo --scope project
cd /path/to/repo
MUSE_NO_AUTO_UPDATE=1 muse plugins inspect bypass
MUSE_NO_AUTO_UPDATE=1 muse plugins approve bypass
MUSE_NO_AUTO_UPDATE=1 muse
```

Start a new Muse session and run **`/bypass:review`**. **`/bypass:context`** reads saved evidence. An approved `SessionStart` hook adds a compact summary of local monitoring results without network access or automatic scanning. The plugin exposes typed MCP tools rather than a general-purpose shell command.

The package includes its runtime, so Muse's cached copy does not depend on the original source directory. Native Muse installation and capability approval are separate, following its documented trust model. Plugin cache/registry placement is managed by Muse even when project scope is selected. Rebuilding/updating the package changes its digest and requires reviewing the updated runtime capabilities again.

## Honest boundaries

- White-box discovery and black-box investigation are mock adapters. All mock candidates carry `simulation: true` and `simulated_unproven`.
- Real fixture proof is labeled `confirmed_fixture`, never a finding about the customer's deployed app.
- Hosted Bypass sign-in/device authorization and cloud workers are not connected. Local mode is complete and needs no Bypass account. Requests for unconfigured hosted features return exit 3, never a fake success.
- Source fingerprints are conservative whole-repository hashes of eligible source files. The route inventory is heuristic, and this is not complete coverage analysis.
- Build IDs supplied with `retest --build` are operator labels, not deployment attestations.
- Saved tests cover a specific behavior and fixture. They expire with their exported ownership/scope and need real environment bindings, valid test accounts, and stable fixture IDs.
- CI generation writes local files only. It does not push, deploy, provision secrets, or start a remote service.

## Development

```bash
npm run check
npm test
npm run plugin:build
npm run plugin:validate
```

The tests start isolated loopback HTTP servers and temporary Git fixtures. There are no network dependencies and no live model calls in the test suite. Use a terminal environment that permits local server sockets.
