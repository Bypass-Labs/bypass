# Your first complete Bypass journey

Run this from the Bypass checkout:

```bash
./bypass demo
```

No repository URL, model login, DNS, or plugin is required. Bypass creates a separate Ledger app on an available local port. Open the printed URL in a browser if you want to see the two accounts beside the terminal.

## Six steps, six presses of Enter

| Step | What Bypass does | What you see |
| --- | --- | --- |
| 1. Review | Inventory the fixture and create its seeded example | A clearly labeled account-access scenario; discovery is simulated |
| 2. Prove | Send real requests as owner, other account, and anonymous visitor | Owner 200, other account 200, anonymous 401: the defect is reproduced |
| 3. Fix and retest | Change the fixture's ownership check and replay the requests | Owner 200, other account 403, anonymous 401; one regression test saved |
| 4. Export | Export an ordinary Node test and execute it | Independent test passes, without Bypass or a model |
| 5. Catch it again | Reintroduce the defect and run both forms of the test | Both detect the regression; this expected failure is a successful demonstration |
| 6. Remember | Run one due local scheduler tick and read session context | The regression is recorded for the next session |

The walkthrough then restores the fix, retests, pauses its schedule, and stops its local server. The final screen prints the folder containing all evidence and the exported test. This demonstrates one scheduler tick; it does not start a permanent monitoring service.

Type `q` at any step to leave. Partial evidence is kept and the local server stops. Run `./bypass demo` again for a fresh walkthrough. Existing projects and demos are not overwritten.

## Connect your own repository and app

```bash
./bypass onboard
```

Choose **2 → Connect my repository**. Or supply an existing checkout to skip the opening choice:

```bash
./bypass onboard /path/to/your/app
```

### 1. Repository

Paste a local path or Git URL. Bypass uses your existing Git credentials and does not execute the repository's code during setup.

```text
Repository directory or Git URL: https://github.com/Bypass-Labs/job-finder
Clone into folder [~/Projects/job-finder]:
```

Press Enter to accept the suggested folder. An occupied parent folder gets a suggested child folder. A matching checkout can be reused; a different Git origin is shown explicitly before you choose it. Type `back` at the folder prompt to change the repository.

Keep the exact path printed after cloning, including any `-2` suffix. You will use that path when reopening the project.

### 2. Model

Choose your Muse Code subscription, a compatible local Muse/local model server, or your own self-hosted endpoint. Local and self-hosted choices require a running server and its model ID. Bypass does not download model weights.

The connection test is optional: it sends a synthetic prompt and may use your provider allowance. It shows progress and has a 45-second deadline. Press Enter during the check to skip it, or Ctrl+C to exit with settings saved. On failure, continue setup, retry, or change the connection. Skipped and failed checks are never shown as connected.

A model is not called during this prototype's discovery preview or deterministic replay.

### 3. App and DNS

Enter `job-radar.app`, `https://staging.example.com`, or a loopback address such as `localhost:3000`. Deployed domains get HTTPS automatically. Invalid input returns to the address field. Press Enter at the empty field to add an app later.

Select staging/preview or production. For a deployed app, Bypass generates a unique DNS record:

```text
Type    TXT
Name    _bypass-verification.staging.example.com
Value   bypass-verification=<the unique value printed by your wizard>
TTL     Auto / provider default
```

Add it at your DNS provider. If the provider automatically appends `example.com`, use `_bypass-verification.staging` as the relative record name. For the apex `example.com`, use `_bypass-verification`. Copy the complete generated value and keep unrelated DNS records.

Choose **1 → I've added the record — check DNS**, or **press Enter to continue to your review**. Pending DNS is saved setup, not a failed review. You can return later by typing `app` on the project home screen. The wizard retains the challenge until it expires, then issues a new value.

Once ownership is verified, explicitly authorize the testing paths. Defaults are `/api`, GET/HEAD, two requests per second, and a seven-day expiry. Production also requires typing `production`. Ownership alone does not grant testing permission. Loopback apps use an explicit local ownership acknowledgment instead of DNS.

### 4. Optional connections

After authorization, you can add two test-account references. Enter environment-variable names, never token values. Load the actual values privately in the terminal that launches Bypass or Muse.

The Muse plugin is optional. If Bypass is already installed from another checkout, setup recognizes it and does not try to install a conflicting copy. Review native capabilities with `muse plugins inspect bypass`, approve those you want with `muse plugins approve bypass`, and start a new session in your connected repository. Use `/bypass:review` there. To refresh an existing plugin later, use `muse plugins update bypass`.

### 5. Your first preview

Choose **Open my project**, then press Enter. Bypass inventories source locally, shows **Review preview complete**, and opens the result directly. No IDs or separate finding command are needed.

**The scenario is simulated; it is not a vulnerability discovered in your repository.** DNS verification does not change this boundary. Choose the offered local walkthrough to experience real HTTP proof, the fix, and saved-test replay now.

## Finding commands without memorizing them

The home screen shows three choices. Press Enter for the first one; it changes from **Run my first review preview** to **Open review results**, then **Replay saved tests** when that project has saved tests.

Type `?` for the short command menu:

| Command inside the interactive screen | Purpose |
| --- | --- |
| `review` / `results` | Run a preview / open its results |
| `demo` | Start the complete isolated walkthrough |
| `tests` | Replay or export saved tests |
| `app` | Resume app verification and setup |
| `models` / `plugin` | Manage connections |
| `settings` | Open all advanced controls |
| `back` / `q` | Return home / exit |
| `help all` | Show the full CLI reference |

These are interactive shortcuts. For shell commands and automation flags, see the [CLI reference](COMMANDS.md). The program also accepts raw CLI commands inside its interactive screen.

To reopen a project later, run this from the Bypass checkout:

```bash
./bypass --project /path/to/your/app
```

For an extended presentation with source edits in Muse, a detached monitor while Muse is closed, and a second saved regression, use the [advanced presenter script](ADVANCED_WALKTHROUGH.md#4-begin-the-proof-demo-one-ledger-app-two-accounts).
