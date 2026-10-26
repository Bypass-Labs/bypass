# Get started with Bypass

From your Bypass checkout, run:

```bash
./bypass onboard
```

Choose **QuickStart** for your app or **Try the demo** for a ready-to-use local example. Advanced setup adds profile names, custom identity types, and HTTPS ownership verification.

## QuickStart

### 1. Connect your repository

Enter a local directory or a Git URL. Bypass clones remote repositories using your existing Git credentials. It keeps existing source edits and does not run your application's code during setup.

```text
Repository directory or Git URL: https://github.com/Bypass-Labs/job-finder
Clone into folder [~/Projects/job-finder]:
```

**Press Enter at the folder prompt.** Bypass creates the suggested folder. To save it elsewhere, enter a new folder such as `~/Work/job-finder`. If you enter an occupied parent folder, the wizard suggests a subfolder without asking for the URL again. If that repository is already checked out, it offers to use it and keep its files. Type `back` at the folder prompt to change the repository.

If the folder contains a checkout with a different Git origin, Bypass shows both repository names. You can explicitly use that local checkout or clone the requested repository into a new folder.

### 2. Choose a model

Pick your **Muse Code subscription**, a **local Muse/local model server**, or a **self-hosted endpoint**. Local and self-hosted choices need a compatible server and its model ID. A local Muse deployment must be supplied by you; Bypass does not download weights.

You can test the connection now or later. A test sends a synthetic prompt and may use your provider allowance. An untested or failed connection is never shown as connected. Existing model settings are kept when you resume.

The check displays progress immediately and every five seconds while waiting, with a 45-second limit. **Press Enter during the check to skip it and move to the app step.** Ctrl+C exits setup and keeps your saved choices. If the check fails, choose **Continue setup**, **Retry**, or **Choose another model connection**.

For Muse, login errors point to `muse login`; allowance errors point to `muse usage`. A timeout means the check did not finish in time, not that your login is necessarily wrong. Local-model errors tell you to start the server, check the loaded model ID, or set the credential variable. Bypass never asks you to paste a secret token into the wizard.

To resume, pass the local repository folder printed after cloning—use the exact folder, including any `-2` suffix. This keeps your model settings and avoids cloning again:

```bash
./bypass onboard --flow quickstart ~/Projects/job-finder
```

### 3. Connect your running app

Enter the app's origin, such as `https://staging.example.com`, and choose staging or production. Or press Enter to add an app later.

For a deployed app, the wizard prints a DNS record:

```text
Type    TXT
Name    _bypass-verification.staging.example.com
Value   bypass-verification=<your unique generated value>
TTL     Auto / provider default
```

Add that record in the domain's DNS provider. Copy the complete value printed by your own wizard. If the provider appends `example.com` automatically, the relative name is `_bypass-verification.staging`.

Back in the same wizard, select **I've added the record — check DNS**. If it is not visible yet, retry or select **Do this later**. Setup stays saved and live testing stays blocked. Loopback apps use an explicit local-ownership acknowledgment instead of DNS.

After verification, review the paths and authorize read-only checks. The default is `/api`, GET/HEAD, two requests per second, for seven days. Production requires a separate confirmation. Ownership verification alone does not authorize testing.

### 4. Add optional connections

You can add two test-account references and install the Muse plugin, or leave both for later. Enter credential environment-variable names, never token values. Load the actual values privately in the launching terminal before testing accounts or starting Muse.

If you install the plugin, the wizard prints the native Muse review and approval commands. After approving, start a new Muse session in the connected repository and run **`/bypass:review`**.

### 5. Open Bypass

The final summary shows what is configured and what remains pending. Choose **Open Bypass now**, then **4 → Run a review**. With no authorized app, the menu defaults to code-only mode.

To resume later, use the same repository:

```bash
./bypass onboard /path/to/your/app
```

You do not need to recreate its model, target, or DNS challenge. The wizard skips completed setup and returns to unfinished verification or authorization. After an expired challenge, it prints a fresh value to publish.

## Try the demo

Run `./bypass onboard` and choose **2 → Try the demo**. If a demo already exists, continue it or choose a fresh one. Bypass starts the app on an available local port and prints its URL. Open that URL in your browser and choose **Open Bypass now**.

| Step | In the terminal | What you should see |
| --- | --- | --- |
| Review | **4 → Run a review**, accept the displayed plan | A clearly simulated invoice candidate |
| Prove | **5 → Findings**, select the invoice, type `verify` | Owner 200; another account also gets 200; anonymous 401 |
| Fix | **9 → Demo controls → Apply ownership fix** | The running fixture now enforces ownership |
| Retest | **5 → Findings**, select the invoice, type `retest` | Owner 200; other account 403; one saved regression |
| Export | **6 → Saved tests → Export standalone Node tests** | Test files written into the demo repository |
| Bring the bug back | **9 → Demo controls → Reintroduce regression** | The deliberately vulnerable behavior returns |
| Catch it | **6 → Saved tests → Replay all saved tests** | A failed regression with zero model calls |

The dashboard shows the demo repository path. From that directory, run the exported tests directly:

```bash
node --test tests/security/bypass/*.test.mjs
```

They pass after the fix and fail after the regression. They need Node and the running app, with no Bypass or model dependency.

When finished, choose **9 → Demo controls → Stop fixture server**, then **0 → Exit**. Your project and evidence remain saved.

For the full presentation—editing source in Muse, catching a regression while Muse is closed, retrieving it next session, and growing the library to two tests—use the [presenter script](ADVANCED_WALKTHROUGH.md#4-begin-the-proof-demo-one-ledger-app-two-accounts). That script uses its own fresh fixture and port.

## What is real today?

Repository connection, DNS verification, scope, provider connection tests, the local HTTP proof loop, exported tests, and local scheduling work. Discovery and deployed-app investigation are mocked. Real proof in the demo is about its local fixture. The local worker needs an awake machine; a hosted scheduler is not connected.

For individual flags or scripted setup, see the [command reference](COMMANDS.md). `init --non-interactive` remains available for automation; `onboard` is interactive.
