# Advanced reference: manual setup and full demo script

For a first run, use **`./bypass onboard`** and the [short walkthrough](WALKTHROUGH.md). This page is the detailed command reference and presenter rehearsal, not required reading for setup.

**Start with an unconnected repository. End with two security regression tests owned by the team, a returning bug caught without a model, and the result waiting in the next Muse session.**

| Scene | What the customer does | What we show |
| --- | --- | --- |
| 1. Connect | Add an existing repository or clone one | Repository path, branch, commit, and remote |
| 2. Verify the app | Add its HTTPS origin and publish a DNS TXT record | Pending → verified ownership; testing still requires scope |
| 3. Configure | Authorize paths, choose inference, add test accounts | Exact target, data destination, credential references, readiness |
| 4. Review and prove | Run Bypass from the CLI or Muse | Candidate → owner/non-owner/anonymous HTTP evidence |
| 5. Fix and retain | Edit the code, retest, export a regression | Owner works, outsider denied, standalone test passes; library **1** |
| 6. Catch the return | Close Muse, reintroduce the bug | Local worker catches it with **0 model calls**; next session retrieves it |
| 7. Grow | Add an invoice-export route | Old HTTP assertions still pass; new behavior needs investigation; library **2** |

**Today's skeleton:** repository connection, DNS verification, scope, identity requests, provider connection tests, fixture HTTP checks, exported tests, and local monitoring are real. Discovery and deployed-app investigation are mocked. Scenes 1–3 use your repository and app; scenes 4–7 use the separate, clearly labeled Ledger fixture for actual proof. Do not present fixture evidence as evidence about your app. The eventual single-deployed-app demo requires the real analysis engines and deployment integration.

## Before you start

Use Bash for the copyable commands below. You need Node 22+, Git, and access to this private repository. For customer onboarding, have a repository you can access, a public HTTPS staging origin you control, access to its DNS zone, and two separate test accounts. Muse Code is needed only for the Muse experience or its model connection test.

Clone Bypass once. The helper keeps commands working when you later change directories:

```bash
git clone https://github.com/Bypass-Labs/bypass-for-muse.git
cd bypass-for-muse
export BYPASS_ROOT="$PWD"
bypass() { node "$BYPASS_ROOT/bin/bypass.mjs" "$@"; }
bypass --help
```

There is no npm install step. Local Bypass mode needs no Bypass account. Git access uses your existing Git credentials; Muse Code uses its own existing login/subscription.

Run one scene at a time. Expected exit codes `1` (failed security check) and `3` (blocked or simulated/incomplete result) are part of this demonstration; they are called out below. Do not combine these scenes into a shell script that stops on every nonzero exit.

## 1. Connect the customer's repository

Choose an existing checkout. Replace the two example values with your repository directory and app origin:

```bash
export CUSTOMER_REPO='/absolute/path/to/your/app-repository'
export APP_ORIGIN='https://staging.example.com'
bypass init "$CUSTOMER_REPO" --non-interactive
bypass --project "$CUSTOMER_REPO" repo show
```

**Show:** the connected Git repository, remote, branch, and commit. No source code, package scripts, hooks, or submodules are executed. Existing edits remain in place. A plain directory is also accepted but is identified as a directory, not a Git repository.

If the customer has only a Git URL, use this **instead of** the `init` command above. `CUSTOMER_REPO` must name a new or empty destination:

```bash
bypass init --repo https://github.com/YOUR-ORG/YOUR-APP.git \
  --dir "$CUSTOMER_REPO" --non-interactive
```

For the guided experience, run `bypass onboard "$CUSTOMER_REPO"`. It handles model selection, app connection, DNS verification and scope within one resumable wizard. The explicit commands below are the manual alternative. If the wizard already added a model or target, inspect it with `model list` / `target list` instead of adding the same name again.

## 2. Connect the live app and verify its DNS TXT record

```bash
bypass --project "$CUSTOMER_REPO" target add staging \
  --url "$APP_ORIGIN" --environment staging
bypass --project "$CUSTOMER_REPO" target show staging
```

**Show:** ownership is `pending`, and Bypass prints a unique challenge. For `https://staging.example.com`, the output has this shape:

```text
Publish TXT record:
  Name:  _bypass-verification.staging.example.com
  Value: bypass-verification=<unique value printed by this installation>
```

The value above is a placeholder. Copy the **complete generated value**, including `bypass-verification=`, from your own terminal. Each challenge belongs to this project and exact origin.

In the DNS provider for the app's domain, add this record:

| DNS field | What to enter |
| --- | --- |
| Type | `TXT` |
| Name / host | The exact record name Bypass printed |
| Content / value | The complete generated `bypass-verification=…` value |
| TTL | Provider default / Auto is sufficient for this walkthrough |

If the provider asks for a name relative to the `example.com` zone, enter `_bypass-verification.staging`. If it accepts a full hostname, use `_bypass-verification.staging.example.com`. Check the resulting full name so the zone is not appended twice. Add a dedicated verification record; retain unrelated DNS records. Cloudflare's [record creation instructions](https://developers.cloudflare.com/dns/manage-dns-records/how-to/create-dns-records/) show where to choose the type, complete the fields, and save.

**Before verification, demonstrate the gate:**

```bash
bypass --project "$CUSTOMER_REPO" scan --target staging --plan
```

Expected: ownership is a blocker, exit `3`. This does not run a scan. A code-only mock review can still run while DNS propagates.

After saving the TXT record:

```bash
bypass --project "$CUSTOMER_REPO" target verify staging --method dns --wait 30s
bypass --project "$CUSTOMER_REPO" target show staging
```

Expected: `ownership.status: verified`, method `dns`. Bypass queries DNS and checks the complete TXT value. DNS propagation can take longer than 30 seconds: a pending result is exit `3`; retry the same verification command after the record is visible. It is not a successful verification until Bypass says so.

For DNS troubleshooting, query the exact record name shown by `target show`, for example `dig +short TXT _bypass-verification.staging.example.com`. The challenge expires after 24 hours. If it expired, run `target verify staging --renew`, publish the newly printed value, and verify again. Renewal clears previous ownership and scope. Successful ownership verification currently lasts 30 days.

If DNS cannot be edited, Bypass also prints an HTTPS challenge URL. Serve the exact token as the response body at that URL and use `target verify staging --method http`. This is an alternative control check, not permission to skip ownership verification.

## 3. Authorize scope, choose inference, and connect test accounts

### Authorize the specific app paths

**Show:** domain control and testing authorization are separate. After DNS verification, `scan --plan` still blocks until scope exists.

Create this reviewed scope in the connected repository's local Bypass directory:

```bash
cat > "$CUSTOMER_REPO/.bypass/staging-scope.json" <<'JSON'
{
  "paths": ["/api"],
  "methods": ["GET", "HEAD"],
  "maxRequestsPerSecond": 2,
  "productionAcknowledged": false
}
JSON

bypass --project "$CUSTOMER_REPO" target authorize staging \
  --scope-file "$CUSTOMER_REPO/.bypass/staging-scope.json"
bypass --project "$CUSTOMER_REPO" target use staging
```

Replace `/api` with the paths you authorize before running the command. The scope defaults to seven days; an explicit `expiresAt` must be within 30 days. The current skeleton supports read-only GET/HEAD checks. Production is a separate target/environment and requires `productionAcknowledged: true`; staging verification does not authorize another origin or production. App targets must resolve to public addresses; a private/VPN-only deployment is not supported by these app-request paths yet.

### Choose one model option

| Choice | Customer benefit | Current connection mechanism |
| --- | --- | --- |
| **Muse Code subscription** | Use the coding environment and account the developer already has | Official installed Muse CLI; the plugin uses the host Muse session |
| **Local Muse / local model** | Keep Bypass inference on this machine for greater privacy | A running compatible local model server and a model ID you supply |
| **Your self-hosted model** | Use infrastructure and an inference endpoint your team controls | Compatible HTTPS endpoint; optional token referenced by environment-variable name |

For the main presentation, select Muse Code:

```bash
bypass --project "$CUSTOMER_REPO" model add muse --provider muse-code
bypass --project "$CUSTOMER_REPO" model use muse
bypass --project "$CUSTOMER_REPO" model test muse
```

If Muse is not signed in, run `muse login` in your own terminal first. The optional `model test` makes a real synthetic model request and may consume provider/subscription usage. It sends no repository content. A configured profile is not a successful connection test; show `connected` only after this command succeeds.

Alternative: use a local Muse model or another model served through a compatible local server. This requires a model deployment you supply; the skeleton does not bundle model weights or validate availability of a particular Muse model. Replace the model ID with the server's actual ID:

```bash
bypass --project "$CUSTOMER_REPO" model add local --provider local \
  --base-url http://127.0.0.1:1234/v1 --model YOUR_LOCAL_MODEL_ID
bypass --project "$CUSTOMER_REPO" model use local
bypass --project "$CUSTOMER_REPO" model test local
```

Alternative: your self-hosted endpoint. Set `BYPASS_MODEL_TOKEN` securely in the launching environment if the endpoint requires it:

```bash
bypass --project "$CUSTOMER_REPO" model add selfhosted --provider endpoint \
  --base-url https://models.example.com/v1 --model YOUR_MODEL_ID \
  --secret-env BYPASS_MODEL_TOKEN
bypass --project "$CUSTOMER_REPO" model use selfhosted
bypass --project "$CUSTOMER_REPO" model test selfhosted
```

These endpoint profiles use the chat-completions response contract. An internal HTTPS model endpoint needs the explicit `--allow-private` flag on `model add`; that does not widen app-testing scope. Bypass does not download weights or silently fall back to a cloud model. Selecting a local Bypass profile also does not change the provider of an independently hosted Muse session. The mock discovery engine currently calls none of these models.

### Connect two test accounts

Use a legitimate resource owner and a different account that must not see that resource. For this example, `/api/me` is an authenticated endpoint on your app; replace it if needed and include the actual endpoint in scope.

Load real credentials privately into environment variables, never into chat or CLI flags. In Bash, these prompts hide typed input and avoid placing token literals in shell history:

```bash
read -r -s -p 'Owner test-account token: ' BYPASS_STAGING_OWNER_TOKEN
printf '\n'
read -r -s -p 'Other test-account token: ' BYPASS_STAGING_OUTSIDER_TOKEN
printf '\n'
export BYPASS_STAGING_OWNER_TOKEN BYPASS_STAGING_OUTSIDER_TOKEN

bypass --project "$CUSTOMER_REPO" identity add staging-owner \
  --target staging --type bearer --secret-env BYPASS_STAGING_OWNER_TOKEN \
  --check-path /api/me
bypass --project "$CUSTOMER_REPO" identity add staging-outsider \
  --target staging --type bearer --secret-env BYPASS_STAGING_OUTSIDER_TOKEN \
  --check-path /api/me
bypass --project "$CUSTOMER_REPO" identity test staging-owner
bypass --project "$CUSTOMER_REPO" identity test staging-outsider
bypass --project "$CUSTOMER_REPO" status
bypass --project "$CUSTOMER_REPO" scan --target staging --plan
```

**Show:** only credential-variable names are stored. Identity tests make real, scoped HTTP requests; a 2xx response means the endpoint accepted the credential, not that Bypass attested its account role. Readiness shows the repository, verified and authorized target, selected model, and the next action. The plan shows saved checks first, source inventory, inference destination, and the mock-analysis boundary.

You can now run `bypass --project "$CUSTOMER_REPO" scan --target staging`. Expected: a **simulated, unproven** candidate and exit `3`. Verification against this customer app remains mocked and sends no exploit. The working proof/fix loop below uses the local fixture explicitly.

## The same onboarding through the Muse plugin

Install the plugin into the repository, review its capabilities, and start a fresh session:

```bash
bypass integrate muse --project "$CUSTOMER_REPO" --scope project
cd "$CUSTOMER_REPO"
MUSE_NO_AUTO_UPDATE=1 muse plugins inspect bypass
MUSE_NO_AUTO_UPDATE=1 muse plugins approve bypass
MUSE_NO_AUTO_UPDATE=1 muse
```

In Muse, run `/bypass:review`. If the project is already configured above, Muse resumes it. To demonstrate onboarding from Muse instead, install into a fresh customer checkout before running the CLI setup and give Muse this request, replacing the example origin:

> Connect this repository to Bypass and add https://staging.example.com as a staging target. Show me the exact DNS TXT record to publish. After I publish it, verify it and show me the proposed read-only /api scope for authorization. Use my existing Muse Code account. Add owner and outsider test identities using BYPASS_STAGING_OWNER_TOKEN and BYPASS_STAGING_OUTSIDER_TOKEN, and show readiness and the review plan. Keep simulated results labeled.

| Customer action | Native Muse tool / behavior |
| --- | --- |
| Connect this checkout | `bypass_init` |
| Add the app and display its challenge | `bypass_add_target` |
| Publish the TXT record | Customer saves it in their DNS provider |
| Check DNS | `bypass_verify_target` with method `dns` |
| Authorize the reviewed paths | `bypass_authorize_target` after the customer's scope decision |
| Choose provider and test accounts | `bypass_add_model`, `bypass_use_model`, `bypass_add_identity`, `bypass_test_identity` |
| Show readiness and data flow | `bypass_status`, `bypass_prepare_scan` |
| Run and retrieve the review | `bypass_scan`, then poll `bypass_run` using its returned run ID |

Real token variables must be present before launching Muse so its MCP process inherits them. Use the CLI for the optional model smoke test; there is no separate MCP model-test tool. Capability approval is separate from installation. The plugin's typed tools share the same project state and scope rules as the CLI.

## 4. Begin the proof demo: one Ledger app, two accounts

**Presenter transition:** “The repository and DNS onboarding you just saw are real. Discovery is mocked in this skeleton. We will now use a deliberately vulnerable local app to demonstrate the working proof, fix, test export, and monitoring journey.”

Keep the Bypass terminal or Muse session on the left and the Ledger browser on the right. Evidence is shown in CLI/MCP results; there is no separate Bypass web dashboard in this build.

From your Bypass checkout, create a fresh presentation fixture. This helper preconfigures its local target, public accounts, and Muse profile; it is the rehearsal shortcut, not the customer's onboarding flow above:

```bash
export BYPASS_ROOT="$PWD"
bypass() { node "$BYPASS_ROOT/bin/bypass.mjs" "$@"; }
export DEMO_REPO="$BYPASS_ROOT/.demo/presentation"
bypass demo start --dir "$DEMO_REPO" --port 4327
bp() { bypass --project "$DEMO_REPO" "$@"; }
bp repo show
bp status
```

Open **http://127.0.0.1:4327**. The initial invoice is accessible to both Acme (owner) and Globex (another account). All account tokens and invoice data in this fixture are deliberately public. For a repeated rehearsal, use a new empty directory and available port to start with zero findings and zero saved tests. `demo reset` retains history, so it is not a fresh first-time run.

For the Muse version of these scenes, install the plugin into `DEMO_REPO` using the installation steps above with that path, then start Muse there. Otherwise, `bp` opens the terminal menu. The CLI below is the exact command path for either presentation; Muse calls the equivalent typed tools.

### Discover and prove the first issue

```bash
bp scan --plan
bp scan
bp finding list
```

Expected: review plan, saved-check replay first, then one `simulated_unproven` invoice candidate. The scan exits `3` because analysis is simulated. Copy its actual ID into the following variable:

```bash
INVOICE_FINDING='finding_REPLACE_WITH_PRINTED_ID'
bp finding show "$INVOICE_FINDING"
bp verify "$INVOICE_FINDING"
```

Expected: `confirmed_fixture`, exit `1`, and three actual HTTP controls:

| Request | Vulnerable app | After the fix |
| --- | --- | --- |
| Acme requests its own invoice | 200 with the expected invoice ID | 200 with the expected invoice ID |
| Globex requests Acme's invoice | 200 with that same invoice ID | 403 |
| Anonymous request | 401 | 401 |

**Say:** “The candidate was simulated. These HTTP responses are real evidence about this fixture.” A broken owner login, wrong resource ID, server error, or redirect is **blocked**, never a passing fix.

## 5. Fix, retest, and keep the test — library 1

Open `app.mjs` inside `DEMO_REPO` in Muse or your editor. Change only:

```js
export const enforceOwnership = false;
```

to:

```js
export const enforceOwnership = true;
```

This changes the actual `canReadInvoice` behavior used by the running server. The fixture reloads edited source automatically; no restart is needed. In a deployed product journey, this point would be a real deployment before retesting. The skeleton's `--build` value is an operator label, not deployment attestation.

```bash
bp retest "$INVOICE_FINDING" --build walkthrough-invoice-fixed
bp test list
bp test export --all
cd "$DEMO_REPO"
node --test tests/security/bypass/*.test.mjs
```

**Show:** `fixed_verified`; owner 200, outsider 403, anonymous 401; one saved check created automatically; one standalone Node test passing. Open the printed `tests/security/bypass/check_….test.mjs` and its copied `bypass-regression-runtime.mjs` to show the expected resource, account controls, and assertion on the replay result.

The exported suite uses only Node built-ins. It does not import Bypass, invoke Muse, or call a model. The test is an asset in the application repository. Real-app exports contain credential-variable names; only fixture exports contain the deliberately public demo values. Scope and ownership still expire and must be refreshed when needed.

## 6. Close Muse, let the worker catch the return, reopen Muse

First start the real local scheduler while the fixed check passes:

```bash
bp monitor add demo-watch --target demo --every 10s
bp monitor worker --detach
bp monitor list
```

**Close the Muse session. Keep the app and local worker running.** In the separate terminal, deliberately reintroduce the invoice defect:

```bash
bp demo regress
```

Label this action on screen: **“Deliberate regression for the demo.”** Wait for the next scheduled run (normally about ten seconds plus request time), then:

```bash
bp monitor list
bp context
```

Copy `lastRunId` from `demo-watch` and inspect that exact run:

```bash
MONITOR_RUN='run_REPLACE_WITH_LAST_RUN_ID'
bp --json run show "$MONITOR_RUN"
node --test "$DEMO_REPO"/tests/security/bypass/*.test.mjs
```

**Show:** the scheduled run has exit `1`, failed HTTP evidence, measured `durationMs`, and `modelCalls: 0`. The standalone test fails too. A run's lifecycle can say `completed` while its check failed; use its exit code and result, not that lifecycle label. Do not substitute a manual `monitor run` and describe it as an automatic scheduled catch.

Start a new Muse session in `DEMO_REPO` and run `/bypass:context`. With the plugin approved, its SessionStart hook also reads the saved local context. **Show:** the previous regression is visible immediately, with the saved check and evidence. Bypass did not need the coding session to stay open.

For the CLI-only version, `bp context` shows the same persisted result. This worker requires an awake machine and a reachable target; cloud scheduling is not connected.

Pause the schedule while presenting the next code change, then repair and retest the invoice:

```bash
bp monitor pause demo-watch
bp monitor worker --stop
bp demo fix
bp retest "$INVOICE_FINDING" --build walkthrough-invoice-restored
```

`demo fix` is a disclosed convenience edit to the fixture's ownership flags. Use the normal source edit instead when showing the developer's editing experience.

## 7. Ship a new route and grow the library to 2

Add the invoice-export behavior:

```bash
bp demo add-route
node --test "$DEMO_REPO"/tests/security/bypass/*.test.mjs
bp coverage
bp scan
bp finding list
```

**Show:** the old standalone invoice-read test still passes its HTTP assertions. That does not cover `/api/exports/invoice-acme-001`. Bypass conservatively marks the old check **stale** because source changed, and the mock discovery adapter adds a separate export candidate. Current freshness uses a whole-source fingerprint, not precise route-level change analysis.

Copy the **new export finding's** ID, leaving `INVOICE_FINDING` unchanged:

```bash
EXPORT_FINDING='finding_REPLACE_WITH_EXPORT_ID'
bp verify "$EXPORT_FINDING"
```

Expected: the second account can retrieve the export; exit `1`, `confirmed_fixture`. In `app.mjs`, change `enforceExportOwnership` from `false` to `true`, preserving `enforceOwnership = true`. Then:

```bash
bp retest "$EXPORT_FINDING" --build walkthrough-export-fixed
bp retest "$INVOICE_FINDING" --build walkthrough-export-fixed
bp test list
bp test run --all
bp test export --all --force
node --test "$DEMO_REPO"/tests/security/bypass/*.test.mjs
bp coverage
```

Retesting the original invoice check refreshes its source evidence after the export change. `--force` regenerates the previously exported Bypass test files with their current bindings; review changes before committing them.

**Closing proof:** two distinct saved checks; both owner/outsider/anonymous control sets pass; two independent Node tests pass; replay uses zero model calls. Read and export are separate behaviors. This is not a claim that every route or vulnerability class is covered.

## Presenter run sheet

These are presentation targets, not measured product timings. DNS propagation and model startup belong in rehearsal preparation or a visibly time-compressed onboarding recording.

| Time | Screen and action | Evidence to keep visible |
| --- | --- | --- |
| 0:00–2:00 | Customer repo → staging origin → generated TXT → DNS provider → verify → scope | Actual pending and verified states; exact origin and authorized paths |
| 2:00–3:00 | Choose Muse / local / self-hosted; add account references | Data destination; real connection result if tested; no exposed credentials |
| 3:00–4:00 | Explicitly switch to Ledger; scan and verify | Simulated candidate label, followed by real 200/200/401 fixture evidence |
| 4:00–5:00 | Edit source; retest; open and run the exported file | 200/403/401; library 1; standalone pass |
| 5:00–6:30 | Close Muse; introduce regression; worker detects; reopen Muse | Scheduled run ID, failure, elapsed time, zero model calls, retrieved context |
| 6:30–8:00 | Add export route; old assertion still passes; prove and fix export | Explicit stale/uncovered distinction; library 2; two standalone passes |

For a three-minute cut, show a short recording of the real onboarding first, then concentrate on proof → saved test → scheduled catch → library growth. Do not skip ownership from the story or imply that a prepared fixture performed live DNS verification.

## CI, cleanup, and the next development milestone

`ci init` can generate a GitHub Actions workflow and exported tests. Before enabling it, the same Bypass project needs a verified, authorized **deployed** target and explicit saved-test bindings with real test-account environment references. A hosted GitHub runner cannot reach this laptop's loopback fixture. CI generation does not deploy the app, push code, or provision secrets. See [test binding and CI commands](COMMANDS.md).

When finished with this rehearsal:

```bash
bp monitor pause demo-watch
bp monitor worker --stop
bp demo stop
```

To stop testing a connected customer app, use `bypass --project "$CUSTOMER_REPO" target revoke staging`. This removes its authorization and pauses its monitors while retaining evidence.

The next engine milestone is to run this same prove/fix/save loop against the customer's verified deployment: actual source-derived candidates, live investigation and counter-evidence, and a deployed fix retest. Local/self-hosted analysis comparisons, an external pilot, and a measured Muse-only baseline are also future evidence; the current smoke checks and fixture do not establish those claims.
