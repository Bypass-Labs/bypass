# Walkthrough: make the direction concrete

Use the terminal menu for product review, and keep the Ledger browser page beside it. Everything below uses the same CLI/service layer as the Muse plugin.

## 1. First-time onboarding

Run `./bypass init /path/to/repo` without `--non-interactive` to see the setup wizard. It connects the repository, asks which inference provider to use, and offers to connect an app.

The three model choices are **Muse Code subscription**, **local model**, and **your compatible self-hosted endpoint**. A connection test is optional and sends a synthetic prompt. The mock discovery engine never secretly calls a selected model.

For a deployed app, setup stops at a real pending ownership challenge. The customer publishes the exact TXT record or HTTPS challenge value. After verification they authorize path prefixes, methods, expiry, and a request rate. Production is a separate acknowledgment. A repository can still receive a code-only simulated review while DNS is pending.

Test identities are optional at setup. They are references to environment variables containing bearer tokens, cookies, or custom header values. Two distinct accounts and a stable owned resource are needed for an account-boundary regression. No real credentials are accepted in flags or written to configuration.

## 2. Immediate demo without external setup

From the package directory:

```bash
./bypass demo start
./bypass --project .demo/ledger
```

The demo creates a real local Git repository, two public test identities, an authorized loopback target, and a functioning HTTP application. Open http://127.0.0.1:4317 and try the invoice as both accounts. Before the fix, both receive HTTP 200.

The dashboard shows the connected repository, target, model profile, local evidence, saved-test counts, worker state, and next action. **MOCK ANALYSIS** is always visible.

## 3. Review and prove

Choose **4 → Run a review**. The plan explains scope and data destinations before execution. The real workflow stores a run ID and stages. It replays any saved checks before the simulated discovery adapter returns a clearly labeled candidate.

Choose **5 → Findings → the invoice candidate → verify**. The fixture verifier makes three real HTTP requests:

| Control | Vulnerable fixture | Fixed fixture |
| --- | --- | --- |
| Owner requests their invoice | 200 with the expected invoice ID | 200 with the expected invoice ID |
| Another account requests the same invoice | 200 with the expected invoice ID | 403 |
| Anonymous request | 401 | 401 |

A missing owner token, wrong fixture ID, server error, or redirect produces **blocked**, not “fixed.” Proof is labeled **confirmed fixture** and is never generalized to another application.

## 4. Fix through normal source editing

Open `.demo/ledger/app.mjs` in Muse. Change:

```js
export const enforceOwnership = false;
```

to:

```js
export const enforceOwnership = true;
```

The local server reloads the fixture module when its contents change. No restart is needed. The flag is used by the actual `canReadInvoice` function that serves the requests. `demo fix` is a convenience control for the same source edit.

Retest the finding. Both the owner positive control and access-denial controls must pass. A successful retest saves a regression check automatically. It records an operator-supplied build label separately from observed HTTP evidence.

## 5. Show the durable value

Choose **6 → Export standalone Node tests**, then run:

```bash
node --test .demo/ledger/tests/security/bypass/*.test.mjs
```

The generated test and small copied runtime use Node built-ins. They do not need Bypass, Muse, a model key, or the Bypass source tree. Real environment bindings contain credential-variable names, never credential values. Demo bindings contain only deliberately public fixture tokens.

Choose **9 → Reintroduce regression**, then **6 → Replay all saved tests**. The test fails with actual HTTP evidence and `modelCalls: 0`. It also fails when executed as an independent Node test.

## 6. Show what still needs investigation

Fix and retest again, then choose **9 → Add uncovered export route**. Run another review. A previously passing test becomes stale because eligible source changed; the new export behavior returns to the simulated investigation queue. One saved invoice-read check does not establish complete coverage of the export route.

The fixture has a second explicit `enforceExportOwnership` flag. Fix it and retest to save a separate regression for that behavior.

## 7. Monitoring and the next session

Create a local monitor, start the worker, and close Muse:

```bash
./bypass --project .demo/ledger monitor add hourly --target demo --every 1h
./bypass --project .demo/ledger monitor worker --detach
```

For a faster presentation use `--every 10s`. The worker replays saved checks without a model and persists results independently of Muse. An awake machine and reachable target are required. There is no invisible hosted worker.

On the next Muse session, the approved SessionStart hook includes a compact monitor summary. `/bypass:context` or CLI `context` shows details. Failed, blocked, and stale checks stay visible. Pausing a schedule, revoking a target, and stopping the worker have distinct effects.

## 8. Review questions for today

1. Does setup make the repository → target → ownership → scope → identities → provider sequence understandable?
2. Can a developer immediately tell a simulated candidate from actual fixture proof?
3. Is the owner positive control clear enough to trust the fix verification?
4. Does the exported test feel like an asset the team owns?
5. Does the next-session context identify a useful action without claiming blanket coverage?

## Restart and cleanup

`demo reset` resets fixture behavior and preserves history. Use a fresh `demo start --dir /new/empty/path --port 4327` for a clean first-time run. Stop scheduling with `monitor worker --stop`; stop the fixture with `demo stop`. This does not delete the repository or evidence.
