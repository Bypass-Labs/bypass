# Real POC — host reasoning and shared execution

Version 0.5 separates two AI execution modes. Source reads, real scoped HTTP controls, evidence and regressions are shared; the identity of the reasoning agent is explicit.

## Plugin demo — primary path

Inside an approved, fresh Muse session, run `/bypass:demo`. Muse reviews an isolated fixture's actual source, chooses its approved account-boundary test, interprets observed unauthorized access, fixes the fixture, retests and exports a regression. No internal model calls, nested Muse invocation, separate API key or Docker are needed. [Exact demo journey](WALKTHROUGH.md).

Muse subscription billing is not attested through MCP. Bypass reports that limit; it does not infer billing from credentials or allowance. Select subscription mode in the host. Confidential source requires Standard mode; the fixture contains only public synthetic accounts.

## Standalone API/Docker POC

Requires Git, Docker and an explicit provider API-key profile. No Muse installation or login is used for inference. First configure the provider in your application or a separate initialized working folder:

```bash
bypass init .
bypass model add api --provider openai --secret-env OPENAI_API_KEY
bypass model use api
bypass model test api
bypass poc start --dir /tmp/bypass-api-fixture --project .
bypass scan --mode combined --project /tmp/bypass-api-fixture
```

The environment variable must already contain your privately supplied API key. The POC copies the explicitly selected profile, creates a separate local fixture, and configures its public accounts and authorized resource. It never picks a subscription backend. Without a profile you can create the fixture, but must explicitly configure a provider before an AI scan.

The source planner and one bounded Docker source worker use the selected profile. The worker has no network, credentials, source mount or Docker socket; it requests bounded excerpts through the broker and is removed on completion/error/cancellation. The host black-box runner performs all HTTP discovery and proof under the saved scope, rechecking current ownership and testing authorization.

Inspect `finding list` / `finding show <id>`. Fix the generated fixture's `policy.mjs` to require `account === invoice.ownerId`, then run:

```bash
bypass retest <finding-id> --project /tmp/bypass-api-fixture
bypass test export --all --project /tmp/bypass-api-fixture
bypass test run --all --project /tmp/bypass-api-fixture
bypass poc stop --project /tmp/bypass-api-fixture
```

Use the printed paths/IDs, not literal placeholders. Saved tests require current app authorization and account access, but no model API key. Reintroducing the fixture bug makes the saved test fail; restore the fix before stopping.

## Evidence boundaries

- Cited source is a hypothesis until observed HTTP controls establish unauthorized access.
- Owner/other-account identity controls must be distinct and valid; invalid logins are blocked execution, never a passing negative control.
- A fixed behavior becomes a regression only after prior confirmation and successful retesting.
- Only exact saved behaviors passing in the current replay can exclude further probes.
- Source knowledge and prior evidence help future feature work; changed source makes knowledge stale.
- The POC covers configured JSON authentication/account boundaries, not general browser pentesting or every vulnerability class.

[Provider contracts and migration](AI_MODES.md) · [Observed validation](AI_VALIDATION.md). Historical evidence files from earlier versions describe their own old architecture and do not validate the current host mode.
