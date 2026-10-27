# AI integration validation — 0.5.0

Checked on **2026-10-27**. This report separates execution evidence from compatibility claims. The implementation and migration guide are in [AI_MODES.md](AI_MODES.md).

## Actual Muse host: passed

Muse Code **1.4.13** installed and approved a temporary native plugin under a distinct audit ID. The test used a fresh workspace, normal host permission handling, Contributor mode off for that invocation, and the public local invoice fixture. The customer's installed plugin and account settings were left unchanged by the audit.

The actual host completed **21 successful plugin tool calls**, with no failed tool calls:

1. Started the fixture and selected its repository and local app.
2. Started a host-directed review, read source and submitted a hypothesis citing the missing ownership check.
3. Selected an approved HTTP probe. Bypass observed owner **200**, other account **200**, anonymous **401**, with both account identity controls succeeding.
4. Applied the fixture repair through the fixture tool and verified owner **200**, other account **403**, anonymous **401**.
5. Created and exported the saved regression; replay passed with exit **0**.
6. Reintroduced the deliberate bug; replay failed with exit **1**.
7. Restored the fix and stopped the fixture.

Bypass recorded **zero independent model calls** throughout. Muse performed the reasoning in its active session. This proves the native host workflow; it does **not** attest subscription billing. The supported MCP interface does not expose that attestation. The fixture repair tool is deliberately limited to the generated demo; customer remediation uses Muse's normal coding tools and approvals.

[Sanitized native-host evidence](evidence/muse-host-ai-modes-2026-10-27.json) includes the host tool receipts, source finding, HTTP controls and saved-check results. The full host trace remains local and is not published.

An initial candidate install exceeded its timeout when the SDK was copied as thousands of files. Bundling the pinned official SDK into one portable module fixed the installation; the successful host run used that bundle. This also keeps the downloadable plugin independent of npm on the customer's machine.

## Automated and packaged checks

- Final full local suite with Docker enabled: **116 passed, zero failures, zero skips**, including the packaged SDK and inherited-environment isolation tests.
- The API transport tests use local, scripted HTTP servers. They exercise the actual official SDK, Chat and Responses replay, provider reasoning state, streamed tools, cancellation, malformed arguments, authentication and rate-limit errors, redaction, redirect refusal, credential changes, and provider-specific request settings.
- The standalone loop test uses the actual SDK, **two real Docker workers**, and the actual vulnerable HTTP fixture. Five requests to a **scripted local API** share one configured model; the source read/tool round trip, observed finding, fix and replay pass. This is an integration test, not live-provider reasoning evidence.
- Host-mode tests run with inherited provider keys and an old selected profile present. Independent provider requests are blocked before credential lookup; native source/probe/fix/replay operations still work. Workspace reuse, source-change rejection and cancellation retain evidence.
- Syntax and plugin parity checks pass: **83 public command paths and their options map to 78 typed tools**. Model configuration deliberately stays host-owned inside Muse; parity does not mean allowing independent API inference from the plugin.
- The macOS x64 release bundle builds with its pinned Node runtime. The exact native manifest launches the hook and MCP server from a separate application workspace; the bundled SDK executes without an installed `node_modules` directory.

Reproduce locally:

```bash
npm ci --ignore-scripts
npm run plugin:build
npm run check
BYPASS_DOCKER_TESTS=1 npm test
npm run test:live
node scripts/provider-smoke.mjs
```

`test:live` requires the installed, authenticated Muse host and uses that host's allowance or billing. It does not bypass normal approvals. It creates and removes an isolated candidate plugin and stops its fixture afterward. The provider smoke script sends a synthetic prompt only when that provider's named API key is explicitly available.

## Unverified and limited scope

No authorized provider API keys were present. **Meta, OpenAI, Anthropic, Moonshot and DeepSeek live API smoke tests were not run.** Custom endpoints also require explicit configuration. [Provider smoke report](evidence/api-provider-smoke-2026-10-27.json). Official documentation and local protocol tests support the presets; they do not establish live model availability, account entitlement or end-to-end performance with each provider.

This validation does not test Job Radar production, arbitrary vulnerability classes, an exhausted host allowance, or a complete independent repair of customer code. The implemented POC covers source-grounded authentication/account-boundary hypotheses and configured JSON-resource HTTP controls. A source hypothesis, a blocked probe or an untested resource is never presented as a confirmed vulnerability or a clean security assessment.

The release workflow separately validates Linux/Docker, immutable downloads, native manifest launch, shell PATH setup and the public Windows installer under PowerShell 5.1 and 7 before promoting the main download. Consult the GitHub workflow result for the published commit; local build success alone is not release promotion evidence.
