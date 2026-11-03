# AI execution modes — 0.5

## Architecture

| Mode | Reasoning | Execution | Credentials |
| --- | --- | --- | --- |
| Muse plugin (`muse-host`) | Active Muse session plans, interprets, follows up and fixes | Typed MCP source/proof tools; shared executor | No provider key or subscription token access |
| Standalone (`standalone-api`) | Explicit provider API session; orchestrator + two isolated Docker workers | Same source grounding, scoped HTTP proof, evidence, checks | Only the configured environment-variable reference |

`execution-mode.mjs` binds the mode to asynchronous request context. The provider entry point rejects host mode before looking up the selected credential or opening a connection. Plugin model-configuration/check tools explain host ownership; they cannot configure or invoke a model. No nested Muse inference path exists.

`host-review.mjs` persists host-directed sessions: `bypass_scan` prepares inventory, saved-test replay and approved resources; `bypass_review_step` exposes read, source-hypothesis, probe, status, finish and cancel. Muse chooses each operation. `security-execution.mjs` is shared with CLI agents and derives finding status exclusively from grounded source or observed HTTP controls. Normal Muse coding tools propose/apply customer fixes under host permissions; Bypass verifies them. POC scope is account boundaries on JSON resources, not arbitrary generated-code execution.

Source access is restricted to eligible inventory, exact file hashes and actually read lines. A changed snapshot requires a new review. Reads are bounded to eight files per request, 400 lines/64 KB per excerpt and 192 KB total. A host review permits 32 operations over 24 hours. Evidence is persisted after every operation; status resumes after a disconnect, cancellation retains evidence, and retries do not restart onboarding. Large source/evidence remains local; compact receipts reference `.bypass/runs/<id>.json`.

## Native host contract

Muse 1.4.13 supports native plugin skills, slash commands, session hooks and stdio MCP tools. Its MCP initialization does not attest the active billing mode. An account allowance cannot prove which billing route a particular chat uses. Bypass reports **unknown / unverified**, never reads credential files, and instructs users to select subscription mode if the host indicates API billing. Auth/quota recovery belongs to Muse; there is no separately billed fallback. Confidential/personal content requires Standard mode with Contributor mode off; Bypass never changes account settings.

References: [native MCP plugins](https://meta-models.github.io/muse-code-sdk/next/guides/plugins/concepts/mcp-servers/), [native plugin lifecycle](https://meta-models.github.io/muse-code-sdk/next/guides/plugins/), [Contributor requirements](https://dev.meta.ai/help/subscriptions/muse-code-contributor-mode). Installed host validator/help is also checked, because the online `next` documentation can be newer than an installed host.

## Provider matrix

Official contracts checked **2026-10-27**. Defaults are explicit configuration values, not promises of access. A provider can change aliases, availability or pricing. Enter an exact model ID when reproducibility matters. Bypass never substitutes a different model.

| Preset | Default API base / key variable | Default model | Bypass transports | Limits |
| --- | --- | --- | --- | --- |
| `meta` | `https://api.meta.ai/v1` / `MODEL_API_KEY` | `muse-spark-1.3` | Responses default; Chat optional | Responses replays encrypted reasoning. Chat has no cross-turn reasoning continuity. Standard model default. [Official protocols](https://dev.meta.ai/docs/protocols), [model catalog](https://dev.meta.ai/docs/overview) |
| `openai` | `https://api.openai.com/v1` / `OPENAI_API_KEY` | `gpt-6-luna` | Responses default; Chat optional for compatible models | Responses replays output/reasoning items with `store:false`; Chat needs a model that supports it. [Models](https://developers.openai.com/api/docs/models), [tool calling](https://developers.openai.com/api/docs/guides/function-calling) |
| `anthropic` | `https://api.anthropic.com/v1` / `ANTHROPIC_API_KEY` | `claude-opus-5-5` | Chat only | Official OpenAI SDK compatibility path. No extended thinking through this adapter; `reasoning_effort`, strict schemas and `response_format` are ignored by the compatibility layer. Bypass rejects effort overrides, omits response_format, uses automatic tool choice and validates locally. Some account keys also need a workspace header. [Official compatibility](https://platform.claude.com/docs/en/cli-sdks-libraries/libraries/openai-sdk) |
| `moonshot` | `https://api.moonshot.ai/v1` / `MOONSHOT_API_KEY` | `kimi-k3.1-pro` | Chat | Kimi is Moonshot's model family. Preserve `reasoning_content` with tool messages. Use model defaults; explicit effort overrides and Moonshot Responses are not enabled in this adapter yet. [Official quickstart](https://platform.kimi.ai/docs/get-your-api-key) |
| `deepseek` | `https://api.deepseek.com` / `DEEPSEEK_API_KEY` | `deepseek-flash` | Chat default; Responses optional | Preserve Chat reasoning_content; Responses is stateless and replays all output items. Explicit effort accepts none/low/high/max. [Quickstart](https://api-docs.deepseek.com/quick_start), [thinking](https://api-docs.deepseek.com/guides/thinking_mode/), [Responses](https://api-docs.deepseek.com/api/create-response/) |
| `custom` | Explicit `--base-url` / `BYPASS_MODEL_API_KEY` | Required | Explicit Chat or Responses | Requires a nonempty credential variable; a no-auth loopback server can use the placeholder below. No inferred capabilities or proprietary reasoning parameters. HTTPS remotely; HTTP permitted on explicit loopback. Private networks require explicit opt-in. |

All presets use the pinned official OpenAI JavaScript SDK. Release builds bundle it into a portable module with its license. Each provider session uses one model and destination, zero automatic retries, a bounded timeout/output budget, streamed completion assembly, cancellation and locally validated arguments/results. SDK debug logging is disabled. Implicit SDK organization, project, alternate credentials and custom headers are not forwarded; only the configured key and optional explicit Anthropic workspace header reach the chosen endpoint. Truncated, malformed, unknown or multiple actions do not execute. Chat replays exact tool IDs/results and provider reasoning state; Responses replays output items and matching function outputs without relying on server persistence. Reasoning stays ephemeral and is never included in progress or saved reports.

Claude forced tool calls are not used because current model families can reject them. A valid JSON result is also accepted only after local validation; prose or malformed results stop the review. Requests use one bounded action schema, not arbitrary shell tools. Token defaults are 8192, configurable 32–32768; timeout defaults to 60 seconds, configurable 1–180 seconds or explicitly disabled with `--timeout-ms 0`. Model-specific unsupported settings are surfaced as provider errors, never silently stripped or retried on another protocol. Auth, rate-limit, request-format, timeout and transport failures have separate recovery messages; raw provider bodies and keys are not logged.

## CLI examples

Load keys privately in your launching environment or secret manager. These commands store references, never key values. Run from an initialized application directory:

```bash
bypass model add meta-api --provider meta --secret-env MODEL_API_KEY
bypass model add openai-api --provider openai --secret-env OPENAI_API_KEY
bypass model add claude-api --provider anthropic --secret-env ANTHROPIC_API_KEY
bypass model add kimi-api --provider moonshot --secret-env MOONSHOT_API_KEY
bypass model add deepseek-api --provider deepseek --secret-env DEEPSEEK_API_KEY
bypass model add private-api --provider custom --base-url https://models.example.com/v1 --model your-model --secret-env PRIVATE_MODEL_API_KEY --transport chat
bypass model use openai-api
bypass model test openai-api
```

Use `--model` for an exact ID; `--transport`, `--max-output-tokens`, `--timeout-ms`, `--stream false` and supported `--effort` are explicit. For an Anthropic account key needing workspace selection, add `--workspace-env ANTHROPIC_WORKSPACE_ID`. Changing a preset to a different origin requires an explicit `--secret-env`; no default credential is forwarded automatically. Redirects are not followed. The URL is used as supplied, without appending an invented `/v1` path.

For slower local inference, create a profile with `--timeout-ms 180000` and select it with `model use`. Source-review progress displays the selected profile's per-request timeout. Adding or testing another profile does not switch an existing active profile, and a running review keeps the profile it started with.

## Local Muse Glimmer source review

Run an OpenAI-compatible Muse Glimmer server separately at
`http://127.0.0.1:8080/v1` (the local model's default endpoint) and keep Docker running. Bypass does not launch the
model. This standalone workflow connects directly to your local server; do not
invoke the Muse CLI, which uses its own model configuration.

Check the server's exact model ID:

```bash
curl --fail http://127.0.0.1:8080/v1/models
```

From the Bypass checkout, set your application path. If it is not initialized,
run `npm start -- init "$APP"` first. For a server without authentication:

```bash
export APP=/path/to/your/app
export BYPASS_LOCAL_MUSE_KEY=local-muse-no-key

npm start -- model add glimmer-local-180s \
  --provider custom \
  --base-url http://127.0.0.1:8080/v1 \
  --model Muse-Glimmer-30B \
  --secret-env BYPASS_LOCAL_MUSE_KEY \
  --transport chat \
  --timeout-ms 180000 \
  --project "$APP"

npm start -- model use glimmer-local-180s --project "$APP"
npm start -- model list --project "$APP" --json
npm start -- model test glimmer-local-180s --project "$APP"

npm start -- engine use docker --project "$APP"
npm start -- scan --mode code --project "$APP"
```

Replace `Muse-Glimmer-30B` if your server exposes a different ID. With an installed
CLI, replace `npm start --` with `bypass`. Create the profile once; on subsequent
runs, export the placeholder variable in the launching shell and reuse the saved
profile. For an authenticated local server, load its actual key privately into
the same variable instead.

The no-auth option still sends `Authorization: Bearer local-muse-no-key`; the
server must tolerate this placeholder. Guided onboarding also offers **Local Muse
model → No API key**. Generic `API-key billing` progress wording does not imply
cloud inference or a charge; the selected profile controls the destination.

Before scanning, confirm that `model list` shows `"active": "glimmer-local-180s"`
and that profile has `"timeoutMs": 180000`. The scan should name
`glimmer-local-180s / Muse-Glimmer-30B`, with waiting messages ending in `/ 180s`.
The timeout is per model request, not the total scan duration.

If the scan still names `local-muse`, explicitly run `model use` for the new
profile. Stop and restart any scan already in progress; changing profiles cannot
change its saved configuration. Older checkouts always printed `/ 60s` in waiting
messages even when the selected profile had a longer timeout; update the checkout
for accurate progress.

If setup says **simulated**, the project retained its offline/mock engine.
`engine use docker` selects real inference without changing the model profile.
If a request still times out at 180 seconds, inspect the local server's generation
and streaming logs. An incomplete review is not a completed security result.

### Disable the model timeout

For local generation that takes longer than 180 seconds, explicitly opt into
unlimited waiting with `--timeout-ms 0`. From the checkout, with `APP` and
`BYPASS_LOCAL_MUSE_KEY` exported as above:

```bash
npm start -- model add glimmer-local-unlimited \
  --provider custom \
  --base-url http://127.0.0.1:8080/v1 \
  --model Muse-Glimmer-30B \
  --secret-env BYPASS_LOCAL_MUSE_KEY \
  --transport chat \
  --timeout-ms 0 \
  --project "$APP"

npm start -- model use glimmer-local-unlimited --project "$APP"
npm start -- model list --project "$APP" --json
npm start -- model test glimmer-local-unlimited --project "$APP"
npm start -- engine use docker --project "$APP"
npm start -- scan --mode code --project "$APP"
```

Verify `"active": "glimmer-local-unlimited"` and `"timeoutMs": 0`. Waiting
messages now show `/ no timeout · cancel to stop`. Restart any existing scan
after switching profiles.

This disables the model-request deadline, socket inactivity timeout, synthetic
connection-check deadline, and Docker review worker's ten-minute deadline for
`scan`. Cancellation still works; a stalled server can wait indefinitely until
you cancel. Token, call, evidence, and container resource limits remain.
Discovery/evaluation task leases and running-app authorization/run budgets are
separate safeguards and are not disabled by this model setting. Other profiles
retain their configured timeouts; the default remains 60 seconds.

## Migration

Existing evidence and app configuration remain valid. Old `muse-code`, `local` and `endpoint` profiles remain visible but are blocked for standalone AI; Bypass never reads a coding-agent credential store or translates a subscription login into an API key. Create a new profile above, explicitly select it with `model use`, then optionally run `model test`. For a self-hosted/local server use `custom` and its API key, or the documented placeholder for a no-auth loopback server. Standalone inference always requires a nonempty credential environment variable.

Inside Muse, ignore old provider profiles: update/approve the plugin and open a new session. Run `/bypass:review`; no model migration or separate key is needed. Old background scans remain historical; start a new host-directed review instead of trying to resume their former internal AI loop. Deterministic tests, reports, memory, ownership and app setup remain usable without an AI key.
