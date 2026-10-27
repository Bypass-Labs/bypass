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
| `custom` | Explicit `--base-url` / `BYPASS_MODEL_API_KEY` | Required | Explicit Chat or Responses | Requires a key even on loopback. No inferred capabilities or proprietary reasoning parameters. HTTPS remotely; HTTP permitted on explicit loopback. Private networks require explicit opt-in. |

All presets use the pinned official OpenAI JavaScript SDK. Release builds bundle it into a portable module with its license. Each provider session uses one model and destination, zero automatic retries, a bounded timeout/output budget, streamed completion assembly, cancellation and locally validated arguments/results. Truncated, malformed, unknown or multiple actions do not execute. Chat replays exact tool IDs/results and provider reasoning state; Responses replays output items and matching function outputs without relying on server persistence. Reasoning stays ephemeral and is never included in progress or saved reports.

Claude forced tool calls are not used because current model families can reject them. A valid JSON result is also accepted only after local validation; prose or malformed results stop the review. Requests use one bounded action schema, not arbitrary shell tools. Token defaults are 8192, configurable 32–32768; timeout defaults to 60 seconds, configurable 1–180 seconds. Model-specific unsupported settings are surfaced as provider errors, never silently stripped or retried on another protocol. Auth, rate-limit, request-format, timeout and transport failures have separate recovery messages; raw provider bodies and keys are not logged.

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

## Migration

Existing evidence and app configuration remain valid. Old `muse-code`, `local` and `endpoint` profiles remain visible but are blocked for standalone AI; Bypass never reads a coding-agent credential store or translates a subscription login into an API key. Create a new profile above, explicitly select it with `model use`, then optionally run `model test`. For a self-hosted/local server use `custom` and its API key. Keyless inference is intentionally unsupported in standalone mode.

Inside Muse, ignore old provider profiles: update/approve the plugin and open a new session. Run `/bypass:review`; no model migration or separate key is needed. Old background scans remain historical; start a new host-directed review instead of trying to resume their former internal AI loop. Deterministic tests, reports, memory, ownership and app setup remain usable without an AI key.
