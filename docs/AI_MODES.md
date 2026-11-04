# AI execution modes — 0.5

## Architecture

| Mode | Reasoning | Execution | Credentials |
| --- | --- | --- | --- |
| Muse plugin (`muse-host`) | Active Muse session plans, interprets, follows up and fixes | Typed MCP source/proof tools; shared executor | No provider key or subscription token access |
| Standalone (`standalone-api`) | Explicit provider API session; one isolated Docker source worker plus the host black-box runner | Cited source grounding, broad scoped HTTP proof, unified evidence and checks | Only the configured environment-variable reference |

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
| `custom` | Explicit `--base-url` / `BYPASS_MODEL_API_KEY` | Required | Explicit Chat or Responses | Requires a nonempty credential variable; a no-auth loopback server can use the placeholder below. Explicit effort accepts minimal/low/medium/high/xhigh/max when supported by your endpoint; no capability inference or proprietary reasoning parameters. HTTPS remotely; HTTP permitted on explicit loopback. Private networks require explicit opt-in. |

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

### Select minimal reasoning for local Glimmer

Glimmer's server-side template can default to high reasoning strength. If
generation is slow or returns reasoning without a final action, explicitly try
`--effort minimal`. Bypass forwards this as `reasoning_effort: "minimal"` for Chat
or `reasoning: {"effort": "minimal"}` for Responses. Custom profiles accept
`minimal`, `low`, `medium`, `high`, `xhigh`, and `max`; the endpoint must support
the chosen value. No override is sent when `--effort` is omitted, and unsupported
settings fail explicitly without automatic retries or fallback.

From the checkout, with `APP` and `BYPASS_LOCAL_MUSE_KEY` exported:

```bash
npm start -- model add glimmer-local-minimal \
  --provider custom \
  --base-url http://127.0.0.1:8080/v1 \
  --model meta-models/Muse-Glimmer-30B-GGUF:Q4_K_M \
  --secret-env BYPASS_LOCAL_MUSE_KEY \
  --transport chat \
  --effort minimal \
  --stream false \
  --timeout-ms 0 \
  --project "$APP"

npm start -- model use glimmer-local-minimal --project "$APP"
npm start -- model list --project "$APP" --json
npm start -- model test glimmer-local-minimal --project "$APP"
npm start -- engine use docker --project "$APP"
npm start -- scan --mode code --project "$APP"
```

Use your server's exact model ID. Verify `"active": "glimmer-local-minimal"`
and that the selected profile has `"effort": "minimal"`. Restart existing scans
after switching profiles. This changes reasoning strength, not schema enforcement
or validation; it does not guarantee a successful review. The combination above
also selects buffered output and unlimited waiting.

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
Standalone discovery/evaluation also disables its per-task and overall
reasoning-stage timeouts for these profiles. CodeQL extraction/analysis resource
timeouts and running-app authorization/run budgets remain separate safeguards. Other profiles
retain their configured timeouts; the default remains 60 seconds.

### Connection interrupted despite no timeout

`API connection interrupted or destination rejected` is not a model-timeout
message. The current transport reports both a broken connection and a response
size-limit failure with this generic error, so it does not establish the cause.

Bypass limits each API response to **1 MiB of received bytes**. With streaming
enabled (the default), this includes every SSE event's JSON framing and metadata,
not just generated text. Many small chunks can exhaust this limit before the
default **8192 output-token** budget. Disabling the timeout does not disable
either limit. Context capacity is separate: check your server's actual
configuration rather than assuming the model's advertised context is available.
A completed response reporting token truncation produces
`Model output incomplete or filtered`; a context rejection typically produces an
HTTP request error, though a server can also fail mid-stream.

To test whether streaming overhead is responsible, create a buffered profile.
With `APP` and `BYPASS_LOCAL_MUSE_KEY` exported as above:

```bash
curl --fail http://127.0.0.1:8080/v1/models

npm start -- model add glimmer-local-buffered \
  --provider custom \
  --base-url http://127.0.0.1:8080/v1 \
  --model meta-models/Muse-Glimmer-30B-GGUF:Q4_K_M \
  --secret-env BYPASS_LOCAL_MUSE_KEY \
  --transport chat \
  --stream false \
  --timeout-ms 0 \
  --project "$APP"

npm start -- model use glimmer-local-buffered --project "$APP"
npm start -- model list --project "$APP" --json
npm start -- model test glimmer-local-buffered --project "$APP"
npm start -- engine use docker --project "$APP"
npm start -- scan --mode code --project "$APP"
```

Replace the GGUF model ID with the exact `data[].id` returned by your server.
Verify the active profile is `glimmer-local-buffered`, with `"stream": false`
and `"timeoutMs": 0`, and restart any existing scan. Buffered mode waits for the
complete response instead of consuming token events; waiting heartbeats and
cancellation remain available. The 1 MiB response limit still applies, but there
is no per-token SSE overhead.

If buffered mode succeeds, that supports (but does not prove) the streaming
overhead diagnosis. If it still fails, inspect server logs for context errors,
generation failures, memory pressure, or disconnected clients. Do not treat
partial evidence from an interrupted review as a completed security result.

### Source citation validation stopped the review

`Source citation did not match the actual line` means inference returned a
candidate, but its quote was not an exact match (ignoring surrounding whitespace)
for the cited line actually delivered to the model. This is not a timeout or
network error. Saving source interpretations to memory does not establish that
the candidate findings have valid citations.

The CLI reports the candidate number, known source file and cited line, and
whether the file/line was unread, the quote was invalid, or the quote mismatched.
For mismatches it also reports exact matches on other already-read lines, a
line-number prefix, or a multi-line quote when applicable. These are diagnostic
hints only; Bypass never silently changes the citation or accepts an unsupported
finding.

Structured diagnostics are saved in `.bypass/runs/<run-id>.json` under
`result.details.citation`, with `result.details.reason` set to
`source_citation_invalid` and the failure stage set to `white-box`. Diagnostics
include quote/line character counts but not source text or model quotes. Valid
memory interpretations remain saved even when subsequent finding validation
fails. Inspect the indicated source location locally and rerun the review;
partial evidence is not a completed security result.

### Model returned no valid security action

This means the completed model response had no usable `security_action` tool
call and its text could not be parsed as JSON. A simple `model test` checks an
exact reply marker, not reliable tool calling or schema compliance.

Rejected completed responses now print a `Response diagnostics:` progress line.
The same object is saved in `.bypass/runs/<run-id>.json` under
`result.details.responseDiagnostics` and, for Docker source reviews, the failed
entry in `agentEvidence.modelUsage[].responseDiagnostics`.

Diagnostics include transport/streaming mode, content type and character count,
reasoning character count, tool-call count, up to four tool-argument character
counts, and an allowlisted finish reason (`unknown` for unrecognized values).
`jsonSource` distinguishes response content from tool arguments. `jsonStatus`
is `not_attempted`, `empty_content`, `invalid_json`, or `parsed`; `schemaStatus:
"invalid"` means JSON parsed but failed the security-action schema. Raw content,
reasoning, arguments, tool names, and JSON parser exception messages are not
logged. Parsed objects also report `actionFields` (only names declared in the
tool schema) and `unknownFieldCount`; unknown field names and values remain
private.

For example, zero tool calls plus `jsonStatus: "invalid_json"` indicates
non-JSON or malformed JSON text; `empty_content` with a positive reasoning count
indicates reasoning was returned without a final text action. `finishReason:
"length"` indicates truncated generation. Inspect the local server's chat
template/tool support and generation settings accordingly. Diagnostics do not
change action validation or accept unsupported findings. Docker `scan` stops
on invalid actions; standalone `discover` can request corrections as described
below. Provider transport requests still have zero automatic retries.

## CodeQL and policy discovery with local Glimmer

`scan --mode code` is a separate bounded AI source-review workflow focused on
authentication and cross-account access. It does not run CodeQL or the bundled
policy catalog. To use those detectors, run `discover` with the same initialized
application and explicitly selected local model profile.

With `APP` and `BYPASS_LOCAL_MUSE_KEY` exported and the
`glimmer-local-minimal` profile created above:

```bash
npm start -- model use glimmer-local-minimal --project "$APP"

# Preview detector selection without Docker or inference.
npm start -- discover --detector both --plan --project "$APP"

# CodeQL SAST plus AI policy discovery, followed by source-only evaluation.
npm start -- discover --detector both --project "$APP"
```

Other detector choices:

```bash
# Bundled AI policies only; no CodeQL.
npm start -- discover --detector policy --project "$APP"

# CodeQL discovery only; no model calls or automatic evaluation.
npm start -- discover --detector sast --discovery-only --project "$APP"
```

Discovery uses Docker; the selected local model handles policy reasoning and
automatic evaluation. CodeQL queries themselves are deterministic. Run
`npm start -- scanner policies` or `npm start -- scanner rules` to inspect the
available policies/rules. See the [scanner guide](../scanner/README.md) for exact
selectors, source exclusions, CodeQL licensing, and stage budgets.

**Evaluation is enabled by default**, for SAST, policy, combined discovery, and
SARIF import. Each candidate is evaluated against cited source and classified as:

- `confirmed`: supported by source evidence, not runtime reproduction.
- `refuted`: affirmative source evidence disproves the candidate.
- `needs_review`: missing evidence or unresolved conditions.

To defer evaluation for either detector, pass `--discovery-only`. Use the run ID
printed by discovery to inspect or evaluate a saved run:

```bash
npm start -- discover status <run-id> --project "$APP"
npm start -- discover report <run-id> --format md --project "$APP"
npm start -- discover evaluate <run-id> --project "$APP"
```

Explicit evaluation requires unchanged source and the recorded scanner runtime.
Neither discovery nor evaluation tests the running app or proves exploitability.
Unresolved evaluation cases can keep a run incomplete; zero signals or completed
evaluation does not establish complete security coverage.

In Muse Code, `/bypass:discover` runs the same detector/evaluation workflow, but
reasoning uses the **active Muse session**, not your standalone local profile.
Use standalone `discover` to keep reasoning on local Glimmer. In Muse, pass
`discovery-only: true` to `bypass_discover` to skip evaluation.

The model profile's `--timeout-ms 0` disables standalone discovery/evaluation
per-task and policy/evaluation reasoning-stage timeouts, including on resumed
tasks. There is no 300-second task cutoff or 1,800-second reasoning-stage cutoff.
The issued task records `taskTimeoutDisabled: true`,
`stageTimeoutDisabled: true`, and `expiresAt: 0` (no time expiry).
Model-request and per-task evidence-request count limits are also disabled for
zero-timeout profiles, in both discovery and evaluation. Usage is still counted
and saved, including across resumes; reaching 256 model calls or 32 evidence
requests no longer interrupts these profiles. Finite profiles and Muse retain
their configured request limits. Evidence-byte, task-count, attempt-count, and
context budgets still apply, as does cancellation. Deterministic CodeQL timeouts remain.
Finite profiles and Muse-hosted reasoning retain their configured task leases.

Standalone discovery/evaluation tasks have no fixed per-task conversation-turn
cap. A task can continue requesting evidence until its submission is accepted.
Applicable task leases, stage deadlines and request limits, evidence-byte budgets,
conversation-size limits, and cancellation still apply. This does not change
the separate Docker `scan` worker's turn limits.

Standalone scanner actions have mutually exclusive shapes: evidence contains
only `action`, `operation`, and `arguments`; submit contains only `action` and
`result`, matching the task's result schema. Unused fields must be omitted,
not supplied as empty placeholders. Previously the model-facing schema
permitted mixed shapes that the driver rejected as `Invalid policy submission
action`; historical runs do not record which field caused that rejection.

Malformed JSON or schema-invalid actions are never executed or silently
normalized. The driver prints safe response/field diagnostics and returns
validation feedback to the model so it can correct the action within the same
task. Every attempted model request, including corrections, counts against the
applicable budgets; zero-timeout profiles have no request-count limits, while
evidence-byte/context limits and cancellation still apply. Network
and timeout failures still interrupt immediately. If repeated invalid actions
ultimately interrupt the task, its manifest message includes the last safe
rejection feedback. This correction behavior applies to standalone discovery
and evaluation, not Docker `scan` or Muse-hosted reasoning.

An interrupted scanner run prints its failure message and stores its manifest
under `.bypass/scanner/<run-id>/manifest.json`, separately from `scan` evidence.
Standalone start, resume, and evaluate commands print `Scanner run: scan_<id>`
as soon as the scanner returns the run, before scan/model progress. Final
summaries repeat `Run: scan_<id>`. Use that full ID for status/resume/cancel;
the UUID appended to a debug filename identifies the log session, not the run.
Reasoning progress shows completed/total tasks, remaining policy tasks and
deferred work, detector signals, and stage model requests. Evaluation also
shows source-confirmed/refuted/needs-review case counts; its unfinished task
count includes any tasks not completed, including deferred tasks. Counts refresh
when tasks are leased or submissions accepted. Totals can grow as mapping and
follow-ups create tasks; they are not a fixed percentage or ETA. While a model
request is pending, a 15-second heartbeat shows elapsed time and the latest
counts, including in buffered mode. Final summaries repeat both stage counts.
Use `discover status <run-id>` to inspect the saved state and
`discover resume <run-id>` to retry unfinished tasks when the recorded source,
runtime, and applicable stage budgets still permit it. Accepted CodeQL signals and completed
evaluation cases are retained; restarting a run is necessary if its stage budget
has expired.

### Explicit JSON-schema responses

To diagnose repeated corrections, add `--debug-log` to standalone `discover`,
`discover resume`, or `discover evaluate`. The CLI prints a unique local
`.bypass/debug/<run-id>-<uuid>.jsonl` path. Records include timestamps, task/phase,
request counts, elapsed response times, response diagnostics, corrections, and
accepted action/operation names, without source or argument values.

Add `--debug-raw` **together with `--debug-log`** to capture rejected final
content and all tool argument strings for JSON analysis without log-specific
truncation; reasoning, request prompts, credentials, and headers
are not captured. Known environment/registered secrets are redacted, but this
is not comprehensive sanitization: raw output can repeat sensitive repository
data. Keep it local, review before sharing, and delete it after analysis.
Logging is off by default and unavailable in Muse-hosted mode.
Files are created exclusively with owner-only permissions and are outside
scanner report artifacts. There is no log-size cap or automatic rotation;
records continue appending until the command ends. Filesystem write failures
(such as a full disk) are surfaced explicitly. Monitor disk space during long runs.

```sh
npm start -- discover --detector both --project "$APP" --debug-log --debug-raw
```

For a compatible custom server such as local llama.cpp, opt in with
`--response-mode json-schema` when adding the profile. The default is `tools`.
This sends Chat `response_format.json_schema` or Responses `text.format`,
without tool definitions. Bypass still parses and validates final response JSON
locally; invalid responses never execute. Unsupported formats fail explicitly,
with no automatic protocol fallback. A plain `model test` remains a marker
check, not a structured-action compatibility test.

```sh
npm start -- model add glimmer-local-json \
  --provider custom \
  --base-url http://127.0.0.1:8080/v1 \
  --model meta-models/Muse-Glimmer-30B-GGUF:Q4_K_M \
  --secret-env BYPASS_LOCAL_MUSE_KEY \
  --transport chat --response-mode json-schema \
  --effort minimal --stream false --timeout-ms 0 \
  --project "$APP"
npm start -- model use glimmer-local-json --project "$APP"
npm start -- discover --detector both --project "$APP"
```

An empty tool-argument object (`toolArgumentCharacters: [2]`, no `actionFields`)
cannot be corrected by increasing time alone. JSON-schema mode constrains final
content instead of relying on tool argument generation. A local synthetic test
through Bypass's actual scanner driver completed a read and submission in two
Glimmer requests, about 16 seconds, with no rejected actions. No application
source was sent. A complete application discovery run is still required to
verify model reliability on that repository.

This task-timeout change requires the updated pinned scanner image, prepared
automatically on first use. Older runs pinned to a different image cannot be
resumed with the new image; start a new discovery run. Existing artifacts and
accepted signals remain saved. Runtime identity checks are not bypassed.

## Migration

Existing evidence and app configuration remain valid. Old `muse-code`, `local` and `endpoint` profiles remain visible but are blocked for standalone AI; Bypass never reads a coding-agent credential store or translates a subscription login into an API key. Create a new profile above, explicitly select it with `model use`, then optionally run `model test`. For a self-hosted/local server use `custom` and its API key, or the documented placeholder for a no-auth loopback server. Standalone inference always requires a nonempty credential environment variable.

Inside Muse, ignore old provider profiles: update/approve the plugin and open a new session. Run `/bypass:review`; no model migration or separate key is needed. Old background scans remain historical; start a new host-directed review instead of trying to resume their former internal AI loop. Deterministic tests, reports, memory, ownership and app setup remain usable without an AI key.
