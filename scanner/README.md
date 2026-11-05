# Whitebox discovery and source evaluation

The Python scanner runs deterministic CodeQL discovery inside Docker: source
snapshot → per-language extraction → pinned queries → unevaluated signals and
reports. Policy discovery and automatic source-only evaluation use a bounded
reasoning task loop. Runtime reproduction and patching remain unavailable.

The Bypass scanner source is licensed under [Apache-2.0](../LICENSE). The
CodeQL CLI is downloaded separately under [GitHub's usage terms](https://github.com/github/codeql-cli-binaries/blob/main/LICENSE.md).
Bypass's license does not grant CodeQL rights for private or commercial code.
Policy-only mode does not use CodeQL. [Dependency notices](../THIRD_PARTY_NOTICES.md).

## Prerequisites

A running Docker daemon is required for `scanner prepare` and every discovery
run. Plans (`--plan`) and `scanner policies` need none. Run `bypass scanner doctor`
even when Docker is missing or stopped; it reports `docker.reason` and exact
`docker.remediation` commands for the detected setup.

On macOS, the `docker` CLI is only a client. Start Docker Desktop
(`open -a Docker`) or use Colima (Homebrew):

```sh
brew install colima docker
colima start                 # or: colima start <profile>
docker context use colima    # named profile: colima-<profile>
docker version               # must print a Server version
```

On Linux, start Docker Engine (for example `sudo systemctl start docker`).
Bypass never auto-starts a VM. Keep several GB of free disk for the first image
build. If `docker version` prints only client info, check `docker context ls`
and, on macOS, `colima list` before retrying; a stopped profile or wrong context
can block the scan even though the CLI is installed.

## Select detectors and rules

`--detector sast` is the default; `codeql` remains an alias. Select `policy` for
AI policy discovery or `both` for SAST followed by policy discovery on the same
snapshot. `codeql,policy` and `sast,policy` are also accepted.

```sh
bypass scanner policies
bypass discover --detector policy --plan
bypass scanner prepare --detector policy
bypass discover --detector policy --policy authz/object-access
bypass discover --detector both --rule py/weak-cryptographic-algorithm \
  --policy authz/object-access \
  --exclude-policy filesystem/path-containment
```

Use actual SAST IDs from `scanner rules`; unknown IDs are errors. `--rule` and
`--exclude-rule` affect only SAST. `--policy` and `--exclude-policy` affect only
policy discovery. Each accepts exact case-sensitive comma-separated IDs. A
nonempty inclusion replaces that detector's defaults; exclusions win. Explicit rule flags require their detector. Saved per-detector settings remain
available when switching modes. Discovery plans and bundled policy lists
require no Docker, model configuration, or inference.

Bundled policies cover authentication and authorization, delegated and reserved
identities, derived-state lineage, interpreter and query injection, browser and
HTTP trust boundaries, AI instruction and output authority, unsafe parsing,
integrations, network and filesystem effects, file and field handling,
credentials, cryptographic trust decisions, sensitive-data lifecycle, migrations,
resource bounds, deployment modes, auditability, exceptional conditions,
workflow integrity, and build/extension execution. The JSON catalog under
`policies/` references Markdown bodies authored once. Mapping assigns only
applicable surface-policy pairs so the broader catalog does not spend the task
budget on clearly unrelated checks. Custom catalogs use the same schema, with
unique IDs and repository-relative in-scope body paths.

The bundled catalog is mapped to current OWASP Web, API, MCP, and GenAI/agentic
risk families in [OWASP policy coverage](../docs/OWASP_POLICY_COVERAGE.md).

```json
{
  "detectors": ["codeql", "policy"],
  "includeRules": ["py/weak-cryptographic-algorithm"],
  "excludeRules": [],
  "includePolicies": ["authz/object-access"],
  "excludePolicies": [],
  "policyCatalogs": ["docs/security/catalog.json"],
  "contextFiles": ["docs/security/threat-model.md"],
  "policyLimits": {"maxTasks":64,"taskTimeoutSeconds":300,"timeoutSeconds":1800}
}
```

Catalog and context inputs are optional. The scanner freezes selected policy
bodies and in-scope root/nested SECURITY.md context, creates a provisional source
map, and schedules surface/policy tasks. Documents are context, not permission to
execute code, read secrets, or change enabled policies. Existing test/example/
generated exclusions apply to evidence reads too; unavailable controls become
proof gaps rather than assumed missing checks.

Muse receives `awaiting_reasoning`, calls `bypass_discover_next_task`, uses
`bypass_discover_evidence` for inventory/literal search/ranged reads, and submits
the declared result schema using issued evidence receipts. Search is navigation;
read receipts are required for citations. Follow `nextAction` and `nextCursor`.
The standalone CLI drives this loop automatically with its selected API profile.
The server does not launch a model or a shell.

Standalone reasoning has no fixed per-task conversation-turn cap: evidence
requests can continue until an accepted submission or a remaining budget,
deadline, or cancellation stops the task. Other workflows retain their own
turn limits. A standalone profile with `--timeout-ms 0` also disables per-task
timeouts: the driver leases tasks with `disableTaskTimeout: true`, and the
issued task records `taskTimeoutDisabled: true`. Zero-timeout standalone
profiles also disable policy/evaluation stage deadlines: tasks record
`stageTimeoutDisabled: true` and `expiresAt: 0`. Finite profiles and
Muse-hosted tasks retain their leases and stage deadlines. CodeQL resource
timeouts, evidence-byte/context budgets, task/attempt limits, and cancellation
remain enforced. Zero-timeout standalone profiles also disable model-request
and per-task evidence-request count limits for policy discovery and evaluation.
Counts remain recorded across resumes without resetting usage. Finite profiles
and Muse-hosted tasks retain request limits. Progress identifies unlimited
request counts explicitly.

Standalone tool schemas distinguish evidence (`action`, `operation`,
`arguments`) from submission (`action`, `result`); unused fields must be absent.
Malformed JSON and schema-invalid actions receive explicit model correction
feedback without executing them. Correction requests consume the same model
budgets and applicable task lease, with no new turn cap. Safe diagnostics identify declared
fields only, never source or argument values. If invalid actions continue until
interruption, the manifest message retains the last rejection feedback.
Transport and timeout failures still interrupt immediately.

Task leases, retry counts, model requests, evidence requests/bytes, follow-up
levels, and run deadlines are bounded. Exact submissions are idempotent. Resume
checks source/runtime/policy identity; expired run budgets require a new run.
Cancellation preserves accepted results. A task budget exhausted with remaining
surfaces yields deferred coverage, never a clean-coverage claim.

Policy-only first use prepares a lightweight Python/git image via Docker's
`policy` target, without downloading CodeQL or compiled-language toolchains.
SAST and combined runs use the pinned CodeQL image. Status/report/artifact tools
can inspect saved v2/v3 runs; the current wire contract is v4. Policy signals
carry policy/task provenance rather than fabricated SARIF result positions.
Policy artifacts include selection, context, threat model, coverage, issued
evidence events, submissions, and signals alongside existing SAST artifacts.

The automated task-loop tests use scripted reasoning responses. They verify
orchestration, citation integrity, execution boundaries, and recovery; they are
not a benchmark of LLM detection quality. Quality depends on the selected model
and repository context. Keep source-grounded hypotheses separate from evaluation.

## Use it

```sh
bypass discover --plan
bypass scanner doctor
bypass scanner prepare                 # optional: prewarm before first use
bypass scanner rules --language javascript --query injection
bypass discover --languages javascript --rule js/command-line-injection
bypass discover status <run>
bypass discover signals <run> --limit 20
bypass discover artifact <run> --path languages/javascript/raw.sarif
bypass discover report <run> --format md
bypass discover resume <run>
bypass discover cancel <run>
```

Connect/select a source repository through Bypass project setup first. Source-only
and code+app profiles work; app-only profiles have no source to scan. Planning
needs neither a project nor Docker. Doctor checks availability without downloads.
`--sarif <file>` imports SARIF 2.1.0 against a fresh snapshot instead of running CodeQL.

In Muse use `/bypass:discover`. Typed tools start asynchronously, poll status,
page signals/artifacts, cancel/resume, and return report references. The direct
CLI waits for completion and prints phase progress. Both use the same Python
implementation. Runs live in `.bypass/scanner/<run>/`, separately from assessment
findings. Original signals are candidates; separate evaluation cases record source verdicts. Zero alerts does not prove
complete coverage.

## Automatic evaluation

Discovery is followed by source-only evaluation by default, for SAST, policy,
combined runs, and SARIF import. Each candidate gets a separate case; original
signals and detector severity/provenance remain unchanged. Deterministic
snapshot/scope checks precede reasoning about controls, reachability,
prerequisites, counterevidence, and impact.

- `confirmed`: supported by cited source evidence, **not runtime reproduction**.
- `refuted`: affirmative source evidence disproves the hypothesis.
- `needs_review`: missing proof or unresolved conditions; retain questions and
  the next action. Unavailable evidence does not establish safety.

Use the discovery-only opt-out to defer evaluation:

```sh
bypass discover --discovery-only
bypass discover evaluate <run>
```

In Muse, pass `discovery-only: true` to `bypass_discover`, or use
`bypass_discover_evaluate` on a saved run. JSON config uses `"evaluation": "off"`
instead of the default `"auto"`. `evaluationLimits` accepts the same bounded
fields as `policyLimits`, but has a separate task, request, evidence, and time
budget. Task-budget exhaustion creates unresolved cases rather than dropping
candidates. A bounded `deep_investigation` task can answer specific source
questions; runtime-only questions remain unresolved.

Default standalone scans require a valid API profile before starting because
evaluation uses reasoning. SAST discovery-only remains independent of API
settings. Zero candidates finish evaluation without model requests. Muse always
uses the active session, never independent inference or provider credentials.

Evaluation uses the existing `next_task` / `evidence` / `submit` loop. Only
evaluation tasks accept verdicts; discovery submissions still cannot assign them.
Issued read receipts bind citations to the task, revision, file hash, and range.
Exact submissions are idempotent. Cancellation/interruption retain accepted
cases; resume checks source/snapshot/image identity and reissues unfinished
leases. Failed SAST queries are retried without discarding accepted evaluations;
new signals get new cases within the original evaluation budget. Expired stage
budgets require a new scan with explicit limits.

Markdown reports list only confirmed findings, ordered by evaluated severity.
Each finding separates the issue, impact, and next action from location/evidence
details, severity rationale, counterevidence, and prerequisites. Summary counts
cover confirmed, refuted, unresolved-after-analysis, and not-analysed candidates;
the latter includes `needs_review` cases without an evidence-backed evaluation.
JSON reports retain all signals and cases unchanged. Inspect `evaluation/cases.json`,
`evaluation/coverage.json`, and evaluation submissions/evidence artifacts.
The Markdown contents list links directly to each confirmed finding. Project
identity is recorded at start for new scans; historical report connections are
labelled as current context, not original scan metadata. Reports show snapshot
identity and source scope, selected/static rules in completed query runs by
language, and selected/distinct reviewed policy rules. A policy reviewed on one
surface does not establish exhaustive coverage. SARIF import records no scanner
query execution; missing historical counts remain explicitly unrecorded.
`signals` pages link candidates to their cases. Any unresolved case or discovery
failure keeps the overall run incomplete; completed evaluation never establishes
complete discovery coverage. Historical reports remain inspectable without
reasoning or source freshness checks; explicit evaluation requires unchanged
source and the recorded runtime.

## Analysis scope

New runs exclude common tests/fixtures, examples/demos/benchmarks, and generated
or vendored copies from the analysis scope by default. This includes `test/`,
`tests/`, `__tests__/`, `fixtures/`, `.test.*`/`.spec.*` files, Python `test_*.py`,
Go `*_test.go`, Java/C# test-name conventions, `examples/`, `benchmarks/`,
`generated/`, `dist/`, `vendor/`, and the packaged duplicate `plugin/runtime/`.
The shared `sourceScope` policy in `protocol/v4.json` lists the exact patterns.

Opt in separately when those sources matter:

```sh
bypass discover --include-tests
bypass discover --include-examples
bypass discover --include-generated
bypass discover --include-tests --include-examples --include-generated
```

The matching `bypass_discover` Muse arguments use the same hyphenated names and
boolean values. JSON config uses `includeTests`, `includeExamples`, and
`includeGenerated`, all defaulting to `false`. Explicit CLI/Muse arguments override
the config file. Nested categories need each applicable opt-in: tests inside
examples require both `includeTests` and `includeExamples`.

Build context is retained so test helpers and build manifests remain available.
No-build extraction receives CodeQL `paths-ignore` filters. Manual/autobuild
extraction can still contain excluded code because CodeQL analyzes code built by
the build command; see [GitHub's build-mode guidance](https://docs.github.com/en/code-security/reference/code-scanning/troubleshoot-analysis-errors/alerts-in-generated-code).
In both modes and for imported SARIF, alerts whose primary locations are all
excluded are omitted from candidate signals. Related locations alone do not bring
a test alert back into scope. Raw SARIF is preserved; filtered-alert references
and reasons are saved in `filtered-signals.json` artifacts.

`analysis-scope.json` records selected paths, exclusions, reasons, and the effective
options. Reports show `scope.analysisFiles`, `scope.contextFiles`, excluded counts,
and filtered alerts. These are scope counts, not proof of extraction coverage.
`sourceReads` counts the retained build snapshot. Inline tests inside production
files remain in scope. Scripts and CI workflows are kept unless a specific path
matches the policy; add project-specific exclusions to `.bypassignore`.

Include options do not override `.gitignore`, `.bypassignore`, credential,
dependency-cache, or symlink exclusions. Existing runs keep their original scope;
start a new run to apply these defaults or change inclusion options.
Build-output caches (`dist`, `target`, `.next`, `coverage`) stay out of the copied
context by default to avoid copying large build artifacts. `includeGenerated`
allows those paths too when they are not otherwise ignored.

## Exact rule selection

The default suite is upstream `security-extended`. Selectors are exact,
case-sensitive CodeQL query `@id` values, also exposed as SARIF `ruleId`:

```sh
bypass discover --rule js/command-line-injection,py/sql-injection
bypass discover --exclude-rule js/command-line-injection
```

Nonempty inclusion replaces the default suite. Exclusions apply afterward and
win on overlap. Unknown IDs, incompatible included languages, and empty selections
fail before database extraction. No wildcard, alias, CWE, or filename matching.
`scanner rules` lists the pinned catalog with pack versions and `defaultSuite`;
`--cursor`/`--limit` page it. Custom Scratch queries are deferred. Auxiliary
upstream metrics/diagnostics remain enabled independently of alert-rule selection.

## Languages and build configuration

| Family (`--languages`) | Sources | Default extraction |
| --- | --- | --- |
| `cpp` | C/C++ | `none` |
| `csharp` | C# | `none` |
| `go` | Go | `autobuild` |
| `java` | Java, Kotlin | `none`; Kotlin triggers `autobuild` |
| `javascript` | JavaScript, TypeScript | `none` |
| `python` | Python | `none` |
| `ruby` | Ruby | `none` |
| `rust` | Rust | `none` |
| `actions` | GitHub workflows/actions YAML | `none` |

Swift extraction is deferred. Detection uses the complete scanner snapshot,
independently of the bounded inventory in the separate source-review workflow.
Each family runs independently; one failed build preserves other languages'
signals. A requested family without applicable files reports `no_files`, not a
successful empty scan. Unsupported sources and coverage gaps remain visible.

Use `--config scanner.json` for builds/resources. Commands are argv arrays; shell
syntax needs an explicitly selected shell. `cwd` is relative to the writable
build copy, never the original source:

```json
{
  "languages": ["java", "javascript"],
  "excludeRules": ["js/command-line-injection"],
  "builds": {
    "java": {
      "mode": "manual",
      "prepare": [["mvn", "-B", "dependency:go-offline"]],
      "command": ["mvn", "-B", "-DskipTests", "clean", "package"],
      "cwd": "backend",
      "network": "on"
    }
  },
  "resources": {
    "threads": 2,
    "ramMb": 4096,
    "memoryMb": 8192,
    "cpus": 2,
    "timeoutSeconds": 900
  }
}
```

The default `timeoutSeconds` is 1,800 (30 minutes). Preparation commands and
extraction share that budget per language; query analysis has a separate budget
of the same length. Diagnostics are limited to 60 seconds. The network-worker
handoff allows 30 extra seconds for startup and fails if no receipt arrives;
expired workers are cancelled and removed. Timeout failures retain artifacts
and leave the language incomplete for inspection or resume. Build/CodeQL/git
subprocesses receive closed input, so they cannot consume MCP protocol messages.
Non-UTF-8 filenames are excluded with an escaped path and reason in
`source-manifest.json`; they do not abort analysis of the remaining source.

Network defaults to `off`. This example explicitly permits dependency downloads
and builds in a separate network-enabled extraction container. The controller and
query-analysis container always use `--network none`. Image preparation downloads
its dependencies regardless of scan settings. Host credentials, registry auth,
Docker sockets, and model configuration are not passed to scans. Private
dependencies need a future explicit credential mechanism; unresolved dependencies
are reported as build failures.

The original repository is mounted read-only. Build snapshots include tracked and
nonignored untracked regular files, excluding symlinks, special files, `.git`,
`.bypass`, dependency caches such as `node_modules`, `.env*`, and private-key files.
`.bypassignore` supports simple glob/prefix exclusions, without negation rules.
Each language builds a writable copy of a content-addressed snapshot. Evidence
locations and hashes refer to that snapshot. Uncitable alerts remain in raw SARIF.

## Installation and Docker

The plugin build generates `plugin/runtime/scanner/` from this directory using an
explicit allowlist. `plugin/runtime/` is ignored build output, not a second source
tree. Plugin and release builds include that generated copy so installations are
self-contained. Edit the sources here and rebuild with `npm run plugin:build`.

Plugin installation ships Python source, protocol, lock file, and Docker recipe.
It does **not** build an image at installation. With
Docker installed/running, the first scan or rule listing builds the local image
automatically. Plugin users need no clone, host Python, or host CodeQL.
`scanner prepare` prewarms the same image.

### Enable scanner tools in Muse

Plugin installation and runtime approval are separate steps. Bypass can be
enabled and `/bypass:discover` visible while its `security` MCP server remains
`review_needed`. In that state, Muse may show **No MCP servers configured** and
the `bypass_discover*` tools will be unavailable.

After reviewing the plugin's runtime permissions, run this in your terminal:

```sh
MUSE_NO_AUTO_UPDATE=1 muse plugins approve bypass
MUSE_NO_AUTO_UPDATE=1 muse plugins inspect bypass --json
```

This approval command was confirmed to resolve the missing tools with Muse Code
1.4.14. In `runtime_capabilities`, check that the `security` MCP server and
`session-context` hook both show `trusted_enabled`. Approval applies to the
current package; changed packages can require a new review.

Start a **new Muse session** in the source repository, then ask:

> Call `bypass_scanner_capabilities` through MCP. If the tool is unavailable,
> report the MCP loading problem and stop without falling back to the shell.

Once that succeeds, use `/bypass:discover`. A local CLI scan verifies the CLI
path; it does not verify that Muse loaded the plugin's MCP server. The packaged
stdio MCP test also runs the server directly, so native Muse activation must be
checked separately. No additional MCP configuration file is needed for the
server declared by the plugin.

### Image contents and execution

The image has a checksum-verified CodeQL bundle, pinned upstream query packs, and
C/C++, .NET, Go, JDK/Maven/Kotlin, Node, Python, Ruby, and Rust toolchains.
`codeql-lock.json` records bundle/checksum and pack versions; catalog construction
rejects mismatches. Images are local/internal builds; public CodeQL image
distribution is not implemented. See [CodeQL CLI availability](https://docs.github.com/en/code-security/codeql-cli/getting-started-with-the-codeql-cli/about-the-codeql-cli)
for licensing requirements.

Containers are Linux AMD64 (emulated on ARM), unprivileged, with a read-only root
filesystem, temporary writable filesystem, and CPU/memory/PID limits. Defaults:
2 threads/CPUs, 4 GiB CodeQL RAM, 8 GiB container memory. Docker needs sufficient
memory/disk for the toolchains and retained databases. Recipes are tagged by
content; each run binds an immutable image ID.

Runs retain source identity, selected rules/catalog, per-language checkpoints,
SARIF, diagnostics, logs, signals, and reports. Cancellation stops process groups;
completed artifacts survive. Lost workers become `interrupted`. Resume verifies
source/snapshot and image/catalog identity, reuses finalized extraction, and skips
completed query stages. Changed source/image requires a new run. No Scratch run
migration is implemented. Reports retain unknown coverage rather than claiming
that successful query execution established complete extraction.

## LLM boundary

SAST/CodeQL discovery and SARIF import make **zero model calls** and require no
LLM settings when run with `--discovery-only`. Automatic evaluation is a separate
reasoning stage; default standalone scans check API readiness before discovery.
Policy-only and combined runs perform policy mapping and discovery through
`next_task`, `evidence`, and `submit`.

Inside Muse the active session supplies all reasoning with its current settings.
The plugin never looks up an API profile, reads model credentials, or performs
independent inference. It cannot attest subscription billing or count host tokens;
reports show zero independent requests and unknown host usage, rather than claiming
no AI reasoning occurred. Direct CLI policy execution requires an explicit saved
API profile and runs the same bounded protocol through `src/scanner/api-driver.mjs`.
Its request attempts are recorded; provider token usage is currently unavailable.

Discovery submissions cannot set vulnerability verdicts, and original signals
keep `evaluation: not_run`. Separate evaluation cases hold source-based verdicts.

## Files and development

| File/directory | Responsibility |
| --- | --- |
| `protocol/v4.json` | Shared authored schemas, operations/version, and local schema references |
| `contracts.py` | Manifest loading and structural validation |
| `service.py` | Transport-independent routing and bounded response pages |
| `workflow.py` | Project lease, durable lifecycle/checkpoints, reports, artifact allowlist |
| `discovery/languages.py` | Source detection and build modes |
| `discovery/catalog.py` | Offline pinned-pack catalog and exact selection |
| `discovery/codeql.py` | Cancellable extraction/query subprocesses and file logs |
| `discovery/sarif.py` | Source-safe signals and coverage evidence |
| `repository/snapshot.py` | Source policy, immutable copy, content identity |
| `worker.py` | Explicit network-enabled extraction helper |
| `transports/mcp.py` | Bounded newline-delimited stdio MCP; stdout contains protocol only |
| `tasks.py` | Shared task leases, budgets, source evidence receipts, and citation checks |
| `evaluation/engine.py` | Durable source-only cases, verdicts, and bounded investigation |
| `reporting/` | Reporting boundary; JSON/Markdown rendering lives in workflow |
| `../src/scanner/` | Node Docker lifecycle/client, CLI/Muse routing, standalone API driver |

Python 3.11+ is needed only for local development/tests. No Python runtime package
dependencies are required.

Repeated protocol shapes use local `$ref` pointers within `protocol/v4.json`.
Python and Node expand them at load time, so MCP clients still receive
self-contained schemas. External references, cycles, and unresolved pointers
are rejected. There is one authored definition for configuration, build settings,
run responses, and evidence; packaging copies the same document without rewriting
it. The reference loaders do not make network requests.
Only the active v4 contract ships; earlier contracts remain in Git history.

```sh
npm run test:scanner
npm run plugin:build
npm run check
npm test
npm run test:policy                    # real lightweight Docker + scripted-host MCP
npm run test:codeql                    # real CodeQL fixtures, boundaries, scope and combined mode
```

The deterministic Python suite uses a fake executable to test lifecycle, failures,
evidence, cancellation, resume, and network handoff. Node tests cover CLI/Muse
parity, provider isolation, MCP bounds, and process cleanup. The opt-in matrix
runs vulnerable/corrected MIT fixtures across supported families plus Kotlin and
TypeScript, then a packaged Muse MCP scan. Set `BYPASS_CODEQL_CASES=python` to
select cases. Artifacts remain in the printed temporary directory. Pull requests
also run `npm run test:codeql` in a separate Docker job with a 120-minute limit,
disk cleanup for the multi-language image, and `BYPASS_CODEQL_CONCURRENCY=1`
to stay within hosted-runner memory. Local runs default to two fixture cases at
a time. This job covers the actual pinned bundle, isolation/recovery, and scope;
the smaller Python suite remains independent of Docker.

Transport development:

```sh
PYTHONPATH=scanner/src PYTHONDONTWRITEBYTECODE=1 python3 -m bypass_scanner
```

Initialize with a version in `protocol/v4.json`, send
`notifications/initialized`, then inspect `tools/list`/`scanner_capabilities`.
Without the image, transport/capabilities work but CodeQL operations report the
missing catalog. Wire frames are capped at 1 MiB; artifact data are paged.
