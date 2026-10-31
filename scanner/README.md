# Whitebox SAST and policy discovery

The Python scanner runs deterministic CodeQL discovery inside Docker: source
snapshot → per-language extraction → pinned queries → unevaluated signals and
reports. Policy discovery adds a source-only reasoning task loop. Formal evaluation,
runtime reproduction, and patching remain unavailable.

The Bypass scanner source is licensed under [Apache-2.0](../LICENSE). The
CodeQL CLI is downloaded separately under [GitHub's usage terms](https://github.com/github/codeql-cli-binaries/blob/main/LICENSE.md).
Bypass's license does not grant CodeQL rights for private or commercial code.
Policy-only mode does not use CodeQL. [Dependency notices](../THIRD_PARTY_NOTICES.md).

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

Bundled policies cover object ownership/tenant access, privileged action
boundaries, outbound destinations, and filesystem containment. The JSON catalog
under `policies/` references Markdown bodies authored once. Custom catalogs use
the same schema, with unique IDs and repository-relative in-scope body paths.

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

Task leases, retry counts, model requests, evidence requests/bytes, follow-up
levels, and run deadlines are bounded. Exact submissions are idempotent. Resume
checks source/runtime/policy identity; expired run budgets require a new run.
Cancellation preserves accepted results. A task budget exhausted with remaining
surfaces yields deferred coverage, never a clean-coverage claim.

Policy-only first use prepares a lightweight Python/git image via Docker's
`policy` target, without downloading CodeQL or compiled-language toolchains.
SAST and combined runs use the pinned CodeQL image. Status/report/artifact tools
can inspect saved v2 CodeQL runs; the current wire contract is v3. Policy signals
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
findings. Signals are not confirmed vulnerabilities. Zero alerts does not prove
complete coverage.

## Analysis scope

New runs exclude common tests/fixtures, examples/demos/benchmarks, and generated
or vendored copies from the analysis scope by default. This includes `test/`,
`tests/`, `__tests__/`, `fixtures/`, `.test.*`/`.spec.*` files, Python `test_*.py`,
Go `*_test.go`, Java/C# test-name conventions, `examples/`, `benchmarks/`,
`generated/`, `dist/`, `vendor/`, and the packaged duplicate `plugin/runtime/`.
The shared `sourceScope` policy in `protocol/v3.json` lists the exact patterns.

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
LLM settings in either interface. The SAST-only route never loads the API driver.
Policy-only and combined runs perform policy mapping and discovery through
`next_task`, `evidence`, and `submit`.

Inside Muse the active session supplies all reasoning with its current settings.
The plugin never looks up an API profile, reads model credentials, or performs
independent inference. It cannot attest subscription billing or count host tokens;
reports show zero independent requests and unknown host usage, rather than claiming
no AI reasoning occurred. Direct CLI policy execution requires an explicit saved
API profile and runs the same bounded protocol through `src/scanner/api-driver.mjs`.
Its request attempts are recorded; provider token usage is currently unavailable.

Formal confirmation/refutation is not implemented. Discovery submissions cannot
set vulnerability verdicts, and all accepted signals keep `evaluation: not_run`.

## Files and development

| File/directory | Responsibility |
| --- | --- |
| `protocol/v3.json` | Shared authored schemas, operations/version, and local schema references |
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
| `evaluation/`, `reporting/` | Future interfaces; discovery reports currently live in workflow |
| `../src/scanner/` | Node Docker lifecycle/client, CLI/Muse routing, reserved API driver |

Python 3.11+ is needed only for local development/tests. No Python runtime package
dependencies are required.

Repeated protocol shapes use local `$ref` pointers within `protocol/v3.json`.
Python and Node expand them at load time, so MCP clients still receive
self-contained schemas. External references, cycles, and unresolved pointers
are rejected. There is one authored definition for configuration, build settings,
run responses, and evidence; packaging copies the same document without rewriting
it. The reference loaders do not make network requests.
Only the active v2 contract ships; the retired v1 scaffold remains in Git history.

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

Initialize with a version in `protocol/v3.json`, send
`notifications/initialized`, then inspect `tools/list`/`scanner_capabilities`.
Without the image, transport/capabilities work but CodeQL operations report the
missing catalog. Wire frames are capped at 1 MiB; artifact data are paged.
