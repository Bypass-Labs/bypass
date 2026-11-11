# Local scanner benchmark · 2026-11-10

This benchmark uses the deliberately vulnerable Aegis Mission Control fixture.
It measures Bypass behavior on one local app; it does not establish coverage or
cost for other applications. The standalone CLI comparison used Meta Model API with
`muse-spark-1.3-contributor`, the same vulnerable source, local target
`http://127.0.0.1:3221`, all HTTP methods, `/` path scope, 20 requests per
second, 25 maximum tasks, a ten-minute ceiling, and no external discovery.
Both scanners used the same saved scope. The old `main` checkout had only the
token counter from this PR applied; no scanner fixes were backported.

| Scanner | Model-call cap | Confirmed issues | Elapsed | Actual calls | Provider-reported tokens |
| --- | ---: | ---: | ---: | ---: | ---: |
| Old `main` · normal allowance | 60 | 1 | 304.7 s | 20 | 86,543 |
| Old `main` · equal allowance | 3 | 1 | 29.7 s | 2 | 4,861 |
| This PR | 3 | 5 | 64.5 s | 3 | 12,960 |

Against old `main` with its normal allowance, the PR finished about 79%
sooner and used about 85% fewer provider-reported tokens while confirming
five issues instead of one. At the equal
three-call cap, old `main` spent fewer total tokens but found only one issue;
the PR used about 47% fewer tokens per confirmed issue (2,592 versus 4,861).
Two earlier PR runs, before token recording, also confirmed the same five
distinct issues in 46.8 and 95.5 seconds with two and three calls.

The five PR findings were SQL injection, anonymous dossier disclosure,
identity-header spoofing, server-side fetch misuse, and missing local login
throttling. The old run confirmed the dossier disclosure only. The old
normal-allowance run stopped with an invalid `security_action.notes` response.
All three reports state partial coverage; absent same-role test identities
left account-boundary checks untested. The earlier plain Muse Code baseline
confirmed four issues in 157 seconds and 15 calls, but it did not save token
usage, so a token-spend comparison with that session is unavailable.

Evidence is saved locally in the Aegis project's `.bypass/runs/` directory:

| Run | Report | Usage and limits |
| --- | --- | --- |
| Old normal allowance · `bx-20261111-a8eb5bfe` | `report.md` | `run.json` |
| Old equal allowance · `bx-20261111-3a7a02f0` | `report.md` | `run.json` |
| This PR · `bx-20261111-792681a1` | `report.md` | `run.json` |

To repeat this comparison, run the vulnerable local fixture and configure a
Meta Model API profile for the exact model above. For each checkout, run:

```bash
bypass blackbox http://127.0.0.1:3221 \
  --project <aegis-project> --scope <saved-scope> \
  --source <vulnerable-aegis-source> --model <spark-profile> \
  --max-tasks 25 --model-calls <3-or-60> --minutes 10 --rps 20 \
  --accept-local --offline --no-discovery
```

The actual model calls, provider tokens, elapsed time, confirmed findings,
and untested work are in each run's `run.json` and `report.md`. Usage is
reported only when the provider returns counts; the report marks missing or
partial usage rather than estimating it from model-call count.

## Native Muse plugin run on the same PR

I refreshed the locally installed native plugin from this branch and ran it
through **Muse Code 1.4.14** with the active `muse-spark-1.3-contributor` model.
The plugin performed a **combined source and live audit** of the same vulnerable
source and `http://127.0.0.1:3221`. Its source review ID was passed to the full
live audit, which used `/`, all HTTP methods, 20 RPS, a 25-task cap, a
15-decision cap, and a ten-minute audit ceiling. It did not call the standalone
CLI or a separate model endpoint. The source pass consumed part of the ceiling,
leaving 8.4 minutes for live work. This is a **different workflow** from the
source-guided CLI black-box command above, so the rows below are observed
performance, not a controlled speedup claim.

| This PR path | Confirmed report entries | Distinct weaknesses | End-to-end elapsed | Live audit elapsed | HTTP requests | Executed tasks | Model work |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | --- |
| Standalone CLI · source-guided black box | 5 | 5 | 64.5 s | 64.5 s | 123 | 22 | 3 Meta API calls; 12,960 provider tokens |
| Native Muse plugin · combined source + live | 3 | 2 | 345.6 s | 187.7 s | 150 | 25 | 15 bounded decisions; 56 Muse host calls |

The plugin's three report entries are a SQL boolean proof, a separate SQL
`UNION SELECT` proof on the same telemetry route, and a crew identity-header
bypass. All three PoCs were confirmed again by `bypass_blackbox_verify`. The
scanner recorded four positive task outcomes, but the report has three entries
and only two distinct weaknesses. The plugin found **neither the dossier,
SSRF, nor login-throttling issue** reported by the CLI run. Its report marks
coverage partial, with 35 leads beyond the task budget and seven inconclusive
tasks. A source citation was rejected for a quote mismatch, and the source
review continued with seven cited hypotheses. Missing usable test identities
also limited account-boundary checks.

Muse's session usage record reports **56 host calls**, 7,693,809 input tokens
(7,344,726 cached), and 21,801 output tokens. The plugin scanner's own report
cannot attest those host tokens and marks its 15 decision calls as having no
provider usage data. The CLI's 12,960 tokens are provider-reported API usage;
these token counters cover different work and billing paths. In this run, the
plugin workflow took longer and confirmed fewer distinct weaknesses than the
CLI workflow despite using the improved scanner build. The bottleneck includes
source/orchestration time and bounded live decisions; this single run does not
isolate which component explains each missed proof.

Plugin evidence is in the fixture's
`.bypass/runs/bx-20261111-9ffacb17/` (`run.json`, `report.md`,
`coverage.json`, `poc/`); the connected source review is
`.bypass/runs/run_f1fdb830.json`. The captured Muse headless session is at
`/tmp/bypass-plugin-perf.jsonl` on the test machine. The session was run with
`--disable-write --disable-shell`, so the host did not edit application source;
the plugin wrote its own project state and evidence.
