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

## Native Muse plugin: handoff before and after the fix

Both plugin runs used **Muse Code 1.4.14** with the active
`muse-spark-1.3-contributor` model. They performed a combined source and live
audit of the same vulnerable source and `http://127.0.0.1:3221`. The source
review ID was passed to the full live audit, which used `/`, all HTTP methods,
20 RPS, a 25-task cap, a 15-decision cap, and a ten-minute audit ceiling. The
host did not call the standalone CLI or a separate model endpoint. The retest
used a clean copy of the same source to avoid saved project state. This is a
**different workflow** from the source-guided CLI black-box command above, so
the rows below are observed performance, not a controlled speedup claim.

| This PR path | Confirmed report entries | Distinct weaknesses | End-to-end elapsed | Live audit elapsed | HTTP requests | Executed tasks | Model work |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | --- |
| Standalone CLI · source-guided black box | 5 | 5 | 64.5 s | 64.5 s | 123 | 22 | 3 Meta API calls; 12,960 provider tokens |
| Native Muse plugin · before handoff fix | 3 | 2 | 345.6 s | 187.7 s | 150 | 25 | 15 bounded decisions; 56 Muse host calls |
| Native Muse plugin · after handoff fix | 5 | 5 | 262.2 s | 138.8 s | 134 | 14 | 15 bounded decisions; 54 Muse host calls |

Before the fix, the plugin report had two SQL proofs on the same telemetry
route and one crew identity-header bypass: three entries, two distinct
weaknesses. It did not confirm the CLI's dossier, SSRF, or login-throttling
findings. Its source handoff imported seven findings but no validated request
body fields. The early cited-source disclosure, header and fetch proofs ran
zero checks, and no POST contract was admitted.

After the fix, the connected live audit runs the existing bounded,
deterministic source route extractor without a second model source pass. It
merges 30 extracted route facts with the host's cited findings, and accepts a
request field for an imported lead only when both its exact citation and the
extracted route contract contain that field. The retest saved 35 combined
source endpoints, admitted four JSON POST contracts plus login, and ran early
source-guided dossier and server-fetch proofs. It confirmed SQL injection,
anonymous dossier disclosure, SSRF, missing local login throttling, and crew
identity-header bypass. `bypass_blackbox_verify` reconfirmed all **5/5** PoCs
with an intact 155-record evidence ledger.

The fixed plugin was about 24% faster end to end and 26% faster in the live
audit in this one paired observation. The report still marks coverage partial:
47 web-probe leads were beyond the task and decision budget, one research
checkpoint remained pending, and no usable same-role test identities were
available. The model's source findings also varied between runs, so these two
samples do not establish a general performance distribution.

Muse's session usage record reports 56 host calls, 7,693,809 input tokens
(7,344,726 cached), and 21,801 output tokens before the fix; 54 host calls,
6,417,076 input tokens (6,122,356 cached), and 12,519 output tokens after it.
The plugin scanner's own report cannot attest those host tokens and marks its
15 decision calls as having no provider usage data. The CLI's 12,960 tokens are
provider-reported API usage; these counters cover different work and billing
paths. The host still spends many calls on source work and the next/submit
loop. Matching the CLI's five issues does **not** make the plugin as fast as
the CLI's narrower black-box command.

Before-fix plugin evidence is in the original fixture's
`.bypass/runs/bx-20261111-9ffacb17/`, connected to `run_f1fdb830`.
After-fix evidence is in the clean source copy at
`/Users/stepan/Downloads/aegis-plugin-handoff-retest-2026-11-10/.bypass/runs/bx-20261111-52c2a46a/`,
connected to `run_266c2d1a`. Each run has `run.json`, `report.md`,
`coverage.json`, and sealed proofs under `poc/`. The captured headless Muse
sessions are `/tmp/bypass-plugin-perf.jsonl` and
`/tmp/bypass-plugin-retest.jsonl` on the test machine. Both used
`--disable-write --disable-shell`, so the host did not edit application source;
the plugin wrote its own project state and evidence.
