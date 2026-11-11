# Local scanner benchmark · 2026-11-10

This benchmark uses the deliberately vulnerable Aegis Mission Control fixture.
It measures Bypass scanner behavior on one local app; it does not establish
coverage or cost for other applications. Every run used Meta Model API with
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
