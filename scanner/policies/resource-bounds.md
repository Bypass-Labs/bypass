# Attacker-controlled resource consumption

Invariant: unauthenticated or low-privilege input must not trigger unbounded or
grossly disproportionate CPU, memory, storage, database, network, process, or
third-party cost. Trace collection sizes, pagination, recursion, regexes,
decompression, parsing, fan-out, retries, and job creation to their limiting
controls.

Inspect request and decoded-size limits, maximum page size, query complexity,
timeouts, cancellation, concurrency and queue bounds, retry budgets, streaming
behavior, regex input shape, archive expansion, and per-actor quotas. A limit
applied after buffering or expansion may be too late. Infrastructure throttling
is relevant counterevidence only when established as an explicit assumption;
bounded algorithms and early rejection are source counterevidence.

Candidates must identify the attacker-controlled scaling factor, expensive
operation, absent or bypassable bound, and availability or cost impact. Give a
source-supported growth argument rather than claiming denial of service from any
loop or allocation. Do not run load tests, expensive inputs, or external jobs.
