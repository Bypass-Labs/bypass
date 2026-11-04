# Audit contract and evaluation

The audit contract is tested at three levels:

1. Unit and integration tests validate source citation grounding, source-to-live handoff, scope and identity translation, proof reconciliation, progress events, reports and proof replay.
2. `npm run test:audit` runs the focused deterministic contract suite with controlled inference and local fixtures. It spends no provider allowance.
3. `npm run audit:eval -- --project /path/to/app --run run_<id>` reads a completed audit's durable state and artifacts without contacting the model or app. Add `--json` for CI output.

The artifact evaluator requires one parent scan, a canonical `code`, `live` or `combined` mode, the selected formal source result, the selected broad live result, a sealed report/coverage/ledger set, an immutable scope snapshot matching the saved target authorization, at least one live HTTP request, unique reconciled finding IDs, proof links for confirmed findings, and durable structured progress. It prints every gate and exits 1 when a required gate fails.

This evaluator proves that the product executed the intended architecture and retained reviewable evidence. It does not prove vulnerability coverage or that an app is secure. Security-quality evaluations must use deliberately vulnerable fixtures with expected findings plus negative controls, and must record time, requests, model calls, confirmed findings, false positives, inconclusive work and untested classes. Production runs are never acceptance fixtures.

When changing the audit pipeline:

- add or update a deterministic contract test for the behavior;
- run `npm run test:audit`;
- run `npm test` and `npm run check`;
- run the local vulnerable POC for any change to live scheduling, proof or reconciliation;
- evaluate the saved parent with `audit:eval`;
- keep provider-backed and production observations separate from deterministic CI evidence.
