# Why the three-probe review stopped — follow-up audit

The new transcript concerns the same historical review, `run_25457168`. The local fixes from the earlier audit were not installed in that Muse session. The transcript nevertheless exposed additional gaps in the local implementation, addressed here without changing the application, active plugin or production deployment.

## What the evidence establishes

- Muse explicitly said it selected three probes and stopped, even though it could have prepared more owned resources. This was an execution/planning error. Requiring the user to say “go deeper” again was unnecessary for the continuing assessment.
- GET/HEAD/POST permission excluded unapproved PUT/DELETE requests. It did not exclude additional permitted reads or authorized isolated synthetic creation. Cleanup permission is a separate recorded constraint.
- Starting ingestion, email or paid AI jobs could have additional consequences. Those individual paths needed a specific constraint or approval; they did not justify omitting unrelated note/thread access checks.
- Read-only inspection of job-finder source confirms separate POST handlers for empty prep threads and ordinary prep notes. These perform inserts without the AI-generation calls used by other handlers. Workflows require source-specific analysis of configuration and enabled state; a generic safe-creation assumption would be wrong.
- The five finding records represent **four distinct issues**, with **one confirmed**: the analysis-job source record duplicates its matching live HTTP proof. No new production requests were made in this audit.

The new coverage reporter was exercised read-only against the real saved run. It identifies the legacy `completed` status as insufficient to support completion, retains the three recorded probes, and identifies pending route inventory. The older run did not record HTTP methods or exact delivered source ranges. Its reconstructed route count is not a count of runnable tests or a historical permission attestation. The application source has changed since that run, so continuation requires a fresh source assessment using existing app setup and permissions.

## Additional implementation changes

**Source work remains visible.** Inventory records file line counts. Every delivered excerpt updates merged source ranges. A source conclusion or the first 200/400 lines of a large file no longer makes unread files/tails disappear. The next action includes concrete remaining ranges. These counters measure delivery, not exhaustive reasoning or complete vulnerability-class coverage. Job-finder currently has about 1.29 MB of eligible source; the plugin budget is now 2 MB instead of 192 KB. The per-excerpt limits and explicit incomplete outcomes remain.

**Missing IDs trigger preparation.** Parameterized routes include source-derived collection/create candidates within recorded permission. Muse is instructed to derive minimal payloads and selectors, reuse approved owned collections, create authorized synthetic records, then run account controls. It must not conflate this with paid/global/email work. A `missing_resource` disposition with available setup routes requires real request/discovery evidence. A successful returned ID or configured probe prevents declaring the resource missing. An empty collection alone cannot dismiss an available authorized POST setup path. Requests remain single-shot, are not automatically retried/replayed, and do not themselves constitute a security finding.

**Coverage answers the actual question.** CLI and plugin coverage accept a run/target and expose pending work, source ranges, route dispositions, legacy limitations, and the next continuation operation. Older records stay unchanged. The dashboard leads to the next executable review action rather than another status poll.

**Late proof does not duplicate the hypothesis.** If the host submits a source hypothesis before configuring its HTTP probe, the later matching proof attaches to that same finding and saves its regression. Historical duplicates remain addressable but receive a distinct-issue summary; a list of records is not a list of independently confirmed vulnerabilities. Source-only severity remains provisional.

**One reasoning failure does not discard independent controls.** A combined standalone review still runs its already-configured deterministic HTTP controls if orchestrator, source-worker or black-box reasoning fails. Structured failure details stay in evidence; mixed results remain incomplete even if one vulnerability is confirmed. A code-only review with failed reasoning remains failed because no independent live controls exist. Model connection/runtime prerequisites retain their explicit setup failures; no provider fallback was added.

## Acceptance and remaining limits

Automated coverage includes the first finding followed by POST preparation and another owner/outsider check; missing-resource blocker rejection; late probe binding; unread files and large-file tails; an actual file beyond the former 192 KB limit; read-only legacy coverage; duplicate-record summaries; and continuation after failure of each reasoning stage. Tests use disposable local HTTP apps and controlled worker reasoning, not production credentials or a real provider.

Final verification: **208 tests passed, zero failed, two opt-in Docker tests skipped**, in 95.2 seconds. Syntax checks passed for 112 JavaScript modules; all 94 public commands and options map to 88 typed plugin tools. Native Muse package validation returned `valid: true` with no diagnostics. The initial full run caught a source-only error-status regression; it was corrected and the entire suite rerun before recording these results. `git diff --check` passed. HEAD and local origin/main remain `c0c4b7f2375d853385593d63bfcdaa9280ab701f`.

The standalone worker still has narrower source/read budgets and configured-resource coverage. Arbitrary browser workflows and replayable mutating vulnerability tests are not claimed as implemented. Native Muse still owns conversational continuation and editor permissions: the runtime can refuse completion and expose remaining actions, but cannot force the host to keep generating or veto arbitrary editor writes. Fresh native-session acceptance remains necessary before publication.

Changes are local and unpublished. Existing job-finder fixes and all historical evidence were preserved.
