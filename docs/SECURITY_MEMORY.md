# Security context for the next feature

Bypass retains project security knowledge so a coding agent can use past work when implementing new features. The aim is continuity: an ownership rule learned while fixing invoice reads should inform a later invoice-export implementation.

## The user journey

1. **Connect your application once.** Use `/bypass:start` for a review. A source-only review can learn application knowledge without a running app.
2. **Review and learn.** The white-box agent returns cited interpretations of authentication, authorization, routing, data models and trust boundaries. Bypass accepts only quotes from exact lines actually delivered to the agent. This validates the citation, not the interpretation's correctness.
3. **Prove and keep behavior.** Scoped HTTP controls establish findings. Retesting a previously confirmed finding after a fix can save a deterministic regression. That check supplies an explicit behavior requirement for future changes.
4. **Build the next feature.** In Muse, ask: “Use Bypass's security context while adding invoice export. Preserve the account boundaries and test the new route.” Or use `/bypass:build`. The host coding agent retrieves context, reads current source, implements the feature and tests it.
5. **Revalidate.** A new route needs new tests. Old invoice-read checks alone cannot prove invoice export is safe. Changed code and blocked replay are visible, never converted into a pass.

Context retrieval itself is read-only: no inference, Docker, application HTTP or additional review setup. The CLI supplies context; the host coding agent writes the feature. There is no separate autonomous feature-writing service.

## What is remembered

| Record | Provenance | How a coding agent should use it |
| --- | --- | --- |
| Source knowledge | Exact file/line/quote, full-file hash, repository fingerprint and run ID | Re-read and validate the model's interpretation against current source |
| Investigation | Real source hypothesis or HTTP finding, status, source citation and recent history | Understand prior failures and approaches; distinguish unproven, confirmed and fixed |
| HTTP observation | Target origin, configured account/resource binding, control status codes and run ID | Historical account-boundary evidence; never current proof or permission |
| Regression | Saved check ID, associated finding, resource and last result | Preserve owner access and deny other-account/anonymous access; replay before claiming a current pass |
| Interrupted investigation | Stopped stage and source ranges already read | Resume from a useful starting point without claiming a clean review |

Mock-engine candidates are excluded. Real fixture results remain scoped to their own example project and target. Memory is not a conversational transcript, vector database or complete architecture model.

## Retrieval and freshness

`bypass_feature_context` takes a task description, optional comma-separated repository-relative files, and an optional configured target. It ranks matching files and task terms alongside changed source, source knowledge and prior findings. It returns up to 12 records / 14 KB of serialized records, provenance, why each was selected, stale items, and saved behavior requirements. General reviews use up to 12 records / 12 KB and record the selected IDs, freshness and byte count in the run evidence. Up to two saved regression records are prioritized so matching source facts cannot crowd out all behavior requirements. These are record budgets; the enclosing response also includes instructions and summaries.

The whole eligible-source fingerprint is checked conservatively. Even a change outside the cited file makes an interpretation stale because dependencies may change its meaning. Missing, ignored or deleted source is excluded from automatic agent retrieval, including prior source hypotheses. Old records remain inspectable locally. A live-only review does not upload old source knowledge from memory.

HTTP history is scoped to the project ID, target name, exact origin and account/resource binding. A different origin is excluded from automatic retrieval; reconnecting cannot relabel old proof with the new origin. Legacy HTTP evidence without a recorded origin is withheld from automatic retrieval until fresh verification/replay binds it. A changed binding is marked stale. Source matches do not attest the deployed build. Historical HTTP observations always remain historical. Current ownership, authorization expiry, credentials and controls still govern replay; memory cannot grant access or suppress a finding. Only fresh, exact passing checks can exclude a behavior from a scan.

Facts can be incomplete, conflicting or wrong despite a valid quotation. Stored content is explicitly treated as untrusted data in worker prompts and plugin instructions. The coding agent must resolve stale or conflicting interpretations by reading current source. This is a grounding and retrieval layer, not a guarantee against model mistakes or prompt injection.

## Plugin and CLI

Primary plugin flow:

```text
/bypass:build
Add invoice export. Use the remembered ownership rules and relevant tests.
```

For an already selected application, an ordinary feature request also activates the skill. The session hook supplies only a small availability summary and a retrieval instruction. It does not inject the full memory. Select the app if needed and ensure Muse's editor is in that application before editing. Selection persists for future sessions opened from the same host folder.

Typed tools for the coding agent:

- `bypass_feature_context(task, files?, target?)`: feature-specific context; no scan or model call.
- `bypass_memory(query?, target?)`: inspect/search records, including disabled memory.
- `bypass_forget_memory(id)`: forget one compact record after an explicit user request.
- `bypass_memory_mode(mode: "on" | "off")`: control recording and automatic retrieval.

Standalone CLI (substitute your paths):

```bash
bypass context --project /path/to/app \
  --task "Add invoice export" --files "src/routes.js,src/auth.js" --json
bypass memory --project /path/to/app
bypass memory --project /path/to/app --query ownership
bypass memory show memory_ID --project /path/to/app
bypass memory forget memory_ID --project /path/to/app
bypass memory use off --project /path/to/app
bypass memory use on --project /path/to/app
```

JSON/stdio MCP can supply other coding agents; dedicated integrations for other products are not included. When the project has no knowledge yet, the response says so and directs the agent to current source and tests rather than inventing a history.

## Storage, privacy and control

Memory is enabled by default and stored in the local project's `.bypass/state.json`, already excluded from Git by initialization, with owner-only file permissions. `/memory`, `/context`, and their JSON/tool equivalents show that absolute path, plus existing source citations, run records, reports, and proof files for retrieved entries. It stays with that checkout; separate clones do not automatically synchronize memory. Existing real evidence is consolidated when the project is reconnected or a real review/retest/replay runs. No external database, cloud sync or embedding call is added.

Each project retains up to 500 records. Existing records can be updated; new entries are refused when full and `capacitySkipped` reports this. Records are not silently evicted. Forget a record to free capacity. Forgetting creates a tombstone for that record identity so the same evidence is not immediately reimported. A new citation or new investigation may create a different record. Disabling stops recording and automatic agent retrieval but leaves stored records inspectable and regression replay functional.

Forgetting memory is **not deletion of original evidence**: findings, checks, exported tests and past run logs remain. Disabling or forgetting cannot remove context already delivered to a coding session or provider. A full project/evidence deletion and retention-policy interface is not implemented.

The memory layer stores compact observations and source excerpts, not raw HTTP response bodies. It redacts configured credential values and recognizable JWTs; this is best-effort redaction, not universal secret detection. Keep credentials outside source and use `.bypassignore` for sensitive source files. Previously recorded material is retained locally until forgotten, even when its source becomes ignored.

Use compatible local inference for enhanced privacy, your own self-hosted model, or the Muse Code subscription. Selected memory follows the model receiving it. The **host coding agent** may use a different provider from Bypass's review profile; a local Bypass model does not make a hosted Muse conversation private to your machine. There is no claim that this feature alone makes the application secure or unique among all competing tools.
