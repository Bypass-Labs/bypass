# Job Radar through the Muse plugin

This walkthrough uses `https://github.com/Bypass-Labs/job-finder` and `https://job-radar.app`. It describes real setup and the remaining production proof steps, not the Ledger fixture. Bypass supports this app's large server file and nested JSON resource identifiers.

**Validation is partial:** native plugin setup/resumption and real DNS verification worked. Actual AI source-review attempts encountered intermittent Muse failures/timeouts, and production account-isolation proof still requires validated test accounts and a known owner resource. Do not treat this walkthrough as a completed production test.

## 1. Connect the app inside Muse

Start with `/bypass:start`, then say:

> Review https://github.com/Bypass-Labs/job-finder with Bypass. Its production app is https://job-radar.app. Reuse my existing checkout and saved setup if available. Use this Muse session for reasoning and Bypass tools for actual source and HTTP evidence. I authorize read-only testing of /api/profile and /api/run. Guide me through anything missing.

Bypass should show the **actual selected folder**, loaded version/source, model and next step. An old walkthrough's DNS date is not current proof: check the selected project's saved ownership and scope. If needed, publish the generated TXT record, then ask Bypass to verify it. Source-only review can run while DNS propagates.

## 2. Let Muse connect the test accounts

If Muse already created two dedicated accounts and saved their credentials privately, say **“Continue Bypass setup using the test accounts you created.”** It should import that known file itself and continue in the same session. You should not run a refresh script, source an env file, or restart Muse for credentials.

Muse uses `bypass_import_identity` with the account name, private file path, token and refresh-token field names, `provider: firebase`, and the app's public Firebase config file/key field. Existing references are updated without creating duplicate users. For this repository the public web API key is configured in `ui/.env` as `VITE_FIREBASE_API_KEY`; the adapter reads it internally. Credentials remain outside the repository, MCP responses and security memory. Automatic refresh uses Google's official token endpoint and retains rotated refresh tokens.

If there are no account credentials yet, Muse needs an authorized sign-in or permission to create dedicated test accounts. That access step cannot be invented. It must not request passwords or tokens in chat. Other authentication providers currently support private static credentials; automatic refresh is Firebase-specific. See [Account connection](ACCOUNTS.md).

## 3. Let Muse prepare the resource and continue

Muse reads the source to establish the API routes and selectors, then reuses an exact owner resource ID observed during authorized setup. It should not ask you to reconstruct details it already knows.

For a private run, the source establishes:

- Bearer authentication and `GET /api/profile`, account selector `owner_uid`.
- Resource `GET /api/run/EXACT_RUN_ID`, resource selector `run.id`.

The resource must belong to the owner test account and the route must be explicitly authorized. If only `/api/profile` and `/api/jobs/` are authorized, that does **not** permit `/api/run/`; Muse must request the additional scope before testing it. Run records are held in application memory and may expire. A nonexistent owner resource is inconclusive, never a passing security result.

If the new account owns no suitable resource, Muse should explain the specific missing resource and offer to create one with permission (including any app/provider cost), or use an existing dedicated test resource. It must not guess IDs, silently create production data or ask you to learn internal JSON selectors.

Muse then calls `bypass_test_probe`: two login checks and one owner-resource GET. Only after these succeed does it continue to the requested review and cross-account proof. Setup is retained if any control is blocked. Prep notes/threads need their own route and selector (`note.id` / `thread.id`), rather than blindly reusing `run.id`.

## What a completed proof means

During the proof phase, Bypass makes five actual GET requests for the selected resource (in addition to the three positive preflight requests):

1. Owner identity returns 200 and an account ID.
2. Other identity returns 200 and a **different** account ID.
3. Owner resource access returns 200 with the expected `run.id`.
4. Other-account access is checked for the same resource.
5. Anonymous access is checked for that resource.

If another account or an anonymous caller receives the expected resource, Bypass confirms an exposure. If both are denied, that behavior passes. Expired logins, missing resources, redirects and server errors are **blocked/inconclusive**, never a passing security result. A source hypothesis alone cannot confirm a production vulnerability.

For a confirmed issue, review and deploy an actual application fix through your usual release process. Ask Muse to retest the finding after deployment. When all controls pass, Bypass saves a regression and can export standalone Node tests. Subsequent replay uses zero model calls. No production fix, regression test or completed production proof should be claimed before those steps occur.

## Evidence and validation limits

The checked-in validation record separates installed-plugin/MCP tests, actual Muse/Docker source review and local HTTP regression tests from pending production proof. See [Job Radar evidence](evidence/job-radar-plugin-2026-10-26.json). Local test responses are not evidence about Job Radar production.
