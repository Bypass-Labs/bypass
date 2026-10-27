# Job Radar through the Muse plugin

This walkthrough uses `https://github.com/Bypass-Labs/job-finder` and `https://job-radar.app`. It describes real setup and the remaining production proof steps, not the Ledger fixture. Bypass 0.2.2 supports this app's large server file and nested JSON resource identifiers.

**Validation is partial:** native plugin setup/resumption and real DNS verification worked. Actual AI source-review attempts encountered intermittent Muse failures/timeouts, and production account-isolation proof still needs two test-account references and a known owner resource. Do not treat this walkthrough as a completed production test.

## Continue the existing setup

The application is already connected at `/Users/maksim/Projects/job-finder-3`. Its commit is `1f5684f9d1b051187ec6be40e981ba489d6240a8`. The installed plugin remembers this selection when Muse starts from `/Users/maksim/Downloads/bypass-for-muse`. Open a **new Muse session** to load the updated plugin. No new clone or DNS record is necessary for this saved setup.

Paste this:

> Use Bypass to continue reviewing Job Finder at /Users/maksim/Projects/job-finder-3, production https://job-radar.app. Reuse the saved Muse profile, real Docker engine and verified ownership. Show the current source review and help me complete the two-account HTTP proof. I authorize read-only testing of /api/profile and /api/run. Ask only for missing inputs; do not start another demo or duplicate a running review.

## What the plugin should show

| Step | Result |
| --- | --- |
| Repository | Existing Job Finder checkout, matching GitHub HEAD at validation time |
| Shared model | Existing Muse Code profile reused |
| Analysis | Real Docker engine; no mock fallback |
| App | `https://job-radar.app`, production |
| Ownership | Published DNS TXT verified on 2026-10-27 UTC; valid for 30 days |
| Testing scope | GET/HEAD on `/api/profile` and `/api/run`, at most 2 requests/second; seven-day authorization |
| Accounts | Needs two dedicated, valid Firebase ID-token references |
| Resource | Needs one existing run ID belonging to the owner account |
| Production proof | Pending account/resource setup; no confirmed production finding yet |

DNS proves control of the domain. It does not attest that production is running the checked-out commit. Existing seeded findings remain marked simulated and are not evidence against this app.

## Supply the remaining inputs once

Load two dedicated test accounts' **Firebase ID tokens** in the terminal that launches Muse. These are user ID tokens, not Firebase service-account keys or refresh tokens. Keep values out of chat and Git. Choose environment names such as `JOB_RADAR_OWNER_TOKEN` and `JOB_RADAR_OTHER_TOKEN`; use your normal private credential-loading mechanism before starting Muse. Refresh expired tokens and restart the session when necessary.

Then tell Muse the names and an existing private run owned by the first account:

> The owner token is in JOB_RADAR_OWNER_TOKEN and the other-account token is in JOB_RADAR_OTHER_TOKEN, loaded in this Muse process. The owner’s existing run ID is YOUR_RUN_ID. Configure those references and run the real review.

Replace `YOUR_RUN_ID`; do not submit a guessed ID. The source establishes the rest:

- Bearer authentication for both accounts.
- Identity control: `GET /api/profile`, account selector **`owner_uid`**.
- Resource: `GET /api/run/YOUR_RUN_ID`, expected ID `YOUR_RUN_ID`, resource selector **`run.id`**.

Run records live in application memory and may expire or disappear after a restart. Use a recent existing run from the owner account. A missing run is an inconclusive positive control, not proof that access is secured.

Muse performs the Bypass tools itself. It adds the two identities and the resource probe, shows the plan, starts the review and polls progress. If you choose a prep note/thread instead, it must update the authorized resource route and match the corresponding response selector (`note.id` / `thread.id`); it must not reuse `run.id` blindly.

## What a completed proof means

Bypass makes five actual GET requests for the selected resource:

1. Owner identity returns 200 and an account ID.
2. Other identity returns 200 and a **different** account ID.
3. Owner resource access returns 200 with the expected `run.id`.
4. Other-account access is checked for the same resource.
5. Anonymous access is checked for that resource.

If another account or an anonymous caller receives the expected resource, Bypass confirms an exposure. If both are denied, that behavior passes. Expired logins, missing resources, redirects and server errors are **blocked/inconclusive**, never a passing security result. A source hypothesis alone cannot confirm a production vulnerability.

For a confirmed issue, review and deploy an actual application fix through your usual release process. Ask Muse to retest the finding after deployment. When all controls pass, Bypass saves a regression and can export standalone Node tests. Subsequent replay uses zero model calls. No production fix, regression test or completed production proof should be claimed before those steps occur.

## Evidence and validation limits

The checked-in validation record separates installed-plugin/MCP tests, actual Muse/Docker source review and local HTTP regression tests from pending production proof. See [Job Radar evidence](evidence/job-radar-plugin-2026-10-26.json). Local test responses are not evidence about Job Radar production.
