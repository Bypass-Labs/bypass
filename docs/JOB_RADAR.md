# Job Radar through the Muse plugin

This walkthrough uses `https://github.com/Bypass-Labs/job-finder` and `https://job-radar.app`. It describes real setup and the remaining production proof steps, not the Ledger fixture. Bypass supports this app's large server file and nested JSON resource identifiers.

**Validation is partial:** native plugin setup/resumption and real DNS verification worked. Actual AI source-review attempts encountered intermittent Muse failures/timeouts, and production account-isolation proof still needs two test-account references and a known owner resource. Do not treat this walkthrough as a completed production test.

## 1. Connect the app inside Muse

Start with `/bypass:start`, then say:

> Review https://github.com/Bypass-Labs/job-finder with Bypass. Its production app is https://job-radar.app. Reuse my existing checkout and saved setup if available. Use this Muse session for reasoning and Bypass tools for actual source and HTTP evidence. I authorize read-only testing of /api/profile and /api/run. Guide me through anything missing.

Bypass should show the **actual selected folder**, loaded version/source, model and next step. An old walkthrough's DNS date is not current proof: check the selected project's saved ownership and scope. If needed, publish the generated TXT record, then ask Bypass to verify it. Source-only review can run while DNS propagates.

## 2. Finish ownership, scope and model setup first

Confirm your two dedicated test accounts work in the app. Confirm host subscription/Standard settings and complete DNS and testing permission before fetching short-lived tokens. Then create or open one recent run owned by the first account and keep its exact ID. Run data is held in application memory and can disappear after an app restart.

## 3. Get the two Firebase ID tokens privately

For this app, the browser already sends the needed Firebase ID token with authenticated API requests. You do not need a service-account key or a refresh token.

1. Sign in to `https://job-radar.app` as the **owner test account**. Open the browser's developer tools → **Network**.
2. Reload the signed-in app. Select its request to **`/api/profile`**. Under **Request Headers**, find `Authorization: Bearer …`. Copy only the token after `Bearer ` into the private terminal prompt below.
3. Repeat in a separate browser profile/private window signed in as the **other test account**. Do not reuse the owner's account.
4. In the terminal from which you will start Muse, run `bash`, then these commands. Pasted values are hidden and are not part of shell command history:

```bash
read -r -s -p 'Owner Firebase ID token: ' JOB_RADAR_OWNER_TOKEN
printf '\n'
export JOB_RADAR_OWNER_TOKEN
read -r -s -p 'Other account Firebase ID token: ' JOB_RADAR_OTHER_TOKEN
printf '\n'
export JOB_RADAR_OTHER_TOKEN
muse --reasoning-effort minimal
```

Do not paste tokens into chat, command arguments, screenshots or Git. Do not copy the entire request as cURL. Clear your clipboard after pasting. If Muse is already running, exit it first; a running process cannot inherit variables exported in another shell.

Firebase ID tokens last about **one hour**. If validation returns a login failure, reload the signed-in app, copy fresh tokens, repeat the private prompts and start a new Muse session. Bypass keeps the saved references and resource setup. The app's source uses `user.getIdToken()` in `ui/src/lib/api.ts`; the SDK can refresh an expired token. [Firebase session lifetime](https://firebase.google.com/docs/auth/admin/manage-sessions) · [Firebase getIdToken reference](https://firebase.google.com/docs/reference/js/auth.user#getidtoken).

## 4. Give Muse names and the real resource ID

Then tell Muse the names and an existing private run owned by the first account:

> The owner token is in JOB_RADAR_OWNER_TOKEN and the other-account token is in JOB_RADAR_OTHER_TOKEN, loaded in this Muse process. The owner’s existing run ID is YOUR_RUN_ID. Configure those references and run the real review.

Replace `YOUR_RUN_ID`; do not submit a guessed ID. The source establishes the rest:

- Bearer authentication for both accounts.
- Identity control: `GET /api/profile`, account selector **`owner_uid`**.
- Resource: `GET /api/run/YOUR_RUN_ID`, expected ID `YOUR_RUN_ID`, resource selector **`run.id`**.

Run records live in application memory and may expire or disappear after a restart. Use a recent existing run from the owner account. A missing run is an inconclusive positive control, not proof that access is secured.

Muse performs the Bypass tools itself. It adds the two identities and resource probe, calls `bypass_test_probe` itself, then shows the plan and starts the review. Preflight performs only the first three controls below and must succeed before AI. A live review repeats these positive controls before model calls. Missing tokens or a nonexistent owner resource are blocked with a concrete recovery step, not marked ready. If you choose a prep note/thread instead, it must update the authorized resource route and match the corresponding response selector (`note.id` / `thread.id`); it must not reuse `run.id` blindly.

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
