# Optional test accounts and registration checks

Start source and anonymous JSON/HTML checks without credentials. Bypass always includes registration coverage in a live review. Muse derives signup details from source; when account creation is authorized, Bypass creates up to two dedicated accounts through a JSON signup endpoint or Firebase email/password. Tokens go directly into the private credential store and are available in the same session. Firebase refresh tokens are retained privately and refreshed on use.

Retries reuse the saved attempt ledger. An uncertain POST is never retried automatically. CAPTCHA, social login, invitation-only registration and unsupported payloads are reported as gaps; the rest of the review continues. Accounts may send emails through your app, so use an authorized test domain. Created accounts and cleanup needs appear in registration status; removing a local identity does not delete the application user.

An account created without email verification is an observation. A confirmed email-verification issue additionally requires an established verified-email policy, a valid unverified account positive control, and successful access to the protected account resource. A separate identity endpoint lets the regression prove that the account remains valid after protected access is denied. A failed login, already-verified account, redirect or missing resource is inconclusive. This follows the [OWASP registration testing guidance](https://wstg.owasp.org/latest/4-Web_Application_Security_Testing/03-Identity_Management/02-User_Registration_Process/) and [Firebase signup contract](https://firebase.google.com/docs/reference/rest/auth#section-create-email-password).

In Muse, say: **“Review this app. You may create up to two dedicated test accounts using our test domain.”** Muse configures and runs the supported check itself after app ownership and scope are established. Existing credentials remain optional.

CLI examples after ownership/scope setup (replace endpoint/selector values with your app's actual contract):

```bash
bypass registration configure --path /api/signup --check-path /api/me --access-path /api/verified-profile --email-domain tests.example.com --token-field token --verified-field emailVerified --require-verification --accept
bypass registration test
bypass registration status
```

Firebase uses `--provider firebase --config-file ui/.env --project-id your-firebase-project --api-key-field VITE_FIREBASE_API_KEY` instead of a signup path/token selector. Supply the app identity endpoint and its ID selector, such as `--check-path /api/profile --identity-field owner_uid`. Only enable `--require-verification` when the tested access actually requires verified email.

Muse can select existing owned test data with `bypass_discover_resources`: it reads the chosen account's identity and authorized collection, returns only owned IDs and configures their probes. It never guesses customer IDs or creates resources silently. No suitable data means a reported gap, not a forced onboarding loop.

## Import existing accounts

In Muse, ask **“Continue setup with the test accounts you created.”** When the account credentials already exist in a private local file, Muse imports them itself and continues. No terminal exports or session restart is needed. The same connection works for live checks, deterministic saved tests and local monitor workers.

Bypass supports bearer tokens, cookies and custom headers. Firebase accounts can refresh automatically. Other providers currently use static credentials: replace the private file's token and reimport the same account when needed. Bypass does not automate arbitrary OAuth, browser login or MFA.

## What Muse does

1. Reuses the selected repository, app, ownership, testing scope and account references.
2. Calls `bypass_import_identity` with **file paths and field names**, never secret values. An existing account name is updated without creating another application user.
3. For Firebase, imports the ID token, refresh token and public web API key. Before app requests, Bypass refreshes an expiring token through Google's fixed HTTPS endpoint, checks the returned account/project claims, and saves the new ID and refresh tokens. Revoked or invalid logins block testing with a reconnect action.
4. Derives routes and JSON selectors from source; reuses a known owner resource ID from authorized setup. If none exists, asks only for the missing resource or permission to create one.
5. Runs the login and owner-resource controls before cross-account testing. A connected account does not by itself prove that these controls pass.

Initial sign-in, MFA, DNS access, creating accounts/resources and expanding testing scope may require the user's access or permission. Reuse authorization already given. Do not make the user perform tool calls or disclose credentials in the conversation.

## Standalone CLI equivalent

For an existing private account file with `OWNER_ID_TOKEN`, `OWNER_REFRESH_TOKEN`, `OTHER_ID_TOKEN` and `OTHER_REFRESH_TOKEN` fields:

```bash
bypass identity import owner --file /private/path/accounts.env --token-field OWNER_ID_TOKEN --provider firebase --refresh-token-field OWNER_REFRESH_TOKEN --config-file ui/.env --api-key-field VITE_FIREBASE_API_KEY --check-path /api/profile
bypass identity import outsider --file /private/path/accounts.env --token-field OTHER_ID_TOKEN --provider firebase --refresh-token-field OTHER_REFRESH_TOKEN --config-file ui/.env --api-key-field VITE_FIREBASE_API_KEY --check-path /api/profile
bypass identity test owner
bypass identity test outsider
```

The active target is used; `--target` selects another configured app. Existing identities retain their type, endpoint and CI variable reference unless explicitly changed. New identities default to bearer tokens. `--provider static` is the default for tokens/cookies without a refresh adapter. `bypass identity refresh owner` forces a Firebase refresh; ordinary checks refresh automatically before expiry.

Inputs may be a JSON object of string fields or a data-only env file (`KEY=value`, optional `export`, simple quoted values). Shell expressions and scripts are never executed. On macOS/Linux, credential input files must be owned by the current user and have mode `600`. Public Firebase config files do not need secret-file permissions. Bypass copies only the selected credentials; account passwords are not retained. Import does not delete or modify the source file.

## Storage, removal and CI

The default store is `~/.local/state/bypass/credentials`, outside the application and installation. Project state contains an opaque reference bound to the project, checkout path, target origin and identity. The runtime reads it on demand, including in already-running MCP sessions. Local files use owner-only permissions on macOS/Linux and a restricted directory ACL on Windows. This is local access control, **not encryption against the signed-in OS user**. `BYPASS_CREDENTIAL_DIR` can select another private location outside the app.

`bypass identity remove owner` deletes the local credential and account reference; it does not delete the user from your application. Switching an identity back to `--secret-env` removes its private stored credential. Existing accounts must be reconnected on another machine or checkout. Back up this directory only as private credential material.

Exported independent Node tests contain only environment-variable names. CI supplies fresh app credentials through its secret system; local refresh tokens and private-store references are never exported. Local Bypass replay and monitors use the private connection automatically, while monitors still require an awake machine and running worker.

The Firebase adapter follows the [official refresh-token exchange](https://firebase.google.com/docs/reference/rest/auth#section-refresh-token), including retaining a replacement refresh token. Token claims are checked for account/project continuity; successful app identity controls establish that the app accepts the credentials.

## Validation for 0.7.0

The packaged MCP integration test starts the server before the credential file exists, imports two accounts, performs local HTTP proof, verifies a fixture fix, replays a saved regression in a separate process, runs a monitor tick, and replaces a token while the same MCP process remains running. It checks that exported tests and project state contain no credentials. Refresh tests cover expiration, rotated refresh tokens, concurrent requests, wrong-account/project responses, redirects, revocation and cancellation. The local full suite passed 133 tests with two Docker-only tests skipped; release CI runs the Docker tests separately.

Both existing Job Radar test accounts also completed a real Firebase refresh and returned HTTP 200 from the already-authorized `/api/profile` endpoint. No resource proof or model calls ran, and the app scope was unchanged. [Redacted production account-validation record](evidence/account-connection-2026-10-27.json). This validates account connection, not production authorization security or live model reasoning.

The actual Muse agent also completed this setup on a local fixture: two private imports, three positive-control GETs and live-ready status in the same session. The temporary audit plugin was removed afterward. This used host reasoning; Bypass made no independent model calls. [Native Muse onboarding evidence](evidence/muse-account-onboarding-2026-10-27.json).

App JSON signup requires POST in the saved method scope as well as explicit account-creation permission. In Muse, reopen the testing-permission picker and select POST alongside the methods needed for identity/access controls. Firebase signup retains its separate bounded project and account-creation permission.
