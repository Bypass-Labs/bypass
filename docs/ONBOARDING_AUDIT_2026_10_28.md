# October 28 onboarding audit — local changes, not released

The reviewed Muse conversation stopped too early. A missing `.env` established
that the clone did not contain resolved Firebase values; it did not establish
that the values were unavailable. The same session later retrieved them from
the deployed app and continued without the user supplying them.

## What the session actually did

Times are Pacific on October 28, 2026. These observations come from the existing
local Muse session log; this audit did not repeat its production requests.

| Time | Observed action | Consequence |
| --- | --- | --- |
| 09:36:25 | Called registration configuration with `ui/src/lib/firebase.ts`, environment-variable field names, and no Firebase project ID | The tool expected resolved JSON/env values; the TypeScript template did not satisfy that contract |
| 09:36:51 | Asked the user to paste the project ID | Premature fallback before inspecting the deployed client's public configuration |
| 09:38:26 | Repeated the request for Firebase configuration | More user work despite account creation already being authorized |
| 09:39:25–09:39:40 | Inspected the deployed landing/login page, `index.html`, and the linked JavaScript asset | Found the public client configuration |
| 09:39:54 | Wrote resolved values into the application's `ui/.env` | Changed application configuration just to configure a security review |
| 09:40:01–09:40:06 | Configured Firebase registration and started the account check | Demonstrated that user-supplied configuration was not necessary in this case |

Three product problems contributed: the registration tool had no automatic
discovery fallback, the host guidance treated missing fields as a reason to ask
the user, and setup did not clearly distinguish source templates from resolved
client configuration. The subsequent shell-based recovery also did not enforce
Bypass's saved request scope. The replacement runs discovery through the shared
scope-aware runtime.

Firebase documents its client configuration and service API keys as public
project-identification data. This does not make authentication tokens or other
API credentials public. See [Firebase API keys](https://firebase.google.com/docs/projects/api-keys)
and [Firebase web configuration](https://firebase.google.com/docs/web/learn-more#config-object).

## Implemented behavior

1. Use an explicitly supplied resolved config file when available. Do not treat
   `import.meta.env` references as resolved values.
2. If Firebase values are missing, discover the configuration from the verified
   app's authorized pages and observed same-origin JavaScript assets. Try the
   landing page and `index.html`, covering the separate landing-page/SPA case.
3. Read at most eight responses, with bounded size, timeouts, rate limits,
   cancellation and current ownership/scope checks. Do not execute downloaded
   JavaScript, send cookies/tokens, or follow another origin. Show progress.
4. Save resolved public config under `.bypass/discovery/`, excluded from Git.
   Do not alter the application's `.env` or print the API key in tool output.
5. Reuse existing account-creation permission. Supply a synthetic test email
   namespace automatically unless the user selected another one. Existing
   registration attempt budgets continue to prevent duplicate signups.
6. Ask only after discovery genuinely cannot resolve the missing input, multiple
   projects require a choice, or access/permission is missing. Continue independent
   checks while a specific part is blocked. A review request does not authorize
   editing application source to remediate findings.

Public configuration discovery does not silently expand an existing `/api`
scope. New setup can include bounded anonymous public-page/script reads in the
same permission summary as the testing methods. Existing narrow scope requires
an explicit update. A shell request must not bypass that decision.

## Other onboarding fixes in this local change

- Native review-type choices: Code only, Code + running app, Running app only.
  App-only has its own managed profile and does not pretend to have source.
- Native environment choices: Production, Staging, Preview, Local development.
  Previously supplied values are reused; production does not require real users.
- Supplied repository URLs become actual connect/clone actions. Empty parent
  directories are rejected before DNS, scope setup or a source review.
- Ownership is persisted independently of the checkout, keyed by the exact
  normalized app origin with provenance and expiry. Changing checkout does not
  require a new TXT record for an already-verified origin.
- An explicit switch for the same app retains its exact unexpired scope. An
  unrelated repository or origin does not inherit it. Revocation survives stale
  cache writes; new ownership does not resurrect a previously revoked grant.
- Fresh CLI and MCP processes resume the explicitly selected application.
  `--project` remains an explicit CLI override.

## Validation boundary

The new parser found exactly one complete Firebase configuration in the
already-downloaded job-radar JavaScript bundle, identifying
`job-finder-ai-68c27`. This check made zero network requests and did not expose
the API key.

The automated journeys use temporary repositories and local HTTP fixtures. They
exercise the packaged MCP runtime, fresh-process selection, DNS proof reuse,
scope restrictions, app-only HTTP confirmation and saved regression creation,
and the exact source-template/missing-project-ID recovery path. They also cover
the separate landing page, multiple Firebase projects, request budgets,
cancellation and revocation.

The full regression suite passed **187 tests**, with **zero failures** and
**two opt-in Docker tests skipped**, in 91.8 seconds. Syntax checks passed for
107 JavaScript modules; parity covers 93 public commands/options and 87 typed
plugin tools. Muse's native validator accepts the local plugin package with no
diagnostics. After the final CLI ownership message adjustment, all 13 wizard
and app-connection tests passed again. Automated tool journeys do not establish interactive
picker rendering or a complete production UAT. The installed plugin, active
user session, production app and DNS records were not changed by this work.

Nothing has been committed, pushed, published or installed. The release version
remains unchanged until the remaining bug fixes are ready.
