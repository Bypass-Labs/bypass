# Walk through Bypass inside Muse

Setup uses choices with recommendations and a custom-answer/note field. Reuse inputs already given; do not answer the same question twice. For signed-in checks, choose **Create two test accounts**, **Use existing test accounts**, or **Continue without accounts**. The first option records permission for at most two attempts; it does not ask you to find Firebase IDs or keys. Bypass discovers those from authorized public app configuration. Discovery failure offers recovery choices while other checks continue. Arbitrary CLI custom instructions are interpreted by Muse only; standalone pickers accept exact custom values.


Install and approve the plugin using the [README](../README.md), then open a new Muse session. No separate model configuration or Docker is required for this plugin workflow.

## Your application

1. Type `/bypass:start`, or ask: “Use Bypass to review this app and guide me through the missing setup.”
2. Choose **Code only**, **Code + running app**, or **Running app only** in Muse's picker. Code review needs the actual application folder or Git URL. Muse connects/clones that source and validates it before calling it ready. An empty parent directory and the Bypass tooling folder are not your application. App-only connects a managed profile with no repository.
3. Muse surfaces the billing limitation once: MCP does not attest subscription mode. Confirm your host is using its subscription. For confidential/personal code, select Standard mode by turning Contributor mode off in Muse `/settings`. Bypass does not change your settings.
4. For app review, Muse reuses the supplied app URL and environment. If missing, provide the URL, then choose **Production**, **Staging**, **Preview**, or **Local development** in the environment picker. Localhost is recognized automatically. Bypass reuses valid ownership for the same normalized app origin across checkout changes and new sessions. Otherwise publish its exact TXT record and say “check DNS.” Code review can continue while DNS updates when code was selected.
5. Choose allowed methods and paths. The scope summary includes the app, environment, rate, expiry and optional anonymous reads of public pages/scripts for sign-in discovery. POST creates test data/jobs; PUT/PATCH modify data; DELETE removes it. Ownership alone does not authorize testing. Existing exact scope carries across a checkout switch for the same selected app; a different app requires its own permission.
6. Credentials are optional. Muse investigates signup from source or authorized app observations. Once account creation is authorized, Bypass tries up to two dedicated JSON/Firebase signups and stores credentials privately. It first resolves missing Firebase config from existing config or public app pages and linked scripts. A missing `.env` is not a reason to stop and ask for the project ID. Generated config is kept separately from the app's environment. A synthetic email namespace is supplied automatically; existing attempts prevent duplicate users. Existing accounts can also be imported without exports or a restart. Unverified access is an observation unless the route requires verified email.
7. Muse derives routes/selectors and discovers exact owned IDs from an authorized collection. It reads source, submits cited hypotheses, and executes approved JSON/HTML probes. The saved worklist tracks discovered routes and configured controls. A finding does not end the assessment: Muse continues independent checks, adds newly discovered probes, and records specific reasons for blocked or unsupported routes. An early `finish` returns the next pending action. Each route marked checked requires runtime HTTP evidence; a source assessment cannot manufacture a pass.
8. During review, Muse shows Done / Now / Next, elapsed time and executed/remaining/blocked counts. Time estimates are based on observed HTTP durations and cover only configured probes; source investigation and resource setup remain uncertain. Progress messages come from Muse while it reasons and from Bypass while tools execute.
9. Confirmed HTTP findings immediately save failing regressions. The final report includes confirmed and source-only findings, recommendations, saved checks, remaining blockers and cleanup status. A review does not authorize application edits; “keep working” continues the assessment. A separate explicit request to fix an issue can start remediation and replay its saved test. A passing replay closes only its matching previously confirmed finding; blocked credentials cannot count as a fix. Use `/bypass:build` before adding a feature to retrieve the saved context.

You stay in Muse after external DNS setup. Muse calls the typed tools; you do not copy JSON or run model-connection commands. `/bypass:status` gives Done / Now / Next; `/bypass:help` discovers actions.

## The self-contained demo

Type `/bypass:demo`. This request authorizes routine changes to a separate public fixture, not your customer app.

| Milestone | What you see | Evidence |
| --- | --- | --- |
| Setup | Generated app folder, loopback URL, two public accounts | No model profile or API key needed |
| Source investigation | Muse reads `policy.mjs` and `server.mjs`, identifies missing ownership check | Exact file/line/quote; suspected only |
| HTTP proof | Muse requests the configured invoice probe | Owner 200; other account 200; anonymous 401; unauthorized access confirmed |
| Fix | Muse applies a fixture-only policy change | Source edit alone is not a verified fix |
| Retest | Owner still succeeds; other account and anonymous are denied | Existing failing regression passes; matching finding becomes fixed |
| Replay/export | Independent Node test and deterministic replay | Zero plugin model calls |
| Regression | Fixture bug restored and the saved test fails | Expected security result, not an execution error |
| Restore/stop | Fixed again, verified and stopped | Evidence retained; prior application selection restored |

A demo may also run one monitor tick and retrieve feature context. That is one scheduled execution, not always-on monitoring. An explicitly requested legacy offline preview remains labeled seeded discovery; it never substitutes for a failed real review.

## Recovery

- **Source changed:** start a new review for fresh citations. Existing findings can still be retested after the fix.
- **App login/resource blocked:** repair the named credential reference or resource. DNS and prior evidence remain saved.
- **Muse authentication/allowance blocked:** use the host account/usage controls, then resume. No separate API request is made.
- **Plugin missing/stale:** inspect/approve the installed plugin and open a fresh session; loaded and installed versions are shown separately.
- **Stopped real fixture:** resume its saved instance; known fixture forms restart without new IDs. A deliberately stopped fixture requires an explicit resume.
- **Interrupted host review:** ask Muse to inspect its durable review status and continue. HTTP actions are bounded/cancellable; incomplete and not-run checks are explicit.

The standalone wizard is a separate experience: `bypass onboard` asks for an API provider, key reference, model and endpoint, then the selected code/app setup. App-only selections persist across CLI invocations from the same folder; `--project` still overrides the saved selection. [CLI examples and migration](AI_MODES.md).
