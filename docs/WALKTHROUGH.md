# Walk through Bypass inside Muse

Install and approve the plugin using the [README](../README.md), then open a new Muse session. No separate model configuration or Docker is required for this plugin workflow.

## Your application

1. Type `/bypass:start`, or ask: “Use Bypass to review this app and guide me through the missing setup.”
2. Muse reuses the initialized active repository or confirms your application folder/Git URL. A Git URL can be cloned into a suggested application folder; an existing matching checkout can be reused. The Bypass tooling folder is not silently treated as your app.
3. Muse surfaces the billing limitation: MCP does not attest subscription mode. Confirm your host is using its subscription. For confidential/personal code, select Standard mode by turning Contributor mode off in Muse `/settings`. Bypass does not change your settings.
4. Choose source review now, or connect the running app. For a deployed app, give its origin/environment. Bypass returns an exact TXT record name and value. Publish that record in DNS, then ask Muse to verify it. Source review can proceed while DNS propagates.
5. Authorize the exact read-only paths. Ownership alone does not authorize testing; production scope needs explicit production permission.
6. Credentials are optional. Muse investigates signup from source. If account creation is authorized, Bypass tries up to two dedicated JSON/Firebase signups and stores their credentials privately; otherwise it continues source/anonymous tests. Existing account files can be imported without exports or a restart. Unverified access is flagged with evidence; it becomes a policy violation only when verified email is required for that route.
7. Muse derives routes/selectors and discovers exact owned IDs from an authorized collection. It reads enough source, submits cited hypotheses, and executes approved JSON/HTML probes. Batched completion reduces model round trips while preserving the actual HTTP controls. Missing data, unsupported signup and blocked probes remain visible gaps.
8. Confirmed HTTP findings immediately save failing regressions. Export one before fixing the app, or let Muse apply an authorized fix and replay it. A passing replay closes only its matching previously confirmed finding; blocked credentials cannot count as a fix. Use `/bypass:build` before adding a feature to retrieve the saved context.

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

The standalone wizard is a separate experience: `bypass onboard` asks for an API provider, key reference, model and endpoint, then optional app setup. [CLI examples and migration](AI_MODES.md).
