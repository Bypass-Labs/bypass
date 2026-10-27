# Walk through Bypass inside Muse

Install and approve the plugin using the [README](../README.md), then open a new Muse session. No separate model configuration or Docker is required for this plugin workflow.

## Your application

1. Type `/bypass:start`, or ask: “Use Bypass to review this app and guide me through the missing setup.”
2. Muse reuses the initialized active repository or confirms your application folder/Git URL. A Git URL can be cloned into a suggested application folder; an existing matching checkout can be reused. The Bypass tooling folder is not silently treated as your app.
3. Muse surfaces the billing limitation: MCP does not attest subscription mode. Confirm your host is using its subscription. For confidential/personal code, select Standard mode by turning Contributor mode off in Muse `/settings`. Bypass does not change your settings.
4. Choose source review now, or connect the running app. For a deployed app, give its origin/environment. Bypass returns an exact TXT record name and value. Publish that record in DNS, then ask Muse to verify it. Source review can proceed while DNS propagates.
5. Authorize the exact read-only paths. Ownership alone does not authorize testing; production scope needs explicit production permission.
6. For live account-boundary tests, supply the **environment-variable names** for two distinct test accounts, the JSON identity endpoint, and one owner-owned resource path/ID. Muse can infer endpoint shapes from reviewed source but must not guess private resource IDs. Load app credentials privately in the environment that launches Muse; never paste their values into chat. Bypass validates both logins and owner access before proof.
7. Ask for the review. Muse plans, reads source, submits cited hypotheses and chooses approved HTTP probes. Bypass returns structured evidence. Muse interprets it and proposes/applies a fix using its normal coding tools and permissions, then requests retesting.
8. A previously confirmed issue whose fix passes becomes a saved test. Ask Muse to export it or run all saved checks. Use `/bypass:build` before adding a feature to retrieve security knowledge and behavior requirements.

You stay in Muse after external DNS/credential setup. Muse calls the typed tools; you do not copy JSON or run model-connection commands. `/bypass:status` gives Done / Now / Next; `/bypass:help` discovers actions.

## The self-contained demo

Type `/bypass:demo`. This request authorizes routine changes to a separate public fixture, not your customer app.

| Milestone | What you see | Evidence |
| --- | --- | --- |
| Setup | Generated app folder, loopback URL, two public accounts | No model profile or API key needed |
| Source investigation | Muse reads `policy.mjs` and `server.mjs`, identifies missing ownership check | Exact file/line/quote; suspected only |
| HTTP proof | Muse requests the configured invoice probe | Owner 200; other account 200; anonymous 401; unauthorized access confirmed |
| Fix | Muse applies a fixture-only policy change | Source edit alone is not a verified fix |
| Retest | Owner still succeeds; other account and anonymous are denied | Saved regression created after all controls pass |
| Replay/export | Independent Node test and deterministic replay | Zero plugin model calls |
| Regression | Fixture bug restored and the saved test fails | Expected security result, not an execution error |
| Restore/stop | Fixed again, verified and stopped | Evidence retained; prior application selection restored |

A demo may also run one monitor tick and retrieve feature context. That is one scheduled execution, not always-on monitoring. An explicitly requested legacy offline preview remains labeled seeded discovery; it never substitutes for a failed real review.

## Recovery

- **Source changed:** start a new review for fresh citations. Existing findings can still be retested after the fix.
- **App login/resource blocked:** repair the named credential reference or resource. DNS and prior evidence remain saved.
- **Muse authentication/allowance blocked:** use the host account/usage controls, then resume. No separate API request is made.
- **Plugin missing/stale:** inspect/approve the installed plugin and open a fresh session; loaded and installed versions are shown separately.
- **Interrupted host review:** ask Muse to inspect its durable review status and continue. HTTP actions are bounded/cancellable; incomplete and not-run checks are explicit.

The standalone wizard is a separate experience: `bypass onboard` asks for an API provider, key reference, model and endpoint, then optional app setup. [CLI examples and migration](AI_MODES.md).
