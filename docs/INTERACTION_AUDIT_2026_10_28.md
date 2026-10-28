# Choices-first interaction audit — October 28, 2026

Local implementation only. Not committed, published, or installed into the active Muse session. This extends the [onboarding session audit](ONBOARDING_AUDIT_2026_10_28.md).

## Problem and resulting behavior

The reported Firebase prompt mixed three different things: permission to create accounts, discoverable public application configuration, and a synthetic email namespace that Bypass can suggest. It handed implementation work back to the user before discovery had been exhausted.

The account decision is now:

```text
How should Bypass test signed-in account access?

  Create two test accounts (recommended)
    Up to two dedicated signup attempts on the selected app.
    Bypass discovers configuration and stores credentials privately.
  Use existing test accounts
    Connect a private account file; do not paste tokens into chat.
  Continue without accounts
    Keep source and anonymous checks; report signed-in coverage gaps.

  Custom instructions: use the host's custom answer or optional note.
```

The picker includes the selected origin, two-attempt maximum and suggested email namespace. Choosing creation explicitly records permission through `bypass_choose_accounts`; configuration can then reuse it after a process restart. Existing/skip choices persist too. Discovery failure returns a recovery picker rather than another compound account/config question. Scope changes invalidate unused creation consent. Deferring signup preserves previous attempts and cannot reset the two-account budget.

## Audit inventory

All interactive `ask`, question descriptors and installer prompts in `src`, `bin`, installation scripts, plugin commands and the plugin skill were inspected. The shared interaction contract is in `src/interaction.mjs`.

| Interaction | Behavior after this audit |
| --- | --- |
| Review type | Code, code + app, or app only; native picker and custom notes in Muse. |
| Repository | Reuse a supplied path/URL. Offer a detected source folder only when it contains eligible source. Plugin offers Git/local-folder choices when unresolved. An unknown exact path/URL remains one value input. |
| Clone destination | Suggested unused folder or custom path; occupied folders keep the source URL while the destination is corrected. |
| App URL | Reuse a supplied URL. Ask once for the exact address when none is known; never offer an invented localhost port. |
| Environment | Production, staging, preview, local. Do not infer or recommend a remote environment from a hostname. |
| Ownership | Check DNS, review code/wait, or HTTPS file; local ownership uses explicit confirm/defer. Existing valid same-origin proof is reused. |
| Testing scope | Individual HTTP methods/custom methods plus saved/common path suggestions and custom paths. Show scope before authorization. Declining production consent returns without saving or treating it as a tool failure. |
| Model configuration | Existing provider presets; environment-variable name, model and endpoint suggestions with exact custom values. Collect no API secret in prompts. Plugin continues to use Muse's model. |
| Test accounts | Create / existing / skip with saved decisions, explicit creation permission and custom notes. No required Firebase-ID or email-domain question before discovery. |
| Firebase ambiguity/recovery | Offer observed projects without guessing a recommendation. On failure: continue other checks, use a known sign-in page, or provide a config file; retain creation permission. |
| Identity setup | Credential type, variable-reference name, identity endpoint, header and selector suggestions/custom values. Known private file imports remain available through the shared CLI/MCP service; Muse performs them itself. |
| Resources | Muse derives routes and discovers owned IDs using authorized tools. Standalone manual probe setup still needs exact unknown resource path/ID; there are no fabricated customer-ID suggestions. |
| Saved checks/findings | Select actual existing objects. Muse interprets custom notes and invokes typed tools. Do not invent an audit reason. |
| Monitoring | Saved schedule reuse; hourly / 15-minute / daily / custom cadence when missing. Existing worker and awake-machine requirements remain explicit. |
| Installation | Numbered enable/defer choices, plus “review or customize permissions inside Muse.” Enter defers. Native approval and package-change verification remain enforced. |
| Help/recovery | Native workflow and recovery pickers; reuse prior answers and show the specific blocker. All slash commands inherit the same interaction policy. |

## Custom input and recommendations

Muse uses the host's native question tool, including its free-text answer or note field. Custom instructions refine a supported action; they do not silently authorize requests, resolve contradictory choices, or promise unsupported operations. Recommendations use saved settings, observed candidates or clearly labeled common defaults. Multiple plausible Firebase projects and unknown deployment environments have no invented recommendation.

CLI value pickers accept arrows, numbered choices, direct typed custom values and a separate custom-entry option. CLI permission prompts accept an explicit selection and defer by default. The standalone CLI does not interpret arbitrary natural-language instructions; Muse does. Enumerated modes remain bounded by supported capabilities.

Remaining text inputs are intentional: an unknown exact Git/app URL, file path, resource identifier, custom value, feature requirements or truthful audit reason. Enter-to-continue, command entry and navigation are not configuration questions. Secrets must never be entered into chat.

The standalone engine wizard does not autonomously infer all signup fields. Typed registration configuration remains available through CLI commands; Muse discovers and supplies those fields. This audit does not claim identical reasoning behavior between the two execution modes.

## Verification and release boundary

- Initial focused suite: 65 passed; one outdated installer-copy assertion was corrected.
- Targeted regression suite: 50 passed, zero failed in 33.3 seconds. Covers keyboard/custom selection, consent deferral, configuration recovery, persisted account choices across fresh packaged MCP processes and existing signup proof/budget behavior.
- Final full suite: **196 passed, zero failed, two opt-in Docker tests skipped**, 93.5 seconds (`/tmp/bypass-interaction-full-suite.log`).
- Syntax: 109 JavaScript modules checked. Parity: all 94 public CLI commands and options mapped to 88 typed plugin tools.
- Native `muse plugins validate plugin --json`: valid, no diagnostics (`/tmp/bypass-interaction-plugin-validation.json`).
- `git diff --check`: passed.

No new requests were sent to `job-radar.app`, no production accounts were created, and the user's installed plugin/session was not changed. Native host question rendering and a fresh interactive Muse acceptance pass remain release checks; automated fixture/MCP tests are not production or visual UAT.
