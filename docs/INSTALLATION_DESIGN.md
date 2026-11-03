# One-command installation for the complete Muse plugin

Research checked on 2026-10-27 against the primary sources below and installed Muse 1.4.13. The goal is one clear entry point, an honest permission boundary and a usable first session.

| Integration | What makes starting easier | What Bypass adopts |
| --- | --- | --- |
| [Strix coding-agent skills](https://github.com/usestrix/strix#-use-strix-from-your-coding-agent) | A skill brings the workflow into the agent; its CLI/cloud runtime is a separate concern. | A discoverable installation skill that installs the full product and explains its actual readiness. |
| [Superpowers](https://github.com/obra/superpowers#installation) | Uses native plugins where supported, and a “fetch and follow” prompt for OpenCode. Its Muse integration still requires runtime approval and a new session. | Native Runtime review and a fresh session. A fetch-and-follow prompt remains an optional installation route. |
| [Context7](https://github.com/upstash/context7#installation) | One setup command handles client configuration, with explicit CLI/skill and MCP choices. | One installer handles platform, runtime, PATH and registration, with an explicit Muse versus standalone entry point. |
| [Vercel Skills](https://github.com/vercel-labs/skills/blob/main/docs/commands.md#skills-add) | Can install a SKILL.md directly from HTTPS, not only GitHub. | Serve the bootstrap from the existing release domain; GitHub source access is unnecessary. |

## The shipped journey

During plugin installation, a live checklist shows **Check setup → Install plugin → Verify installation**, with Bypass colors, the active operation's elapsed time, the two-minute Muse timeout, cancellation and the next action. Stages advance only when the corresponding native operation finishes. After thirty seconds without a result, the display explicitly says it is waiting for Muse. Success appears only after Muse confirms a valid installation. The installer restores a replaced plugin if installation fails or is cancelled.

This follows the [Command Line Interface Guidelines](https://clig.dev/) on immediate feedback, bounded operations and readable nonterminal output, and [NN/g's guidance for long waits](https://www.nngroup.com/articles/designing-for-waits-and-interruptions/) on showing completed/current/remaining steps when reliable percentages are unavailable. There is no invented percentage or completion estimate. Redirected output, CI, `TERM=dumb` and `BYPASS_PLAIN=1` use plain status lines; `NO_COLOR` removes colors. PTY checks exercise the shipped entrypoint with slow success, failure, cancellation/rollback, narrow layout and resize.

1. Run `curl -fsSL https://bypasslabs.ai/install/muse | bash` in a macOS/Linux terminal, or `irm https://bypasslabs.ai/install/muse.ps1 | iex` in Windows PowerShell. The installer checks Muse availability, downloads a checksum-verified release with its own Node runtime, sets PATH and registers the full native plugin at user scope. Installation invokes no model and requests no provider key.
2. The installer names **Security tools** (selected-code review, scoped app checks, local evidence/tests) and **Security memory** (loading saved project context in future sessions), marking each as needing permission or already enabled. It explains model access to reviewed code/context and the ownership/scope requirements for live testing. The choice is explicit: `y` enables the listed permissions and starts setup here; `n` or Enter keeps the installation for later. “Enable Bypass and open Muse?” is the only consent question. After `y`, live progress shows the package check, each pending permission and final verification before opening Muse. Approval still uses the native manager, preserves existing decisions, checks package identity, and stops on failure or cancellation.
3. Bypass resumes missing application setup. Source review can start immediately; deployed HTTP proof needs ownership and bounded authorization, with accounts optional for checks that do not require them. Demo, fixes, deterministic replay, exports, monitoring and security memory remain part of the same native plugin. Muse's own account/workspace trust prompts still apply when needed.

## Connecting an app: choices first (0.7.7)

The old question mixed an address, an environment and the option to skip live testing. Muse could turn this into a menu that elevated a documented local port into an apparent running-app recommendation. Repository documentation is not evidence of a current deployment, and a local address must not replace a production URL the user already supplied.

The revised flow adopts three patterns checked against primary documentation on 2026-10-27:

- [Strix CLI](https://github.com/usestrix/strix/blob/main/docs/usage/cli.mdx) accepts repositories and URLs directly, including both in one command. Bypass reuses the repository and app URL already given in the conversation.
- [Vercel project linking](https://vercel.com/docs/cli/project-linking) offers an identified matching project and remembers the link. Bypass reuses an exact saved app and its ownership record; an unconfirmed README address is not an identified deployment.
- [OpenClaw onboarding](https://docs.openclaw.ai/start/wizard) separates Quick start from custom configuration and reuses configured choices. Bypass asks for the next missing input and postpones advanced details until relevant. The [CLI Guidelines](https://clig.dev/) also recommend human-readable output, useful defaults and clear interaction.

On a fresh start, show the review-type picker:

```text
What would you like to review?
1. Code + running app (recommended)
2. Code only
3. Running app only
Custom instructions are available.
```

Reuse a supplied mode, repository, app URL or environment. For code, connect the actual repository before live setup. Ask for the URL only when an app mode was selected and its address is missing. If the environment is missing, offer Production, Staging, Preview and Local development with custom instructions. Production can have no real users. Loopback is recognized automatically; no remote environment is inferred from the hostname. Native permission questions require an explicit answer.

`bypass_onboarding` accepts these conversational inputs and returns a structured text/choice input or a concrete next tool action. It remains read-only: no startup command, discovery request, DNS lookup, target write or authorization is performed. `mode: code` bypasses live setup for the current review and preserves saved app configuration. The CLI accepts the same plain-language choice and `code only` answer.

After the app is selected, propose source-derived paths, request rate and expiry for permission. The default flow confirms app control together with that explicit scope approval; it does not require a DNS change. Approval immediately starts running-app-only testing with the displayed plan and default bounded budgets—no repeated scope or start questions. Teams can configure a DNS TXT record or HTTPS verification file as a separate ownership proof. Credentials remain optional. Muse renders its own question controls; the plugin supplies the question type and instructions, rather than owning that UI. Tests cover the packaged MCP conversation, saved app reuse, URL validation, code-only review, optional DNS/HTTPS proof, and the production authorization gate.

The direct installer is the recommended path: no prompt, skill discovery or agent interpretation is needed to install. It supports macOS, glibc Linux and Windows on x64/arm64 (PowerShell 5.1+). Git is needed when connecting a Git repository.

Updating/repairing uses that same command. It preserves identical-package approvals and project evidence, validates before replacement, attempts rollback on failed replacement, and reports the actual native capability state. A disabled/rejected capability is not silently enabled.

Interactive installation reads consent from the real terminal, including when the script arrives through `curl | bash`. Empty input, decline and cancellation do not approve anything. CI, redirected output and `BYPASS_NO_OPEN_MUSE=1` leave approval and opening Muse to the user. The fallback is `/plugins` → Installed → Bypass → Runtime, followed by a new session and `/bypass:start`. An unexpected capability or a package that changes while the user is deciding requires a new review.

### Manual runtime approval and missing MCP tools

Confirmed with Muse Code 1.4.14 on 2026-10-30: Bypass was enabled and its slash
commands were visible, but its `security` MCP server remained `review_needed`.
The MCP panel showed **No MCP servers configured**. After reviewing Bypass's
runtime permissions, this terminal command resolved the approval blocker:

```bash
MUSE_NO_AUTO_UPDATE=1 muse plugins approve bypass
MUSE_NO_AUTO_UPDATE=1 muse plugins inspect bypass --json
```

Verify `trusted_enabled` for both required runtime capabilities: MCP server
`security` and hook `session-context`. Then start a **new Muse session**. Enabled
status, visible slash commands, and an approved hook alone do not establish that
the MCP server is available. Recheck approval after changing the installed package.

For CodeQL, first call `bypass_scanner_capabilities` through the native Muse
session, then run discovery. A successful CLI scan or direct packaged-server
test does not prove native Muse tool exposure. If tools are missing, report the
activation blocker and stop instead of substituting the CLI during the MCP test.

## Optional: install from inside Muse

Ask: `Read https://bypasslabs.ai/install/muse.md and install Bypass for Muse.` The host reads the skill and executes the same OS-specific installer. This is a convenience for users already in a chat; it adds no capabilities over the direct command. Headless installation does not open a nested Muse session or record approval; the user completes the manual fallback above.

## Why not just a marketplace or npx?

Muse's [marketplaces](https://meta-models.github.io/muse-code-sdk/next/guides/plugins/concepts/marketplaces-and-updates/) require adding a catalog and then installing a plugin. They do not supply the platform-specific Node binary for us. They can become an additional discovery channel; creating one now would add steps and require another distribution source.

The [Skills registry](https://github.com/vercel-labs/skills/blob/main/docs/agents.md) currently has no Muse selector. Project-scoped `-a universal` writes `.agents/skills`, which [Muse supports](https://meta-models.github.io/muse-code-sdk/next/guides/extend/skills/). Global universal installs use `~/.config/agents/skills`, so that flag is not advertised as a Muse-global install. `npx` also needs system Node. The direct installer avoids these extra prerequisites.

For users who already use skills, run this from the application folder with Node 22.20+:

```bash
npx skills add https://bypasslabs.ai/install/muse.md -a universal
```

Then run `/skills reload` in Muse and ask “Install Bypass for Muse.” This installs the bootstrap skill; it still runs the full native installer. It is not a shorter path than the recommended command.

## Boundaries we keep

- [Muse approval](https://meta-models.github.io/muse-code-sdk/next/guides/plugins/concepts/trust-review-and-scopes/) binds to the package and capability definition. Package `active=true` alone is not runtime approval. Both required capabilities must be `trusted_enabled` before we report ready for a new session.
- No automatic approval, silent billing/provider switch, nested Muse inference, raw-secret prompts or automatic testing of a production app.
- Installing a skill is not installing the native runtime. Installing/approving the runtime does not load it into an already running chat.
- Public bootstrap files are versioned release assets. Promotion checks all assets before moving the public URLs. The source repository stays private.

## Verification

Automated coverage includes installer argument/preflight behavior, absent Muse, plugin registration failure, identical-package reruns, capability state reporting, changed-package review, failed replacement rollback, public asset promotion, all 78 MCP tools and CLI/plugin command parity. Native install/inspect/approval checks are performed with isolated XDG directories, never the user's active plugin store. Windows plugin-entrypoint parsing and installer execution run in the existing PowerShell 5.1/7 release gate. Installation tests are distinct from a paid model test or a production security review.

### Terminal handoff regression (0.5.3)

On macOS, passing an opened `/dev/tty` alias as Muse stdin caused its kqueue input registration to fail. Installation, permission approval and MCP startup completed, but the UI stayed blank before the initial request. The piped installer now releases its consent reader and gives Muse a readable descriptor for the actual terminal device. Direct terminal and Windows launches retain their existing handoff.

The terminal smoke test now waits for interactive input through the child process and uses the platform event selector, including kqueue on macOS. It fails on the 0.5.2 handoff and passes on 0.5.3. Both Linux and macOS checks gate publication. Native Muse 1.4.14 was also exercised through a piped installer in an isolated store with the offline echo provider: visible UI, submitted initial request, response and clean interactive exit. This verifies the terminal handoff; it is not a paid-model onboarding or production review test.
