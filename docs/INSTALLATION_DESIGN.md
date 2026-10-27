# One-command installation for the complete Muse plugin

Research checked on 2026-10-27 against the primary sources below and installed Muse 1.4.13. The goal is one clear entry point, an honest permission boundary and a usable first session.

| Integration | What makes starting easier | What Bypass adopts |
| --- | --- | --- |
| [Strix coding-agent skills](https://github.com/usestrix/strix#-use-strix-from-your-coding-agent) | A skill brings the workflow into the agent; its CLI/cloud runtime is a separate concern. | A discoverable installation skill that installs the full product and explains its actual readiness. |
| [Superpowers](https://github.com/obra/superpowers#installation) | Uses native plugins where supported, and a “fetch and follow” prompt for OpenCode. Its Muse integration still requires runtime approval and a new session. | Native Runtime review and a fresh session. A fetch-and-follow prompt remains an optional installation route. |
| [Context7](https://github.com/upstash/context7#installation) | One setup command handles client configuration, with explicit CLI/skill and MCP choices. | One installer handles platform, runtime, PATH and registration, with an explicit Muse versus standalone entry point. |
| [Vercel Skills](https://github.com/vercel-labs/skills/blob/main/docs/commands.md#skills-add) | Can install a SKILL.md directly from HTTPS, not only GitHub. | Serve the bootstrap from the existing release domain; GitHub source access is unnecessary. |

## The shipped journey

1. Run `curl -fsSL https://bypasslabs.ai/install/muse | bash` in a macOS/Linux terminal, or `irm https://bypasslabs.ai/install/muse.ps1 | iex` in Windows PowerShell. The installer checks Muse availability, downloads a checksum-verified release with its own Node runtime, sets PATH and registers the full native plugin at user scope. Installation invokes no model and requests no provider key.
2. The installer explains the security-tools and session-context permissions and asks “Allow these permissions and open Muse?” Answering `y` records approval for exactly those two capabilities through Muse's native CLI, checks the result, and opens a new interactive Muse session in the current folder with onboarding already requested.
3. Bypass resumes missing application setup. Source review can start immediately; deployed HTTP proof still needs ownership, bounded authorization and account references. Demo, fixes, deterministic replay, exports, monitoring and security memory remain part of the same native plugin. Muse's own account/workspace trust prompts still apply when needed.

The direct installer is the recommended path: no prompt, skill discovery or agent interpretation is needed to install. It supports macOS, glibc Linux and Windows on x64/arm64 (PowerShell 5.1+). Git is needed when connecting a Git repository.

Updating/repairing uses that same command. It preserves identical-package approvals and project evidence, validates before replacement, attempts rollback on failed replacement, and reports the actual native capability state. A disabled/rejected capability is not silently enabled.

Interactive installation reads consent from the real terminal, including when the script arrives through `curl | bash`. Empty input, decline and cancellation do not approve anything. CI, redirected output and `BYPASS_NO_OPEN_MUSE=1` leave approval and opening Muse to the user. The fallback is `/plugins` → Installed → Bypass → Runtime, followed by a new session and `/bypass:start`. An unexpected capability or a package that changes while the user is deciding requires a new review.

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
