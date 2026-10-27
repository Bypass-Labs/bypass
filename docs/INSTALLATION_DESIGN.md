# Start in the coding agent; keep the complete runtime

Research checked on 2026-10-27 against the primary sources below and installed Muse 1.4.13. The goal is one clear entry point, an honest permission boundary and a usable first session.

| Integration | What makes starting easier | What Bypass adopts |
| --- | --- | --- |
| [Strix coding-agent skills](https://github.com/usestrix/strix#-use-strix-from-your-coding-agent) | A skill brings the workflow into the agent; its CLI/cloud runtime is a separate concern. | A discoverable installation skill that installs the full product and explains its actual readiness. |
| [Superpowers](https://github.com/obra/superpowers#installation) | Uses native plugins where supported, and a “fetch and follow” prompt for OpenCode. Its Muse integration still requires runtime approval and a new session. | One prompt inside Muse, followed by its native Runtime review. No invented hot reload for MCP. |
| [Context7](https://github.com/upstash/context7#installation) | One setup command handles client configuration, with explicit CLI/skill and MCP choices. | One installer handles platform, runtime, PATH and registration, with an explicit Muse versus standalone entry point. |
| [Vercel Skills](https://github.com/vercel-labs/skills/blob/main/docs/commands.md#skills-add) | Can install a SKILL.md directly from HTTPS, not only GitHub. | Serve the bootstrap from the existing release domain; GitHub source access is unnecessary. |

## The shipped journey

1. In Muse: `Read https://bypasslabs.ai/install/muse.md and install Bypass for Muse.`
2. The host reads the skill, checks the OS/Muse availability and executes the matching plugin installer. It downloads a checksum-verified, self-contained release, sets PATH and installs the native plugin at user scope. Installation invokes no AI review and requests no provider key.
3. The user reviews the local MCP server and session-context hook in `/plugins` → Installed → Bypass → Runtime. Then they open a fresh Muse session and use `/bypass:start`.
4. Bypass resumes missing application setup. Source review can start immediately; deployed HTTP proof still needs ownership, bounded authorization and account references. Demo, fixes, deterministic replay, exports, monitoring and security memory remain part of the same native plugin.

The terminal alternative is one command: `curl -fsSL https://bypasslabs.ai/install/muse | bash`, or Windows `irm https://bypasslabs.ai/install/muse.ps1 | iex`. Updating/repairing uses that same command. It preserves identical-package approvals and project evidence, validates before replacement, attempts rollback on failed replacement, and reports the actual native capability state. A disabled/rejected capability is not silently enabled.

## Why not just a marketplace or npx?

Muse's [marketplaces](https://meta-models.github.io/muse-code-sdk/next/guides/plugins/concepts/marketplaces-and-updates/) require adding a catalog and then installing a plugin. They do not supply the platform-specific Node binary for us. They can become an additional discovery channel; creating one now would add steps and require another distribution source.

The [Skills registry](https://github.com/vercel-labs/skills/blob/main/docs/agents.md) currently has no Muse selector. Project-scoped `-a universal` writes `.agents/skills`, which [Muse supports](https://meta-models.github.io/muse-code-sdk/next/guides/extend/skills/). Global universal installs use `~/.config/agents/skills`, so that flag is not advertised as a Muse-global install. `npx` also needs system Node. We support the direct-URL project skill as an option; the primary prompt avoids those prerequisites.

## Boundaries we keep

- [Muse approval](https://meta-models.github.io/muse-code-sdk/next/guides/plugins/concepts/trust-review-and-scopes/) binds to the package and capability definition. Package `active=true` alone is not runtime approval. Both required capabilities must be `trusted_enabled` before we report ready for a new session.
- No automatic approval, silent billing/provider switch, nested Muse inference, raw-secret prompts or automatic testing of a production app.
- Installing a skill is not installing the native runtime. Installing/approving the runtime does not load it into an already running chat.
- Public bootstrap files are versioned release assets. Promotion checks all assets before moving the public URLs. The source repository stays private.

## Verification

Automated coverage includes installer argument/preflight behavior, absent Muse, plugin registration failure, identical-package reruns, capability state reporting, changed-package review, failed replacement rollback, public asset promotion, all 78 MCP tools and CLI/plugin command parity. Native install/inspect/approval checks are performed with isolated XDG directories, never the user's active plugin store. Windows plugin-entrypoint parsing and installer execution run in the existing PowerShell 5.1/7 release gate. Installation tests are distinct from a paid model test or a production security review.
