---
name: bypass-install
description: Install, update or repair the full Bypass security plugin for Muse Code. Use when the user wants Bypass in Muse Code, has only installed its skill, or cannot see its native tools or commands.
---

# Install Bypass in Muse Code

This skill handles installation. The installed product is the full native plugin: MCP tools, slash commands, SessionStart security context, source review, scoped HTTP proof, saved regressions and local security memory. A downloaded skill alone is not that product.

## Do the setup

1. Check the OS and whether `muse` is available. Run from the user's application folder when supplied; never select the Bypass tooling repository as their app. If Muse Code is missing, direct the user to https://dev.meta.ai to install/sign in, then resume. Do not request provider API keys, install Docker or launch nested Muse Code inference.
2. Tell the user: “I’ll install the full plugin. Muse Code will ask you to review its local tool server and session-context hook; then you’ll open a fresh session.” The user's install/update request authorizes downloading and registering Bypass. Follow the host's normal execution permissions.
3. Run the correct command yourself:

   macOS / Linux:
   ```bash
   curl -fsSL https://bypasslabs.ai/install/muse | bash
   ```

   Windows PowerShell:
   ```powershell
   irm https://bypasslabs.ai/install/muse.ps1 | iex
   ```

   The installer includes Node, verifies the release checksum, configures PATH and registers the plugin at user scope. No GitHub checkout, npm or existing Bypass command is required. Repeat the same command for update/repair; an identical package preserves existing permission decisions. A changed package requires renewed review. Do not replace existing user directories or edit Muse Code's plugin database by hand.
4. Read the actual result. **Installed** is different from **approved**, which is different from **loaded in this session**. If setup fails, report the exact reason and one recovery action; do not claim success or silently switch to standalone AI. A missing host, failed download or incomplete integration is not a completed installation.
5. Guide the user to `/plugins` → **Installed** → **Bypass for Muse Code** → **Runtime**. Explain the two permissions: the MCP server executes Bypass operations locally, including authorized app requests and evidence writes; the SessionStart hook retrieves saved workspace/security context. The user reviews and approves these in Muse Code. Do not run `muse plugins approve` on their behalf unless they explicitly approve those capabilities after seeing this explanation. Do not disable host trust checks. If the package is disabled, use the panel to enable it; respect a deliberate rejection.
6. Ask them to start a **new Muse Code session in their application folder**, then use **`/bypass:start`**. A running chat cannot acquire the new MCP server just because the install succeeded. Do not retry missing tools in a loop. An already approved, unchanged installation only needs a new session if tools are absent.

Keep the handoff short: **Done** (installed version), **Now** (permission review, if needed), **Next** (fresh session → `/bypass:start`). Do not present inspect/approve/replace commands as a checklist users must memorize. `bypass integrate status --json` is an optional diagnostic; use the installer's full executable path if this shell has not refreshed PATH.

## First session

When Bypass tools are present, call `bypass_onboarding` and follow the installed bypass skill. Reuse saved setup. Confirm the application repository only when needed, then guide app URL → exact DNS TXT ownership record for a deployed app → testing scope → two account credential references → one owned resource. Never ask for raw credentials in chat. Offer source review while live setup is pending, or `/bypass:demo` for the isolated fixture.

Reasoning stays in the active Muse Code session. Bypass makes no independent model request; host subscription billing is not attested through MCP. Ask the user to check their Muse Code billing mode; for confidential code, use Standard mode with Contributor mode off. Do not change account settings for them.

If asked to install in another coding agent, explain that this native integration is for Muse Code. Do not install a partial MCP-only substitute and call it equivalent. The standalone CLI is available at https://bypasslabs.ai/install (Windows: https://bypasslabs.ai/install.ps1); standalone AI requires an explicitly configured provider API key and Docker.
