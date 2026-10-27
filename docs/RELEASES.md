# R2 releases and one-line installation

For the **Muse plugin**, run:

```bash
curl -fsSL https://bypasslabs.ai/install/muse | bash
```

Windows: `irm https://bypasslabs.ai/install/muse.ps1 | iex`.

Run it from your app folder. After explaining the two permissions, the installer asks once to approve them and open Muse. Answer `y` to begin onboarding in a new Muse session automatically. Noninteractive installation leaves permission review and session startup to the user. [Quick start](../README.md#start-in-muse).

## Standalone CLI installation

Windows PowerShell 5.1 / PowerShell 7:

```powershell
irm https://bypasslabs.ai/install.ps1 | iex
```

macOS / Linux:

```bash
curl -fsSL https://bypasslabs.ai/install | bash
```

On macOS/Linux, `-f` makes an HTTP error stop the download. The Bash installer downloads the latest tested main build, verifies SHA-256, and atomically updates the local `current` link. It installs under `~/.local/share/bypass` with a launcher at `~/.local/bin/bypass`. It uses no sudo and does not modify customer repositories. Windows locations and PATH behavior are described below.

The installer detects the configured shell from `SHELL` and adds one managed PATH block to its startup files. For Bash, it updates `.bashrc` plus the first existing login profile in Bash's order: `.bash_profile`, `.bash_login`, `.profile`; when none exists, it creates `.bash_profile`. It never creates a higher-priority file that would hide an existing login profile. For Zsh, it updates `.zshrc` and `.zprofile`, respecting an exported `ZDOTDIR`. Existing content, profile symlinks and permissions are preserved. Repeated installs keep one managed block and one PATH entry. Unsupported shells and unwritable profiles receive an actionable message without undoing the installation.

Open a new terminal, or run the printed `export PATH=…` command to activate Bypass in the existing terminal. A piped child process cannot change its parent shell's environment. The installer prints full-path commands that work immediately too. Set `BYPASS_NO_MODIFY_PATH=1` on the bash process to opt out (for example, `curl -fsSL https://bypasslabs.ai/install | BYPASS_NO_MODIFY_PATH=1 bash`). CI uses this opt-out for its temporary install paths; automated tests independently exercise Bash and Zsh startup files. Pinned releases before 0.3.2 retain their manual PATH setup.

Startup-file references: [Bash](https://www.gnu.org/software/bash/manual/html_node/Bash-Startup-Files), [Zsh](https://zsh.sourceforge.io/Doc/Release/Files.html).

Artifacts contain the CLI, native Muse plugin, and an official checksum-pinned Node.js runtime. Six builds are published: Windows x64/arm64 ZIPs, macOS x64/arm64 archives, and Linux x64/arm64 archives. Node 22 requires Windows 10/Server 2016+, macOS 11+, or glibc 2.28+ Linux. Alpine/musl and 32-bit systems are not supported. Git, Muse and Docker remain separate prerequisites for the workflows that use them; downloading Bypass itself requires neither GitHub access nor a system Node installation.

## Windows installation

The PowerShell installer defaults to `%LOCALAPPDATA%\Bypass` with `bin\bypass.cmd` on PATH. It updates both the current process PATH and user PATH, preserving machine PATH. No administrator rights, symlinks, profile edits, or persistent execution-policy changes are needed. The launcher uses a process-scoped execution-policy flag to run its local script, as the official Muse launcher does. Corporate policies may still restrict PowerShell execution.

Windows releases include `node.exe`; the native plugin manifest uses it directly. The CLI recognizes the official Muse `muse.cmd` / `.muse-launcher.ps1` installation and invokes its PowerShell script without interpolating repository paths into a command shell. Authentication remains Muse's own login.

Downloads must pass SHA-256 and a CLI startup check before the launcher configuration changes. The configuration is replaced atomically; old version directories are retained. Repeating installation reuses the release and does not duplicate PATH entries. Corrupt downloads, overlapping installs, unrelated files, and ZIP path traversal are rejected. `BYPASS_INSTALL_DIR`, `BYPASS_BIN_DIR`, `BYPASS_RELEASE`, and `BYPASS_NO_MODIFY_PATH=1` can be set as PowerShell environment variables before running the installer. Directories containing semicolons cannot be used as executable directories because Windows PATH uses semicolons as separators.

CI runs the downloaded x64 package on Windows Server 2022 in both Windows PowerShell 5.1 and PowerShell 7. It checks current/persistent PATH, a fresh terminal, repeat installation, CLI initialization and feature context, raw MCP startup, the Muse launcher adapter with a fixture, corrupt-download recovery, and preservation of unrelated directories. Native Windows arm64 execution and live Muse account/Docker security reviews are not exercised by this gate. Windows Docker reviews require Docker Desktop using Linux containers.

## Muse integration

The recommended Muse entry point is the direct one-command installer above. Optionally, users already in Muse can ask “Read https://bypasslabs.ai/install/muse.md and install Bypass for Muse.” That skill runs the same complete installer. The `/install/muse` and `/install/muse.ps1` endpoints install the plugin; the original `/install` and `/install.ps1` remain CLI-only.

The plugin installer calls the shared `integrate muse` operation with user scope and replacement internally. It compares all package bytes with the installed cache, preserving approval for an identical package. Changed packages are validated before replacement; failed replacements attempt to restore the previous source. On a real terminal, `muse-setup.mjs` presents both permissions and waits for explicit `y`/`yes`. It approves only those stable capability IDs through `muse plugins approve`, rechecks readiness, and launches an interactive Muse session with an onboarding request. It never changes model, provider, billing, workspace trust or sandbox settings.

Decline, EOF, cancellation, CI or `BYPASS_NO_OPEN_MUSE=1` do not approve or launch anything. Existing disabled/rejected states and unknown runtime capabilities require manual review. The download lock is released before starting Muse, so a running session does not prevent a later update. The underlying `bypass integrate muse` and `integrate status` commands remain noninteractive and never approve runtime capabilities.

The source installer variants and installation skill are generated and uploaded with every release. Promotion requires their sizes and SHA-256 digests to match R2 metadata, alongside all six runtime archives. The public entry points always resolve the promoted release. No extra public repository or system npm is required.

The CLI-only path is `bypass onboard`. Existing app state stays in the app's `.bypass` folder.

## CI publishing

`.github/workflows/release.yml` runs on pushes to `main` and manual dispatches of `main`:

1. Run syntax checks and the full test suite, including real fixture HTTP requests and Docker agent tests. The piped installer must also pass interactive terminal input checks on Linux and macOS before promotion. CI does not call a paid model or test a production application.
2. Build six archives using the pinned runtime/checksums in `scripts/node-runtime.json`. Include Node's upstream license.
3. Upload archives, checksum list, installer and release manifest to private R2 bucket `bypass-releases` through Worker `bypass-distribution`.
4. Install the candidate through its public versioned URLs on Linux and Windows runners. Exercise CLI version/help, repository initialization, feature-context retrieval, and platform-specific PATH checks. Windows must pass in PowerShell 5.1 and 7 before promotion.
5. Validate the complete manifest and every asset, then atomically promote `channels/main.json`. An older CI run cannot replace a newer promoted run.
6. Test the public `https://bypasslabs.ai/install` entry point and check that `https://bypasslabs.ai/install.ps1` serves the exact PowerShell script tested on Windows.

Every release has an immutable ID `main-<commit SHA>-<GitHub run ID>-<attempt>`. A retry has its own version prefix. Previous releases remain available. There is no automatic retention/deletion policy yet, either in R2 or in the local install directory; old plugin installations may still reference them. A partial upload never becomes the `main` download. A failure before promotion leaves the prior main release active. The final post-promotion smoke check reports a failure for investigation; it does not silently roll back.

Re-running a failed test/promotion job can reuse an upload from an earlier attempt of the same GitHub run and commit. Signed publishing identity cannot promote another run's artifacts. Re-running the build produces a new attempt prefix.

Pull requests run tests through `check.yml` with no publishing permission.

## Identity and scope

CI uses GitHub OIDC tokens with audience `https://bypasslabs.ai/downloads/bypass`. There are no stored Cloudflare account keys, R2 S3 keys or publishing passwords in GitHub. The Worker verifies the token's signature using GitHub's signing keys and checks issuer, audience, expiry, repository and owner IDs, main branch, exact release-workflow path, event, commit and run identity. Uploads are restricted to that run's release prefix, fixed filenames, bounded sizes and supplied checksums. R2 verifies the uploaded bytes. Promotion checks all required objects before updating the channel with a conditional write.

The Worker exposes only the installer, the main manifest and allowlisted immutable release files. Anonymous upload/promotion requests are rejected. The R2 bucket itself is private. The packaged runtime code is publicly downloadable by design; the private GitHub repository and non-package files are not exposed.

Worker routes are limited to `bypasslabs.ai/install*` and `bypasslabs.ai/downloads/bypass/*`. The existing marketing Worker and its source are managed separately.

CI writes use the dedicated `bypass-distribution.maksim-b26.workers.dev` hostname, with the same GitHub authentication policy and audience. This separates machine publishing from the marketing domain's browser/firewall rules. Customer downloads and all installer checks use `bypasslabs.ai`; no website firewall exceptions are required.

The trust policy uses this repository's immutable GitHub subject: `repo:Bypass-Labs@348399906/bypass-for-muse@1434899468:ref:refs/heads/main`. GitHub's repository OIDC settings can be inspected with `gh api repos/Bypass-Labs/bypass-for-muse/actions/oidc/customization/sub`.

Official references: [GitHub OIDC claims](https://docs.github.com/en/actions/reference/security/oidc), [Cloudflare R2 checksums and conditional writes](https://developers.cloudflare.com/r2/api/workers/workers-api-reference/), [Worker route precedence](https://developers.cloudflare.com/workers/configuration/routing/routes/).

## Operations

Infrastructure is deployed separately using the authorized local Cloudflare login:

```bash
npx --yes wrangler@4.153.0 deploy --config infra/releases/wrangler.jsonc
```

Normal application changes need only a push to main. Worker-code changes require the explicit infrastructure deploy as well. Keep the numeric repository and owner IDs aligned if the repository is transferred or recreated; renaming the release workflow requires updating the Worker trust policy.

Manual rebuild/release: run the GitHub **Test and publish main downloads** workflow on `main`. Download metadata is visible at `https://bypasslabs.ai/downloads/bypass/channels/main.json`.

To install a specific retained release, set `BYPASS_RELEASE` on the **bash process**, not only on curl:

```bash
curl -fsSL https://bypasslabs.ai/install | BYPASS_RELEASE=main-COMMIT-RUN-ATTEMPT bash
```

Replace the placeholder with an actual release ID. To change local directories, likewise set `BYPASS_INSTALL_DIR` and `BYPASS_BIN_DIR` on bash. Existing unrelated files are never overwritten. Installer updates are serialized with a directory lock; a hard-killed installation may leave a lock that the error message tells you how to remove. Removing local installs or old release directories is an explicit operator action; do not remove a version still referenced by the Muse plugin.

A public-channel rollback is an explicit administrative operation: validate a retained release's artifacts, then replace `channels/main.json` using authenticated Cloudflare/R2 tooling. Do not alter immutable release objects. Future CI promotions remain subject to the monotonic workflow-run check. This POC does not yet have a dedicated rollback CLI or signed-release transparency log; HTTPS plus recorded SHA-256 checks protect the current distribution flow.
