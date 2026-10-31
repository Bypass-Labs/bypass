# GitHub Releases, R2, and one-line installation

For the **Muse Code plugin**, run:

```bash
curl -fsSL https://bypasslabs.ai/install/muse | bash
```

Windows: `irm https://bypasslabs.ai/install/muse.ps1 | iex`.

Run it from your app folder. After explaining the two permissions, the installer asks once to approve them and open Muse Code. Answer `y` to begin onboarding in a new Muse Code session automatically. Noninteractive installation leaves permission review and session startup to the user. [Quick start](../README.md#start-in-muse-code).

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

Artifacts contain the CLI, native Muse Code plugin, and an official checksum-pinned Node.js runtime. Six builds are published: Windows x64/arm64 ZIPs, macOS x64/arm64 archives, and Linux x64/arm64 archives. Node 22 requires Windows 10/Server 2016+, macOS 11+, or glibc 2.28+ Linux. Alpine/musl and 32-bit systems are not supported. Git, Muse Code and Docker remain separate prerequisites for the workflows that use them; downloading Bypass itself requires neither GitHub access nor a system Node installation.

## Windows installation

The PowerShell installer defaults to `%LOCALAPPDATA%\Bypass` with `bin\bypass.cmd` on PATH. It updates both the current process PATH and user PATH, preserving machine PATH. No administrator rights, symlinks, profile edits, or persistent execution-policy changes are needed. The launcher uses a process-scoped execution-policy flag to run its local script, as the official Muse Code launcher does. Corporate policies may still restrict PowerShell execution.

Windows releases include `node.exe`; the native plugin manifest uses it directly. The CLI recognizes the official Muse Code `muse.cmd` / `.muse-launcher.ps1` installation and invokes its PowerShell script without interpolating repository paths into a command shell. Authentication remains Muse Code's own login.

Downloads must pass SHA-256 and a CLI startup check before the launcher configuration changes. The configuration is replaced atomically; old version directories are retained. Repeating installation reuses the release and does not duplicate PATH entries. Corrupt downloads, overlapping installs, unrelated files, and ZIP path traversal are rejected. `BYPASS_INSTALL_DIR`, `BYPASS_BIN_DIR`, `BYPASS_RELEASE`, and `BYPASS_NO_MODIFY_PATH=1` can be set as PowerShell environment variables before running the installer. Directories containing semicolons cannot be used as executable directories because Windows PATH uses semicolons as separators.

CI runs the downloaded x64 package on Windows Server 2022 in both Windows PowerShell 5.1 and PowerShell 7. It checks current/persistent PATH, a fresh terminal, repeat installation, CLI initialization and feature context, raw MCP startup, the Muse Code launcher adapter with a fixture, corrupt-download recovery, and preservation of unrelated directories. Native Windows arm64 execution and live Muse Code account/Docker security reviews are not exercised by this gate. Windows Docker reviews require Docker Desktop using Linux containers.

## Muse Code integration

The recommended Muse Code entry point is the direct one-command installer above. Optionally, users already in Muse Code can ask “Read https://bypasslabs.ai/install/muse.md and install Bypass for Muse Code.” That skill runs the same complete installer. The `/install/muse` and `/install/muse.ps1` endpoints install the plugin; the original `/install` and `/install.ps1` remain CLI-only.

The plugin installer calls the shared `integrate muse` operation with user scope and replacement internally. It compares all package bytes with the installed cache, preserving approval for an identical package. Changed packages are validated before replacement; failed replacements attempt to restore the previous source. On a real terminal, `muse-setup.mjs` presents both permissions and waits for explicit `y`/`yes`. It approves only those stable capability IDs through `muse plugins approve`, rechecks readiness, and launches an interactive Muse Code session with an onboarding request. It never changes model, provider, billing, workspace trust or sandbox settings.

Decline, EOF, cancellation, CI or `BYPASS_NO_OPEN_MUSE=1` do not approve or launch anything. Existing disabled/rejected states and unknown runtime capabilities require manual review. The download lock is released before starting Muse Code, so a running session does not prevent a later update. The underlying `bypass integrate muse` and `integrate status` commands remain noninteractive and never approve runtime capabilities.

The source installer variants and installation skill are generated and uploaded with every release. Promotion requires their sizes and SHA-256 digests to match R2 metadata, alongside all six runtime archives. The public entry points always resolve the promoted release. No extra public repository or system npm is required.

The CLI-only path is `bypass onboard`. Existing app state stays in the app's `.bypass` folder.

## CI publishing

`.github/workflows/release.yml` runs Windows account/MCP and macOS terminal smoke
checks on pull requests. Each job installs dependencies and explicitly builds
the generated plugin runtime before invoking Node or Python tests directly.
Superseded PR checks are cancelled; main publishing runs remain serialized.
`npm run check` also verifies that every esbuild platform binary has its pinned
version and integrity hash recorded in the lockfile.

Pushes to `main` and manual dispatches of `main` run the publishing pipeline:

1. Run syntax checks and the full test suite, including real fixture HTTP requests and Docker agent tests. The piped installer must also pass interactive terminal input checks on Linux and macOS before promotion. CI does not call a paid model or test a production application.
2. Build six archives once using the pinned runtime/checksums in `scripts/node-runtime.json`. Include Bypass's Apache-2.0 license and notices, the SDK's upstream notices, and Node's complete upstream license file.
3. Create a **draft GitHub Release** at the exact source commit. Upload the six archives, five installer/skill files, `SHASUMS256.txt`, and `release.json` from the build directory. Verify GitHub's SHA-256 digest and size for all 13 assets. A failure stops the R2 upload.
4. Upload those same files to private R2 bucket `bypass-releases` through Worker `bypass-distribution`. Both publishers use the inventory in `scripts/release-files.mjs`; neither rebuilds files or uploads unlisted build-directory contents.
5. Install the R2 candidate on Linux and Windows. Exercise CLI version/help, repository initialization, feature-context retrieval, and PATH checks. Windows must pass in PowerShell 5.1 and 7 before promotion.
6. Verify the GitHub archive against the exact R2 manifest, then atomically promote `channels/main.json`. An older CI run cannot replace a newer promoted run.
7. Test the public installer entry points. Publish the GitHub Release only after these checks succeed and the promoted R2 release ID matches. If publication fails, the verified assets remain in the draft; rerun the promotion job to finish.

Every release has an immutable ID `main-<commit SHA>-<GitHub run ID>-<attempt>`. A retry has its own version prefix. Previous releases remain available. There is no automatic retention/deletion policy yet, either in R2 or in the local install directory; old plugin installations may still reference them. A partial upload never becomes the `main` download. Its GitHub Release remains a draft. A failure before promotion leaves the prior main release active. The final post-promotion smoke check reports a failure for investigation; it does not silently roll back.

Re-running a failed test/promotion job can reuse an upload from an earlier attempt of the same GitHub run and commit. Signed publishing identity cannot promote another run's artifacts. Re-running the build produces a new attempt prefix.

Pull requests also run the general and CodeQL suites through `check.yml`.
The platform smoke jobs have only read access; publishing jobs require `main`
and are skipped for pull requests. Only the release and promotion jobs receive
`contents: write`. Their GitHub steps use the automatic `github.token` as
`GH_TOKEN`; no personal token or new repository secret is needed. R2 continues
to use GitHub OIDC with no stored Cloudflare credential.

## GitHub release archive

[GitHub Releases](https://github.com/Bypass-Labs/bypass-for-muse/releases) is the archive for downloadable plugin/CLI bundles. GitHub Packages is intended for package registries such as npm and container images; this pipeline does not publish a second npm package or a Docker image.

- The tag is the complete R2 release ID, `main-<commit>-<run>-<attempt>`. Package versions can repeat; the tag cannot. Main builds are labeled **prerelease** rather than claiming a separately versioned stable release.
- Each release preserves all 13 files, including the original `release.json` bytes. Platform archives, installer scripts, and metadata match R2 by SHA-256 and byte size. Source archives generated by GitHub are separate from these platform bundles.
- Retries reuse a matching draft and skip verified uploads. A failed empty upload placeholder may be retried; a conflicting nonempty asset, tag, manifest, or unexpected file stops the operation. Published assets are not overwritten.
- GitHub releases inherit repository access. While the repository is private, its releases require repository access; R2 remains the public installer/download route. Adding a license or a release does not change repository visibility.
- R2 promotion and GitHub publication are separate operations. If the post-promotion check or GitHub publication fails, R2 can already serve the candidate while GitHub retains its draft. CI reports the failure; rerunning the job completes publication. It does not silently roll back either service.

To archive an already promoted R2 release without rebuilding it, load a GitHub token with repository `contents: write` privately as `GH_TOKEN`, then run:

```bash
node scripts/github-release.mjs --from-r2 main-COMMIT-RUN-ATTEMPT
node scripts/github-release.mjs --from-r2 main-COMMIT-RUN-ATTEMPT --verify
node scripts/github-release.mjs --from-r2 main-COMMIT-RUN-ATTEMPT --publish
```

Replace the placeholder with the full retained release ID. `--publish` requires that exact release to be the current promoted R2 build. Historical noncurrent builds can be archived as drafts. Do not put the token in command arguments. Archived historical files retain their original contents and notices; new licensing changes do not rewrite old packages.

References: [GitHub Releases](https://docs.github.com/en/repositories/releasing-projects-on-github/about-releases), [release-asset checksums](https://docs.github.com/en/rest/releases/assets), [GitHub token permissions](https://docs.github.com/en/actions/security-for-github-actions/security-guides/automatic-token-authentication).

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

Replace the placeholder with an actual release ID. To change local directories, likewise set `BYPASS_INSTALL_DIR` and `BYPASS_BIN_DIR` on bash. Existing unrelated files are never overwritten. Installer updates are serialized with a directory lock; a hard-killed installation may leave a lock that the error message tells you how to remove. Removing local installs or old release directories is an explicit operator action; do not remove a version still referenced by the Muse Code plugin.

A public-channel rollback is an explicit administrative operation: validate a retained release's artifacts, then replace `channels/main.json` using authenticated Cloudflare/R2 tooling. Do not alter immutable release objects. Future CI promotions remain subject to the monotonic workflow-run check. This POC does not yet have a dedicated rollback CLI or signed-release transparency log; HTTPS plus recorded SHA-256 checks protect the current distribution flow.
