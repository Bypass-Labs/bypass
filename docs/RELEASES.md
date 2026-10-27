# R2 releases and one-line installation

```bash
curl -fsSL https://bypasslabs.ai/install | bash
```

`-f` makes an HTTP error stop the download. The installer downloads the latest tested main build, verifies SHA-256, and atomically updates the local `current` link. It installs under `~/.local/share/bypass` with a launcher at `~/.local/bin/bypass`. It uses no sudo and does not modify customer repositories.

The installer detects the configured shell from `SHELL` and adds one managed PATH block to its startup files. For Bash, it updates `.bashrc` plus the first existing login profile in Bash's order: `.bash_profile`, `.bash_login`, `.profile`; when none exists, it creates `.bash_profile`. It never creates a higher-priority file that would hide an existing login profile. For Zsh, it updates `.zshrc` and `.zprofile`, respecting an exported `ZDOTDIR`. Existing content, profile symlinks and permissions are preserved. Repeated installs keep one managed block and one PATH entry. Unsupported shells and unwritable profiles receive an actionable message without undoing the installation.

Open a new terminal, or run the printed `export PATH=…` command to activate Bypass in the existing terminal. A piped child process cannot change its parent shell's environment. The installer prints full-path commands that work immediately too. Set `BYPASS_NO_MODIFY_PATH=1` on the bash process to opt out (for example, `curl -fsSL https://bypasslabs.ai/install | BYPASS_NO_MODIFY_PATH=1 bash`). CI uses this opt-out for its temporary install paths; automated tests independently exercise Bash and Zsh startup files. Pinned releases before 0.3.2 retain their manual PATH setup.

Startup-file references: [Bash](https://www.gnu.org/software/bash/manual/html_node/Bash-Startup-Files), [Zsh](https://zsh.sourceforge.io/Doc/Release/Files.html).

Artifacts contain the CLI, native Muse plugin, and an official checksum-pinned Node.js runtime. Four builds are published: macOS x64/arm64 and Linux x64/arm64. Node 22 requires macOS 11+ or glibc 2.28+ Linux. Alpine/musl and Windows are not supported by this installer. Git, Muse and Docker remain separate prerequisites for the workflows that use them; downloading Bypass itself requires neither GitHub access nor a system Node installation.

## Muse integration

```bash
bypass integrate muse --scope user --replace
muse plugins inspect bypass
muse plugins approve bypass
```

`--replace` validates the bundled package before replacing a prior plugin, including one sourced from a Git checkout. It attempts to restore the old source if the new install fails. Muse's native runtime approval remains a separate explicit step. The distribution plugin contains its own Node binary, so its MCP server and session hook do not depend on system Node. The plugin is version-pinned until reinstalled with the command above; rerun it after updating the CLI and restart Muse.

The CLI-only path is `bypass onboard`. Existing app state stays in the app's `.bypass` folder.

## CI publishing

`.github/workflows/release.yml` runs on pushes to `main` and manual dispatches of `main`:

1. Run syntax checks and the full test suite, including real fixture HTTP requests and Docker agent tests. CI does not call a paid model or test a production application.
2. Build four archives using the pinned runtime/checksums in `scripts/node-runtime.json`. Include Node's upstream license.
3. Upload archives, checksum list, installer and release manifest to private R2 bucket `bypass-releases` through Worker `bypass-distribution`.
4. Install the candidate through its public versioned URL on the GitHub Linux runner. Exercise CLI version/help, repository initialization and feature-context retrieval.
5. Validate the complete manifest and every asset, then atomically promote `channels/main.json`. An older CI run cannot replace a newer promoted run.
6. Test the public `https://bypasslabs.ai/install` entry point.

Every release has an immutable ID `main-<commit SHA>-<GitHub run ID>-<attempt>`. A retry has its own version prefix. Previous releases remain available. There is no automatic retention/deletion policy yet, either in R2 or in the local install directory; old plugin installations may still reference them. A partial upload never becomes the `main` download. A failure before promotion leaves the prior main release active. The final post-promotion smoke check reports a failure for investigation; it does not silently roll back.

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
