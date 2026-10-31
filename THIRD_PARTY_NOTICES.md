# Third-party notices

The Apache-2.0 license in this repository covers Bypass-authored code and documentation. It does not relicense third-party dependencies, external tools, models, or services. Existing notices must be retained when redistributing them.

## Included in the plugin and release archives

- **OpenAI JavaScript SDK** (`openai`, version pinned in `package-lock.json`): Apache-2.0. The plugin includes the SDK bundle, its license at `plugin/runtime/vendor/OPENAI_SDK_LICENSE`, and upstream vendored notices in `plugin/runtime/vendor/openai-licenses/`. In a plugin-only installation these paths start at `runtime/`. [Upstream license](https://github.com/openai/openai-node/blob/master/LICENSE).
- **Node.js** (version and hashes pinned in `scripts/node-runtime.json`): MIT license plus licenses of bundled components. Platform release archives include the complete upstream notice file at `plugin/runtime/NODE_LICENSE`. A development plugin built with a system Node does not bundle Node. [Upstream notices](https://github.com/nodejs/node/blob/main/LICENSE).

The release root and plugin runtime include Bypass's `LICENSE`, `NOTICE`, and this notice file. Build dependencies such as esbuild are not distributed as executable dependencies of the release.

## Downloaded or supplied separately

- **GitHub CodeQL**: SAST and Both modes download the CodeQL bundle when preparing the local Docker image. The CLI is governed by the [GitHub CodeQL Terms and Conditions](https://github.com/github/codeql-cli-binaries/blob/main/LICENSE.md), which limit permitted uses. Do not assume Bypass's Apache-2.0 license grants CodeQL rights for private or commercial code; obtain the applicable GitHub entitlement. Policy-only discovery does not download or use CodeQL. CodeQL binaries are not included in Bypass's R2/GitHub platform archives.
- **Docker images and toolchains**: base images, Python, Git, language runtimes, compilers, and their dependencies retain upstream licenses. The repository ships Docker recipes; the images are built locally and are not published as Bypass platform archives.
- **Muse Code and model services**: installed or configured separately, under their respective provider terms. Bypass's license grants no rights to Meta products, model weights, API access, or other providers' software.

Bypass is an independent Bypass Labs project. Product names identify integrations and dependencies; this project does not claim endorsement by Meta, GitHub, or other providers.
