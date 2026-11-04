# Hackathon build record

**Bypass for Muse Code** was built by a three-person Bypass Labs team for the 2026 Meta Global AI Developer Hackathon. The [source repository](https://github.com/Bypass-Labs/bypass) begins with commit `5654c39`, dated October 26, 2026. Bypass Labs and the team's security engineering experience predate the event; the team reports that it built this plugin, CLI, scanner integration, and testing workflow during the hackathon, with coding-agent assistance. The human team directed and reviewed the work.

## What we built

| Part | Current implementation |
| --- | --- |
| Muse Code plugin with onboarding, commands, typed MCP tools, and a session hook | [`plugin/`](plugin/), [`src/mcp.mjs`](src/mcp.mjs) |
| Standalone macOS, Linux, and Windows CLI and installers | [`bin/bypass.mjs`](bin/bypass.mjs), [installation guide](README.md#choose-your-experience) |
| CodeQL SAST and model-guided policy discovery | [`scanner/`](scanner/), [`src/scanner/`](src/scanner/), [source review guide](README.md#white-box-source-review) |
| Scoped HTTP and isolated browser checks, negative controls, coverage, and proof replay | [`src/blackbox/`](src/blackbox/), [running-app audit](docs/BLACKBOX_AUDIT.md) |
| Combined source-to-live handoff, saved checks, and context for later feature work | [`src/host-review.mjs`](src/host-review.mjs), [`src/portable-check.mjs`](src/portable-check.mjs), [security context](docs/SECURITY_MEMORY.md) |
| GitHub PR source review and replay of approved checks after deployment or on a schedule | [`src/github-agent.mjs`](src/github-agent.mjs), [GitHub guide](docs/GITHUB_AGENT.md) |

The plugin can start a code-only, running-app-only, or combined audit from `/bypass:start`. In a combined audit, cited source leads flow into one full running-app audit, which also covers other observed routes. The CLI exposes these through `bypass scan --mode code`, `--mode live`, and `--mode combined`. A five-minute plugin quick test is available and reports unfinished work as untested. Source hypotheses and model suggestions are kept separate from confirmed HTTP findings. Supported proofs can become Node regression tests that replay without model calls. [Execution and evidence diagram](docs/assets/muse-security-loop.svg) ([PNG](docs/assets/muse-security-loop.png)) · [First-audit walkthrough](docs/WALKTHROUGH.md).

## How Meta models are used

The native plugin uses the developer's active Muse Code model, such as Muse Spark or Muse Wonder, to inspect bounded source and observations, choose follow-up work, and explain results through Bypass's typed tools. It does not need a separate Bypass API key. Bypass enforces the approved target and test limits, executes requests, and records evidence independently of the model's conclusion.

The standalone CLI can use Meta Model API with a selected Muse model or an explicitly configured compatible local server for Muse Spark Open or Muse Glimmer. Its Meta API default is `muse-spark-1.3`; the onboarding picker can recommend Muse Wonder when available. The GitHub PR agent uses Meta Model API for an immutable PR source revision, defaults to `muse-spark-1.3`, and can be configured for Muse Wonder. It cites file and line concerns and does not execute PR code. Approved saved live checks replay separately after a verified deployment or on a schedule. [Model modes](docs/AI_MODES.md) · [GitHub behavior and limits](docs/GITHUB_AGENT.md).

## External tools and dependencies

Muse Code, Muse models, and Meta Model API provide the coding-agent host and model access. Docker and base images provide scanner isolation; GitHub CodeQL supplies SAST rules under its own license. Node.js, Python, Chrome/Chromium, GitHub Actions, and the `openai`, `esbuild`, and `setuptools` packages are external dependencies. The Bypass integration, audit controls, reports, regressions, plugin, CLI, and GitHub runner are implemented in this repository. [Third-party notices](THIRD_PARTY_NOTICES.md).

## Inspect and validate

- [README](README.md): install, onboarding, audit modes, and commands.
- [Audit evaluation contract](docs/AUDIT_EVALUATION.md): how a combined run links source, live evidence, scope, findings, and proof IDs.
- [Running-app coverage](docs/BLACKBOX_AUDIT.md): supported checks, evidence, and explicit limits.
- [Security context](docs/SECURITY_MEMORY.md): provenance and freshness of local memory.
- [Architecture slide](docs/assets/muse-continuous-testing-slide.svg) ([PNG](docs/assets/muse-continuous-testing-slide.png)): build, test, verify, retest, and replay loop.

From a source checkout, `npm run check` validates source and generated command documentation, `npm run plugin:validate` checks the native plugin package, and `npm run test:audit` exercises the audit evaluation and reconciliation paths. The complete test suite is `npm test`. The demo command `/bypass:demo` uses an isolated fixture; it does not assess a customer's app. [Test and release commands](README.md#contributing).
