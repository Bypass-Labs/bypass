# Pull request checks

PR validation keeps the full test inventory for code and scanner changes while separating early feedback from expensive integration checks.

1. **Fast checks** builds the plugin, checks source syntax/version/tool parity, and tests the CI planner/gate. Scanner changes and mixed code changes also run Python scanner tests.
2. **Four regression shards** run on separate Ubuntu runners. Files are assigned using longest-estimated-duration-first balancing. Each runner keeps Node's `--test-concurrency=1` and `BYPASS_DOCKER_TESTS=1`, preserving serial browser/Docker execution within the runner. A failed shard does not cancel the others.
3. **Policy and CodeQL** keep the existing real integration fixtures. CodeQL runs for scanner, shared service/provider/store, workflow, and unknown changes. An isolated black-box source/test change still runs all regression shards and policy, but skips CodeQL. CodeQL's source-derived image tag is prepared with Docker Buildx and GitHub Actions layer caching, then loaded into the local Docker daemon. No registry image is published. Cache misses rebuild the image; scan-time isolation and checksum-pinned CodeQL downloads remain unchanged. CodeQL extractors still run one at a time.
4. The existing **`check`** status is a final gate. It requires fast checks plus every job selected by the change classifier to succeed. A missing, skipped, failed, or cancelled required job cannot pass.

All `test/*.test.mjs` files are discovered from the checkout. `scripts/ci-test-timings.json` controls scheduling only, never inclusion. New files without a timing estimate receive 15 seconds for balancing and still run. The recorded estimates come from [this completed CI run](https://github.com/Bypass-Labs/bypass/actions/runs/41227344018); they are not a promised runtime. Each shard prints its file list and estimate, retains its TAP log as a seven-day workflow artifact, and reports actual elapsed time.

## Documentation-only changes

Only the root `README.md` and ordinary Markdown under `docs/` can skip the three integration job groups. Fast checks still run, and the final `check` explicitly verifies those skips. The runtime research catalog `docs/muse_spark_bug_bounty_tier_1_tier_2.md` is excluded from this shortcut.

## Muse plugin guidance and context only

A PR limited to Muse plugin skills/commands, the session context hook, `src/plugin-context.mjs`, its compaction test, and ordinary documentation runs focused plugin, review, MCP, and onboarding tests in the fast job. The full regression shards, policy Docker job, and CodeQL image job are skipped because those files do not change the scanner or HTTP runner. This cuts the roughly four 10–12 minute regression jobs plus the roughly 13-minute CodeQL job seen on the recent PR run. Any other code, test, workflow, scanner, or mixed change runs the full suite. The final `check` verifies the expected skips; unknown or missing Git comparison data fails closed to full validation.

Classification uses the complete Git diff between the event's exact base/head commits, with both sides of renames preserved. Missing commit metadata, failed comparison, or an empty diff defaults to full validation including CodeQL. CodeQL is skipped only when every changed file is ordinary documentation, a plugin-only file, an isolated `src/blackbox/*.mjs` module, or a `test/blackbox-*.test.mjs` test. Shared service/provider/store code remains CodeQL-sensitive because the scanner imports it or its fixtures exercise it. No GitHub path filter can leave the required `check` permanently pending.

## Local reproduction

```bash
npm ci --ignore-scripts
npm run plugin:build
node scripts/ci-tests.mjs plan
BYPASS_DOCKER_TESTS=1 node scripts/ci-tests.mjs run 1
```

Use shard numbers 1 through 4. Without PR commit metadata, `plan` defaults to the full suite. `npm test` still runs the complete suite serially, and the main release workflow remains unchanged.

## Limits and rollout

- Four runners reduce elapsed regression time, but do not reduce total test work. Runner quotas can introduce queuing, and setup is repeated per shard.
- Full validation including CodeQL still runs for this PR because it changes shared dispatch and this workflow. Recent full jobs took roughly 10–12 minutes per shard and 13 minutes for CodeQL. The narrow shortcuts apply to future eligible changes.
- npm caching stores downloaded dependencies, not `node_modules`; installation still checks the lockfile. Docker caching stores build layers, never application evidence or credentials. GitHub branch/PR cache isolation applies. PR-created caches do not overwrite the default branch cache. Caches can be evicted; successful builds do not depend on saving a cache.
- Existing main-release tests and publication gates are unchanged. This change does not deploy, merge, publish images, or alter branch protection. Repositories that separately require `policy`/`codeql` must allow those skipped jobs for documentation-only and plugin-only PRs.

References: [Node test isolation and concurrency](https://nodejs.org/api/test.html), [Docker build caching in GitHub Actions](https://docs.docker.com/build/ci/github-actions/cache/), [GitHub cache access restrictions](https://docs.github.com/en/actions/reference/workflows-and-actions/dependency-caching).
