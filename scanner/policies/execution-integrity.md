# Build and extension execution integrity

Invariant: code, dependencies, updates, plugins, and automation executed in a
trusted build or runtime context must originate from an authorized, integrity-
checked source with least-privilege credentials. Trace repository events,
dependency resolution, downloads, generators, plugin loading, update channels,
and CI inputs into execution.

Inspect mutable references, unverified downloads, install hooks, lockfile use,
artifact signatures or digests, pull-request and fork event boundaries, checkout
selection, cache restoration, script interpolation, plugin path discovery, and
credential permissions. A trusted registry name alone does not pin content.
Immutable digests, verified signatures, protected release workflows, and
non-privileged execution are relevant counterevidence.

Candidates must identify who can influence the executed material, the privileged
execution context, the integrity control, and resulting capability. Distinguish
maintainer authority from lower-trust contribution paths and record hosting
assumptions. Do not fetch dependencies, run build steps, or inspect credentials.
