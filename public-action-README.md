# Bypass GitHub Action

This repository distributes the Bypass GitHub Action used by workflows generated with `bypass ci init --agent`. The Action downloads an immutable Bypass release from `bypasslabs.ai`, verifies its SHA-256 checksum against that release's manifest, and runs the packaged security agent. It does not contain the private Bypass source repository.

Use the full commit SHA of this Action and a full Bypass release ID. Bypass generates those values in the workflow; do not use a moving branch or tag. PR source review requires a `MODEL_API_KEY` secret in the application repository. Saved-check replay after deployment uses no model calls.

Run `bypass ci init --agent` in the application repository to generate the policy and workflows.
