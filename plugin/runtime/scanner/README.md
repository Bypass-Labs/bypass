# Whitebox scanner scaffold

The scanner is a Python package in the Bypass repository. It owns the future
Signal Discovery → Evaluation → Reporting pipeline. The current implementation
provides contracts, MCP initialization/tool discovery, and capability inspection.
All analysis operations return `not_implemented`; no runs, findings, source reads,
model calls, or reports are created.

## Run the transport and tests

From the repository root (Python 3.11+; no Python runtime dependencies):

```sh
PYTHONPATH=scanner/src PYTHONDONTWRITEBYTECODE=1 python3 -m bypass_scanner
PYTHONPATH=scanner/src PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s scanner/tests
```

The first command reads newline-delimited MCP JSON-RPC from stdin. Initialize
with a protocol version listed in `protocol/v1.json`, send
`notifications/initialized`, then use `tools/list` or call `scanner_capabilities`.
All other declared tools validate their input and return an MCP tool error with
`code: not_implemented`. Invalid requests use JSON-RPC errors. Frames are capped
at 1 MiB. Stdout contains protocol messages only. A package installation also
provides the `bypass-scanner` entry point and installs the shared protocol data.

```sh
bypass discover --plan
bypass scanner doctor
bypass scanner prepare
```

Image preparation is explicit and may download the Python base image. The image
contains only this dependency-free scaffold, without CodeQL or model clients.
The runtime uses an immutable image ID, no network, no host mounts/credentials,
and a read-only filesystem. Diagnostics/image preparation require no model setup.
Image preparation is not evidence of a working scanner.

## Ownership

- `protocol/v1.json`: shared self-contained wire schemas, operation inputs, and
  protocol versions. Python and Node read the same file. Subset validation checks
  structure; future evaluation must also validate evidence and task semantics.
- `service.py`: application boundary independent of MCP and model providers.
- `workflow.py`: future scheduling, budgets, source identity, and durable state.
- `discovery/`: future CodeQL and independent AI policy signal producers.
- `evaluation/`: future deterministic checks, fast/deep instructions, and results.
- `repository/`: future scoped source reads, search, navigation, and citations.
- `reporting/`: future JSON/Markdown rendering from persisted evaluations.
- `transports/mcp.py`: bounded stdio MCP scaffold.
- `../src/scanner/`: Node container lifecycle/client, shared service routing, and
  future standalone API driver.

Muse performs reasoning in the active session using its settings. Neither the
plugin nor this image configures an external model or makes independent API
requests. MCP does not attest the host's billing mode. Direct Bypass CLI analysis
requires an explicit standalone API profile and credential environment variable;
its driver validates configuration then returns `not_implemented` without a
request. The scaffold never reads Muse login credentials or switches billing paths.

The intended future task loop is next task → evidence tools → typed submission.
Python owns security instructions and stage transitions; clients supply reasoning.
No task loop, detector execution, persistence, CodeQL packaging, legacy Scratch
run migration, runtime reproduction, patching, or self-improvement is implemented.
The external Scratch repository and existing Bypass assessment workflows are
unchanged. Future scanner state belongs under `.bypass/scanner/`.
