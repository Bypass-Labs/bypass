# 0.7.6 verification — October 28, 2026

The recent scope-editing and update fixes passed verification against the **published, installed 0.7.6 package**. No additional runtime changes were needed. Complete production UAT, first-time-user validation, and protection against resetting a project while Muse is active remain open in [TODO](../TODO.md).

The tested release is `main-b8955a89c91ddfd14f412b8540121f2156a01a17-40639306192-1`. Native Muse inspection confirmed both previously approved runtime capabilities were enabled. The installed CLI also reported 0.7.6.

| Reported issue | Verification | Result |
| --- | --- | --- |
| Runtime rejects everything except GET/HEAD | The installed runtime sent GET, HEAD, POST, PUT, PATCH, DELETE, OPTIONS and PROPFIND to an isolated HTTP fixture. Each explicit request was dispatched once. | Passed |
| Scope cannot be changed through Muse chat | The public plugin opened the real host picker without a follow-up request. Selecting Custom methods saved all seven standard methods plus PROPFIND; independent state readback matched. | Passed; zero tool errors |
| Muse serializes method arrays as strings | In the actual interactive session, Muse sent a JSON-encoded string. The installed plugin accepted it on the first attempt. Malformed lists were also rejected without changing the saved grant in regression tests. | Passed |
| Approved scope file is rejected or changes silently | Installed-package tests saved and read back all seven methods, `/`, 2 requests/second and production acknowledgment. Opening the picker alone did not expand scope. | Passed |
| POST permission does not lead to a usable test | Packaged MCP created a local fixture resource with POST, used its returned ID for access proof, saved a failing regression, and passed replay after the fixture fix. Replay did not repeat resource creation. | Passed on the controlled local fixture |
| Scope edits invalidate existing account setup | Registration tests changed scope after account creation and reused the recorded attempts with zero duplicate signup requests. | Passed |
| Source, installed plugin and active session disagree | A fresh native Muse conversation reported loaded, installed and published versions as 0.7.6, with `restartRequired: false`. Update/restart/offline recovery cases also passed. | Passed |

## Checks run

- Full local suite: **170 passed, 0 failed, 2 Docker-only tests skipped**. Syntax checks and parity passed for 91 CLI commands, every command option, and 85 typed MCP tools.
- Installed-package suite: **32 passed, 0 failed, 0 skipped**, covering scope, onboarding, update handling and reliability. This included optional accounts, DNS setup responses, quoted-source memory, a second review, interrupted-fixture recovery and saved regression replay.
- The successful [release workflow](https://github.com/Bypass-Labs/bypass-for-muse/actions/runs/40639306192) ran **172 tests with no failures or skips**, including Docker. macOS terminal, Linux installer/PATH, Windows PowerShell 5.1 and PowerShell 7 checks passed.
- Native validation of the installed public plugin: valid, no diagnostics.
- Fresh Muse readback of the existing job-finder setup: **38 seconds**, no tool errors; production scope retained GET, HEAD, POST, PUT, PATCH, DELETE, OPTIONS on `/`, at 2 requests/second.
- Interactive public-plugin picker: **1m51s including waiting for keyboard input**, no tool errors. Session: `01a182f4-dcc3-7782-b262-57bdda9f8a74`.

The installed-package checks used a temporary copy of the existing tests with unchanged assertions. Runtime imports pointed to the downloaded package; packaged MCP launches used its actual manifest command and bundled Node from the test application's working directory. Installed runtime files were not patched.

## Limits

All mutating requests in this verification went to isolated localhost fixtures. The existing job-finder production setup was read only; no new application requests were sent to job-radar.app. A passing local proof/regression loop does not establish a complete production review, arbitrary write-operation regression support, or consistent host-model latency.

Structured results: [verification evidence](evidence/verification-076-2026-10-28.json).
