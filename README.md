# Bypass for Muse

Prove a security issue, verify the fix, and keep a regression test that runs without a model.

**Working prototype:** repository setup, model connection checks, DNS ownership, local HTTP proof, exported tests, and local scheduling work. Discovery and deployed-app investigation are mocked. A preview of your repository is not a security verdict.

## Start here: the complete walkthrough

Requires **Node 22+** and Git. No dependency installation, model login, DNS, or plugin is needed for this walkthrough.

```bash
git clone https://github.com/Bypass-Labs/bypass-for-muse.git
cd bypass-for-muse
./bypass demo
```

**Press Enter at each of six steps.** Bypass creates a separate local app, prints its browser URL, and guides you through:

1. **Review** — see a clearly labeled example access-control issue.
2. **Prove** — real HTTP requests show another account can read the owner's invoice.
3. **Fix and retest** — apply the fixture fix, verify access is denied, and save a regression test.
4. **Export** — execute the test with ordinary Node, without Bypass or a model.
5. **Catch a regression** — bring the bug back and watch both tests catch it.
6. **Remember** — execute one local scheduler tick and save the result for the next session.

It finishes with the fixture fixed, the test and evidence saved, and the demo server stopped. It does not change your connected app. Type `q` at a step to leave early.

## Connect your own project

From this Bypass checkout:

```bash
./bypass onboard
```

Choose **2 → Connect my repository**. The wizard takes you through the repository, model choice, optional app connection, and first review. You can also open an existing checkout directly:

```bash
./bypass onboard /path/to/your/app
```

- **Repository:** paste a Git URL or local folder. Press Enter for the suggested clone folder. Existing files are kept; a matching checkout can be reused.
- **Model:** choose your Muse Code subscription, a compatible local Muse/local model server, or your own self-hosted endpoint. The optional connection check shows progress; press Enter to skip it.
- **App:** enter a domain such as `job-radar.app` or a full URL. Bypass supplies HTTPS for deployed domains and prints the DNS TXT record. **Press Enter to continue while DNS is pending.** Live testing stays disabled until ownership and testing scope are authorized.
- **Plugin:** optional. An existing Muse installation is reused. Capability approval stays in Muse.

On the project home screen, **press Enter to run the first preview and open its result**. The preview inventories source locally and shows a simulated scenario. Its next step offers the complete local walkthrough because deployed-app investigation is not built yet.

```text
  1  Run my first review preview  ← Enter
  2  Walk through prove → fix → retest → regression
  3  Settings & optional connections
  0  Exit
```

Type `?` for commands, `app` to resume verification, `models` for connections, or `q` to exit. After a preview, action 1 becomes **Open review results**. Resume with `./bypass --project /path/to/your/app`.

## Model choice and privacy

| Choice | What you need | Where inference runs |
| --- | --- | --- |
| Muse Code subscription | Installed Muse CLI and your existing login | Your configured Muse provider |
| Local Muse / local model | A compatible running server and model ID | This machine; no cloud fallback |
| Self-hosted model | Your compatible HTTPS endpoint and optional credential reference | Your infrastructure |

No weights are bundled. Connection checks send only a synthetic prompt and may use your provider allowance. Mock analysis and saved-test replay make zero model calls. A local Bypass profile does not change a separate Muse session's provider. Evidence stays local; real credentials are referenced by environment-variable name.

For the plugin, review its capabilities in Muse, start a new Muse session in your connected repository, and run **`/bypass:review`**.

## More detail

- [Walkthrough and app connection](docs/WALKTHROUGH.md)
- [Interactive commands and full CLI reference](docs/COMMANDS.md)
- [Advanced presenter script](docs/ADVANCED_WALKTHROUGH.md)
- [Architecture and current boundaries](docs/ARCHITECTURE.md)
- [Verification record](docs/VALIDATION.md)

For development: `npm run check`, `npm test`, `npm run plugin:build`, and `npm run plugin:validate`.
