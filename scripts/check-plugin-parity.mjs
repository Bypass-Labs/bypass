import fs from 'node:fs';
import assert from 'node:assert/strict';
import { toolDefinitions } from '../src/mcp.mjs';
import { capabilityCatalog } from '../src/plugin-parity.mjs';
const catalog=capabilityCatalog(toolDefinitions),file=new URL('../docs/PLUGIN_COMMANDS.md',import.meta.url);
assert.deepEqual(catalog.filter(c=>!c.tool&&!c.hostOwned),[],'Every public CLI command needs a plugin equivalent.');
assert.deepEqual(catalog.flatMap(c=>c.options.filter(o=>!o.available).map(o=>`${c.command} --${o.flag}`)),[],'Every CLI option needs a plugin equivalent.');
const escape=value=>String(value).replaceAll('|','\\|');
const rows=catalog.map(c=>`| \`${escape(c.command)}\` | ${c.tool?'`'+c.tool+'`':'Muse starts the approved server'}${c.arguments?' · '+escape(JSON.stringify(c.arguments)):''} | ${escape(c.note||c.description)} |`);
const document=`# Muse plugin capability reference

The Muse plugin is the primary experience. Use ordinary requests or its slash commands; Muse calls these tools for you. You do not need to learn MCP syntax or leave Muse for project operations.

Standalone model setup has a deliberate mode boundary: plugin model tools explain host ownership and cannot configure or invoke API inference. This reference is generated from the CLI catalog and plugin definitions. CI checks all ${catalog.length} public CLI commands and their options; there are ${toolDefinitions.length} typed tools. Regenerate with \`node scripts/check-plugin-parity.mjs --write\` after intentionally changing the catalog.

## Start inside Muse

Use /bypass:blackbox to audit an authorized running app through the active Muse session, then replay proofs and export regressions. A bare command asks in chat for the exact target URL, allowed paths, request rate, Muse-call cap and time limit; the user can type custom numbers or choose 120 Muse calls and 30 minutes as separate defaults. It does not start an audit of an app selected in an earlier session.

- \`/bypass:start\`: reuse your repository and active Muse reasoning, and finish missing app/DNS/scope setup; accounts are optional.
- \`/bypass:demo\`: a real local Muse-directed demonstration, through proof, fixture fix, saved test, deliberate regression, one monitor tick and security context. Ask for an offline preview explicitly to use seeded discovery.
- \`/bypass:status\`: Done / Now / Next, progress, evidence and actual worker health.
- \`/bypass:review\`, \`/bypass:tests\`, \`/bypass:monitor\`, \`/bypass:build\`, \`/bypass:context\`, \`/bypass:help\`: the remaining workflows.

## Shared behavior and deliberate UI differences

The plugin calls the same application services and reads/writes the same project state as the CLI. An initialized application workspace is reused; other repository selection is explicit. Host reviews use durable read/source/probe/finish steps directed by Muse. Short deterministic replays return completed controls directly; pending runs use bounded progress calls. Monitor workers run detached, or for one tick. Demo creation selects a separate fixture, and stopping it restores the prior application selection while retaining evidence.

An observed vulnerability or failed regression retains CLI exit code 1 but is a successful MCP operation with a security result. Execution errors, blocked requests and incomplete reviews stay explicit. A configured model, accepted job or saved monitor schedule is never shown as a successful review or running monitor.

Muse owns interactive sign-in, plugin capability approval and session restart. Bypass provides an explicit handoff for official login instead of collecting credentials or claiming sign-in succeeded. The already-approved MCP server is started by Muse, so \`mcp serve\` is transport lifecycle. For optional test accounts, Muse can perform authorized bounded JSON/Firebase registration or import an existing private account file through \`bypass_import_identity\`; Firebase tokens refresh automatically without environment exports or session restarts. DNS publication and initial app sign-in may need user access; reuse authorized host integrations where available. Installation/update/removal tools require an explicit user request and do not approve themselves.

CLI global \`--project\` maps to the selected repository; \`--json\` maps to structured tool results; \`--help\`/\`--version\` map to the guide and runtime identity. Terminal rendering/keyboard flags are represented by the conversational UI. Output paths stay in the selected repository and may not traverse symlinks.

## Complete operation mapping

| CLI command | Muse tool | Behavior |
| --- | --- | --- |
${rows.join('\n')}

Use \`bypass_help\` with a query for live option discovery. Tool schemas include the corresponding CLI options; presentation aliases above explain intentional differences. Source hypotheses, fixture proof, real HTTP evidence and historical results keep their original labels in both interfaces.
`;
if(process.argv.includes('--write'))fs.writeFileSync(file,document);
else assert.equal(fs.readFileSync(file,'utf8'),document,'Plugin capability documentation is stale; run the generator.');
console.log(`Plugin parity: ${catalog.length} public commands and every command option mapped; ${toolDefinitions.length} typed tools.`);
