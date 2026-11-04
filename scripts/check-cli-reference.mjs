import fs from 'node:fs';
import assert from 'node:assert/strict';
import {commands, booleanFlags, globalFlags} from '../src/catalog.mjs';

const file=new URL('../docs/CLI_REFERENCE.md',import.meta.url);
const visible=Object.values(commands).filter(command=>!command.hidden);
const options=command=>command.flags.length?
  command.flags.map(flag=>`\`--${flag}${booleanFlags.has(flag)?'':' <value>'}\``).join(', '):
  'None.';
const sections=visible.map(command=>`## \`bypass ${command.usage}\`

${command.description}

Options: ${options(command)}
`).join('\n');
const globals=[...new Set(globalFlags)].map(flag=>
  `\`--${flag}${booleanFlags.has(flag)?'':' <value>'}\``).join(', ');
const document=`# Exact CLI command reference

This file is generated from the parser catalog, so every public command and accepted option is listed exactly as the installed CLI parses it. Use [COMMANDS.md](COMMANDS.md) for workflow explanations and \`bypass <command> --help\` for terminal help. Regenerate intentionally with \`node scripts/check-cli-reference.mjs --write\`.

Global options: ${globals}.

${sections}## Exit codes

- \`0\`: operation succeeded.
- \`1\`: a confirmed finding or failed regression was produced.
- \`2\`: command usage or configuration is invalid.
- \`3\`: the operation is incomplete, blocked, or has no conclusive result.
- \`130\`: cancelled.
`;

if(process.argv.includes('--write'))fs.writeFileSync(file,document);
else assert.equal(fs.readFileSync(file,'utf8'),document,
  'CLI reference is stale; run node scripts/check-cli-reference.mjs --write.');
console.log(`CLI reference: ${visible.length} public commands and all accepted options documented.`);
