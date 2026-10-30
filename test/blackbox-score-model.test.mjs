import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import {temp} from './helpers.mjs';
import {execFile} from '../src/util.mjs';
import {scoreBlackbox} from '../scripts/blackbox-score.mjs';

test('the randomized scorer runs its model row through the Muse CLI transport', async t => {
  if (process.platform === 'win32') {t.skip('the Muse process fixture uses an executable POSIX script'); return;}
  const root = temp();
  t.after(() => fs.rmSync(root, {recursive: true, force: true}));
  const bin = path.join(root, 'bin');
  fs.mkdirSync(bin);
  const muse = path.join(bin, 'muse');
  const stub = [
    '#!' + process.execPath,
    "const fs=require('node:fs');",
    'const args=process.argv.slice(2);',
    "const value=flag=>args[args.indexOf(flag)+1];",
    "if(args[0]!=='exec'||!args.includes('--disable-shell')||!args.includes('--output-schema')||value('--provider')!=='meta')process.exit(2);",
    "const schema=JSON.parse(fs.readFileSync(value('--output-schema'),'utf8'));",
    'function blank(node){',
    "const type=Array.isArray(node.type)?node.type.find(item=>item!=='null'):node.type;",
    "if(node.enum)return node.enum[0];",
    "if(type==='object')return Object.fromEntries((node.required||[]).map(key=>[key,blank(node.properties[key])]));",
    "if(type==='array')return [];",
    "if(type==='integer'||type==='number')return node.minimum||0;",
    "if(type==='boolean')return false;",
    "if(type==='string')return '';",
    "if(node.anyOf)return blank(node.anyOf[0]);",
    'return null;',
    '}',
    "const answer=blank(schema);",
    "const ids=schema.properties?.files?.items?.properties?.id?.enum;",
    "if(ids)answer.files=ids.map(id=>({...blank(schema.properties.files.items),id,role:'unknown'}));",
    "console.log(JSON.stringify({payload:{kind:'run_terminal',terminal:'completed',text:JSON.stringify(answer)}}));",
  ].join('\n') + '\n';
  fs.writeFileSync(muse, stub, {mode: 0o700});
  const before = process.env.PATH;
  process.env.PATH = `${bin}${path.delimiter}${before}`;
  t.after(() => {process.env.PATH = before;});
  const output = path.join(root, 'score');
  const score = await scoreBlackbox({trials: 2, seed: 20261028, out: output, model: true});
  const [code, modeled] = score.rows;
  assert.equal(code.missed, 0);
  assert.equal(modeled.missed, 0);
  assert.equal(modeled.falsePositives, 0);
  assert.ok(modeled.modelCalls > 0);
  assert.equal(modeled.valid, true,
    JSON.stringify(score.results.map(item => item.runs.find(run => run.mode === 'model')?.modelState)));
  assert.equal(modeled.modelReadyRuns, modeled.modelRuns,
    JSON.stringify(score.results.map(item => item.runs.find(run => run.mode === 'model')?.modelState)));
  assert.equal(modeled.modelRuns, 3, 'vulnerable, fixed and clean model audits all ran');
  assert.equal(modeled.modelAdds, 0, 'empty fixture responses do not claim model-only discoveries');
  assert.ok(score.results[0].runs.find(run => run.mode === 'model').found.length >= 16);
});

test('the scorer rejects a model row when Muse calls fail despite code findings', async t => {
  if (process.platform === 'win32') {t.skip('the Muse process fixture uses an executable POSIX script'); return;}
  const root = temp();
  t.after(() => fs.rmSync(root, {recursive: true, force: true}));
  const bin = path.join(root, 'bin');
  fs.mkdirSync(bin);
  fs.writeFileSync(path.join(bin, 'muse'), `#!${process.execPath}\nprocess.exit(9);\n`, {mode: 0o700});
  const output = path.join(root, 'score');
  const run = await execFile(process.execPath,
    ['scripts/blackbox-score.mjs', '--trials', '2', '--seed', '20261028',
      '--model', '--json', '--out', output],
    {cwd: path.resolve(import.meta.dirname, '..'),
      env: {PATH: `${bin}${path.delimiter}${process.env.PATH}`}, timeout: 90000});
  assert.equal(run.code, 1, run.stderr || run.stdout);
  const score = JSON.parse(run.stdout);
  const [code, modeled] = score.rows;
  assert.equal(code.valid, true);
  assert.equal(code.missed, 0);
  assert.equal(modeled.missed, 0, 'baseline probes still find every planted bug');
  assert.equal(modeled.valid, false);
  assert.equal(modeled.modelReadyRuns, 0);
  assert.equal(modeled.modelRuns, 3);
  assert.equal(modeled.modelAdds, null);
  assert.equal(modeled.precision, null);
  assert.equal(modeled.recall, null);
  assert.ok(score.results.flatMap(item => [...item.runs, ...item.fixedControls])
    .filter(item => item.mode === 'model').every(item => item.modelState.error));
});
