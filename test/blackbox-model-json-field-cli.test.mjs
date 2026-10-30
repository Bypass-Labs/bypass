import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import {spawn} from 'node:child_process';
import {fileURLToPath} from 'node:url';
import {CLI} from '../src/demo.mjs';
import {execFile} from '../src/util.mjs';

const fixture = fileURLToPath(new URL('./fixtures/blackbox-json-field-blind.mjs', import.meta.url));

test('Muse selected private JSON field replays and client-supplied material stays inconclusive', async t => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'bypass-json-field-'));
  t.after(() => fs.rmSync(root, {recursive: true, force: true}));
  const fixtureRoot = path.join(root, 'fixture');
  const child = spawn(process.execPath, [fixture, fixtureRoot],
    {stdio: ['ignore', 'pipe', 'pipe']});
  t.after(() => child.kill('SIGTERM'));
  const manifest = await new Promise((resolve, reject) => {
    let output = '';
    child.once('error', reject);
    child.stdout.on('data', chunk => {
      output += chunk;
      if (output.includes('\n')) {
        try {resolve(JSON.parse(output.split('\n')[0]));} catch (error) {reject(error);}
      }
    });
    child.once('exit', code => reject(Error(`fixture exited ${code}`)));
  });
  const scopePath = path.join(root, 'blackbox.scope.json');
  fs.writeFileSync(scopePath, JSON.stringify({schemaVersion: 1,
    target: {origin: manifest.origin}, include: ['/'],
    identities: {identityPath: manifest.protectedPath},
    limits: {rps: 30, maxUrls: 60, minutes: 2, modelCalls: 30, tasks: 40}}));
  const bin = path.join(root, 'bin');
  fs.mkdirSync(bin);
  fs.writeFileSync(path.join(bin, 'muse'), [
    '#!' + process.execPath,
    "const fs=require('node:fs');",
    'const args=process.argv.slice(2);',
    'const value=flag=>args[args.indexOf(flag)+1];',
    "if(args.includes('--version')){console.log('muse fixture');process.exit(0);}",
    "if(args[0]!=='exec'||!args.includes('--output-schema'))process.exit(2);",
    "const messages=JSON.parse(fs.readFileSync(value('--prompt-file'),'utf8'));",
    'const system=messages[0].content;',
    'const context=JSON.parse(messages[1].content);',
    'let answer;',
    "if(system.startsWith('You are planning bounded, authorized HTTP research.')){",
    ' const read=context.protectedReadRoutes?.find(item=>item===process.env.BX_PROTECTED);',
    ' const route=context.routes?.find(item=>item.path===process.env.BX_FILTER);',
    ' const source=process.env.BX_ECHO===\'1\'?context.observedReadRoutes?.find(item=>item.path===process.env.BX_SOURCE):null;',
    " answer={flows:read&&route&&(!process.env.BX_ECHO||source)?[{family:'private-field-disclosure',why:'The public filter may expose a field from an owner-only JSON record',priority:9,as:'anonymous',oracle:'protected-json-field',protectedPath:read,prelude:source?[{method:'GET',path:source.path,headers:[]}]:[],subject:{method:'GET',path:route.path,placement:'query',key:'term',fixedFields:[],bodyTemplate:'',headers:[]},observe:[],...(source?{binding:{from:0,pointer:'/nonce',to:'subject',index:0,key:'copy'}}:{}),controlValue:'recent',firstValue:'all',secondValue:'archive',marker:context.marker,secondMarker:context.secondMarker,assertion:{step:'subject',index:0,location:'body',name:''}}]:[]};",
    '}',
    "else if(system.startsWith('Revise at most one bounded, authorized HTTP experiment'))answer={flows:[]};",
    'else {',
    " const schema=JSON.parse(fs.readFileSync(value('--output-schema'),'utf8'));",
    " const blank=s=>s?.type==='object'?Object.fromEntries((s.required??[]).map(key=>[key,blank(s.properties?.[key])])):s?.type==='array'?[]:s?.type==='integer'||s?.type==='number'?0:s?.type==='boolean'?false:s?.enum?.[0]??'';",
    ' answer=blank(schema);',
    '}',
    "console.log(JSON.stringify({payload:{kind:'run_terminal',terminal:'completed',text:JSON.stringify(answer)}}));",
  ].join('\n') + '\n', {mode: 0o700});
  const env = {PATH: `${bin}${path.delimiter}${process.env.PATH}`,
    OWNER_TOKEN: manifest.ownerToken, BX_PROTECTED: manifest.protectedPath,
    BX_FILTER: manifest.filterPath};
  const cli = async (...args) => {
    const completed = await execFile(process.execPath,
      [CLI, 'blackbox', ...args, '--project', root, '--json', '--non-interactive'],
      {cwd: root, env, timeout: 90000});
    return {code: completed.code, data: JSON.parse(completed.stdout)};
  };
  const audit = await cli(manifest.origin, '--scope', scopePath, '--offline');
  const finding = audit.data.findings.find(item =>
    item.kind === 'model-access-boundary' && item.pattern === manifest.filterPath);
  assert.ok(finding?.proof, JSON.stringify(audit.data.findings));
  assert.equal(finding.webProof.comparison, 'json-field');
  assert.equal((await cli('verify', audit.data.run)).code, 1);
  const exported = await cli('export', audit.data.run, '--out', path.join(root, 'regression'));
  assert.equal(exported.code, 0);
  const regression = async () => execFile(process.execPath,
    ['--test', ...exported.data.files],
    {env: {...env, NODE_TEST_CONTEXT: undefined}, timeout: 20000});
  const red = await regression();
  assert.equal(red.code, 1, `${red.stdout}\n${red.stderr}`);
  fs.writeFileSync(manifest.modeFile, 'fixed');
  assert.equal((await cli('verify', audit.data.run)).code, 0);
  assert.equal((await regression()).code, 0);
  const saved = fs.readFileSync(path.join(audit.data.runDir, 'web-probes.json'), 'utf8');
  const secret = (await (await fetch(`${manifest.origin}${manifest.protectedPath}`,
    {headers: {authorization: `Bearer ${manifest.ownerToken}`}})).json()).secret;
  assert.ok(!saved.includes(manifest.ownerToken));
  assert.ok(!saved.includes(secret));

  // A public source value copied into the subject request cannot prove an
  // owner-only disclosure, even when the response repeats that value.
  const echoRoot = path.join(root, 'echo');
  const echoFixture = path.join(echoRoot, 'fixture');
  const echoChild = spawn(process.execPath, [fixture, echoFixture, 'echo'],
    {stdio: ['ignore', 'pipe', 'pipe']});
  t.after(() => echoChild.kill('SIGTERM'));
  const echoManifest = await new Promise((resolve, reject) => {
    let output = '';
    echoChild.once('error', reject);
    echoChild.stdout.on('data', chunk => {
      output += chunk;
      if (output.includes('\n')) {
        try {resolve(JSON.parse(output.split('\n')[0]));} catch (error) {reject(error);}
      }
    });
    echoChild.once('exit', code => reject(Error(`echo fixture exited ${code}`)));
  });
  const echoScope = path.join(echoRoot, 'blackbox.scope.json');
  fs.writeFileSync(echoScope, JSON.stringify({schemaVersion: 1,
    target: {origin: echoManifest.origin}, include: ['/'],
    identities: {identityPath: echoManifest.protectedPath},
    limits: {rps: 60, maxUrls: 400, minutes: 2, modelCalls: 30, tasks: 40}}));
  const echoEnv = {...env, OWNER_TOKEN: echoManifest.ownerToken,
    BX_PROTECTED: echoManifest.protectedPath, BX_FILTER: echoManifest.filterPath,
    BX_SOURCE: echoManifest.sourcePath, BX_ECHO: '1'};
  const echoRun = await execFile(process.execPath,
    [CLI, 'blackbox', echoManifest.origin, '--scope', echoScope, '--offline',
      '--project', echoRoot, '--json', '--non-interactive'],
    {cwd: echoRoot, env: echoEnv, timeout: 90000});
  const echoAudit = JSON.parse(echoRun.stdout);
  assert.ok(!echoAudit.findings.some(item =>
    item.kind === 'model-access-boundary' && item.pattern === echoManifest.filterPath));
  const ledger = fs.readFileSync(path.join(echoAudit.runDir, 'evidence.jsonl'), 'utf8');
  assert.match(ledger, /private JSON material was supplied by the client request/,
    ledger.split('\n').filter(line => /model-http-sequence|model-protected-body/.test(line))
      .slice(-12).join('\n').slice(0, 4000));
  const echoSecret = (await (await fetch(`${echoManifest.origin}${echoManifest.sourcePath}`)).json()).nonce;
  const leakedFiles = fs.readdirSync(echoAudit.runDir, {recursive: true})
    .filter(file => fs.statSync(path.join(echoAudit.runDir, file)).isFile())
    .filter(file => fs.readFileSync(path.join(echoAudit.runDir, file), 'utf8')
      .includes(echoSecret));
  const leakedEvidence = ledger.split('\n').filter(line => line.includes(echoSecret))
    .map(line => {const item = JSON.parse(line); return {step: item.step,
      kind: item.kind, path: item.request?.url?.split('?')[0],
      hasExcerpt: typeof item.excerpt === 'string'};});
  assert.deepEqual(leakedFiles, [], `saved run artifacts exposed the bound private value: ${JSON.stringify(leakedEvidence)}`);
});
