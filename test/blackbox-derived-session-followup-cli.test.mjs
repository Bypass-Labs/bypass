import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import {spawn} from 'node:child_process';
import {CLI} from '../src/demo.mjs';
import {execFile} from '../src/util.mjs';

test('blind CLI proves login bypass and credential exposure without treating public private-marked JSON as a bug', async t => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'bypass-derived-followup-'));
  t.after(() => { if (!process.env.BX_KEEP_TEST_ROOT) fs.rmSync(root, {recursive: true, force: true}); });
  const fixture = path.join(import.meta.dirname, 'fixtures/blackbox-derived-blind.mjs');
  const server = spawn(process.execPath, [fixture, root], {stdio: ['ignore', 'pipe', 'inherit']});
  t.after(() => server.kill());
  const origin = await new Promise((resolve, reject) => {
    server.stdout.once('data', chunk => resolve(String(chunk).trim()));
    server.once('error', reject);
    server.once('exit', code => reject(Error(`fixture exited ${code}`)));
  });
  const scopeFile = path.join(root, 'blackbox.scope.json');
  fs.writeFileSync(scopeFile, JSON.stringify({schemaVersion: 1, target: {origin}, include: ['/'],
    limits: {rps: 50, maxUrls: 60, minutes: 3, modelCalls: 35, tasks: 64}}));
  const bin = path.join(root, 'bin');
  fs.mkdirSync(bin);
  fs.writeFileSync(path.join(bin, 'muse'), [
    '#!' + process.execPath,
    "const fs=require('node:fs');",
    'const args=process.argv.slice(2);',
    'const value=flag=>args[args.indexOf(flag)+1];',
    "if(args.includes('--version')){console.log('muse fixture');process.exit(0);}",
    "if(args[0]!=='exec'||!args.includes('--disable-shell')||!args.includes('--output-schema')||value('--provider')!=='meta')process.exit(2);",
    "const messages=JSON.parse(fs.readFileSync(value('--prompt-file'),'utf8'));",
    'const system=messages[0].content;',
    'const context=JSON.parse(messages[1].content);',
    'let answer;',
    "if(system.startsWith('From only the observed authorized JSON login operations')){",
    " const post=context.posts.find(item=>item.usernameField==='username'&&item.passwordField==='password');",
    " const read=context.reads.find(item=>item.path.includes('/api/me-'));",
    " const second=context.reads.find(item=>item.path.includes('/api/settings-'));",
    " const first=post&&read?{loginPath:post.path,userField:'username',passwordField:'password',proofMode:'protected-status',userPayloads:[\"admin' OR '1'='1\"],tokenPointer:'/authentication/token',privatePath:read.path,principalPointer:'',why:'Observed login may accept a synthetic tautology under an invalid password'}:null;",
    " answer={checks:first&&second?[first,{...first,privatePath:second.path,userPayloads:[\"root' OR '2'='2\"],why:'A second synthetic tautology tests the same login contract against another protected route'}]:[]};",
    '}',
    "else if(system.startsWith('Map this authorized authenticated web surface'))answer={paths:[]};",
    "else if(system.includes('Interpret only the extracted'))answer={files:[]};",
    "else if(system.includes('Assess only these independently proved'))answer={notes:[]};",
    "else if(system.includes('Continue mapping this authorized primary application'))answer={paths:[]};",
    "else if(system.includes('mapping an authorized web API'))answer={paths:[],notes:[]};",
    "else if(system.includes('Propose bounded GET access-control'))answer={tasks:[]};",
    "else if(system.includes('Rank only the supplied observed read-only web-test candidates'))answer={priorities:[],strategies:[],experiments:[]};",
    'else {',
    " const schema=JSON.parse(fs.readFileSync(value('--output-schema'),'utf8'));",
    " const blank=s=>s?.type==='object'?Object.fromEntries((s.required??[]).map(key=>[key,blank(s.properties?.[key])])):s?.type==='array'?[]:s?.type==='integer'||s?.type==='number'?0:s?.type==='boolean'?false:s?.enum?.[0]??'';",
    ' answer=blank(schema);',
    '}',
    "console.log(JSON.stringify({payload:{kind:'run_terminal',terminal:'completed',text:JSON.stringify(answer)}}));",
  ].join('\n') + '\n', {mode: 0o700});
  const env = {...process.env, PATH: `${bin}${path.delimiter}${process.env.PATH}`};
  const cli = async (...args) => {
    const completed = await execFile(process.execPath,
      [CLI, 'blackbox', ...args, '--project', root, '--json', '--non-interactive'],
      {cwd: root, env, timeout: 90000});
    return {code: completed.code, data: JSON.parse(completed.stdout)};
  };
  const audit = await cli(origin, '--scope', scopeFile);
  const findings = audit.data.findings;
  const login = findings.find(item => item.kind === 'model-auth-login');
  const exposure = findings.find(item => item.kind === 'anonymous-credential-data');
  const privateRead = findings.find(item => item.kind === 'derived-private-read');
  assert.ok(login?.proof, JSON.stringify({findings, run: audit.data.runDir, root}));
  assert.ok(exposure?.proof, JSON.stringify({findings, run: audit.data.runDir}));
  assert.equal(privateRead, undefined,
    'a public JSON field named private is not independent evidence of unauthorized access');
  assert.ok(exposure.tags.includes('discovered-via-derived-session'));
  const web = JSON.parse(fs.readFileSync(path.join(audit.data.runDir, 'web-probes.json'), 'utf8'));
  assert.ok(web.modelCoverage.some(item => item.discoveredVia === 'derived-session' &&
    ((item.httpSequenceSent ?? 0) > 0 || (item.pagesSent ?? 0) > 0)),
  'the first confirmed session must reach a Muse protected-route planning page');
  assert.ok(web.results.some(item => item.kind === 'anonymous-credential-data' &&
    item.verdict === 'confirmed' && item.discoveredVia === 'derived-session'));
  const coverage = JSON.parse(fs.readFileSync(path.join(audit.data.runDir, 'coverage.json'), 'utf8'));
  assert.equal(coverage.derivedSessionRecon.sessions, 2,
    'distinct login recipes without a proved principal identity keep separate inventories');
  assert.equal(coverage.derivedSessionRecon.reused, 0,
    'a second private route must not inherit an unproved session identity');
  assert.ok(coverage.derivedSessionRecon.anonymousChecks > 0);
  assert.ok(web.results.some(item => item.kind === 'derived-private-read' &&
    item.verdict === 'inconclusive' && item.discoveredVia === 'derived-session'));
  const ledger = fs.readFileSync(path.join(audit.data.runDir, 'evidence.jsonl'), 'utf8')
    .trim().split('\n').map(line => JSON.parse(line));
  assert.ok(ledger.some(item => item.agent === 'derived-session-authenticated' &&
    item.step === 'control'), 'the authenticated recheck must have control provenance');
  const report = JSON.parse(fs.readFileSync(path.join(audit.data.runDir, 'report.json'), 'utf8'));
  const recon = JSON.parse(fs.readFileSync(path.join(audit.data.runDir,
    'derived-session-recon.json'), 'utf8'));
  assert.equal(recon.sessions.filter(session => !session.coverage?.anonymousChecks).length, 1,
    'one distinct login recipe was mapped but its duplicate route inventory was not retested');
  assert.ok(report.limitations.some(line => line.includes('no anonymous follow-up checks ran')),
    'the unmapped session must remain visible as an incomplete pass');
  assert.equal((await cli('verify', audit.data.run)).code, 1);
  const artifacts = fs.readdirSync(audit.data.runDir, {recursive: true, withFileTypes: true})
    .filter(item => item.isFile()).map(item => fs.readFileSync(path.join(item.parentPath, item.name), 'utf8')).join('\n');
  assert.doesNotMatch(artifacts, /token-[0-9a-f]{48}/);
  assert.doesNotMatch(artifacts, /ak_[0-9a-f]{48}/);
  assert.doesNotMatch(artifacts, /public workspace note for/);
  const exported = await cli('export', audit.data.run, '--out', path.join(root, 'regression'));
  assert.equal(exported.code, 0);
  const relevant = new Set([login.id, exposure.id]);
  const relevantTests = exported.data.files.filter(file =>
    [...relevant].some(id => path.basename(file).includes(id)));
  assert.equal(relevantTests.length, 2);
  const regression = async () => (await execFile(process.execPath,
    ['--test', ...relevantTests], {env: {...env, NODE_TEST_CONTEXT: undefined},
      timeout: 30000})).code;
  assert.equal(await regression(), 1);
  fs.writeFileSync(path.join(root, 'mode'), 'fix-exposure');
  const exposureProof = await execFile(process.execPath, [exposure.proof], {env, timeout: 20000});
  assert.equal(JSON.parse(exposureProof.stdout).verdict, 'not_reproduced');
  fs.writeFileSync(path.join(root, 'mode'), 'fixed');
  const fixed = await cli('verify', audit.data.run);
  for (const id of relevant)
    assert.equal(fixed.data.proofs.find(item => item.id === id)?.verdict,
      'not_reproduced', JSON.stringify(fixed.data));
  assert.equal(await regression(), 0);
});
