import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import {spawn} from 'node:child_process';
import {CLI} from '../src/demo.mjs';
import {execFile} from '../src/util.mjs';

test('blind CLI follows a model-selected login into a protected read-only SQL finding and replays the fix',
  {timeout: 180000}, async t => {
    const root = fs.mkdtempSync(path.join(os.tmpdir(), 'bypass-protected-sql-'));
    t.after(() => { if (!process.env.BX_KEEP_TEST_ROOT) fs.rmSync(root, {recursive: true, force: true}); });
    const fixture = path.join(import.meta.dirname, 'fixtures/blackbox-protected-sql-blind.mjs');
    const server = spawn(process.execPath, [fixture, root], {stdio: ['ignore', 'pipe', 'inherit']});
    t.after(() => server.kill());
    const origin = await new Promise((resolve, reject) => {
      server.stdout.once('data', chunk => resolve(String(chunk).trim()));
      server.once('error', reject);
      server.once('exit', code => reject(Error(`fixture exited ${code}`)));
    });
    const scopeFile = path.join(root, 'blackbox.scope.json');
    fs.writeFileSync(scopeFile, JSON.stringify({schemaVersion: 1, target: {origin}, include: ['/'],
      limits: {rps: 50, maxUrls: 70, minutes: 3, modelCalls: 40, tasks: 90}}));
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
      " answer={checks:post&&read?[{loginPath:post.path,userField:'username',passwordField:'password',proofMode:'protected-status',userPayloads:[\"admin' OR '1'='1\"],tokenPointer:'/authentication/token',privatePath:read.path,principalPointer:'',why:'Observed login and denied identity route support a synthetic invalid-password control'}]:[]};",
      '}',
      "else if(system.includes('Rank only the supplied observed read-only web-test candidates')){",
      " const candidate=context.candidates.find(item=>item.kind==='sql-boolean'&&item.parameter==='q'&&item.path.endsWith('/item'));",
      " const render=context.candidates.find(item=>item.kind==='ssti-arithmetic'&&item.parameter==='q'&&item.path.endsWith('/render'));",
      " answer={priorities:[...(candidate?[{kind:candidate.kind,path:candidate.path,parameter:'q',priority:10,why:'Protected JS documents a numeric item lookup'}]:[]),...(render?[{kind:render.kind,path:render.path,parameter:'q',priority:10,why:'Protected JS documents an HTML render input'}]:[])],strategies:candidate?[{family:'sql-boolean',path:candidate.path,parameter:'q',base:'1',style:'numeric',priority:10,why:'Read-only numeric lookup with an observed benign example'}]:[],experiments:[]};",
      '}',
      "else if(system.startsWith('Map this authorized authenticated web surface')){const route=context.contracts.find(item=>item.method==='GET'&&item.params.includes('q')&&item.path.endsWith('/item'));answer={paths:route?[route.path+'?q=1']:[]};}",
      "else if(system.includes('Interpret only the extracted'))answer={files:[]};",
      "else if(system.includes('Assess only these independently proved')){",
      " const proved=(context.chains||[]).filter(item=>item.proofExecuted&&item.steps.some(step=>step.use.includes('Fresh invalid-password login')&&step.evidence.length));",
      " answer={notes:[],chainNotes:proved.map(item=>({id:item.id,impact:'The replayed login bypass reached a protected record',preconditions:'Fresh invalid-password login',remediation:'Validate passwords and protect the record'}))};",
      '}',
      "else if(system.includes('Continue mapping this authorized primary application'))answer={paths:[]};",
      "else if(system.includes('mapping an authorized web API'))answer={paths:[],notes:[]};",
      "else if(system.includes('Propose bounded GET access-control'))answer={tasks:[]};",
      'else {',
      " const schema=JSON.parse(fs.readFileSync(value('--output-schema'),'utf8'));",
      " const blank=s=>s?.type==='object'?Object.fromEntries((s.required??[]).map(key=>[key,blank(s.properties?.[key])])):s?.type==='array'?[]:s?.type==='integer'||s?.type==='number'?0:s?.type==='boolean'?false:s?.enum?.[0]??'';",
      ' answer=blank(schema);',
      '}',
      "console.log(JSON.stringify({payload:{kind:'run_terminal',terminal:'completed',text:JSON.stringify(answer)}}));",
    ].join('\n') + '\n', {mode: 0o700});
    const env = {...process.env, PATH: `${bin}${path.delimiter}${process.env.PATH}`};
    const cli = async (...args) => {
      const done = await execFile(process.execPath,
        [CLI, 'blackbox', ...args, '--project', root, '--json', '--non-interactive'],
        {cwd: root, env, timeout: 120000});
      return {code: done.code, data: JSON.parse(done.stdout)};
    };
    const audit = await cli(origin, '--scope', scopeFile);
    assert.ok(audit.data.runDir, JSON.stringify(audit));
    const login = audit.data.findings.find(item => item.kind === 'model-auth-login');
    const sql = audit.data.findings.find(item => item.kind === 'sql-boolean' &&
      item.tags.includes('discovered-via-derived-session'));
    const ssti = audit.data.findings.find(item => item.kind === 'ssti-arithmetic' &&
      item.tags.includes('discovered-via-derived-session'));
    const web = JSON.parse(fs.readFileSync(path.join(audit.data.runDir, 'web-probes.json'), 'utf8'));
    assert.ok(login?.proof, JSON.stringify({findings: audit.data.findings, results: web.results}));
    assert.ok(sql?.proof, JSON.stringify({findings: audit.data.findings,
      derived: JSON.parse(fs.readFileSync(path.join(audit.data.runDir, 'derived-session-recon.json'))),
      results: web.results}));
    assert.ok(ssti?.proof, JSON.stringify({findings: audit.data.findings,
      results: web.results.filter(item => item.kind === 'ssti-arithmetic')}));
    const chains = JSON.parse(fs.readFileSync(path.join(audit.data.runDir, 'chains.json'), 'utf8'));
    const prerequisite = chains.find(item => item.status === 'confirmed' &&
      item.template === 'derived-login-to-protected-impact' &&
      item.findings.includes(login.id) && item.findings.includes(sql.id));
    assert.ok(prerequisite?.proof, JSON.stringify(chains));
    assert.equal(prerequisite.assessment?.impact,
      'The replayed login bypass reached a protected record');
    assert.equal(prerequisite.severity, 'high', 'the chain must not inflate severity');
    assert.ok(!audit.data.findings.some(item => item.id === prerequisite.id),
      'a chain must not duplicate a finding');
    const chainProof = JSON.parse((await execFile(process.execPath, [prerequisite.proof],
      {env, timeout: 20000})).stdout);
    assert.equal(chainProof.verdict, 'confirmed');
    assert.ok(chainProof.controls.some(item => item.label === 'fresh-login-boundary' &&
      item.verdict === 'confirmed'));
    assert.ok(chainProof.controls.some(item => item.label === 'protected-route-boundary' &&
      item.anonymousStatus === 401 && item.invalidBearerStatus === 401));
    assert.equal(sql.webProof.request.as, 'derived');
    assert.ok(sql.webProof.derivedLogin, 'the saved SQL proof must replay a fresh login');
    assert.equal(ssti.webProof.request.as, 'derived');
    assert.ok(ssti.webProof.derivedLogin, 'the protected HTML proof must replay a fresh login');
    const freshProof = JSON.parse((await execFile(process.execPath, [sql.proof],
      {env, timeout: 20000})).stdout);
    assert.equal(freshProof.verdict, 'confirmed');
    assert.ok(freshProof.controls.some(item => item.label === 'fresh-login-boundary' &&
      item.verdict === 'confirmed'));
    assert.ok(freshProof.controls.some(item => item.label === 'protected-route-boundary' &&
      item.anonymousStatus === 401 && item.invalidBearerStatus === 401));
    const sstiProof = JSON.parse((await execFile(process.execPath, [ssti.proof],
      {env, timeout: 20000})).stdout);
    assert.equal(sstiProof.verdict, 'confirmed');
    assert.ok(sstiProof.controls.some(item => item.label === 'fresh-login-boundary' &&
      item.verdict === 'confirmed'));
    assert.ok(!audit.data.findings.some(item => item.kind === 'sql-boolean' &&
      /safe-item|public-item/.test(item.pattern)));
    const artifacts = fs.readdirSync(audit.data.runDir, {recursive: true, withFileTypes: true})
      .filter(item => item.isFile()).map(item => fs.readFileSync(path.join(item.parentPath, item.name), 'utf8')).join('\n');
    assert.doesNotMatch(artifacts, /token-[0-9a-f]{48}/);
    const report = fs.readFileSync(path.join(audit.data.runDir, 'report.md'), 'utf8');
    assert.doesNotMatch(report, /\$undefined/);
    assert.match(report, /Muse chain assessment \(interpretation\): `The replayed login bypass reached a protected record`/);
    assert.ok(report.includes(`node '${sql.proof}'`),
      'the protected-session finding must point to its executable PoC');
    assert.equal((await cli('verify', audit.data.run)).code, 1);
    const exported = await cli('export', audit.data.run, '--out', path.join(root, 'regression'));
    assert.equal(exported.code, 0);
    const regression = async () => (await execFile(process.execPath,
      ['--test', ...exported.data.files], {env: {...env, NODE_TEST_CONTEXT: undefined},
        timeout: 30000})).code;
    assert.equal(await regression(), 1);
    fs.writeFileSync(path.join(root, 'mode'), 'fixed-sql');
    const sqlProof = await execFile(process.execPath, [sql.proof], {env, timeout: 20000});
    assert.equal(JSON.parse(sqlProof.stdout).verdict, 'not_reproduced');
    const fixedChainProof = await execFile(process.execPath, [prerequisite.proof],
      {env, timeout: 20000});
    assert.equal(JSON.parse(fixedChainProof.stdout).verdict, 'not_reproduced');
    const fixedSstiProof = await execFile(process.execPath, [ssti.proof], {env, timeout: 20000});
    assert.equal(JSON.parse(fixedSstiProof.stdout).verdict, 'not_reproduced');
    fs.writeFileSync(path.join(root, 'mode'), 'fixed');
    assert.equal((await cli('verify', audit.data.run)).code, 0);
    assert.equal(await regression(), 0);
  });
