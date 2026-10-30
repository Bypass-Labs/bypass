import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import {spawn} from 'node:child_process';
import {CLI} from '../src/demo.mjs';
import {execFile} from '../src/util.mjs';

const sleep = ms => new Promise(resolve => setTimeout(resolve, ms));

test('CLI resumes a derived Muse HTTP sequence from feedback without repeating its first payload',
  {timeout: 180000}, async t => {
    const root = fs.mkdtempSync(path.join(os.tmpdir(), 'bypass-flow-resume-'));
    t.after(() => {if (!process.env.BX_KEEP_TEST_ROOT)
      fs.rmSync(root, {recursive: true, force: true});});
    const fixture = path.join(import.meta.dirname, 'fixtures/blackbox-protected-sql-blind.mjs');
    const server = spawn(process.execPath, [fixture, root],
      {stdio: ['ignore', 'pipe', 'ignore'], env: {...process.env, BX_FIXTURE_HEX: '1'}});
    t.after(() => server.kill());
    const origin = await new Promise((resolve, reject) => {
      server.stdout.once('data', chunk => resolve(String(chunk).trim()));
      server.once('error', reject);
      server.once('exit', code => reject(Error(`fixture exited ${code}`)));
    });
    const suffix = fs.readFileSync(path.join(root, 'route-suffix'), 'utf8').trim();
    const renderPath = `/api/${suffix}/render`;
    const scopeFile = path.join(root, 'blackbox.scope.json');
    const scope = JSON.parse(fs.readFileSync(scopeFile, 'utf8'));
    scope.limits = {...scope.limits, rps: 50, maxUrls: 80, minutes: 3,
      modelCalls: 50, tasks: 100};
    fs.writeFileSync(scopeFile, JSON.stringify(scope));
    const bin = path.join(root, 'bin');
    fs.mkdirSync(bin);
    fs.writeFileSync(path.join(bin, 'muse'), [
      '#!' + process.execPath,
      "const fs=require('node:fs');",
      '(async()=>{',
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
      " answer={checks:post&&read?[{loginPath:post.path,userField:'username',passwordField:'password',proofMode:'protected-status',userPayloads:[\"admin' OR '1'='1\"],tokenPointer:'/authentication/token',privatePath:read.path,principalPointer:'',why:'Observed login and denied identity route'}]:[]};",
      '}',
      "else if(system.startsWith('Allocate the next black-box investigation effort'))answer={priorities:['sequence','web','access','json','stored','session'].map(name=>({name,weight:name==='sequence'?100:1,why:'Observed protected render input'}))};",
      "else if(system.startsWith('You are planning bounded, authorized HTTP research.')){",
      " const route=context.routes.find(item=>item.path===process.env.BX_RENDER&&item.kind==='read'&&item.fields.includes('q'));",
      " answer={flows:process.env.BX_RESUME==='1'||!route?[]:[{family:'server-rendered-expression',why:'Observed protected render query',priority:8,as:'derived',oracle:'observation',prelude:[],subject:{method:'GET',path:route.path,placement:'query',key:'q',fixedFields:[],bodyTemplate:'',headers:[]},observe:[],controlValue:'plain',firstValue:'resume-probe-alpha',secondValue:'resume-probe-beta',marker:'',secondMarker:'',assertion:{step:'subject',index:0,location:'body',name:''}}]};",
      '}',
      "else if(system.includes('Revise at most one bounded, authorized HTTP experiment')){",
      " if(process.env.BX_SLOW_REVISION==='1')await new Promise(resolve=>setTimeout(resolve,12000));",
      " const encoded=v=>'hex:'+Buffer.from(v).toString('hex');",
      " answer={flows:context.historySummary?.attempts>1?[]:[{family:'server-rendered-expression',why:'Refine after reflection-only result',priority:8,as:'derived',oracle:'marker',prelude:[],subject:{method:'GET',path:process.env.BX_RENDER,placement:'query',key:'q',fixedFields:[],bodyTemplate:'',headers:[]},observe:[],controlValue:'plain',firstValue:encoded(context.marker),secondValue:encoded(context.secondMarker),marker:context.marker,secondMarker:context.secondMarker,assertion:{step:'subject',index:0,location:'body',name:''}}]};",
      '}',
      "else if(system.startsWith('Map this authorized authenticated web surface'))answer={paths:[]};",
      "else if(system.includes('Interpret only the extracted'))answer={files:[]};",
      "else if(system.includes('Assess only these independently proved'))answer={notes:[]};",
      "else if(system.includes('Continue mapping this authorized primary application'))answer={paths:[]};",
      "else if(system.includes('mapping an authorized web API'))answer={paths:[],notes:[]};",
      "else if(system.includes('Propose bounded GET access-control'))answer={tasks:[]};",
      'else {',
      " const schema=JSON.parse(fs.readFileSync(value('--output-schema'),'utf8'));",
      " const blank=s=>s?.type==='object'?Object.fromEntries((s.required??[]).map(key=>[key,blank(s.properties?.[key])])):s?.type==='array'?[]:s?.type==='integer'||s?.type==='number'?0:s?.type==='boolean'?false:s?.enum?.[0]??'';",
      ' answer=blank(schema);',
      '}',
      "console.log(JSON.stringify({payload:{kind:'run_terminal',terminal:'completed',text:JSON.stringify(answer)}}));",
      '})().catch(error=>{console.error(error);process.exit(1)});',
    ].join('\n') + '\n', {mode: 0o700});
    const env = {...process.env, PATH: `${bin}${path.delimiter}${process.env.PATH}`,
      BX_RENDER: renderPath, BX_FIXTURE_HEX: '1'};
    const cli = async (args, extraEnv = {}) => execFile(process.execPath,
      [CLI, 'blackbox', ...args, '--project', root, '--json', '--non-interactive'],
      {cwd: root, env: {...env, ...extraEnv}, timeout: 120000});
    const child = spawn(process.execPath,
      [CLI, 'blackbox', origin, '--project', root, '--scope', scopeFile,
        '--json', '--non-interactive'],
      {cwd: root, env: {...env, BX_SLOW_REVISION: '1'}, stdio: 'ignore'});
    t.after(() => {if (child.exitCode == null) child.kill('SIGKILL');});
    const runsDir = path.join(root, '.bypass/runs');
    let firstRun, checkpoint;
    const deadline = Date.now() + 45000;
    while (Date.now() < deadline) {
      const folder = fs.existsSync(runsDir) ? fs.readdirSync(runsDir).find(name =>
        fs.readdirSync(path.join(runsDir, name)).some(file =>
          file.startsWith('http-sequence-') &&
          file !== 'http-sequence-page-checkpoint.json' &&
          file.endsWith('-checkpoint.json'))) : null;
      if (folder) {
        const candidates = fs.readdirSync(path.join(runsDir, folder))
          .filter(file => file.startsWith('http-sequence-') &&
            file !== 'http-sequence-page-checkpoint.json' &&
            file.endsWith('-checkpoint.json'))
          .map(file => JSON.parse(fs.readFileSync(path.join(runsDir, folder,
            file), 'utf8')));
        checkpoint = candidates.find(item => item.active?.phase === 'attempted' &&
          item.active.history.length === 1) ?? candidates.at(-1);
        if (checkpoint.active?.phase === 'attempted' &&
            checkpoint.active.history.length === 1) {
          firstRun = folder;
          break;
        }
      }
      if (child.exitCode != null) break;
      await sleep(50);
    }
    assert.equal(checkpoint?.active?.phase, 'attempted',
      JSON.stringify({firstRun, checkpoint}));
    assert.equal(checkpoint.kind, 'http-sequence');
    assert.equal(checkpoint.active.history[0].verdict, 'inconclusive');
    assert.equal(checkpoint.active.currentLead.as, 'derived');
    assert.ok(!JSON.stringify(checkpoint).match(/token-[0-9a-f]{48}/));
    child.kill('SIGKILL');
    await new Promise(resolve => child.once('exit', resolve));
    const resumed = await cli(['resume', firstRun], {BX_RESUME: '1', BX_SLOW_REVISION: '0'});
    const data = JSON.parse(resumed.stdout);
    assert.ok(data.runDir, resumed.stderr);
    const ledger = fs.readFileSync(path.join(data.runDir, 'evidence.jsonl'), 'utf8');
    const attempts = ledger.trim().split('\n').map(line => JSON.parse(line))
      .filter(item => item.kind === 'model-http-sequence-attempt' &&
        item.path === renderPath && item.as === 'derived');
    assert.equal(attempts.length, 1, JSON.stringify(attempts));
    assert.equal(attempts[0].attempt, 2);
    assert.ok(!ledger.includes('resume-probe-alpha'));
    assert.ok(!ledger.includes('resume-probe-beta'));
    assert.ok(!ledger.match(/token-[0-9a-f]{48}/));
    const web = JSON.parse(fs.readFileSync(path.join(data.runDir, 'web-probes.json'), 'utf8'));
    const investigation = web.investigations.find(item => item.initial.path === renderPath &&
      item.attempts.some(attempt => attempt.sourceRun === firstRun));
    assert.ok(investigation, JSON.stringify(web.investigations));
    assert.equal(investigation.final.verdict, 'observed');
    const observation = data.findings.find(item => item.kind === 'model-http-sequence' &&
      item.pattern === renderPath);
    assert.ok(observation?.proof, JSON.stringify({root, findings: data.findings
      .map(item => [item.kind, item.pattern]), investigations: web.investigations}));
    const replay = JSON.parse((await execFile(process.execPath, [observation.proof],
      {env, timeout: 20000})).stdout);
    assert.equal(replay.verdict, 'observed');
    assert.ok(replay.controls.some(item => item.label === 'fresh-login-boundary' &&
      item.verdict === 'confirmed'));
    const exported = await cli(['export', data.run, '--out', path.join(root, 'regression')],
      {BX_RESUME: '1'});
    assert.equal(exported.code, 0);
    const exportedData = JSON.parse(exported.stdout);
    const regression = () => execFile(process.execPath,
      ['--test', ...exportedData.files.filter(file => file.includes(observation.id))],
      {env: {...env, NODE_TEST_CONTEXT: undefined}, timeout: 30000});
    assert.equal((await regression()).code, 1);
    assert.equal((await execFile(process.execPath, [fixture, root, 'fixed'],
      {env, timeout: 5000})).code, 0);
    assert.equal((await regression()).code, 0);
  });
