import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import http from 'node:http';
import os from 'node:os';
import path from 'node:path';
import {spawn} from 'node:child_process';
import {execFile} from '../src/util.mjs';
import {CLI} from '../src/demo.mjs';

const sleep = ms => new Promise(resolve => setTimeout(resolve, ms));

test('CLI resumes an interrupted Muse GET investigation with fresh evidence and the original scope', async t => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'bypass-resume-'));
  t.after(() => fs.rmSync(root, {recursive: true, force: true}));
  const expressions = [];
  const server = http.createServer((request, response) => {
    const url = new URL(request.url, 'http://fixture');
    if (url.pathname === '/') {
      response.writeHead(200, {'content-type': 'text/html'});
      response.end('<html><body>Expression service</body></html>');
      return;
    }
    if (url.pathname === '/openapi.json') {
      response.writeHead(200, {'content-type': 'application/json'});
      response.end(JSON.stringify({openapi: '3.0.0', paths: {'/api/render': {get: {
        summary: 'Render an expression', parameters: [{name: 'expr', in: 'query'}]}}}}));
      return;
    }
    if (url.pathname === '/api/render') {
      const expr = url.searchParams.get('expr') ?? '';
      expressions.push(expr);
      const codes = /^\{\{String\.fromCharCode\(([\d,]+)\)\}\}$/.exec(expr)?.[1];
      const result = codes ? String.fromCharCode(...codes.split(',').map(Number)) :
        /^(?:probe|check)0$/.test(expr) ? 'Use String.fromCharCode' : expr;
      response.writeHead(200, {'content-type': 'application/json', 'cache-control': 'no-store'});
      response.end(JSON.stringify({result}));
      return;
    }
    response.writeHead(404, {'content-type': 'application/json'});
    response.end('{"error":"Not found"}');
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  t.after(() => new Promise(resolve => server.close(resolve)));
  const origin = `http://127.0.0.1:${server.address().port}`;
  const bin = path.join(root, 'bin');
  fs.mkdirSync(bin);
  const muse = path.join(bin, 'muse');
  fs.writeFileSync(muse, [
    '#!' + process.execPath,
    "const fs=require('node:fs');",
    '(async()=>{',
    'const args=process.argv.slice(2);',
    'const value=flag=>args[args.indexOf(flag)+1];',
    "if(args[0]!=='exec'||!args.includes('--disable-shell')||value('--provider')!=='meta')process.exit(2);",
    "const messages=JSON.parse(fs.readFileSync(value('--prompt-file'),'utf8'));",
    'const system=messages[0].content;',
    'const context=JSON.parse(messages[1].content);',
    'let answer;',
    "if(system.includes('Rank only the supplied observed read-only web-test candidates')){",
    "const lead=context.candidates.find(item=>item.kind==='xss-reflected'&&item.path==='/api/render'&&item.parameter==='expr');",
    "answer={priorities:[],strategies:[],experiments:lead?[{family:'expression-evaluation',path:lead.path,parameter:'expr',prelude:[],headers:[],controlValue:'plain',firstValue:'probe0',secondValue:'check0',marker:context.canary,secondMarker:context.secondCanary,priority:10,why:'Observed expression input'}]:[]};",
    '}',
    "else if(system.includes('Revise one inconclusive')){",
    "if(process.env.BX_SLOW_REVISION==='1')await new Promise(resolve=>setTimeout(resolve,12000));",
    "const chars=value=>'{{String.fromCharCode('+[...value].map(char=>char.charCodeAt(0)).join(',')+')}}';",
    "answer={experiments:[{family:'expression-evaluation',path:context.path,parameter:context.parameter,prelude:[],headers:[],controlValue:'plain',firstValue:chars(context.canary),secondValue:chars(context.secondCanary),marker:context.canary,secondMarker:context.secondCanary,why:'Target names expression syntax'}]};",
    '}',
    "else if(system.includes('Interpret only the extracted'))answer={files:context.files.map(file=>({id:file.id,role:'app',why:'Observed asset',authFlow:'',routes:[]}))};",
    "else if(system.includes('Assess only these independently proved'))answer={notes:[]};",
    "else answer={paths:[],notes:[],tasks:[],checks:[],experiments:[],files:[]};",
    "console.log(JSON.stringify({payload:{kind:'run_terminal',terminal:'completed',text:JSON.stringify(answer)}}));",
    '})().catch(error=>{console.error(error);process.exit(1)});',
  ].join('\n') + '\n', {mode: 0o700});
  const env = {...process.env, PATH: bin + path.delimiter + process.env.PATH,
    OWNER_TOKEN: 'RESUME_CREDENTIAL_DO_NOT_STORE'};
  const cli = async (args, extraEnv = {}) => execFile(process.execPath,
    [CLI, 'blackbox', ...args, '--project', root, '--json', '--non-interactive'],
    {cwd: root, env: {...env, ...extraEnv}, timeout: 120000});
  const setup = await cli(['setup', origin]);
  assert.equal(setup.code, 0, setup.stderr);
  const child = spawn(process.execPath,
    [CLI, 'blackbox', origin, '--project', root, '--rps', '30',
      '--model-calls', '17', '--max-urls', '63', '--max-tasks', '45',
      '--minutes', '2', '--dom-script-bytes', '1048576', '--json', '--non-interactive'],
    {cwd: root, env: {...env, BX_SLOW_REVISION: '1'}, stdio: 'ignore'});
  t.after(() => {if (child.exitCode == null) child.kill('SIGKILL');});
  const runsDir = path.join(root, '.bypass', 'runs');
  let firstRun, checkpoint;
  const deadline = Date.now() + 45000;
  while (Date.now() < deadline) {
    const folder = fs.existsSync(runsDir) ? fs.readdirSync(runsDir).find(name =>
      fs.existsSync(path.join(runsDir, name, 'research-checkpoint.json'))) : null;
    if (folder) {
      firstRun = folder;
      checkpoint = JSON.parse(fs.readFileSync(path.join(runsDir, folder,
        'research-checkpoint.json'), 'utf8'));
      if (checkpoint.active?.phase === 'attempted' && checkpoint.active.history.length === 1) break;
    }
    if (child.exitCode != null) break;
    await sleep(50);
  }
  assert.equal(checkpoint?.active?.phase, 'attempted', JSON.stringify({firstRun, checkpoint}));
  assert.equal(checkpoint.active.history[0].verdict, 'not_reproduced');
  assert.ok(!JSON.stringify(checkpoint).includes(env.OWNER_TOKEN));
  const firstMetadata = JSON.parse(fs.readFileSync(path.join(runsDir, firstRun,
    'run-start.json'), 'utf8'));
  assert.deepEqual({rps: firstMetadata.effectiveLimits.rps,
    modelCalls: firstMetadata.effectiveLimits.modelCalls,
    maxUrls: firstMetadata.effectiveLimits.maxUrls,
    tasks: firstMetadata.effectiveLimits.tasks,
    minutes: firstMetadata.effectiveLimits.minutes,
    domScriptBytes: firstMetadata.effectiveLimits.domScriptBytes},
  {rps: 30, modelCalls: 17, maxUrls: 63, tasks: 45, minutes: 2,
    domScriptBytes: 1048576});
  child.kill('SIGKILL');
  await new Promise(resolve => child.once('exit', resolve));
  const previousCount = expressions.filter(value => value === 'probe0' || value === 'check0').length;
  const scopeFile = path.join(root, 'blackbox.scope.json');
  const originalScope = fs.readFileSync(scopeFile, 'utf8');
  const changedScope = JSON.parse(originalScope);
  changedScope.include = ['/api/render'];
  fs.writeFileSync(scopeFile, JSON.stringify(changedScope));
  const mismatched = await cli(['resume', firstRun], {BX_SLOW_REVISION: '0'});
  assert.notEqual(mismatched.code, 0);
  assert.match(mismatched.stdout + mismatched.stderr, /different scope or target/);
  fs.writeFileSync(scopeFile, originalScope);
  const resumed = await cli(['resume', firstRun, '--model-calls', '19'],
    {BX_SLOW_REVISION: '0'});
  const data = JSON.parse(resumed.stdout);
  assert.ok(data.runDir, resumed.stderr);
  const run = JSON.parse(fs.readFileSync(path.join(data.runDir, 'run.json'), 'utf8'));
  assert.equal(run.resumedFrom, firstRun);
  assert.equal(run.rps, 30);
  assert.notEqual(run.scopeHash, firstMetadata.scopeHash,
    'a changed execution budget has its own effective scope hash');
  assert.deepEqual(run.scope.include, JSON.parse(originalScope).include);
  assert.deepEqual(run.scope.never, JSON.parse(originalScope).never);
  assert.deepEqual({rps: run.scope.limits.rps,
    modelCalls: run.scope.limits.modelCalls, maxUrls: run.scope.limits.maxUrls,
    tasks: run.scope.limits.tasks, minutes: run.scope.limits.minutes,
    domScriptBytes: run.scope.limits.domScriptBytes},
  {rps: 30, modelCalls: 19, maxUrls: 63, tasks: 45, minutes: 2,
    domScriptBytes: 1048576});
  const web = JSON.parse(fs.readFileSync(path.join(data.runDir, 'web-probes.json'), 'utf8'));
  const investigation = web.investigations.find(item => item.initial.path === '/api/render' &&
    item.attempts.some(attempt => attempt.sourceRun === firstRun));
  assert.ok(investigation, JSON.stringify(web.investigations));
  assert.equal(investigation.attemptsNew, 1);
  assert.equal(investigation.final.verdict, 'confirmed');
  assert.equal(expressions.filter(value => value === 'probe0' || value === 'check0').length, previousCount);
  const newEvidence = fs.readFileSync(path.join(data.runDir, 'evidence.jsonl'), 'utf8');
  assert.ok(!newEvidence.includes(env.OWNER_TOKEN));
  assert.ok(investigation.attempts.at(-1).evidence.every(id => newEvidence.includes(id)));
  assert.equal(investigation.attempts[0].sourceRun, firstRun);
  const complete = await cli(['resume', data.run], {BX_SLOW_REVISION: '0'});
  assert.notEqual(complete.code, 0);
  assert.match(complete.stdout + complete.stderr, /no pending Muse GET investigation/);
});
