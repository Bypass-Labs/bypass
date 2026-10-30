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

test('CLI resumes a test-response route after interruption without its old evidence ID',
  {timeout: 120000}, async t => {
    const root = fs.mkdtempSync(path.join(os.tmpdir(), 'bypass-feedback-resume-'));
    t.after(() => fs.rmSync(root, {recursive: true, force: true}));
    let reveal = true;
    const requested = [];
    const server = http.createServer((request, response) => {
      const url = new URL(request.url, 'http://fixture');
      requested.push(`${url.pathname}${url.search}`);
      response.setHeader('cache-control', 'no-store');
      if (url.pathname === '/') {
        response.setHeader('content-type', 'text/html');
        return response.end('<html><script src="/app.js"></script></html>');
      }
      if (url.pathname === '/app.js') {
        response.setHeader('content-type', 'application/javascript');
        return response.end('fetch("/probe?item=baseline");');
      }
      response.setHeader('content-type', 'application/json');
      if (url.pathname === '/probe') return response.end(JSON.stringify(
        url.searchParams.get('item') === 'baseline' || !url.searchParams.has('item') ?
          {status: 'ready'} : {status: 'changed', ...(reveal ? {nextRoute: '/late'} : {})}));
      if (url.pathname === '/late') return response.end(JSON.stringify({status: 'ready'}));
      response.statusCode = 404;
      response.end(JSON.stringify({error: 'missing'}));
    });
    await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
    t.after(() => new Promise(resolve => server.close(resolve)));
    const origin = `http://127.0.0.1:${server.address().port}`;
    const bin = path.join(root, 'bin');
    fs.mkdirSync(bin);
    fs.writeFileSync(path.join(bin, 'muse'), [
      '#!' + process.execPath,
      "const fs=require('node:fs');",
      '(async()=>{',
      'const args=process.argv.slice(2);',
      'const value=flag=>args[args.indexOf(flag)+1];',
      "if(args[0]!=='exec'||!args.includes('--disable-shell')||value('--provider')!=='meta')process.exit(2);",
      "const messages=JSON.parse(fs.readFileSync(value('--prompt-file'),'utf8'));",
      'const system=messages[0].content;',
      'let answer;',
      "if(system.includes('Continue mapping this authorized test-feedback')){",
      "if(process.env.BX_SLOW_FEEDBACK==='1')await new Promise(resolve=>setTimeout(resolve,12000));",
      "answer={paths:['/late?probe=baseline']};",
      '}',
      "else if(system.includes('Interpret only the extracted')){",
      'const context=JSON.parse(messages[1].content);',
      "answer={files:context.files.map(file=>({id:file.id,role:'app',why:'Observed asset',authFlow:'',routes:[]}))};",
      '}',
      'else answer={paths:[],notes:[],tasks:[],checks:[],experiments:[],files:[]};',
      "console.log(JSON.stringify({payload:{kind:'run_terminal',terminal:'completed',text:JSON.stringify(answer)}}));",
      '})().catch(error=>{console.error(error);process.exit(1)});',
    ].join('\n') + '\n', {mode: 0o700});
    const env = {...process.env, PATH: bin + path.delimiter + process.env.PATH,
      OWNER_TOKEN: 'RESUME_FEEDBACK_SECRET_DO_NOT_STORE'};
    const cli = (args, extraEnv = {}) => execFile(process.execPath,
      [CLI, 'blackbox', ...args, '--project', root, '--json', '--non-interactive'],
      {cwd: root, env: {...env, ...extraEnv}, timeout: 90000});
    assert.equal((await cli(['setup', origin])).code, 0);
    const child = spawn(process.execPath,
      [CLI, 'blackbox', origin, '--project', root, '--rps', '50',
        '--json', '--non-interactive'],
      {cwd: root, env: {...env, BX_SLOW_FEEDBACK: '1'}, stdio: 'ignore'});
    t.after(() => {if (child.exitCode == null) child.kill('SIGKILL');});
    const runsDir = path.join(root, '.bypass/runs');
    let firstRun, checkpoint;
    const deadline = Date.now() + 60000;
    while (Date.now() < deadline) {
      firstRun = fs.existsSync(runsDir) ? fs.readdirSync(runsDir).find(name =>
        fs.existsSync(path.join(runsDir, name, 'test-feedback-checkpoint.json'))) : null;
      if (firstRun) {
        checkpoint = JSON.parse(fs.readFileSync(path.join(runsDir, firstRun,
          'test-feedback-checkpoint.json'), 'utf8'));
        if (checkpoint.pending.includes('/late')) break;
      }
      if (child.exitCode != null) break;
      await sleep(50);
    }
    const webFile = firstRun && path.join(runsDir, firstRun, 'web-probes.json');
    const web = webFile && fs.existsSync(webFile) ? JSON.parse(fs.readFileSync(webFile)) : null;
    const surfaceFile = firstRun && path.join(runsDir, firstRun, 'surface.json');
    const surface = surfaceFile && fs.existsSync(surfaceFile) ?
      JSON.parse(fs.readFileSync(surfaceFile)) : null;
    assert.ok(checkpoint?.pending.includes('/late'),
      `the first run did not checkpoint its test-response route: ${JSON.stringify({
        checkpoint, requests: requested.filter(value => value.startsWith('/probe')).slice(-20),
        feedback: surface?.testResponseFollowup,
        results: web?.results?.map(item => ({kind: item.kind, verdict: item.verdict})),
        modelCoverage: web?.modelCoverage?.map(item => ({candidatesSent: item.candidatesSent,
          adaptiveAttempts: item.adaptiveAttempts}))})}`);
    assert.deepEqual(checkpoint.pending, ['/late']);
    assert.ok(!JSON.stringify(checkpoint).includes(env.OWNER_TOKEN));
    child.kill('SIGKILL');
    await new Promise(resolve => child.once('exit', resolve));
    reveal = false;
    const afterInterruption = requested.length;
    const resumed = await cli(['resume', firstRun], {BX_SLOW_FEEDBACK: '0'});
    const data = JSON.parse(resumed.stdout);
    assert.ok(data.runDir, JSON.stringify({code: resumed.code, data, stderr: resumed.stderr}));
    assert.ok(requested.slice(afterInterruption).some(url =>
      url.startsWith('/late?probe=')), 'a saved route must be tested after its response hint disappears');
    const run = JSON.parse(fs.readFileSync(path.join(data.runDir, 'run.json'), 'utf8'));
    assert.equal(run.resumedFrom, firstRun);
    const next = JSON.parse(fs.readFileSync(path.join(data.runDir,
      'test-feedback-checkpoint.json'), 'utf8'));
    assert.deepEqual(next.pending, []);
    assert.equal(next.resumedFrom, firstRun);
    assert.ok(!fs.readFileSync(path.join(data.runDir, 'evidence.jsonl'), 'utf8')
      .includes(env.OWNER_TOKEN));
  });
