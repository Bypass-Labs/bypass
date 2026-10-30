import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import http from 'node:http';
import os from 'node:os';
import path from 'node:path';
import {spawn} from 'node:child_process';
import {execFile} from '../src/util.mjs';
import {CLI} from '../src/demo.mjs';
import {loadScope} from '../src/blackbox/scope.mjs';
import {runJsonExperiments} from '../src/blackbox/json-experiment.mjs';

const sleep = ms => new Promise(resolve => setTimeout(resolve, ms));

test('CLI resumes committed Muse JSON POST feedback without resending the earlier writes',
  {timeout: 120000}, async t => {
    if (process.platform === 'win32') {
      t.skip('the Muse process fixture uses an executable POSIX script');
      return;
    }
    const root = fs.mkdtempSync(path.join(os.tmpdir(), 'bypass-json-resume-'));
    t.after(() => fs.rmSync(root, {recursive: true, force: true}));
    const route = '/api/evaluate';
    const submitted = [];
    let vulnerable = true;
    const server = http.createServer(async (request, response) => {
      const url = new URL(request.url, 'http://fixture.invalid');
      const json = (status, value) => {
        response.writeHead(status, {'content-type': 'application/json',
          'cache-control': 'no-store'});
        response.end(JSON.stringify(value));
      };
      if (url.pathname === '/') return json(200, {service: 'expression evaluator'});
      if (url.pathname === '/openapi.json') return json(200, {openapi: '3.0.0',
        paths: {[route]: {post: {summary: 'Evaluate an expression',
          requestBody: {content: {'application/json': {schema: {type: 'object',
            properties: {expression: {type: 'string'}}, required: ['expression']}}}}}}}});
      if (url.pathname === route && request.method === 'POST') {
        const chunks = [];
        for await (const chunk of request) chunks.push(chunk);
        const expression = JSON.parse(Buffer.concat(chunks).toString()).expression;
        submitted.push(expression);
        const codes = /^String\.fromCharCode\((\d+(?:,\d+)*)\)$/.exec(expression)?.[1];
        return json(200, {result: vulnerable && codes ?
          String.fromCharCode(...codes.split(',').map(Number)) : expression,
        message: 'PRIVATE_RESPONSE_SENTINEL'});
      }
      return json(404, {error: 'missing'});
    });
    await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
    t.after(() => new Promise(resolve => server.close(resolve)));
    const origin = `http://127.0.0.1:${server.address().port}`;
    const scopeFile = path.join(root, 'blackbox.scope.json');
    fs.writeFileSync(scopeFile, JSON.stringify({schemaVersion: 1,
      target: {origin}, include: ['/'], probes: {jsonPostPaths: [route]},
      limits: {rps: 40, maxUrls: 80, minutes: 2, modelCalls: 40, tasks: 100}}));
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
      "if(messages.some(item=>item.content.includes('PRIVATE_RESPONSE_SENTINEL')))fs.writeFileSync(process.env.BX_JSON_LEAK_MARKER,'leaked');",
      'const system=messages[0].content;',
      'const context=JSON.parse(messages[1].content);',
      'let answer;',
      "if(system.includes('Allocate the next black-box investigation effort')){",
      "answer={priorities:context.tracks.map(row=>({name:row.name,weight:row.name==='json'?100:1,why:'Observed method contract'}))};",
      '}',
      "else if(system.includes('Select distinct harmless response-transformation experiments for the reviewed JSON POST routes')){",
      " const operation=context.operations.find(item=>item.path===process.env.BX_JSON_ROUTE&&item.fields.includes('expression'));",
      " const planned=fs.existsSync(process.env.BX_JSON_PLAN_FILE);",
      " if(!planned)fs.writeFileSync(process.env.BX_JSON_PLAN_FILE,'planned');",
      " answer={experiments:operation&&!planned?[{family:'expression-evaluation',path:operation.path,field:'expression',as:'anonymous',oracle:'observation',controlValue:'plain0',firstValue:'first0',secondValue:'second0',marker:context.marker,secondMarker:context.secondMarker,fixedFields:[],prelude:[],observePath:'',observeAs:'anonymous',why:'Observed evaluator input',priority:10}]:[]};",
      '}',
      "else if(system.includes('Revise one negative or inconclusive experiment on an explicitly reviewed')){",
      " if(process.env.BX_JSON_SLOW_REVISION==='1')await new Promise(resolve=>setTimeout(resolve,12000));",
      " const chars=text=>'String.fromCharCode('+[...text].map(char=>char.charCodeAt(0)).join(',')+')';",
      " answer={experiments:[{family:'expression-evaluation',path:process.env.BX_JSON_ROUTE,field:'expression',oracle:'marker',controlValue:'7',firstValue:chars(context.marker),secondValue:chars(context.secondMarker),marker:context.marker,secondMarker:context.secondMarker,fixedFields:[],prelude:[],observePath:'',observeAs:'anonymous',why:'Use the observed evaluator syntax'}]};",
      '}',
      'else {',
      " const schema=JSON.parse(fs.readFileSync(value('--output-schema'),'utf8'));",
      " const blank=s=>s?.type==='object'?Object.fromEntries((s.required??[]).map(key=>[key,blank(s.properties?.[key])])):s?.type==='array'?[]:s?.type==='integer'||s?.type==='number'?0:s?.type==='boolean'?false:s?.enum?.[0]??'';",
      ' answer=blank(schema);',
      '}',
      "console.log(JSON.stringify({payload:{kind:'run_terminal',terminal:'completed',text:JSON.stringify(answer)}}));",
      '})().catch(error=>{console.error(error);process.exit(1)});',
    ].join('\n') + '\n', {mode: 0o700});
    const env = {...process.env, PATH: `${bin}${path.delimiter}${process.env.PATH}`,
      BX_JSON_ROUTE: route, BX_JSON_PLAN_FILE: path.join(root, 'planned'),
      BX_JSON_LEAK_MARKER: path.join(root, 'prompt-leaked'),
      OWNER_TOKEN: 'JSON_RESUME_CREDENTIAL_DO_NOT_STORE'};
    const first = spawn(process.execPath,
      [CLI, 'blackbox', origin, '--project', root, '--scope', scopeFile,
        '--json', '--non-interactive'],
      {cwd: root, env: {...env, BX_JSON_SLOW_REVISION: '1'}, stdio: 'ignore'});
    t.after(() => {if (first.exitCode == null) first.kill('SIGKILL');});
    const runsDir = path.join(root, '.bypass', 'runs');
    let firstRun, checkpoint;
    const deadline = Date.now() + 45000;
    while (Date.now() < deadline) {
      const folder = fs.existsSync(runsDir) ? fs.readdirSync(runsDir).find(name =>
        fs.existsSync(path.join(runsDir, name, 'json-experiment-checkpoint.json'))) : null;
      if (folder) {
        firstRun = folder;
        checkpoint = JSON.parse(fs.readFileSync(path.join(runsDir, folder,
          'json-experiment-checkpoint.json'), 'utf8'));
        if (checkpoint.active?.phase === 'attempted' &&
            checkpoint.active.history.length === 1) break;
      }
      if (first.exitCode != null) break;
      await sleep(50);
    }
    assert.equal(checkpoint?.active?.phase, 'attempted',
      JSON.stringify({firstRun, checkpoint}));
    assert.equal(checkpoint.active.history[0].verdict, 'inconclusive');
    assert.ok(!JSON.stringify(checkpoint).includes(env.OWNER_TOKEN));
    assert.ok(!JSON.stringify(checkpoint).includes('PRIVATE_RESPONSE_SENTINEL'));
    assert.equal(fs.existsSync(env.BX_JSON_LEAK_MARKER), false);
    first.kill('SIGKILL');
    await new Promise(resolve => first.once('exit', resolve));
    const oldCount = submitted.filter(value =>
      ['plain0', 'first0', 'second0'].includes(value)).length;
    assert.equal(oldCount, 3);
    const resumed = await execFile(process.execPath,
      [CLI, 'blackbox', 'resume', firstRun, '--project', root,
        '--json', '--non-interactive'],
      {cwd: root, env: {...env, BX_JSON_SLOW_REVISION: '0'}, timeout: 90000});
    const audit = JSON.parse(resumed.stdout);
    assert.ok(audit.runDir, resumed.stderr);
    const web = JSON.parse(fs.readFileSync(path.join(audit.runDir, 'web-probes.json')));
    const investigation = web.investigations.find(item => item.initial.path === route &&
      item.attempts.some(attempt => attempt.sourceRun === firstRun));
    assert.ok(investigation, JSON.stringify(web.investigations));
    assert.equal(investigation.attemptsNew, 1);
    assert.equal(investigation.final.verdict, 'confirmed');
    assert.equal(submitted.filter(value =>
      ['plain0', 'first0', 'second0'].includes(value)).length, oldCount);
    const finding = audit.findings.find(item => item.kind === 'model-json-differential');
    assert.ok(finding?.proof, JSON.stringify(audit.findings));
    const proof = await execFile(process.execPath, [finding.proof],
      {cwd: root, env, timeout: 20000});
    assert.equal(JSON.parse(proof.stdout).verdict, 'confirmed');
    const verify = () => execFile(process.execPath,
      [CLI, 'blackbox', 'verify', audit.run, '--project', root,
        '--json', '--non-interactive'], {cwd: root, env, timeout: 20000});
    assert.equal((await verify()).code, 1);
    const finishedCheckpoint = JSON.parse(fs.readFileSync(path.join(audit.runDir,
      'json-experiment-checkpoint.json'), 'utf8'));
    assert.equal(finishedCheckpoint.cursor, finishedCheckpoint.leads.length);
    const exported = await execFile(process.execPath,
      [CLI, 'blackbox', 'export', audit.run, '--project', root,
        '--out', path.join(root, 'regression'), '--json', '--non-interactive'],
      {cwd: root, env, timeout: 20000});
    assert.equal(exported.code, 0, exported.stderr);
    const files = JSON.parse(exported.stdout).files;
    const regression = () => execFile(process.execPath, ['--test', ...files],
      {cwd: root, env: {...env, NODE_TEST_CONTEXT: undefined}, timeout: 20000});
    assert.equal((await regression()).code, 1);
    vulnerable = false;
    assert.equal(JSON.parse((await execFile(process.execPath, [finding.proof],
      {cwd: root, env, timeout: 20000})).stdout).verdict, 'not_reproduced');
    assert.equal((await verify()).code, 0);
    assert.equal((await regression()).code, 0);
    const finishedResume = await execFile(process.execPath,
      [CLI, 'blackbox', 'resume', audit.run, '--project', root,
        '--json', '--non-interactive'], {cwd: root, env, timeout: 20000});
    assert.notEqual(finishedResume.code, 0);
    assert.match(finishedResume.stdout + finishedResume.stderr,
      /no pending Muse.*investigation/);
    assert.ok(!fs.readFileSync(path.join(audit.runDir, 'evidence.jsonl'), 'utf8')
      .includes(env.OWNER_TOKEN));
    const artifactText = directory => fs.readdirSync(directory,
      {recursive: true, withFileTypes: true}).filter(item => item.isFile())
      .map(item => fs.readFileSync(path.join(item.parentPath, item.name), 'utf8')).join('\n');
    for (const directory of [path.join(runsDir, firstRun), audit.runDir])
      assert.ok(!artifactText(directory).includes('PRIVATE_RESPONSE_SENTINEL'));
    assert.equal(fs.existsSync(env.BX_JSON_LEAK_MARKER), false);
  });

test('JSON feedback coalesces an unchanged revision before recording it as accepted', async () => {
  const origin = 'http://127.0.0.1:43127';
  const scope = loadScope({origin, overrides: {acceptLocal: true}}).scope;
  const route = '/api/evaluate';
  const lead = {path: route, parameter: 'expression', as: 'anonymous',
    oracle: 'observation', fixedFields: [], observedFields: ['expression'],
    prelude: [], observePath: '', observeAs: 'anonymous',
    family: 'expression-evaluation', why: 'Observed expression input',
    controlValue: 'plain0', firstValue: 'first0', secondValue: 'second0',
    marker: 'bx111111111111', secondMarker: 'bx222222222222'};
  let requests = 0;
  const run = await runJsonExperiments([lead], scope, {
    surface: {patterns: [], jsonBodyOperations: [{path: route,
      method: 'POST', contentType: 'application/json', fields: ['expression']}]},
    requester: async ({body}) => {
      const value = JSON.parse(body).expression;
      const responseBody = JSON.stringify({result: value});
      return {status: 200, type: 'application/json', body: responseBody,
        hash: `sha256:${requests++}`, evidenceId: `ev-${requests}`};
    },
    model: 'fixture', modelCallsAvailable: 1,
    infer: async (_model, messages) => {
      const context = JSON.parse(messages[1].content);
      return {experiments: [{family: lead.family, path: route,
        field: lead.parameter, oracle: 'observation',
        controlValue: lead.controlValue, firstValue: lead.firstValue,
        secondValue: lead.secondValue,
        marker: context.marker, secondMarker: context.secondMarker,
        fixedFields: [], prelude: [], observePath: '',
        observeAs: 'anonymous', why: lead.why}]};
    }});
  assert.equal(requests, 3);
  assert.equal(run.decisions[0]?.accepted, false);
  assert.equal(run.decisions[0]?.reason, 'duplicate-payload');
  assert.equal(run.investigations[0].attemptsNew, 1);
});
