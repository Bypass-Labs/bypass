import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import http from 'node:http';
import path from 'node:path';
import {randomBytes} from 'node:crypto';
import {spawn} from 'node:child_process';
import {temp} from './helpers.mjs';
import {execFile} from '../src/util.mjs';
import {CLI} from '../src/demo.mjs';
import {validModelExperiment, validModelHeaders} from '../src/blackbox/poc-runtime.mjs';
import {researchCatalogIndex, researchCatalogHint} from '../src/blackbox/research-catalog.mjs';

test('model syntax is accepted for local experiments and constrained elsewhere', () => {
  assert.equal(researchCatalogIndex().length, 35);
  assert.equal(researchCatalogIndex().find(item => item.name === 'Remote File Inclusion (RFI)')?.tier, 2);
  assert.match(researchCatalogHint('Remote File Inclusion (RFI)')?.verification ?? '',
    /controlled origin/);
  const spec = {parameter: 'expr', controlValue: 'plain',
    firstValue: "{{'b'+'x'}}", secondValue: "{{'b'+'y'}}",
    marker: 'bx123456789abc', secondMarker: 'bxabcdef123456'};
  assert.equal(validModelExperiment({...spec, origin: 'http://127.0.0.1:3000'}), true);
  assert.equal(validModelExperiment({...spec, origin: 'https://example.test'}), false);
  assert.equal(validModelExperiment({...spec, origin: 'http://127.0.0.1:3000',
    firstValue: "{{'b';'x'}}"}), false);
  assert.equal(validModelHeaders([{name: 'X-Mode', value: 'expression'}]), true);
  assert.equal(validModelHeaders([{name: 'Authorization', value: 'Bearer test'}]), false);
  assert.equal(validModelHeaders([{name: 'X-Mode', value: 'bad\r\nHeader: injected'}]), false);
});

test('Muse feedback loop pivots across observed routes after many negative experiments and replays proof', async t => {
  const liveMuse = process.env.BLACKBOX_LIVE_MUSE === '1';
  const root = temp();
  if (!liveMuse) t.after(() => fs.rmSync(root, {recursive: true, force: true}));
  const suffix = randomBytes(5).toString('hex');
  const intake = '/api/intake-' + suffix;
  const compute = '/api/compute-' + suffix;
  const requested = [];
  let vulnerable = true;
  const server = http.createServer((request, response) => {
    const url = new URL(request.url, 'http://fixture');
    requested.push(url.pathname);
    let status = 404, body = {error: 'Not found'};
    if (url.pathname === '/') {
      response.writeHead(200, {'content-type': 'text/html'});
      return response.end('<html><body>Expression service</body></html>');
    }
    if (url.pathname === '/openapi.json') {
      status = 200;
      body = {openapi: '3.0.0', paths: {
        [intake]: {get: {summary: 'Accept an expression for later computation',
          parameters: [{name: 'value', in: 'query', description: 'Expression to inspect'}]}},
        [compute]: {get: {summary: 'Compute a submitted expression with a client mode header',
          parameters: [{name: 'expr', in: 'query', description: 'Expression to compute'}]}},
        '/api/delete': {get: {}}}};
    } else if (url.pathname === intake) {
      status = 200;
      body = {error: 'Expressions are evaluated by the compute route'};
    } else if (url.pathname === compute) {
      status = 200;
      const expression = url.searchParams.get('expr') ?? '';
      if (!vulnerable) body = {result: expression};
      else if (request.headers['x-mode'] !== 'expression')
        body = {error: 'Set X-Mode: expression to evaluate this input'};
      else if (/^\{\{String\.fromCharCode\([\d,]+\)\}\}$/.test(expression) ||
          /^\{\{\[.+\]\.join\(''\)\}\}$/.test(expression)) {
        try {body = {result: Function('return ' + expression.slice(2, -2))()};}
        catch {body = {error: 'Invalid expression'};}
      } else {
        const match = /^probe(\d+)$/.exec(expression);
        body = {error: liveMuse ?
          'Unsupported expression syntax; use {{String.fromCharCode(...)}} for codepoint expressions' :
          match && Number(match[1]) >= 6 ?
          'Try String.fromCharCode for this expression syntax' :
          'Unsupported expression syntax'};
      }
    } else if (url.pathname === '/api/delete') {
      status = 500;
      body = {error: 'Protected decoy'};
    }
    response.writeHead(status, {'content-type': 'application/json', 'cache-control': 'no-store'});
    response.end(JSON.stringify(body));
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  t.after(() => new Promise(resolve => server.close(resolve)));
  const origin = 'http://127.0.0.1:' + server.address().port;
  const bin = path.join(root, 'bin');
  fs.mkdirSync(bin);
  const muse = path.join(bin, 'muse');
  if (!liveMuse) {
  fs.writeFileSync(muse, [
    '#!' + process.execPath,
    "const fs=require('node:fs');",
    'const args=process.argv.slice(2);',
    'const value=flag=>args[args.indexOf(flag)+1];',
    "if(args[0]!=='exec'||!args.includes('--disable-shell')||!args.includes('--output-schema')||value('--provider')!=='meta')process.exit(2);",
    "const messages=JSON.parse(fs.readFileSync(value('--prompt-file'),'utf8'));",
    'const system=messages[0].content;',
    'let answer;',
    "if(system.includes('Rank only the supplied observed read-only web-test candidates')){",
    'const context=JSON.parse(messages[1].content);',
    "const lead=context.candidates.find(item=>item.kind==='xss-reflected'&&item.path===process.env.BX_INTAKE&&item.parameter==='value');",
    "answer={priorities:[],strategies:[],experiments:lead&&context.catalogReference?.some(item=>item.name==='Remote File Inclusion (RFI)'&&item.tier===2)?[{family:'unknown-expression-evaluation',path:lead.path,parameter:'value',prelude:[],headers:[],controlValue:'plain',firstValue:'probe0',secondValue:'check0',marker:context.canary,secondMarker:context.secondCanary,priority:10,why:'Investigate the observed expression input'}]:[]};",
    '}',
    "else if(system.includes('Revise one inconclusive')){",
    'const context=JSON.parse(messages[1].content);',
    'const last=context.recentAttempts.at(-1);',
    "const hinted=last.responses.some(item=>item.fields?.error?.includes('String.fromCharCode'));",
    "const modeHint=last.responses.some(item=>item.fields?.error?.includes('X-Mode: expression'));",
    "const move=context.path===process.env.BX_INTAKE&&last.responses.some(item=>item.fields?.error?.includes('compute route'));",
    "const path=move?process.env.BX_COMPUTE:context.path;",
    "const parameter=move?'expr':context.parameter;",
    "let firstValue='probe'+context.attemptsSoFar;",
    "let secondValue='check'+context.attemptsSoFar;",
    "if(hinted){firstValue='{{String.fromCharCode('+[...context.canary].map(char=>char.charCodeAt(0)).join(',')+')}}';secondValue='{{['+[...context.secondCanary].map(char=>JSON.stringify(char)).join(',')+\"].join('')}}\";}",
    "answer={experiments:[{family:'unknown-expression-evaluation',path,parameter,prelude:[],headers:modeHint?[{name:'X-Mode',value:'expression'}]:last.headers??[],controlValue:'plain',firstValue,secondValue,marker:context.canary,secondMarker:context.secondCanary,why:move?'Pivoted after target response named the compute route':hinted?'Target revealed a relevant expression syntax':'Refine after negative result'}]};",
    '}',
    "else if(system.includes('Interpret only the extracted')){const context=JSON.parse(messages[1].content);answer={files:context.files.map(file=>({id:file.id,role:'app',why:'Observed public asset',authFlow:'',routes:[]}))};}",
    "else if(system.includes('Assess only these independently proved'))answer={notes:[]};",
    "else if(system.includes('mapping an authorized web API'))answer={paths:[],notes:[]};",
    "else if(system.includes('Propose bounded GET access-control'))answer={tasks:[]};",
    "else answer={paths:[],notes:[],tasks:[],checks:[],experiments:[],files:[]};",
    "console.log(JSON.stringify({payload:{kind:'run_terminal',terminal:'completed',text:JSON.stringify(answer)}}));",
  ].join('\n') + '\n', {mode: 0o700});
  const syntax = await execFile(process.execPath, ['--check', muse]);
  assert.equal(syntax.code, 0, syntax.stderr);
  }
  const env = {...(!liveMuse ? {PATH: bin + path.delimiter + process.env.PATH} : {}),
    BX_INTAKE: intake, BX_COMPUTE: compute};
  const cli = async (...args) => {
    const done = await execFile(process.execPath,
      [CLI, 'blackbox', ...args, '--project', root, '--json', '--non-interactive'],
      {cwd: root, env, timeout: liveMuse ? 660000 : 120000});
    return {code: done.code, data: JSON.parse(done.stdout)};
  };
  const baseline = await cli(origin, '--no-model', '--rps', '30');
  assert.ok(!baseline.data.findings.some(item => item.kind === 'model-differential'));
  const modeled = await cli(origin, '--rps', '30');
  assert.ok(modeled.data.runDir, JSON.stringify(modeled));
  const web = JSON.parse(fs.readFileSync(path.join(modeled.data.runDir, 'web-probes.json'), 'utf8'));
  assert.equal(modeled.code, 3, JSON.stringify({runDir: modeled.data.runDir,
    findings: modeled.data.findings, modelError: web.modelError,
    modelOutput: modeled.data.modelOutput, coverage: web.modelCoverage,
    decisions: web.strategyDecisions, investigations: web.investigations}));
  const finding = modeled.data.findings.find(item =>
    item.kind === 'model-differential' && item.pattern === compute);
  assert.ok(finding, JSON.stringify(modeled.data.findings));
  assert.ok(fs.existsSync(finding.proof));
  const investigation = web.investigations.find(item => liveMuse ?
    item.final.path === compute && item.final.verdict === 'confirmed' : item.initial.path === intake);
  assert.ok(investigation);
  if (!liveMuse) assert.ok(investigation.attempts.length >= 8, JSON.stringify(investigation));
  assert.equal(investigation.final.path, compute);
  assert.equal(investigation.final.verdict, 'confirmed');
  assert.equal(investigation.stopReason, 'confirmed');
  assert.ok(investigation.attempts.some(item => item.headers?.some(header =>
    header.name === 'X-Mode' && header.value === 'expression')));
  assert.ok(investigation.attempts.some(item => item.responses.some(response =>
    Number.isInteger(response.ms) && response.ms >= 0)));
  if (!liveMuse) assert.ok(investigation.attempts.some(item => item.responses.some(response =>
    response.fields?.error?.includes('String.fromCharCode'))));
  const ledger = fs.readFileSync(path.join(modeled.data.runDir, 'evidence.jsonl'), 'utf8')
    .trim().split('\n').map(line => JSON.parse(line));
  assert.ok(ledger.filter(item => item.kind === 'model-differential-attempt').length >=
    (liveMuse ? 1 : 8));
  if (!liveMuse) {
    assert.ok(ledger.some(item => item.kind === 'model-differential-decision' &&
      item.accepted && item.path === compute));
    assert.ok(web.strategyDecisions.some(item => item.mode === 'experiment-revision' &&
      item.accepted && item.path === compute));
  }
  assert.ok(!requested.includes('/api/delete'));
  assert.equal((await cli('verify', modeled.data.run)).code, 1);
  const exported = await cli('export', modeled.data.run, '--out', path.join(root, 'regressions'));
  assert.equal(exported.code, 0);
  const runExport = () => new Promise((resolve, reject) => {
    const child = spawn(process.execPath, ['--test', ...exported.data.files],
      {env: Object.fromEntries(Object.entries(process.env).filter(([key]) => key !== 'NODE_TEST_CONTEXT')),
        stdio: 'ignore'});
    child.once('error', reject);
    child.once('close', resolve);
  });
  assert.equal(await runExport(), 1);
  vulnerable = false;
  assert.equal((await cli('verify', modeled.data.run)).code, 0);
  assert.equal(await runExport(), 0);
  assert.ok(!requested.includes('/api/delete'));
});
