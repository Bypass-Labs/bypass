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

test('actual CLI executes a Muse-proposed experiment outside named probe profiles and replays its fix', async t => {
  const root = temp();
  t.after(() => fs.rmSync(root, {recursive: true, force: true}));
  const route = `/api/processor-${randomBytes(4).toString('hex')}`;
  const preludeRoutes = Array.from({length: 5}, () =>
    `/api/prepare-${randomBytes(4).toString('hex')}`);
  const requested = [];
  let vulnerable = true;
  const prepared = new Set();
  const server = http.createServer((request, response) => {
    const url = new URL(request.url, 'http://local');
    requested.push(url.pathname);
    if (url.pathname === '/') {
      response.writeHead(200, {'content-type': 'text/html'});
      return response.end('<html><body>Processor</body></html>');
    }
    if (url.pathname === '/openapi.json') {
      response.writeHead(200, {'content-type': 'application/json'});
      return response.end(JSON.stringify({openapi: '3.0.0', paths: {
        [route]: {get: {parameters: [{name: 'expression', in: 'query'}]}},
        ...Object.fromEntries(preludeRoutes.map(path => [path, {get: {}}])),
        '/api/delete': {get: {}}}}));
    }
    if (preludeRoutes.includes(url.pathname)) {
      prepared.add(url.pathname);
      response.writeHead(200, {'content-type': 'application/json', 'cache-control': 'no-store'});
      return response.end(JSON.stringify({ready: true}));
    }
    if (url.pathname === route) {
      const expression = url.searchParams.get('expression') ?? '7';
      let value = expression;
      const canRun = preludeRoutes.every(path => prepared.has(path));
      prepared.clear();
      if (vulnerable && canRun) try { value = Function(`return (${expression})`)(); }
      catch { value = 'invalid'; }
      response.writeHead(200, {'content-type': 'application/json', 'cache-control': 'no-store'});
      return response.end(JSON.stringify({result: value}));
    }
    response.writeHead(url.pathname === '/api/delete' ? 500 : 404);
    response.end();
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  t.after(() => new Promise(resolve => server.close(resolve)));
  const origin = `http://127.0.0.1:${server.address().port}`;
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
    'let answer;',
    "if(system.includes('Rank only the supplied observed read-only web-test candidates')){",
    'const context=JSON.parse(messages[1].content);',
    "const lead=context.candidates.find(item=>item.kind==='xss-reflected'&&item.path===process.env.BX_ROUTE&&item.parameter==='expression');",
    'const preludes=context.preludeRoutes.filter(item=>process.env.BX_PRELUDES.split(",").includes(item));',
    'const marker=context.canary;',
    'const secondMarker=context.secondCanary;',
    "const firstValue=`String.fromCharCode(${[...marker].map(char=>char.charCodeAt(0)).join(',')})`;",
    "const secondValue='8';",
    "answer={priorities:[],strategies:[],experiments:lead&&preludes.length===5?[{family:'unsafe-expression-evaluation',path:lead.path,parameter:lead.parameter,prelude:preludes,controlValue:'7',firstValue,secondValue,marker,secondMarker,priority:10,why:'Observed expression is evaluated by the server after five observed preparation requests'}]:[]};",
    '}',
    "else if(system.includes('Revise one inconclusive')){",
    'const context=JSON.parse(messages[1].content);',
    'const marker=context.canary;',
    'const secondMarker=context.secondCanary;',
    "const firstValue=`String.fromCharCode(${[...marker].map(char=>char.charCodeAt(0)).join(',')})`;",
    "const secondValue=`[${[...secondMarker].map(char=>JSON.stringify(char)).join(',')}].join('')`;",
    "answer={experiments:[{family:'unsafe-expression-evaluation',path:context.path,parameter:context.parameter,controlValue:'7',firstValue,secondValue,marker,secondMarker,why:'The first response showed evaluation; revise the second expression'}]};",
    '}',
    "else if(system.includes('Interpret only the extracted')){",
    'const context=JSON.parse(messages[1].content);',
    "answer={files:context.files.map(file=>({id:file.id,role:'app',why:'Observed public client',authFlow:'',routes:file.routes.map(route=>({path:route.path,method:route.method,purpose:'Observed route',parameters:[]}))}))};",
    '}',
    "else if(system.includes('Assess only these independently proved'))answer={notes:[]};",
    "else if(system.includes('mapping an authorized web API'))answer={paths:[],notes:[]};",
    "else if(system.includes('Propose bounded GET access-control'))answer={tasks:[]};",
    'else process.exit(3);',
    "console.log(JSON.stringify({payload:{kind:'run_terminal',terminal:'completed',text:JSON.stringify(answer)}}));",
  ].join('\n') + '\n', {mode: 0o700});
  const env = {PATH: `${bin}${path.delimiter}${process.env.PATH}`, BX_ROUTE: route,
    BX_PRELUDES: preludeRoutes.join(',')};
  const cli = async (...args) => {
    const completed = await execFile(process.execPath,
      [CLI, 'blackbox', ...args, '--project', root, '--json', '--non-interactive'],
      {cwd: root, env, timeout: 90000});
    return {code: completed.code, data: JSON.parse(completed.stdout)};
  };
  const baseline = await cli(origin, '--no-model', '--rps', '20');
  assert.ok(!baseline.data.findings.some(item => item.kind === 'model-differential'));
  const modeled = await cli(origin, '--rps', '20');
  const web = JSON.parse(fs.readFileSync(path.join(modeled.data.runDir, 'web-probes.json'), 'utf8'));
  assert.equal(modeled.code, 3, JSON.stringify({error: modeled.data.modelError,
    findings: modeled.data.findings, decisions: web.strategyDecisions}));
  const finding = modeled.data.findings.find(item => item.kind === 'model-differential' && item.pattern === route);
  assert.ok(finding, JSON.stringify(modeled.data.findings));
  assert.equal(finding.modelHypothesis.family, 'unsafe-expression-evaluation');
  assert.equal(finding.owasp, 'Unclassified behavior');
  const report = fs.readFileSync(path.join(modeled.data.runDir, 'report.md'), 'utf8');
  assert.match(report, /Muse hypothesis:.*unsafe-expression-evaluation/);
  assert.match(report, /security impact are not established by the generic canary check/);
  assert.ok(fs.existsSync(finding.proof));
  // Split planning can accept another fresh-canary experiment for this input.
  assert.ok(modeled.data.modelOutput.webExperiments >= 2);
  assert.ok(web.strategyDecisions.some(item => item.mode === 'experiment' && item.accepted && item.path === route));
  assert.ok(web.strategyDecisions.some(item => item.mode === 'experiment' && item.accepted &&
    item.prelude?.length === 5));
  assert.equal(finding.webProof.prelude.length, 5);
  assert.ok(preludeRoutes.every(path => requested.filter(item => item === path).length >= 3));
  assert.ok(web.strategyDecisions.some(item => item.mode === 'experiment-revision' && item.accepted && item.path === route));
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
  const fixed = await cli(origin, '--rps', '20');
  assert.ok(!fixed.data.findings.some(item => item.kind === 'model-differential'));
  assert.ok(!requested.includes('/api/delete'));
});
