import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import http from 'node:http';
import path from 'node:path';
import {randomBytes} from 'node:crypto';
import {temp} from './helpers.mjs';
import {execFile} from '../src/util.mjs';
import {CLI} from '../src/demo.mjs';
import {loadScope} from '../src/blackbox/scope.mjs';
import {planWebLeads} from '../src/blackbox/web-probes.mjs';

test('an observed Reflected XSS strategy needs no model payload or extra model call', async () => {
  const {scope} = loadScope({origin: 'http://127.0.0.1:4329',
    overrides: {acceptLocal: true}});
  const surface = {patterns: [{pattern: '/api/view', methods: ['GET'],
    params: {term: []}, source: ['public-openapi']}]};
  const planned = await planWebLeads(surface, scope, {budget: 20, model: 'fixture',
    infer: async () => ({priorities: [], experiments: [], strategies: [
      {family: 'Reflected XSS', path: '/api/view', parameter: 'term',
        priority: 10, why: 'Observed term might reach HTML'},
      {family: 'Reflected XSS', path: '/api/unobserved', parameter: 'term',
        priority: 10, why: 'Invented route'}]})});
  assert.equal(planned.modelCalls, 1);
  assert.ok(planned.strategyDecisions.some(item => item.accepted &&
    item.translatedTo === 'xss-reflected' && item.path === '/api/view'));
  assert.ok(planned.strategyDecisions.some(item => !item.accepted &&
    item.reason === 'unobserved-pair' && item.path === '/api/unobserved'));
  assert.ok(planned.leads.some(item => item.kind === 'xss-reflected' &&
    item.lead.path === '/api/view' && item.lead.basis === 'model-browser-strategy'));
});

test('actual CLI translates an observed Muse reflected-XSS proposal into browser checks without sending model markup', async t => {
  const root = temp();
  t.after(() => fs.rmSync(root, {recursive: true, force: true}));
  const route = `/api/records-${randomBytes(5).toString('hex')}`;
  const requested = [];
  const server = http.createServer((request, response) => {
    const url = new URL(request.url, 'http://fixture');
    requested.push({path: url.pathname, value: url.searchParams.get('active')});
    if (url.pathname === '/') {
      response.writeHead(200, {'content-type': 'text/html'});
      return response.end('<html><body>Records</body></html>');
    }
    if (url.pathname === '/openapi.json') {
      response.writeHead(200, {'content-type': 'application/json'});
      return response.end(JSON.stringify({openapi: '3.0.0', paths: {
        [route]: {get: {parameters: [{name: 'active', in: 'query'}]}}
      }}));
    }
    if (url.pathname === route) {
      response.writeHead(200, {'content-type': 'application/json', 'cache-control': 'no-store'});
      return response.end(JSON.stringify({active: url.searchParams.get('active') ?? null}));
    }
    response.writeHead(404);
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
    "const lead=context.candidates.find(item=>item.kind==='xss-reflected'&&item.path===process.env.BX_ROUTE&&item.parameter==='active');",
    "answer={priorities:[],strategies:[],experiments:lead?[{family:'reflected-xss',path:lead.path,parameter:lead.parameter,",
    "controlValue:'clean',firstValue:'<img src=x onerror=alert(1)>',secondValue:'<svg onload=alert(2)>',",
    "marker:context.canary,secondMarker:context.secondCanary,prelude:[],headers:[],priority:10,why:'Observed input might reach HTML'}]:[]};",
    '}',
    "else if(system.includes('Interpret only the extracted')){",
    'const context=JSON.parse(messages[1].content);',
    "answer={files:context.files.map(file=>({id:file.id,role:'app',why:'Observed client',authFlow:'',routes:file.routes.map(route=>({path:route.path,method:route.method,purpose:'Observed route',parameters:[]}))}))};",
    '}',
    "else if(system.includes('Assess only these independently proved'))answer={notes:[]};",
    "else if(system.includes('mapping an authorized web API'))answer={paths:[],notes:[]};",
    "else if(system.includes('Propose bounded GET access-control'))answer={tasks:[]};",
    'else answer={};',
    "console.log(JSON.stringify({payload:{kind:'run_terminal',terminal:'completed',text:JSON.stringify(answer)}}));",
  ].join('\n') + '\n', {mode: 0o700});
  const completed = await execFile(process.execPath,
    [CLI, 'blackbox', origin, '--project', root, '--rps', '20', '--json', '--non-interactive'],
    {cwd: root, env: {PATH: `${bin}${path.delimiter}${process.env.PATH}`, BX_ROUTE: route},
      timeout: 90000});
  const output = JSON.parse(completed.stdout);
  const web = JSON.parse(fs.readFileSync(path.join(output.runDir, 'web-probes.json'), 'utf8'));
  assert.ok(web.strategyDecisions.some(item => item.mode === 'experiment' &&
    item.path === route && item.parameter === 'active' && item.accepted &&
    item.translatedTo === 'xss-reflected' && item.modelValuesExecuted === false),
  JSON.stringify(web.strategyDecisions));
  assert.ok(web.plan.some(item => item.kind === 'xss-reflected' && item.path === route &&
    item.parameter === 'active' && item.by === 'model'));
  assert.ok(web.results.some(item => item.kind === 'xss-reflected' &&
    item.verdict === 'not_reproduced'));
  assert.ok(requested.some(item => item.path === route && item.value?.includes('<')));
  assert.ok(!requested.some(item => /onerror|onload/.test(item.value ?? '')));
  assert.ok(!output.findings.some(item => item.kind === 'xss-reflected'));
});
