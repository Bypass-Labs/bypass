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
import {check} from '../src/blackbox/poc-runtime.mjs';

test('actual CLI lets Muse link proved findings across unrelated paths and proves the chain', async t => {
  if (process.platform === 'win32') {t.skip('the Muse process fixture uses an executable POSIX script'); return;}
  const root = temp();
  t.after(() => fs.rmSync(root, {recursive: true, force: true}));
  const suffix = randomBytes(4).toString('hex');
  const list = `/api/${suffix}/records`;
  const collection = `/api/${suffix}/documents`;
  const item = `${collection}/{id}`;
  const owner = {id: `doc-${suffix}-101`, ownerId: 'u-1', title: 'Owner document'};
  const outsider = {id: `doc-${suffix}-202`, ownerId: 'u-2', title: 'Other document'};
  const requested = [];
  let vulnerable = true, cachedList = false;
  const server = http.createServer((request, response) => {
    const url = new URL(request.url, 'http://local');
    requested.push(url.pathname);
    const who = request.headers.authorization === 'Bearer owner-token' ? 'u-1' :
      request.headers.authorization === 'Bearer other-token' ? 'u-2' : null;
    let status = 404, body = {error: 'Not found'};
    if (url.pathname === '/openapi.json') {status = 200; body = {openapi: '3.0.0', paths: {
      '/api/me': {get: {}}, [collection]: {get: {}}, [item]: {get: {}},
      [list]: {get: {parameters: [{name: 'all', in: 'query'}]}},
      '/api/delete': {get: {}},
    }};}
    else if (url.pathname === '/api/me') {
      status = who ? 200 : 401;
      body = who ? {id: who, role: 'member'} : {error: 'Sign in'};
    } else if (url.pathname === collection || url.pathname === list) {
      status = who ? 200 : 401;
      body = who ? url.pathname === list && url.searchParams.get('all') === '1' && vulnerable ?
        [owner, outsider] : [owner, outsider].filter(record => record.ownerId === who) :
        {error: 'Sign in'};
    } else if (url.pathname === `${collection}/${owner.id}`) {
      status = !who ? 401 : who === 'u-1' || vulnerable ? 200 : 403;
      body = status === 200 ? owner : {error: 'Denied'};
    } else if (url.pathname === `${collection}/${outsider.id}`) {
      status = !who ? 401 : who === 'u-2' || vulnerable ? 200 : 403;
      body = status === 200 ? outsider : {error: 'Denied'};
    } else if (url.pathname === '/api/delete') {status = 500; body = {error: 'Protected decoy'};}
    response.writeHead(status, {'content-type': 'application/json', 'cache-control': 'no-store',
      ...(cachedList && url.pathname === list ? {age: '1', 'x-cache': 'HIT'} : {})});
    response.end(JSON.stringify(body));
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  t.after(() => new Promise(resolve => server.close(resolve)));
  const origin = `http://127.0.0.1:${server.address().port}`;
  const bin = path.join(root, 'bin');
  fs.mkdirSync(bin);
  const logFile = path.join(root, 'chain-candidates.jsonl');
  const muse = [
    '#!' + process.execPath,
    "const fs=require('node:fs');",
    'const args=process.argv.slice(2);',
    "const value=flag=>args[args.indexOf(flag)+1];",
    "if(args[0]!=='exec'||!args.includes('--disable-shell')||!args.includes('--output-schema')||value('--provider')!=='meta')process.exit(2);",
    "const messages=JSON.parse(fs.readFileSync(value('--prompt-file'),'utf8'));",
    "const schema=JSON.parse(fs.readFileSync(value('--output-schema'),'utf8'));",
    'function blank(node){',
    "const type=Array.isArray(node.type)?node.type.find(item=>item!=='null'):node.type;",
    'if(node.enum)return node.enum[0];',
    "if(type==='object')return Object.fromEntries((node.required||[]).map(key=>[key,blank(node.properties[key])]));",
    "if(type==='array')return [];",
    "if(type==='integer'||type==='number')return node.minimum||0;",
    "if(type==='boolean')return false;",
    "if(type==='string')return '';",
    'if(node.anyOf)return blank(node.anyOf[0]);',
    'return null;',
    '}',
    'let answer=blank(schema);',
    "if(messages[0].content.includes('Select at most three useful list-to-item chains')){",
    'const context=JSON.parse(messages[1].content);',
    "fs.appendFileSync(process.env.BX_CHAIN_STUB_LOG,JSON.stringify(context)+'\\n');",
    'const row=context.candidates[0];',
    "answer={proposals:row?[{yields:row.yields,reads:'/api/delete',as:row.as,why:'Invented route'},",
    "{yields:row.yields,reads:row.reads,as:row.as,why:'Observed ID overlap'}]:[]};",
    '}',
    "console.log(JSON.stringify({payload:{kind:'run_terminal',terminal:'completed',text:JSON.stringify(answer)}}));",
  ].join('\n') + '\n';
  fs.writeFileSync(path.join(bin, 'muse'), muse, {mode: 0o700});
  const env = {PATH: `${bin}${path.delimiter}${process.env.PATH}`,
    BX_CHAIN_STUB_LOG: logFile, OWNER_TOKEN: 'owner-token', OTHER_TOKEN: 'other-token'};
  const cli = async (...args) => {
    const done = await execFile(process.execPath,
      [CLI, 'blackbox', ...args, '--project', root, '--json', '--non-interactive'],
      {cwd: root, env, timeout: 90000});
    return {code: done.code, data: JSON.parse(done.stdout)};
  };
  assert.equal((await cli('scope', origin, '--include', '/api')).code, 0);
  const baseline = await cli(origin, '--accept-local', '--no-model');
  const baselineResults = JSON.parse(fs.readFileSync(path.join(baseline.data.runDir, 'results.json'), 'utf8'));
  assert.equal(baseline.code, 1, JSON.stringify({findings: baseline.data.findings,
    results: baselineResults.filter(value => value.task?.pattern === list || value.task?.pattern === item)
      .map(value => ({kind: value.task.kind, pattern: value.task.pattern, verdict: value.verdict,
        reason: value.reason, rule: value.rule}))}));
  const baselineSurface = JSON.parse(fs.readFileSync(path.join(baseline.data.runDir, 'surface.json'), 'utf8'));
  assert.ok(baseline.data.findings.some(finding => finding.kind === 'list-leak' && finding.pattern === list),
    JSON.stringify({findings: baseline.data.findings.map(value => ({kind: value.kind, pattern: value.pattern})),
      pattern: baselineSurface.patterns.find(value => value.pattern === list),
      listResults: baselineResults.filter(value => value.task?.pattern === list)
        .map(value => ({kind: value.task.kind, verdict: value.verdict, rule: value.rule, reason: value.reason}))}));
  assert.ok(baseline.data.findings.some(finding => finding.kind === 'idor' && finding.pattern === item));
  assert.deepEqual(JSON.parse(fs.readFileSync(path.join(baseline.data.runDir, 'chains.json'), 'utf8')),
    [], 'the code template cannot connect unrelated route paths');
  const modeled = await cli(origin, '--accept-local');
  assert.equal(modeled.code, 1, JSON.stringify(modeled.data));
  const chains = JSON.parse(fs.readFileSync(path.join(modeled.data.runDir, 'chains.json'), 'utf8'));
  const chain = chains.find(value => value.status === 'confirmed' && value.selectedBy === 'model');
  assert.ok(chain, JSON.stringify(chains));
  assert.equal(chain.findings.length, 2);
  const severityOrder = ['info', 'low', 'medium', 'high', 'critical'];
  const parents = modeled.data.findings.filter(finding => chain.findings.includes(finding.id));
  const parentRank = Math.max(...parents.map(finding => severityOrder.indexOf(finding.severity)));
  assert.equal(parents.length, 2);
  assert.equal(chain.baseSeverity, severityOrder[parentRank]);
  assert.equal(chain.severity, severityOrder[Math.min(parentRank + 1, severityOrder.length - 1)]);
  assert.match(fs.readFileSync(modeled.data.reportPath, 'utf8'),
    /Selected by: Muse proposal, independently replayed/);
  assert.ok(fs.existsSync(chain.proof));
  const planning = JSON.parse(fs.readFileSync(path.join(modeled.data.runDir, 'chain-planning.json'), 'utf8'));
  assert.equal(planning[0].accepted, 1);
  assert.equal(planning[0].rejected, 1);
  assert.equal(planning[0].candidatesSent, planning[0].candidatesAvailable);
  const contexts = fs.readFileSync(logFile, 'utf8').trim().split('\n').map(line => JSON.parse(line));
  assert.ok(contexts[0].candidates.some(value => value.listPath === list && value.itemPath === item));
  assert.ok(!requested.includes('/api/delete'));
  const spec = JSON.parse(fs.readFileSync(path.join(path.dirname(chain.proof), 'spec.json'), 'utf8'));
  cachedList = true;
  assert.equal((await check(spec, env)).verdict, 'inconclusive',
    'a cached list cannot independently confirm the model-selected chain');
  cachedList = false;
  assert.equal((await cli('verify', modeled.data.run)).code, 1);
  const exported = await cli('export', modeled.data.run, '--out', path.join(root, 'regressions'));
  assert.equal(exported.code, 0);
  const testEnv = {...Object.fromEntries(Object.entries(process.env).filter(([key]) => key !== 'NODE_TEST_CONTEXT')),
    OWNER_TOKEN: env.OWNER_TOKEN, OTHER_TOKEN: env.OTHER_TOKEN};
  const runExport = () => new Promise((resolve, reject) => {
    const child = spawn(process.execPath, ['--test', ...exported.data.files],
      {cwd: root, env: testEnv, stdio: 'ignore'});
    child.on('error', reject);
    child.on('close', resolve);
  });
  assert.equal(await runExport(), 1);
  vulnerable = false;
  assert.equal((await cli('verify', modeled.data.run)).code, 0);
  assert.equal(await runExport(), 0);
  assert.ok(!requested.includes('/api/delete'));
});
