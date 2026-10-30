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

test('actual CLI proves a Muse-selected file profile on an observed dotted file parameter', async t => {
  if (process.platform !== 'linux' || !/^127\.0\.0\.1[\t ]+localhost(?:[\t \r]|$)/m
    .test(fs.readFileSync('/etc/hosts', 'utf8'))) {
    t.skip('a standard local hosts file is needed for this file-read fixture');
    return;
  }
  const root = temp();
  t.after(() => fs.rmSync(root, {recursive: true, force: true}));
  const filesDir = path.join(root, 'public', 'files');
  fs.mkdirSync(filesDir, {recursive: true});
  const route = `/api/doc-${randomBytes(4).toString('hex')}/preview`;
  const requested = [];
  let vulnerable = true;
  const server = http.createServer((request, response) => {
    const url = new URL(request.url, 'http://local');
    requested.push(url.pathname);
    if (url.pathname === '/') {
      response.writeHead(200, {'content-type': 'text/html'});
      return response.end('<html><script src="/app.js"></script></html>');
    }
    if (url.pathname === '/app.js') {
      response.writeHead(200, {'content-type': 'application/javascript'});
      return response.end(`export const preview = () => fetch('${route}?source.file=guide.txt');`);
    }
    if (url.pathname === '/openapi.json') {
      response.writeHead(200, {'content-type': 'application/json'});
      return response.end(JSON.stringify({openapi: '3.0.0', paths: {
        [route]: {get: {parameters: [{name: 'source.file', in: 'query'}]}},
        '/api/delete': {get: {}}}}));
    }
    if (url.pathname === route) {
      const file = path.resolve(filesDir, url.searchParams.get('source.file') ?? '');
      if (!vulnerable && !file.startsWith(`${filesDir}${path.sep}`)) {
        response.writeHead(403, {'content-type': 'text/plain', 'cache-control': 'no-store'});
        return response.end('Outside file directory');
      }
      try {
        const body = fs.readFileSync(file, 'utf8');
        response.writeHead(200, {'content-type': 'text/plain', 'cache-control': 'no-store'});
        return response.end(body);
      } catch {
        response.writeHead(404, {'content-type': 'text/plain', 'cache-control': 'no-store'});
        return response.end('Not found');
      }
    }
    response.writeHead(url.pathname === '/api/delete' ? 500 : 404);
    response.end();
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  t.after(() => new Promise(resolve => server.close(resolve)));
  const origin = `http://127.0.0.1:${server.address().port}`;
  const bin = path.join(root, 'bin');
  fs.mkdirSync(bin);
  const muse = path.join(bin, 'muse');
  const webLog = path.join(root, 'muse-web.jsonl');
  fs.writeFileSync(muse, [
    '#!' + process.execPath,
    "const fs=require('node:fs');",
    'const args=process.argv.slice(2);',
    'const value=flag=>args[args.indexOf(flag)+1];',
    "if(args[0]!=='exec'||!args.includes('--disable-shell')||!args.includes('--output-schema')||value('--provider')!=='meta')process.exit(2);",
    "const messages=JSON.parse(fs.readFileSync(value('--prompt-file'),'utf8'));",
    'const system=messages[0].content;',
    'let answer;',
    "if(system.includes('Interpret only the extracted')){",
    'const context=JSON.parse(messages[1].content);',
    "answer={files:context.files.map(file=>({id:file.id,role:'app',why:'Observed client file preview',authFlow:'',routes:file.routes.map(route=>({path:route.path,method:route.method,purpose:route.path===process.env.BX_ROUTE?'Reads a local document':'Other client call',parameters:[]}))}))};",
    '}',
    "else if(system.includes('Rank only the supplied')){",
    'const context=JSON.parse(messages[1].content);',
    "fs.appendFileSync(process.env.BX_WEB_LOG,JSON.stringify(context)+'\\n');",
    "const lead=context.candidates.find(item=>item.kind==='xss-reflected'&&item.path===process.env.BX_ROUTE&&item.parameter==='source.file');",
    "answer={priorities:[],strategies:lead?[{family:'path-traversal-hosts',path:lead.path,parameter:lead.parameter,priority:10,why:'Observed local document preview'}]:[]};",
    '}',
    "else if(system.includes('Assess only these independently proved'))answer={notes:[]};",
    "else if(system.includes('mapping an authorized web API'))answer={paths:[],notes:[]};",
    "else if(system.includes('Propose bounded GET access-control'))answer={tasks:[]};",
    'else process.exit(3);',
    "console.log(JSON.stringify({payload:{kind:'run_terminal',terminal:'completed',text:JSON.stringify(answer)}}));",
  ].join('\n') + '\n', {mode: 0o700});
  const env = {PATH: `${bin}${path.delimiter}${process.env.PATH}`, BX_WEB_LOG: webLog,
    BX_ROUTE: route};
  const cli = async (...args) => {
    const done = await execFile(process.execPath,
      [CLI, 'blackbox', ...args, '--project', root, '--json', '--non-interactive'],
      {cwd: root, env, timeout: 90000});
    return {code: done.code, data: JSON.parse(done.stdout)};
  };
  const baseline = await cli(origin, '--accept-local', '--no-model', '--offline');
  assert.ok(!baseline.data.findings.some(item => item.kind === 'path-traversal-hosts'));
  const modeled = await cli(origin, '--accept-local', '--offline');
  const web = JSON.parse(fs.readFileSync(path.join(modeled.data.runDir, 'web-probes.json'), 'utf8'));
  assert.equal(modeled.code, 1, JSON.stringify({findings: modeled.data.findings,
    plan: web.plan.filter(item => item.path === route),
    decisions: web.strategyDecisions.filter(item => item.path === route),
    results: web.results.filter(item => item.lead?.path === route),
    modelError: web.modelError, limitations: modeled.data.limitations}));
  const finding = modeled.data.findings.find(item =>
    item.kind === 'path-traversal-hosts' && item.pattern === route);
  assert.ok(finding, JSON.stringify(modeled.data.findings));
  assert.ok(finding.tags.includes('model-strategy-lead'));
  assert.ok(fs.existsSync(finding.proof));
  assert.ok(web.plan.some(item => item.kind === 'path-traversal-hosts' && item.path === route &&
    item.parameter === 'source.file' && item.basis === 'model-strategy'));
  assert.ok(web.strategyDecisions.some(item => item.family === 'path-traversal-hosts' &&
    item.path === route && item.parameter === 'source.file' && item.accepted));
  const contexts = fs.readFileSync(webLog, 'utf8').trim().split('\n').map(line => JSON.parse(line));
  assert.ok(contexts.some(context => context.candidates.some(item =>
    item.kind === 'xss-reflected' && item.path === route && item.parameter === 'source.file' &&
    item.purpose === 'Reads a local document')));
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
  const fixed = await cli(origin, '--accept-local', '--offline');
  assert.ok(!fixed.data.findings.some(item => item.kind === 'path-traversal-hosts'));
  assert.ok(!requested.includes('/api/delete'));
});
