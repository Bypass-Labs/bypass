import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import http from 'node:http';
import path from 'node:path';
import {spawn} from 'node:child_process';
import {temp} from './helpers.mjs';
import {execFile} from '../src/util.mjs';
import {CLI} from '../src/demo.mjs';

test('actual CLI proves a Muse-interpreted redirect parameter and replays its fix', async t => {
  if (process.platform === 'win32') {t.skip('the Muse process fixture uses an executable POSIX script'); return;}
  const root = temp();
  t.after(() => fs.rmSync(root, {recursive: true, force: true}));
  const route = '/api/continue';
  let vulnerable = true;
  const requested = [];
  const server = http.createServer((request, response) => {
    const url = new URL(request.url, 'http://local');
    requested.push(url.pathname);
    if (url.pathname === '/') {
      response.writeHead(200, {'content-type': 'text/html'});
      return response.end('<html><script src="/app.js"></script></html>');
    }
    if (url.pathname === '/app.js') {
      response.writeHead(200, {'content-type': 'application/javascript'});
      return response.end("export const continueAfter = () => fetch('/api/continue?after.path=/safe');");
    }
    if (url.pathname === '/openapi.json') {
      response.writeHead(200, {'content-type': 'application/json'});
      return response.end(JSON.stringify({openapi: '3.0.0', paths: {
        [route]: {get: {parameters: [{name: 'after.path', in: 'query'}]}},
        '/api/delete': {get: {}}}}));
    }
    if (url.pathname === route) {
      const destination = vulnerable ? url.searchParams.get('after.path') ?? '/safe' : '/safe';
      if (/[\x00-\x1f\x7f]/.test(destination)) {
        response.writeHead(400, {'content-type': 'text/plain'});
        return response.end('Invalid redirect destination');
      }
      response.writeHead(302, {location: destination, 'cache-control': 'no-store'});
      return response.end();
    }
    if (url.pathname === '/api/delete') {
      response.writeHead(500);
      return response.end('Protected decoy');
    }
    response.writeHead(404);
    response.end();
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  t.after(() => new Promise(resolve => server.close(resolve)));
  const origin = `http://127.0.0.1:${server.address().port}`;
  const bin = path.join(root, 'bin');
  fs.mkdirSync(bin);
  const muse = path.join(bin, 'muse');
  const assetLog = path.join(root, 'muse-assets.jsonl');
  const webLog = path.join(root, 'muse-web.jsonl');
  const stub = [
    '#!' + process.execPath,
    "const fs=require('node:fs');",
    "const args=process.argv.slice(2);",
    "const value=flag=>args[args.indexOf(flag)+1];",
    "if(args[0]!=='exec'||!args.includes('--disable-shell')||!args.includes('--output-schema')||value('--provider')!=='meta')process.exit(2);",
    "const messages=JSON.parse(fs.readFileSync(value('--prompt-file'),'utf8'));",
    "const system=messages[0].content;",
    "let answer;",
    "if(system.includes('Interpret only the extracted')){",
    "const context=JSON.parse(messages[1].content);",
    "fs.appendFileSync(process.env.BX_ASSET_STUB_LOG,JSON.stringify(context)+'\\n');",
    "answer={files:context.files.map(file=>({id:file.id,role:'app',why:'Observed navigation call',authFlow:'',routes:file.routes.map(route=>({path:route.path,method:route.method,purpose:route.path===process.env.BX_TARGET_PATH?'Redirects the browser after sign-in':'Other client call',parameters:route.path===process.env.BX_TARGET_PATH&&route.params.includes('after.path')?[{name:'after.path',meaning:'Destination URL for browser navigation'}]:[]}))}))};",
    "}",
    "else if(system.includes('Rank only the supplied')){",
    "const context=JSON.parse(messages[1].content);",
    "fs.appendFileSync(process.env.BX_WEB_STUB_LOG,JSON.stringify(context)+'\\n');",
    "const lead=context.candidates.find(item=>item.kind==='open-redirect'&&item.path===process.env.BX_TARGET_PATH&&item.parameter==='after.path');",
    "answer={priorities:lead?[{kind:lead.kind,path:lead.path,parameter:lead.parameter,priority:10,why:'Observed browser navigation URL'}]:[]};",
    "}",
    "else if(system.includes('Assess only these independently proved'))answer={notes:[]};",
    "else if(system.includes('mapping an authorized web API'))answer={paths:[],notes:[]};",
    "else if(system.includes('Propose bounded GET access-control'))answer={tasks:[]};",
    "else process.exit(3);",
    "console.log(JSON.stringify({payload:{kind:'run_terminal',terminal:'completed',text:JSON.stringify(answer)}}));",
  ].join('\n') + '\n';
  fs.writeFileSync(muse, stub, {mode: 0o700});
  const env = {PATH: `${bin}${path.delimiter}${process.env.PATH}`,
    BX_ASSET_STUB_LOG: assetLog, BX_WEB_STUB_LOG: webLog, BX_TARGET_PATH: route};
  const cli = async (...args) => {
    const done = await execFile(process.execPath,
      [CLI, 'blackbox', ...args, '--project', root, '--json', '--non-interactive'],
      {cwd: root, env, timeout: 90000});
    return {code: done.code, data: JSON.parse(done.stdout)};
  };
  const baseline = await cli(origin, '--accept-local', '--no-model');
  assert.ok(!baseline.data.findings.some(item => item.kind === 'open-redirect' && item.pattern === route));
  const modeled = await cli(origin, '--accept-local');
  assert.equal(modeled.code, 1, JSON.stringify(modeled.data));
  const finding = modeled.data.findings.find(item => item.kind === 'open-redirect' && item.pattern === route);
  assert.ok(finding, JSON.stringify(modeled.data.findings));
  assert.ok(fs.existsSync(finding.proof));
  const assetContexts = fs.readFileSync(assetLog, 'utf8').trim().split('\n').map(line => JSON.parse(line));
  assert.ok(assetContexts.some(context => context.files.some(file => file.routes.some(item =>
    item.path === route && item.params.includes('after.path')))));
  const webContexts = fs.readFileSync(webLog, 'utf8').trim().split('\n').map(line => JSON.parse(line));
  assert.ok(webContexts.some(context => context.candidates.some(item =>
    item.kind === 'open-redirect' && item.path === route && item.parameter === 'after.path' &&
    item.parameterMeaning === 'Destination URL for browser navigation')));
  const web = JSON.parse(fs.readFileSync(path.join(modeled.data.runDir, 'web-probes.json'), 'utf8'));
  assert.ok(web.plan.some(item => item.kind === 'open-redirect' && item.path === route &&
    item.parameter === 'after.path' && item.basis === 'model-parameter-meaning'));
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
  const fixed = await cli(origin, '--accept-local');
  assert.ok(!fixed.data.findings.some(item => item.kind === 'open-redirect' && item.pattern === route));
});
