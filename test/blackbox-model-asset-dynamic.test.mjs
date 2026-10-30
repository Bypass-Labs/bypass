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

test('actual CLI proves a Muse-proposed route assembled in a public JavaScript bundle', async t => {
  if (process.platform === 'win32') {t.skip('the Muse process fixture uses an executable POSIX script'); return;}
  const root = temp();
  t.after(() => fs.rmSync(root, {recursive: true, force: true}));
  const suffix = randomBytes(4).toString('hex');
  const route = `/api/jump-${suffix}`;
  const secret = 'sk_live_abcdefghijklmnopqrstuvwxyz012345';
  const decoyCalls = Array.from({length: 12}, (_, index) =>
    `const skip${index}=['/api','skip-${index}'].join('/');fetch(skip${index}+'?next=/safe');`)
    .join(' '.repeat(320));
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
      return response.end(`const secret='${secret}'; ${decoyCalls} ${' '.repeat(320)} const base='/api'; ` +
        `const jump=[base,'jump-${suffix}'].join('/'); fetch(jump+'?next=/safe'); ` +
        "const write=[base,'write-decoy'].join('/'); fetch(write,{method:'POST'});");
    }
    if (url.pathname === route) {
      const destination = vulnerable ? url.searchParams.get('next') ?? '/safe' : '/safe';
      if (/[\r\n]/.test(destination)) {response.writeHead(400); return response.end('Invalid destination');}
      response.writeHead(302, {location: destination, 'cache-control': 'no-store'});
      return response.end();
    }
    if (url.pathname === '/api/write-decoy' || url.pathname === '/api/delete') {
      response.writeHead(500); return response.end('Protected decoy');
    }
    response.writeHead(404); response.end();
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  t.after(() => new Promise(resolve => server.close(resolve)));
  const origin = `http://127.0.0.1:${server.address().port}`;
  const bin = path.join(root, 'bin');
  fs.mkdirSync(bin);
  const muse = path.join(bin, 'muse');
  const assetLog = path.join(root, 'muse-assets.jsonl');
  const stub = [
    '#!' + process.execPath,
    "const fs=require('node:fs');",
    'const args=process.argv.slice(2);',
    'const value=flag=>args[args.indexOf(flag)+1];',
    "if(args[0]!=='exec'||!args.includes('--disable-shell')||!args.includes('--output-schema')||value('--provider')!=='meta')process.exit(2);",
    "const messages=JSON.parse(fs.readFileSync(value('--prompt-file'),'utf8'));",
    'const system=messages[0].content;',
    'let answer;',
    "if(system.includes('Interpret only the extracted, redacted client-asset facts')){",
    'const context=JSON.parse(messages[1].content);',
    "fs.appendFileSync(process.env.BX_ASSET_STUB_LOG,JSON.stringify(context)+'\\n');",
    "answer={files:context.files.map(file=>{",
    "const get=file.hints.find(hint=>hint.method==='GET'&&hint.excerpt.includes('jump-'));",
    "const post=file.hints.find(hint=>hint.method==='POST');",
    "const base=get&&/base=['\"]([^'\"]+)['\"]/.exec(get.excerpt)?.[1];",
    "const segment=get&&/['\"](jump-[a-z0-9]+)['\"]/.exec(get.excerpt)?.[1];",
    "const proposals=get&&base&&segment?[{hintId:get.id,path:base+'/'+segment+'?next=/safe'},",
    "{hintId:get.id,path:base+'/invented?next=/safe'},",
    "{hintId:post?.id??get.id,path:'/api/write-decoy'},",
    "{hintId:get.id,path:'https://off-origin.invalid/api/x'}]:[];",
    "return {id:file.id,role:'app',why:'Indirect client navigation',authFlow:'',routes:[],proposals};",
    '})};',
    '}',
    "else if(system.includes('Rank only the supplied'))answer={priorities:[]};",
    "else if(system.includes('Assess only these independently proved'))answer={notes:[]};",
    'else process.exit(3);',
    "console.log(JSON.stringify({payload:{kind:'run_terminal',terminal:'completed',text:JSON.stringify(answer)}}));",
  ].join('\n') + '\n';
  fs.writeFileSync(muse, stub, {mode: 0o700});
  const env = {PATH: `${bin}${path.delimiter}${process.env.PATH}`, BX_ASSET_STUB_LOG: assetLog};
  const cli = async (...args) => {
    const done = await execFile(process.execPath,
      [CLI, 'blackbox', ...args, '--project', root, '--json', '--non-interactive'],
      {cwd: root, env, timeout: 90000});
    return {code: done.code, data: JSON.parse(done.stdout)};
  };
  const baseline = await cli(origin, '--accept-local', '--no-model');
  assert.ok(!baseline.data.findings.some(item => item.kind === 'open-redirect' && item.pattern === route));
  const modeled = await cli(origin, '--accept-local');
  assert.equal(modeled.code, 1, JSON.stringify({findings: modeled.data.findings,
    limitations: modeled.data.limitations}));
  const finding = modeled.data.findings.find(item => item.kind === 'open-redirect' && item.pattern === route);
  assert.ok(finding, JSON.stringify(modeled.data.findings));
  assert.ok(fs.existsSync(finding.proof));
  const analysis = JSON.parse(fs.readFileSync(path.join(modeled.data.runDir, 'asset-analysis.json'), 'utf8'));
  assert.ok(analysis.proposals.some(item => item.path === route && item.params.includes('next')));
  assert.ok(!analysis.proposals.some(item => item.path === '/api/write-decoy' || item.path === '/api/invented'));
  const contexts = fs.readFileSync(assetLog, 'utf8').trim().split('\n').map(line => JSON.parse(line));
  assert.ok(contexts.some(context => context.files.some(file => file.hints.some(hint =>
    hint.id === 'h13' && hint.method === 'GET' && hint.excerpt.includes(`jump-${suffix}`)))));
  assert.ok(!JSON.stringify(contexts).includes(secret));
  assert.ok(!requested.includes('/api/write-decoy') && !requested.includes('/api/delete'));
  assert.equal((await cli('verify', modeled.data.run)).code, 1);
  const exported = await cli('export', modeled.data.run, '--out', path.join(root, 'regressions'));
  assert.equal(exported.code, 0);
  const exportedCode = () => new Promise((resolve, reject) => {
    const child = spawn(process.execPath, ['--test', ...exported.data.files],
      {env: Object.fromEntries(Object.entries(process.env).filter(([key]) => key !== 'NODE_TEST_CONTEXT')),
        stdio: 'ignore'});
    child.once('error', reject);
    child.once('close', resolve);
  });
  assert.equal(await exportedCode(), 1);
  vulnerable = false;
  assert.equal((await cli('verify', modeled.data.run)).code, 0);
  assert.equal(await exportedCode(), 0);
  const fixed = await cli(origin, '--accept-local');
  assert.ok(!fixed.data.findings.some(item => item.kind === 'open-redirect'));
  assert.ok(!requested.includes('/api/write-decoy') && !requested.includes('/api/delete'));
});
