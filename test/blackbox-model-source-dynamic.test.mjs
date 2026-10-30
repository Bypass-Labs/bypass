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

test('actual CLI uses Muse source hints to find and replay a dynamic-path redirect', async t => {
  if (process.platform === 'win32') {t.skip('the Muse process fixture uses an executable POSIX script'); return;}
  const root = temp();
  t.after(() => fs.rmSync(root, {recursive: true, force: true}));
  const suffix = randomBytes(4).toString('hex');
  const route = `/api/jump-${suffix}`;
  const source = path.join(root, 'source');
  fs.mkdirSync(source);
  const secret = 'sk_live_abcdefghijklmnopqrstuvwxyz012345';
  fs.writeFileSync(path.join(source, 'routes.php'),
    "$base = '/api';\n" +
    `// token ${secret}\n` +
    `Route::get($base . '/jump-${suffix}', function ($request) { return redirect($request->query('next')); });\n` +
    "Route::post($base . '/delete', function () { return 'ok'; });\n" +
    "Route::post('/api/mutate', function () { return 'ok'; });\n");
  let vulnerable = true;
  const requested = [];
  const server = http.createServer((request, response) => {
    const url = new URL(request.url, 'http://local');
    requested.push(`${request.method} ${url.pathname}`);
    if (request.method === 'GET' && url.pathname === route) {
      const destination = vulnerable ? url.searchParams.get('next') ?? '/safe' : '/safe';
      if (/[\r\n]/.test(destination)) {response.writeHead(400); return response.end('Invalid destination');}
      response.writeHead(302, {location: destination, 'cache-control': 'no-store'});
      return response.end();
    }
    if (url.pathname === '/api/delete' || url.pathname === '/api/mutate') {
      response.writeHead(500); return response.end('Protected decoy');
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
  const sourceLog = path.join(root, 'muse-source.jsonl');
  const stub = [
    '#!' + process.execPath,
    "const fs=require('node:fs');",
    'const args=process.argv.slice(2);',
    'const value=flag=>args[args.indexOf(flag)+1];',
    "if(args[0]!=='exec'||!args.includes('--disable-shell')||!args.includes('--output-schema')||value('--provider')!=='meta')process.exit(2);",
    "const messages=JSON.parse(fs.readFileSync(value('--prompt-file'),'utf8'));",
    'const system=messages[0].content;',
    'let answer;',
    "if(system.includes('Interpret these redacted source route excerpts')){",
    'const context=JSON.parse(messages[1].content);',
    "fs.appendFileSync(process.env.BX_SOURCE_STUB_LOG,JSON.stringify(context)+'\\n');",
    "const excerpts=context.snippets.map(item=>item.excerpt).join('\\n');",
    String.raw`const base=/\$base = '([^']+)'/.exec(excerpts)?.[1];`,
    String.raw`const suffix=/Route::get\(\$base \. '([^']+)'/.exec(excerpts)?.[1];`,
    'if(!base||!suffix)process.exit(4);',
    "answer={notes:[],paths:[base+suffix+'?next=/safe','/api/delete','/api/mutate']};",
    '}',
    "else if(system.includes('mapping an authorized web API'))answer={paths:[],notes:[]};",
    "else if(system.includes('Propose bounded GET access-control'))answer={tasks:[]};",
    "else if(system.includes('Rank only the supplied'))answer={priorities:[]};",
    "else if(system.includes('Assess only these independently proved'))answer={notes:[]};",
    'else process.exit(3);',
    "console.log(JSON.stringify({payload:{kind:'run_terminal',terminal:'completed',text:JSON.stringify(answer)}}));",
  ].join('\n') + '\n';
  fs.writeFileSync(muse, stub, {mode: 0o700});
  const env = {PATH: `${bin}${path.delimiter}${process.env.PATH}`, BX_SOURCE_STUB_LOG: sourceLog};
  const cli = async (...args) => {
    const done = await execFile(process.execPath,
      [CLI, 'blackbox', ...args, '--project', root, '--json', '--non-interactive'],
      {cwd: root, env, timeout: 90000});
    return {code: done.code, data: JSON.parse(done.stdout)};
  };
  const baseline = await cli(origin, '--accept-local', '--no-model', '--source', source);
  assert.ok(!baseline.data.findings.some(item => item.kind === 'open-redirect'));
  const modeled = await cli(origin, '--accept-local', '--source', source);
  const sourceResult = JSON.parse(fs.readFileSync(path.join(modeled.data.runDir, 'source.json'), 'utf8'));
  const surface = JSON.parse(fs.readFileSync(path.join(modeled.data.runDir, 'surface.json'), 'utf8'));
  assert.equal(modeled.code, 1, JSON.stringify({proposals: sourceResult.proposals,
    patterns: surface.patterns.map(item => ({pattern: item.pattern, params: item.params})),
    limitations: modeled.data.limitations}));
  const finding = modeled.data.findings.find(item => item.kind === 'open-redirect' && item.pattern === route);
  assert.ok(finding, JSON.stringify(modeled.data.findings));
  assert.ok(fs.existsSync(finding.proof));
  assert.equal(sourceResult.stats.unresolvedRoutes, 2);
  assert.ok(sourceResult.proposals.includes(`${route}?next=/safe`));
  assert.ok(!sourceResult.proposals.includes('/api/mutate'));
  assert.ok(!sourceResult.endpoints.some(item => item.path === route));
  const contexts = fs.readFileSync(sourceLog, 'utf8').trim().split('\n').map(line => JSON.parse(line));
  assert.ok(contexts.some(context => context.snippets.some(item => item.path === null &&
    item.method === 'GET' && item.excerpt.includes("$base = '/api'"))));
  assert.ok(!JSON.stringify(contexts).includes(secret));
  assert.ok(!requested.some(value => value.endsWith('/api/delete')));
  assert.ok(!requested.some(value => value.endsWith('/api/mutate')));
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
  const fixed = await cli(origin, '--accept-local', '--source', source);
  assert.ok(!fixed.data.findings.some(item => item.kind === 'open-redirect'));
  assert.ok(!requested.some(value => value.endsWith('/api/delete')));
  assert.ok(!requested.some(value => value.endsWith('/api/mutate')));
});
