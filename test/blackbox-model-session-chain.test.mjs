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

test('Muse selects a public owner-session sequence; CLI proves, redacts and replays the fix', async t => {
  const root = temp();
  t.after(() => fs.rmSync(root, {recursive: true, force: true}));
  const tag = randomBytes(4).toString('hex');
  const sourcePath = `/api/public-session-${tag}`;
  const privatePath = `/api/private-account-${tag}`;
  const ownerToken = `owner-${randomBytes(24).toString('hex')}`;
  const otherToken = `other-${randomBytes(24).toString('hex')}`;
  const requested = [];
  const privateBearers = [];
  let vulnerable = true;
  const server = http.createServer((request, response) => {
    const url = new URL(request.url, 'http://fixture');
    requested.push(url.pathname);
    const json = (status, body) => {
      response.writeHead(status, {'content-type': 'application/json', 'cache-control': 'no-store'});
      response.end(JSON.stringify(body));
    };
    if (url.pathname === '/') {
      response.writeHead(200, {'content-type': 'text/html'});
      return response.end('<html><body>Account portal</body></html>');
    }
    if (url.pathname === '/openapi.json') return json(200, {openapi: '3.0.0', paths: {
      '/api/whoami': {get: {}}, [sourcePath]: {get: {}}, [privatePath]: {get: {}},
      '/api/delete': {get: {}}}});
    if (url.pathname === '/api/whoami') return request.headers.authorization === `Bearer ${ownerToken}` ?
      json(200, {id: 'owner'}) : json(401, {error: 'denied'});
    if (url.pathname === sourcePath) return json(200,
      {session: {ownerBearer: vulnerable ? ownerToken : otherToken}});
    if (url.pathname === privatePath) {
      privateBearers.push(request.headers.authorization ?? null);
      return request.headers.authorization === `Bearer ${ownerToken}` ?
        json(200, {id: 'owner', balance: 42}) : json(401, {error: 'denied'});
    }
    return json(url.pathname === '/api/delete' ? 500 : 404, {error: 'missing'});
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
    "if(JSON.stringify(messages).includes(process.env.OWNER_TOKEN))process.exit(4);",
    'const system=messages[0].content;',
    'let answer;',
    "if(system.includes('Identify at most one read-only public-session-token sequence')){",
    'const context=JSON.parse(messages[1].content);',
    "const source=context.publicRoutes.find(item=>item.path===process.env.BX_SOURCE);",
    "const target=context.privateRoutes.find(item=>item.path===process.env.BX_PRIVATE);",
    "answer={chains:source&&target?[{family:'public-session-account-takeover',sourcePath:source.path,tokenPointer:'/session/ownerBearer',privatePath:target.path,why:'Public route exposes the owner test bearer',priority:10}]:[]};",
    '}',
    "else if(system.includes('Interpret only the extracted')){",
    'const context=JSON.parse(messages[1].content);',
    "answer={files:context.files.map(file=>({id:file.id,role:'app',why:'Observed public client',authFlow:'',routes:file.routes.map(route=>({path:route.path,method:route.method,purpose:'Observed route',parameters:[]}))}))};",
    '}',
    "else if(system.includes('Assess only these independently proved'))answer={notes:[]};",
    "else if(system.includes('mapping an authorized web API'))answer={paths:[],notes:[]};",
    "else if(system.includes('Propose bounded GET access-control'))answer={tasks:[]};",
    "else if(system.includes('Rank only the supplied observed read-only web-test candidates'))answer={priorities:[],strategies:[],experiments:[]};",
    'else process.exit(3);',
    "console.log(JSON.stringify({payload:{kind:'run_terminal',terminal:'completed',text:JSON.stringify(answer)}}));",
  ].join('\n') + '\n', {mode: 0o700});
  const env = {PATH: `${bin}${path.delimiter}${process.env.PATH}`, OWNER_TOKEN: ownerToken,
    BX_SOURCE: sourcePath, BX_PRIVATE: privatePath};
  const cli = async (...args) => {
    const completed = await execFile(process.execPath,
      [CLI, 'blackbox', ...args, '--project', root, '--json', '--non-interactive'],
      {cwd: root, env, timeout: 90000});
    return {code: completed.code, data: JSON.parse(completed.stdout)};
  };
  const baseline = await cli(origin, '--no-model', '--rps', '20', '--identity-path', '/api/whoami');
  assert.ok(!baseline.data.findings.some(item => item.kind === 'public-session-token'));
  const modeled = await cli(origin, '--rps', '20', '--identity-path', '/api/whoami');
  const web = JSON.parse(fs.readFileSync(path.join(modeled.data.runDir, 'web-probes.json'), 'utf8'));
  assert.equal(modeled.code, 1, JSON.stringify({error: modeled.data.modelError,
    findings: modeled.data.findings, decisions: web.strategyDecisions}));
  const finding = modeled.data.findings.find(item => item.kind === 'public-session-token');
  assert.ok(finding, JSON.stringify(modeled.data.findings));
  assert.equal(finding.pattern, sourcePath);
  assert.equal(modeled.data.modelOutput.sessionChains, 1);
  assert.ok(web.strategyDecisions.some(item => item.mode === 'session-chain' && item.accepted));
  assert.ok(!requested.includes('/api/delete'));
  const files = dir => fs.readdirSync(dir, {withFileTypes: true}).flatMap(entry => {
    const target = path.join(dir, entry.name);
    return entry.isDirectory() ? files(target) : [target];
  });
  for (const file of files(modeled.data.runDir))
    assert.ok(!fs.readFileSync(file, 'utf8').includes(ownerToken), file);
  assert.equal((await cli('verify', modeled.data.run)).code, 1);
  const exported = await cli('export', modeled.data.run, '--out', path.join(root, 'regressions'));
  assert.equal(exported.code, 0);
  const runExport = () => new Promise((resolve, reject) => {
    const child = spawn(process.execPath, ['--test', ...exported.data.files],
      {env: {...Object.fromEntries(Object.entries(process.env)
        .filter(([key]) => key !== 'NODE_TEST_CONTEXT')), ...env}, stdio: 'ignore'});
    child.once('error', reject);
    child.once('close', resolve);
  });
  assert.equal(await runExport(), 1);
  vulnerable = false;
  assert.equal((await cli('verify', modeled.data.run)).code, 0);
  assert.equal(await runExport(), 0);
  const fixed = await cli(origin, '--rps', '20', '--identity-path', '/api/whoami');
  assert.ok(!fixed.data.findings.some(item => item.kind === 'public-session-token'));
  assert.ok(!privateBearers.includes(`Bearer ${otherToken}`));
});
