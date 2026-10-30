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

test('actual CLI follows successive observed responses and proves a hidden list leak on the third probe', async t => {
  if (process.platform === 'win32') {t.skip('the Muse process fixture uses an executable POSIX script'); return;}
  const root = temp();
  t.after(() => fs.rmSync(root, {recursive: true, force: true}));
  const route = `/api/cohort-${randomBytes(3).toString('hex')}/records`;
  const requested = [];
  let vulnerable = true;
  const records = [{id: 'rec-101', ownerId: 'u-1'}, {id: 'rec-202', ownerId: 'u-2'}];
  const server = http.createServer((request, response) => {
    const url = new URL(request.url, 'http://local');
    requested.push(url.pathname);
    const who = request.headers.authorization === 'Bearer owner-token' ? 'u-1' :
      request.headers.authorization === 'Bearer other-token' ? 'u-2' : null;
    let status = 404, body = {error: 'Not found'}, type = 'application/json';
    if (url.pathname === '/') {status = 200; type = 'text/html';
      body = '<html><script src="/app.js"></script></html>';}
    else if (url.pathname === '/app.js') {status = 200; type = 'application/javascript';
      body = `fetch('${route}?scope=team'); fetch('${route}?scope=near'); fetch('${route}?scope=preview'); fetch('${route}?scope=global');`;}
    else if (url.pathname === '/openapi.json') {status = 200;
      body = {openapi: '3.0.0', paths: {'/api/me': {get: {}}, [route]: {get: {
        parameters: [{name: 'scope', in: 'query', example: 'team'}]}}, '/api/delete': {get: {}}}};}
    else if (url.pathname === '/api/me') {status = who ? 200 : 401;
      body = who ? {id: who, role: 'member'} : {error: 'Sign in'};}
    else if (url.pathname === route) {status = who ? 200 : 401;
      body = who ? vulnerable && url.searchParams.get('scope') === 'global' ? records :
        records.filter(item => item.ownerId === who) : {error: 'Sign in'};}
    else if (url.pathname === '/api/delete') {status = 500; body = {error: 'Protected decoy'};}
    response.writeHead(status, {'content-type': type, 'cache-control': 'no-store'});
    response.end(typeof body === 'string' ? body : JSON.stringify(body));
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  t.after(() => new Promise(resolve => server.close(resolve)));
  const origin = `http://127.0.0.1:${server.address().port}`;
  const bin = path.join(root, 'bin');
  fs.mkdirSync(bin);
  const callsFile = path.join(root, 'muse-followup.jsonl');
  const stub = [
    '#!' + process.execPath,
    "const fs=require('node:fs');",
    'const args=process.argv.slice(2);',
    'const value=flag=>args[args.indexOf(flag)+1];',
    "if(args[0]!=='exec'||!args.includes('--disable-shell')||!args.includes('--output-schema')||value('--provider')!=='meta')process.exit(2);",
    "const messages=JSON.parse(fs.readFileSync(value('--prompt-file'),'utf8'));",
    "fs.appendFileSync(process.env.BX_MUSE_FOLLOWUP_LOG,JSON.stringify(messages)+'\\n');",
    'const system=messages[0].content;',
    'let answer;',
    "if(system.includes('Interpret only the extracted, redacted client-asset facts'))answer={files:[]};",
    "else if(system.includes('mapping an authorized web API'))answer={paths:[],notes:[]};",
    "else if(system.includes('Propose bounded GET access-control'))answer={tasks:[]};",
    "else if(system.includes('These access-control reads were inconclusive')){",
    'const context=JSON.parse(messages[1].content);',
    "const next=context.round===1?'near':context.round===2?'preview':'global';",
    "let root=fs.existsSync(process.env.BX_MUSE_FOLLOWUP_STATE)?fs.readFileSync(process.env.BX_MUSE_FOLLOWUP_STATE,'utf8'):'';",
    "const wanted=root?root+(context.round===1?'':'-f'+(context.round-1)):null;",
    "const row=context.leads.find(lead=>lead.pattern===process.env.BX_TEST_ROUTE&&lead.kind==='list-leak'&&(!wanted||lead.taskId===wanted)&&lead.candidates.some(candidate=>candidate.url.includes('scope='+next)));",
    "const candidate=row?.candidates.find(candidate=>candidate.url.includes('scope='+next));",
    "if(row&&!root)fs.writeFileSync(process.env.BX_MUSE_FOLLOWUP_STATE,row.taskId);",
    "answer={choices:row&&candidate?[{taskId:row.taskId,candidateId:'invented',why:'invented'},",
    "{taskId:row.taskId,candidateId:candidate.id,why:'Observed next scope may reveal owner records'}]:[]};",
    '}',
    "else if(system.includes('Rank only the supplied'))answer={priorities:[]};",
    "else if(system.includes('Assess only these independently proved'))answer={notes:[]};",
    'else process.exit(3);',
    "console.log(JSON.stringify({payload:{kind:'run_terminal',terminal:'completed',text:JSON.stringify(answer)}}));",
  ].join('\n') + '\n';
  const muse = path.join(bin, 'muse');
  fs.writeFileSync(muse, stub, {mode: 0o700});
  const env = {PATH: `${bin}${path.delimiter}${process.env.PATH}`,
    BX_MUSE_FOLLOWUP_LOG: callsFile, BX_TEST_ROUTE: route,
    BX_MUSE_FOLLOWUP_STATE: path.join(root, 'followup-root'),
    OWNER_TOKEN: 'owner-token', OTHER_TOKEN: 'other-token'};
  const cli = async (...args) => {
    const done = await execFile(process.execPath,
      [CLI, 'blackbox', ...args, '--project', root, '--json', '--non-interactive'],
      {cwd: root, env, timeout: 90000});
    return {code: done.code, data: JSON.parse(done.stdout)};
  };
  const baseline = await cli(origin, '--accept-local', '--no-model');
  assert.deepEqual(baseline.data.findings, []);
  const modeled = await cli(origin, '--accept-local');
  const debugSurface = JSON.parse(fs.readFileSync(path.join(modeled.data.runDir, 'surface.json'), 'utf8'));
  assert.equal(modeled.code, 1, JSON.stringify({findings: modeled.data.findings,
    followup: debugSurface.accessFollowup,
    params: debugSurface.patterns.find(item => item.pattern === route)?.params,
    limitations: modeled.data.limitations}));
  const finding = modeled.data.findings.find(item => item.kind === 'list-leak' && item.pattern === route);
  assert.ok(finding, JSON.stringify(modeled.data.findings));
  assert.equal(finding.foundBy, 'model');
  assert.ok(fs.existsSync(finding.proof));
  const surface = JSON.parse(fs.readFileSync(path.join(modeled.data.runDir, 'surface.json'), 'utf8'));
  assert.ok(surface.accessFollowup.selected.some(item => item.url.includes('scope=global')));
  assert.deepEqual(surface.accessFollowup.selected.map(item => new URL(item.url, origin).searchParams.get('scope')),
    ['near', 'preview', 'global']);
  assert.deepEqual(surface.accessFollowup.selected.map(item => item.round), [1, 2, 3]);
  assert.ok(surface.accessFollowup.selected.slice(0, 2).every(item =>
    item.resultRule?.startsWith('inconclusive/')));
  assert.equal(surface.accessFollowup.selected[2].resultRule, 'confirmed/list-leak/owner-id');
  assert.ok(surface.accessFollowup.selected.every(item => item.priorEvidence.length > 0 &&
    item.resultEvidence.length > 0));
  assert.equal(surface.accessFollowup.coverage.rounds, 3);
  assert.equal(surface.accessFollowup.coverage.probes, 3);
  assert.ok(surface.accessFollowup.rejected.some(item => item.candidateId === 'invented'));
  assert.ok(surface.accessFollowup.coverage.tasksSent >= 1);
  const report = JSON.parse(fs.readFileSync(path.join(modeled.data.runDir, 'report.json'), 'utf8'));
  assert.ok(report.surface.application.accessFollowup.selected.length >= 1);
  assert.match(fs.readFileSync(modeled.data.reportPath, 'utf8'), /Muse access-control follow-up:/);
  const calls = fs.readFileSync(callsFile, 'utf8').trim().split('\n').map(line => JSON.parse(line));
  const followupCalls = calls.filter(messages => messages[0].content.includes('These access-control reads were inconclusive'));
  assert.ok(followupCalls.length >= 3);
  assert.deepEqual([...new Set(followupCalls.map(messages => JSON.parse(messages[1].content).round))], [1, 2, 3]);
  assert.ok(!JSON.stringify(calls).includes('owner-token') && !JSON.stringify(calls).includes('other-token'));
  assert.ok(!requested.includes('/api/delete'));
  assert.equal((await cli('verify', modeled.data.run)).code, 1);
  const exported = await cli('export', modeled.data.run, '--out', path.join(root, 'regressions'));
  assert.equal(exported.code, 0);
  const childEnv = {...Object.fromEntries(Object.entries(process.env).filter(([key]) => key !== 'NODE_TEST_CONTEXT')),
    OWNER_TOKEN: 'owner-token', OTHER_TOKEN: 'other-token'};
  const exportedCode = () => new Promise((resolve, reject) => {
    const child = spawn(process.execPath, ['--test', ...exported.data.files], {env: childEnv, stdio: 'ignore'});
    child.on('error', reject);
    child.on('close', resolve);
  });
  assert.equal(await exportedCode(), 1);
  vulnerable = false;
  assert.equal((await cli('verify', modeled.data.run)).code, 0);
  assert.equal(await exportedCode(), 0);
  const fixed = await cli(origin, '--accept-local');
  assert.deepEqual(fixed.data.findings, []);
});
