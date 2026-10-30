import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import http from 'node:http';
import path from 'node:path';
import {randomBytes} from 'node:crypto';
import {spawn} from 'node:child_process';
import {temp} from './helpers.mjs';
import {runAudit} from '../src/blackbox/index.mjs';
import {verifyRun} from '../src/blackbox/poc.mjs';
import {execFile} from '../src/util.mjs';
import {CLI} from '../src/demo.mjs';

test('model task adds a documented query path beyond baseline and the proof still decides the finding', async t => {
  const root = temp();
  t.after(() => fs.rmSync(root, {recursive: true, force: true}));
  const server = http.createServer((req, res) => {
    const url = new URL(req.url, 'http://local');
    const who = req.headers.authorization === 'Bearer owner-token' ? 'u-1' :
      req.headers.authorization === 'Bearer other-token' ? 'u-2' : null;
    let status = 404, body = {error: 'Not found'};
    if (url.pathname === '/openapi.json') {status = 200; body = {openapi: '3.0.0', paths: {
      '/api/me': {get: {}}, '/api/items': {get: {}},
      '/api/items/{id}': {get: {parameters: [{name: 'view', in: 'query'}]}}}};}
    else if (url.pathname === '/api/me') {status = who ? 200 : 401; body = who ? {id: who, role: 'member'} : {error: 'Sign in'};}
    else if (url.pathname === '/api/items') {status = who ? 200 : 401;
      body = who ? [{id: who === 'u-1' ? 'itm-101' : 'itm-202', ownerId: who}] : {error: 'Sign in'};}
    else if (['/api/items/itm-101', '/api/items/itm-202'].includes(url.pathname)) {status = who ? 200 : 401;
      const first = url.pathname.endsWith('itm-101');
      body = who ? {id: first ? 'itm-101' : 'itm-202', ownerId: first ? 'u-1' : 'u-2',
        ...(url.searchParams.get('view') === 'private' ? {email: first ? 'owner@example.test' : 'other@example.test'} : {})} :
        {error: 'Sign in'};}
    res.writeHead(status, {'content-type': 'application/json', 'cache-control': 'no-store'});
    res.end(JSON.stringify(body));
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  t.after(() => new Promise(resolve => server.close(resolve)));
  const origin = `http://127.0.0.1:${server.address().port}`;
  const calls = [];
  const fakeInfer = async (_profile, messages) => {
    const prompt = messages[0].content;
    calls.push(prompt);
    if (prompt.includes('mapping an authorized web API')) return {paths: [], notes: []};
    if (prompt.includes('Propose bounded GET access-control')) return {tasks: [{kind: 'param-filter',
      pattern: '/api/items/{id}', request: {method: 'GET', url: '/api/items/itm-101?view=private', as: 'outsider'},
      control: {url: '/api/items/itm-101?view=private', as: 'owner'}, why: 'The view parameter may expose a private field.', priority: 10}]};
    if (prompt.includes('Assess only these independently proved')) return {notes: []};
    throw Error('Unexpected model prompt');
  };
  const options = {url: origin, root, overrides: {acceptLocal: true},
    env: {OWNER_TOKEN: 'owner-token', OTHER_TOKEN: 'other-token'}};
  const baseline = await runAudit({...options, noModel: true});
  assert.ok(!baseline.findings.some(item => item.kind === 'param-filter'));
  const enriched = await runAudit({...options, infer: fakeInfer});
  const modelFinding = enriched.findings.find(item => item.kind === 'param-filter');
  assert.ok(modelFinding, JSON.stringify(enriched.findings));
  assert.equal(modelFinding.foundBy, 'model');
  assert.ok(fs.existsSync(modelFinding.proof));
  assert.ok(calls.length >= 3, 'recon, planning and assessment all invoked the model');
  assert.equal(enriched.stats.modelCalls, calls.length);
});

test('Muse uses a bundle value hint to plan and prove a model-only list exposure', async t => {
  const root = temp();
  t.after(() => fs.rmSync(root, {recursive: true, force: true}));
  let vulnerable = true;
  const requested = [];
  const server = http.createServer((request, response) => {
    const url = new URL(request.url, 'http://local');
    requested.push(url.pathname);
    const who = request.headers.authorization === 'Bearer owner-token' ? 'u-1' :
      request.headers.authorization === 'Bearer other-token' ? 'u-2' : null;
    const records = [{id: 'rec-101', ownerId: 'u-1'}, {id: 'rec-202', ownerId: 'u-2'}];
    let status = 404, body = {error: 'Not found'}, type = 'application/json';
    if (url.pathname === '/') {status = 200; type = 'text/html';
      body = '<html><script src="/app.js"></script></html>';}
    else if (url.pathname === '/app.js') {status = 200; type = 'application/javascript';
      body = "export const load=()=>fetch('/api/records?scope=global',{headers:{Authorization:'Bearer'}});";}
    else if (url.pathname === '/openapi.json') {status = 200;
      body = {openapi: '3.0.0', paths: {'/api/me': {get: {}}, '/api/records': {get: {}},
        '/api/delete': {get: {}}}};}
    else if (url.pathname === '/api/me') {status = who ? 200 : 401;
      body = who ? {id: who, role: 'member'} : {error: 'Sign in'};}
    else if (url.pathname === '/api/records') {status = who ? 200 : 401;
      body = who ? vulnerable && url.searchParams.get('scope') === 'global' ? records :
        records.filter(item => item.ownerId === who) : {error: 'Sign in'};}
    else if (url.pathname === '/api/delete') {status = 500; body = {error: 'Protected decoy'};}
    response.writeHead(status, {'content-type': type, 'cache-control': 'no-store'});
    response.end(typeof body === 'string' ? body : JSON.stringify(body));
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  t.after(() => new Promise(resolve => server.close(resolve)));
  const origin = `http://127.0.0.1:${server.address().port}`;
  const options = {url: origin, root, overrides: {acceptLocal: true},
    env: {OWNER_TOKEN: 'owner-token', OTHER_TOKEN: 'other-token'}};
  const baseline = await runAudit({...options, noModel: true});
  assert.ok(!baseline.findings.some(item => item.kind === 'list-leak'));
  const stages = [];
  const infer = async (_profile, messages) => {
    const system = messages[0].content;
    if (system.includes('Identify at most one read-only public-session-token sequence')) return {chains: []};
    stages.push(system);
    if (system.includes('Interpret only the extracted, redacted client-asset facts')) {
      const context = JSON.parse(messages[1].content);
      assert.ok(context.files.some(file => file.routes.some(route =>
        route.path === '/api/records' && route.examples.scope.includes('global'))));
      return {files: context.files.map(file => ({id: file.id, role: 'app', why: 'Client list call',
        authFlow: 'Authorization header', routes: file.routes.map(route => ({path: route.path,
          method: route.method, purpose: 'Global scope may expand a private record list',
          parameters: route.params.map(name => ({name, meaning: 'Controls list scope'}))}))}))};
    }
    if (system.includes('mapping an authorized web API')) return {paths: [], notes: []};
    if (system.includes('Propose bounded GET access-control')) {
      const context = JSON.parse(messages[1].content);
      assert.ok(context.routeNotes.some(note => note.path === '/api/records' &&
        note.by === 'asset-model'));
      assert.ok(context.assetEndpoints.some(item => item.path === '/api/records' &&
        item.examples.scope.includes('global')));
      return {tasks: [{kind: 'list-leak', pattern: '/api/records',
        request: {method: 'GET', url: '/api/records?scope=global', as: 'outsider'},
        control: {url: '/api/records?scope=global', as: 'owner'},
        why: 'The client exposes a global list scope.', priority: 10}]};
    }
    if (system.includes('Rank only the supplied')) return {priorities: []};
    if (system.includes('Assess only these independently proved')) return {notes: []};
    throw Error(`Unexpected Muse prompt: ${system}`);
  };
  const modeled = await runAudit({...options, infer});
  const leak = modeled.findings.find(item => item.kind === 'list-leak' && item.pattern === '/api/records');
  assert.ok(leak, JSON.stringify({findings: modeled.findings, limitations: modeled.limitations}));
  assert.equal(leak.foundBy, 'model');
  assert.ok(fs.existsSync(leak.proof));
  assert.ok(!requested.includes('/api/delete'));
  assert.ok(stages.some(system => system.includes('Interpret only the extracted')));
  const analysis = JSON.parse(fs.readFileSync(path.join(modeled.runDir, 'asset-analysis.json'), 'utf8'));
  assert.ok(analysis.notes.some(note => note.path === '/api/records' && note.parameters.includes('scope')));
  const report = JSON.parse(fs.readFileSync(path.join(modeled.runDir, 'report.json'), 'utf8'));
  assert.ok(report.surface.external.assetModelAnalysis.coverage.routesSent >= 1);
  assert.equal((await verifyRun(root, modeled.run, {env: options.env})).exitCode, 1);
  vulnerable = false;
  assert.equal((await verifyRun(root, modeled.run, {env: options.env})).exitCode, 0);
  fs.writeFileSync(path.join(root, 'blackbox.scope.json'), JSON.stringify({target: {origin},
    limits: {modelCalls: 3}}));
  const capped = await runAudit({...options, infer});
  assert.equal(capped.exitCode, 3);
  assert.ok(capped.limitations.some(item => /Muse reviewed 0 of 1 mined files/.test(item)));
});

test('Muse recon uses a guarded response to discover and prove a second-step redirect route', async t => {
  const root = temp();
  t.after(() => fs.rmSync(root, {recursive: true, force: true}));
  let vulnerable = true;
  const requested = [];
  const server = http.createServer((request, response) => {
    const url = new URL(request.url, 'http://local');
    requested.push(url.pathname);
    const who = request.headers.authorization === 'Bearer owner-token' ? 'u-1' :
      request.headers.authorization === 'Bearer other-token' ? 'u-2' : null;
    let status = 404, body = {error: 'Not found'}, headers = {'content-type': 'application/json'};
    if (url.pathname === '/openapi.json') {status = 200; body = {openapi: '3.0.0', paths: {
      '/api/me': {get: {}}, '/api/portal': {get: {}}}};}
    else if (url.pathname === '/api/me') {status = who ? 200 : 401;
      body = who ? {id: who, role: 'member'} : {error: 'Sign in'};}
    else if (url.pathname === '/api/portal') {status = 200; body = {service: 'portal'};}
    else if (url.pathname === '/api/portal/meta') {status = 200;
      body = {module: 'redirect', slug: 'proof-42', credentialEcho: who === 'u-1' ? 'owner-token' : null};}
    else if (url.pathname === '/api/portal/proof-42') {
      const destination = vulnerable ? url.searchParams.get('next') ?? '/safe' : '/safe';
      if (/[\r\n]/.test(destination)) {status = 400; body = {error: 'Invalid destination'};}
      else {status = 302; body = ''; headers = {location: destination};}
    } else if (url.pathname === '/api/delete') {status = 500; body = {error: 'Protected decoy'};}
    response.writeHead(status, headers);
    response.end(typeof body === 'string' ? body : JSON.stringify(body));
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  t.after(() => new Promise(resolve => server.close(resolve)));
  const origin = `http://127.0.0.1:${server.address().port}`;
  const env = {OWNER_TOKEN: 'owner-token', OTHER_TOKEN: 'other-token'};
  const options = {url: origin, root, overrides: {acceptLocal: true}, env};
  const baseline = await runAudit({...options, noModel: true});
  assert.deepEqual(baseline.findings, []);
  const modelPrompts = [];
  const infer = async (_profile, messages) => {
    const system = messages[0].content;
    modelPrompts.push(system);
    if (system.includes('Identify at most one read-only public-session-token sequence')) return {chains: []};
    if (system.includes('mapping an authorized web API'))
      return {paths: ['/api/portal/meta'], notes: []};
    if (system.includes('Continue mapping this authorized web API')) {
      const context = JSON.parse(messages[1].content);
      assert.ok(!messages[1].content.includes('owner-token') && !messages[1].content.includes('other-token'));
      if (context.observations.some(item => item.path === '/api/portal/meta' &&
        item.status === 200 && item.excerpt.includes('proof-42')))
        return {paths: ['/api/portal/proof-42?next=/safe', '/api/delete']};
      assert.ok(context.observations.some(item =>
        item.path.startsWith('/api/portal/proof-42?') && item.status === 302 &&
        new URL(item.path, origin).searchParams.get('next') === '/safe'));
      return {paths: []};
    }
    if (system.includes('Propose bounded GET access-control')) return {tasks: []};
    if (system.includes('Allocate the next black-box investigation effort'))
      return {priorities: []};
    if (system.includes('Rank only the supplied')) return {priorities: []};
    if (system.includes('You are planning bounded, authorized HTTP research')) return {flows: []};
    if (system.includes('Assess only these independently proved')) return {notes: []};
    throw Error(`Unexpected Muse prompt: ${system}`);
  };
  const modeled = await runAudit({...options, infer});
  const redirect = modeled.findings.find(item => item.kind === 'open-redirect' &&
    item.pattern === '/api/portal/proof-42');
  assert.ok(redirect, JSON.stringify({findings: modeled.findings, limitations: modeled.limitations}));
  assert.ok(fs.existsSync(redirect.proof));
  assert.ok(modelPrompts.some(item => item.includes('Continue mapping this authorized web API')));
  const surface = JSON.parse(fs.readFileSync(path.join(modeled.runDir, 'surface.json'), 'utf8'));
  assert.equal(surface.modelCoverage.followupPathsAvailable, 2);
  assert.equal(surface.modelCoverage.followupPathsSent, 2);
  assert.equal(surface.modelCoverage.pathProposals, 3);
  assert.equal(surface.modelCoverage.pathAccepted, 2);
  assert.deepEqual(surface.modelCoverage.pathRejectedByReason, {'read-action-review': 1});
  assert.ok(surface.modelFollowup.every(page => !page.accepted.includes('/api/delete')));
  assert.ok(surface.patterns.some(item => item.pattern === '/api/portal/{id}' &&
    item.representative === '/api/portal/proof-42' && Object.hasOwn(item.params, 'next')));
  const report = JSON.parse(fs.readFileSync(path.join(modeled.runDir, 'report.json'), 'utf8'));
  assert.equal(report.surface.application.modelFollowup.length, 2);
  assert.match(fs.readFileSync(modeled.reportPath, 'utf8'), /Muse recon follow-up:/);
  assert.ok(!requested.includes('/api/delete'));
  assert.equal((await verifyRun(root, modeled.run, {env})).exitCode, 1);
  vulnerable = false;
  assert.equal((await verifyRun(root, modeled.run, {env})).exitCode, 0);
  fs.writeFileSync(path.join(root, 'blackbox.scope.json'), JSON.stringify({target: {origin},
    limits: {modelCalls: 3}}));
  const capped = await runAudit({...options, infer});
  assert.equal(capped.exitCode, 3);
  assert.ok(capped.limitations.some(item =>
    /Muse reviewed 0 of 1 guarded reconnaissance GET responses/.test(item)),
  JSON.stringify(capped.limitations));
});

test('Muse can use safe facts from an observed route to prove a hidden redirect through the CLI', async t => {
  if (process.platform === 'win32') {t.skip('the Muse process fixture uses an executable POSIX script'); return;}
  const root = temp();
  t.after(() => fs.rmSync(root, {recursive: true, force: true}));
  let vulnerable = true;
  const requested = [];
  const secret = 'sk_live_abcdefghijklmnopqrstuvwxyz012345';
  const server = http.createServer((request, response) => {
    const url = new URL(request.url, 'http://local');
    requested.push(url.pathname);
    const who = request.headers.authorization === 'Bearer owner-token' ? 'u-1' :
      request.headers.authorization === 'Bearer other-token' ? 'u-2' : null;
    let status = 404, body = {error: 'Not found'}, headers = {'content-type': 'application/json'};
    if (url.pathname === '/openapi.json') {status = 200; body = {openapi: '3.0.0', paths: {
      '/api/me': {get: {}}, '/api/portal': {get: {}}}};}
    else if (url.pathname === '/api/me') {status = who ? 200 : 401;
      body = who ? {id: who, role: 'member'} : {error: 'Sign in'};}
    else if (url.pathname === '/api/portal') {status = 200;
      body = {module: 'redirect', slug: 'proof-42',
        variant: 'abcdefghijklmnopqrstuvwxyz0123456789', apiKey: secret};}
    else if (url.pathname === '/api/portal/proof-42') {
      const destination = vulnerable ? url.searchParams.get('next') ?? '/safe' : '/safe';
      if (/[\r\n]/.test(destination)) {status = 400; body = {error: 'Invalid destination'};}
      else {status = 302; body = ''; headers = {location: destination};}
    } else if (url.pathname === '/api/delete') {status = 500; body = {error: 'Protected decoy'};}
    response.writeHead(status, headers);
    response.end(typeof body === 'string' ? body : JSON.stringify(body));
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  t.after(() => new Promise(resolve => server.close(resolve)));
  const origin = `http://127.0.0.1:${server.address().port}`;
  const env = {OWNER_TOKEN: 'owner-token', OTHER_TOKEN: 'other-token'};
  const options = {url: origin, root, overrides: {acceptLocal: true}, env};
  const baseline = await runAudit({...options, noModel: true});
  assert.ok(!baseline.findings.some(item => item.kind === 'open-redirect'));
  let feedbackSeen = false;
  const infer = async (_profile, messages) => {
    const system = messages[0].content;
    if (system.includes('Identify at most one read-only public-session-token sequence')) return {chains: []};
    if (system.includes('mapping an authorized web API')) return {paths: [], notes: []};
    if (system.includes('Continue mapping this authorized web API')) {
      const context = JSON.parse(messages[1].content);
      const portal = context.observations.find(item => item.path === '/api/portal');
      assert.equal(portal?.source, 'observed-route');
      assert.equal(portal?.excerpt, null);
      assert.deepEqual(portal.hints, [{field: 'module', value: 'redirect'},
        {field: 'slug', value: 'proof-42'}]);
      assert.ok(!messages[1].content.includes(secret));
      feedbackSeen = true;
      return {paths: ['/api/portal/proof-42?next=/safe', '/api/delete']};
    }
    if (system.includes('Propose bounded GET access-control')) return {tasks: []};
    if (system.includes('Rank only the supplied')) return {priorities: []};
    if (system.includes('Assess only these independently proved')) return {notes: []};
    throw Error(`Unexpected Muse prompt: ${system}`);
  };
  const modeled = await runAudit({...options, infer});
  assert.ok(feedbackSeen);
  const redirect = modeled.findings.find(item => item.kind === 'open-redirect' &&
    item.pattern === '/api/portal/proof-42');
  assert.ok(redirect, JSON.stringify({findings: modeled.findings, limitations: modeled.limitations}));
  assert.ok(fs.existsSync(redirect.proof));
  const surface = JSON.parse(fs.readFileSync(path.join(modeled.runDir, 'surface.json'), 'utf8'));
  assert.equal(surface.modelCoverage.baselinePathsAvailable, 1);
  assert.equal(surface.modelCoverage.baselinePathsSent, 1);
  assert.ok(!requested.includes('/api/delete'));
  assert.equal((await verifyRun(root, modeled.run, {env})).exitCode, 1);
  vulnerable = false;
  assert.equal((await verifyRun(root, modeled.run, {env})).exitCode, 0);

  vulnerable = true;
  const bin = path.join(root, 'bin'), logPath = path.join(root, 'muse-observed-calls.jsonl');
  fs.mkdirSync(bin);
  const stub = [
    '#!' + process.execPath,
    "const fs=require('node:fs');",
    'const args=process.argv.slice(2);',
    "const value=flag=>args[args.indexOf(flag)+1];",
    "if(args[0]!=='exec'||value('--provider')!=='meta'||!args.includes('--output-schema')||!args.includes('--disable-shell'))process.exit(2);",
    "if(process.env.BX_MUSE_STUB_FAIL){console.error('muse usage: not logged in: run muse login first');process.exit(1);}",
    "const messages=JSON.parse(fs.readFileSync(value('--prompt-file'),'utf8'));",
    "fs.appendFileSync(process.env.BX_MUSE_STUB_LOG,JSON.stringify(messages)+'\\n');",
    'const system=messages[0].content;',
    'let answer;',
    "if(system.includes('mapping an authorized web API'))answer={paths:[],notes:[]};",
    "else if(system.includes('Identify at most one read-only public-session-token sequence'))answer={chains:[]};",
    "else if(system.includes('Continue mapping this authorized web API'))answer={paths:['/api/portal/proof-42?next=/safe','/api/delete']};",
    "else if(system.includes('Propose bounded GET access-control'))answer={tasks:[]};",
    "else if(system.includes('Allocate the next black-box investigation effort'))answer={priorities:[]};",
    "else if(system.includes('Rank only the supplied'))answer={priorities:[]};",
    "else if(system.includes('You are planning bounded, authorized HTTP research'))answer={flows:[]};",
    "else if(system.includes('Assess only these independently proved'))answer={notes:[]};",
    'else process.exit(3);',
    "console.log(JSON.stringify({payload:{kind:'run_terminal',terminal:'completed',text:JSON.stringify(answer)}}));",
  ].join('\n') + '\n';
  fs.writeFileSync(path.join(bin, 'muse'), stub, {mode: 0o700});
  const cliEnv = {PATH: `${bin}${path.delimiter}${process.env.PATH}`,
    BX_MUSE_STUB_LOG: logPath, ...env};
  const cli = async (...args) => {
    const done = await execFile(process.execPath,
      [CLI, 'blackbox', ...args, '--project', root, '--json', '--non-interactive'],
      {cwd: root, env: cliEnv, timeout: 90000});
    return {code: done.code, data: JSON.parse(done.stdout)};
  };
  const codeOnlyCli = await cli(origin, '--accept-local', '--no-model');
  assert.ok(!codeOnlyCli.data.findings.some(item => item.kind === 'open-redirect'));
  const failed = await execFile(process.execPath,
    [CLI, 'blackbox', origin, '--accept-local', '--project', root, '--json', '--non-interactive'],
    {cwd: root, env: {...cliEnv, BX_MUSE_STUB_FAIL: '1'}, timeout: 90000});
  const failedData = JSON.parse(failed.stdout);
  assert.equal(failed.code, 3);
  assert.match(failedData.modelError, /authentication failure/);
  assert.equal(failedData.incomplete, true);
  const modeledCli = await cli(origin, '--accept-local');
  assert.equal(modeledCli.code, 1, JSON.stringify(modeledCli.data));
  assert.equal(modeledCli.data.modelError, null);
  const cliFinding = modeledCli.data.findings.find(item => item.kind === 'open-redirect' &&
    item.pattern === '/api/portal/proof-42');
  assert.ok(cliFinding?.proof);
  const calls = fs.readFileSync(logPath, 'utf8');
  assert.ok(calls.includes('observed-route'));
  for (const forbidden of [secret, 'owner-token', 'other-token', 'abcdefghijklmnopqrstuvwxyz0123456789'])
    assert.ok(!calls.includes(forbidden), 'model prompt must omit credential and long opaque values');
  assert.equal((await cli('verify', modeledCli.data.run)).code, 1);
  const exported = await cli('export', modeledCli.data.run, '--out', path.join(root, 'regressions'));
  assert.equal(exported.code, 0);
  assert.ok(exported.data.files.length > 0);
  const exportEnv = {...Object.fromEntries(Object.entries(process.env)
    .filter(([key]) => key !== 'NODE_TEST_CONTEXT')), ...env};
  const runExport = () => new Promise((resolve, reject) => {
    const child = spawn(process.execPath, ['--test', ...exported.data.files], {env: exportEnv});
    let stdout = '', stderr = '';
    child.stdout.on('data', chunk => {stdout += chunk;});
    child.stderr.on('data', chunk => {stderr += chunk;});
    child.on('error', reject);
    child.on('close', code => resolve({code, stdout, stderr}));
  });
  assert.equal((await runExport()).code, 1);
  vulnerable = false;
  assert.equal((await cli('verify', modeledCli.data.run)).code, 0);
  const green = await runExport();
  assert.equal(green.code, 0, green.stdout + green.stderr);
  assert.ok(!requested.includes('/api/delete'));
});

test('anonymous blackbox CLI follows guarded response hints into a hidden route and replays its proof', async t => {
  if (process.platform === 'win32') {t.skip('the Muse process fixture uses an executable POSIX script'); return;}
  const root = temp();
  t.after(() => fs.rmSync(root, {recursive: true, force: true}));
  const slug = `proof-${randomBytes(4).toString('hex')}`;
  const secondHop = `/api/next/${randomBytes(4).toString('hex')}`;
  const secret = `sk_live_${randomBytes(24).toString('hex')}`;
  const requested = [];
  let vulnerable = true;
  const server = http.createServer((request, response) => {
    const url = new URL(request.url, 'http://local');
    requested.push(url.pathname);
    let status = 404, body = {error: 'Not found'}, headers = {'content-type': 'application/json'};
    if (url.pathname === '/openapi.json') {status = 200; body = {openapi: '3.0.0', paths: {
      ...Object.fromEntries(Array.from({length: 29}, (_, index) => [`/api/decoy-${index}`, {get: {}}])),
      '/api/portal': {get: {}}, '/api/delete': {get: {}}}};}
    else if (/^\/api\/decoy-(?:[0-9]|1[0-9]|2[0-8])$/.test(url.pathname)) {status = 200;
      body = {ok: true};}
    else if (url.pathname === '/api/portal') {status = 200;
      body = {module: 'redirect', slug, apiKey: secret,
        variant: 'abcdefghijklmnopqrstuvwxyz0123456789'};}
    else if (url.pathname === `/api/portal/${slug}`) {
      const destination = vulnerable ? url.searchParams.get('next') ?? '/safe' : '/safe';
      if (/[\r\n]/.test(destination)) {status = 400; body = {error: 'Invalid destination'};}
      else {status = 302; body = {path: secondHop}; headers = {location: destination};}
    }
    else if (url.pathname === secondHop) {status = 200; body = {feature: 'second-hop'};}
    else if (url.pathname === '/api/delete') {status = 500; body = {error: 'Protected decoy'};}
    response.writeHead(status, headers);
    response.end(typeof body === 'string' ? body : JSON.stringify(body));
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  t.after(() => new Promise(resolve => server.close(resolve)));
  const origin = `http://127.0.0.1:${server.address().port}`;
  const bin = path.join(root, 'bin'), logPath = path.join(root, 'muse-anonymous-calls.jsonl');
  fs.mkdirSync(bin);
  const stub = [
    '#!' + process.execPath,
    "const fs=require('node:fs');",
    'const args=process.argv.slice(2);',
    "const value=flag=>args[args.indexOf(flag)+1];",
    "if(args[0]!=='exec'||value('--provider')!=='meta'||!args.includes('--output-schema')||!args.includes('--disable-shell'))process.exit(2);",
    "if(process.env.BX_MUSE_STUB_FAIL){console.error('muse usage: not logged in: run muse login first');process.exit(1);}",
    "const messages=JSON.parse(fs.readFileSync(value('--prompt-file'),'utf8'));",
    "fs.appendFileSync(process.env.BX_MUSE_STUB_LOG,JSON.stringify(messages)+'\\n');",
    'const system=messages[0].content;',
    'let answer;',
    "if(system.includes('Continue mapping this authorized primary application')){const context=JSON.parse(messages[1].content);const first=context.observations.some(item=>item.path==='/api/portal');const next=context.observations.find(item=>item.path==='/api/portal/" + slug + "')?.hints.find(item=>item.field==='path')?.value;answer=first?{paths:['/api/portal/" + slug + "?next=/safe','/api/delete']}:next?{paths:[next]}:{paths:[]};}",
    "else if(system.includes('bounded, authorized HTTP research'))answer={flows:[]};",
    "else if(system.includes('Rank only the supplied'))answer={priorities:[]};",
    "else if(system.includes('Assess only these independently proved'))answer={notes:[]};",
    'else process.exit(3);',
    "console.log(JSON.stringify({payload:{kind:'run_terminal',terminal:'completed',text:JSON.stringify(answer)}}));",
  ].join('\n') + '\n';
  fs.writeFileSync(path.join(bin, 'muse'), stub, {mode: 0o700});
  const cliEnv = {PATH: `${bin}${path.delimiter}${process.env.PATH}`,
    BX_MUSE_STUB_LOG: logPath};
  const cli = async (...args) => {
    const done = await execFile(process.execPath,
      [CLI, 'blackbox', ...args, '--project', root, '--json', '--non-interactive'],
      {cwd: root, env: cliEnv, timeout: 90000});
    return {code: done.code, data: JSON.parse(done.stdout)};
  };
  const codeOnly = await cli(origin, '--accept-local', '--no-model');
  assert.ok(!codeOnly.data.findings.some(item => item.kind === 'open-redirect'));
  const failed = await execFile(process.execPath,
    [CLI, 'blackbox', origin, '--accept-local', '--project', root, '--json', '--non-interactive'],
    {cwd: root, env: {...cliEnv, BX_MUSE_STUB_FAIL: '1'}, timeout: 90000});
  const failedData = JSON.parse(failed.stdout);
  assert.equal(failed.code, 3);
  assert.equal(failedData.incomplete, true);
  assert.match(failedData.modelError, /authentication failure/);
  assert.ok(failedData.limitations.some(item => /guarded anonymous GET responses/.test(item)));
  const failedSurface = JSON.parse(fs.readFileSync(path.join(failedData.runDir, 'surface.json'), 'utf8'));
  assert.ok(failedSurface.anonymousResponseFollowup.pagesAvailable >= 5);
  assert.equal(failedSurface.anonymousResponseFollowup.pagesSent, 0);
  const modeled = await cli(origin, '--accept-local');
  assert.equal(modeled.code, 1, JSON.stringify(modeled.data));
  const redirect = modeled.data.findings.find(item => item.kind === 'open-redirect' &&
    item.pattern === `/api/portal/${slug}`);
  assert.ok(redirect?.proof, JSON.stringify(modeled.data.findings));
  assert.ok(redirect.tags.includes('model-route-lead'));
  const surface = JSON.parse(fs.readFileSync(path.join(modeled.data.runDir, 'surface.json'), 'utf8'));
  assert.ok(surface.patterns.some(item => item.pattern === `/api/portal/${slug}` &&
    Object.hasOwn(item.params, 'next')));
  assert.equal(surface.anonymousResponseFollowup.pathsAccepted, 2);
  assert.equal(surface.anonymousResponseFollowup.pathsRejected, 1);
  assert.ok(surface.anonymousResponseFollowup.pagesSent >= 7);
  assert.ok(surface.anonymousResponseFollowup.routesReviewed >= 32);
  assert.ok(surface.patterns.some(item => item.pattern === secondHop));
  const report = JSON.parse(fs.readFileSync(path.join(modeled.data.runDir, 'report.json'), 'utf8'));
  assert.equal(report.surface.application.anonymousResponseFollowup.pathsAccepted, 2);
  assert.match(fs.readFileSync(modeled.data.reportPath, 'utf8'), /Muse anonymous recon follow-up:/);
  const calls = fs.readFileSync(logPath, 'utf8');
  assert.ok(calls.includes('Continue mapping this authorized primary application'));
  assert.ok(calls.includes(slug));
  assert.ok(calls.trim().split('\n').map(line => JSON.parse(line)).some(messages => {
    if (!messages[0].content.includes('Continue mapping this authorized primary application')) return false;
    return JSON.parse(messages[1].content).observations.some(item => item.path === secondHop);
  }), 'the second-hop response must be interpreted by Muse');
  for (const forbidden of [secret, 'abcdefghijklmnopqrstuvwxyz0123456789'])
    assert.ok(!calls.includes(forbidden), 'model prompt must omit secret and opaque values');
  assert.ok(!requested.includes('/api/delete'));
  assert.equal((await cli('verify', modeled.data.run)).code, 1);
  const exported = await cli('export', modeled.data.run, '--out', path.join(root, 'regressions'));
  assert.equal(exported.code, 0);
  const runExport = () => new Promise((resolve, reject) => {
    const child = spawn(process.execPath, ['--test', ...exported.data.files],
      {env: Object.fromEntries(Object.entries(process.env).filter(([key]) => key !== 'NODE_TEST_CONTEXT'))});
    let output = '';
    child.stdout.on('data', chunk => {output += chunk;});
    child.stderr.on('data', chunk => {output += chunk;});
    child.on('error', reject);
    child.on('close', code => resolve({code, output}));
  });
  assert.equal((await runExport()).code, 1);
  vulnerable = false;
  assert.equal((await cli('verify', modeled.data.run)).code, 0);
  const green = await runExport();
  assert.equal(green.code, 0, green.output);
  fs.writeFileSync(path.join(root, 'blackbox.scope.json'), JSON.stringify({target: {origin},
    limits: {modelCalls: 3}}));
  const capped = await cli(origin, '--accept-local');
  assert.equal(capped.code, 3);
  const cappedSurface = JSON.parse(fs.readFileSync(path.join(capped.data.runDir, 'surface.json'), 'utf8'));
  assert.ok(cappedSurface.anonymousResponseFollowup.routesReviewed <
    cappedSurface.anonymousResponseFollowup.routesAvailable);
  assert.ok(cappedSurface.anonymousResponseFollowup.routesAvailable >= 8);
  assert.ok(cappedSurface.anonymousResponseFollowup.pagesSent <= 1);
  assert.ok(capped.data.limitations.some(item => /guarded anonymous GET responses/.test(item)));
});

test('model-guided anonymous recon finds a hidden redirect on an exact secondary application origin', async t => {
  if (process.platform === 'win32') {t.skip('the Muse process fixture uses an executable POSIX script'); return;}
  const root = temp();
  t.after(() => fs.rmSync(root, {recursive: true, force: true}));
  const slug = `proof-${randomBytes(4).toString('hex')}`;
  const origins = [], requested = [];
  let vulnerable = true;
  for (const secondary of [false, true]) {
    const server = http.createServer((request, response) => {
      const url = new URL(request.url, 'http://local');
      requested.push({secondary, path: url.pathname});
      let status = 404, body = {error: 'Not found'}, headers = {'content-type': 'application/json'};
      if (!secondary && url.pathname === '/') {status = 200; body = {service: 'primary'};}
      else if (secondary && url.pathname === '/openapi.json') {status = 200;
        body = {openapi: '3.0.0', paths: {'/api/portal': {get: {}}, '/api/delete': {get: {}}}};}
      else if (secondary && url.pathname === '/api/portal') {status = 200;
        body = {module: 'redirect', slug};}
      else if (secondary && url.pathname === `/api/portal/${slug}`) {
        const destination = vulnerable ? url.searchParams.get('next') ?? '/safe' : '/safe';
        if (/[\r\n]/.test(destination)) {status = 400; body = {error: 'Invalid destination'};}
        else {status = 302; body = ''; headers = {location: destination};}
      } else if (secondary && url.pathname === '/api/delete') {status = 500;
        body = {error: 'Protected decoy'};}
      response.writeHead(status, headers);
      response.end(typeof body === 'string' ? body : JSON.stringify(body));
    });
    await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
    t.after(() => new Promise(resolve => server.close(resolve)));
    origins.push(`http://127.0.0.1:${server.address().port}`);
  }
  fs.writeFileSync(path.join(root, 'blackbox.scope.json'), JSON.stringify({
    target: {origin: origins[0]}, credentialOrigins: origins, include: ['/api'],
    discovery: {sensitivePaths: false}}));
  const bin = path.join(root, 'bin'), logPath = path.join(root, 'muse-secondary-calls.jsonl');
  fs.mkdirSync(bin);
  const stub = [
    '#!' + process.execPath,
    "const fs=require('node:fs');",
    'const args=process.argv.slice(2);',
    "const value=flag=>args[args.indexOf(flag)+1];",
    "if(args[0]!=='exec'||value('--provider')!=='meta'||!args.includes('--output-schema')||!args.includes('--disable-shell'))process.exit(2);",
    "const messages=JSON.parse(fs.readFileSync(value('--prompt-file'),'utf8'));",
    "fs.appendFileSync(process.env.BX_MUSE_STUB_LOG,JSON.stringify(messages)+'\\n');",
    'const system=messages[0].content;',
    'let answer;',
    "if(system.includes('Continue mapping this authorized credential-origin application'))answer={paths:['/api/portal/" + slug + "?next=/safe','/api/delete']};",
    "else if(system.includes('bounded, authorized HTTP research'))answer={flows:[]};",
    "else if(system.includes('Rank only the supplied'))answer={priorities:[]};",
    "else if(system.includes('Assess only these independently proved'))answer={notes:[]};",
    'else process.exit(3);',
    "console.log(JSON.stringify({payload:{kind:'run_terminal',terminal:'completed',text:JSON.stringify(answer)}}));",
  ].join('\n') + '\n';
  fs.writeFileSync(path.join(bin, 'muse'), stub, {mode: 0o700});
  const cliEnv = {PATH: `${bin}${path.delimiter}${process.env.PATH}`, BX_MUSE_STUB_LOG: logPath};
  const cli = async (...args) => {
    const done = await execFile(process.execPath,
      [CLI, 'blackbox', ...args, '--project', root, '--json', '--non-interactive'],
      {cwd: root, env: cliEnv, timeout: 90000});
    return {code: done.code, data: JSON.parse(done.stdout)};
  };
  const codeOnly = await cli(origins[0], '--accept-local', '--no-model');
  assert.ok(!codeOnly.data.findings.some(item => item.kind === 'open-redirect'));
  const modeled = await cli(origins[0], '--accept-local');
  assert.equal(modeled.code, 1, JSON.stringify(modeled.data));
  const finding = modeled.data.findings.find(item => item.kind === 'open-redirect' &&
    item.pattern === `/api/portal/${slug}` && item.url.startsWith(origins[1]));
  assert.ok(finding?.proof, JSON.stringify(modeled.data.findings));
  assert.ok(finding.tags.includes('model-route-lead'));
  const report = JSON.parse(fs.readFileSync(path.join(modeled.data.runDir, 'report.json'), 'utf8'));
  assert.equal(report.surface.application.otherOrigins[0].anonymousResponseFollowup.pathsAccepted, 1);
  assert.equal(report.surface.application.otherOrigins[0].anonymousResponseFollowup.pathsRejected, 1);
  assert.ok(fs.readFileSync(logPath, 'utf8').includes('credential-origin application'));
  assert.ok(!requested.some(item => item.path === '/api/delete'));
  assert.equal((await cli('verify', modeled.data.run)).code, 1);
  const exported = await cli('export', modeled.data.run, '--out', path.join(root, 'regressions'));
  assert.equal(exported.code, 0);
  const runExport = () => new Promise((resolve, reject) => {
    const child = spawn(process.execPath, ['--test', ...exported.data.files],
      {env: Object.fromEntries(Object.entries(process.env).filter(([key]) => key !== 'NODE_TEST_CONTEXT'))});
    let output = '';
    child.stdout.on('data', chunk => {output += chunk;});
    child.stderr.on('data', chunk => {output += chunk;});
    child.on('error', reject);
    child.on('close', code => resolve({code, output}));
  });
  assert.equal((await runExport()).code, 1);
  vulnerable = false;
  assert.equal((await cli('verify', modeled.data.run)).code, 0);
  const green = await runExport();
  assert.equal(green.code, 0, green.output);
});

test('actual blackbox CLI accepts a bounded Muse process task and proves the model-only lead', async t => {
  if (process.platform === 'win32') {t.skip('the Muse process fixture uses an executable POSIX script'); return;}
  const root = temp();
  t.after(() => fs.rmSync(root, {recursive: true, force: true}));
  let vulnerable = true;
  const requested = [];
  const server = http.createServer((req, res) => {
    const url = new URL(req.url, 'http://local');
    requested.push(url.pathname);
    const who = req.headers.authorization === 'Bearer owner-token' ? 'u-1' :
      req.headers.authorization === 'Bearer other-token' ? 'u-2' : null;
    let status = 404, body = {error: 'Not found'};
    if (url.pathname === '/openapi.json') {status = 200; body = {openapi: '3.0.0', paths: {
      '/api/me': {get: {}}, '/api/items': {get: {}},
      '/api/items/{id}': {get: {parameters: [{name: 'view', in: 'query'}]}},
      '/api/delete': {get: {}}}};}
    else if (url.pathname === '/api/me') {status = who ? 200 : 401;
      body = who ? {id: who, role: 'member'} : {error: 'Sign in'};}
    else if (url.pathname === '/api/items') {status = who ? 200 : 401;
      body = who ? [{id: who === 'u-1' ? 'itm-101' : 'itm-202', ownerId: who}] : {error: 'Sign in'};}
    else if (['/api/items/itm-101', '/api/items/itm-202'].includes(url.pathname)) {
      const first = url.pathname.endsWith('itm-101');
      const owner = first ? 'u-1' : 'u-2';
      const privateView = url.searchParams.get('view') === 'private';
      status = !who ? 401 : who === owner || vulnerable && privateView ? 200 : 403;
      body = status === 200 ? {id: first ? 'itm-101' : 'itm-202', ownerId: owner,
        ...(privateView ? {email: first ? 'owner@example.test' : 'other@example.test'} : {})} :
        {error: 'Denied'};
    } else if (url.pathname === '/api/delete') {status = 500; body = {error: 'Protected decoy'};}
    res.writeHead(status, {'content-type': 'application/json', 'cache-control': 'no-store'});
    res.end(JSON.stringify(body));
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  t.after(() => new Promise(resolve => server.close(resolve)));
  const origin = `http://127.0.0.1:${server.address().port}`;
  const bin = path.join(root, 'bin');
  fs.mkdirSync(bin);
  const logPath = path.join(root, 'muse-calls.jsonl');
  const stub = `#!${process.execPath}\n` +
    `const fs=require('node:fs');\n` +
    `const args=process.argv.slice(2);\n` +
    `const value=flag=>args[args.indexOf(flag)+1];\n` +
    `if(args[0]!=='exec'||!args.includes('--disable-shell')||!args.includes('--output-schema')||value('--provider')!=='meta')process.exit(2);\n` +
    `const messages=JSON.parse(fs.readFileSync(value('--prompt-file'),'utf8'));\n` +
    `fs.appendFileSync(process.env.BX_MUSE_STUB_LOG,JSON.stringify({args,messages})+'\\n');\n` +
    `const system=messages[0].content;\n` +
    `let answer;\n` +
    `if(system.includes('mapping an authorized web API'))answer={paths:[],notes:[]};\n` +
    `else if(system.includes('Propose bounded GET access-control'))answer={tasks:[{kind:'param-filter',pattern:'/api/items/{id}',request:{method:'GET',url:'/api/items/itm-101?view=private',as:'outsider'},control:{url:'/api/items/itm-101?view=private',as:'owner'},why:'The view parameter may expose a private field.',priority:10}]};\n` +
    `else if(system.includes('Rank only the supplied'))answer={priorities:[]};\n` +
    `else if(system.includes('bounded, authorized HTTP research'))answer={flows:[]};\n` +
    `else if(system.includes('Assess only these independently proved'))answer={notes:[]};\n` +
    `else process.exit(3);\n` +
    `console.log(JSON.stringify({payload:{kind:'run_terminal',terminal:'completed',text:JSON.stringify(answer)}}));\n`;
  const muse = path.join(bin, 'muse');
  fs.writeFileSync(muse, stub, {mode: 0o700});
  const env = {PATH: `${bin}${path.delimiter}${process.env.PATH}`, BX_MUSE_STUB_LOG: logPath,
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
  assert.equal(modeled.code, 1, JSON.stringify(modeled.data));
  const finding = modeled.data.findings.find(item => item.kind === 'param-filter');
  assert.ok(finding, JSON.stringify(modeled.data.findings));
  assert.equal(finding.foundBy, 'model');
  assert.ok(fs.existsSync(finding.proof));
  assert.equal((await cli('verify', modeled.data.run)).code, 1);
  const exported = await cli('export', modeled.data.run, '--out', path.join(root, 'regressions'));
  assert.equal(exported.code, 0);
  const childEnv = {...Object.fromEntries(Object.entries(process.env).filter(([key]) => key !== 'NODE_TEST_CONTEXT')),
    OWNER_TOKEN: 'owner-token', OTHER_TOKEN: 'other-token'};
  const runExport = () => new Promise((resolve, reject) => {
    const child = spawn(process.execPath, ['--test', ...exported.data.files], {env: childEnv});
    let stdout = '', stderr = '';
    child.stdout.on('data', chunk => {stdout += chunk;});
    child.stderr.on('data', chunk => {stderr += chunk;});
    child.on('error', reject);
    child.on('close', code => resolve({code, stdout, stderr}));
  });
  assert.equal((await runExport()).code, 1);
  vulnerable = false;
  const afterFix = await cli('verify', modeled.data.run);
  assert.equal(afterFix.code, 0, JSON.stringify({findings: modeled.data.findings, verification: afterFix.data}));
  const afterExport = await runExport();
  assert.equal(afterExport.code, 0, JSON.stringify(afterExport));
  const calls = fs.readFileSync(logPath, 'utf8').trim().split('\n').map(line => JSON.parse(line));
  assert.ok(calls.length >= 3, 'Muse process was invoked for recon, planning and assessment');
  assert.ok(!JSON.stringify(calls).includes('owner-token') && !JSON.stringify(calls).includes('other-token'));
  assert.ok(!requested.includes('/api/delete'));
});

test('actual CLI sends mined bundle value facts to Muse and proves the selected list leak', async t => {
  if (process.platform === 'win32') {t.skip('the Muse process fixture uses an executable POSIX script'); return;}
  const root = temp();
  t.after(() => fs.rmSync(root, {recursive: true, force: true}));
  let vulnerable = true;
  const requested = [];
  const server = http.createServer((request, response) => {
    const url = new URL(request.url, 'http://local');
    requested.push(url.pathname);
    const who = request.headers.authorization === 'Bearer owner-token' ? 'u-1' :
      request.headers.authorization === 'Bearer other-token' ? 'u-2' : null;
    const records = [{id: 'rec-101', ownerId: 'u-1'}, {id: 'rec-202', ownerId: 'u-2'}];
    let status = 404, body = {error: 'Not found'}, type = 'application/json';
    if (url.pathname === '/') {status = 200; type = 'text/html';
      body = '<html><script src="/app.js"></script></html>';}
    else if (url.pathname === '/app.js') {status = 200; type = 'application/javascript';
      body = "export const load=()=>fetch('/api/records?scope=global',{headers:{Authorization:'Bearer'}});";}
    else if (url.pathname === '/openapi.json') {status = 200;
      body = {openapi: '3.0.0', paths: {'/api/me': {get: {}}, '/api/records': {get: {}},
        '/api/delete': {get: {}}}};}
    else if (url.pathname === '/api/me') {status = who ? 200 : 401;
      body = who ? {id: who, role: 'member'} : {error: 'Sign in'};}
    else if (url.pathname === '/api/records') {status = who ? 200 : 401;
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
  const logPath = path.join(root, 'muse-bundle-calls.jsonl');
  const stub = [
    '#!' + process.execPath,
    "const fs=require('node:fs');",
    "const args=process.argv.slice(2);",
    "const value=flag=>args[args.indexOf(flag)+1];",
    "if(args[0]!=='exec'||!args.includes('--disable-shell')||!args.includes('--output-schema')||value('--provider')!=='meta')process.exit(2);",
    "const messages=JSON.parse(fs.readFileSync(value('--prompt-file'),'utf8'));",
    "fs.appendFileSync(process.env.BX_MUSE_STUB_LOG,JSON.stringify(messages)+'\\n');",
    "const system=messages[0].content;",
    'let answer;',
    "if(system.includes('Interpret only the extracted, redacted client-asset facts')){",
    'const context=JSON.parse(messages[1].content);',
    "if(!context.files.some(file=>file.routes.some(route=>route.path==='/api/records'&&route.examples.scope.includes('global'))))process.exit(4);",
    "answer={files:context.files.map(file=>({id:file.id,role:'app',why:'Client list call',authFlow:'Authorization header',routes:file.routes.map(route=>({path:route.path,method:route.method,purpose:'Global list scope may expose another account',parameters:route.params.map(name=>({name,meaning:'Controls list scope'}))}))}))};",
    '}',
    "else if(system.includes('mapping an authorized web API'))answer={paths:[],notes:[]};",
    "else if(system.includes('Propose bounded GET access-control')){",
    'const context=JSON.parse(messages[1].content);',
    "if(!context.routeNotes.some(note=>note.path==='/api/records'&&note.by==='asset-model')||!context.assetEndpoints.some(item=>item.path==='/api/records'&&item.examples.scope.includes('global')))process.exit(5);",
    "answer={tasks:[{kind:'list-leak',pattern:'/api/records',request:{method:'GET',url:'/api/records?scope=global',as:'outsider'},control:{url:'/api/records?scope=global',as:'owner'},why:'Client bundle contains global scope',priority:10}]};",
    '}',
    "else if(system.includes('Rank only the supplied'))answer={priorities:[]};",
    "else if(system.includes('bounded, authorized HTTP research'))answer={flows:[]};",
    "else if(system.includes('Assess only these independently proved'))answer={notes:[]};",
    'else process.exit(3);',
    "console.log(JSON.stringify({payload:{kind:'run_terminal',terminal:'completed',text:JSON.stringify(answer)}}));",
  ].join('\n') + '\n';
  fs.writeFileSync(path.join(bin, 'muse'), stub, {mode: 0o700});
  const env = {PATH: `${bin}${path.delimiter}${process.env.PATH}`, BX_MUSE_STUB_LOG: logPath,
    OWNER_TOKEN: 'owner-token', OTHER_TOKEN: 'other-token'};
  const cli = async (...args) => {
    const done = await execFile(process.execPath,
      [CLI, 'blackbox', ...args, '--project', root, '--json', '--non-interactive'],
      {cwd: root, env, timeout: 90000});
    return {code: done.code, data: JSON.parse(done.stdout)};
  };
  const baseline = await cli(origin, '--accept-local', '--no-model');
  assert.ok(!baseline.data.findings.some(item => item.kind === 'list-leak'));
  const modeled = await cli(origin, '--accept-local');
  assert.equal(modeled.code, 1, JSON.stringify(modeled.data));
  const leak = modeled.data.findings.find(item => item.kind === 'list-leak' &&
    item.pattern === '/api/records');
  assert.ok(leak, JSON.stringify(modeled.data.findings));
  assert.equal(leak.foundBy, 'model');
  assert.ok(fs.existsSync(leak.proof));
  assert.ok(!requested.includes('/api/delete'));
  const analysis = JSON.parse(fs.readFileSync(path.join(modeled.data.runDir, 'asset-analysis.json'), 'utf8'));
  assert.ok(analysis.notes.some(note => note.path === '/api/records' && note.parameters.includes('scope')));
  const calls = fs.readFileSync(logPath, 'utf8').trim().split('\n').map(line => JSON.parse(line));
  assert.ok(calls.some(messages => messages[0].content.includes('Interpret only the extracted')));
  assert.ok(!JSON.stringify(calls).includes('owner-token') && !JSON.stringify(calls).includes('other-token'));
  assert.equal((await cli('verify', modeled.data.run)).code, 1);
  vulnerable = false;
  assert.equal((await cli('verify', modeled.data.run)).code, 0);
});

test('actual CLI Muse web planner promotes a late observed redirect lead into proof', async t => {
  if (process.platform === 'win32') {t.skip('the Muse process fixture uses an executable POSIX script'); return;}
  const root = temp();
  t.after(() => fs.rmSync(root, {recursive: true, force: true}));
  const routes = Array.from({length: 25}, (_, index) =>
    '/api/go-' + String(index).padStart(2, '0'));
  const late = routes.at(-1);
  const paths = Object.fromEntries(routes.map(route => [route,
    {get: {parameters: [{name: 'next', in: 'query'}]}}]));
  paths['/api/me'] = {get: {}};
  paths['/api/delete'] = {get: {}};
  let vulnerable = true;
  const requested = [];
  const server = http.createServer((req, res) => {
    const url = new URL(req.url, 'http://local');
    requested.push(url.pathname);
    if (url.pathname === '/') {
      res.writeHead(200, {'content-type': 'text/html'});
      res.end('<html>Generated audit fixture</html>');
    } else if (url.pathname === '/openapi.json') {
      res.writeHead(200, {'content-type': 'application/json'});
      res.end(JSON.stringify({openapi: '3.0.0', paths}));
    } else if (url.pathname === '/api/me') {
      const who = req.headers.authorization === 'Bearer owner-token' ? 'u-1' :
        req.headers.authorization === 'Bearer other-token' ? 'u-2' : null;
      res.writeHead(who ? 200 : 401, {'content-type': 'application/json'});
      res.end(JSON.stringify(who ? {id: who, role: 'member'} : {error: 'Sign in'}));
    } else if (routes.includes(url.pathname)) {
      const next = url.searchParams.get('next');
      const location = vulnerable && url.pathname === late && next ? next : '/safe';
      res.writeHead(302, {location, 'cache-control': 'no-store'});
      res.end();
    } else if (url.pathname === '/api/delete') {
      res.writeHead(500);
      res.end('Protected decoy');
    } else {
      res.writeHead(404);
      res.end();
    }
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  t.after(() => new Promise(resolve => server.close(resolve)));
  const origin = 'http://127.0.0.1:' + server.address().port;
  const bin = path.join(root, 'bin');
  fs.mkdirSync(bin);
  const muse = path.join(bin, 'muse');
  const logPath = path.join(root, 'muse-web-calls.jsonl');
  const reconLogPath = path.join(root, 'muse-recon-calls.jsonl');
  const stub = [
    '#!' + process.execPath,
    "const fs=require('node:fs');",
    "const args=process.argv.slice(2);",
    "const value=flag=>args[args.indexOf(flag)+1];",
    "if(args[0]!=='exec'||!args.includes('--disable-shell')||!args.includes('--output-schema')||value('--provider')!=='meta')process.exit(2);",
    "const messages=JSON.parse(fs.readFileSync(value('--prompt-file'),'utf8'));",
    "const system=messages[0].content;",
    "let answer;",
    "if(system.includes('mapping an authorized web API')){",
    "const context=JSON.parse(messages[1].content);",
    "fs.appendFileSync(process.env.BX_RECON_STUB_LOG,JSON.stringify(context)+'\\n');",
    "answer={paths:[],notes:[]};",
    "}",
    "else if(system.includes('Propose bounded GET access-control'))answer={tasks:[]};",
    "else if(system.includes('Rank only the supplied')){",
    "const context=JSON.parse(messages[1].content);",
    "fs.appendFileSync(process.env.BX_WEB_STUB_LOG,JSON.stringify(context)+'\\n');",
    "const target=context.candidates.find(item=>item.kind==='open-redirect'&&item.path===process.env.BX_TARGET_PATH);",
    "answer={priorities:target?[{kind:target.kind,path:target.path,parameter:target.parameter,priority:10,why:'Observed navigation destination'}]:[]};",
    "}",
    "else if(system.includes('bounded, authorized HTTP research'))answer={flows:[]};",
    "else if(system.includes('Assess only these independently proved'))answer={notes:[]};",
    "else process.exit(3);",
    "console.log(JSON.stringify({payload:{kind:'run_terminal',terminal:'completed',text:JSON.stringify(answer)}}));",
  ].join('\n') + '\n';
  fs.writeFileSync(muse, stub, {mode: 0o700});
  const env = {PATH: bin + path.delimiter + process.env.PATH, BX_WEB_STUB_LOG: logPath,
    BX_RECON_STUB_LOG: reconLogPath, BX_TARGET_PATH: late,
    OWNER_TOKEN: 'owner-token', OTHER_TOKEN: 'other-token'};
  const cli = async (...args) => {
    const done = await execFile(process.execPath,
      [CLI, 'blackbox', ...args, '--project', root, '--json', '--non-interactive'],
      {cwd: root, env, timeout: 90000});
    return {code: done.code, data: JSON.parse(done.stdout)};
  };
  const configured = await cli('scope', origin, '--include', '/api');
  assert.equal(configured.code, 0);
  const scope = JSON.parse(fs.readFileSync(configured.data.file, 'utf8'));
  scope.limits.tasks = 1;
  fs.writeFileSync(configured.data.file, JSON.stringify(scope));
  const baseline = await cli(origin, '--accept-local', '--no-model');
  assert.deepEqual(baseline.data.findings, []);
  const modeled = await cli(origin, '--accept-local');
  assert.equal(modeled.code, 1, JSON.stringify(modeled.data));
  const redirect = modeled.data.findings.find(item => item.kind === 'open-redirect' && item.pattern === late);
  assert.ok(redirect, JSON.stringify(modeled.data.findings));
  assert.ok(fs.existsSync(redirect.proof));
  const web = JSON.parse(fs.readFileSync(path.join(modeled.data.runDir, 'web-probes.json'), 'utf8'));
  assert.ok(web.modelCoverage[0].candidatesAvailable > 70);
  assert.equal(web.modelCoverage[0].candidatesSent, web.modelCoverage[0].candidatesAvailable);
  const surface = JSON.parse(fs.readFileSync(path.join(modeled.data.runDir, 'surface.json'), 'utf8'));
  assert.ok(surface.modelCoverage.pagesAvailable > 1);
  assert.equal(surface.modelCoverage.routesSent, surface.modelCoverage.routesAvailable);
  const reconContexts = fs.readFileSync(reconLogPath, 'utf8').trim().split('\n').map(line => JSON.parse(line));
  assert.ok(reconContexts.some(context => context.routes.some(item => item.path === late)));
  assert.ok(reconContexts.every(context => context.routes.length <= 20));
  const contexts = fs.readFileSync(logPath, 'utf8').trim().split('\n').map(line => JSON.parse(line));
  assert.ok(contexts.length > 1);
  assert.ok(contexts.some(context => context.candidates.some(item =>
    item.kind === 'open-redirect' && item.path === late)));
  assert.ok(contexts.every(context => context.candidates.length <= 40));
  assert.ok(contexts.every(context => Buffer.byteLength(JSON.stringify(context)) <= 20000));
  assert.ok(!requested.includes('/api/delete'));
  assert.equal((await cli('verify', modeled.data.run)).code, 1);
  const exported = await cli('export', modeled.data.run, '--out', path.join(root, 'regressions'));
  assert.equal(exported.code, 0);
  const runExport = () => new Promise((resolve, reject) => {
    const child = spawn(process.execPath, ['--test', ...exported.data.files],
      {env: Object.fromEntries(Object.entries(process.env).filter(([key]) => key !== 'NODE_TEST_CONTEXT')),
        stdio: 'ignore'});
    child.on('error', reject);
    child.on('close', resolve);
  });
  assert.equal(await runExport(), 1);
  vulnerable = false;
  assert.equal((await cli('verify', modeled.data.run)).code, 0);
  assert.equal(await runExport(), 0);
  scope.limits.modelCalls = 3;
  fs.writeFileSync(configured.data.file, JSON.stringify(scope));
  const capped = await cli(origin, '--accept-local');
  assert.equal(capped.code, 3, JSON.stringify(capped.data.limitations));
  assert.ok(capped.data.limitations.some(item =>
    /Muse reviewed \d+ of \d+ observed reconnaissance routes/.test(item)));
  assert.ok(!requested.includes('/api/delete'));
});
