import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import http from 'node:http';
import path from 'node:path';
import {createHash, randomBytes} from 'node:crypto';
import {DatabaseSync} from 'node:sqlite';
import {spawn} from 'node:child_process';
import {temp} from './helpers.mjs';
import {execFile} from '../src/util.mjs';
import {CLI} from '../src/demo.mjs';
import {loadScope} from '../src/blackbox/scope.mjs';
import {planWebLeads} from '../src/blackbox/web-probes.mjs';

test('SQL strategy proposals stay on observed GET inputs with a valid benign baseline', async t => {
  const root = temp();
  t.after(() => fs.rmSync(root, {recursive: true, force: true}));
  const origin = 'http://127.0.0.1:3000';
  const file = path.join(root, 'scope.json');
  fs.writeFileSync(file, JSON.stringify({schemaVersion: 1, target: {origin}}));
  const scope = loadScope({file, origin}).scope;
  const surface = {patterns: [{pattern: '/api/lookup', methods: ['GET'],
    params: {needle: []}, publicIds: ['alpha'], source: ['public-openapi'],
    fingerprint: {anonymous: {status: 200, type: 'application/json'}}}]};
  const strategy = (route, base, style = 'quoted') => ({family: 'sql-boolean',
    path: route, parameter: 'needle', base, style, priority: 10, why: 'Observed public ID'});
  const infer = async () => ({priorities: [], experiments: [], strategies: [
    strategy('/api/invented', 'alpha'), strategy('/api/lookup', 'alpha/beta'),
    strategy('/api/lookup', 'alpha', 'numeric'), strategy('/api/lookup', 'alpha')]});
  const plan = await planWebLeads(surface, scope, {infer, model: 'fixture',
    budget: 10, maxModelPages: 1});
  assert.deepEqual(plan.strategyDecisions.map(item => [item.accepted, item.reason]),
    [[false, 'unobserved-pair-or-unread-page'], [true, undefined],
      [true, undefined], [true, undefined]]);
  assert.ok(plan.strategyDecisions.slice(1, 3).every(item =>
    item.normalizedTo === 'benign-sql-baseline'));
  assert.ok(plan.leads.some(item => item.kind === 'sql-boolean' &&
    item.lead.path === '/api/lookup' && item.lead.base === 'alpha' &&
    item.lead.basis === 'model-strategy'));
});

test('a Muse SQL plan coalesces with an already queued observed check', async () => {
  const {scope} = loadScope({origin: 'http://127.0.0.1:4329',
    overrides: {acceptLocal: true}});
  const route = `/api/${randomBytes(4).toString('hex')}/items`;
  const surface = {patterns: [{pattern: route, methods: ['GET'],
    params: {q: ['test']}, source: ['public-openapi'],
    fingerprint: {anonymous: {status: 200, type: 'application/json'}}}]};
  const baseline = await planWebLeads(surface, scope, {budget: 100});
  const sql = baseline.leads.find(item => item.kind === 'sql-boolean' && item.lead.path === route);
  assert.ok(sql);
  const key = createHash('sha256').update(JSON.stringify([
    sql.kind, sql.lead.path, sql.lead.parameter, sql.lead.as ?? 'anonymous',
    sql.lead.base, sql.lead.style, null, null, null, null,
  ])).digest('hex');
  const plan = await planWebLeads(surface, scope, {budget: 100,
    skipLeadKeys: [key], model: 'fixture', infer: async () => ({priorities: [],
      experiments: [], strategies: [{family: 'SQL Injection Boolean-Based',
        profile: 'sql-boolean', path: route, parameter: 'q', priority: 10,
        why: 'Observed query input may affect a backend search'}]})});
  assert.equal(plan.strategyDecisions[0].accepted, false);
  assert.equal(plan.strategyDecisions[0].coalesced, true);
  assert.equal(plan.strategyDecisions[0].reason, 'duplicate-lead');
  assert.equal(plan.strategyDecisions[0].normalizedTo, 'observed-sql-baseline');
  assert.ok(!plan.leads.some(item => item.kind === 'sql-boolean' && item.lead.path === route));
});

test('a Muse SQL variant preserves the documented search baseline', async () => {
  const {scope} = loadScope({origin: 'http://127.0.0.1:4329',
    overrides: {acceptLocal: true}});
  const route = `/api/${randomBytes(4).toString('hex')}/search`;
  const surface = {patterns: [{pattern: route, methods: ['GET'],
    params: {q: ['test']}, source: ['public-openapi'],
    fingerprint: {anonymous: {status: 200, type: 'application/json'}}}]};
  const plan = await planWebLeads(surface, scope, {budget: 100, model: 'fixture',
    infer: async () => ({priorities: [], experiments: [], strategies: [{
      family: 'sql-boolean', path: route, parameter: 'q', base: '1', style: 'quoted',
      priority: 10, why: 'Try a quoted lookup baseline'}]})});
  const variants = plan.leads.filter(item => item.kind === 'sql-boolean' &&
    item.lead.path === route).map(item => [item.lead.base, item.lead.style,
    item.lead.basis]);
  assert.deepEqual(variants, [['1', 'quoted', 'model-strategy'],
    ['test', 'search-quote-close-or', 'documented-value']]);
});

test('an incompatible numeric style is normalized for a different text baseline', async () => {
  const {scope} = loadScope({origin: 'http://127.0.0.1:4329',
    overrides: {acceptLocal: true}});
  const route = `/api/${randomBytes(4).toString('hex')}/items`;
  const surface = {patterns: [{pattern: route, methods: ['GET'],
    params: {id: ['1']}, source: ['public-openapi'],
    fingerprint: {anonymous: {status: 200, type: 'application/json'}}}]};
  const plan = await planWebLeads(surface, scope, {budget: 100, model: 'fixture',
    infer: async () => ({priorities: [], experiments: [], strategies: [{
      family: 'sql-boolean', path: route, parameter: 'id', base: 'alpha',
      style: 'numeric', priority: 10, why: 'Observed lookup may parse a text ID'}]})});
  assert.equal(plan.strategyDecisions[0].accepted, true);
  assert.equal(plan.strategyDecisions[0].style, 'quoted');
  assert.ok(plan.leads.some(item => item.kind === 'sql-boolean' &&
    item.lead.path === route && item.lead.base === 'alpha' && item.lead.style === 'quoted'));
});

test('a Muse SQL priority without a new baseline keeps an observed executable variant', async () => {
  const {scope} = loadScope({origin: 'http://127.0.0.1:4329',
    overrides: {acceptLocal: true}});
  const route = `/api/${randomBytes(4).toString('hex')}/search`;
  const surface = {patterns: [{pattern: route, methods: ['GET'],
    params: {q: ['apple']}, source: ['public-openapi'],
    fingerprint: {anonymous: {status: 200, type: 'application/json'}}}]};
  const plan = await planWebLeads(surface, scope, {budget: 100, model: 'fixture',
    infer: async () => ({priorities: [], experiments: [], strategies: [{
      family: 'sql-boolean', path: route, parameter: 'q', priority: 10,
      why: 'Prioritize this observed search input'}]})});
  assert.equal(plan.strategyDecisions[0]?.accepted, true);
  assert.equal(plan.strategyDecisions[0]?.normalizedTo, 'observed-sql-baseline');
  assert.ok(plan.leads.some(item => item.kind === 'sql-boolean' &&
    item.lead.path === route && item.lead.base === 'apple' && item.priority === 10));
});

test('Muse uses an anonymous list ID to prove SQL injection on a documented lookup with no example', async t => {
  const root = temp();
  t.after(() => fs.rmSync(root, {recursive: true, force: true}));
  const suffix = randomBytes(5).toString('hex');
  const route = `/api/lookup-${suffix}`;
  const id = `ref-${suffix}`;
  const db = new DatabaseSync(':memory:');
  t.after(() => db.close());
  db.exec('CREATE TABLE records (id TEXT PRIMARY KEY, value TEXT)');
  db.prepare('INSERT INTO records VALUES (?, ?)').run(id, 'public-fixture-record');
  db.prepare('INSERT INTO records VALUES (?, ?)').run('a', 'fallback-fixture-record');
  const requested = [];
  let vulnerable = true;
  const server = http.createServer((request, response) => {
    const url = new URL(request.url, 'http://fixture');
    requested.push(url.pathname);
    let status = 404, body = {error: 'Not found'};
    if (url.pathname === '/') {
      response.writeHead(200, {'content-type': 'text/html'});
      return response.end(`<html><a href="/api/entries">Records</a><a href="${route}">Lookup</a></html>`);
    }
    if (url.pathname === '/openapi.json') {
      status = 200;
      body = {openapi: '3.0.0', paths: {
        '/api/entries': {get: {}},
        [route]: {get: {parameters: [{name: 'needle', in: 'query'}]}},
        '/api/delete': {get: {}}}};
    } else if (url.pathname === '/api/entries') {
      status = 200;
      body = [{id, value: 'public-fixture-record'}];
    } else if (url.pathname === route) {
      const value = url.searchParams.get('needle') ?? '';
      try {
        const record = vulnerable ?
          db.prepare(`SELECT id, value FROM records WHERE id='${value}'`).get() :
          db.prepare('SELECT id, value FROM records WHERE id=?').get(value);
        status = record ? 200 : 404;
        body = record ?? {error: 'Not found'};
      } catch {status = 400; body = {error: 'Invalid lookup'};}
    } else if (url.pathname === '/api/delete') {
      status = 500;
      body = {error: 'Protected decoy'};
    }
    response.writeHead(status, {'content-type': 'application/json', 'cache-control': 'no-store'});
    response.end(JSON.stringify(body));
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
    "if(system.includes('Rank only the supplied')){",
    'const context=JSON.parse(messages[1].content);',
    "fs.appendFileSync(process.env.BX_WEB_LOG,JSON.stringify(context)+'\\n');",
    "const candidate=context.candidates.find(item=>item.kind==='xss-reflected'&&item.path===process.env.BX_ROUTE&&item.parameter==='needle');",
    "const observed=context.publicRecordIds.includes(process.env.BX_ID);",
    "answer={priorities:[],strategies:candidate&&observed?[{family:'sql-boolean',path:candidate.path,parameter:'needle',base:process.env.BX_BAD_SQL_BASE?process.env.BX_ID+'/':process.env.BX_ID,style:process.env.BX_BAD_SQL_BASE?'numeric':'quoted',priority:10,why:'Public list supplies a record ID for the lookup'}]:[],experiments:[]};",
    '}',
    "else if(system.includes('Assess only these independently proved'))answer={notes:[]};",
    "else if(system.includes('mapping an authorized web API'))answer={paths:[],notes:[]};",
    "else if(system.includes('Propose bounded GET access-control'))answer={tasks:[]};",
    "else if(system.includes('Interpret only the extracted')){const context=JSON.parse(messages[1].content);answer={files:context.files.map(file=>({id:file.id,role:'app',why:'Observed public asset',authFlow:'',routes:[]}))};}",
    "else {fs.appendFileSync(process.env.BX_WEB_LOG,JSON.stringify({unknown:system.slice(0,160)})+'\\n');answer={paths:[],notes:[],files:[],tasks:[],priorities:[],strategies:[],experiments:[],checks:[]};}",
    "console.log(JSON.stringify({payload:{kind:'run_terminal',terminal:'completed',text:JSON.stringify(answer)}}));",
  ].join('\n') + '\n', {mode: 0o700});
  const syntax = await execFile(process.execPath, ['--check', muse]);
  assert.equal(syntax.code, 0, syntax.stderr);
  const env = {PATH: `${bin}${path.delimiter}${process.env.PATH}`,
    BX_ROUTE: route, BX_ID: id, BX_WEB_LOG: webLog};
  const cli = async (...args) => {
    const done = await execFile(process.execPath,
      [CLI, 'blackbox', ...args, '--project', root, '--json', '--non-interactive'],
      {cwd: root, env, timeout: 90000});
    return {code: done.code, data: JSON.parse(done.stdout)};
  };
  const baseline = await cli(origin, '--accept-local', '--no-model', '--offline');
  assert.ok(!baseline.data.findings.some(item => item.kind === 'sql-boolean' && item.pattern === route));
  const modeled = await cli(origin, '--accept-local', '--offline');
  const web = JSON.parse(fs.readFileSync(path.join(modeled.data.runDir, 'web-probes.json'), 'utf8'));
  assert.equal(modeled.code, 1, JSON.stringify({findings: modeled.data.findings,
    decisions: web.strategyDecisions.filter(item => item.path === route),
    results: web.results.filter(item => item.lead?.path === route),
    publicRecordIds: fs.existsSync(webLog) ? fs.readFileSync(webLog, 'utf8').trim()
      .split('\n').map(line => {try {return JSON.parse(line).publicRecordIds;} catch {return null;}}) : [],
    surfaceIds: JSON.parse(fs.readFileSync(path.join(modeled.data.runDir, 'surface.json'), 'utf8'))
      .patterns.map(item => [item.pattern, item.publicIds]),
    modelError: web.modelError, limitations: modeled.data.limitations}));
  const finding = modeled.data.findings.find(item => item.kind === 'sql-boolean' && item.pattern === route);
  assert.ok(finding, JSON.stringify(modeled.data.findings));
  assert.ok(finding.tags.includes('model-strategy-lead'));
  assert.ok(fs.existsSync(finding.proof));
  assert.ok(web.strategyDecisions.some(item => item.family === 'sql-boolean' &&
    item.path === route && item.parameter === 'needle' && item.accepted));
  const contexts = fs.readFileSync(webLog, 'utf8').trim().split('\n').map(line => JSON.parse(line));
  assert.ok(contexts.some(context => context.publicRecordIds?.includes(id) &&
    context.candidates.some(item => item.path === route && item.parameter === 'needle')));
  assert.ok(!requested.includes('/api/delete'));
  assert.equal((await cli('verify', modeled.data.run)).code, 1);
  env.BX_BAD_SQL_BASE = '1';
  const normalized = await cli(origin, '--accept-local', '--offline');
  const normalizedWeb = JSON.parse(fs.readFileSync(path.join(normalized.data.runDir,
    'web-probes.json'), 'utf8'));
  assert.equal(normalized.code, 1, JSON.stringify(normalizedWeb.strategyDecisions));
  assert.ok(normalized.data.findings.some(item => item.kind === 'sql-boolean' &&
    item.pattern === route));
  assert.ok(normalizedWeb.strategyDecisions.some(item => item.family === 'sql-boolean' &&
    item.path === route && item.accepted && item.normalizedTo === 'benign-sql-baseline'));
  assert.equal((await cli('verify', normalized.data.run)).code, 1);
  delete env.BX_BAD_SQL_BASE;
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
  assert.ok(!requested.includes('/api/delete'));
});
