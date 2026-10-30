import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import http from 'node:http';
import os from 'node:os';
import path from 'node:path';
import {randomBytes} from 'node:crypto';
import {execFile} from '../src/util.mjs';
import {CLI} from '../src/demo.mjs';
import {researchReportReserveMs, sanitizeJsonCheckpoint} from '../src/blackbox/index.mjs';

test('JSON checkpoint redacts hypothesis metadata without changing a request', () => {
  const secret = 'sk_live_AB12CD34EF56GH78IJ90KL12MN34';
  const lead = {path: '/api/preview', parameter: 'expression', as: 'anonymous',
    oracle: 'marker', controlValue: 'plain', firstValue: 'first',
    secondValue: 'second', marker: 'bx111111111111',
    secondMarker: 'bx222222222222', fixedFields: [], observedFields: ['expression'],
    prelude: [], observePath: '', observeAs: 'anonymous',
    family: 'expression-preview', why: `Reason ${secret}`};
  const payload = {kind: 'json-experiment', cursor: 0, leads: [lead], active: null};
  const metadata = sanitizeJsonCheckpoint(payload);
  assert.equal(metadata.leads.length, 1);
  assert.equal(metadata.leads[0].controlValue, 'plain');
  assert.ok(!JSON.stringify(metadata).includes(secret));
  const changedRequest = sanitizeJsonCheckpoint({...payload,
    leads: [{...lead, firstValue: secret}]});
  assert.equal(changedRequest.leads.length, 0);
  assert.equal(changedRequest.redactedExecutableLeads, 1);
  assert.ok(!JSON.stringify(changedRequest).includes(secret));
  const knownCredential = sanitizeJsonCheckpoint({...payload,
    leads: [{...lead, firstValue: 'private-known-token'}]},
  ['private-known-token']);
  assert.equal(knownCredential.redactedExecutableLeads, 1);
});

test('CLI resumes a Muse JSON POST accepted before its research window ended',
  {timeout: 120000}, async t => {
    if (process.platform === 'win32') return t.skip('Muse fixture uses a POSIX executable');
    const root = fs.mkdtempSync(path.join(os.tmpdir(), 'bypass-json-queued-'));
    t.after(() => fs.rmSync(root, {recursive: true, force: true}));
    const route = `/api/transform-${randomBytes(4).toString('hex')}`;
    const submitted = [];
    let vulnerable = true;
    const server = http.createServer(async (request, response) => {
      const pathname = new URL(request.url, 'http://fixture.invalid').pathname;
      const json = (status, value) => {
        response.writeHead(status, {'content-type': 'application/json',
          'cache-control': 'no-store'});
        response.end(JSON.stringify(value));
      };
      if (pathname === '/') return json(200, {service: 'expression preview'});
      if (pathname === '/openapi.json') return json(200, {openapi: '3.0.0', paths: {
        [route]: {post: {summary: 'Preview an expression', requestBody: {content: {
          'application/json': {schema: {type: 'object',
            properties: {expression: {type: 'string'}}, required: ['expression']}}}}}}}});
      if (pathname === route && request.method === 'POST') {
        const chunks = [];
        for await (const chunk of request) chunks.push(chunk);
        const expression = JSON.parse(Buffer.concat(chunks).toString()).expression;
        submitted.push(expression);
        const codes = /^String\.fromCharCode\((\d+(?:,\d+)*)\)$/.exec(expression)?.[1];
        return json(200, {result: vulnerable && codes ?
          String.fromCharCode(...codes.split(',').map(Number)) : expression});
      }
      return json(404, {error: 'missing'});
    });
    await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
    t.after(() => new Promise(resolve => server.close(resolve)));
    const origin = `http://127.0.0.1:${server.address().port}`;
    const scopeFile = path.join(root, 'blackbox.scope.json');
    fs.writeFileSync(scopeFile, JSON.stringify({schemaVersion: 1, target: {origin},
      include: ['/'], probes: {jsonPostPaths: [route]},
      limits: {rps: 40, maxUrls: 80, minutes: 1, modelCalls: 40, tasks: 100}}));
    const researchCutoffMs = 60_000 - researchReportReserveMs(60_000) + 250;
    const bin = path.join(root, 'bin');
    fs.mkdirSync(bin);
    fs.writeFileSync(path.join(bin, 'muse'), [
      '#!' + process.execPath,
      "const fs=require('node:fs');",
      '(async()=>{',
      'const args=process.argv.slice(2);',
      'const value=flag=>args[args.indexOf(flag)+1];',
      "if(args.includes('--version')){console.log('muse fixture');process.exit(0);}",
      "if(args[0]!=='exec'||!args.includes('--disable-shell')||!args.includes('--output-schema')||value('--provider')!=='meta')process.exit(2);",
      "const messages=JSON.parse(fs.readFileSync(value('--prompt-file'),'utf8'));",
      'const system=messages[0].content;',
      'const context=JSON.parse(messages.at(-1).content);',
      'let answer;',
      "if(system.includes('Allocate the next black-box investigation effort'))answer={priorities:context.tracks.map(row=>({name:row.name,weight:row.name==='json'?100:1,why:'Observed JSON route'}))};",
      "else if(system.includes('Select distinct harmless response-transformation experiments for the reviewed JSON POST routes')){",
      " const operation=context.operations.find(item=>item.path===process.env.BX_ROUTE);",
      ' const planned=fs.existsSync(process.env.BX_PLANNED);',
      " if(!planned){fs.writeFileSync(process.env.BX_PLANNED,'planned');",
      "  const run=fs.readdirSync(process.env.BX_RUNS).find(name=>fs.existsSync(process.env.BX_RUNS+'/'+name+'/run-start.json'));",
      "  const started=JSON.parse(fs.readFileSync(process.env.BX_RUNS+'/'+run+'/run-start.json')).startedAt;",
      `  await new Promise(resolve=>setTimeout(resolve,Math.max(0,Date.parse(started)+${researchCutoffMs}-Date.now())));`,
      ' }',
      " const chars=text=>'String.fromCharCode('+[...text].map(char=>char.charCodeAt(0)).join(',')+')';",
      " answer={experiments:operation&&!planned?[{family:'expression-preview',path:operation.path,field:'expression',as:'anonymous',oracle:'marker',controlValue:'plain',firstValue:chars(context.marker),secondValue:chars(context.secondMarker),marker:context.marker,secondMarker:context.secondMarker,fixedFields:[],prelude:[],observePath:'',observeAs:'anonymous',why:'Observed expression preview',priority:10}]:[]};",
      '}',
      'else {',
      " const schema=JSON.parse(fs.readFileSync(value('--output-schema'),'utf8'));",
      " const blank=s=>s?.type==='object'?Object.fromEntries((s.required??[]).map(key=>[key,blank(s.properties?.[key])])):s?.type==='array'?[]:s?.type==='integer'||s?.type==='number'?0:s?.type==='boolean'?false:s?.enum?.[0]??'';",
      ' answer=blank(schema);',
      '}',
      "console.log(JSON.stringify({payload:{kind:'run_terminal',terminal:'completed',text:JSON.stringify(answer)}}));",
      '})().catch(error=>{console.error(error);process.exit(1)});',
    ].join('\n') + '\n', {mode: 0o700});
    const env = {...process.env, PATH: `${bin}${path.delimiter}${process.env.PATH}`,
      BX_ROUTE: route, BX_PLANNED: path.join(root, 'planned'),
      BX_RUNS: path.join(root, '.bypass/runs')};
    const cli = async (...args) => {
      const done = await execFile(process.execPath,
        [CLI, 'blackbox', ...args, '--project', root, '--json', '--non-interactive'],
        {cwd: root, env, timeout: 90000});
      return {code: done.code, data: JSON.parse(done.stdout), stderr: done.stderr};
    };
    const first = await cli(origin, '--scope', scopeFile, '--offline');
    assert.ok(first.data.runDir, first.stderr);
    assert.equal(submitted.length, 0, 'expired accepted plan must not send a POST');
    const pending = JSON.parse(fs.readFileSync(path.join(first.data.runDir,
      'json-experiment-checkpoint.json'), 'utf8'));
    assert.equal(pending.pass, 'primary');
    assert.equal(pending.cursor, 0);
    assert.equal(pending.leads.length, 1);
    assert.equal(pending.leads[0].path, route);
    assert.equal(pending.leads[0].oracle, 'marker');
    // Another accepted track must remain resumable after this JSON checkpoint
    // is selected. This page belongs to a different pass and is never sent.
    const otherPage = {pass: 'derived-late', derivedLoginPath: '/unavailable-login',
      origin, nextRouteOffset: 0, totalRoutes: 1, routePrefixHash: '',
      priorSequenceResults: [], updatedAt: new Date().toISOString()};
    fs.writeFileSync(path.join(first.data.runDir,
      'http-sequence-page-checkpoint.json'), JSON.stringify({version: 1,
      run: first.data.run, scopeHash: pending.scopeHash, origin,
      pages: [otherPage]}));
    const resumed = await cli('resume', first.data.run);
    assert.ok(resumed.data.runDir, resumed.stderr);
    const web = JSON.parse(fs.readFileSync(path.join(resumed.data.runDir,
      'web-probes.json'), 'utf8'));
    assert.equal(web.results.filter(item => item.kind === 'model-json-differential' &&
      item.lead.path === route && item.verdict === 'confirmed').length, 1);
    assert.ok(submitted.length >= 3);
    const finding = resumed.data.findings.find(item =>
      item.kind === 'model-json-differential' && item.pattern === route);
    assert.ok(finding?.proof, JSON.stringify(resumed.data.findings));
    const proof = await execFile(process.execPath, [finding.proof],
      {cwd: root, env, timeout: 20000});
    assert.equal(JSON.parse(proof.stdout).verdict, 'confirmed');
    const exported = await cli('export', resumed.data.run,
      '--out', path.join(root, 'regression'));
    assert.equal(exported.code, 0, exported.stderr);
    const regression = () => execFile(process.execPath,
      ['--test', ...exported.data.files],
      {cwd: root, env: {...env, NODE_TEST_CONTEXT: undefined}, timeout: 20000});
    assert.equal((await regression()).code, 1);
    vulnerable = false;
    assert.equal(JSON.parse((await execFile(process.execPath, [finding.proof],
      {cwd: root, env, timeout: 20000})).stdout).verdict, 'not_reproduced');
    assert.equal((await regression()).code, 0);
    const complete = JSON.parse(fs.readFileSync(path.join(resumed.data.runDir,
      'json-experiment-checkpoint.json'), 'utf8'));
    assert.equal(complete.cursor, complete.leads.length);
    const carried = JSON.parse(fs.readFileSync(path.join(resumed.data.runDir,
      'http-sequence-page-checkpoint.json'), 'utf8'));
    assert.equal(carried.run, resumed.data.run);
    assert.ok(carried.pages.some(page => page.pass === otherPage.pass &&
      page.derivedLoginPath === otherPage.derivedLoginPath &&
      page.nextRouteOffset === 0));
    const coverage = JSON.parse(fs.readFileSync(path.join(resumed.data.runDir,
      'coverage.json'), 'utf8'));
    assert.ok(coverage.pendingResearchCheckpoints >= 1);
  });
