import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import http from 'node:http';
import os from 'node:os';
import path from 'node:path';
import {randomBytes} from 'node:crypto';
import {spawn} from 'node:child_process';
import {CLI} from '../src/demo.mjs';
import {execFile} from '../src/util.mjs';

test('Muse tests an undocumented GET query key on a scoped route and exports red-green replay',
  {timeout: 120000}, async t => {
    const root = fs.mkdtempSync(path.join(os.tmpdir(), 'bypass-novel-get-'));
    t.after(() => fs.rmSync(root, {recursive: true, force: true}));
    const suffix = randomBytes(5).toString('hex');
    const route = `/api/render-${suffix}`;
    const field = `probe_${randomBytes(4).toString('hex')}`;
    let vulnerable = true;
    const seen = [];
    const server = http.createServer((request, response) => {
      const url = new URL(request.url, 'http://fixture.invalid');
      seen.push(`${request.method} ${url.pathname}${url.search}`);
      const json = (status, body) => {
        response.writeHead(status, {'content-type': 'application/json',
          'cache-control': 'no-store'});
        response.end(JSON.stringify(body));
      };
      if (request.method === 'GET' && url.pathname === '/') {
        response.writeHead(200, {'content-type': 'text/html', 'cache-control': 'no-store'});
        return response.end('<a href="/openapi.json">API</a>');
      }
      if (request.method === 'GET' && url.pathname === '/openapi.json')
        return json(200, {openapi: '3.0.0', paths: {
          [route]: {get: {summary: 'Render a preview response'}}}});
      if (request.method === 'GET' && url.pathname === route) {
        const value = url.searchParams.get(field) ?? '';
        const rendered = vulnerable && /^hex:[0-9a-f]+$/i.test(value) ?
          Buffer.from(value.slice(4), 'hex').toString('utf8') : value;
        response.writeHead(200, {'content-type': 'text/plain',
          'cache-control': 'no-store'});
        return response.end(rendered || 'preview');
      }
      return json(404, {error: 'missing'});
    });
    await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
    t.after(() => new Promise(resolve => server.close(resolve)));
    const origin = `http://127.0.0.1:${server.address().port}`;
    const scopePath = path.join(root, 'blackbox.scope.json');
    fs.writeFileSync(scopePath, JSON.stringify({schemaVersion: 1,
      target: {origin}, include: ['/'],
      limits: {rps: 40, minutes: 2, modelCalls: 25, tasks: 30}}));
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
      'const system=messages[0].content;',
      'const context=JSON.parse(messages[1].content);',
      'let answer;',
      "if(system.startsWith('You are planning bounded, authorized HTTP research.')){",
      " const route=[...(context.routes??[]),...(context.observedReadRoutes??[])].find(item=>item.path===process.env.BX_ROUTE&&item.methods.includes('GET'));",
      " const novel=route&&!route.fields.includes(process.env.BX_FIELD);",
      " const encode=value=>`hex:${Buffer.from(value).toString('hex')}`;",
      " answer={flows:novel?[{family:'undocumented-preview-input',why:'The observed preview route may process an undocumented query key',priority:10,as:'anonymous',oracle:'marker',prelude:[],subject:{method:'GET',path:route.path,placement:'query',key:process.env.BX_FIELD,fixedFields:[],bodyTemplate:'',headers:[]},observe:[],controlValue:'plain',firstValue:encode(context.marker),secondValue:encode(context.secondMarker),marker:context.marker,secondMarker:context.secondMarker,assertion:{step:'subject',index:0,location:'body',name:''}}]:[]};",
      '}',
      "else if(system.includes('Interpret only the extracted'))answer={files:[]};",
      "else if(system.includes('Assess only these independently proved'))answer={notes:[]};",
      "else if(system.includes('Continue mapping this authorized primary application'))answer={paths:[]};",
      "else if(system.includes('mapping an authorized web API'))answer={paths:[],notes:[]};",
      "else if(system.includes('Propose bounded GET access-control'))answer={tasks:[]};",
      "else if(system.includes('Rank only the supplied observed read-only web-test candidates'))answer={priorities:[],strategies:[],experiments:[]};",
      'else {',
      " const schema=JSON.parse(fs.readFileSync(value('--output-schema'),'utf8'));",
      " const blank=s=>s?.type==='object'?Object.fromEntries((s.required??[]).map(key=>[key,blank(s.properties?.[key])])):s?.type==='array'?[]:s?.type==='integer'||s?.type==='number'?0:s?.type==='boolean'?false:s?.enum?.[0]??'';",
      ' answer=blank(schema);',
      '}',
      "console.log(JSON.stringify({payload:{kind:'run_terminal',terminal:'completed',text:JSON.stringify(answer)}}));",
    ].join('\n') + '\n', {mode: 0o700});
    const env = {PATH: `${bin}${path.delimiter}${process.env.PATH}`,
      BX_ROUTE: route, BX_FIELD: field};
    const cli = async (...args) => {
      const completed = await execFile(process.execPath,
        [CLI, 'blackbox', ...args, '--project', root, '--json', '--non-interactive'],
        {cwd: root, env, timeout: 90000});
      return {code: completed.code, data: JSON.parse(completed.stdout)};
    };
    const audit = await cli(origin, '--scope', scopePath, '--offline');
    assert.ok(audit.data.runDir, JSON.stringify(audit));
    const surface = JSON.parse(fs.readFileSync(path.join(audit.data.runDir, 'surface.json')));
    const web = JSON.parse(fs.readFileSync(path.join(audit.data.runDir, 'web-probes.json')));
    const routeRecord = surface.patterns.find(item => item.pattern === route);
    assert.ok(routeRecord, 'recon must observe the route');
    assert.equal(Object.hasOwn(routeRecord.params ?? {}, field), false,
      'the tested query key must be absent from recon');
    assert.ok(web.strategyDecisions.some(item => item.mode === 'http-sequence' &&
      item.accepted && item.queryKeySource === 'muse-hypothesis'),
    JSON.stringify(web.strategyDecisions));
    const finding = audit.data.findings.find(item => item.kind === 'model-http-sequence' &&
      item.pattern === route);
    assert.ok(finding?.proof, JSON.stringify({findings: audit.data.findings,
      decisions: web.strategyDecisions}));
    assert.equal(finding.verdict, 'observed');
    assert.ok(finding.tags.includes('model-proposed-query-key'));
    assert.equal(finding.webProof.queryKeySource, 'muse-hypothesis');
    assert.ok(seen.some(item => item.startsWith(`GET ${route}?${field}=`)));
    const spec = JSON.parse(fs.readFileSync(path.join(audit.data.runDir,
      `poc/${finding.id}/spec.json`)));
    assert.deepEqual(spec.reviewedReadInputs, [{path: route, methods: ['GET'],
      parameters: []}], 'the proof must retain the observed route without inventing a documented field');
    assert.equal((await cli('verify', audit.data.run)).code, 1);
    const exported = await cli('export', audit.data.run,
      '--out', path.join(root, 'regression'));
    assert.equal(exported.code, 0);
    const regression = () => new Promise((resolve, reject) => {
      const child = spawn(process.execPath, ['--test', ...exported.data.files],
        {env: Object.fromEntries(Object.entries(process.env).filter(([name]) =>
          name !== 'NODE_TEST_CONTEXT')), stdio: 'ignore'});
      child.once('error', reject);
      child.once('close', resolve);
    });
    assert.equal(await regression(), 1);
    vulnerable = false;
    assert.equal((await cli('verify', audit.data.run)).code, 0);
    assert.equal(await regression(), 0);
  });
