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

test('CLI runs an observed local form sequence without hand-editing POST scope, then replays and exports it', async t => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'bypass-sequence-cli-'));
  t.after(() => fs.rmSync(root, {recursive: true, force: true}));
  const suffix = randomBytes(4).toString('hex');
  const route = `/api/calculate-${suffix}`;
  const decoy = `/api/decoy-${suffix}`;
  let vulnerable = true;
  const seen = [];
  const server = http.createServer(async (request, response) => {
    const url = new URL(request.url, 'http://fixture');
    seen.push(`${request.method} ${url.pathname}`);
    const json = (status, body) => {
      response.writeHead(status, {'content-type': 'application/json', 'cache-control': 'no-store'});
      response.end(JSON.stringify(body));
    };
    if (url.pathname === '/') return json(200, {app: 'calculator'});
    if (url.pathname === '/openapi.json') return json(200, {openapi: '3.0.0', paths: {
      [route]: {post: {summary: 'Calculate a supplied expression', requestBody: {content: {
        'application/x-www-form-urlencoded': {schema: {type: 'object',
          required: ['expression'], properties: {expression: {type: 'string'}}}}}}}},
      [decoy]: {post: {requestBody: {content: {
        'application/x-www-form-urlencoded': {schema: {type: 'object',
          properties: {expression: {type: 'string'}}}}}}}},
    }});
    if (request.method === 'POST' && url.pathname === route) {
      const chunks = [];
      for await (const chunk of request) chunks.push(chunk);
      const expression = new URLSearchParams(Buffer.concat(chunks).toString()).get('expression');
      let result = expression;
      if (vulnerable) try {result = Function(`return (${expression})`)();}
      catch {result = 'invalid';}
      return json(200, {result, privateToken: 'fixture-only-private-value'});
    }
    return json(404, {error: 'missing'});
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  t.after(() => new Promise(resolve => server.close(resolve)));
  const origin = `http://127.0.0.1:${server.address().port}`;
  const scopePath = path.join(root, 'blackbox.scope.json');
  fs.writeFileSync(scopePath, JSON.stringify({schemaVersion: 1, target: {origin},
    never: [decoy], limits: {rps: 50}}));
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
    "if(system.startsWith('You are planning bounded, authorized HTTP research.'))answer={flows:[]};",
    "else if(system.startsWith('Choose at most one harmless anonymous sample')){",
    " const operation=context.reviewedMethods.find(item=>item.kind==='form'&&item.path===process.env.BX_ROUTE&&item.fields.includes('expression'));",
    " answer={samples:operation?[{subject:{method:'POST',path:operation.path,placement:'form',key:'expression',fixedFields:[],bodyTemplate:'',headers:[]},value:'2+3',why:'Check the documented calculator input'}]:[]};",
    '}',
    "else if(system.startsWith('Plan at most one bounded HTTP sequence using the reviewed route')){",
    " const operation=context.routes.find(item=>item.kind==='form'&&item.path===process.env.BX_ROUTE&&item.fields.includes('expression'));",
    " const numeric=context.sample?.facts?.jsonPrimitives?.some(item=>item.name==='result'&&item.value===5)&&!JSON.stringify(context.sample).includes('fixture-only-private-value')&&!Object.hasOwn(context.sample.facts,'excerpt')&&!Object.hasOwn(context.sample.facts,'body');",
    " const encode=value=>`String.fromCharCode(${[...value].map(char=>char.charCodeAt(0)).join(',')})`;",
    " answer={flows:operation&&numeric?[{family:'expression-transform',why:'The sampled form route evaluated 2+3 to 5',priority:10,as:'anonymous',prelude:[],subject:{method:'POST',path:operation.path,placement:'form',key:'expression',fixedFields:[],bodyTemplate:'',headers:[]},observe:[],controlValue:'7',firstValue:encode(context.marker),secondValue:encode(context.secondMarker),marker:context.marker,secondMarker:context.secondMarker,assertion:{step:'subject',index:0,location:'body',name:''}}]:[]};",
    '}',
    "else if(system.includes('Select up to five local stored-XSS tests'))answer={checks:[]};",
    "else if(system.includes('Select distinct harmless response-transformation experiments for the reviewed JSON POST routes'))answer={experiments:[]};",
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
  const env = {PATH: `${bin}${path.delimiter}${process.env.PATH}`, BX_ROUTE: route};
  const cli = async (...args) => {
    const completed = await execFile(process.execPath,
      [CLI, 'blackbox', ...args, '--project', root, '--json', '--non-interactive'],
      {cwd: root, env, timeout: 90000});
    return {code: completed.code, data: JSON.parse(completed.stdout)};
  };
  const audit = await cli(origin, '--scope', scopePath, '--rps', '20');
  assert.ok(audit.data.runDir, JSON.stringify(audit));
  const surface = JSON.parse(fs.readFileSync(path.join(audit.data.runDir, 'surface.json'), 'utf8'));
  const localPosts = JSON.parse(fs.readFileSync(path.join(audit.data.runDir, 'local-post-contracts.json'), 'utf8'));
  const web = JSON.parse(fs.readFileSync(path.join(audit.data.runDir, 'web-probes.json'), 'utf8'));
  const finding = audit.data.findings.find(item => item.kind === 'model-http-sequence');
  assert.ok(surface.formBodyOperations.some(item => item.path === route),
    JSON.stringify(surface.formBodyOperations));
  assert.deepEqual(localPosts.admitted.map(item => item.path), [route]);
  assert.ok(web.strategyDecisions.some(item => item.mode === 'http-sequence-sample' && item.accepted),
    JSON.stringify(web.strategyDecisions));
  assert.ok(web.strategyDecisions.some(item => item.mode === 'http-sequence-sample-followup' && item.accepted),
    JSON.stringify(web.strategyDecisions));
  assert.ok(finding?.proof, JSON.stringify({audit: audit.data, web: web.results}));
  assert.equal(audit.data.modelOutput.httpSamples, 1);
  assert.equal(audit.data.modelOutput.httpSequences, 1);
  assert.equal(finding.verdict, 'observed');
  assert.equal(finding.severity, 'unrated');
  assert.match(fs.readFileSync(path.join(audit.data.runDir, 'report.md'), 'utf8'),
    /Research observations \(security impact unverified\)/);
  assert.ok(seen.filter(item => item === `POST ${route}`).length >= 7);
  assert.ok(!seen.includes(`POST ${decoy}`));
  assert.equal((await cli('verify', audit.data.run)).code, 1);
  const exported = await cli('export', audit.data.run, '--out', path.join(root, 'regression'));
  assert.equal(exported.code, 0);
  const runExport = () => new Promise((resolve, reject) => {
    const child = spawn(process.execPath, ['--test', ...exported.data.files],
      {env: Object.fromEntries(Object.entries(process.env).filter(([key]) =>
        key !== 'NODE_TEST_CONTEXT')), stdio: 'ignore'});
    child.once('error', reject);
    child.once('close', resolve);
  });
  assert.equal(await runExport(), 1);
  vulnerable = false;
  assert.equal((await cli('verify', audit.data.run)).code, 0);
  assert.equal(await runExport(), 0);
});
