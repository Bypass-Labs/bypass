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

test('CLI binds a freshly observed JSON value into a later request and replays it', async t => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'bypass-sequence-binding-'));
  t.after(() => fs.rmSync(root, {recursive: true, force: true}));
  const suffix = randomBytes(4).toString('hex');
  const prepare = `/api/context-${suffix}`;
  const transform = `/api/preview-${suffix}`;
  const setupReads = Array.from({length: 4}, (_, index) =>
    `/api/setup-${index}-${suffix}`);
  const observeReads = Array.from({length: 3}, (_, index) =>
    `/api/observe-${index}-${suffix}`);
  const decoy = `/api/delete-${suffix}`;
  const requested = [];
  const workspaces = new Set();
  let vulnerable = true;
  const server = http.createServer((request, response) => {
    const url = new URL(request.url, 'http://fixture');
    requested.push(`${request.method} ${url.pathname}${url.search}`);
    const send = (status, body) => {
      response.writeHead(status, {'content-type': 'application/json',
        'cache-control': 'no-store'});
      response.end(JSON.stringify(body));
    };
    if (url.pathname === '/') return send(200, {service: 'preview workspace'});
    if (url.pathname === '/openapi.json') return send(200, {openapi: '3.0.0', paths: {
      ...Object.fromEntries([...setupReads, ...observeReads].map(route =>
        [route, {get: {summary: 'Read-only workflow step'}}])),
      [prepare]: {get: {summary: 'Create a short preview context'}},
      [transform]: {get: {summary: 'Preview expression within a workspace',
        parameters: [{name: 'workspace', in: 'query', schema: {type: 'string'}},
          {name: 'expression', in: 'query', schema: {type: 'string'}, example: 'plain'}]}}}});
    if (request.method === 'GET' && url.pathname === prepare) {
      const id = `w-${randomBytes(4).toString('hex')}`;
      workspaces.add(id);
      return send(200, {workspace: {id}});
    }
    if (request.method === 'GET' && setupReads.includes(url.pathname))
      return send(200, {ready: true});
    if (request.method === 'GET' && observeReads.includes(url.pathname))
      return send(200, {observed: true});
    if (request.method === 'GET' && url.pathname === transform) {
      const id = url.searchParams.get('workspace');
      const expression = url.searchParams.get('expression') ?? '';
      const active = workspaces.delete(id);
      const result = vulnerable && active && expression.startsWith('hex:') ?
        Buffer.from(expression.slice(4), 'hex').toString('utf8') : expression;
      return send(200, {result});
    }
    if (url.pathname === decoy) return send(200, {deleted: true});
    return send(404, {error: 'missing'});
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  t.after(() => new Promise(resolve => server.close(resolve)));
  const origin = `http://127.0.0.1:${server.address().port}`;
  const scopePath = path.join(root, 'blackbox.scope.json');
  fs.writeFileSync(scopePath, JSON.stringify({schemaVersion: 1, target: {origin},
    never: [decoy], limits: {rps: 50, maxUrls: 40, minutes: 3,
      modelCalls: 30, tasks: 20}}));
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
    ' const subject=context.routes.find(item=>item.path===process.env.BX_TRANSFORM&&item.kind===\'read\'&&item.fields.includes(\'workspace\')&&item.fields.includes(\'expression\'));',
    ' const source=context.observedReadRoutes.find(item=>item.path===process.env.BX_PREPARE);',
    ' const setups=JSON.parse(process.env.BX_SETUP_READS);',
    ' const observations=JSON.parse(process.env.BX_OBSERVE_READS);',
    ' const observed=path=>context.observedReadRoutes.some(item=>item.path===path);',
    " const step=path=>({method:'GET',path,headers:[]});",
    ' const encoded=value=>`hex:${Buffer.from(value).toString(\'hex\')}`;',
    " answer={flows:subject&&source?.responseShapes?.anonymous?.workspace?.id==='string'&&[...setups,...observations].every(observed)?[{family:'contextual-preview-transform',why:'A fresh workspace context may affect the preview result',priority:9,as:'anonymous',prelude:[...setups.slice(0,2).map(step),step(source.path),...setups.slice(2).map(step)],subject:{method:'GET',path:subject.path,placement:'query',key:'expression',fixedFields:[],bodyTemplate:'',headers:[]},observe:observations.map(step),binding:{from:2,pointer:'/workspace/id',to:'subject',index:0,key:'workspace'},controlValue:'plain',firstValue:encoded(context.marker),secondValue:encoded(context.secondMarker),marker:context.marker,secondMarker:context.secondMarker,assertion:{step:'subject',index:0,location:'body',name:''}}]:[]};",
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
    BX_PREPARE: prepare, BX_TRANSFORM: transform,
    BX_SETUP_READS: JSON.stringify(setupReads),
    BX_OBSERVE_READS: JSON.stringify(observeReads)};
  const cli = async (...args) => {
    const completed = await execFile(process.execPath,
      [CLI, 'blackbox', ...args, '--project', root, '--json', '--non-interactive'],
      {cwd: root, env, timeout: 90000});
    return {code: completed.code, data: JSON.parse(completed.stdout)};
  };
  const audit = await cli(origin, '--scope', scopePath, '--rps', '20');
  const web = JSON.parse(fs.readFileSync(path.join(audit.data.runDir,
    'web-probes.json'), 'utf8'));
  const surface = JSON.parse(fs.readFileSync(path.join(audit.data.runDir,
    'surface.json'), 'utf8'));
  const finding = audit.data.findings.find(item => item.kind === 'model-http-sequence');
  assert.ok(web.strategyDecisions.some(item => item.mode === 'http-sequence' &&
    item.accepted), JSON.stringify({decisions: web.strategyDecisions,
      routes: surface.patterns.map(item => ({path: item.pattern,
        params: item.params, shape: item.fingerprint?.anonymous?.shape})),
      modelCoverage: web.modelCoverage, modelError: audit.data.modelError}));
  const accepted = web.strategyDecisions.find(item => item.mode === 'http-sequence' &&
    item.accepted);
  assert.deepEqual(accepted.requestShape.preludePaths,
    [...setupReads.slice(0, 2), prepare, ...setupReads.slice(2)]);
  assert.deepEqual(accepted.requestShape.observePaths, observeReads);
  assert.equal(finding?.verdict, 'observed');
  assert.equal(finding.severity, 'unrated');
  assert.equal(finding.webProof.prelude.length, 5);
  assert.equal(finding.webProof.observe.length, 3);
  assert.equal(finding.webProof.binding.from, 2);
  assert.equal(finding.webProof.binding.pointer, '/workspace/id');
  assert.equal(finding.webProof.bindingReview.sourceAs, 'anonymous');
  assert.ok(finding.webProof.bindingReview.sourceEvidenceId);
  assert.ok(requested.filter(item => item.startsWith(`GET ${transform}?`) &&
    item.includes('workspace=w-')).length >= 3);
  for (const route of [...setupReads, ...observeReads])
    assert.ok(requested.filter(item => item === `GET ${route}`).length >= 3,
      `the long sequence did not run ${route} in every phase`);
  assert.ok(!requested.some(item => item.startsWith(`GET ${decoy}`)));
  assert.equal((await cli('verify', audit.data.run)).code, 1);
  const exported = await cli('export', audit.data.run, '--out', path.join(root, 'regression'));
  assert.equal(exported.code, 0);
  const regression = () => new Promise((resolve, reject) => {
    const child = spawn(process.execPath, ['--test', ...exported.data.files],
      {env: Object.fromEntries(Object.entries(process.env).filter(([key]) =>
        key !== 'NODE_TEST_CONTEXT')), stdio: 'ignore'});
    child.once('error', reject);
    child.once('close', resolve);
  });
  assert.equal(await regression(), 1);
  vulnerable = false;
  assert.equal((await cli('verify', audit.data.run)).code, 0);
  assert.equal(await regression(), 0);
});
