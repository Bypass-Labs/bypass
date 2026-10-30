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

test('CLI uses an observed query example in a Muse-selected prelude and replays the sequence', async t => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'bypass-query-prelude-'));
  t.after(() => fs.rmSync(root, {recursive: true, force: true}));
  const suffix = randomBytes(4).toString('hex');
  const prepare = `/api/prepare-${suffix}`;
  const transform = `/api/transform-${suffix}`;
  const decoy = `/api/delete-${suffix}`;
  const ordinaryReads = Array.from({length: 50}, (_, index) =>
    `/api/ordinary-${index}-${suffix}`);
  const requested = [];
  let vulnerable = true;
  let armed = false;
  const server = http.createServer((request, response) => {
    const url = new URL(request.url, 'http://fixture');
    requested.push(`${request.method} ${url.pathname}${url.search}`);
    const send = (status, body) => {
      response.writeHead(status, {'content-type': 'application/json', 'cache-control': 'no-store'});
      response.end(JSON.stringify(body));
    };
    if (url.pathname === '/') return send(200, {service: 'expression lab'});
    if (url.pathname === '/openapi.json') return send(200, {openapi: '3.0.0', paths: {
      ...Object.fromEntries(ordinaryReads.map(route => [route,
        {get: {summary: 'Ordinary public read'}}])),
      [prepare]: {get: {summary: 'Select calculation mode', parameters: [
        {name: 'mode', in: 'query', example: 'full', schema: {type: 'string'}}]}},
      [transform]: {get: {summary: 'Transform expression in selected mode', parameters: [
        {name: 'expression', in: 'query', example: 'plain', schema: {type: 'string'}}]}},
      [decoy]: {get: {summary: 'Protected decoy'}}}});
    if (request.method === 'GET' && url.pathname === prepare) {
      armed = url.searchParams.get('mode') === 'full';
      return send(200, {ready: armed});
    }
    if (request.method === 'GET' && url.pathname === transform) {
      const value = url.searchParams.get('expression') ?? '';
      const output = vulnerable && armed && value.startsWith('hex:') ?
        Buffer.from(value.slice(4), 'hex').toString('utf8') : value;
      armed = false;
      return send(200, {result: output});
    }
    if (url.pathname === decoy) return send(403, {error: 'protected'});
    return send(404, {error: 'missing'});
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  t.after(() => new Promise(resolve => server.close(resolve)));
  const origin = `http://127.0.0.1:${server.address().port}`;
  const scopePath = path.join(root, 'blackbox.scope.json');
  fs.writeFileSync(scopePath, JSON.stringify({schemaVersion: 1, target: {origin},
    limits: {rps: 50, maxUrls: 150, minutes: 3, modelCalls: 45, tasks: 20}}));
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
    ' const route=context.routes.find(item=>item.path===process.env.BX_TRANSFORM&&item.kind===\'read\'&&item.fields.includes(\'expression\'));',
    ' const prelude=context.observedReadRoutes.find(item=>item.path===process.env.BX_PREPARE);',
    ' const sample=`${process.env.BX_PREPARE}?mode=full`;',
    ' const encoded=value=>`hex:${Buffer.from(value).toString(\'hex\')}`;',
    " answer={flows:route&&prelude?.queryExamples?.includes(sample)?[{family:'contextual-transform',why:'The observed full mode may alter expression handling',priority:9,as:'anonymous',prelude:[{method:'GET',path:sample,headers:[]}],subject:{method:'GET',path:route.path,placement:'query',key:'expression',fixedFields:[],bodyTemplate:'',headers:[]},observe:[],controlValue:'plain',firstValue:encoded(context.marker),secondValue:encoded(context.secondMarker),marker:context.marker,secondMarker:context.secondMarker,assertion:{step:'subject',index:0,location:'body',name:''}}]:[]};",
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
    BX_PREPARE: prepare, BX_TRANSFORM: transform};
  const cli = async (...args) => {
    const completed = await execFile(process.execPath,
      [CLI, 'blackbox', ...args, '--project', root, '--json', '--non-interactive'],
      {cwd: root, env, timeout: 90000});
    return {code: completed.code, data: JSON.parse(completed.stdout)};
  };
  const audit = await cli(origin, '--scope', scopePath, '--rps', '20');
  const surface = JSON.parse(fs.readFileSync(path.join(audit.data.runDir, 'surface.json'), 'utf8'));
  const web = JSON.parse(fs.readFileSync(path.join(audit.data.runDir, 'web-probes.json'), 'utf8'));
  const finding = audit.data.findings.find(item => item.kind === 'model-http-sequence');
  assert.ok(surface.patterns.some(item => item.pattern === prepare &&
    item.params.mode?.includes('full')));
  assert.ok(surface.patterns.filter(item => ordinaryReads.includes(item.pattern)).length > 48,
    'the discovered read inventory extends beyond the former 48-route window');
  assert.ok(web.strategyDecisions.some(item => item.mode === 'http-sequence' && item.accepted),
    JSON.stringify(web.strategyDecisions));
  assert.equal(finding?.verdict, 'observed');
  assert.equal(finding.severity, 'unrated');
  assert.equal(finding.webProof.prelude[0].path, `${prepare}?mode=full`);
  assert.ok(finding.proof);
  assert.ok(requested.filter(item => item === `GET ${prepare}?mode=full`).length >= 3);
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
