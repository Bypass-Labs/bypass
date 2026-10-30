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

test('CLI binds a fresh JSON ID into an observed item path and replays it', async t => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'bypass-sequence-path-binding-'));
  t.after(() => fs.rmSync(root, {recursive: true, force: true}));
  const suffix = randomBytes(4).toString('hex');
  const prepare = `/api/context-${suffix}`;
  const seed = String(100000 + Math.floor(Math.random() * 800000));
  const itemPath = `/api/item/${seed}`;
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
    if (url.pathname === '/') {
      response.writeHead(200, {'content-type': 'text/html', 'cache-control': 'no-store'});
      response.end(`<a href="${itemPath}?expression=plain">Preview item</a>`);
      return;
    }
    if (url.pathname === '/openapi.json') return send(200, {openapi: '3.0.0', paths: {
      [prepare]: {get: {summary: 'Create a short preview context'}},
      '/api/item/{productId}': {get: {summary: 'Preview expression for a listed item',
        parameters: [{name: 'productId', in: 'path', required: true, schema: {type: 'string'}},
          {name: 'expression', in: 'query', schema: {type: 'string'}, example: 'plain'}]}}}});
    if (request.method === 'GET' && url.pathname === prepare) {
      const id = String(100000 + randomBytes(3).readUIntBE(0, 3) % 800000);
      workspaces.add(id);
      return send(200, {item: {id}});
    }
    if (request.method === 'GET' && /^\/api\/item\/\d{6}$/.test(url.pathname)) {
      const id = url.pathname.split('/').at(-1);
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
    ' const subject=context.routes.find(item=>item.path===process.env.BX_ITEM&&item.kind===\'read\'&&item.pathSlots?.some(slot=>slot.key===\'productId\'&&slot.segment===2)&&item.fields.includes(\'expression\'));',
    ' const source=context.observedReadRoutes.find(item=>item.path===process.env.BX_PREPARE);',
    ' const encoded=value=>`hex:${Buffer.from(value).toString(\'hex\')}`;',
    " answer={flows:subject&&source?.responseShapes?.anonymous?.item?.id==='string'?[{family:'contextual-item-transform',why:'A fresh item ID may affect the preview result',priority:9,as:'anonymous',prelude:[{method:'GET',path:source.path,headers:[]}],subject:{method:'GET',path:subject.path,placement:'query',key:'expression',fixedFields:[],bodyTemplate:'',headers:[]},observe:[],binding:{from:0,pointer:'/item/id',to:'subject',index:0,key:'productId',placement:'path',segment:2},controlValue:'plain',firstValue:encoded(context.marker),secondValue:encoded(context.secondMarker),marker:context.marker,secondMarker:context.secondMarker,assertion:{step:'subject',index:0,location:'body',name:''}}]:[]};",
    '}',
    "else if(system.includes('Interpret only the extracted'))answer={files:context.files.map(file=>({id:file.id,role:'app',why:'Observed public route',authFlow:'',routes:[],proposals:[]}))};",
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
    BX_PREPARE: prepare, BX_ITEM: itemPath};
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
        representative: item.representative, source: item.source,
        params: item.params, shape: item.fingerprint?.anonymous?.shape})),
      modelCoverage: web.modelCoverage, modelError: audit.data.modelError}));
  assert.equal(finding?.verdict, 'observed');
  assert.equal(finding.severity, 'unrated');
  assert.equal(finding.webProof.binding.pointer, '/item/id');
  assert.equal(finding.webProof.binding.placement, 'path');
  assert.equal(finding.webProof.binding.segment, 2);
  assert.equal(finding.webProof.bindingReview.targetPathTemplate, '/api/item/{productId}');
  assert.equal(finding.webProof.bindingReview.sourceAs, 'anonymous');
  assert.ok(finding.webProof.bindingReview.sourceEvidenceId);
  assert.ok(requested.filter(item => /^GET \/api\/item\/\d{6}\?expression=/.test(item) &&
    !item.startsWith(`GET ${itemPath}?`)).length >= 3, JSON.stringify(requested));
  assert.ok(!requested.some(item => item.includes('{id}')));
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
