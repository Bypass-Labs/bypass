import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import http from 'node:http';
import os from 'node:os';
import path from 'node:path';
import {randomBytes} from 'node:crypto';
import {CLI} from '../src/demo.mjs';
import {execFile} from '../src/util.mjs';

test('blind CLI Muse flow refines a failed owner-content hypothesis and replays the fix', async t => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'bypass-flow-protected-'));
  t.after(() => fs.rmSync(root, {recursive: true, force: true}));
  const suffix = randomBytes(4).toString('hex');
  const protectedPath = `/api/private-${suffix}`;
  const publicPath = `/api/search-${suffix}`;
  const latePath = `/api/late-${suffix}`;
  const otherPaths = Array.from({length: 9}, (_, index) =>
    `/api/read-${suffix}-${index}`);
  const privateBody = JSON.stringify({title: `Owner workspace ${suffix}`,
    description: `A private workspace record for the authorized test owner ${suffix}`,
    owner: 'fixture-owner', value: 42});
  let vulnerable = true;
  const calls = [];
  const server = http.createServer((request, response) => {
    const url = new URL(request.url, 'http://fixture');
    calls.push(`${request.method} ${url.pathname}${url.search}`);
    response.setHeader('content-type', 'application/json');
    response.setHeader('cache-control', 'no-store');
    if (url.pathname === '/') return response.end('<html><a href="/openapi.json">API</a></html>');
    if (url.pathname === '/openapi.json') return response.end(JSON.stringify({
      openapi: '3.0.0', paths: {
        [protectedPath]: {get: {summary: 'Read owner workspace'}},
        [publicPath]: {get: {summary: 'Search public workspace index',
          parameters: [{name: 'term', in: 'query', schema: {type: 'string'},
            example: 'plain'}]}},
        ...Object.fromEntries([...otherPaths, latePath].map(path =>
          [path, {get: {summary: 'Read public workspace status'}}]))}}));
    if (request.method === 'GET' && url.pathname === protectedPath) {
      if (request.headers.authorization === 'Bearer fixture-owner') return response.end(privateBody);
      response.statusCode = 403;
      return response.end(JSON.stringify({error: 'forbidden'}));
    }
    if (request.method === 'GET' && url.pathname === publicPath) {
      const value = url.searchParams.get('term');
      return response.end(vulnerable && ['wide-one', 'wide-two'].includes(value) ?
        privateBody : JSON.stringify({title: 'Public index', records: []}));
    }
    if (request.method === 'GET' && [...otherPaths, latePath].includes(url.pathname))
      return response.end(JSON.stringify({status: 'public'}));
    response.statusCode = 404;
    response.end(JSON.stringify({error: 'missing'}));
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  t.after(() => new Promise(resolve => server.close(resolve)));
  const origin = `http://127.0.0.1:${server.address().port}`;
  const scopePath = path.join(root, 'blackbox.scope.json');
  fs.writeFileSync(scopePath, JSON.stringify({schemaVersion: 1, target: {origin},
    include: ['/'], identities: {identityPath: protectedPath},
    limits: {rps: 50, maxUrls: 40, minutes: 3, modelCalls: 30, tasks: 20}}));
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
    " fs.appendFileSync(process.env.BX_MODEL_LOG,context.routes.some(item=>item.path===process.env.BX_LATE)?'late-page\\n':'other-page\\n');",
    ' const subject=[...context.routes,...context.observedReadRoutes].find(item=>item.path===process.env.BX_PUBLIC&&item.fields?.includes(\'term\'));',
    ' const protectedRead=context.protectedReadRoutes.find(item=>item===process.env.BX_PROTECTED);',
    " answer={flows:subject&&protectedRead?[{family:'owner-content-disclosure',why:'A public lookup may expose owner-only content',priority:9,as:'anonymous',oracle:'protected-body',protectedPath:protectedRead,prelude:[],subject:{method:'GET',path:subject.path,placement:'query',key:'term',fixedFields:[],bodyTemplate:'',headers:[]},observe:[],controlValue:'plain',firstValue:'narrow-one',secondValue:'narrow-two',marker:context.marker,secondMarker:context.secondMarker,assertion:{step:'subject',index:0,location:'body',name:''}}]:[]};",
    '}',
    "else if(system.startsWith('Revise at most one bounded, authorized HTTP experiment')){",
    " fs.appendFileSync(process.env.BX_MODEL_LOG,'revision\\n');",
    " const prior=context.recentAttempts?.at(-1);",
    " const next=prior?.input?.firstValue==='narrow-one'?['medium-one','medium-two']:prior?.input?.firstValue==='medium-one'?['wide-one','wide-two']:null;",
    " answer={flows:prior?.oracle==='protected-body'&&prior?.verdict==='not_reproduced'&&next?[{family:'owner-content-disclosure',why:'Earlier candidates missed; test another harmless search width',priority:9,as:'anonymous',oracle:'protected-body',protectedPath:process.env.BX_PROTECTED,prelude:[],subject:{method:'GET',path:process.env.BX_PUBLIC,placement:'query',key:'term',fixedFields:[],bodyTemplate:'',headers:[]},observe:[],controlValue:'plain',firstValue:next[0],secondValue:next[1],marker:context.marker,secondMarker:context.secondMarker,assertion:{step:'subject',index:0,location:'body',name:''}}]:[]};",
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
    OWNER_TOKEN: 'fixture-owner', BX_PUBLIC: publicPath, BX_PROTECTED: protectedPath,
    BX_LATE: latePath, BX_MODEL_LOG: path.join(root, 'model-pages.log')};
  const cli = async (...args) => {
    const completed = await execFile(process.execPath,
      [CLI, 'blackbox', ...args, '--project', root, '--json', '--non-interactive'],
      {cwd: root, env, timeout: 90000});
    return {code: completed.code, data: JSON.parse(completed.stdout)};
  };
  const audit = await cli(origin, '--scope', scopePath, '--rps', '20');
  assert.ok(audit.data.runDir, JSON.stringify(audit));
  const web = JSON.parse(fs.readFileSync(path.join(audit.data.runDir, 'web-probes.json'), 'utf8'));
  const finding = audit.data.findings.find(item => item.kind === 'model-access-boundary' &&
    item.pattern === publicPath);
  assert.ok(web.strategyDecisions.some(item => item.mode === 'http-sequence' && item.accepted),
    JSON.stringify(web.strategyDecisions));
  assert.ok(web.strategyDecisions.some(item => item.mode === 'http-sequence-revision' && item.accepted),
    JSON.stringify(web.strategyDecisions));
  assert.ok(web.investigations.some(item => item.attempts?.[0]?.verdict === 'not_reproduced' &&
    item.attempts?.[1]?.verdict === 'not_reproduced' &&
    item.attempts?.[2]?.verdict === 'confirmed'), JSON.stringify(web.investigations));
  const modelPages = fs.readFileSync(env.BX_MODEL_LOG, 'utf8').trim().split('\n');
  assert.ok(modelPages.filter(item => item === 'revision').length >= 2,
    JSON.stringify(modelPages));
  assert.ok(modelPages.includes('late-page'),
    `a later route page did not reach Muse: ${JSON.stringify(modelPages)}`);
  assert.ok(finding?.proof, JSON.stringify({findings: audit.data.findings,
    results: web.results, decisions: web.strategyDecisions}));
  assert.equal(finding.verdict, 'confirmed');
  assert.equal(finding.webProof.comparison, 'exact-body');
  assert.equal((await cli('verify', audit.data.run)).code, 1);
  const exported = await cli('export', audit.data.run, '--out', path.join(root, 'regression'));
  assert.equal(exported.code, 0);
  const regression = async () => (await execFile(process.execPath,
    ['--test', ...exported.data.files], {env: {...env, NODE_TEST_CONTEXT: undefined},
      timeout: 20000})).code;
  assert.equal(await regression(), 1);
  vulnerable = false;
  assert.equal((await cli('verify', audit.data.run)).code, 0);
  assert.equal(await regression(), 0);
  assert.ok(calls.every(call => !call.startsWith('POST ')));
});
