import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import http from 'node:http';
import os from 'node:os';
import path from 'node:path';
import {randomBytes} from 'node:crypto';
import {CLI} from '../src/demo.mjs';
import {execFile} from '../src/util.mjs';

test('owner-triggered sharing before an anonymous sequence is not an auth bypass', async t => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'bypass-flow-owner-share-'));
  t.after(() => fs.rmSync(root, {recursive: true, force: true}));
  const suffix = randomBytes(4).toString('hex');
  const protectedPath = `/api/private-${suffix}`;
  const seedPath = `/api/seed-${suffix}`;
  const filterPath = `/api/filter-${suffix}`;
  const resultPath = `/api/result-${suffix}`;
  const privateBody = JSON.stringify({title: `Owner workspace ${suffix}`,
    description: `A private workspace record for the authorized test owner ${suffix}`,
    owner: 'fixture-owner', value: 42});
  const publicBody = JSON.stringify({title: 'Public index', records: []});
  let lastResult = publicBody;
  let sharedByOwner = false;
  const calls = [];
  const server = http.createServer(async (request, response) => {
    const url = new URL(request.url, 'http://fixture');
    calls.push(`${request.method} ${url.pathname}${url.search}`);
    response.setHeader('content-type', 'application/json');
    response.setHeader('cache-control', 'no-store');
    if (url.pathname === '/') return response.end(`<html><a href="/openapi.json">API</a>
      <a href="${seedPath}">seed</a><a href="${resultPath}">result</a></html>`);
    if (url.pathname === '/openapi.json') return response.end(JSON.stringify({
      openapi: '3.0.0', paths: {
        [protectedPath]: {get: {summary: 'Read owner workspace'}},
        [seedPath]: {get: {summary: 'Owner publishes the workspace for a viewer'}},
        [resultPath]: {get: {summary: 'Read the last public filter result'}},
        [filterPath]: {post: {summary: 'Filter the public workspace index',
          requestBody: {content: {'application/json': {schema: {type: 'object',
            required: ['term'], properties: {term: {type: 'string'}}}}}}}}}}));
    if (request.method === 'GET' && url.pathname === protectedPath) {
      if (request.headers.authorization === 'Bearer fixture-owner') return response.end(privateBody);
      response.statusCode = 403;
      return response.end(JSON.stringify({error: 'forbidden'}));
    }
    if (request.method === 'GET' && url.pathname === seedPath) {
      if (request.headers.authorization !== 'Bearer fixture-owner') {
        response.statusCode = 403;
        return response.end(JSON.stringify({error: 'owner required'}));
      }
      sharedByOwner = true;
      return response.end(JSON.stringify({shared: true}));
    }
    if (request.method === 'POST' && url.pathname === filterPath) {
      let body = {};
      try {body = JSON.parse(await (async () => {
        const chunks = [];
        for await (const chunk of request) chunks.push(chunk);
        return Buffer.concat(chunks).toString();
      })());} catch { /* malformed body stays invalid */ }
      lastResult = sharedByOwner && ['wide-one', 'wide-two'].includes(body.term) ?
        privateBody : publicBody;
      return response.end(JSON.stringify({queued: true}));
    }
    if (request.method === 'GET' && url.pathname === resultPath)
      return response.end(lastResult);
    response.statusCode = 404;
    response.end(JSON.stringify({error: 'missing'}));
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  t.after(() => new Promise(resolve => server.close(resolve)));
  const origin = `http://127.0.0.1:${server.address().port}`;
  const scopePath = path.join(root, 'blackbox.scope.json');
  fs.writeFileSync(scopePath, JSON.stringify({schemaVersion: 1, target: {origin},
    include: ['/'], identities: {identityPath: protectedPath},
    probes: {jsonPostPaths: [filterPath]},
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
    " const subject=context.routes.find(item=>item.path===process.env.BX_FILTER&&item.fields?.includes('term'));",
    ' const seed=context.observedReadRoutes.find(item=>item.path===process.env.BX_SEED);',
    ' const result=context.observedReadRoutes.find(item=>item.path===process.env.BX_RESULT);',
    ' const protectedRead=context.protectedReadRoutes.find(item=>item===process.env.BX_PROTECTED);',
    " answer={flows:subject&&seed&&result&&protectedRead?[{family:'owner-content-disclosure',why:'An observed filter sequence may expose owner-only content',priority:9,as:'anonymous',oracle:'protected-body',protectedPath:protectedRead,prelude:[{method:'GET',as:'owner',path:seed.path,headers:[]}],subject:{method:'POST',path:subject.path,placement:'json',key:'term',fixedFields:[],bodyTemplate:'',headers:[]},observe:[{method:'GET',path:result.path,headers:[]}],binding:null,controlValue:'plain',firstValue:'wide-one',secondValue:'wide-two',marker:context.marker,secondMarker:context.secondMarker,assertion:{step:'observe',index:0,location:'body',name:''}}]:[]};",
    '}',
    "else if(system.startsWith('Revise at most one bounded, authorized HTTP experiment'))answer={flows:[]};",
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
    OWNER_TOKEN: 'fixture-owner', BX_FILTER: filterPath, BX_SEED: seedPath,
    BX_RESULT: resultPath, BX_PROTECTED: protectedPath};
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
    item.pattern === filterPath);
  assert.ok(web.strategyDecisions.some(item => item.mode === 'http-sequence' && item.accepted),
    JSON.stringify(web.strategyDecisions));
  assert.ok(web.investigations.some(item => item.attempts?.[0]?.verdict === 'inconclusive' &&
    item.attempts[0].reason.includes('credentialed prelude may have published')),
    JSON.stringify(web.investigations));
  assert.equal(finding, undefined, JSON.stringify(audit.data.findings));
  assert.ok(calls.some(call => call === `POST ${filterPath}`));
  assert.ok(calls.some(call => call === `GET ${seedPath}`));
});
