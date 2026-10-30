import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import http from 'node:http';
import os from 'node:os';
import path from 'node:path';
import {randomBytes} from 'node:crypto';
import {CLI} from '../src/demo.mjs';
import {execFile} from '../src/util.mjs';

test('an accepted Muse revision executes and does not abort protected follow-up',
  {timeout: 150000}, async t => {
    const root = fs.mkdtempSync(path.join(os.tmpdir(), 'bypass-protected-recovery-'));
    t.after(() => { if (!process.env.BX_KEEP_TEST_ROOT) fs.rmSync(root, {recursive: true, force: true}); });
    const suffix = randomBytes(5).toString('hex');
    const loginPath = `/api/login-${suffix}`;
    const privatePath = `/api/private-${suffix}`;
    const usersPath = `/api/users-${suffix}`;
    const renderPath = `/api/render-${suffix}`;
    const pagePath = `/workspace-${suffix}/home`;
    const scriptPath = `/workspace-${suffix}/app.js`;
    const issued = new Set();
    const server = http.createServer(async (request, response) => {
      const url = new URL(request.url, 'http://fixture.invalid');
      const json = (status, body) => {
        response.writeHead(status, {'content-type': 'application/json', 'cache-control': 'no-store'});
        response.end(JSON.stringify(body));
      };
      if (request.method === 'GET' && url.pathname === '/') {
        response.writeHead(200, {'content-type': 'text/html', 'cache-control': 'no-store'});
        return response.end('<html><a href="/openapi.json">API</a></html>');
      }
      if (request.method === 'GET' && url.pathname === '/openapi.json') return json(200, {
        openapi: '3.0.0', paths: {
          [loginPath]: {post: {summary: 'Login', requestBody: {content: {
            'application/json': {schema: {type: 'object', required: ['username', 'password'],
              properties: {username: {type: 'string'}, password: {type: 'string'}}}}}}}},
          [usersPath]: {post: {summary: 'Create user', requestBody: {content: {
            'application/json': {schema: {type: 'object', required: ['email'],
              properties: {email: {type: 'string'}}}}}}}},
          [privatePath]: {get: {summary: 'Authenticated profile'}}}});
      if (request.method === 'POST' && url.pathname === loginPath) {
        let body = ''; for await (const chunk of request) body += chunk;
        const input = JSON.parse(body);
        if (input.username === "admin' OR '1'='1" &&
            /^bx-invalid-[0-9a-f]{24}$/.test(String(input.password ?? ''))) {
          const token = `token-${randomBytes(24).toString('hex')}`;
          issued.add(token);
          return json(200, {authentication: {token}});
        }
        return json(401, {error: 'invalid credentials'});
      }
      const bearer = String(request.headers.authorization ?? '').replace(/^Bearer /, '');
      if (request.method === 'GET' && url.pathname === privatePath)
        return issued.has(bearer) ? json(200, {role: 'member', workspace: pagePath}) :
          json(401, {error: 'denied'});
      if (request.method === 'GET' && url.pathname === pagePath) {
        if (!issued.has(bearer)) return json(401, {error: 'denied'});
        response.writeHead(200, {'content-type': 'text/html', 'cache-control': 'no-store'});
        return response.end(`<html><script src="${scriptPath}"></script></html>`);
      }
      if (request.method === 'GET' && url.pathname === scriptPath) {
        if (!issued.has(bearer)) return json(401, {error: 'denied'});
        response.writeHead(200, {'content-type': 'text/javascript', 'cache-control': 'no-store'});
        return response.end(`async function render(){return fetch('${renderPath}?q=plain').then(r=>r.json())}`);
      }
      if (request.method === 'GET' && url.pathname === renderPath) {
        if (!issued.has(bearer)) return json(401, {error: 'denied'});
        const value = url.searchParams.get('q') ?? '';
        return json(200, {result: /^hex:(?:[0-9a-f]{2}){3,80}$/i.test(value) ?
          Buffer.from(value.slice(4), 'hex').toString('utf8') : value});
      }
      if (request.method === 'POST' && url.pathname === usersPath) {
        let body = ''; for await (const chunk of request) body += chunk;
        return json(201, {accepted: JSON.parse(body).email});
      }
      return json(404, {error: 'missing'});
    });
    await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
    t.after(() => new Promise(resolve => server.close(resolve)));
    const origin = `http://127.0.0.1:${server.address().port}`;
    const scopeFile = path.join(root, 'blackbox.scope.json');
    fs.writeFileSync(scopeFile, JSON.stringify({schemaVersion: 1, target: {origin}, include: ['/'],
      limits: {rps: 50, maxUrls: 70, minutes: 3, modelCalls: 45, tasks: 90}}));
    const bin = path.join(root, 'bin'); fs.mkdirSync(bin);
    const authCount = path.join(root, 'auth-count');
    fs.writeFileSync(bin + '/muse', [
      '#!' + process.execPath,
      "const fs=require('node:fs');",
      'const args=process.argv.slice(2), value=flag=>args[args.indexOf(flag)+1];',
      "if(args.includes('--version')){console.log('muse fixture');process.exit(0);}",
      "if(args[0]!=='exec'||!args.includes('--disable-shell')||!args.includes('--output-schema')||value('--provider')!=='meta')process.exit(2);",
      "const messages=JSON.parse(fs.readFileSync(value('--prompt-file'),'utf8'));",
      'const system=messages[0].content, context=JSON.parse(messages[1].content);',
      'let answer;',
      "if(system.startsWith('From only the observed authorized JSON login operations')){",
      ' const count=Number(fs.existsSync(process.env.BX_AUTH_COUNT)?fs.readFileSync(process.env.BX_AUTH_COUNT):0);',
      ' fs.writeFileSync(process.env.BX_AUTH_COUNT,String(count+1));',
      " const post=context.posts.find(item=>item.path===process.env.BX_LOGIN);",
      " const read=context.reads.find(item=>item.path===process.env.BX_PRIVATE);",
      ' answer={checks:count===0&&post&&read?[{loginPath:post.path,userField:\'username\',passwordField:\'password\',proofMode:\'protected-status\',userPayloads:["admin\' OR \'1\'=\'1"],tokenPointer:\'/authentication/token\',privatePath:read.path,principalPointer:\'\',why:\'Synthetic invalid-password test\'}]:[]};',
      '}',
      "else if(system.startsWith('You are planning bounded, authorized HTTP research.')){",
      " const post=context.routes.find(item=>item.path===process.env.BX_USERS&&item.kind==='json');",
      " const read=context.observedReadRoutes.find(item=>item.path===process.env.BX_RENDER&&item.fields.includes('q'));",
      ' const flow=(route,as,field,placement,values,oracle)=>({family:\'response-transform\',why:\'Test reviewed input\',priority:8,as,oracle,prelude:[],subject:{method:route.methods[0],path:route.path,placement,key:field,fixedFields:[],bodyTemplate:\'\',headers:[]},observe:[],controlValue:values[0],firstValue:values[1],secondValue:values[2],marker:context.marker,secondMarker:context.secondMarker,assertion:{step:\'subject\',index:0,location:\'body\',name:\'\'}});',
      ' const encoded=value=>\'hex:\'+Buffer.from(value).toString(\'hex\');',
      ' answer={flows:context.derivedAvailable&&post&&read?[flow(post,\'anonymous\',\'email\',\'json\',[\'plain\',\'one\',\'two\'],\'marker\'),flow(read,\'derived\',\'q\',\'query\',[\'plain\',encoded(context.marker),encoded(context.secondMarker)],\'marker\')]:[]};',
      '}',
      "else if(system.startsWith('Revise at most one bounded, authorized HTTP experiment')){",
      ' const prior=context.hypothesis?.family;',
      ' const route=context.observedRoutes.find(item=>item.path===process.env.BX_USERS&&item.kind===\'json\');',
      ' answer={flows:prior===\'response-transform\'&&route&&context.historySummary.attempts===1?[{family:\'response-transform\',why:\'Try email-shaped inputs\',priority:8,as:\'anonymous\',oracle:\'marker\',prelude:[],subject:{method:\'POST\',path:route.path,placement:\'json\',key:\'email\',fixedFields:[],bodyTemplate:\'\',headers:[]},observe:[],controlValue:\'plain\',firstValue:\'test@example.com\',secondValue:\'other@example.com\',marker:context.marker,secondMarker:context.secondMarker,assertion:{step:\'subject\',index:0,location:\'body\',name:\'\'}}]:[]};',
      '}',
      "else if(system.startsWith('Map this authorized authenticated web surface'))answer={paths:[]};",
      "else if(system.includes('Interpret only the extracted'))answer={files:[]};",
      "else if(system.includes('Assess only these independently proved'))answer={notes:[]};",
      "else if(system.includes('Continue mapping this authorized primary application'))answer={paths:[]};",
      "else if(system.includes('mapping an authorized web API'))answer={paths:[],notes:[]};",
      "else if(system.includes('Propose bounded GET access-control'))answer={tasks:[]};",
      "else if(system.includes('Rank only the supplied observed read-only web-test candidates'))answer={priorities:[],strategies:[],experiments:[]};",
      'else { const schema=JSON.parse(fs.readFileSync(value(\'--output-schema\'),\'utf8\')); const blank=s=>s?.type===\'object\'?Object.fromEntries((s.required??[]).map(key=>[key,blank(s.properties?.[key])])):s?.type===\'array\'?[]:s?.type===\'integer\'||s?.type===\'number\'?0:s?.type===\'boolean\'?false:s?.enum?.[0]??\'\'; answer=blank(schema); }',
      "console.log(JSON.stringify({payload:{kind:'run_terminal',terminal:'completed',text:JSON.stringify(answer)}}));",
    ].join('\n') + '\n', {mode: 0o700});
    const env = {...process.env, PATH: `${bin}${path.delimiter}${process.env.PATH}`,
      BX_AUTH_COUNT: authCount, BX_LOGIN: loginPath, BX_PRIVATE: privatePath,
      BX_USERS: usersPath, BX_RENDER: renderPath};
    const completed = await execFile(process.execPath,
      [CLI, 'blackbox', origin, '--scope', scopeFile, '--project', root, '--json', '--non-interactive'],
      {cwd: root, env, timeout: 120000});
    assert.ok(completed.stdout, completed.stderr);
    const audit = JSON.parse(completed.stdout);
    assert.ok(audit.runDir, JSON.stringify({code: completed.code, audit}));
    const derived = JSON.parse(fs.readFileSync(path.join(audit.runDir, 'derived-session-recon.json')));
    assert.equal(derived.sessions[0]?.coverage?.earlyWebError, undefined,
      JSON.stringify(derived.sessions[0]?.coverage));
    const ledger = fs.readFileSync(path.join(audit.runDir, 'evidence.jsonl'), 'utf8')
      .trim().split('\n').map(JSON.parse);
    assert.ok(ledger.some(item => item.kind === 'model-http-sequence-decision' &&
      item.path === usersPath && item.accepted), JSON.stringify({root, decisions: ledger
      .filter(item => item.kind?.startsWith('model-http-sequence'))
      .map(item => ({kind: item.kind, path: item.path, accepted: item.accepted,
        reason: item.reason, proposals: item.proposals, routesSent: item.routesSent}))}));
    assert.ok(ledger.some(item => item.kind === 'model-http-sequence-attempt' &&
      item.path === usersPath && item.attempt === 2 &&
      item.verdict === 'not_reproduced'),
    'accepted revision must execute and record its negative result');
    assert.ok(ledger.some(item => item.request?.method === 'POST' &&
      new URL(item.request.url).pathname === usersPath && item.response?.status === 201),
    'the reviewed POST contract must reach the target');
    assert.ok(ledger.some(item => item.kind === 'model-http-sequence-attempt' &&
      item.path === renderPath && item.as === 'derived'),
    'the next protected lead must execute with its derived session');
  });
