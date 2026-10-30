import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import http from 'node:http';
import os from 'node:os';
import path from 'node:path';
import {randomBytes} from 'node:crypto';
import {CLI} from '../src/demo.mjs';
import {execFile} from '../src/util.mjs';

test('CLI forwards an audit-owned callback through a fresh derived session and reviewed POST',
  {timeout: 150000}, async t => {
    const root = fs.mkdtempSync(path.join(os.tmpdir(), 'bypass-derived-callback-'));
    t.after(() => fs.rmSync(root, {recursive: true, force: true}));
    const suffix = randomBytes(5).toString('hex');
    const loginPath = `/api/login-${suffix}`;
    const privatePath = `/api/me-${suffix}`;
    const previewPath = `/api/preview-${suffix}`;
    const issued = new Set();
    const previewCalls = [];
    let loginVulnerable = true, callbackVulnerable = true;
    const server = http.createServer(async (request, response) => {
      const url = new URL(request.url, 'http://fixture.invalid');
      const authorized = issued.has(String(request.headers.authorization ?? '')
        .replace(/^Bearer /, ''));
      const json = (status, body) => {
        response.writeHead(status, {'content-type': 'application/json',
          'cache-control': 'no-store'});
        response.end(JSON.stringify(body));
      };
      if (request.method === 'GET' && url.pathname === '/') {
        response.writeHead(200, {'content-type': 'text/html'});
        return response.end('<html><a href="/openapi.json">API</a></html>');
      }
      if (request.method === 'GET' && url.pathname === '/openapi.json') return json(200, {
        openapi: '3.0.0', paths: {
          [loginPath]: {post: {summary: 'Login with username and password',
            requestBody: {content: {'application/json': {schema: {type: 'object',
              required: ['username', 'password'], properties: {
                username: {type: 'string'}, password: {type: 'string'}}}}}}}},
          [privatePath]: {get: {summary: 'Read protected identity'}},
          [previewPath]: {post: {summary: 'Fetch a URL for a protected preview',
            requestBody: {content: {'application/json': {schema: {type: 'object',
              required: ['previewUrl'], properties: {
                previewUrl: {type: 'string'}}}}}}}}}});
      if (request.method === 'GET' && url.pathname === privatePath)
        return authorized ? json(200, {previewPath}) : json(401, {error: 'unauthorized'});
      if (request.method === 'POST' && [loginPath, previewPath].includes(url.pathname)) {
        const chunks = [];
        for await (const chunk of request) chunks.push(chunk);
        let input;
        try {input = JSON.parse(Buffer.concat(chunks).toString());}
        catch {return json(400, {error: 'invalid JSON'});}
        if (url.pathname === loginPath) {
          if (loginVulnerable && input.username === "admin' OR '1'='1" &&
              /^bx-invalid-[0-9a-f]{24}$/.test(String(input.password ?? ''))) {
            const token = `token-${randomBytes(24).toString('hex')}`;
            issued.add(token);
            return json(200, {authentication: {token}});
          }
          return json(401, {error: 'invalid credentials'});
        }
        previewCalls.push({authorized, callback: /^http:\/\/127\.0\.0\.1:\d+\/bx-ssrf\/[0-9a-f]{24}$/.test(
          String(input.previewUrl ?? ''))});
        if (!authorized) return json(401, {error: 'unauthorized'});
        if (callbackVulnerable && previewCalls.at(-1).callback)
          http.get(input.previewUrl, fetched => fetched.resume()).on('error', () => {});
        return json(callbackVulnerable ? 200 : 403, {queued: callbackVulnerable});
      }
      return json(404, {error: 'missing'});
    });
    await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
    t.after(() => new Promise(resolve => server.close(resolve)));
    const origin = `http://127.0.0.1:${server.address().port}`;
    const scopeFile = path.join(root, 'blackbox.scope.json');
    fs.writeFileSync(scopeFile, JSON.stringify({schemaVersion: 1,
      target: {origin}, include: ['/'], limits: {rps: 50,
        maxUrls: 80, minutes: 3, modelCalls: 50, tasks: 100}}));
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
      "if(system.startsWith('From only the observed authorized JSON login operations')){",
      " const post=context.posts.find(item=>item.path===process.env.BX_LOGIN);",
      " const read=context.reads.find(item=>item.path===process.env.BX_PRIVATE);",
      " answer={checks:post&&read?[{loginPath:post.path,userField:'username',passwordField:'password',proofMode:'protected-status',userPayloads:[\"admin' OR '1'='1\"],tokenPointer:'/authentication/token',privatePath:read.path,principalPointer:'',why:'Observed login and denied identity read'}]:[]};",
      '}',
      "else if(system.startsWith('You are planning bounded, authorized HTTP research.')){",
      " const post=context.routes.find(item=>item.kind==='json'&&item.path===process.env.BX_PREVIEW&&item.fields.includes('previewUrl'));",
      " answer={flows:context.derivedAvailable&&post?[{family:'server-side-fetch',why:'The protected preview field holds a URL',priority:10,as:'derived',oracle:'local-callback',prelude:[],subject:{method:'POST',path:post.path,placement:'json',key:'previewUrl',fixedFields:[],bodyTemplate:'',headers:[]},observe:[],binding:null,controlValue:'',firstValue:'',secondValue:'',marker:'',secondMarker:'',assertion:{step:'subject',index:0,location:'body',name:''}}]:[]};",
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
    const env = {...process.env, PATH: `${bin}${path.delimiter}${process.env.PATH}`,
      BX_LOGIN: loginPath, BX_PRIVATE: privatePath, BX_PREVIEW: previewPath};
    const cli = async (...args) => {
      const done = await execFile(process.execPath,
        [CLI, 'blackbox', ...args, '--project', root, '--json', '--non-interactive'],
        {cwd: root, env, timeout: 120000});
      return {code: done.code, data: JSON.parse(done.stdout)};
    };
    const audit = await cli(origin, '--scope', scopeFile);
    assert.ok(audit.data.runDir, JSON.stringify(audit));
    const callback = audit.data.findings.find(item => item.kind === 'ssrf-loopback' &&
      item.pattern === previewPath);
    const web = JSON.parse(fs.readFileSync(path.join(audit.data.runDir,
      'web-probes.json'), 'utf8'));
    assert.ok(callback?.proof, JSON.stringify({findings: audit.data.findings,
      decisions: web.strategyDecisions.filter(item =>
        item.mode?.startsWith('http-sequence'))}));
    assert.equal(callback.webProof.request.as, 'derived');
    assert.ok(previewCalls.filter(item => item.authorized && item.callback).length >= 2,
      'the reviewed POST must reach the server with a fresh derived bearer and callback');
    const proved = JSON.parse((await execFile(process.execPath, [callback.proof],
      {env, timeout: 20000})).stdout);
    assert.equal(proved.verdict, 'confirmed');
    const artifacts = fs.readdirSync(audit.data.runDir, {recursive: true, withFileTypes: true})
      .filter(item => item.isFile()).map(item =>
        fs.readFileSync(path.join(item.parentPath, item.name), 'utf8')).join('\n');
    for (const token of issued) assert.ok(!artifacts.includes(token));
    callbackVulnerable = false;
    const fixed = JSON.parse((await execFile(process.execPath, [callback.proof],
      {env, timeout: 20000})).stdout);
    assert.equal(fixed.verdict, 'not_reproduced');
    const verification = await cli('verify', audit.data.run);
    assert.equal(verification.code, 1, 'the separate login bug remains');
    assert.equal(verification.data.proofs.find(item => item.id === callback.id)?.verdict,
      'not_reproduced');
  });
