import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import http from 'node:http';
import os from 'node:os';
import path from 'node:path';
import {randomBytes} from 'node:crypto';
import {CLI} from '../src/demo.mjs';
import {execFile} from '../src/util.mjs';

for (const method of ['POST', 'PATCH']) test(
  `CLI sends a Muse-planned reviewed ${method} with a transient derived bearer and replays its proof`,
  {timeout: 180000}, async t => {
    const root = fs.mkdtempSync(path.join(os.tmpdir(), 'bypass-derived-post-flow-'));
    t.after(() => fs.rmSync(root, {recursive: true, force: true}));
    const suffix = randomBytes(5).toString('hex');
    const loginPath = `/api/login-${suffix}`;
    const privatePath = `/api/me-${suffix}`;
    const processPath = `/api/${suffix}/process`;
    const resultPath = `/api/${suffix}/result`;
    const issued = new Set(), postCalls = [];
    let loginVulnerable = true, transformVulnerable = true, last = 'plain';
    const server = http.createServer(async (request, response) => {
      const url = new URL(request.url, 'http://fixture.invalid');
      const bearer = String(request.headers.authorization ?? '').replace(/^Bearer /, '');
      const authorized = issued.has(bearer);
      const json = (status, body, headers = {}) => {
        response.writeHead(status, {'content-type': 'application/json',
          'cache-control': 'no-store', ...headers});
        response.end(JSON.stringify(body));
      };
      if (request.method === 'GET' && url.pathname === '/') {
        response.writeHead(200, {'content-type': 'text/html', 'cache-control': 'no-store'});
        return response.end('<html><a href="/openapi.json">API</a></html>');
      }
      if (request.method === 'GET' && url.pathname === '/openapi.json') return json(200, {
        openapi: '3.0.0', paths: {
          [loginPath]: {post: {summary: 'Login with username and password',
            requestBody: {content: {'application/json': {schema: {type: 'object',
              required: ['username', 'password'], properties: {
                username: {type: 'string'}, password: {type: 'string'}}}}}}}},
          [privatePath]: {get: {summary: 'Authenticated workspace identity'}},
          [processPath]: {[method.toLowerCase()]: {summary: 'Process an authenticated expression',
            requestBody: {content: {'application/json': {schema: {type: 'object',
              required: ['expression'], properties: {expression: {type: 'string'}}}}}}}},
          [resultPath]: {get: {summary: 'Read the processed result'}}}});
      if (request.method === 'POST' && url.pathname === loginPath) {
        const chunks = [];
        for await (const chunk of request) chunks.push(chunk);
        let input;
        try {input = JSON.parse(Buffer.concat(chunks).toString());}
        catch {return json(400, {error: 'invalid JSON'});}
        if (loginVulnerable && input.username === "admin' OR '1'='1" &&
            /^bx-invalid-[0-9a-f]{24}$/.test(String(input.password ?? ''))) {
          const token = `token-${randomBytes(24).toString('hex')}`;
          issued.add(token);
          return json(200, {authentication: {token}});
        }
        return json(401, {error: 'invalid credentials'});
      }
      if (request.method === 'GET' && url.pathname === privatePath)
        return authorized ? json(200, {resultPath, processPath}) :
          json(401, {error: 'unauthorized'});
      if (request.method === method && url.pathname === processPath) {
        postCalls.push({authorized, contentType: request.headers['content-type'] ?? ''});
        if (!authorized) return json(401, {error: 'unauthorized'});
        const chunks = [];
        for await (const chunk of request) chunks.push(chunk);
        let input;
        try {input = JSON.parse(Buffer.concat(chunks).toString());}
        catch {return json(400, {error: 'invalid JSON'});}
        const value = String(input.expression ?? '');
        last = transformVulnerable && /^hex:(?:[0-9a-f]{2}){3,80}$/i.test(value) ?
          Buffer.from(value.slice(4), 'hex').toString('utf8') : value;
        return json(200, {accepted: true}, {location: last});
      }
      if (request.method === 'GET' && url.pathname === resultPath)
        return authorized ? json(200, {ready: true}, {location: last}) :
          json(401, {error: 'unauthorized'});
      return json(404, {error: 'missing'});
    });
    await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
    t.after(() => new Promise(resolve => server.close(resolve)));
    const origin = `http://127.0.0.1:${server.address().port}`;
    const scopeFile = path.join(root, 'blackbox.scope.json');
    fs.writeFileSync(scopeFile, JSON.stringify({schemaVersion: 1, target: {origin}, include: ['/'],
      probes: {writeOperations: method === 'PATCH' ?
        [{method: 'PATCH', path: processPath, placement: 'json'}] : []},
      limits: {rps: 50, maxUrls: 70, minutes: 3, modelCalls: 45, tasks: 90}}));
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
      " const post=context.posts.find(item=>item.path===process.env.BX_LOGIN&&item.usernameField==='username'&&item.passwordField==='password');",
      " const read=context.reads.find(item=>item.path===process.env.BX_PRIVATE);",
      " answer={checks:post&&read?[{loginPath:post.path,userField:'username',passwordField:'password',proofMode:'protected-status',userPayloads:[\"admin' OR '1'='1\"],tokenPointer:'/authentication/token',privatePath:read.path,principalPointer:'',why:'Synthetic invalid-password check on observed login and protected identity route'}]:[]};",
      '}',
      "else if(system.startsWith('You are planning bounded, authorized HTTP research.')){",
      " const post=context.routes.find(item=>item.kind==='json'&&item.path===process.env.BX_PROCESS&&item.methods.includes(process.env.BX_METHOD)&&item.fields.includes('expression'));",
      " const encoded=value=>`hex:${Buffer.from(value).toString('hex')}`;",
      " answer={flows:context.derivedAvailable&&post?[{family:'protected-response-transform',why:'The documented protected processor may transform its expression field',priority:10,as:'derived',oracle:'marker',prelude:[],subject:{method:process.env.BX_METHOD,path:post.path,placement:'json',key:'expression',fixedFields:[],bodyTemplate:'',headers:[]},observe:[],binding:null,controlValue:'plain',firstValue:encoded(context.marker),secondValue:encoded(context.secondMarker),marker:context.marker,secondMarker:context.secondMarker,assertion:{step:'subject',index:0,location:'header',name:'location'}}]:[]};",
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
      BX_LOGIN: loginPath, BX_PRIVATE: privatePath, BX_PROCESS: processPath,
      BX_RESULT: resultPath, BX_METHOD: method};
    const cli = async (...args) => {
      const done = await execFile(process.execPath,
        [CLI, 'blackbox', ...args, '--project', root, '--json', '--non-interactive'],
        {cwd: root, env, timeout: 120000});
      return {code: done.code, data: JSON.parse(done.stdout)};
    };
    const audit = await cli(origin, '--scope', scopeFile);
    assert.ok(audit.data.runDir, JSON.stringify(audit));
    const observation = audit.data.findings.find(item => item.kind === 'model-http-sequence' &&
      item.pattern === processPath);
    const web = JSON.parse(fs.readFileSync(path.join(audit.data.runDir, 'web-probes.json'), 'utf8'));
    assert.ok(observation, JSON.stringify({modelOutput: audit.data.modelOutput,
      coverage: audit.data.coverage?.derivedSessionRecon,
      modelCoverage: web.modelCoverage,
      decisions: web.strategyDecisions}));
    assert.equal(observation.verdict, 'observed');
    assert.equal(observation.severity, 'unrated');
    assert.equal(observation.webProof.as, 'derived');
    assert.equal(observation.webProof.subject.method, method);
    assert.ok(web.strategyDecisions.some(item => item.mode === 'http-sequence' && item.accepted));
    assert.ok(postCalls.some(item => item.authorized &&
      item.contentType.startsWith('application/json')),
    'the live research executor must send the reviewed JSON body with a derived bearer');
    const proof = await execFile(process.execPath, [observation.proof], {env, timeout: 20000});
    assert.equal(JSON.parse(proof.stdout).verdict, 'observed');
    assert.equal((await cli('verify', audit.data.run)).code, 1);
    const artifacts = fs.readdirSync(audit.data.runDir, {recursive: true, withFileTypes: true})
      .filter(item => item.isFile()).map(item => fs.readFileSync(path.join(item.parentPath, item.name), 'utf8')).join('\n');
    for (const token of issued) assert.ok(!artifacts.includes(token), 'issued bearer leaked into artifacts');
    const exported = await cli('export', audit.data.run, '--out', path.join(root, 'regression'));
    assert.equal(exported.code, 0);
    const sequenceTest = exported.data.files.find(file =>
      path.basename(file).includes(observation.id));
    assert.ok(sequenceTest);
    const regression = async () => (await execFile(process.execPath,
      ['--test', sequenceTest], {env: {...env, NODE_TEST_CONTEXT: undefined},
        timeout: 30000})).code;
    assert.equal(await regression(), 1);
    transformVulnerable = false;
    assert.equal(JSON.parse((await execFile(process.execPath, [observation.proof],
      {env, timeout: 20000})).stdout).verdict, 'not_reproduced');
    loginVulnerable = false;
    const fixed = await cli('verify', audit.data.run);
    assert.equal(fixed.data.proofs.find(item => item.id === observation.id)?.verdict,
      'not_reproduced', JSON.stringify(fixed.data));
    assert.equal(await regression(), 0);
  });
