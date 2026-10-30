import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import http from 'node:http';
import os from 'node:os';
import path from 'node:path';
import {randomBytes} from 'node:crypto';
import {CLI} from '../src/demo.mjs';
import {execFile} from '../src/util.mjs';

test('CLI follows a route revealed by a protected test response with the same transient session',
  {timeout: 180000}, async t => {
    const root = fs.mkdtempSync(path.join(os.tmpdir(), 'bypass-derived-feedback-'));
    t.after(() => {if (!process.env.BX_KEEP_TEST_ROOT)
      fs.rmSync(root, {recursive: true, force: true});});
    const suffix = randomBytes(5).toString('hex');
    const loginPath = '/api/login-' + suffix;
    const privatePath = '/api/me-' + suffix;
    const probePath = '/api/' + suffix + '/probe';
    const latePath = '/api/' + suffix + '/late';
    const issued = new Set(), requests = [];
    const server = http.createServer(async (request, response) => {
      const url = new URL(request.url, 'http://fixture.invalid');
      const authorized = issued.has(String(request.headers.authorization ?? '')
        .replace(/^Bearer /, ''));
      requests.push({path: url.pathname, query: url.search, authorized});
      const json = (status, body) => {
        response.writeHead(status, {'content-type': 'application/json',
          'cache-control': 'no-store'});
        response.end(JSON.stringify(body));
      };
      if (request.method === 'GET' && url.pathname === '/') {
        response.writeHead(200, {'content-type': 'text/html',
          'cache-control': 'no-store'});
        return response.end('<html><a href="/openapi.json">API</a><script src="/app.js"></script></html>');
      }
      if (request.method === 'GET' && url.pathname === '/app.js') {
        response.writeHead(200, {'content-type': 'application/javascript',
          'cache-control': 'no-store'});
        return response.end("fetch('" + probePath + "?q=baseline')");
      }
      if (request.method === 'GET' && url.pathname === '/openapi.json')
        return json(200, {openapi: '3.0.0', paths: {
          [loginPath]: {post: {summary: 'Login with username and password',
            requestBody: {content: {'application/json': {schema: {type: 'object',
              required: ['username', 'password'], properties: {
                username: {type: 'string'}, password: {type: 'string'}}}}}}}},
          [privatePath]: {get: {summary: 'Authenticated identity route'}},
          [probePath]: {get: {summary: 'Protected probe', parameters: [{
            name: 'q', in: 'query', schema: {type: 'string'}}]}}}});
      if (request.method === 'POST' && url.pathname === loginPath) {
        const chunks = [];
        for await (const chunk of request) chunks.push(chunk);
        let input;
        try {input = JSON.parse(Buffer.concat(chunks).toString());}
        catch {return json(400, {error: 'invalid JSON'});}
        if (input.username === "admin' OR '1'='1" &&
            /^bx-invalid-[0-9a-f]{24}$/.test(String(input.password ?? ''))) {
          const token = 'token-' + randomBytes(24).toString('hex');
          issued.add(token);
          return json(200, {authentication: {token}});
        }
        return json(401, {error: 'invalid credentials'});
      }
      if (url.pathname === privatePath)
        return authorized ? json(200, {workspace: 'ready'}) :
          json(401, {error: 'unauthorized'});
      if (url.pathname === probePath) {
        if (!authorized) return json(401, {error: 'unauthorized'});
        const q = url.searchParams.get('q');
        return json(200, q && q !== 'baseline' ?
          {status: 'changed', nextRoute: latePath} : {status: 'ready'});
      }
      if (url.pathname === latePath)
        return authorized ? json(200, {result: url.searchParams.get('q') ?? 'ready'}) :
          json(401, {error: 'unauthorized'});
      return json(404, {error: 'missing'});
    });
    await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
    t.after(() => new Promise(resolve => server.close(resolve)));
    const origin = 'http://127.0.0.1:' + server.address().port;
    fs.writeFileSync(path.join(root, 'blackbox.scope.json'), JSON.stringify({
      schemaVersion: 1, target: {origin}, include: ['/'],
      limits: {rps: 60, maxUrls: 100, minutes: 3, modelCalls: 70, tasks: 100}}));
    const bin = path.join(root, 'bin');
    fs.mkdirSync(bin);
    const feedbackLog = path.join(root, 'feedback.json');
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
      " answer={checks:post&&read?[{loginPath:post.path,userField:'username',passwordField:'password',proofMode:'protected-status',userPayloads:[\"admin' OR '1'='1\"],tokenPointer:'/authentication/token',privatePath:read.path,principalPointer:'',why:'Observed login and denied identity route support a synthetic invalid-password control'}]:[]};",
      '}',
      "else if(system.startsWith('Allocate the next black-box investigation effort'))answer={priorities:context.tracks.map(row=>({name:row.name,weight:row.name==='sequence'?100:1,why:'Observed protected route input'}))};",
      "else if(system.startsWith('You are planning bounded, authorized HTTP research.')){",
      " const late=context.routes.find(item=>item.path===process.env.BX_LATE&&item.kind==='read'&&item.fields.includes('q'));",
      " const probe=context.routes.find(item=>item.path===process.env.BX_PROBE&&item.kind==='read'&&item.fields.includes('q'));",
      " const route=context.derivedAvailable?(late??probe):null;",
      " answer={flows:route?[{family:'response-route-feedback',why:'Compare the observed protected query response',priority:10,as:'derived',oracle:'observation',prelude:[],subject:{method:'GET',path:route.path,placement:'query',key:'q',fixedFields:[],bodyTemplate:'',headers:[]},observe:[],controlValue:'plain',firstValue:'one',secondValue:'two',marker:'',secondMarker:'',assertion:{step:'subject',index:0,location:'body',name:''}}]:[]};",
      '}',
      "else if(system.startsWith('Continue mapping this authorized derived-test-feedback')){",
      " fs.writeFileSync(process.env.BX_FEEDBACK_LOG,JSON.stringify({identity:context.identity,paths:context.observations.map(item=>item.path)}));",
      " answer={paths:[process.env.BX_LATE+'?q=baseline']};",
      '}',
      "else if(system.includes('Interpret only the extracted'))answer={files:[]};",
      "else if(system.includes('Assess only these independently proved'))answer={notes:[]};",
      "else if(system.startsWith('Map this authorized authenticated web surface'))answer={paths:[]};",
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
    const env = {...process.env, PATH: bin + path.delimiter + process.env.PATH,
      BX_LOGIN: loginPath, BX_PRIVATE: privatePath, BX_PROBE: probePath,
      BX_LATE: latePath, BX_FEEDBACK_LOG: feedbackLog};
    const done = await execFile(process.execPath, [CLI, 'blackbox', origin,
      '--project', root, '--scope', path.join(root, 'blackbox.scope.json'),
      '--json', '--non-interactive'], {cwd: root, env, timeout: 120000});
    const audit = JSON.parse(done.stdout);
    assert.ok(audit.runDir, JSON.stringify({code: done.code, audit}));
    const coverage = JSON.parse(fs.readFileSync(path.join(audit.runDir,
      'coverage.json'), 'utf8'));
    const web = JSON.parse(fs.readFileSync(path.join(audit.runDir,
      'web-probes.json'), 'utf8'));
    assert.ok(fs.existsSync(feedbackLog), JSON.stringify({
      coverage: coverage.derivedTestResponseFollowup, requests}));
    const feedback = JSON.parse(fs.readFileSync(feedbackLog, 'utf8'));
    assert.equal(feedback.identity, 'derived-session');
    assert.ok(feedback.paths.includes(latePath));
    assert.equal(feedback.paths.filter(item => item === latePath).length, 1);
    assert.ok(coverage.derivedTestResponseFollowup?.routesAdded >= 1);
    assert.ok(coverage.derivedTestResponseFollowup?.checksExecuted >= 1);
    assert.ok(requests.some(item => item.path === latePath &&
      item.query.includes('q=one') && item.authorized),
    'Muse follow-up must execute on the newly revealed route with the transient bearer');
    assert.ok(web.modelCoverage.some(item =>
      item.discoveredVia === 'derived-test-response' && item.sessionIndex === 0));
    const derivedSessions = JSON.parse(fs.readFileSync(path.join(audit.runDir,
      'derived-session-recon.json'), 'utf8'));
    assert.equal(derivedSessions.sessions[0].coverage.testResponseFollowup.sessionIndex, 0);
    assert.match(derivedSessions.sessions[0].coverage.testResponseFollowup
      .principalFingerprint, /^[0-9a-f]{64}$/);
    const artifacts = fs.readdirSync(audit.runDir,
      {recursive: true, withFileTypes: true}).filter(item => item.isFile())
      .map(item => fs.readFileSync(path.join(item.parentPath, item.name), 'utf8'))
      .join('\n');
    assert.doesNotMatch(artifacts, /token-[0-9a-f]{48}/);
  });
