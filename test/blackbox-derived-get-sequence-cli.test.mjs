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

for (const leadingTrack of ['sequence', 'access']) test(
  `CLI executes an HTTP sequence with ${leadingTrack} ranked first alongside a large web backlog and replays fresh login`,
  {timeout: 180000}, async t => {
    const root = fs.mkdtempSync(path.join(os.tmpdir(), 'bypass-derived-get-flow-'));
    t.after(() => fs.rmSync(root, {recursive: true, force: true}));
    const suffix = randomBytes(5).toString('hex');
    const loginPath = `/api/login-${suffix}`;
    const identityPath = `/api/me-${suffix}`;
    const pagePath = `/workspace-${suffix}/home`;
    const scriptPath = `/workspace-${suffix}/app.js`;
    const transformPath = `/api/${suffix}/render`;
    const accessPath = `/api/${suffix}/lookup`;
    const privateRecord = {id: `private-${suffix}`, owner: `fixture-${suffix}`,
      note: `Only the authenticated fixture session may read this ${suffix}`};
    const backlogPaths = Array.from({length: 24}, (_, index) =>
      `/api/${suffix}/browse-${index}`);
    let loginVulnerable = true, transformVulnerable = true;
    const languageHeaders = [];
    const issued = new Set();
    const server = http.createServer(async (request, response) => {
      const url = new URL(request.url, 'http://fixture.invalid');
      const bearer = String(request.headers.authorization ?? '').replace(/^Bearer /, '');
      const authorized = issued.has(bearer);
      const json = (status, body) => {
        response.writeHead(status, {'content-type': 'application/json', 'cache-control': 'no-store'});
        response.end(JSON.stringify(body));
      };
      if (request.method === 'GET' && url.pathname === '/') {
        response.writeHead(200, {'content-type': 'text/html', 'cache-control': 'no-store'});
        return response.end(`<html><a href="/openapi.json">API</a>` +
          `<a href="${accessPath}?mode=normal">Lookup</a></html>`);
      }
      if (request.method === 'GET' && url.pathname === '/openapi.json') return json(200, {
        openapi: '3.0.0', paths: {
          [loginPath]: {post: {summary: 'Login with username and password',
            requestBody: {content: {'application/json': {schema: {type: 'object',
              required: ['username', 'password'], properties: {
                username: {type: 'string'}, password: {type: 'string'}}}}}}}},
          [identityPath]: {get: {summary: 'Return the authenticated workspace route'}},
          [accessPath]: {get: {summary: 'Look up public records', parameters: [
            {name: 'mode', in: 'query', schema: {type: 'string'}, example: 'normal'}]}}}});
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
      if (request.method === 'GET' && url.pathname === identityPath)
        return authorized ? json(200, {...privateRecord, workspace: pagePath}) :
          json(401, {error: 'unauthorized'});
      if (request.method === 'GET' && url.pathname === accessPath)
        return json(200, {records: ['all', 'archive'].includes(url.searchParams.get('mode')) ?
          [privateRecord] : []});
      if (request.method === 'GET' && url.pathname === pagePath) {
        if (!authorized) return json(401, {error: 'unauthorized'});
        response.writeHead(200, {'content-type': 'text/html', 'cache-control': 'no-store'});
        return response.end(`<html><script src="${scriptPath}"></script></html>`);
      }
      if (request.method === 'GET' && url.pathname === scriptPath) {
        if (!authorized) return json(401, {error: 'unauthorized'});
        response.writeHead(200, {'content-type': 'text/javascript', 'cache-control': 'no-store'});
        return response.end(`async function render(){return fetch('${transformPath}?q=1').then(r=>r.json())}` +
          backlogPaths.map((route, index) =>
            `async function browse${index}(){return fetch('${route}?q=1').then(r=>r.json())}`).join(''));
      }
      if (request.method === 'GET' && backlogPaths.includes(url.pathname))
        return authorized ? json(200, {items: [{id: 1, name: 'sample'}]}) :
          json(401, {error: 'unauthorized'});
      if (request.method === 'GET' && url.pathname === transformPath) {
        if (!authorized) return json(401, {error: 'unauthorized'});
        languageHeaders.push(request.headers['accept-language'] ?? '');
        const value = url.searchParams.get('q') ?? '';
        const result = transformVulnerable && /^hex:(?:[0-9a-f]{2}){3,80}$/i.test(value) ?
          Buffer.from(value.slice(4), 'hex').toString('utf8') : value;
        return json(200, {result});
      }
      return json(404, {error: 'missing'});
    });
    await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
    t.after(() => new Promise(resolve => server.close(resolve)));
    const origin = `http://127.0.0.1:${server.address().port}`;
    const scopeFile = path.join(root, 'blackbox.scope.json');
    fs.writeFileSync(scopeFile, JSON.stringify({schemaVersion: 1, target: {origin}, include: ['/'],
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
      " const post=context.posts.find(item=>item.usernameField==='username'&&item.passwordField==='password');",
      " const read=context.reads.find(item=>item.path.includes('/api/me-'));",
      " answer={checks:post&&read?[{loginPath:post.path,userField:'username',passwordField:'password',proofMode:'protected-status',userPayloads:[\"admin' OR '1'='1\"],tokenPointer:'/authentication/token',privatePath:read.path,principalPointer:'',why:'Synthetic invalid-password check on observed login and denied identity route'}]:[]};",
      '}',
      "else if(system.startsWith('Map this authorized authenticated web surface')){const route=context.contracts.find(item=>item.method==='GET'&&item.params.includes('q')&&item.path===process.env.BX_TRANSFORM);answer={paths:route?[route.path+'?q=1']:[]};}",
      "else if(system.startsWith('Allocate the next black-box investigation effort')){const first=process.env.BX_LEADING_TRACK==='access'?'access':'sequence';answer={priorities:[first,first==='access'?'sequence':'web',first==='access'?'web':'access','json','stored','session'].map(name=>({name,weight:name==='sequence'?100:name==='access'?80:name==='web'?40:1,why:'Observed protected and public query inputs'}))};}",
      "else if(system.startsWith('You are investigating whether an observed anonymous GET query input')){",
      " const privateRead=context.protectedReads.find(item=>item.path===process.env.BX_IDENTITY);",
      " const publicRead=context.publicGets.find(item=>item.path===process.env.BX_ACCESS&&item.fields.includes('mode'));",
      " answer={tests:process.env.BX_LEADING_TRACK==='access'&&privateRead&&publicRead?[{family:'public lookup exposed private record',why:'Observed public lookup may disclose the private identity record',priority:9,comparison:'object',protectedPath:privateRead.path,subject:{method:'GET',path:publicRead.path,placement:'query',key:'mode',fixedFields:[]},controlValue:'normal',firstValue:'all',secondValue:'archive',ownerPointer:'',candidatePointer:'/records',identityField:'id',matchFields:['id','owner','note']}]:[]};",
      '}',
      "else if(system.startsWith('You are planning bounded, authorized HTTP research.')){",
      " const route=context.routes.find(item=>item.path===process.env.BX_TRANSFORM&&item.kind==='read'&&item.fields.includes('q'));",
      " const encoded=value=>`hex:${Buffer.from(value).toString('hex')}`;",
      " answer={flows:route?[{family:'server-rendered-expression',why:'Observed protected GET transforms a query value',priority:8,as:'derived',oracle:'marker',prelude:[],subject:{method:'GET',path:route.path,placement:'query',key:'q',fixedFields:[],bodyTemplate:'',headers:[{name:'Accept-Language',value:'en-US'}]},observe:[],controlValue:'plain',firstValue:encoded(context.marker),secondValue:encoded(context.secondMarker),marker:context.marker,secondMarker:context.secondMarker,assertion:{step:'subject',index:0,location:'body',name:''}}]:[]};",
      '}',
      "else if(system.includes('Interpret only the extracted'))answer={files:[]};",
      "else if(system.includes('Assess only these independently proved'))answer={notes:[]};",
      "else if(system.includes('Continue mapping this authorized primary application'))answer={paths:[]};",
      "else if(system.includes('mapping an authorized web API'))answer={paths:[],notes:[]};",
      "else if(system.includes('Propose bounded GET access-control'))answer={tasks:[]};",
      "else if(system.includes('Rank only the supplied observed read-only web-test candidates')){if(context.candidates?.some(item=>item.path===process.env.BX_TRANSFORM))fs.appendFileSync(process.env.BX_WEB_PLAN_FILE,new Date().toISOString()+'\\n');answer={priorities:[],strategies:[],experiments:[]};}",
      'else {',
      " const schema=JSON.parse(fs.readFileSync(value('--output-schema'),'utf8'));",
      " const blank=s=>s?.type==='object'?Object.fromEntries((s.required??[]).map(key=>[key,blank(s.properties?.[key])])):s?.type==='array'?[]:s?.type==='integer'||s?.type==='number'?0:s?.type==='boolean'?false:s?.enum?.[0]??'';",
      ' answer=blank(schema);',
      '}',
      "console.log(JSON.stringify({payload:{kind:'run_terminal',terminal:'completed',text:JSON.stringify(answer)}}));",
    ].join('\n') + '\n', {mode: 0o700});
    const env = {...process.env, PATH: `${bin}${path.delimiter}${process.env.PATH}`,
      BX_TRANSFORM: transformPath, BX_ACCESS: accessPath, BX_IDENTITY: identityPath,
      BX_LEADING_TRACK: leadingTrack,
      BX_WEB_PLAN_FILE: path.join(root, 'protected-web-planning')};
    const cli = async (...args) => {
      const done = await execFile(process.execPath,
        [CLI, 'blackbox', ...args, '--project', root, '--json', '--non-interactive'],
        {cwd: root, env, timeout: 120000});
      return {code: done.code, data: JSON.parse(done.stdout)};
    };
    const audit = await cli(origin, '--scope', scopeFile);
    assert.ok(audit.data.runDir, JSON.stringify(audit));
    const observation = audit.data.findings.find(item => item.kind === 'model-http-sequence' &&
      item.pattern === transformPath);
    const web = JSON.parse(fs.readFileSync(path.join(audit.data.runDir, 'web-probes.json'), 'utf8'));
    assert.ok(web.modelCoverage.some(item => item.discoveredVia === 'derived-session' &&
      item.candidatesAvailable > 60), 'the protected pass must have a substantial candidate backlog');
    const attempts = fs.readFileSync(path.join(audit.data.runDir, 'evidence.jsonl'), 'utf8')
      .trim().split('\n').map(line => JSON.parse(line))
      .filter(item => item.kind === 'model-http-sequence-attempt' && item.as === 'derived' &&
        item.path === transformPath);
    assert.ok(attempts.length, 'a Muse-selected derived HTTP sequence must send real requests');
    if (leadingTrack === 'access') {
      const accessAttempts = fs.readFileSync(path.join(audit.data.runDir, 'evidence.jsonl'), 'utf8')
        .trim().split('\n').map(line => JSON.parse(line))
        .filter(item => item.kind === 'model-access-boundary-attempt' && item.path === accessPath);
      assert.ok(accessAttempts.length, 'Muse-ranked access work must execute before sequence work');
      assert.ok(Date.parse(accessAttempts[0].at) <= Date.parse(attempts[0].at),
        'access work must execute before a second-ranked HTTP sequence');
    }
    const firstWebPlan = fs.readFileSync(env.BX_WEB_PLAN_FILE, 'utf8').trim().split('\n')[0];
    assert.ok(Number.isFinite(Date.parse(firstWebPlan)),
      'Muse must review the protected web candidate backlog');
    assert.ok(web.modelCoverage.some(item => item.earlyWebChecksExecuted > 0),
      'the web verifier pool must execute checks while HTTP research is scheduled');
    const savedRun = JSON.parse(fs.readFileSync(path.join(audit.data.runDir, 'run.json'), 'utf8'));
    assert.ok(Date.parse(attempts[0].at) < Date.parse(savedRun.startedAt) + 135000,
      'the derived attempt must occur before the three-minute run reserves report time');
    assert.ok(observation, JSON.stringify({findings: audit.data.findings,
      decisions: web.strategyDecisions, results: web.results}));
    assert.equal(observation.verdict, 'observed');
    assert.equal(observation.severity, 'unrated');
    assert.equal(observation.webProof.as, 'derived');
    assert.ok(observation.webProof.derivedLogin);
    assert.ok(web.strategyDecisions.some(item => item.mode === 'http-sequence' && item.accepted));
    assert.ok(languageHeaders.includes('en-US'),
      'the derived GET executor must forward a reviewed noncredential header');
    const before = await execFile(process.execPath, [observation.proof], {env, timeout: 20000});
    const replay = JSON.parse(before.stdout);
    assert.equal(replay.verdict, 'observed');
    assert.ok(replay.controls.some(item => item.label === 'fresh-login-boundary' &&
      item.verdict === 'confirmed'));
    assert.ok(replay.controls.some(item => item.label === 'protected-route-boundary' &&
      item.anonymousStatus === 401 && item.invalidBearerStatus === 401));
    const artifacts = fs.readdirSync(audit.data.runDir, {recursive: true, withFileTypes: true})
      .filter(item => item.isFile()).map(item => fs.readFileSync(path.join(item.parentPath, item.name), 'utf8')).join('\n');
    assert.doesNotMatch(artifacts, /token-[0-9a-f]{48}/);
    assert.equal((await cli('verify', audit.data.run)).code, 1);
    const exported = await cli('export', audit.data.run, '--out', path.join(root, 'regression'));
    assert.equal(exported.code, 0);
    const regression = async () => (await execFile(process.execPath,
      ['--test', ...exported.data.files], {env: {...env, NODE_TEST_CONTEXT: undefined},
        timeout: 30000})).code;
    assert.equal(await regression(), 1);
    transformVulnerable = false;
    assert.equal(JSON.parse((await execFile(process.execPath, [observation.proof],
      {env, timeout: 20000})).stdout).verdict, 'not_reproduced');
    loginVulnerable = false;
    assert.equal((await cli('verify', audit.data.run)).code, 0);
    assert.equal(await regression(), 0);
  });
