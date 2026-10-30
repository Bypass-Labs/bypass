import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import http from 'node:http';
import os from 'node:os';
import path from 'node:path';
import {randomBytes} from 'node:crypto';
import {CLI} from '../src/demo.mjs';
import {execFile} from '../src/util.mjs';

test('CLI avoids retesting completed protected leads while executing deferred Muse plans',
  {timeout: 180000}, async t => {
    const root = fs.mkdtempSync(path.join(os.tmpdir(), 'bypass-derived-dedup-'));
    t.after(() => {if (!process.env.BX_KEEP_TEST_ROOT) fs.rmSync(root, {recursive: true, force: true});});
    const suffix = randomBytes(5).toString('hex');
    const loginPath = `/api/login-${suffix}`;
    const identityPath = `/api/me-${suffix}`;
    const pagePath = `/workspace-${suffix}/home`;
    const scriptPath = `/workspace-${suffix}/app.js`;
    const renderPath = `/api/${suffix}/render`;
    const issued = new Set();
    let loginCalls = 0;
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
        return response.end('<html><a href="/openapi.json">API</a></html>');
      }
      if (request.method === 'GET' && url.pathname === '/openapi.json') return json(200, {
        openapi: '3.0.0', paths: {
          [loginPath]: {post: {summary: 'Login with username and password',
            requestBody: {content: {'application/json': {schema: {type: 'object',
              required: ['username', 'password'], properties: {
                username: {type: 'string'}, password: {type: 'string'}}}}}}}},
          [identityPath]: {get: {summary: 'Return the authenticated workspace route'}}}});
      if (request.method === 'POST' && url.pathname === loginPath) {
        const chunks = [];
        for await (const chunk of request) chunks.push(chunk);
        let input;
        try {input = JSON.parse(Buffer.concat(chunks).toString());}
        catch {return json(400, {error: 'invalid JSON'});}
        if (input.username === "admin' OR '1'='1" &&
            /^bx-invalid-[0-9a-f]{24}$/.test(String(input.password ?? ''))) {
          loginCalls++;
          const token = `token-${randomBytes(24).toString('hex')}`;
          issued.add(token);
          return json(200, {authentication: {token}});
        }
        return json(401, {error: 'invalid credentials'});
      }
      if (request.method === 'GET' && url.pathname === identityPath)
        return authorized ? json(200, {workspace: pagePath}) : json(401, {error: 'unauthorized'});
      if (request.method === 'GET' && url.pathname === pagePath) {
        if (!authorized) return json(401, {error: 'unauthorized'});
        response.writeHead(200, {'content-type': 'text/html', 'cache-control': 'no-store'});
        return response.end(`<html><script src="${scriptPath}"></script></html>`);
      }
      if (request.method === 'GET' && url.pathname === scriptPath) {
        if (!authorized) return json(401, {error: 'unauthorized'});
        response.writeHead(200, {'content-type': 'text/javascript', 'cache-control': 'no-store'});
        return response.end(`function render(){return fetch('${renderPath}?q=1').then(r=>r.json())}`);
      }
      if (request.method === 'GET' && url.pathname === renderPath) {
        if (!authorized) return json(401, {error: 'unauthorized'});
        const tested = url.searchParams.get('template');
        const query = url.searchParams.get('q') ?? '';
        const result = tested && /^hex:(?:[0-9a-f]{2}){3,80}$/i.test(tested) ?
          Buffer.from(tested.slice(4), 'hex').toString('utf8') :
          tested ?? (/^hex:(?:[0-9a-f]{2}){3,80}$/i.test(query) ?
            Buffer.from(query.slice(4), 'hex').toString('utf8') :
            query.startsWith('plain') ? 'baseline' : '');
        return json(200, {result});
      }
      return json(404, {error: 'missing'});
    });
    await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
    t.after(() => new Promise(resolve => server.close(resolve)));
    const origin = `http://127.0.0.1:${server.address().port}`;
    const scopeFile = path.join(root, 'blackbox.scope.json');
    fs.writeFileSync(scopeFile, JSON.stringify({schemaVersion: 1, target: {origin}, include: ['/'],
      limits: {rps: 50, maxUrls: 70, minutes: 3, modelCalls: 80, tasks: 56}}));
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
      'const stageFile=process.env.BX_STAGE_FILE;',
      'let answer;',
      "if(system.startsWith('From only the observed authorized JSON login operations')){",
      " const post=context.posts.find(item=>item.usernameField==='username'&&item.passwordField==='password');",
      " const read=context.reads.find(item=>item.path.includes('/api/me-'));",
      " answer={checks:post&&read?[{loginPath:post.path,userField:'username',passwordField:'password',proofMode:'protected-status',userPayloads:[\"admin' OR '1'='1\"],tokenPointer:'/authentication/token',privatePath:read.path,principalPointer:'',why:'Synthetic invalid-password check on observed login and denied identity route'}]:[]};",
      '}',
      "else if(system.startsWith('Map this authorized authenticated web surface')){const routes=context.contracts.filter(item=>item.method==='GET'&&item.params.includes('q')&&item.path===process.env.BX_RENDER);answer={paths:routes.map(item=>item.path+'?q=1')};}",
      "else if(system.startsWith('Allocate the next black-box investigation effort')){answer={priorities:['web','sequence','access','session','stored','json'].map(name=>({name,weight:name==='web'?100:name==='sequence'?20:1,why:'Observed protected query input'}))};}",
      "else if(system.startsWith('You are planning bounded, authorized HTTP research.')){",
      " const route=context.routes.find(item=>item.path===process.env.BX_RENDER&&item.kind==='read'&&item.fields.includes('q'));",
      " const encoded=value=>`hex:${Buffer.from(value).toString('hex')}`;",
      " const qMarker=index=>({family:'protected-query-marker-'+index,why:'Compare encoded canaries in the observed protected query input',priority:8-index,as:'derived',oracle:'marker',prelude:[],subject:{method:'GET',path:route.path,placement:'query',key:'q',fixedFields:[],bodyTemplate:'',headers:[]},observe:[],binding:null,controlValue:'plain'+index,firstValue:encoded(context.marker+index),secondValue:encoded(context.secondMarker+index),marker:context.marker,secondMarker:context.secondMarker,assertion:{step:'subject',index:0,location:'body',name:''}});",
      " const marker={family:'protected-render-template',why:'Test a bounded template key on the observed protected GET route',priority:5,as:'derived',oracle:'marker',prelude:[],subject:{method:'GET',path:route.path,placement:'query',key:'template',fixedFields:[],bodyTemplate:'',headers:[]},observe:[],binding:null,controlValue:'plain',firstValue:encoded(context.marker),secondValue:encoded(context.secondMarker),marker:context.marker,secondMarker:context.secondMarker,assertion:{step:'subject',index:0,location:'body',name:''}};",
      " if(route&&!fs.existsSync(stageFile)){fs.writeFileSync(stageFile,'proposed');answer={flows:[...Array.from({length:7},(_,index)=>qMarker(index)),marker]};}else answer={flows:[]};",
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
      BX_RENDER: renderPath, BX_STAGE_FILE: path.join(root, 'model-stage')};
    const done = await execFile(process.execPath,
      [CLI, 'blackbox', origin, '--scope', scopeFile, '--project', root, '--json', '--non-interactive'],
      {cwd: root, env, timeout: 120000});
    const audit = JSON.parse(done.stdout);
    assert.ok(audit.runDir, JSON.stringify({code: done.code, audit}));
    const web = JSON.parse(fs.readFileSync(path.join(audit.runDir, 'web-probes.json'), 'utf8'));
    const progress = JSON.parse(fs.readFileSync(path.join(audit.runDir, 'web-progress.json'), 'utf8'));
    const derived = JSON.parse(fs.readFileSync(path.join(audit.runDir,
      'derived-session-recon.json'), 'utf8'));
    assert.ok(derived.sessions[0]?.coverage?.earlyWebChecks >= 1);
    assert.ok(derived.sessions[0]?.coverage?.earlyWebCut >= 1,
      'Muse accepted more protected experiments than the early task share could execute');
    assert.equal(derived.sessions[0]?.coverage?.protectedInputsAvailable, 1);
    assert.equal(derived.sessions[0]?.coverage?.protectedInputsUntestedAfterEarly, 0,
      'the early derived experiment already covered the sole observed input key');
    assert.ok(web.strategyDecisions.some(item => item.mode === 'http-sequence' &&
      item.path === renderPath && item.requestShape?.key === 'template' &&
      item.accepted && item.deferred), 'the novel-key plan must be accepted, not rejected');
    assert.ok(progress.passes['derived-0-late']?.completed >= 1,
      'the late pass must execute an accepted deferred plan even after q was checked');
    const generic = web.results.filter(item => item.discoveredVia === 'derived-session' &&
      item.lead?.path === renderPath && item.lead?.as === 'derived' &&
      !item.kind.startsWith('model-') && !['untested', 'blocked'].includes(item.verdict));
    assert.ok(generic.length > 0,
      'the early protected pass must complete a generic lead to exercise deduplication');
    const identity = item => JSON.stringify([item.kind, item.lead.path,
      item.lead.parameter ?? null, item.lead.as ?? 'anonymous', item.lead.base ?? null,
      item.lead.style ?? null, item.lead.family ?? null,
      item.lead.controlValue ?? null, item.lead.firstValue ?? null,
      item.lead.secondValue ?? null]);
    const counts = new Map();
    for (const item of generic) counts.set(identity(item), (counts.get(identity(item)) ?? 0) + 1);
    const repeated = [...counts.values()].filter(count => count > 1);
    assert.deepEqual(repeated, [],
      'a completed protected lead must not consume late-pass requests a second time');
    assert.equal(web.cut, 0, 'executed deferrals must not remain in the final cut count');
    const deferredResult = web.results.find(item => item.kind === 'model-http-sequence' &&
      item.discoveredVia === 'derived-session' && item.lead?.path === renderPath &&
      item.lead?.parameter === 'template');
    assert.ok(deferredResult && deferredResult.verdict !== 'untested' &&
      deferredResult.evidence?.length,
    'the accepted deferred Muse plan must produce a recorded execution verdict');
    assert.ok(loginCalls > 1, 'the protected plan must obtain fresh sessions while it executes');
  });
