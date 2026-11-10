import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import http from 'node:http';
import os from 'node:os';
import path from 'node:path';
import {randomBytes} from 'node:crypto';
import {CLI} from '../src/demo.mjs';
import {execFile} from '../src/util.mjs';

for (const authMode of ['explicit-cookie', 'auto-cookie', 'dual-fallback']) test(
  `Muse-selected ${authMode} login opens protected recon and replays red-green without saving cookies`,
  {timeout: 120000}, async t => {
    const root = fs.mkdtempSync(path.join(os.tmpdir(), 'bypass-cookie-login-cli-'));
    t.after(() => {if (!process.env.BX_KEEP_TEST_ROOT)
      fs.rmSync(root, {recursive: true, force: true});});
    const suffix = randomBytes(5).toString('hex');
    const loginPath = `/api/signin-${suffix}`;
    const identityPath = `/api/me-${suffix}`;
    const pagePath = `/member-${suffix}/home`;
    const scriptPath = `/member-${suffix}/app.js`;
    const dataPath = `/api/member-${suffix}/data`;
    const renderPath = `/api/member-${suffix}/render`;
    const username = "admin' OR '1'='1";
    const issued = new Set();
    const calls = [];
    let fixed = false, templateFixed = false;
    const json = (response, status, value) => {
      response.writeHead(status, {'content-type': 'application/json',
        'cache-control': 'no-store'});
      response.end(JSON.stringify(value));
    };
    const server = http.createServer(async (request, response) => {
      const url = new URL(request.url, 'http://fixture.invalid');
      const cookie = String(request.headers.cookie ?? '');
      const authenticated = [...issued].some(value => cookie.split('; ').includes(value));
      calls.push({method: request.method, path: url.pathname, authenticated,
        bearerAttempt: Boolean(request.headers.authorization)});
      if (request.method === 'GET' && url.pathname === '/') {
        response.writeHead(200, {'content-type': 'text/html', 'cache-control': 'no-store'});
        return response.end('<html><a href="/openapi.json">API</a></html>');
      }
      if (request.method === 'GET' && url.pathname === '/openapi.json') return json(response, 200, {
        openapi: '3.0.0', paths: {
          [loginPath]: {post: {summary: 'Sign in with username and password',
            requestBody: {content: {'application/json': {schema: {type: 'object',
              required: ['username', 'password'], properties: {
                username: {type: 'string'}, password: {type: 'string'}}}}}}}},
          [identityPath]: {get: {summary: 'Return the current member workspace'}},
        }});
      if (request.method === 'POST' && url.pathname === loginPath) {
        const chunks = [];
        for await (const chunk of request) chunks.push(chunk);
        let body;
        try {body = JSON.parse(Buffer.concat(chunks).toString());}
        catch {return json(response, 400, {error: 'invalid JSON'});}
        if (!fixed && body.username === username &&
            /^bx-invalid-[0-9a-f]{24}$/.test(String(body.password ?? ''))) {
          const session = `bx_session=${randomBytes(24).toString('hex')}`;
          issued.add(session);
          response.writeHead(200, {'content-type': 'application/json',
            'cache-control': 'no-store', 'set-cookie': `${session}; HttpOnly; SameSite=Lax; Path=/`});
          return response.end(JSON.stringify(authMode === 'dual-fallback' ?
            {ok: true, authentication: {token: `decoy-${randomBytes(18).toString('hex')}`}} :
            {ok: true}));
        }
        return json(response, 401, {error: 'invalid credentials'});
      }
      if (request.method === 'GET' && url.pathname === identityPath)
        return authenticated ? json(response, 200, {workspace: pagePath}) :
          json(response, 401, {error: 'login required'});
      if (request.method === 'GET' && url.pathname === pagePath) {
        if (!authenticated) return json(response, 401, {error: 'login required'});
        response.writeHead(200, {'content-type': 'text/html', 'cache-control': 'no-store'});
        return response.end(`<html><script src="${scriptPath}"></script></html>`);
      }
      if (request.method === 'GET' && url.pathname === scriptPath) {
        if (!authenticated) return json(response, 401, {error: 'login required'});
        response.writeHead(200, {'content-type': 'application/javascript', 'cache-control': 'no-store'});
        return response.end(`fetch('${dataPath}');fetch('${renderPath}?q=hello');`);
      }
      if (request.method === 'GET' && url.pathname === dataPath)
        return authenticated ? json(response, 200, {member: true}) :
          json(response, 401, {error: 'login required'});
      if (request.method === 'GET' && url.pathname === renderPath) {
        if (!authenticated) return json(response, 401, {error: 'login required'});
        const input = url.searchParams.get('q') ?? '';
        const expression = /^\{\{(\d{4})\*(\d{4})\}\}$/.exec(input);
        response.writeHead(200, {'content-type': 'text/plain', 'cache-control': 'no-store'});
        return response.end(!templateFixed && expression ?
          String(Number(expression[1]) * Number(expression[2])) : input);
      }
      return json(response, 404, {error: 'not found'});
    });
    await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
    t.after(() => new Promise(resolve => server.close(resolve)));
    const origin = `http://127.0.0.1:${server.address().port}`;
    const scopePath = path.join(root, 'blackbox.scope.json');
    if (authMode === 'explicit-cookie')
      fs.writeFileSync(scopePath, JSON.stringify({schemaVersion: 1, target: {origin},
        include: ['/'], limits: {rps: 50, maxUrls: 40, minutes: 2,
          modelCalls: 24, tasks: 50}}));
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
      " const read=context.reads.find(item=>item.path===process.env.BX_IDENTITY);",
      " if(context.sessionKind!==process.env.BX_SESSION_KIND)process.exit(8);",
      " answer={checks:post&&read?[{loginPath:post.path,userField:'username',passwordField:'password',proofMode:'protected-status',userPayloads:[\"admin' OR '1'='1\"],tokenPointer:'',privatePath:read.path,why:'Synthetic input may establish a cookie session under an invalid password'}]:[]};",
      '}',
      "else if(system.includes('Interpret only the extracted'))answer={files:context.files.map(file=>({id:file.id,role:'app',why:'Observed client asset',authFlow:'',routes:[],proposals:[]}))};",
      "else if(system.includes('Assess only these independently proved'))answer={notes:[]};",
      "else if(system.includes('Continue mapping this authorized primary application'))answer={paths:[]};",
      "else if(system.startsWith('Map this authorized authenticated web surface'))answer={paths:[]};",
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
      BX_LOGIN: loginPath, BX_IDENTITY: identityPath,
      BX_SESSION_KIND: authMode === 'explicit-cookie' ? 'cookie' : 'auto'};
    const cli = async (...args) => {
      const completed = await execFile(process.execPath,
        [CLI, 'blackbox', ...args, '--project', root, '--json', '--non-interactive'],
        {cwd: root, env, timeout: 90000});
      return {code: completed.code, data: JSON.parse(completed.stdout)};
    };
    const audit = await cli(origin,
      ...(authMode === 'explicit-cookie' ? ['--scope', scopePath, '--auth', 'cookie'] :
        ['--accept-local', '--model-calls', '24', '--max-urls', '40',
          '--minutes', '2', '--max-tasks', '50']), '--rps', '30');
    assert.ok(audit.data.runDir, JSON.stringify(audit));
    const finding = audit.data.findings.find(item => item.kind === 'model-auth-login');
    const ssti = audit.data.findings.find(item => item.kind === 'ssti-arithmetic' &&
      item.pattern === renderPath);
    assert.ok(finding?.proof, JSON.stringify({root, runDir: audit.data.runDir,
      findings: audit.data.findings, results: audit.data.results}));
    assert.ok(ssti?.proof, JSON.stringify({root, runDir: audit.data.runDir,
      findings: audit.data.findings}));
    assert.equal(finding.verdict, 'confirmed');
    const derivedPath = path.join(audit.data.runDir, 'derived-session-recon.json');
    assert.ok(fs.existsSync(derivedPath), 'cookie session must start protected recon');
    const derived = JSON.parse(fs.readFileSync(derivedPath, 'utf8'));
    assert.ok(derived.sessions[0].routes.some(route => route.path === pagePath));
    assert.ok(derived.sessions[0].routes.some(route => route.path === scriptPath));
    assert.ok(derived.sessions[0].routes.some(route => route.path === dataPath));
    assert.ok(derived.sessions[0].routes.some(route => route.path === renderPath));
    assert.ok(calls.some(item => item.path === dataPath && item.authenticated),
      'protected API must be reached with the derived cookie');
    if (authMode === 'dual-fallback')
      assert.ok(calls.some(item => item.path === identityPath &&
        item.bearerAttempt && !item.authenticated),
      'a decoy bearer must fail before the cookie session succeeds');
    assert.equal((await cli('verify', audit.data.run)).code, 1);
    const artifactText = directory => fs.readdirSync(directory, {withFileTypes: true})
      .map(item => {const file = path.join(directory, item.name);
        return item.isDirectory() ? artifactText(file) : fs.readFileSync(file, 'utf8');}).join('\n');
    const artifacts = artifactText(audit.data.runDir);
    for (const session of issued) {
      assert.ok(!artifacts.includes(session), 'issued cookie leaked into run artifacts');
      assert.ok(!artifacts.includes(session.slice(session.indexOf('=') + 1)),
        'issued cookie value leaked into run artifacts');
    }
    const exported = await cli('export', audit.data.run, '--out', path.join(root, 'regression'));
    assert.equal(exported.code, 0);
    const relevant = new Set([finding.id, ssti.id]);
    const relevantTests = exported.data.files.filter(file =>
      [...relevant].some(id => path.basename(file).includes(id)));
    assert.equal(relevantTests.length, 2);
    const regression = async files => (await execFile(process.execPath,
      ['--test', ...(files ?? relevantTests)], {env: {...env, NODE_TEST_CONTEXT: undefined},
        timeout: 20000})).code;
    assert.equal(await regression(), 1);
    templateFixed = true;
    const templateVerification = await cli('verify', audit.data.run);
    assert.equal(templateVerification.code, 1, 'login bug remains until its separate fix');
    assert.equal(templateVerification.data.proofs.find(item => item.id === ssti.id)?.verdict,
      'not_reproduced');
    assert.equal(await regression(exported.data.files.filter(file =>
      file.includes(ssti.id))), 0, 'SSTI regression must clear after only the template fix');
    fixed = true;
    const verified = await cli('verify', audit.data.run);
    for (const id of relevant)
      assert.equal(verified.data.proofs.find(item => item.id === id)?.verdict,
        'not_reproduced', JSON.stringify(verified.data));
    assert.equal(await regression(), 0);
    assert.ok(calls.every(call => call.method !== 'POST' || call.path === loginPath));
  });
