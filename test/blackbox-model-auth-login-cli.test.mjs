import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import http from 'node:http';
import os from 'node:os';
import path from 'node:path';
import {randomBytes} from 'node:crypto';
import {CLI} from '../src/demo.mjs';
import {execFile} from '../src/util.mjs';

for (const proofMode of ['principal', 'protected-status', 'adaptive-status']) test(
  `blind CLI Muse ${proofMode} login check confirms bypass and replays a fix without saving tokens`, async t => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'bypass-auth-login-cli-'));
  t.after(() => fs.rmSync(root, {recursive: true, force: true}));
  const suffix = randomBytes(4).toString('hex');
  const loginPath = `/api/login-${suffix}`;
  const privatePath = `/api/me-${suffix}`;
  const protectedPage = `/app/private-${suffix}`;
  const protectedScript = `/app/private-${suffix}.js`;
  const secondPath = `/api/inside-${suffix}`;
  const userPayloads = ["admin' OR '1'='1", "root' OR '2'='2"];
  const issued = new Set(), calls = [], loginUsers = [];
  let vulnerable = true;
  const server = http.createServer(async (request, response) => {
    const url = new URL(request.url, 'http://fixture');
    calls.push(`${request.method} ${url.pathname}`);
    response.setHeader('content-type', 'application/json');
    response.setHeader('cache-control', 'no-store');
    if (url.pathname === '/') return response.end('<html><a href="/openapi.json">API</a></html>');
    if (url.pathname === '/openapi.json') return response.end(JSON.stringify({
      openapi: '3.0.0', paths: {
        [loginPath]: {post: {summary: 'Login with username and password',
          requestBody: {content: {'application/json': {schema: {type: 'object',
            required: ['username', 'password'], properties: {
              username: {type: 'string'}, password: {type: 'string'}}}}}}}},
        [privatePath]: {get: {summary: 'Return the authenticated principal'}}}}));
    if (request.method === 'POST' && url.pathname === loginPath) {
      const chunks = [];
      for await (const chunk of request) chunks.push(chunk);
      const body = JSON.parse(Buffer.concat(chunks).toString());
      loginUsers.push(body.username);
      if (proofMode === 'protected-status' && body.username === userPayloads[1]) {
        response.statusCode = 500;
        return response.end(JSON.stringify({error: 'unsupported syntax'}));
      }
      if (vulnerable && (proofMode === 'adaptive-status' ? body.username === userPayloads[0] :
          userPayloads.includes(body.username)) &&
          /^bx-invalid-[0-9a-f]{24}$/.test(body.password)) {
        const token = `token-${randomBytes(18).toString('hex')}`;
        issued.add(token);
        return response.end(JSON.stringify({authentication: {token}}));
      }
      response.statusCode = 401;
      return response.end(JSON.stringify({error: 'invalid credentials'}));
    }
    if (request.method === 'GET' && url.pathname === privatePath) {
      const bearer = String(request.headers.authorization ?? '').replace(/^Bearer /, '');
      if (proofMode !== 'principal') {
        if (issued.has(bearer)) return response.end(JSON.stringify({path: protectedPage}));
        response.statusCode = 401;
        return response.end(JSON.stringify({error: 'unauthorized'}));
      }
      return response.end(issued.has(bearer) ?
        JSON.stringify({user: {id: 'owner-42', role: 'member'}, path: protectedPage}) : '{}');
    }
    if ([protectedPage, protectedScript, secondPath].includes(url.pathname)) {
      const bearer = String(request.headers.authorization ?? '').replace(/^Bearer /, '');
      if (!issued.has(bearer)) {
        response.statusCode = 401;
        return response.end(JSON.stringify({error: 'unauthorized'}));
      }
      if (url.pathname === protectedPage) {
        response.setHeader('content-type', 'text/html');
        return response.end(`<html data-session="${bearer}"><script src="${protectedScript}"></script>` +
          '<script src="https://outside.example.invalid/external.js"></script></html>');
      }
      if (url.pathname === protectedScript) {
        response.setHeader('content-type', 'text/javascript');
        return response.end(`const session="${bearer}";fetch('${secondPath}');`);
      }
      return response.end(JSON.stringify({result: 'private', session: bearer}));
    }
    response.statusCode = 404;
    response.end('{}');
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  t.after(() => new Promise(resolve => server.close(resolve)));
  const origin = `http://127.0.0.1:${server.address().port}`;
  const scopePath = path.join(root, 'blackbox.scope.json');
  fs.writeFileSync(scopePath, JSON.stringify({schemaVersion: 1, target: {origin},
    include: ['/'], limits: {rps: 50, maxUrls: 40, minutes: 3,
      modelCalls: 30, tasks: 30}}));
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
    ' const login=context.posts.find(item=>item.path===process.env.BX_LOGIN&&item.usernameField===\'username\'&&item.passwordField===\'password\');',
    ' const identity=context.reads.find(item=>item.path===process.env.BX_PRIVATE);',
    " const status=process.env.BX_PROOF_MODE!=='principal';",
    " const adaptive=process.env.BX_PROOF_MODE==='adaptive-status';",
    " const followup=Array.isArray(context.priorAttempts)&&context.priorAttempts.length>0;",
    " if(adaptive&&followup&&/bx-invalid-[0-9a-f]{24}|token-[0-9a-f]{36}/.test(JSON.stringify(context.priorAttempts)))process.exit(9);",
    " const probes=adaptive?(followup?[\"admin' OR '1'='1\"]:[\"nobody' OR '9'='8\"]):[\"admin' OR '1'='1\",\"root' OR '2'='2\"];",
    " answer={checks:login&&identity?[{loginPath:login.path,userField:'username',passwordField:'password',proofMode:status?'protected-status':'principal',userPayloads:probes,tokenPointer:'/authentication/token',privatePath:identity.path,principalPointer:status?'':'/user/id',why:followup?'Revised synthetic input after denied first probe':'The observed login input may authenticate with invalid passwords'}]:[]};",
    '}',
    "else if(system.includes('Interpret only the extracted'))answer={files:[]};",
    "else if(system.includes('Assess only these independently proved'))answer={notes:[]};",
    "else if(system.includes('Continue mapping this authorized primary application'))answer={paths:[]};",
    "else if(system.startsWith('Map this authorized authenticated web surface'))answer={paths:[process.env.BX_SECOND+'?id=7']};",
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
    BX_LOGIN: loginPath, BX_PRIVATE: privatePath, BX_SECOND: secondPath,
    BX_PROOF_MODE: proofMode};
  const cli = async (...args) => {
    const completed = await execFile(process.execPath,
      [CLI, 'blackbox', ...args, '--project', root, '--json', '--non-interactive'],
      {cwd: root, env, timeout: 90000});
    return {code: completed.code, data: JSON.parse(completed.stdout)};
  };
  const audit = await cli(origin, '--scope', scopePath, '--rps', '20');
  assert.ok(audit.data.runDir, JSON.stringify(audit));
  const web = JSON.parse(fs.readFileSync(path.join(audit.data.runDir, 'web-probes.json'), 'utf8'));
  const surface = JSON.parse(fs.readFileSync(path.join(audit.data.runDir, 'surface.json'), 'utf8'));
  assert.ok(surface.authBodyOperations.some(item => item.path === loginPath &&
    item.usernameField === 'username' && item.passwordField === 'password'),
    JSON.stringify(surface.authBodyOperations));
  assert.ok(web.strategyDecisions.some(item => item.mode === 'auth-login' && item.accepted),
    JSON.stringify(web.strategyDecisions));
  const finding = audit.data.findings.find(item => item.kind === 'model-auth-login');
  assert.ok(finding?.proof, JSON.stringify({findings: audit.data.findings,
    results: web.results, decisions: web.strategyDecisions}));
  assert.equal(finding.verdict, 'confirmed');
  const derivedPath = path.join(audit.data.runDir, 'derived-session-recon.json');
  assert.ok(fs.existsSync(derivedPath), 'confirmed session must start protected recon');
  const derived = JSON.parse(fs.readFileSync(derivedPath, 'utf8'));
  assert.ok(derived.sessions[0].routes.some(route => route.path === protectedPage));
  assert.ok(derived.sessions[0].routes.some(route => route.path === protectedScript));
  assert.ok(derived.sessions[0].routes.some(route => route.path === secondPath));
  assert.ok(calls.includes(`GET ${secondPath}`), 'second protected GET must be requested in this run');
  assert.ok(derived.sessions[0].coverage.offOriginRejected > 0);
  assert.ok(audit.data.coverage.derivedSessionRecon.routes >= 3);
  if (proofMode !== 'principal')
    assert.deepEqual([finding.webProof.proofMode, finding.webProof.userPayloads],
      ['protected-status', [userPayloads[0]]]);
  if (proofMode === 'adaptive-status') {
    assert.ok(loginUsers.includes("nobody' OR '9'='8"));
    assert.ok(loginUsers.includes(userPayloads[0]));
    assert.ok(web.strategyDecisions.filter(item => item.mode === 'auth-login' && item.accepted).length >= 2);
    assert.ok(web.modelCoverage.some(item => item.authFollowupCalls === 1));
  }
  assert.equal((await cli('verify', audit.data.run)).code, 1);
  const sealed = fs.readFileSync(path.join(audit.data.runDir,
    `poc/${finding.id}/spec.json`), 'utf8');
  const evidence = fs.readFileSync(path.join(audit.data.runDir, 'evidence.jsonl'), 'utf8');
  assert.equal(sealed.includes('bx-invalid-'), false);
  assert.equal(evidence.includes('token-'), false);
  const artifactText = directory => fs.readdirSync(directory, {withFileTypes: true}).map(item => {
    const file = path.join(directory, item.name);
    return item.isDirectory() ? artifactText(file) : fs.readFileSync(file, 'utf8');
  }).join('\n');
  const artifacts = artifactText(audit.data.runDir);
  for (const token of issued) assert.ok(!artifacts.includes(token), 'issued bearer leaked into artifacts');
  const exported = await cli('export', audit.data.run, '--out', path.join(root, 'regression'));
  assert.equal(exported.code, 0);
  const regression = async () => (await execFile(process.execPath,
    ['--test', ...exported.data.files], {env: {...env, NODE_TEST_CONTEXT: undefined},
      timeout: 20000})).code;
  assert.equal(await regression(), 1);
  vulnerable = false;
  assert.equal((await cli('verify', audit.data.run)).code, 0);
  assert.equal(await regression(), 0);
  if (proofMode === 'protected-status') {
    const fixed = await cli(origin, '--scope', scopePath, '--rps', '20');
    assert.ok(fixed.data.runDir, JSON.stringify(fixed));
    assert.equal(fs.existsSync(path.join(fixed.data.runDir, 'derived-session-recon.json')), false);
    assert.equal(fixed.data.coverage.derivedSessionRecon.sessions, 0);
  }
  assert.ok(calls.every(call => !call.startsWith('POST ') || call === `POST ${loginPath}`));
});
