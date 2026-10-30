import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import http from 'node:http';
import os from 'node:os';
import path from 'node:path';
import {randomBytes} from 'node:crypto';
import {CLI} from '../src/demo.mjs';
import {execFile} from '../src/util.mjs';

test('a proved derived login makes protected reads available to Muse access planning without an owner env token',
  {timeout: 180000}, async t => {
    const root = fs.mkdtempSync(path.join(os.tmpdir(), 'bypass-derived-access-track-'));
    t.after(() => { if (!process.env.BX_KEEP_TEST_ROOT) fs.rmSync(root, {recursive: true, force: true}); });
    const suffix = randomBytes(5).toString('hex');
    const loginPath = `/api/login-${suffix}`;
    const identityPath = `/api/me-${suffix}`;
    const publicInput = `/api/${suffix}/lookup`;
    const extraInputs = Array.from({length: 8}, (_, index) =>
      `/api/${suffix}/lookup-${index}`);
    const privateRecord = {id: `me-${suffix}`, owner: `fixture-${suffix}`,
      note: `Only the authenticated fixture session may read this record ${suffix}`};
    const issued = new Set();
    let vulnerable = true;
    const server = http.createServer(async (request, response) => {
      const url = new URL(request.url, 'http://fixture.invalid');
      const json = (status, value) => {
        response.writeHead(status, {'content-type': 'application/json', 'cache-control': 'no-store'});
        response.end(JSON.stringify(value));
      };
      if (request.method === 'GET' && url.pathname === '/') {
        response.writeHead(200, {'content-type': 'text/html', 'cache-control': 'no-store'});
        return response.end(`<a href="/openapi.json">API</a><a href="${publicInput}?mode=normal">Lookup</a>`);
      }
      if (request.method === 'GET' && url.pathname === '/openapi.json') return json(200, {
        openapi: '3.0.0', paths: {
          [loginPath]: {post: {summary: 'Login with username and password', requestBody: {
            content: {'application/json': {schema: {type: 'object', required: ['username', 'password'],
              properties: {username: {type: 'string'}, password: {type: 'string'}}}}}}}},
          [identityPath]: {get: {summary: 'Read the authenticated private record'}},
          [publicInput]: {get: {summary: 'Look up public records', parameters: [
            {name: 'mode', in: 'query', schema: {type: 'string'}, example: 'normal'}]}},
          ...Object.fromEntries(extraInputs.map(route => [route, {get: {
            summary: 'Look up another public record', parameters: [
              {name: 'mode', in: 'query', schema: {type: 'string'}, example: 'normal'}]}}])),
        }});
      if (request.method === 'POST' && url.pathname === loginPath) {
        const chunks = [];
        for await (const chunk of request) chunks.push(chunk);
        let body;
        try { body = JSON.parse(Buffer.concat(chunks).toString()); }
        catch { return json(400, {error: 'bad JSON'}); }
        if (body.username === "admin' OR '1'='1" &&
            /^bx-invalid-[0-9a-f]{24}$/.test(String(body.password ?? ''))) {
          const token = `token-${randomBytes(24).toString('hex')}`;
          issued.add(token);
          return json(200, {authentication: {token}});
        }
        return json(401, {error: 'invalid credentials'});
      }
      if (request.method === 'GET' && url.pathname === identityPath) {
        const token = String(request.headers.authorization ?? '').replace(/^Bearer /, '');
        return issued.has(token) ? json(200, privateRecord) : json(401, {error: 'denied'});
      }
      if (request.method === 'GET' && url.pathname === publicInput) {
        const records = vulnerable && ['all', 'archive'].includes(url.searchParams.get('mode')) ?
          [privateRecord] : [];
        return json(200, {records});
      }
      if (request.method === 'GET' && extraInputs.includes(url.pathname))
        return json(200, {records: []});
      return json(404, {error: 'missing'});
    });
    await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
    t.after(() => new Promise(resolve => server.close(resolve)));
    const origin = `http://127.0.0.1:${server.address().port}`;
    const scopeFile = path.join(root, 'blackbox.scope.json');
    fs.writeFileSync(scopeFile, JSON.stringify({schemaVersion: 1, target: {origin},
      include: ['/'], limits: {rps: 80, maxUrls: 80, minutes: 3,
        modelCalls: 60, tasks: 0}}));
    const decisionsFile = path.join(root, 'muse-access-input.jsonl');
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
      " const read=context.reads.find(item=>item.path===process.env.BX_IDENTITY);",
      " answer={checks:post&&read?[{loginPath:post.path,userField:'username',passwordField:'password',proofMode:'protected-status',userPayloads:[\"admin' OR '1'='1\"],tokenPointer:'/authentication/token',privatePath:read.path,principalPointer:'',why:'Observed login and denied identity route support an invalid-password control'}]:[]};",
      '}',
      "else if(system.startsWith('Allocate the next black-box investigation effort')){",
      " fs.appendFileSync(process.env.BX_DECISIONS,JSON.stringify({kind:'schedule',tracks:context.tracks})+'\\n');",
      " answer={priorities:[{name:'access',weight:10,why:'A protected read changed from denied to allowed after login'}]};",
      '}',
      "else if(system.startsWith('You are investigating whether an observed anonymous GET query input')){",
      " fs.appendFileSync(process.env.BX_DECISIONS,JSON.stringify({kind:'access',context})+'\\n');",
      " const protectedRead=context.protectedReads.find(item=>item.path===process.env.BX_IDENTITY);",
      " const publicRead=context.publicGets.find(item=>item.path===process.env.BX_PUBLIC&&item.fields.includes('mode'));",
      " answer={tests:protectedRead&&publicRead?[{family:'public lookup exposed private record',why:'The documented public lookup might return the protected record',priority:9,comparison:'object',protectedPath:protectedRead.path,subject:{method:'GET',path:publicRead.path,placement:'query',key:'mode',fixedFields:[]},controlValue:'normal',firstValue:'all',secondValue:'archive',ownerPointer:'',candidatePointer:'/records',identityField:'id',matchFields:['id','owner','note']}]:[]};",
      '}',
      "else if(system.startsWith('Map this authorized authenticated web surface'))answer={paths:[]};",
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
      BX_IDENTITY: identityPath, BX_PUBLIC: publicInput, BX_DECISIONS: decisionsFile};
    delete env.OWNER_TOKEN;
    delete env.OWNER_USER;
    delete env.OWNER_PASS;
    const audit = await execFile(process.execPath,
      [CLI, 'blackbox', origin, '--scope', scopeFile, '--project', root,
        '--json', '--non-interactive'], {cwd: root, env, timeout: 150000});
    const data = JSON.parse(audit.stdout);
    assert.ok(data.runDir, JSON.stringify(data));
    assert.equal(data.stats.beyondBudget, 0,
      'unlimited tasks must not turn the early authenticated share into a task cut');
    const webProgress = JSON.parse(fs.readFileSync(path.join(data.runDir,
      'web-progress.json'), 'utf8'));
    const webPlan = JSON.parse(fs.readFileSync(path.join(data.runDir,
      'web-probes.json'), 'utf8'));
    const earlyCandidates = webPlan.modelCoverage.find(item =>
      item.accessPrivateReadsAvailable > 0 && item.candidatesAvailable > 0);
    assert.ok(earlyCandidates?.candidatesAvailable > 20,
      'the authenticated fixture must present more leads than the old route-count allowance');
    assert.ok(webProgress.passes['derived-0-early'].planned >=
      earlyCandidates.candidatesAvailable,
    'unlimited tasks must queue every observed authenticated web lead in the early pass');
    const login = data.findings.find(item => item.kind === 'model-auth-login');
    assert.ok(login?.proof, JSON.stringify(data.findings));
    const mapped = JSON.parse(fs.readFileSync(path.join(data.runDir,
      'derived-session-recon.json'), 'utf8'));
    assert.ok(mapped.sessions.some(session => session.routes.some(route =>
      route.path === identityPath && route.status === 200)));
    const decisions = fs.readFileSync(decisionsFile, 'utf8').trim().split('\n').map(JSON.parse);
    assert.ok(decisions.some(item => item.kind === 'schedule' &&
      item.tracks.some(track => track.name === 'access' && track.count > 0)),
    'a confirmed derived bearer and a denied-to-allowed read must make the access track eligible');
    assert.ok(decisions.some(item => item.kind === 'access' &&
      item.context.protectedReads.some(read => read.path === identityPath) &&
      item.context.publicGets.some(read => read.path === publicInput)),
    'Muse must receive the protected read and observed public input in one access-planning page');
    const boundary = data.findings.find(item => item.kind === 'model-access-boundary' &&
      item.pattern === publicInput);
    assert.ok(boundary?.proof, 'the Muse-selected public input must be proved against the derived private record');
    assert.ok(boundary.webProof?.derivedLogin,
      'the sealed access proof must replay login rather than save a bearer');
    const proof = JSON.parse((await execFile(process.execPath, [boundary.proof],
      {env, timeout: 20000})).stdout);
    assert.equal(proof.verdict, 'confirmed', 'the saved access proof must acquire a fresh bearer');
    assert.ok(proof.controls.some(item => item.label === 'fresh-login-boundary' &&
      item.verdict === 'confirmed'));
    const artifactText = fs.readdirSync(data.runDir, {recursive: true, withFileTypes: true})
      .filter(item => item.isFile())
      .map(item => fs.readFileSync(path.join(item.parentPath, item.name), 'utf8')).join('\n');
    assert.doesNotMatch(artifactText, /token-[0-9a-f]{48}/,
      'fresh bearer values must not be saved in run artifacts');
    const exported = await execFile(process.execPath,
      [CLI, 'blackbox', 'export', data.run, '--project', root,
        '--out', path.join(root, 'regression'), '--json', '--non-interactive'],
      {cwd: root, env, timeout: 20000});
    assert.equal(exported.code, 0);
    const regression = JSON.parse(exported.stdout).files.find(file =>
      file.includes(boundary.id));
    assert.ok(regression, 'the derived access finding must export a regression');
    const runRegression = () => execFile(process.execPath, ['--test', regression],
      {env: {...env, NODE_TEST_CONTEXT: undefined}, timeout: 20000});
    assert.equal((await runRegression()).code, 1,
      'the exported regression must fail while private data is exposed');
    vulnerable = false;
    const fixedProof = JSON.parse((await execFile(process.execPath, [boundary.proof],
      {env, timeout: 20000})).stdout);
    assert.equal(fixedProof.verdict, 'not_reproduced');
    assert.equal((await runRegression()).code, 0,
      'the exported regression must pass after the public lookup is fixed');
  });
