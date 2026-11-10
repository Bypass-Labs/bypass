import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import http from 'node:http';
import os from 'node:os';
import path from 'node:path';
import {randomBytes} from 'node:crypto';
import {CLI} from '../src/demo.mjs';
import {execFile} from '../src/util.mjs';

test('Muse uses a derived login as a protected-content control and replays an anonymous disclosure',
  async t => {
    const root = fs.mkdtempSync(path.join(os.tmpdir(), 'bypass-derived-content-'));
    t.after(() => fs.rmSync(root, {recursive: true, force: true}));
    const suffix = randomBytes(4).toString('hex');
    const loginPath = `/api/login-${suffix}`;
    const privatePath = `/api/private-${suffix}`;
    const publicPath = `/api/lookup-${suffix}`;
    const privateBody = JSON.stringify({record: `private-${suffix}`,
      description: `A session-only workspace record for fixture ${suffix}`,
      owner: 'fixture-owner', classification: 'private', value: 42});
    const tokens = new Set();
    const calls = [];
    let exposed = true;
    let loginVulnerable = true;
    const server = http.createServer(async (request, response) => {
      const url = new URL(request.url, 'http://fixture');
      calls.push(`${request.method} ${url.pathname}`);
      response.setHeader('content-type', 'application/json');
      response.setHeader('cache-control', 'no-store');
      if (url.pathname === '/') return response.end('<html><a href="/openapi.json">API</a><script src="/app.js"></script></html>');
      if (url.pathname === '/app.js') return response.end(
        `fetch('${publicPath}', {method: 'POST', headers: {'content-type': 'application/json'}, body: JSON.stringify({term: 'plain'})});`);
      if (url.pathname === '/openapi.json') return response.end(JSON.stringify({
        openapi: '3.0.0', paths: {
          [loginPath]: {post: {summary: 'Login with username and password',
            requestBody: {content: {'application/json': {schema: {type: 'object',
              required: ['username', 'password'], properties: {
                username: {type: 'string'}, password: {type: 'string'}}}}}}}},
          [privatePath]: {get: {summary: 'Read a session-only workspace record'}},
          [publicPath]: {post: {summary: 'Look up public workspace records by literal term or glob selector',
            requestBody: {content: {'application/json': {schema: {type: 'object',
              required: ['term'], properties: {term: {type: 'string'}}}}}}}}}}));
      if (request.method === 'POST' && url.pathname === loginPath) {
        const chunks = [];
        for await (const chunk of request) chunks.push(chunk);
        const body = JSON.parse(Buffer.concat(chunks).toString());
        if (loginVulnerable && body.username === "admin' OR '1'='1" &&
            /^bx-invalid-[0-9a-f]{24}$/.test(body.password)) {
          const token = `token-${randomBytes(18).toString('hex')}`;
          tokens.add(token);
          return response.end(JSON.stringify({authentication: {token}}));
        }
        response.statusCode = 401;
        return response.end(JSON.stringify({error: 'invalid credentials'}));
      }
      if (request.method === 'GET' && url.pathname === privatePath) {
        const bearer = String(request.headers.authorization ?? '').replace(/^Bearer /, '');
        if (tokens.has(bearer)) return response.end(privateBody);
        response.statusCode = 401;
        return response.end(JSON.stringify({error: 'unauthorized'}));
      }
      if (request.method === 'POST' && url.pathname === publicPath) {
        const chunks = [];
        for await (const chunk of request) chunks.push(chunk);
        const body = JSON.parse(Buffer.concat(chunks).toString());
        return response.end(exposed && ['wide-one', 'wide-two'].includes(body.term) ?
          privateBody : JSON.stringify({records: [], access: 'public'}));
      }
      response.statusCode = 404;
      response.end('{}');
    });
    await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
    t.after(() => new Promise(resolve => server.close(resolve)));
    const origin = `http://127.0.0.1:${server.address().port}`;
    const scopePath = path.join(root, 'blackbox.scope.json');
    fs.writeFileSync(scopePath, JSON.stringify({schemaVersion: 1, target: {origin},
      include: ['/'], identities: {identityPath: privatePath},
      limits: {rps: 50, maxUrls: 70, minutes: 3, modelCalls: 45, tasks: 45}}));
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
      ' const login=context.posts.find(item=>item.path===process.env.BX_LOGIN);',
      ' const identity=context.reads.find(item=>item.path===process.env.BX_PRIVATE);',
      ' answer={checks:login&&identity?[{loginPath:login.path,userField:"username",passwordField:"password",proofMode:"protected-status",userPayloads:["admin\' OR \'1\'=\'1"],tokenPointer:"/authentication/token",privatePath:identity.path,principalPointer:"",why:"The observed login may authenticate invalid passwords"}]:[]};',
      '}',
      "else if(system.startsWith('You are planning bounded, authorized HTTP research.')){",
      ' const protectedRead=context.protectedReadRoutes?.find(item=>item===process.env.BX_PRIVATE);',
      ' const subject=context.routes?.find(item=>item.path===process.env.BX_PUBLIC&&item.methods?.includes("POST")&&item.fields?.includes("term"));',
      ' fs.appendFileSync(process.env.BX_MODEL_LOG,JSON.stringify({protectedRead:Boolean(protectedRead),derivedAvailable:context.derivedAvailable,subject:Boolean(subject),purpose:subject?.purpose,modelPurpose:subject?.modelPurpose})+"\\n");',
      ' answer={flows:protectedRead&&subject?[{family:"session-only-content-disclosure",why:"A public lookup may return the session-only record",priority:9,as:"anonymous",oracle:"protected-body",protectedPath:protectedRead,prelude:[],subject:{method:"POST",path:subject.path,placement:"json",key:"term",fixedFields:[],bodyTemplate:"",headers:[]},observe:[],controlValue:"plain",firstValue:"wide-one",secondValue:"wide-two",marker:context.marker,secondMarker:context.secondMarker,assertion:{step:"subject",index:0,location:"body",name:""}}]:[]};',
      '}',
      "else if(system.includes('Interpret only the extracted'))answer={files:context.files.map(file=>({id:file.id,role:'app',why:'Observed client route',authFlow:'',routes:(file.routes??[]).filter(route=>route.path===process.env.BX_PUBLIC).map(route=>({path:route.path,method:route.method,purpose:'Lookup public records',parameters:[]})),proposals:[]}))};",
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
      OWNER_TOKEN: '', OWNER_USER: '', OWNER_PASS: '',
      BX_LOGIN: loginPath, BX_PRIVATE: privatePath, BX_PUBLIC: publicPath,
      BX_MODEL_LOG: path.join(root, 'model-pages.log')};
    const cli = async (...args) => {
      const completed = await execFile(process.execPath,
        [CLI, 'blackbox', ...args, '--project', root, '--json', '--non-interactive'],
        {cwd: root, env, timeout: 120000});
      return {code: completed.code, data: JSON.parse(completed.stdout)};
    };
    const audit = await cli(origin, '--scope', scopePath, '--rps', '30');
    assert.ok(audit.data.runDir, JSON.stringify(audit));
    const web = JSON.parse(fs.readFileSync(path.join(audit.data.runDir, 'web-probes.json'), 'utf8'));
    const finding = audit.data.findings.find(item =>
      item.kind === 'model-access-boundary' && item.pattern === publicPath);
    const pages = fs.readFileSync(env.BX_MODEL_LOG, 'utf8').trim().split('\n').map(JSON.parse);
    assert.ok(pages.some(item => item.derivedAvailable && item.protectedRead && item.subject),
      JSON.stringify({pages, coverage: web.modelCoverage}));
    assert.ok(pages.some(item => item.subject &&
      item.purpose === 'Look up public workspace records by literal term or glob selector' &&
      item.modelPurpose === 'Lookup public records'), JSON.stringify(pages));
    assert.ok(finding?.proof, JSON.stringify({findings: audit.data.findings,
      results: web.results, decisions: web.strategyDecisions}));
    assert.equal(finding.verdict, 'confirmed');
    assert.equal(finding.webProof.protectedAs, 'derived');
    assert.equal(finding.webProof.comparison, 'exact-body');
    assert.ok(finding.webProof.derivedLogin);
    assert.equal((await cli('verify', audit.data.run)).code, 1);
    const exported = await cli('export', audit.data.run, '--out', path.join(root, 'regression'));
    assert.equal(exported.code, 0);
    const contentRegression = exported.data.files.find(file =>
      file.endsWith(`-${finding.id}.test.mjs`));
    assert.ok(contentRegression);
    const relevant = new Set(audit.data.findings.filter(item =>
      item.proof && item.kind !== 'rate-limit-auth-gate').map(item => item.id));
    const relevantTests = exported.data.files.filter(file =>
      [...relevant].some(id => path.basename(file).includes(id)));
    assert.equal(relevantTests.length, relevant.size);
    const regression = async (files = [contentRegression]) => (await execFile(process.execPath,
      ['--test', ...files], {env: {...env, NODE_TEST_CONTEXT: undefined},
        timeout: 20000})).code;
    assert.equal(await regression(), 1);
    const artifactText = directory => fs.readdirSync(directory,
      {withFileTypes: true}).map(item => {
      const file = path.join(directory, item.name);
      return item.isDirectory() ? artifactText(file) : fs.readFileSync(file, 'utf8');
    }).join('\n');
    const artifacts = artifactText(audit.data.runDir);
    for (const token of tokens) assert.ok(!artifacts.includes(token));
    exposed = false;
    const disclosureFixed = await cli('verify', audit.data.run);
    assert.equal(disclosureFixed.data.proofs.find(item => item.id === finding.id)?.verdict,
      'not_reproduced');
    assert.equal(await regression(), 0);
    loginVulnerable = false;
    const verified = await cli('verify', audit.data.run);
    for (const id of relevant)
      assert.equal(verified.data.proofs.find(item => item.id === id)?.verdict,
        'not_reproduced', JSON.stringify(verified.data));
    assert.equal(await regression(relevantTests), 0);
    assert.ok(calls.includes(`GET ${privatePath}`));
    assert.ok(calls.includes(`POST ${publicPath}`));
  });
