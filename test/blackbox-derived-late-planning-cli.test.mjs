import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import http from 'node:http';
import os from 'node:os';
import path from 'node:path';
import {randomBytes} from 'node:crypto';
import {CLI} from '../src/demo.mjs';
import {execFile} from '../src/util.mjs';
import {protectedPlanningDeadline, researchReportReserveMs, remainingDeferredCut,
  reconciledPassResults} from '../src/blackbox/index.mjs';

test('the user time window leaves a bounded proof reserve without stranding a fifth of research time', () => {
  assert.equal(researchReportReserveMs(5 * 60_000), 30_000);
  assert.equal(researchReportReserveMs(15 * 60_000), 90_000);
});

test('authenticated recon finishing after the original early window still gets Muse planning time', () => {
  const start = 1_000_000;
  const researchDeadline = start + 15 * 60_000;
  const originalEarlyDeadline = start + 6 * 60_000;
  const reconFinishedAt = start + 8 * 60_000;
  assert.ok(reconFinishedAt > originalEarlyDeadline);
  const planningDeadline = protectedPlanningDeadline(reconFinishedAt,
    originalEarlyDeadline, researchDeadline);
  assert.ok(planningDeadline > reconFinishedAt + 60_000,
    'the mapped protected routes need a usable post-recon planning window');
  assert.ok(planningDeadline < researchDeadline - 60_000,
    'later protected execution must retain research time');
  assert.equal(protectedPlanningDeadline(start + 60_000,
    originalEarlyDeadline, researchDeadline), originalEarlyDeadline);
  const primaryFinishedLate = start + 11 * 60_000;
  const primaryPlanningDeadline = protectedPlanningDeadline(primaryFinishedLate,
    start + 10 * 60_000, researchDeadline);
  assert.ok(primaryPlanningDeadline > primaryFinishedLate,
    'late protected recon must still leave a primary Muse planning window');
  assert.ok(primaryPlanningDeadline < researchDeadline,
    'the primary window must leave time for the later protected pass');
});

test('deferred cuts are reconciled by lead identity, including unmatched leads', () => {
  const early = {cut: 4, cutLeadKeys: ['completed', 'still-cut', 'early-only', 'opaque']};
  const later = {completedLeadKeys: ['completed', 'other'], cutLeadKeys: ['still-cut']};
  assert.equal(remainingDeferredCut(early, later), 2);
  assert.equal(remainingDeferredCut(early, {completedLeadKeys: [], cutLeadKeys: []}), 4);
  assert.equal(remainingDeferredCut({cut: 2, cutLeadKeys: ['same', 'same']},
    {completedLeadKeys: ['same'], cutLeadKeys: []}), 1);
  assert.equal(remainingDeferredCut({cut: 2, cutLeadKeys: ['queued', 'early-only']},
    {completedLeadKeys: [], cutLeadKeys: [], results: [
      {leadKey: 'queued', verdict: 'untested'}]}), 1,
  'a later queued task must not also be reported as beyond budget');
});

test('a later execution replaces only the matching earlier untested plan record', () => {
  const early = {results: [
    {proposalId: 'carried-a', verdict: 'untested'},
    {proposalId: 'still-pending', verdict: 'untested'},
    {proposalId: 'carried-a', verdict: 'inconclusive'},
  ]};
  assert.deepEqual(reconciledPassResults(early, new Set(['carried-a'])), [
    early.results[1], early.results[2],
  ]);
  const deferredWeb = {results: [
    {leadKey: 'web-a', verdict: 'untested'},
    {leadKey: 'web-b', verdict: 'untested'},
  ]};
  assert.deepEqual(reconciledPassResults(deferredWeb, new Set(['web-a'])),
    [deferredWeb.results[1]]);
});

test('CLI keeps planning protected routes after an early anonymous derived-session check',
  {timeout: 180000}, async t => {
    const root = fs.mkdtempSync(path.join(os.tmpdir(), 'bypass-derived-late-flow-'));
    t.after(() => {if (!process.env.BX_KEEP_TEST_ROOT) fs.rmSync(root, {recursive: true, force: true});});
    const suffix = randomBytes(5).toString('hex');
    const loginPath = `/api/login-${suffix}`;
    const identityPath = `/api/me-${suffix}`;
    const pagePath = `/workspace-${suffix}/home`;
    const scriptPath = `/workspace-${suffix}/app.js`;
    const transformPath = `/api/${suffix}/render`;
    const echoPath = `/api/${suffix}/echo`;
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
        if (loginVulnerable && input.username === "admin' OR '1'='1" &&
            /^bx-invalid-[0-9a-f]{24}$/.test(String(input.password ?? ''))) {
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
        return response.end(`async function render(){fetch('${echoPath}?q=1');return fetch('${transformPath}?q=1').then(r=>r.json())}`);
      }
      if (request.method === 'GET' && url.pathname === echoPath)
        return json(200, {result: url.searchParams.get('q') ?? ''});
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
      limits: {rps: 50, maxUrls: 70, minutes: 3, modelCalls: 80, tasks: 90}}));
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
      "else if(system.startsWith('Map this authorized authenticated web surface')){const routes=context.contracts.filter(item=>item.method==='GET'&&item.params.includes('q')&&[process.env.BX_TRANSFORM,process.env.BX_ECHO].includes(item.path));answer={paths:routes.map(item=>item.path+'?q=1')};}",
      "else if(system.startsWith('You are planning bounded, authorized HTTP research.')){",
      " const early=!fs.existsSync(stageFile);",
      " const route=context.routes.find(item=>item.path===(early?process.env.BX_ECHO:process.env.BX_TRANSFORM)&&item.kind==='read'&&item.fields.includes('q'));",
      " if(early&&route)fs.writeFileSync(stageFile,'early-sequence-planned');",
      " const encoded=value=>`hex:${Buffer.from(value).toString('hex')}`;",
      " answer={flows:route?[{family:early?'public-echo-observation':'server-rendered-expression',why:early?'Check the newly observed anonymous echo first':'Observed protected GET transforms a query value',priority:8,as:early?'anonymous':'derived',oracle:early?'observation':'marker',prelude:[],subject:{method:'GET',path:route.path,placement:'query',key:'q',fixedFields:[],bodyTemplate:'',headers:early?[]:[{name:'Accept-Language',value:'en-US'}]},observe:[],controlValue:'plain',firstValue:early?'one':encoded(context.marker),secondValue:early?'two':encoded(context.secondMarker),marker:early?'':context.marker,secondMarker:early?'':context.secondMarker,assertion:{step:'subject',index:0,location:'body',name:''}}]:[]};",
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
      BX_TRANSFORM: transformPath, BX_ECHO: echoPath,
      BX_STAGE_FILE: path.join(root, 'model-stage')};
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
    const webProgress = JSON.parse(fs.readFileSync(path.join(audit.data.runDir,
      'web-progress.json'), 'utf8'));
    assert.ok(webProgress.passes.primary.completed > 0);
    assert.ok(webProgress.passes.primary.modelCalls > 0,
      'primary Muse planning must run after authenticated reconnaissance');
    assert.ok(Object.keys(webProgress.passes).some(pass => pass.endsWith('-late')));
    assert.ok(webProgress.passes['derived-0-late']?.modelCalls > 0,
      'the protected follow-up must receive a Muse planning call after primary work');
    const coverage = JSON.parse(fs.readFileSync(path.join(audit.data.runDir, 'coverage.json'), 'utf8'));
    assert.ok(coverage.derivedSessionRecon?.sessions >= 1);
    const derived = JSON.parse(fs.readFileSync(path.join(audit.data.runDir,
      'derived-session-recon.json'), 'utf8'));
    assert.ok(derived.sessions[0]?.coverage?.earlyWebChecks >= 1,
      'an early anonymous test must have run before later protected planning');
    assert.ok(derived.sessions[0]?.coverage?.earlyWebCut > 0,
      'the small early pass must record deferred leads');
    assert.equal(derived.sessions[0]?.coverage?.modelRoutesSent,
      derived.sessions[0]?.coverage?.modelRoutesAvailable,
      'authenticated recon must present every mapped route to Muse');
    assert.ok(web.modelCoverage.some(item => item.discoveredVia === 'derived-session' &&
      item.httpSequenceAvailable > 0 &&
      item.httpSequenceSent === item.httpSequenceAvailable),
    'a protected planning pass must present every available method-aware route');
    assert.equal(web.cut, 0,
      'the later protected pass completed those leads, so final coverage must not count the early deferral');
    assert.ok(web.results.some(item => item.kind === 'model-http-observation' &&
      item.lead?.path === echoPath && item.lead?.as === 'anonymous'),
    JSON.stringify({coverage: web.modelCoverage, results: web.results}));
    assert.ok(observation, JSON.stringify({root, findings: audit.data.findings.map(item =>
      [item.kind, item.pattern, item.verdict]),
    planning: web.modelCoverage.filter(item => item.discoveredVia === 'derived-session')
      .map(item => ({sent: item.httpSequenceSent, accepted: item.httpSequenceAccepted})),
    derivedCoverage: derived.sessions[0]?.coverage,
    sequenceResults: web.results.filter(item => item.kind?.startsWith('model-http'))
      .map(item => [item.kind, item.lead?.path, item.lead?.as, item.verdict])}));
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
