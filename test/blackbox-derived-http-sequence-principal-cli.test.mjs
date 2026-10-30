import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import http from 'node:http';
import os from 'node:os';
import path from 'node:path';
import {spawn} from 'node:child_process';
import {randomBytes} from 'node:crypto';
import {CLI} from '../src/demo.mjs';
import {execFile} from '../src/util.mjs';

const sleep = ms => new Promise(resolve => setTimeout(resolve, ms));

test('CLI resumes a saved derived HTTP sequence under its proved principal',
  {timeout: 120000}, async t => {
    if (process.platform === 'win32') return t.skip('Muse fixture uses a POSIX executable');
    const root = fs.mkdtempSync(path.join(os.tmpdir(), 'bypass-derived-flow-principal-'));
    t.after(() => {if (!process.env.BX_KEEP_TEST_ROOT)
      fs.rmSync(root, {recursive: true, force: true});});
    const sessions = new Map(), submitted = [], loginOrder = [];
    const logins = {alpha: 0, beta: 0};
    let holdPreview = true, releasePreview;
    const previewGate = new Promise(resolve => {releasePreview = resolve;});
    const reply = (response, status, value) => {
      response.writeHead(status, {'content-type': 'application/json',
        'cache-control': 'no-store'});
      response.end(JSON.stringify(value));
    };
    const server = http.createServer(async (request, response) => {
      const route = new URL(request.url, 'http://fixture.invalid').pathname;
      if (route === '/') return reply(response, 200, {docs: '/openapi.json'});
      if (route === '/openapi.json') return reply(response, 200, {openapi: '3.0.0', paths: {
        '/api/login': {post: {summary: 'Login with username and password', requestBody: {
          content: {'application/json': {schema: {type: 'object',
            required: ['username', 'password'], properties: {
              username: {type: 'string'}, password: {type: 'string'}}}}}}}},
        '/api/me': {get: {summary: 'Read the authenticated principal'}},
        '/api/preview': {post: {summary: 'Preview an expression', requestBody: {
          content: {'application/json': {schema: {type: 'object',
            required: ['expression'], properties: {expression: {type: 'string'}}}}}}}}}});
      if (route === '/api/login' && request.method === 'POST') {
        const chunks = [];
        for await (const chunk of request) chunks.push(chunk);
        const body = JSON.parse(Buffer.concat(chunks).toString());
        const principal = /^alpha' OR '[12]'='[12]$/.test(body.username) ? 'alpha' :
          /^beta' OR '[12]'='[12]$/.test(body.username) ? 'beta' : null;
        if (!principal || !/^bx-invalid-[0-9a-f]{24}$/.test(body.password))
          return reply(response, 401, {error: 'denied'});
        logins[principal]++;
        loginOrder.push(principal);
        if (principal === 'beta')
          fs.writeFileSync(path.join(root, 'beta-ready'), '1');
        const token = 'session-' + principal + '-' + randomBytes(24).toString('hex');
        sessions.set(token, principal);
        return reply(response, 200, {token});
      }
      if (route === '/api/me') {
        const principal = sessions.get(String(request.headers.authorization ?? '')
          .replace(/^Bearer /, ''));
        return principal ? reply(response, 200, {user: {id: principal}}) :
          reply(response, 401, {error: 'denied'});
      }
      if (route === '/api/preview' && request.method === 'POST') {
        const chunks = [];
        for await (const chunk of request) chunks.push(chunk);
        const body = JSON.parse(Buffer.concat(chunks).toString());
        const principal = sessions.get(String(request.headers.authorization ?? '')
          .replace(/^Bearer /, '')) ?? null;
        submitted.push({principal, value: body.expression});
        if (holdPreview && String(body.expression).startsWith('beta-'))
          await previewGate;
        return principal ? reply(response, 200, {result: body.expression}) :
          reply(response, 401, {error: 'denied'});
      }
      return reply(response, 404, {error: 'missing'});
    });
    await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
    t.after(() => new Promise(resolve => server.close(resolve)));
    const origin = 'http://127.0.0.1:' + server.address().port;
    const scopeFile = path.join(root, 'blackbox.scope.json');
    fs.writeFileSync(scopeFile, JSON.stringify({schemaVersion: 1, target: {origin},
      include: ['/'], probes: {jsonPostPaths: ['/api/preview']},
      limits: {rps: 60, maxUrls: 60, minutes: 3, modelCalls: 80, tasks: 80}}));
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
      'let answer;',
      "if(system.startsWith('From only the observed authorized JSON login operations')){",
      " answer={checks:['alpha','beta'].map(name=>({loginPath:'/api/login',userField:'username',passwordField:'password',proofMode:'principal',userPayloads:[name+\"' OR '1'='1\",name+\"' OR '2'='2\"],tokenPointer:'/token',privatePath:'/api/me',principalPointer:'/user/id',why:'Observed login may accept synthetic syntax'}))};",
      "} else if(system.startsWith('Allocate the next black-box investigation effort')){",
      " answer={priorities:['sequence','web','access','json','stored','session'].map(name=>({name,weight:name==='sequence'?100:1,why:'Observed preview input'}))};",
      "} else if(system.startsWith('You are planning bounded, authorized HTTP research.')){",
      ' const context=JSON.parse(messages[1].content);',
      " const preview=context.routes?.some(route=>route.path==='/api/preview'&&route.fields?.includes('expression'));",
      " const ready=fs.existsSync(process.env.BX_ROOT+'/beta-ready');",
      " const claimed=fs.existsSync(process.env.BX_ROOT+'/flow-proposed');",
      " if(process.env.BX_FLOW_PLAN==='1'&&ready&&preview&&!claimed){",
      "  fs.writeFileSync(process.env.BX_ROOT+'/flow-proposed','1');",
      "  answer={flows:[{family:'expression-preview',priority:8,as:'derived',why:'Observed protected preview input',oracle:'observation',prelude:[],observe:[],binding:null,subject:{method:'POST',path:'/api/preview',placement:'json',key:'expression',fixedFields:[],bodyTemplate:'',headers:[]},controlValue:'beta-normal',firstValue:'beta-first',secondValue:'beta-second',marker:'',secondMarker:'',assertion:{step:'subject',index:0,location:'body',name:''}}]};",
      " } else answer={flows:[]};",
      '} else {',
      " const schema=JSON.parse(fs.readFileSync(value('--output-schema'),'utf8'));",
      " const blank=s=>s?.type==='object'?Object.fromEntries((s.required??[]).map(key=>[key,blank(s.properties?.[key])])):s?.type==='array'?[]:s?.type==='integer'||s?.type==='number'?0:s?.type==='boolean'?false:s?.enum?.[0]??'';",
      ' answer=blank(schema);',
      '}',
      "console.log(JSON.stringify({payload:{kind:'run_terminal',terminal:'completed',text:JSON.stringify(answer)}}));",
    ].join('\n') + '\n', {mode: 0o700});
    const env = {...process.env, PATH: bin + path.delimiter + process.env.PATH,
      BX_ROOT: root};
    const first = spawn(process.execPath,
      [CLI, 'blackbox', origin, '--project', root, '--scope', scopeFile,
        '--offline', '--json', '--non-interactive'],
      {cwd: root, env: {...env, BX_FLOW_PLAN: '1'}, stdio: 'ignore'});
    t.after(() => {if (first.exitCode == null) first.kill('SIGKILL');});
    const runsDir = path.join(root, '.bypass/runs');
    let prior, firstCheckpoint;
    const deadline = Date.now() + 60000;
    while (Date.now() < deadline) {
      const folder = fs.existsSync(runsDir) ? fs.readdirSync(runsDir).find(name =>
        fs.readdirSync(path.join(runsDir, name)).some(file =>
          file.startsWith('http-sequence') && file.endsWith('-checkpoint.json'))) : null;
      if (folder) {
        const file = fs.readdirSync(path.join(runsDir, folder)).find(name =>
          name.startsWith('http-sequence') && name.endsWith('-checkpoint.json'));
        const checkpoint = JSON.parse(fs.readFileSync(path.join(runsDir, folder,
          file), 'utf8'));
        if (checkpoint.leads?.some(lead => lead.controlValue === 'beta-normal')) {
          prior = folder;
          firstCheckpoint = checkpoint;
          break;
        }
      }
      if (first.exitCode != null) break;
      await sleep(50);
    }
    assert.ok(prior, 'the first CLI process must persist Muse-accepted beta work: ' +
      JSON.stringify({firstCheckpoint, flowProposed: fs.existsSync(path.join(root,
        'flow-proposed')), loginOrder}));
    if (first.exitCode == null) {
      first.kill('SIGKILL');
      await new Promise(resolve => first.once('exit', resolve));
    }
    holdPreview = false;
    releasePreview();
    submitted.length = 0;
    const done = await execFile(process.execPath,
      [CLI, 'blackbox', 'resume', prior, '--project', root, '--offline',
        '--json', '--non-interactive'],
      {cwd: root, env: {...env, BX_FLOW_PLAN: '0'}, timeout: 90000});
    assert.ok(done.stdout, done.stderr);
    const audit = JSON.parse(done.stdout);
    assert.ok(audit.runDir, JSON.stringify({code: done.code, audit, stderr: done.stderr}));
    const experiments = submitted.filter(item =>
      /^(alpha|beta)-(normal|first|second)$/.test(item.value));
    assert.ok(experiments.length >= 3,
      'the saved three-control HTTP sequence must execute on resume');
    assert.equal(loginOrder[0], 'alpha', 'alpha was proved before beta');
    assert.deepEqual(experiments.slice(0, 3).map(item => item.value),
      ['beta-normal', 'beta-first', 'beta-second']);
    assert.ok(experiments.every(item => item.principal === 'beta'),
      'all resumed controls must use beta, not the first proved login: ' +
      JSON.stringify({experiments, loginOrder}));
    assert.ok(logins.beta >= 2, 'resume obtains a fresh proved beta session');
    const checkpoints = fs.readdirSync(audit.runDir)
      .filter(name => /^http-sequence.*-checkpoint\.json$/.test(name))
      .map(name => JSON.parse(fs.readFileSync(path.join(audit.runDir, name), 'utf8')));
    assert.ok(checkpoints.some(item => item.cursor === item.leads.length),
      'the executed beta queue must reach a terminal checkpoint');

    // A checkpoint written by an older CLI lacks principal metadata. Its
    // accepted work must remain pending, never run under a guessed identity.
    const legacy = 'bx-20261029-abcdef12';
    const legacyDir = path.join(runsDir, legacy);
    fs.mkdirSync(legacyDir);
    const start = JSON.parse(fs.readFileSync(path.join(runsDir, prior,
      'run-start.json'), 'utf8'));
    fs.writeFileSync(path.join(legacyDir, 'run-start.json'),
      JSON.stringify({...start, run: legacy}));
    fs.writeFileSync(path.join(legacyDir, 'evidence.jsonl'), '');
    const unbound = {...firstCheckpoint, run: legacy};
    delete unbound.principalFingerprint;
    fs.writeFileSync(path.join(legacyDir, 'http-sequence-checkpoint.json'),
      JSON.stringify(unbound));
    submitted.length = 0;
    const legacyDone = await execFile(process.execPath,
      [CLI, 'blackbox', 'resume', legacy, '--project', root, '--offline',
        '--json', '--non-interactive'],
      {cwd: root, env: {...env, BX_FLOW_PLAN: '0'}, timeout: 90000});
    const legacyAudit = JSON.parse(legacyDone.stdout);
    assert.ok(legacyAudit.runDir, legacyDone.stderr);
    assert.deepEqual(submitted.filter(item =>
      /^(alpha|beta)-(normal|first|second)$/.test(item.value)), [],
    'an unbound legacy checkpoint must not run under either proved session');
    const stillPending = JSON.parse(fs.readFileSync(path.join(legacyAudit.runDir,
      'http-sequence-checkpoint.json'), 'utf8'));
    assert.equal(stillPending.cursor, 0);
    assert.equal(stillPending.leads.length, 1);
  });
