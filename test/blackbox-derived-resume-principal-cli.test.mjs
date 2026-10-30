import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import http from 'node:http';
import os from 'node:os';
import path from 'node:path';
import {createHash, randomBytes} from 'node:crypto';
import {CLI} from '../src/demo.mjs';
import {execFile} from '../src/util.mjs';
import {loadScope} from '../src/blackbox/scope.mjs';

const fingerprint = principal => createHash('sha256')
  .update('principal:' + principal).digest('hex');

test('CLI resumes a saved derived JSON task under its proved principal',
  {timeout: 120000}, async t => {
    if (process.platform === 'win32') return t.skip('Muse fixture uses a POSIX executable');
    const root = fs.mkdtempSync(path.join(os.tmpdir(), 'bypass-derived-resume-principal-'));
    t.after(() => {if (!process.env.BX_KEEP_TEST_ROOT)
      fs.rmSync(root, {recursive: true, force: true});});
    const sessions = new Map(), submitted = [], loginOrder = [];
    const logins = {alpha: 0, beta: 0};
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
    const scopeHash = loadScope({file: scopeFile, origin}).hash;
    const prior = 'bx-20261029-abcdef12';
    const priorDir = path.join(root, '.bypass/runs', prior);
    fs.mkdirSync(priorDir, {recursive: true});
    fs.writeFileSync(path.join(priorDir, 'evidence.jsonl'), '');
    fs.writeFileSync(path.join(priorDir, 'run-start.json'), JSON.stringify({
      run: prior, status: 'running', scopeHash, origin, scopeFile,
      effectiveLimits: loadScope({file: scopeFile, origin}).scope.limits}));
    // The beta queue sorts first, while Muse establishes alpha first. This
    // catches a runner that resumes on the first matching login path alone.
    for (const [name, suffix] of [['beta', '000000000000'],
      ['alpha', 'ffffffffffff']]) {
      fs.writeFileSync(path.join(priorDir,
        'json-experiment-derived-' + suffix + '-checkpoint.json'), JSON.stringify({
        version: 1, run: prior, scopeHash, origin, kind: 'json-experiment',
        pass: 'derived-early', derivedLoginPath: '/api/login',
        principalFingerprint: fingerprint(name), cursor: 0, active: null,
        leads: [{path: '/api/preview', parameter: 'expression', as: 'derived',
          oracle: 'observation', family: 'expression preview',
          controlValue: name + '-normal', firstValue: name + '-first',
          secondValue: name + '-second', marker: 'bxfirst' + name,
          secondMarker: 'bxsecond' + name, fixedFields: [],
          observedFields: ['expression'], prelude: [], observePath: '',
          observeAs: 'derived', why: 'Observed protected preview input'}]}));
    }
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
      '} else {',
      " const schema=JSON.parse(fs.readFileSync(value('--output-schema'),'utf8'));",
      " const blank=s=>s?.type==='object'?Object.fromEntries((s.required??[]).map(key=>[key,blank(s.properties?.[key])])):s?.type==='array'?[]:s?.type==='integer'||s?.type==='number'?0:s?.type==='boolean'?false:s?.enum?.[0]??'';",
      ' answer=blank(schema);',
      '}',
      "console.log(JSON.stringify({payload:{kind:'run_terminal',terminal:'completed',text:JSON.stringify(answer)}}));",
    ].join('\n') + '\n', {mode: 0o700});
    const env = {...process.env, PATH: bin + path.delimiter + process.env.PATH};
    const done = await execFile(process.execPath,
      [CLI, 'blackbox', 'resume', prior, '--project', root, '--offline',
        '--json', '--non-interactive'], {cwd: root, env, timeout: 90000});
    assert.ok(done.stdout, done.stderr);
    const audit = JSON.parse(done.stdout);
    assert.ok(audit.runDir, JSON.stringify({code: done.code, audit, stderr: done.stderr}));
    const experiments = submitted.filter(item =>
      /^(alpha|beta)-(normal|first|second)$/.test(item.value));
    assert.equal(experiments.length, 6,
      'both saved principal-bound three-control experiments must execute on resume');
    assert.equal(loginOrder[0], 'alpha', 'alpha was proved before beta');
    for (const principal of ['alpha', 'beta']) {
      const controls = experiments.filter(item => item.value.startsWith(principal + '-'));
      assert.deepEqual(controls.map(item => item.value),
        ['normal', 'first', 'second'].map(part => principal + '-' + part));
      assert.ok(controls.every(item => item.principal === principal),
        `${principal} controls must use the session bound to their checkpoint`);
      assert.ok(logins[principal] >= 2,
        `${principal} resume obtains a fresh proved session`);
    }
    const checkpoints = fs.readdirSync(audit.runDir)
      .filter(name => /^json-experiment-derived-.*-checkpoint\.json$/.test(name))
      .map(name => JSON.parse(fs.readFileSync(path.join(audit.runDir, name), 'utf8')));
    for (const principal of ['alpha', 'beta'])
      assert.ok(checkpoints.some(item =>
        item.principalFingerprint === fingerprint(principal) &&
        item.cursor === item.leads.length),
      `${principal} checkpoint must be complete`);
  });
