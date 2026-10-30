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
import {loadScope} from '../src/blackbox/scope.mjs';
import {runResearchFlows, validateResearchFlow} from '../src/blackbox/research-flow.mjs';

test('Muse-selected HTTP flow proves browser execution and replays red and green',
  {timeout: 150000}, async t => {
    if (process.platform === 'win32') return t.skip('the Muse fixture uses a POSIX executable');
    const chrome = process.env.BYPASS_CHROME ?? '/usr/bin/google-chrome';
    if (!fs.existsSync(chrome)) return t.skip('Chrome is unavailable');
    const root = fs.mkdtempSync(path.join(os.tmpdir(), 'bypass-browser-flow-'));
    t.after(() => fs.rmSync(root, {recursive: true, force: true}));
    const postPath = `/submit-${randomBytes(4).toString('hex')}`;
    const viewPath = `/show-${randomBytes(4).toString('hex')}`;
    const decoy = `/discard-${randomBytes(4).toString('hex')}`;
    const requests = [];
    const comments = [];
    let vulnerable = true;
    const escape = text => String(text).replaceAll('&', '&amp;')
      .replaceAll('<', '&lt;').replaceAll('>', '&gt;')
      .replaceAll('"', '&quot;').replaceAll("'", '&#39;');
    const server = http.createServer((request, response) => {
      const url = new URL(request.url, 'http://fixture.invalid');
      requests.push(`${request.method} ${url.pathname}`);
      if (url.pathname === '/') {
        response.writeHead(200, {'content-type': 'text/html', 'cache-control': 'no-store'});
        return response.end(`<html><a href="${viewPath}">View</a></html>`);
      }
      if (url.pathname === '/openapi.json') {
        response.writeHead(200, {'content-type': 'application/json', 'cache-control': 'no-store'});
        return response.end(JSON.stringify({openapi: '3.0.0', paths: {
          [viewPath]: {get: {}},
          [postPath]: {post: {requestBody: {content: {
            'application/x-www-form-urlencoded': {schema: {type: 'object',
              required: ['message'], properties: {message: {type: 'string'}}}}}}}},
          [decoy]: {post: {requestBody: {content: {'application/json': {
            schema: {type: 'object', properties: {message: {type: 'string'}}}}}}}},
        }}));
      }
      if (url.pathname === postPath && request.method === 'POST') {
        const chunks = [];
        request.on('data', chunk => chunks.push(chunk));
        return request.on('end', () => {
          const message = new URLSearchParams(Buffer.concat(chunks).toString()).get('message');
          if (message !== null) comments.push(message);
          response.writeHead(message === null ? 400 : 201,
            {'content-type': 'application/json', 'cache-control': 'no-store'});
          response.end(JSON.stringify({saved: message !== null}));
        });
      }
      if (url.pathname === viewPath && request.method === 'GET') {
        response.writeHead(200, {'content-type': 'text/html; charset=utf-8',
          'cache-control': 'no-store'});
        return response.end(`<html><body>${comments.map(message =>
          `<div>${vulnerable ? message : escape(message)}</div>`).join('')}</body></html>`);
      }
      response.writeHead(404, {'content-type': 'text/plain', 'cache-control': 'no-store'});
      response.end('missing');
    });
    await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
    t.after(() => new Promise(resolve => server.close(resolve)));
    const origin = `http://127.0.0.1:${server.address().port}`;
    const scopePath = path.join(root, 'blackbox.scope.json');
    fs.writeFileSync(scopePath, JSON.stringify({schemaVersion: 1, target: {origin},
      never: [decoy], limits: {rps: 40, maxUrls: 90, minutes: 3,
        modelCalls: 50, tasks: 100}}));
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
      "if(system.startsWith('You are planning bounded, authorized HTTP research.')){",
      ' const route=context.routes.find(item=>item.kind===\'form\'&&item.path===process.env.BX_POST);',
      ' const view=context.observedReadRoutes.find(item=>item.path===process.env.BX_VIEW);',
      " answer={flows:route&&view?[{family:'browser-script-injection',why:'Observed form input appears in a later HTML view',priority:10,as:'anonymous',oracle:'browser-execution',prelude:[],subject:{method:'POST',path:route.path,placement:'form',key:'message',fixedFields:[],bodyTemplate:'',headers:[]},observe:[{method:'GET',path:view.path,headers:[]}],binding:null,controlValue:'plain',firstValue:'html-double',secondValue:'html-double',marker:'',secondMarker:'',assertion:{step:'observe',index:0,location:'body',name:''}}]:[]};",
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
      BX_POST: postPath, BX_VIEW: viewPath};
    const cli = async (...args) => {
      const completed = await execFile(process.execPath,
        [CLI, 'blackbox', ...args, '--project', root, '--json', '--non-interactive'],
        {cwd: root, env, timeout: 120000});
      return {code: completed.code, data: JSON.parse(completed.stdout)};
    };
    const audit = await cli(origin, '--scope', scopePath);
    assert.ok(audit.data.runDir, JSON.stringify(audit));
    const finding = audit.data.findings.find(item => item.kind === 'model-browser-execution');
    const web = JSON.parse(fs.readFileSync(path.join(audit.data.runDir, 'web-probes.json'), 'utf8'));
    const coverage = JSON.parse(fs.readFileSync(path.join(audit.data.runDir, 'coverage.json'), 'utf8'));
    assert.ok(finding?.proof, JSON.stringify({findings: audit.data.findings,
      decisions: web.strategyDecisions, results: web.results}));
    assert.equal(finding.pattern, postPath);
    assert.ok(coverage.requestedClasses.find(item => item.name === 'Stored XSS')?.attempts > 0);
    assert.ok(requests.filter(item => item === `POST ${postPath}`).length >= 6);
    assert.ok(!requests.includes(`POST ${decoy}`));
    const proved = await execFile(process.execPath, [finding.proof], {env, timeout: 30000});
    const proof = JSON.parse(proved.stdout);
    assert.equal(proof.verdict, 'confirmed');
    assert.ok(proof.controls.some(item => item.label === 'control-browser' &&
      item.executed === false));
    assert.ok(proof.controls.some(item => item.label === 'probe-one-browser' &&
      item.executed === true));
    assert.ok(proof.controls.some(item => item.label === 'probe-two-browser' &&
      item.executed === true));
    assert.equal((await cli('verify', audit.data.run)).code, 1);
    const exported = await cli('export', audit.data.run,
      '--out', path.join(root, 'regression'));
    assert.equal(exported.code, 0);
    const regression = () => new Promise((resolve, reject) => {
      const child = spawn(process.execPath, ['--test', ...exported.data.files],
        {env: Object.fromEntries(Object.entries(env).filter(([key]) =>
          key !== 'NODE_TEST_CONTEXT')), stdio: 'ignore'});
      child.once('error', reject);
      child.once('close', resolve);
    });
    assert.equal(await regression(), 1);
    vulnerable = false;
    assert.equal((await cli('verify', audit.data.run)).code, 0);
    assert.equal(await regression(), 0);
  });

test('a deployed browser write remains an inconclusive plan without sending a persistent request',
  async t => {
    const root = fs.mkdtempSync(path.join(os.tmpdir(), 'bypass-browser-remote-'));
    t.after(() => fs.rmSync(root, {recursive: true, force: true}));
    const origin = 'https://app.example.test';
    const postPath = '/api/comment';
    const viewPath = '/api/comments';
    const expiresAt = new Date(Date.now() + 86400000).toISOString();
    const target = {url: origin, environment: 'staging',
      ownership: {status: 'verified', method: 'dns', expiresAt},
      authorization: {origin, paths: ['/api'], methods: ['GET', 'HEAD', 'POST'],
        maxRequestsPerSecond: 2, expiresAt}};
    const scopePath = path.join(root, 'scope.json');
    fs.writeFileSync(scopePath, JSON.stringify({schemaVersion: 1, target: {origin},
      include: ['/api'], probes: {formPostPaths: [postPath]}, limits: {rps: 2}}));
    const scope = loadScope({file: scopePath, origin, targets: [target]}).scope;
    const surface = {formBodyOperations: [{path: postPath, method: 'POST',
      placement: 'form', contentType: 'application/x-www-form-urlencoded',
      fields: ['message'], requiredFields: ['message']}],
    patterns: [{pattern: viewPath, methods: ['GET']}]};
    const proposal = {family: 'stored-xss', why: 'A saved comment appears in HTML',
      priority: 9, as: 'anonymous', oracle: 'browser-execution', prelude: [],
      subject: {method: 'POST', path: postPath, placement: 'form', key: 'message',
        fixedFields: [], bodyTemplate: '', headers: []},
      observe: [{method: 'GET', path: viewPath, headers: []}], binding: null,
      controlValue: 'plain', firstValue: 'html-double', secondValue: 'html-double',
      marker: '', secondMarker: '',
      assertion: {step: 'observe', index: 0, location: 'body', name: ''}};
    const checked = validateResearchFlow(proposal, surface, scope);
    assert.equal(checked.ok, true, JSON.stringify(checked));
    let sent = 0;
    const run = await runResearchFlows([checked.lead], scope, {surface,
      requester: async () => {sent++; throw Error('must not send a deployed browser write');},
      modelCallsAvailable: 0});
    assert.equal(sent, 0);
    assert.equal(run.results[0].verdict, 'inconclusive');
    assert.match(run.results[0].reason, /disposable|local contract/);
  });
