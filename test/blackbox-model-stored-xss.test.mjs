import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import http from 'node:http';
import path from 'node:path';
import {randomBytes} from 'node:crypto';
import {spawn} from 'node:child_process';
import {temp} from './helpers.mjs';
import {execFile} from '../src/util.mjs';
import {CLI} from '../src/demo.mjs';
import {loadScope} from '../src/blackbox/scope.mjs';
import {planStoredXss} from '../src/blackbox/stored-xss.mjs';

test('stored-XSS model plans cannot add unobserved POSTs, views or body fields', async t => {
  const root = temp();
  t.after(() => fs.rmSync(root, {recursive: true, force: true}));
  const origin = 'http://127.0.0.1:3000';
  const file = path.join(root, 'scope.json');
  fs.writeFileSync(file, JSON.stringify({schemaVersion: 1, target: {origin},
    probes: {jsonPostPaths: ['/api/comment']}}));
  const scope = loadScope({file, origin}).scope;
  const surface = {jsonBodyOperations: [{path: '/api/comment', method: 'POST',
    contentType: 'application/json', fields: ['message', 'kind', 'token'],
    requiredFields: ['message', 'kind'], source: 'public-openapi'}],
  patterns: [{pattern: '/comments', methods: ['GET'],
    fingerprint: {anonymous: {status: 200, type: 'text/html'}}}]};
  const proposed = (postPath, viewPath, field = 'message') => ({postPath, viewPath,
    field, fixedFields: [{field: 'kind', value: 'demo'}], postAs: 'anonymous',
    viewAs: 'anonymous', style: 'html-double', why: 'Comment appears in HTML', priority: 5});
  const infer = async () => ({checks: [proposed('/api/delete', '/comments'),
    proposed('/api/comment', '/private'), proposed('/api/comment', '/comments', 'token'),
    proposed('/api/comment', '/comments')]});
  const plan = await planStoredXss(surface, scope, {infer, model: 'fixture',
    budget: 4, modelCallsAvailable: 1});
  assert.deepEqual(plan.decisions.map(item => [item.accepted, item.reason]),
    [[false, 'unobserved-route-or-field'], [false, 'unobserved-route-or-field'],
      [false, 'unobserved-route-or-field'], [true, undefined]]);
  assert.deepEqual(plan.leads.map(item => [item.path, item.viewPath, item.parameter]),
    [['/api/comment', '/comments', 'message']]);
});

test('stored-XSS planner admits an observed pair on a verified deployed POST scope', async t => {
  const root = temp();
  t.after(() => fs.rmSync(root, {recursive: true, force: true}));
  const origin = 'https://app.example.test', postPath = '/api/comment',
    viewPath = '/comments';
  const expiresAt = new Date(Date.now() + 86400000).toISOString();
  const target = {url: origin, environment: 'staging',
    ownership: {status: 'verified', method: 'dns', expiresAt},
    authorization: {origin, paths: ['/'], methods: ['GET', 'HEAD', 'POST'],
      maxRequestsPerSecond: 2, expiresAt}};
  const file = path.join(root, 'scope.json');
  fs.writeFileSync(file, JSON.stringify({schemaVersion: 1, target: {origin},
    include: ['/'], probes: {jsonPostPaths: [postPath]}, limits: {rps: 2}}));
  const scope = loadScope({file, origin, targets: [target]}).scope;
  const surface = {jsonBodyOperations: [{path: postPath, method: 'POST',
    contentType: 'application/json', fields: ['message'], requiredFields: ['message']}],
  patterns: [{pattern: viewPath, methods: ['GET'], fingerprint: {
    anonymous: {status: 200, type: 'text/html'}}}]};
  const infer = async (_model, messages) => {
    assert.match(messages[0].content, /authorized deployed stored-XSS/);
    return {checks: [{postPath, viewPath, field: 'message', fixedFields: [],
      postAs: 'anonymous', viewAs: 'anonymous', style: 'html-double',
      why: 'Observed comment field and HTML view', priority: 7}]};
  };
  const plan = await planStoredXss(surface, scope, {infer, model: 'fixture',
    budget: 1, modelCallsAvailable: 1});
  assert.equal(plan.coverage.postsAvailable, 1);
  assert.equal(plan.leads.length, 1);
  assert.equal(plan.decisions[0].accepted, true);
  const readOnly = structuredClone(target);
  readOnly.authorization.methods = ['GET', 'HEAD'];
  const readOnlyFile = path.join(root, 'read-only.json');
  fs.writeFileSync(readOnlyFile, JSON.stringify({schemaVersion: 1, target: {origin},
    include: ['/'], limits: {rps: 2}}));
  const restricted = loadScope({file: readOnlyFile, origin, targets: [readOnly]}).scope;
  const denied = await planStoredXss(surface, restricted, {infer: async () => {
    throw Error('Unreviewed deployed POST must not reach Muse.');
  }, model: 'fixture', budget: 1, modelCallsAvailable: 1});
  assert.equal(denied.coverage.postsAvailable, 0);
  assert.equal(denied.modelCalls, 0);
});

test('stored-XSS planning reviews a later page of operator-reviewed POST routes', async t => {
  const root = temp();
  t.after(() => fs.rmSync(root, {recursive: true, force: true}));
  const origin = 'http://127.0.0.1:3000';
  const paths = Array.from({length: 13}, (_, index) => `/api/comment-${index}`);
  const file = path.join(root, 'scope.json');
  fs.writeFileSync(file, JSON.stringify({schemaVersion: 1, target: {origin},
    probes: {jsonPostPaths: paths}}));
  const scope = loadScope({file, origin}).scope;
  const surface = {jsonBodyOperations: paths.map(item => ({path: item, method: 'POST',
    contentType: 'application/json', fields: ['message'], requiredFields: ['message'],
    source: 'public-openapi'})), patterns: [{pattern: '/comments', methods: ['GET'],
    fingerprint: {anonymous: {status: 200, type: 'text/html'}}}]};
  const seen = [];
  const infer = async (_model, messages) => {
    const context = JSON.parse(messages[1].content);
    seen.push(context.posts.map(item => item.path));
    return {checks: context.posts.some(item => item.path === paths[12]) ? [{
      postPath: paths[12], viewPath: '/comments', field: 'message', fixedFields: [],
      postAs: 'anonymous', viewAs: 'anonymous', style: 'html-double',
      why: 'Observed comment view', priority: 8}] : []};
  };
  const plan = await planStoredXss(surface, scope, {infer, model: 'fixture',
    budget: 1, modelCallsAvailable: 2});
  assert.equal(plan.modelCalls, 2);
  assert.equal(plan.coverage.postsSent, 13);
  assert.equal(plan.coverage.postsAvailable, 13);
  assert.deepEqual(seen.map(page => page.length), [12, 1]);
  assert.equal(plan.leads[0]?.path, paths[12]);
});

test('Muse can select an observed HTML view after the former 64-route window', async t => {
  const root = temp();
  t.after(() => fs.rmSync(root, {recursive: true, force: true}));
  const origin = 'http://127.0.0.1:3000';
  const post = '/api/comment';
  const views = Array.from({length: 80}, (_, index) => `/views/${index}`);
  const file = path.join(root, 'scope.json');
  fs.writeFileSync(file, JSON.stringify({schemaVersion: 1, target: {origin},
    probes: {jsonPostPaths: [post]}}));
  const scope = loadScope({file, origin}).scope;
  const surface = {jsonBodyOperations: [{path: post, method: 'POST',
    contentType: 'application/json', fields: ['message']}],
  patterns: views.map(pattern => ({pattern, methods: ['GET'],
    fingerprint: {anonymous: {status: 200, type: 'text/html'}}}))};
  const plan = await planStoredXss(surface, scope, {model: 'fixture',
    budget: 1, modelCallsAvailable: 1, infer: async (_model, messages) => {
      const context = JSON.parse(messages[1].content);
      assert.ok(context.views.some(item => item.path === views.at(-1)));
      return {checks: [{postPath: post, field: 'message', fixedFields: [],
        postAs: 'anonymous', viewPath: views.at(-1), viewAs: 'anonymous',
        style: 'html-double', why: 'Observed HTML view', priority: 5}]};
    }});
  assert.equal(plan.coverage.viewsSent, 80);
  assert.equal(plan.leads[0]?.viewPath, views.at(-1));
});

test('Muse selects a reviewed JSON POST and observed HTML GET for stored XSS proof', async t => {
  const root = temp();
  t.after(() => fs.rmSync(root, {recursive: true, force: true}));
  const suffix = randomBytes(4).toString('hex');
  const postPath = `/api/comment-${suffix}`;
  const viewPath = `/comments-${suffix}`;
  const requests = [];
  const comments = [];
  let vulnerable = true;
  const escape = value => String(value).replaceAll('&', '&amp;').replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;').replaceAll('"', '&quot;').replaceAll("'", '&#39;');
  const server = http.createServer(async (request, response) => {
    const url = new URL(request.url, 'http://fixture');
    requests.push(`${request.method} ${url.pathname}`);
    const json = (status, body) => {
      response.writeHead(status, {'content-type': 'application/json', 'cache-control': 'no-store'});
      response.end(JSON.stringify(body));
    };
    if (url.pathname === '/') {
      response.writeHead(200, {'content-type': 'text/html', 'cache-control': 'no-store'});
      return response.end(`<html><body><a href="${viewPath}">Comments</a></body></html>`);
    }
    if (url.pathname === '/openapi.json') return json(200, {openapi: '3.0.0', paths: {
      [viewPath]: {get: {}},
      [postPath]: {post: {requestBody: {content: {'application/json': {
        schema: {type: 'object', required: ['message', 'kind'],
          properties: {message: {type: 'string'}, kind: {type: 'string'}}}}}}}},
      '/api/delete': {post: {requestBody: {content: {'application/json': {
        schema: {type: 'object', properties: {message: {type: 'string'}}}}}}}},
    }});
    if (url.pathname === viewPath && request.method === 'GET') {
      response.writeHead(200, {'content-type': 'text/html; charset=utf-8',
        'cache-control': 'no-store'});
      return response.end(`<html><body><main>${comments.map(item =>
        `<div class="comment">${vulnerable ? item : escape(item)}</div>`).join('')}</main></body></html>`);
    }
    if (url.pathname === postPath && request.method === 'POST') {
      const chunks = [];
      for await (const chunk of request) chunks.push(chunk);
      let input;
      try {input = JSON.parse(Buffer.concat(chunks).toString());}
      catch {return json(400, {error: 'invalid json'});}
      if (input.kind !== 'demo' || typeof input.message !== 'string')
        return json(400, {error: 'documented fields required'});
      comments.push(input.message);
      return json(201, {saved: true});
    }
    return json(url.pathname === '/api/delete' ? 500 : 404, {error: 'missing'});
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  t.after(() => new Promise(resolve => server.close(resolve)));
  const origin = `http://127.0.0.1:${server.address().port}`;
  const scope = path.join(root, 'blackbox.scope.json');
  fs.writeFileSync(scope, JSON.stringify({schemaVersion: 1, target: {origin},
    probes: {jsonPostPaths: [postPath]}}));
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
    "if(system.includes('Select up to five local stored-XSS tests')){",
    'const context=JSON.parse(messages[1].content);',
    "const post=context.posts.find(item=>item.path===process.env.BX_POST&&item.fields.includes('message')&&item.requiredFields.includes('kind'));",
    "const view=context.views.find(item=>item.path===process.env.BX_VIEW);",
    "answer={checks:post&&view?[{postPath:post.path,field:'message',fixedFields:[{field:'kind',value:'demo'}],postAs:'anonymous',viewPath:view.path,viewAs:'anonymous',style:'html-double',why:'Observed comment body appears on the HTML view',priority:10}]:[]};",
    '}',
    "else if(system.includes('Select distinct harmless response-transformation experiments for the reviewed JSON POST routes'))answer={experiments:[]};",
    "else if(system.includes('Interpret only the extracted')){",
    'const context=JSON.parse(messages[1].content);',
    "answer={files:context.files.map(file=>({id:file.id,role:'app',why:'Observed public client',authFlow:'',routes:file.routes.map(route=>({path:route.path,method:route.method,purpose:'Observed route',parameters:[]}))}))};",
    '}',
    "else if(system.includes('Assess only these independently proved'))answer={notes:[]};",
    "else if(system.includes('Continue mapping this authorized primary application'))answer={paths:[]};",
    "else if(system.includes('mapping an authorized web API'))answer={paths:[],notes:[]};",
    "else if(system.includes('Propose bounded GET access-control'))answer={tasks:[]};",
    "else if(system.includes('Rank only the supplied observed read-only web-test candidates'))answer={priorities:[],strategies:[],experiments:[]};",
    'else process.exit(3);',
    "console.log(JSON.stringify({payload:{kind:'run_terminal',terminal:'completed',text:JSON.stringify(answer)}}));",
  ].join('\n') + '\n', {mode: 0o700});
  const env = {PATH: `${bin}${path.delimiter}${process.env.PATH}`,
    BX_POST: postPath, BX_VIEW: viewPath};
  const cli = async (...args) => {
    const completed = await execFile(process.execPath,
      [CLI, 'blackbox', ...args, '--project', root, '--json', '--non-interactive'],
      {cwd: root, env, timeout: 90000});
    assert.ok(completed.stdout,
      `Blackbox CLI exited ${completed.code} without JSON (${completed.stderr.length} stderr bytes)`);
    return {code: completed.code, data: JSON.parse(completed.stdout)};
  };
  const baseline = await cli(origin, '--scope', scope, '--no-model', '--rps', '20');
  assert.ok(!baseline.data.findings.some(item => item.kind === 'xss-stored'));
  assert.ok(!requests.includes(`POST ${postPath}`));
  const modeled = await cli(origin, '--scope', scope, '--rps', '20');
  const web = JSON.parse(fs.readFileSync(path.join(modeled.data.runDir, 'web-probes.json'), 'utf8'));
  const finding = modeled.data.findings.find(item => item.kind === 'xss-stored');
  assert.equal(modeled.code, 1, JSON.stringify({error: modeled.data.modelError,
    findings: modeled.data.findings, decisions: web.strategyDecisions,
    results: web.results}));
  assert.ok(finding?.proof);
  assert.equal(finding.pattern, postPath);
  assert.equal(finding.webProof.viewPath, viewPath);
  assert.equal(modeled.data.modelOutput.storedXssChecks, 1);
  assert.ok(requests.filter(item => item === `POST ${postPath}`).length >= 6);
  assert.ok(!requests.includes('POST /api/delete'));
  assert.equal((await cli('verify', modeled.data.run)).code, 1);
  const exported = await cli('export', modeled.data.run, '--out', path.join(root, 'regression'));
  assert.equal(exported.code, 0);
  const runExport = () => new Promise((resolve, reject) => {
    const child = spawn(process.execPath, ['--test', ...exported.data.files],
      {env: Object.fromEntries(Object.entries(process.env).filter(([key]) => key !== 'NODE_TEST_CONTEXT')),
        stdio: 'ignore'});
    child.once('error', reject);
    child.once('close', resolve);
  });
  assert.equal(await runExport(), 1);
  vulnerable = false;
  assert.equal((await cli('verify', modeled.data.run)).code, 0);
  assert.equal(await runExport(), 0);
});
