import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import http from 'node:http';
import os from 'node:os';
import path from 'node:path';
import {randomBytes} from 'node:crypto';
import {CLI} from '../src/demo.mjs';
import {execFile} from '../src/util.mjs';
import {createLedger} from '../src/blackbox/ledger.mjs';
import {loadScope} from '../src/blackbox/scope.mjs';
import {runWebProbes} from '../src/blackbox/web-probes.mjs';

const origin = 'http://127.0.0.1:49573';
const jsonLead = number => ({path: '/api/preview', parameter: 'expression',
  as: 'anonymous', oracle: 'observation', family: 'preview response',
  basis: 'model-json-experiment', controlValue: `ordinary-${number}`,
  firstValue: `first-${number}`, secondValue: `second-${number}`,
  marker: `bxfirst${number}`, secondMarker: `bxsecond${number}`,
  fixedFields: [], observedFields: ['expression'], prelude: [],
  observePath: '', observeAs: 'anonymous', why: 'Observed expression input'});

test('a smaller resumed pass preserves the unexecuted tail of a JSON queue', async () => {
  const scope = loadScope({origin, overrides: {acceptLocal: true}}).scope;
  const leads = [jsonLead(1), jsonLead(2), jsonLead(3)];
  const surface = {patterns: [], jsonBodyOperations: [{method: 'POST',
    path: '/api/preview', contentType: 'application/json',
    fields: ['expression'], requiredFields: ['expression']}],
  authBodyOperations: []};
  const checkpoints = [];
  const submitted = [];
  let requestNumber = 0;
  const requester = async request => {
    const value = JSON.parse(request.body).expression;
    submitted.push(value);
    const body = JSON.stringify({result: value});
    return {status: 200, type: 'application/json', body,
      bytes: body.length, headers: {'cache-control': 'no-store'},
      evidenceId: `ev-${++requestNumber}`};
  };
  const run = await runWebProbes(surface, scope, {requester, budget: 1,
    resumeResearch: {kind: 'json-experiment', cursor: 0, leads, active: null,
      run: 'prior-run', pass: 'primary', origin},
    onJsonCheckpoint: checkpoint => checkpoints.push(structuredClone(checkpoint))});
  assert.ok(run.results.some(result => result.kind === 'model-json-observation'),
    'the first queued lead ran');
  assert.deepEqual(submitted, ['ordinary-1', 'first-1', 'second-1']);
  assert.equal(checkpoints.at(-1).cursor, 1);
  assert.deepEqual(checkpoints.at(-1).leads.map(lead => lead.controlValue),
    ['ordinary-1', 'ordinary-2', 'ordinary-3'],
    'the two accepted leads beyond this pass budget remain resumable');
});

test('one CLI resume executes distinct JSON and access queues and coalesces a duplicate',
  {timeout: 120000}, async t => {
    if (process.platform === 'win32') return t.skip('Muse fixture uses a POSIX executable');
    const root = fs.mkdtempSync(path.join(os.tmpdir(), 'bypass-resume-two-queues-'));
    t.after(() => {if (!process.env.BX_KEEP_TEST_ROOT) fs.rmSync(root, {recursive: true, force: true});});
    const privatePath = '/api/private-record';
    const oldPath = '/api/filter-old';
    const freshPath = '/api/filter-new';
    const previewPath = '/api/preview';
    const nextPreviewPath = '/api/preview-next';
    let oldPosts = 0, previewPosts = 0, nextPreviewPosts = 0;
    let readyQueuesWaiting = 0, readyQueuesOverlapped = false;
    let releaseReadyQueues;
    const bothReadyQueues = new Promise(resolve => {releaseReadyQueues = resolve;});
    let releaseStraggler, stragglerCompleted = false;
    let nextStartedBeforeStraggler = false;
    const nextReady = new Promise(resolve => {releaseStraggler = resolve;});
    const server = http.createServer(async (request, response) => {
      const pathname = new URL(request.url, 'http://fixture.invalid').pathname;
      const json = (status, value) => {
        response.writeHead(status, {'content-type': 'application/json',
          'cache-control': 'no-store'});
        response.end(JSON.stringify(value));
      };
      if (request.method === 'GET' && pathname === '/')
        return json(200, {service: 'document filters', docs: '/openapi.json'});
      if (request.method === 'GET' && pathname === '/openapi.json')
        return json(200, {openapi: '3.0.0', paths: {
          [privatePath]: {get: {summary: 'Read the owner record'}},
          ...Object.fromEntries([oldPath, freshPath, previewPath,
            nextPreviewPath].map(route =>
            [route, {post: {summary: 'Filter public records', requestBody: {content: {
              'application/json': {schema: {type: 'object',
                properties: {term: {type: 'string'}}, required: ['term']}}}}}}]))}});
      if (request.method === 'GET' && pathname === privatePath)
        return request.headers.authorization === 'Bearer fixture-owner' ?
          json(200, {id: 'owner-record', title: 'owner record'}) :
          json(403, {error: 'denied'});
      if (request.method === 'POST' &&
          [oldPath, freshPath, previewPath, nextPreviewPath].includes(pathname)) {
        if (pathname === oldPath) oldPosts++;
        if (pathname === previewPath) previewPosts++;
        if (pathname === nextPreviewPath) nextPreviewPosts++;
        let body = '';
        for await (const chunk of request) body += chunk;
        const term = JSON.parse(body).term;
        // The first request in each accepted queue must start before either
        // response is released. A serial resume times out at this barrier.
        if ((pathname === oldPath && term === 'normal-old') ||
            (pathname === previewPath && term === 'ordinary-1')) {
          readyQueuesWaiting++;
          if (readyQueuesWaiting === 2) {
            readyQueuesOverlapped = true;
            releaseReadyQueues();
          } else {
            let timer;
            try {
              await Promise.race([bothReadyQueues,
                new Promise(resolve => {timer = setTimeout(resolve, 1500);})]);
            } finally {clearTimeout(timer);}
          }
          readyQueuesWaiting--;
        }
        if (pathname === nextPreviewPath && term === 'ordinary-3') {
          nextStartedBeforeStraggler = !stragglerCompleted;
          releaseStraggler();
        }
        if (pathname === previewPath && term === 'ordinary-1') {
          let timer;
          try {
            await Promise.race([nextReady,
              new Promise(resolve => {timer = setTimeout(resolve, 2500);})]);
          } finally {clearTimeout(timer);}
          stragglerCompleted = true;
        }
        return json(200, {records: []});
      }
      return json(404, {error: 'missing'});
    });
    await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
    t.after(() => new Promise(resolve => server.close(resolve)));
    const target = `http://127.0.0.1:${server.address().port}`;
    const scopeFile = path.join(root, 'blackbox.scope.json');
    fs.writeFileSync(scopeFile, JSON.stringify({schemaVersion: 1,
      target: {origin: target}, include: ['/'],
      identities: {identityPath: privatePath},
      probes: {jsonPostPaths: [oldPath, freshPath, previewPath,
        nextPreviewPath]},
      limits: {rps: 80, maxUrls: 50, minutes: 1, modelCalls: 35,
        modelConcurrency: 2, tasks: 50}}));
    const {scope, hash: scopeHash} = loadScope({file: scopeFile, origin: target});
    const previousRun = `bx-20261029-${randomBytes(4).toString('hex')}`;
    const previousDir = path.join(root, '.bypass/runs', previousRun);
    fs.mkdirSync(previousDir, {recursive: true});
    fs.writeFileSync(path.join(previousDir, 'run-start.json'), JSON.stringify({
      run: previousRun, status: 'running', scopeHash, origin: target,
      scopeFile, rps: scope.limits.rps, effectiveLimits: scope.limits,
      startedAt: new Date().toISOString()}));
    const ledger = createLedger(previousDir, {run: previousRun});
    ledger.append({step: 'fixture', kind: 'prior-research-checkpoint'});
    ledger.close();
    const metadata = {version: 1, run: previousRun, scopeHash, origin: target,
      pass: 'primary', derivedLoginPath: null, updatedAt: new Date().toISOString()};
    const priorJson = {...metadata, kind: 'json-experiment', cursor: 0,
      leads: [{...jsonLead(1), path: previewPath, parameter: 'term',
        observedFields: ['term']}], active: null, modelCalls: 0};
    const priorAccessLead = {family: 'owner record boundary',
      why: 'Saved Muse owner record test', priority: 10,
      comparison: 'object', protectedAs: 'owner', protectedPath: privatePath,
      subject: {method: 'POST', path: oldPath, placement: 'json', key: 'term',
        fixedFields: []}, controlValue: 'normal-old', firstValue: 'wide-old-one',
      secondValue: 'wide-old-two', ownerPointer: '', candidatePointer: '/records',
      identityField: 'id', matchFields: ['id', 'title']};
    const priorAccess = {...metadata, kind: 'access-boundary', cursor: 0,
      leads: [priorAccessLead], active: null, modelCalls: 0};
    fs.writeFileSync(path.join(previousDir, 'json-experiment-checkpoint.json'),
      JSON.stringify(priorJson));
    fs.writeFileSync(path.join(previousDir, 'access-boundary-checkpoint.json'),
      JSON.stringify(priorAccess));
    fs.writeFileSync(path.join(previousDir,
      'access-boundary-queue-aaaaaaaaaaaa-checkpoint.json'),
    JSON.stringify({...priorAccess, updatedAt: new Date(Date.now() + 1000).toISOString()}));
    fs.writeFileSync(path.join(previousDir,
      'json-experiment-queue-bbbbbbbbbbbb-checkpoint.json'),
    JSON.stringify({...priorJson,
      leads: [{...jsonLead(3), path: nextPreviewPath, parameter: 'term',
        observedFields: ['term']}],
      updatedAt: new Date(Date.now() + 2000).toISOString()}));
    const bin = path.join(root, 'bin');
    fs.mkdirSync(bin);
    fs.writeFileSync(path.join(bin, 'muse'), [
      '#!' + process.execPath,
      "const fs=require('node:fs');",
      '(async()=>{',
      'const args=process.argv.slice(2);',
      'const value=flag=>args[args.indexOf(flag)+1];',
      "if(args.includes('--version')){console.log('muse fixture');process.exit(0);}",
      "if(args[0]!=='exec'||!args.includes('--disable-shell')||!args.includes('--output-schema')||value('--provider')!=='meta')process.exit(2);",
      "const messages=JSON.parse(fs.readFileSync(value('--prompt-file'),'utf8'));",
      'const system=messages[0].content;',
      'const context=JSON.parse(messages.at(-1).content);',
      'let answer;',
      "if(system.includes('Allocate the next black-box investigation effort'))answer={priorities:context.tracks.map(row=>({name:row.name,weight:row.name==='access'?100:1,why:'Observed private read and public filter'}))};",
      "else if(system.startsWith('You are investigating whether an observed anonymous GET query input')){",
      ` const read=context.protectedReads.find(item=>item.path==='${privatePath}');`,
      ` const post=context.publicPosts.find(item=>item.path==='${freshPath}');`,
      ` answer={tests:read&&post?[{family:'owner record boundary',why:'Observed public filter may expose owner record',priority:10,comparison:'object',protectedPath:'${privatePath}',subject:{method:'POST',path:'${freshPath}',placement:'json',key:'term',fixedFields:[]},controlValue:'normal-new',firstValue:'wide-new-one',secondValue:'wide-new-two',ownerPointer:'',candidatePointer:'/records',identityField:'id',matchFields:['id','title']}]:[]};`,
      '}',
      'else {',
      " const schema=JSON.parse(fs.readFileSync(value('--output-schema'),'utf8'));",
      " const blank=s=>s?.type==='object'?Object.fromEntries((s.required??[]).map(key=>[key,blank(s.properties?.[key])])):s?.type==='array'?[]:s?.type==='integer'||s?.type==='number'?0:s?.type==='boolean'?false:s?.enum?.[0]??'';",
      ' answer=blank(schema);',
      '}',
      "console.log(JSON.stringify({payload:{kind:'run_terminal',terminal:'completed',text:JSON.stringify(answer)}}));",
      '})().catch(error=>{console.error(error);process.exit(1)});',
    ].join('\n') + '\n', {mode: 0o700});
    const env = {...process.env, PATH: `${bin}${path.delimiter}${process.env.PATH}`,
      OWNER_TOKEN: 'fixture-owner'};
    const done = await execFile(process.execPath,
      [CLI, 'blackbox', 'resume', previousRun, '--project', root,
        '--offline', '--json', '--non-interactive'],
      {cwd: root, env, timeout: 90000});
    assert.ok(done.stdout, done.stderr);
    const resumed = JSON.parse(done.stdout);
    assert.ok(resumed.runDir, JSON.stringify({code: done.code, stdout: done.stdout,
      stderr: done.stderr, root}));
    const accessFiles = fs.readdirSync(resumed.runDir)
      .filter(name => /^access-boundary.*checkpoint\.json$/.test(name));
    const checkpoints = accessFiles.map(name => JSON.parse(fs.readFileSync(
      path.join(resumed.runDir, name), 'utf8')));
    assert.ok(checkpoints.some(item => item.leads?.some(lead =>
      lead.subject?.path === freshPath)),
    'Muse accepted a fresh access plan in the resumed audit');
    assert.ok(checkpoints.filter(item => item.leads?.some(lead =>
      lead.subject?.path === oldPath)).every(item => item.cursor >= item.leads.length),
    'both copies of the accepted old access lead are complete');
    assert.ok(oldPosts > 0, 'the saved access queue executed in this resume');
    assert.ok(previewPosts > 0, 'the saved JSON queue executed in this resume');
    assert.ok(nextPreviewPosts > 0, 'the third saved queue executed in this resume');
    assert.ok(readyQueuesOverlapped,
      'independent accepted resume queues started before either completed');
    assert.ok(nextStartedBeforeStraggler,
      'a free worker started the next ready queue while the first remained in flight');
    const evidence = fs.readFileSync(path.join(resumed.runDir, 'evidence.jsonl'),
      'utf8').trim().split('\n').map(line => JSON.parse(line));
    assert.equal(evidence.filter(item =>
      item.kind === 'resumed-duplicate-coalesced').length, 1,
    'the duplicate access lead was coalesced without another HTTP test');

  });
