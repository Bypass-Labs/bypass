import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import http from 'node:http';
import os from 'node:os';
import path from 'node:path';
import {randomBytes} from 'node:crypto';
import {CLI} from '../src/demo.mjs';
import {execFile} from '../src/util.mjs';
import {researchReportReserveMs, sanitizeAccessCheckpoint} from '../src/blackbox/index.mjs';
import {loadScope} from '../src/blackbox/scope.mjs';
import {runAccessBoundaries} from '../src/blackbox/access-boundary.mjs';

test('access checkpoint preserves request bytes or records a redaction cut', () => {
  const lead = {protectedAs: 'owner', protectedPath: '/private',
    subject: {method: 'POST', path: '/filter', placement: 'json', key: 'term',
      fixedFields: []}, comparison: 'object', controlValue: 'normal',
    firstValue: 'wide-one', secondValue: 'wide-two', ownerPointer: '',
    candidatePointer: '/records', identityField: 'id', matchFields: ['id', 'title'],
    family: 'access boundary', why: 'Maybe exposed'};
  const secret = 'sk_live_AB12CD34EF56GH78IJ90KL12MN34';
  const metadata = sanitizeAccessCheckpoint({kind: 'access-boundary', cursor: 0,
    leads: [{...lead, why: secret}]});
  assert.equal(metadata.leads.length, 1);
  assert.ok(!JSON.stringify(metadata).includes(secret));
  const changed = sanitizeAccessCheckpoint({kind: 'access-boundary', cursor: 0,
    leads: [{...lead, firstValue: secret}]});
  assert.equal(changed.leads.length, 0);
  assert.equal(changed.redactedExecutableLeads, 1);
  assert.ok(!JSON.stringify(changed).includes(secret));
});

test('stale resumed access contract is a recorded cut before HTTP', async t => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'bypass-access-stale-'));
  t.after(() => fs.rmSync(root, {recursive: true, force: true}));
  const origin = 'http://127.0.0.1:49990';
  const file = path.join(root, 'scope.json');
  fs.writeFileSync(file, JSON.stringify({schemaVersion: 1, target: {origin},
    include: ['/'], identities: {identityPath: '/api/private'},
    probes: {jsonPostPaths: ['/api/filter']}}));
  const scope = loadScope({file, origin}).scope;
  const lead = {family: 'owner record boundary', why: 'Previously observed public filter',
    priority: 10, comparison: 'object', protectedAs: 'owner',
    protectedPath: '/api/private', subject: {method: 'POST', path: '/api/filter',
      placement: 'json', key: 'term', fixedFields: []}, controlValue: 'normal',
    firstValue: 'wide-one', secondValue: 'wide-two', ownerPointer: '',
    candidatePointer: '/records', identityField: 'id', matchFields: ['id', 'title']};
  const checkpoints = [];
  let sent = 0;
  const run = await runAccessBoundaries([lead], scope, {
    requester: async () => {sent++; throw new Error('stale POST was sent');},
    surface: {patterns: [{pattern: '/api/private', methods: ['GET'],
      fingerprint: {owner: {status: 200}, anonymous: {status: 403}}}],
      jsonBodyOperations: []}, env: {OWNER_TOKEN: 'fresh-fixture-owner'},
    resumeResearch: {kind: 'access-boundary', cursor: 0, leads: [lead]},
    onResearchCheckpoint: state => checkpoints.push(state)});
  assert.equal(sent, 0);
  assert.equal(run.results[0].verdict, 'untested');
  assert.match(run.results[0].reason, /^resume-contract-changed:unobserved-route$/);
  assert.equal(checkpoints.at(-1).cursor, 1);
});

test('CLI resumes an accepted owner-boundary POST with fresh controls',
  {timeout: 120000}, async t => {
    if (process.platform === 'win32') return t.skip('Muse fixture uses a POSIX executable');
    const root = fs.mkdtempSync(path.join(os.tmpdir(), 'bypass-access-queued-'));
    t.after(() => {if (!process.env.BX_KEEP_TEST_ROOT) fs.rmSync(root, {recursive: true, force: true});});
    const suffix = randomBytes(4).toString('hex');
    const privatePath = `/api/private-${suffix}`;
    const publicPath = `/api/filter-${suffix}`;
    const privateRecord = {id: `private-${suffix}`, title: `private-${suffix}`};
    const submitted = [], ownerReads = [];
    let vulnerable = true;
    const server = http.createServer(async (request, response) => {
      const url = new URL(request.url, 'http://fixture.invalid');
      const json = (status, value) => {
        response.writeHead(status, {'content-type': 'application/json',
          'cache-control': 'no-store'});
        response.end(JSON.stringify(value));
      };
      if (request.method === 'GET' && url.pathname === '/')
        return json(200, {service: 'document filter', docs: '/openapi.json'});
      if (request.method === 'GET' && url.pathname === '/openapi.json')
        return json(200, {openapi: '3.0.0', paths: {
          [privatePath]: {get: {summary: 'Read private owner document'}},
          [publicPath]: {post: {summary: 'Filter public documents', requestBody: {
            content: {'application/json': {schema: {type: 'object',
              properties: {term: {type: 'string'}}, required: ['term']}}}}}}}});
      if (request.method === 'GET' && url.pathname === privatePath) {
        const owner = request.headers.authorization === 'Bearer fixture-owner';
        ownerReads.push(owner);
        return owner ? json(200, privateRecord) : json(403, {error: 'denied'});
      }
      if (request.method === 'POST' && url.pathname === publicPath) {
        const chunks = [];
        for await (const chunk of request) chunks.push(chunk);
        const term = JSON.parse(Buffer.concat(chunks).toString()).term;
        submitted.push(term);
        return json(200, {records: vulnerable && ['wide-one', 'wide-two'].includes(term) ?
          [privateRecord] : []});
      }
      return json(404, {error: 'missing'});
    });
    await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
    t.after(() => new Promise(resolve => server.close(resolve)));
    const origin = `http://127.0.0.1:${server.address().port}`;
    const scopeFile = path.join(root, 'blackbox.scope.json');
    fs.writeFileSync(scopeFile, JSON.stringify({schemaVersion: 1, target: {origin},
      include: ['/'], identities: {identityPath: privatePath},
      probes: {jsonPostPaths: [publicPath]},
      limits: {rps: 80, maxUrls: 100, minutes: 1, modelCalls: 40, tasks: 100}}));
    const researchCutoffMs = 60_000 - researchReportReserveMs(60_000) + 250;
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
      'const system=messages[0].content,context=JSON.parse(messages.at(-1).content);',
      'let answer;',
      "if(system.includes('Allocate the next black-box investigation effort'))answer={priorities:context.tracks.map(row=>({name:row.name,weight:row.name==='access'?100:1,why:'Owner-only read and public filter'}))};",
      "else if(system.startsWith('You are investigating whether an observed anonymous GET query input')){",
      ' const read=context.protectedReads.find(item=>item.path===process.env.BX_PRIVATE);',
      ' const post=context.publicPosts.find(item=>item.path===process.env.BX_PUBLIC);',
      ' const planned=fs.existsSync(process.env.BX_PLANNED);',
      ' if(!planned){fs.writeFileSync(process.env.BX_PLANNED,\'planned\');',
      "  const run=fs.readdirSync(process.env.BX_RUNS).find(name=>fs.existsSync(process.env.BX_RUNS+'/'+name+'/run-start.json'));",
      "  const started=JSON.parse(fs.readFileSync(process.env.BX_RUNS+'/'+run+'/run-start.json')).startedAt;",
      `  await new Promise(resolve=>setTimeout(resolve,Math.max(0,Date.parse(started)+${researchCutoffMs}-Date.now())));`,
      ' }',
      " answer={tests:read&&post&&!planned?[{family:'owner record boundary',why:'Observed public filter may return owner record',priority:10,comparison:'object',protectedPath:read.path,subject:{method:'POST',path:post.path,placement:'json',key:'term',fixedFields:[]},controlValue:'normal',firstValue:'wide-one',secondValue:'wide-two',ownerPointer:'',candidatePointer:'/records',identityField:'id',matchFields:['id','title']}]:[]};",
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
      OWNER_TOKEN: 'fixture-owner', BX_PRIVATE: privatePath, BX_PUBLIC: publicPath,
      BX_PLANNED: path.join(root, 'planned'), BX_RUNS: path.join(root, '.bypass/runs')};
    const cli = async (...args) => {
      const done = await execFile(process.execPath,
        [CLI, 'blackbox', ...args, '--project', root, '--json', '--non-interactive'],
        {cwd: root, env, timeout: 90000});
      return {code: done.code, data: JSON.parse(done.stdout), stderr: done.stderr};
    };
    const first = await cli(origin, '--scope', scopeFile, '--offline');
    assert.ok(first.data.runDir, first.stderr);
    assert.equal(submitted.filter(item => ['wide-one', 'wide-two'].includes(item)).length, 0);
    const checkpoint = JSON.parse(fs.readFileSync(path.join(first.data.runDir,
      'access-boundary-checkpoint.json'), 'utf8'));
    assert.equal(checkpoint.pass, 'primary');
    assert.equal(checkpoint.cursor, 0);
    assert.equal(checkpoint.leads.length, 1);
    assert.equal(checkpoint.leads[0].subject.path, publicPath);
    assert.ok(!JSON.stringify(checkpoint).includes('fixture-owner'));
    const ownerBefore = ownerReads.length;
    const resumed = await cli('resume', first.data.run);
    assert.ok(resumed.data.runDir, resumed.stderr);
    const web = JSON.parse(fs.readFileSync(path.join(resumed.data.runDir,
      'web-probes.json'), 'utf8'));
    assert.equal(web.results.filter(item => item.kind === 'model-access-boundary' &&
      item.lead.path === publicPath && item.verdict === 'confirmed').length, 1);
    assert.ok(submitted.includes('wide-one'));
    assert.ok(submitted.includes('wide-two'));
    const attempts = fs.readFileSync(path.join(resumed.data.runDir,
      'evidence.jsonl'), 'utf8').trim().split('\n').map(JSON.parse)
      .filter(item => item.kind === 'model-access-boundary-attempt' &&
        item.path === publicPath);
    assert.equal(attempts.length, 1, 'the queued access lead executes once before proof replay');
    assert.ok(ownerReads.slice(ownerBefore).includes(true));
    assert.ok(ownerReads.slice(ownerBefore).includes(false));
    const finding = resumed.data.findings.find(item =>
      item.kind === 'model-access-boundary' && item.pattern === publicPath);
    assert.ok(finding?.proof, JSON.stringify(resumed.data.findings));
    const proof = await execFile(process.execPath, [finding.proof],
      {cwd: root, env, timeout: 20000});
    assert.equal(JSON.parse(proof.stdout).verdict, 'confirmed');
    const exported = await cli('export', resumed.data.run, '--out', path.join(root, 'regression'));
    assert.equal(exported.code, 0, exported.stderr);
    const regression = () => execFile(process.execPath,
      ['--test', ...exported.data.files],
      {cwd: root, env: {...env, NODE_TEST_CONTEXT: undefined}, timeout: 20000});
    assert.equal((await regression()).code, 1);
    vulnerable = false;
    assert.equal(JSON.parse((await execFile(process.execPath, [finding.proof],
      {cwd: root, env, timeout: 20000})).stdout).verdict, 'not_reproduced');
    assert.equal((await regression()).code, 0);
    const complete = JSON.parse(fs.readFileSync(path.join(resumed.data.runDir,
      'access-boundary-checkpoint.json'), 'utf8'));
    assert.equal(complete.cursor, complete.leads.length);
  });
