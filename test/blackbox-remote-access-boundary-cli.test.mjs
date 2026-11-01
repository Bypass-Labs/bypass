import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import http from 'node:http';
import os from 'node:os';
import path from 'node:path';
import {randomBytes} from 'node:crypto';
import {pathToFileURL} from 'node:url';
import {CLI} from '../src/demo.mjs';
import {change} from '../src/store.mjs';
import {execFile} from '../src/util.mjs';
import {cli} from './helpers.mjs';

for (const sequence of [false, true]) test(`authorized deployed protected-body ${sequence ? 'sequence' : 'direct'} proof replays red and green over HTTPS`, async t => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'bypass-remote-boundary-'));
  t.after(() => fs.rmSync(root, {recursive: true, force: true}));
  const origin = 'https://app.example.test';
  const suffix = randomBytes(4).toString('hex');
  const protectedPath = `/api/private-${suffix}`;
  const publicPath = `/api/filter-${suffix}`;
  const seedPath = `/api/seed-${suffix}`;
  const ownerBody = JSON.stringify({id: `owner-${suffix}`,
    secret: 'owned-document', pad: 'x'.repeat(80)});
  let vulnerable = true;
  const seen = [];
  const server = http.createServer(async (request, response) => {
    const url = new URL(request.url, 'http://fixture');
    seen.push(`${request.method} ${url.pathname}`);
    response.setHeader('content-type', 'application/json');
    response.setHeader('cache-control', 'no-store');
    if (request.method === 'GET' && url.pathname === '/')
      return response.end(JSON.stringify({app: 'documents', docs: '/openapi.json'}));
    if (request.method === 'GET' && url.pathname === '/openapi.json')
      return response.end(JSON.stringify({openapi: '3.0.0', paths: {
        [protectedPath]: {get: {summary: 'Read owner document'}},
        [seedPath]: {get: {summary: 'Read public filter seed'}},
        [publicPath]: {post: {summary: 'Filter public documents', requestBody: {
          content: {'application/json': {schema: {type: 'object',
            required: ['term'], properties: {term: {type: 'string'}}}}}}}},
      }}));
    if (request.method === 'GET' && url.pathname === protectedPath) {
      if (request.headers.authorization === 'Bearer fixture-owner')
        return response.end(ownerBody);
      response.statusCode = 403;
      return response.end(JSON.stringify({error: 'forbidden'}));
    }
    if (request.method === 'GET' && url.pathname === seedPath)
      return response.end(JSON.stringify({seed: 'public'}));
    if (request.method === 'POST' && url.pathname === publicPath) {
      const chunks = [];
      for await (const chunk of request) chunks.push(chunk);
      let body;
      try {body = JSON.parse(Buffer.concat(chunks).toString());}
      catch {response.statusCode = 400; return response.end('{}');}
      return response.end(vulnerable && ['wide-one', 'wide-two'].includes(body.term) ?
        ownerBody : JSON.stringify({records: []}));
    }
    response.statusCode = 404;
    return response.end(JSON.stringify({error: 'missing'}));
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  t.after(() => new Promise(resolve => server.close(resolve)));

  const shim = path.join(root, 'mock-remote.mjs');
  fs.writeFileSync(shim, [
    "import dns from 'node:dns/promises';",
    "import https from 'node:https';",
    "import http from 'node:http';",
    'const host=process.env.BX_REMOTE_HOST;',
    'const originalLookup=dns.lookup.bind(dns);',
    "dns.lookup=async (name,options)=>name===host?(options?.all?[{address:'8.8.8.8',family:4}]:{address:'8.8.8.8',family:4}):originalLookup(name,options);",
    'const originalRequest=https.request.bind(https);',
    'https.request=(input,options,callback)=>{',
    ' const target=new URL(input);',
    ' if(target.hostname!==host)return originalRequest(input,options,callback);',
    " const local=new URL(`${target.pathname}${target.search}`,`http://127.0.0.1:${process.env.BX_FIXTURE_PORT}`);",
    ' const redirected={...options};delete redirected.lookup;delete redirected.servername;',
    ' return http.request(local,redirected,callback);',
    '};',
  ].join('\n'));

  const setup = await cli(root, 'blackbox', 'setup', origin, '--rps', '10',
    '--owner-env', 'OWNER_TOKEN');
  assert.equal(setup.code, 0, JSON.stringify(setup.data));
  const blocked = await cli(root, 'blackbox', origin, '--scope', setup.data.scopeFile,
    '--no-model');
  assert.equal(blocked.code, 3, JSON.stringify(blocked.data));
  assert.deepEqual(seen, [], 'unverified deployed target must receive no request');
  const expiresAt = new Date(Date.now() + 86400000).toISOString();
  await change(root, state => {
    for (const target of state.targets) target.ownership =
      {status: 'verified', method: 'dns', expiresAt, origin: target.url};
    return null;
  });
  for (const step of setup.data.steps.filter(item => item.kind === 'authorization')) {
    const approved = await cli(root, 'target', 'authorize', step.target,
      '--scope-file', step.file, '--accept', '--production');
    assert.equal(approved.code, 0, JSON.stringify(approved.data));
    assert.ok(approved.data.authorization.methods.includes('POST'));
  }

  const bin = path.join(root, 'bin');
  fs.mkdirSync(bin);
  fs.writeFileSync(path.join(bin, 'muse'), [
    '#!' + process.execPath,
    "const fs=require('node:fs');",
    'const args=process.argv.slice(2);',
    'const value=flag=>args[args.indexOf(flag)+1];',
    "if(args.includes('--version')){console.log('muse fixture');process.exit(0);}",
    "if(args[0]!=='exec'||!args.includes('--output-schema'))process.exit(2);",
    "const messages=JSON.parse(fs.readFileSync(value('--prompt-file'),'utf8'));",
    'const system=messages[0].content,context=JSON.parse(messages[1].content);',
    'let answer;',
    "if(system.startsWith('You are planning bounded, authorized HTTP research.')){",
    ' const operation=context.routes.find(item=>item.kind===\'json\'&&item.path===process.env.BX_PUBLIC);',
    ' const privateRead=context.protectedReadRoutes?.find(item=>item===process.env.BX_PRIVATE);',
    ' const seed=context.observedReadRoutes?.find(item=>item.path===process.env.BX_SEED);',
    " answer={flows:operation&&privateRead&&(!process.env.BX_SEQUENCE||seed)?[{family:'owner-content-disclosure',why:'Public filter may return owner-only document',priority:10,as:'anonymous',oracle:'protected-body',protectedPath:privateRead,prelude:process.env.BX_SEQUENCE?[{method:'GET',path:seed.path,headers:[]}]:[],subject:{method:'POST',path:operation.path,placement:'json',key:'term',fixedFields:[],bodyTemplate:'',headers:[]},observe:[],controlValue:'plain',firstValue:'wide-one',secondValue:'wide-two',marker:context.marker,secondMarker:context.secondMarker,assertion:{step:'subject',index:0,location:'body',name:''}}]:[]};",
    '} else {',
    " const schema=JSON.parse(fs.readFileSync(value('--output-schema'),'utf8'));",
    " const blank=s=>s?.type==='object'?Object.fromEntries((s.required??[]).map(key=>[key,blank(s.properties?.[key])])):s?.type==='array'?[]:s?.type==='integer'||s?.type==='number'?0:s?.type==='boolean'?false:s?.enum?.[0]??'';",
    ' answer=blank(schema);',
    '}',
    "console.log(JSON.stringify({payload:{kind:'run_terminal',terminal:'completed',text:JSON.stringify(answer)}}));",
  ].join('\n') + '\n', {mode: 0o700});
  const env = {...process.env, PATH: `${bin}${path.delimiter}${process.env.PATH}`,
    OWNER_TOKEN: 'fixture-owner', BX_PUBLIC: publicPath,
    BX_PRIVATE: protectedPath, BX_SEED: seedPath,
    BX_SEQUENCE: sequence ? '1' : '', BX_REMOTE_HOST: new URL(origin).hostname,
    BX_FIXTURE_PORT: String(server.address().port),
    NODE_OPTIONS: `${process.env.NODE_OPTIONS ?? ''} --import=${pathToFileURL(shim).href}`.trim()};
  const auditCall = async (...args) => {
    const completed = await execFile(process.execPath,
      [CLI, 'blackbox', ...args, '--project', root, '--json', '--non-interactive'],
      {cwd: root, env, timeout: 90000});
    return {code: completed.code, data: JSON.parse(completed.stdout)};
  };
  const audit = await auditCall(origin, '--scope', setup.data.scopeFile,
    '--offline');
  const finding = audit.data.findings?.find(item =>
    item.kind === 'model-access-boundary');
  assert.ok(finding?.proof, JSON.stringify({root, runDir: audit.data.runDir,
    code: audit.code, findings: audit.data.findings}));
  const proofSpec = JSON.parse(fs.readFileSync(path.join(path.dirname(finding.proof),
    'spec.json'), 'utf8'));
  assert.equal(proofSpec.comparison, sequence ? 'sequence-exact-body' : 'exact-body');
  assert.ok(seen.some(item => item === `POST ${publicPath}`));
  assert.equal((await auditCall('verify', audit.data.run)).code, 1);
  const exported = await auditCall('export', audit.data.run, '--out',
    path.join(root, 'regression'));
  assert.equal(exported.code, 0, JSON.stringify(exported.data));
  const regressionEnv = {...env, NODE_TEST_CONTEXT: undefined};
  const regression = () => execFile(process.execPath,
    ['--test', ...exported.data.files], {env: regressionEnv, timeout: 20000});
  const regressionRed = await regression();
  assert.equal(regressionRed.code, 1, JSON.stringify({files: exported.data.files,
    stdout: regressionRed.stdout, stderr: regressionRed.stderr}));
  vulnerable = false;
  assert.equal((await auditCall('verify', audit.data.run)).code, 0);
  assert.equal((await regression()).code, 0);
});
