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

test('authorized deployed CLI executes and replays an observed model-selected POST', async t => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'bypass-remote-post-cli-'));
  t.after(() => fs.rmSync(root, {recursive: true, force: true}));
  const origin = 'https://app.example.test';
  const route = `/api/calculate-${randomBytes(4).toString('hex')}`;
  const seen = [];
  let vulnerable = true;
  const server = http.createServer(async (request, response) => {
    const url = new URL(request.url, 'http://fixture');
    seen.push(`${request.method} ${url.pathname}`);
    const json = (status, body) => {
      response.writeHead(status, {'content-type': 'application/json', 'cache-control': 'no-store'});
      response.end(JSON.stringify(body));
    };
    if (request.method === 'GET' && url.pathname === '/')
      return json(200, {app: 'calculator'});
    if (request.method === 'GET' && url.pathname === '/openapi.json')
      return json(200, {openapi: '3.0.0', paths: {[route]: {post: {
        summary: 'Calculate a supplied expression', requestBody: {content: {
          'application/x-www-form-urlencoded': {schema: {type: 'object',
            required: ['expression'], properties: {expression: {type: 'string'}}}}}}}}}});
    if (request.method === 'POST' && url.pathname === route) {
      const chunks = [];
      for await (const chunk of request) chunks.push(chunk);
      const value = new URLSearchParams(Buffer.concat(chunks).toString()).get('expression') ?? '';
      let result = value;
      if (vulnerable) try {result = Function(`return (${value})`)();}
      catch {result = 'invalid';}
      return json(200, {result});
    }
    return json(404, {error: 'missing'});
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  t.after(() => new Promise(resolve => server.close(resolve)));

  // Redirect only this synthetic HTTPS hostname to the local fixture. The CLI
  // still performs its deployed scope, target-authorization and public-IP checks.
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

  const setup = await cli(root, 'blackbox', 'setup', origin, '--rps', '10');
  assert.equal(setup.code, 0, JSON.stringify(setup.data));
  assert.ok(setup.data.steps.some(item => item.kind === 'authorization'));
  const blocked = await cli(root, 'blackbox', origin, '--scope', setup.data.scopeFile,
    '--no-model');
  assert.equal(blocked.code, 3, JSON.stringify(blocked.data));
  assert.deepEqual(seen, []);
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
    assert.deepEqual(approved.data.authorization.methods,
      ['GET', 'HEAD', 'POST', 'PATCH', 'DELETE']);
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
    " const operation=context.routes.find(item=>item.kind==='form'&&item.path===process.env.BX_ROUTE);",
    " const encode=value=>`String.fromCharCode(${[...value].map(char=>char.charCodeAt(0)).join(',')})`;",
    " answer={flows:operation?[{family:'expression-transform',why:'Observed calculator input',priority:10,as:'anonymous',prelude:[],subject:{method:'POST',path:operation.path,placement:'form',key:'expression',fixedFields:[],bodyTemplate:'',headers:[]},observe:[],controlValue:'7',firstValue:encode(context.marker),secondValue:encode(context.secondMarker),marker:context.marker,secondMarker:context.secondMarker,assertion:{step:'subject',index:0,location:'body',name:''}}]:[]};",
    '} else {',
    " const schema=JSON.parse(fs.readFileSync(value('--output-schema'),'utf8'));",
    " const blank=s=>s?.type==='object'?Object.fromEntries((s.required??[]).map(key=>[key,blank(s.properties?.[key])])):s?.type==='array'?[]:s?.type==='integer'||s?.type==='number'?0:s?.type==='boolean'?false:s?.enum?.[0]??'';",
    ' answer=blank(schema);',
    '}',
    "console.log(JSON.stringify({payload:{kind:'run_terminal',terminal:'completed',text:JSON.stringify(answer)}}));",
  ].join('\n') + '\n', {mode: 0o700});
  const env = {PATH: `${bin}${path.delimiter}${process.env.PATH}`, BX_ROUTE: route,
    BX_REMOTE_HOST: new URL(origin).hostname, BX_FIXTURE_PORT: String(server.address().port),
    NODE_OPTIONS: `${process.env.NODE_OPTIONS ?? ''} --import=${pathToFileURL(shim).href}`.trim()};
  const auditCall = async (...args) => {
    const completed = await execFile(process.execPath,
      [CLI, 'blackbox', ...args, '--project', root, '--json', '--non-interactive'],
      {cwd: root, env, timeout: 90000});
    return {code: completed.code, data: JSON.parse(completed.stdout)};
  };
  const audit = await auditCall(origin, '--scope', setup.data.scopeFile);
  assert.ok(audit.data.runDir, JSON.stringify(audit));
  const admitted = JSON.parse(fs.readFileSync(path.join(audit.data.runDir,
    'local-post-contracts.json'), 'utf8'));
  const finding = audit.data.findings.find(item => item.kind === 'model-http-sequence');
  assert.ok(admitted.admitted.some(item => item.path === route), JSON.stringify(admitted));
  assert.ok(seen.filter(item => item === `POST ${route}`).length >= 3,
    JSON.stringify(seen.filter(item => item.startsWith('POST '))));
  assert.ok(finding?.proof, JSON.stringify(audit.data.findings));
  assert.equal(finding.verdict, 'observed');
  assert.equal((await auditCall('verify', audit.data.run)).code, 1);
  vulnerable = false;
  assert.equal((await auditCall('verify', audit.data.run)).code, 0);
});
