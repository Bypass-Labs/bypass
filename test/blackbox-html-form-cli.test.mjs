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

test('a form-only local app reaches Muse, executes its POST and replays the proof', async t => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'bypass-html-form-cli-'));
  t.after(() => fs.rmSync(root, {recursive: true, force: true}));
  const route = `/api/preview-${randomBytes(4).toString('hex')}`;
  let vulnerable = true;
  let posts = 0;
  const server = http.createServer(async (request, response) => {
    const url = new URL(request.url, 'http://fixture');
    if (request.method === 'GET' && url.pathname === '/') {
      response.writeHead(200, {'content-type': 'text/html'});
      response.end(`<form method="post" action="${route}">
        <input name="expression" required><button type="submit">Preview</button></form>`);
      return;
    }
    if (request.method === 'POST' && url.pathname === route) {
      posts++;
      const chunks = [];
      for await (const chunk of request) chunks.push(chunk);
      const value = new URLSearchParams(Buffer.concat(chunks).toString()).get('expression') ?? '';
      let result = value;
      if (vulnerable) try {result = Function(`return (${value})`)();}
      catch {result = 'invalid';}
      response.writeHead(200, {'content-type': 'application/json'});
      response.end(JSON.stringify({result}));
      return;
    }
    response.writeHead(404, {'content-type': 'text/plain'});
    response.end('missing');
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  t.after(() => new Promise(resolve => server.close(resolve)));
  const origin = `http://127.0.0.1:${server.address().port}`;
  const scopePath = path.join(root, 'scope.json');
  fs.writeFileSync(scopePath, JSON.stringify({schemaVersion: 1, target: {origin},
    include: ['/'], limits: {rps: 30}}));
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
    " answer={flows:operation?[{family:'expression-transform',why:'Observed form input',priority:10,as:'anonymous',prelude:[],subject:{method:'POST',path:operation.path,placement:'form',key:'expression',fixedFields:[],bodyTemplate:'',headers:[]},observe:[],binding:null,controlValue:'7',firstValue:encode(context.marker),secondValue:encode(context.secondMarker),marker:context.marker,secondMarker:context.secondMarker,assertion:{step:'subject',index:0,location:'body',name:''}}]:[]};",
    '} else {',
    " const schema=JSON.parse(fs.readFileSync(value('--output-schema'),'utf8'));",
    " const blank=s=>s?.type==='object'?Object.fromEntries((s.required??[]).map(key=>[key,blank(s.properties?.[key])])):s?.type==='array'?[]:s?.type==='integer'||s?.type==='number'?0:s?.type==='boolean'?false:s?.enum?.[0]??'';",
    ' answer=blank(schema);',
    '}',
    "console.log(JSON.stringify({payload:{kind:'run_terminal',terminal:'completed',text:JSON.stringify(answer)}}));",
  ].join('\n') + '\n', {mode: 0o700});
  const env = {PATH: `${bin}${path.delimiter}${process.env.PATH}`, BX_ROUTE: route};
  const cli = async (...args) => {
    const completed = await execFile(process.execPath,
      [CLI, 'blackbox', ...args, '--project', root, '--json', '--non-interactive'],
      {cwd: root, env, timeout: 90000});
    return {code: completed.code, data: JSON.parse(completed.stdout)};
  };
  const audit = await cli(origin, '--scope', scopePath);
  assert.ok(audit.data.runDir, JSON.stringify(audit));
  const admitted = JSON.parse(fs.readFileSync(path.join(audit.data.runDir,
    'local-post-contracts.json'), 'utf8'));
  const surface = JSON.parse(fs.readFileSync(path.join(audit.data.runDir,
    'surface.json'), 'utf8'));
  const web = JSON.parse(fs.readFileSync(path.join(audit.data.runDir,
    'web-probes.json'), 'utf8'));
  assert.deepEqual(admitted.admitted.map(item => item.path), [route]);
  assert.ok(surface.formBodyOperations.some(item => item.path === route));
  assert.ok(posts >= 3, `Only ${posts} form POSTs executed`);
  const finding = audit.data.findings.find(item => item.kind === 'model-http-sequence');
  assert.ok(finding?.proof, JSON.stringify({findings: audit.data.findings,
    decisions: web.strategyDecisions?.filter(item =>
      String(item.mode).includes('http-sequence'))}));
  assert.equal((await cli('verify', audit.data.run)).code, 1);
  const exported = await cli('export', audit.data.run, '--out', path.join(root, 'regression'));
  assert.equal(exported.code, 0);
  assert.equal(exported.data.files.length, 1);
  const regression = () => new Promise((resolve, reject) => {
    const child = spawn(process.execPath, ['--test', ...exported.data.files],
      {env: Object.fromEntries(Object.entries(process.env).filter(([key]) =>
        key !== 'NODE_TEST_CONTEXT')), stdio: 'ignore'});
    child.once('error', reject);
    child.once('close', resolve);
  });
  assert.equal(await regression(), 1);
  vulnerable = false;
  assert.equal((await cli('verify', audit.data.run)).code, 0);
  assert.equal(await regression(), 0);
});
