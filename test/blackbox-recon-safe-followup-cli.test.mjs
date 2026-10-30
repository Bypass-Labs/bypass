import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import http from 'node:http';
import os from 'node:os';
import path from 'node:path';
import {randomBytes} from 'node:crypto';
import {execFile} from '../src/util.mjs';
import {CLI} from '../src/demo.mjs';

test('CLI keeps a model-proposed JSON secret out of Muse and artifacts while following its route hint', async t => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'bypass-recon-safe-'));
  t.after(() => fs.rmSync(root, {recursive: true, force: true}));
  const suffix = randomBytes(4).toString('hex');
  const seed = `/api/seed-${suffix}`;
  const proposed = `/api/probe-${suffix}`;
  const hidden = `/api/hidden-${suffix}`;
  const secret = `n_${randomBytes(6).toString('hex')}`;
  const requested = [];
  const server = http.createServer((request, response) => {
    const url = new URL(request.url, 'http://fixture');
    requested.push(url.pathname);
    response.setHeader('cache-control', 'no-store');
    response.setHeader('content-type', 'application/json');
    if (url.pathname === '/') {
      response.setHeader('content-type', 'text/html');
      return response.end('<a href="/openapi.json">API</a><script src="/app.js"></script>');
    }
    if (url.pathname === '/app.js') {
      response.setHeader('content-type', 'application/javascript');
      return response.end(`fetch('${seed}');`);
    }
    if (url.pathname === '/openapi.json') return response.end(JSON.stringify({
      openapi: '3.0.0', paths: {'/api/me': {get: {}}, [seed]: {get: {}}}}));
    if (url.pathname === '/api/me') {
      const who = request.headers.authorization === 'Bearer owner-test-token' ? 'owner' :
        request.headers.authorization === 'Bearer outsider-test-token' ? 'outsider' : null;
      response.statusCode = who ? 200 : 401;
      return response.end(JSON.stringify(who ? {id: who, role: 'member'} : {error: 'Sign in'}));
    }
    if (url.pathname === seed) return response.end(JSON.stringify({service: 'records'}));
    if (url.pathname === proposed) return response.end(JSON.stringify({
      nonce: secret, nextRoute: hidden, status: 'ready'}));
    if (url.pathname === hidden) return response.end(JSON.stringify({ready: true}));
    response.statusCode = 404;
    response.end(JSON.stringify({error: 'missing'}));
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  t.after(() => new Promise(resolve => server.close(resolve)));
  const origin = `http://127.0.0.1:${server.address().port}`;
  const bin = path.join(root, 'bin'), trace = path.join(root, 'muse-calls.jsonl');
  fs.mkdirSync(bin);
  fs.writeFileSync(path.join(bin, 'muse'), [
    '#!' + process.execPath,
    "const fs=require('node:fs');",
    'const args=process.argv.slice(2);',
    'const value=flag=>args[args.indexOf(flag)+1];',
    "if(args.includes('--version')){console.log('muse fixture');process.exit(0);}",
    "if(args[0]!=='exec'||!args.includes('--output-schema'))process.exit(2);",
    "const messages=JSON.parse(fs.readFileSync(value('--prompt-file'),'utf8'));",
    'fs.appendFileSync(process.env.BX_TRACE,JSON.stringify(messages)+"\\n");',
    'const system=messages[0].content;',
    'let answer;',
    "if(system.includes('mapping an authorized web API'))answer={paths:[process.env.BX_PROPOSED],notes:[]};",
    "else if(system.includes('Continue mapping this authorized web API')){const context=JSON.parse(messages[1].content);const item=context.observations.find(row=>row.path===process.env.BX_PROPOSED);answer={paths:item?.routeHints?.some(h=>h.path===process.env.BX_HIDDEN)?[process.env.BX_HIDDEN]:[]};}",
    "else if(system.includes('Interpret only the extracted')){const context=JSON.parse(messages[1].content);answer={files:context.files.map(file=>({id:file.id,role:'app',why:'Observed public client',authFlow:'',routes:(file.routes??[]).map(route=>({path:route.path,method:route.method,purpose:'Observed route',parameters:[]}))}))};}",
    'else {const schema=JSON.parse(fs.readFileSync(value("--output-schema"),"utf8"));',
    'const blank=s=>s?.type==="object"?Object.fromEntries((s.required??[]).map(k=>[k,blank(s.properties?.[k])])):s?.type==="array"?[]:s?.type==="integer"||s?.type==="number"?0:s?.type==="boolean"?false:s?.enum?.[0]??"";',
    'answer=blank(schema);}',
    "console.log(JSON.stringify({payload:{kind:'run_terminal',terminal:'completed',text:JSON.stringify(answer)}}));",
  ].join('\n') + '\n', {mode: 0o700});
  const env = {PATH: `${bin}${path.delimiter}${process.env.PATH}`,
    OWNER_TOKEN: 'owner-test-token', OTHER_TOKEN: 'outsider-test-token',
    BX_PROPOSED: proposed, BX_HIDDEN: hidden, BX_TRACE: trace};
  const completed = await execFile(process.execPath,
    [CLI, 'blackbox', origin, '--accept-local', '--project', root,
      '--rps', '50', '--model-calls', '16', '--minutes', '2', '--offline',
      '--json', '--non-interactive'], {cwd: root, env, timeout: 90000});
  const audit = JSON.parse(completed.stdout);
  const systems = fs.existsSync(trace) ? fs.readFileSync(trace, 'utf8').trim().split('\n')
    .filter(Boolean).map(row => JSON.parse(row)[0].content.slice(0, 120)) : [];
  assert.ok(requested.includes(proposed), JSON.stringify({requested, systems,
    limitations: audit.limitations}));
  assert.ok(requested.includes(hidden), JSON.stringify(audit.limitations));
  const prompt = fs.readFileSync(trace, 'utf8');
  assert.ok(prompt.includes(hidden), 'Muse received the literal route hint');
  assert.ok(!prompt.includes(secret), 'Muse never received the unrelated nonce');
  const files = [];
  const walk = directory => {
    for (const item of fs.readdirSync(directory, {withFileTypes: true})) {
      const file = path.join(directory, item.name);
      if (item.isDirectory()) walk(file);
      else files.push(file);
    }
  };
  walk(audit.runDir);
  assert.ok(files.every(file => !fs.readFileSync(file, 'utf8').includes(secret)),
    'the nonce never entered the saved run');
});
