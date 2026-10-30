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

test('CLI proves Muse-selected owner-only text disclosure and exported test clears after repair',
  async t => {
    const root = fs.mkdtempSync(path.join(os.tmpdir(), 'bypass-content-cli-'));
    t.after(() => fs.rmSync(root, {recursive: true, force: true}));
    const suffix = randomBytes(4).toString('hex');
    const privatePath = `/api/${suffix}/private/export`;
    const publicPath = `/api/${suffix}/public/download`;
    const decoyPath = `/api/${suffix}/delete`;
    const privateBody = `Owner-only export ${suffix}: ` +
      'controlled confidential account details '.repeat(5);
    let vulnerable = true, decoyHits = 0;
    const seen = [];
    const server = http.createServer((request, response) => {
      const url = new URL(request.url, 'http://fixture');
      seen.push(`${request.method} ${url.pathname}`);
      const reply = (status, body, type = 'text/plain') => {
        response.writeHead(status, {'content-type': type, 'cache-control': 'no-store'});
        response.end(body);
      };
      if (url.pathname === decoyPath) {decoyHits++; return reply(405, 'Protected decoy');}
      if (url.pathname === '/') return reply(200,
        `<a href="${publicPath}?name=normal">Download a public file</a>`, 'text/html');
      if (url.pathname === '/openapi.json') return reply(200,
        JSON.stringify({openapi: '3.0.0', paths: {
          [publicPath]: {get: {summary: 'Download a named public file', parameters: [
            {name: 'name', in: 'query', schema: {type: 'string'}, example: 'normal'}]}},
          [privatePath]: {get: {summary: 'Read the owner export'}},
        }}), 'application/json');
      if (request.method === 'GET' && url.pathname === privatePath)
        return request.headers.authorization === 'Bearer fixture-owner' ?
          reply(200, privateBody) : reply(403, 'Owner only');
      if (request.method === 'GET' && url.pathname === publicPath)
        return reply(200, vulnerable && ['all', 'archive'].includes(url.searchParams.get('name')) ?
          privateBody : `Public file ${url.searchParams.get('name') ?? 'none'}.`);
      return reply(404, 'Not found');
    });
    await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
    t.after(() => new Promise(resolve => server.close(resolve)));
    const origin = `http://127.0.0.1:${server.address().port}`;
    fs.writeFileSync(path.join(root, 'blackbox.scope.json'),
      JSON.stringify({schemaVersion: 1, target: {origin}, include: ['/'],
        never: [decoyPath], identities: {identityPath: privatePath},
        limits: {rps: 50, minutes: 2, tasks: 80, modelCalls: 20}}));
    const bin = path.join(root, 'bin');
    fs.mkdirSync(bin);
    fs.writeFileSync(path.join(bin, 'muse'), [
      '#!' + process.execPath,
      "const fs=require('node:fs');",
      'const args=process.argv.slice(2);',
      'const value=flag=>args[args.indexOf(flag)+1];',
      "if(args.includes('--version')){console.log('muse fixture');process.exit(0);}",
      "if(args[0]!=='exec'||!args.includes('--output-schema')||value('--provider')!=='meta')process.exit(2);",
      "const messages=JSON.parse(fs.readFileSync(value('--prompt-file'),'utf8'));",
      'const system=messages[0].content;',
      'let answer;',
      "if(system.startsWith('You are investigating whether an observed anonymous GET query input')){",
      ' const context=JSON.parse(messages[1].content);',
      " const owner=context.protectedReads.find(item=>item.path===process.env.BX_PRIVATE&&item.ownerType==='text/plain'&&item.ownerBytes>=64);",
      " const input=context.publicGets.find(item=>item.path===process.env.BX_PUBLIC&&item.fields.includes('name'));",
      " answer={tests:owner&&input?[{family:'private export disclosure',why:'The public selector may return the owner export',priority:9,comparison:'exact-body',protectedPath:owner.path,subject:{method:'GET',path:input.path,placement:'query',key:'name',fixedFields:[]},controlValue:'normal',firstValue:'all',secondValue:'archive',ownerPointer:'',candidatePointer:'',identityField:'',matchFields:[]}]:[]};",
      '} else {',
      " const schema=JSON.parse(fs.readFileSync(value('--output-schema'),'utf8'));",
      " const blank=s=>s?.type==='object'?Object.fromEntries((s.required??[]).map(key=>[key,blank(s.properties?.[key])])):s?.type==='array'?[]:s?.type==='integer'||s?.type==='number'?0:s?.type==='boolean'?false:s?.enum?.[0]??'';",
      ' answer=blank(schema);',
      '}',
      "console.log(JSON.stringify({payload:{kind:'run_terminal',terminal:'completed',text:JSON.stringify(answer)}}));",
    ].join('\n') + '\n', {mode: 0o700});
    const env = {...process.env, PATH: `${bin}${path.delimiter}${process.env.PATH}`,
      BX_PRIVATE: privatePath, BX_PUBLIC: publicPath, OWNER_TOKEN: 'fixture-owner'};
    const cli = async (...args) => {
      const completed = await execFile(process.execPath,
        [CLI, 'blackbox', ...args, '--project', root, '--json', '--non-interactive'],
        {cwd: root, env, timeout: 120000});
      return {code: completed.code, data: JSON.parse(completed.stdout)};
    };
    const audit = await cli(origin, '--rps', '30', '--offline');
    const finding = audit.data.findings.find(item =>
      item.kind === 'model-access-boundary' && item.webProof?.comparison === 'exact-body');
    assert.ok(finding?.proof, JSON.stringify({findings: audit.data.findings,
      model: audit.data.modelOutput, run: audit.data.runDir}));
    assert.equal(finding.verdict, 'confirmed');
    assert.equal(audit.code, 1);
    assert.equal((await cli('verify', audit.data.run)).code, 1);
    const exported = await cli('export', audit.data.run, '--out', path.join(root, 'regression'));
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
    assert.equal(decoyHits, 0);
    assert.ok(seen.every(item => item.startsWith('GET ') || item.startsWith('HEAD ')));
  });
