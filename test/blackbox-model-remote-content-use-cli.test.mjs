import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import http from 'node:http';
import os from 'node:os';
import path from 'node:path';
import {randomBytes} from 'node:crypto';
import {CLI} from '../src/demo.mjs';
import {execFile} from '../src/util.mjs';

test('blind CLI proves remote response content use and clears while server fetch remains',
  {timeout: 120000}, async t => {
    if (process.platform === 'win32') return t.skip('the Muse fixture uses a POSIX executable');
    const root = fs.mkdtempSync(path.join(os.tmpdir(), 'bypass-remote-content-use-'));
    t.after(() => fs.rmSync(root, {recursive: true, force: true}));
    const route = `/api/preview-${randomBytes(5).toString('hex')}`;
    let vulnerable = true, callbackFetches = 0;
    const server = http.createServer(async (request, response) => {
      const pathname = new URL(request.url, 'http://fixture.invalid').pathname;
      const json = (status, body) => {
        response.writeHead(status, {'content-type': 'application/json',
          'cache-control': 'no-store'});
        response.end(JSON.stringify(body));
      };
      if (request.method === 'GET' && pathname === '/') {
        response.writeHead(200, {'content-type': 'text/html'});
        return response.end('<html><a href="/openapi.json">API</a></html>');
      }
      if (request.method === 'GET' && pathname === '/openapi.json')
        return json(200, {openapi: '3.0.0', paths: {[route]: {post: {
          summary: 'Build a text preview from a remote resource URL',
          requestBody: {content: {'application/json': {schema: {type: 'object',
            required: ['resourceUrl'], properties: {resourceUrl: {type: 'string'}}}}}}}}}});
      if (request.method !== 'POST' || pathname !== route)
        return json(404, {error: 'missing'});
      const chunks = [];
      for await (const chunk of request) chunks.push(chunk);
      let input;
      try {input = JSON.parse(Buffer.concat(chunks).toString());}
      catch {return json(400, {error: 'invalid JSON'});}
      const destination = String(input.resourceUrl ?? '');
      let remoteBody = '';
      if (/^http:\/\/127\.0\.0\.1:\d+\/bx-ssrf\/[0-9a-f]{24}$/.test(destination)) {
        callbackFetches++;
        remoteBody = await new Promise(resolve => {
          http.get(destination, fetched => {
            const body = [];
            fetched.on('data', chunk => body.push(chunk));
            fetched.on('end', () => resolve(Buffer.concat(body).toString()));
          }).on('error', () => resolve(''));
        });
      }
      return json(200, {rendered: vulnerable ? remoteBody : 'preview ready'});
    });
    await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
    t.after(() => new Promise(resolve => server.close(resolve)));
    const origin = `http://127.0.0.1:${server.address().port}`;
    const scopeFile = path.join(root, 'blackbox.scope.json');
    fs.writeFileSync(scopeFile, JSON.stringify({schemaVersion: 1,
      target: {origin}, include: ['/'], probes: {jsonPostPaths: [route]},
      limits: {rps: 50, maxUrls: 50, minutes: 3, modelCalls: 60, tasks: 40}}));
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
      'const context=JSON.parse(messages.at(-1).content);',
      'let answer;',
      "if(system.startsWith('You are planning bounded, authorized HTTP research.')){",
      " const post=context.routes.find(item=>item.kind==='json'&&item.fields?.includes('resourceUrl'));",
      " answer={flows:post?[{family:'remote-resource-use',why:'The documented URL may supply the rendered preview body',priority:10,as:'anonymous',oracle:'remote-content-use',protectedPath:'',prelude:[],subject:{method:'POST',path:post.path,placement:'json',key:'resourceUrl',fixedFields:[],bodyTemplate:'',headers:[]},observe:[],binding:null,controlValue:'',firstValue:'',secondValue:'',marker:'',secondMarker:'',assertion:{step:'subject',index:0,location:'body',name:''}}]:[]};",
      '}',
      "else if(system.startsWith('Revise at most one bounded, authorized HTTP experiment'))answer={flows:[]};",
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
    const env = {...process.env, PATH: `${bin}${path.delimiter}${process.env.PATH}`};
    const cli = async (...args) => {
      const done = await execFile(process.execPath,
        [CLI, 'blackbox', ...args, '--project', root, '--json', '--non-interactive'],
        {cwd: root, env, timeout: 90000});
      return {code: done.code, data: JSON.parse(done.stdout)};
    };
    const audit = await cli(origin, '--scope', scopeFile, '--offline');
    assert.ok(audit.data.runDir, JSON.stringify(audit));
    const web = JSON.parse(fs.readFileSync(path.join(audit.data.runDir,
      'web-probes.json'), 'utf8'));
    assert.ok(web.strategyDecisions.some(item => item.mode === 'http-sequence' &&
      item.accepted),
    JSON.stringify(web.strategyDecisions.filter(item => item.mode === 'http-sequence')));
    assert.ok(web.investigations.some(item => item.attempts?.some(attempt =>
      attempt.oracle === 'remote-content-use')),
    'the accepted Muse oracle must execute as a content-use check');
    const finding = audit.data.findings.find(item => item.kind === 'remote-content-use' &&
      item.pattern === route);
    assert.ok(finding?.proof, JSON.stringify({findings: audit.data.findings,
      results: web.results, investigations: web.investigations}));
    assert.equal(finding.verdict, 'confirmed');
    assert.doesNotMatch(finding.title, /\b(?:RCE|code execution)\b/i);
    assert.ok(callbackFetches >= 2, 'the target fetched two audit-owned resources');
    const proof = JSON.parse((await execFile(process.execPath, [finding.proof],
      {env, timeout: 20000})).stdout);
    assert.equal(proof.verdict, 'confirmed');
    const exported = await cli('export', audit.data.run, '--out', path.join(root, 'regression'));
    assert.equal(exported.code, 0);
    const regressionFile = exported.data.files.find(file => file.includes(finding.id));
    assert.ok(regressionFile);
    const regression = async () => (await execFile(process.execPath,
      ['--test', regressionFile], {env: {...env, NODE_TEST_CONTEXT: undefined},
        timeout: 30000})).code;
    assert.equal(await regression(), 1);
    vulnerable = false;
    const beforeFixedReplay = callbackFetches;
    const fixed = JSON.parse((await execFile(process.execPath, [finding.proof],
      {env, timeout: 20000})).stdout);
    assert.equal(fixed.verdict, 'not_reproduced');
    assert.ok(callbackFetches >= beforeFixedReplay + 2,
      'the patched target still fetched both resources; content use is what stopped');
    assert.equal(await regression(), 0);
  });
