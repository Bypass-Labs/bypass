import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import http from 'node:http';
import os from 'node:os';
import path from 'node:path';
import {randomBytes} from 'node:crypto';
import {CLI} from '../src/demo.mjs';
import {execFile} from '../src/util.mjs';
import {protectedBoundaryValueHints} from '../src/blackbox/research-flow.mjs';

test('boundary labels are field names, never protected values', () => {
  const hints = protectedBoundaryValueHints([{path: '/api/workspace/private',
    ownerStatus: 200, anonymousStatus: 403,
    ownerJsonFieldNames: ['owner', 'secret', 'nested.apiKey', 'workspace']}]);
  assert.deepEqual(hints.map(item => item.label), ['owner', 'workspace', 'api', 'private']);
  assert.ok(hints.every(item => !Object.hasOwn(item, 'value')));
});

test('CLI sends observed boundary labels to Muse after an unchanged staged response',
  {timeout: 120000}, async t => {
    const root = fs.mkdtempSync(path.join(os.tmpdir(), 'bypass-boundary-label-'));
    t.after(() => {if (!process.env.BX_KEEP_TEST_ROOT)
      fs.rmSync(root, {recursive: true, force: true});});
    const suffix = randomBytes(4).toString('hex');
    const beginPath = `/api/${suffix}/begin`;
    const completePath = `/api/${suffix}/complete`;
    const privatePath = `/api/${suffix}/private`;
    const privateValue = `private-${randomBytes(12).toString('hex')}`;
    const privateBody = JSON.stringify({workspace: `owner-${suffix}`,
      owner: privateValue, note: 'Local owner workspace document with private content.'});
    let vulnerable = true, beginCount = 0;
    const nonces = new Set();
    const server = http.createServer(async (request, response) => {
      const pathname = new URL(request.url, 'http://fixture').pathname;
      response.setHeader('cache-control', 'no-store');
      if (pathname === '/') {
        response.setHeader('content-type', 'text/html');
        return response.end('<a href="/openapi.json">API</a>');
      }
      response.setHeader('content-type', 'application/json');
      if (pathname === '/openapi.json') return response.end(JSON.stringify({
        openapi: '3.0.0', paths: {
          [privatePath]: {get: {summary: 'Read the owner workspace'}},
          [beginPath]: {post: {summary: 'Start workspace flow', requestBody: {
            content: {'application/json': {schema: {type: 'object',
              required: ['kind'], properties: {kind: {type: 'string', example: 'audit'}}}}}},
            responses: {'201': {content: {'application/json': {schema: {
              type: 'object', properties: {nonce: {type: 'string'}}}}}}}}},
          [completePath]: {post: {summary: 'Complete workspace flow', requestBody: {
            content: {'application/json': {schema: {type: 'object',
              required: ['nonce', 'claim'], properties: {nonce: {type: 'string'},
                claim: {type: 'string', example: 'public'}}}}}}}}}}));
      if (request.method === 'GET' && pathname === privatePath) {
        if (request.headers.authorization === 'Bearer fixture-owner')
          return response.end(privateBody);
        response.statusCode = 403;
        return response.end(JSON.stringify({error: 'forbidden'}));
      }
      if (request.method === 'POST' && [beginPath, completePath].includes(pathname)) {
        let raw = '';
        for await (const chunk of request) raw += chunk;
        let body;
        try {body = JSON.parse(raw);} catch {body = null;}
        if (pathname === beginPath && body?.kind === 'audit') {
          const nonce = `n${randomBytes(5).toString('hex')}`;
          nonces.add(nonce);
          beginCount++;
          response.statusCode = 201;
          return response.end(JSON.stringify({nonce}));
        }
        if (pathname === completePath && nonces.delete(body?.nonce) &&
            typeof body?.claim === 'string')
          return response.end(vulnerable && body.claim === 'owner' ? privateBody :
            JSON.stringify({workspace: 'public', owner: false}));
        response.statusCode = 400;
        return response.end(JSON.stringify({error: 'invalid workflow'}));
      }
      response.statusCode = 404;
      response.end(JSON.stringify({error: 'missing'}));
    });
    await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
    t.after(() => new Promise(resolve => server.close(resolve)));
    const origin = `http://127.0.0.1:${server.address().port}`;
    const scopePath = path.join(root, 'blackbox.scope.json');
    fs.writeFileSync(scopePath, JSON.stringify({schemaVersion: 1, target: {origin},
      include: ['/'], identities: {identityPath: privatePath},
      limits: {rps: 50, maxUrls: 40, minutes: 3, modelCalls: 30, tasks: 20}}));
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
      "const flow=(first,second)=>({family:'owner-only workflow',why:'Observed owner boundary and selector',priority:10,as:'anonymous',oracle:'observation',protectedPath:process.env.BX_PRIVATE,prelude:[{method:'POST',path:process.env.BX_BEGIN,as:'anonymous',placement:'json',key:'kind',value:'audit',fixedFields:[],bodyTemplate:'',headers:[]}],subject:{method:'POST',path:process.env.BX_COMPLETE,placement:'json',key:'claim',fixedFields:[],bodyTemplate:'',headers:[]},observe:[],binding:{from:0,pointer:'/nonce',to:'subject',index:0,key:'nonce'},controlValue:'public',firstValue:first,secondValue:second,marker:'',secondMarker:'',assertion:{step:'subject',index:0,location:'body',name:''}});",
      'let answer;',
      "if(system.startsWith('You are planning bounded, authorized HTTP research.')){",
      " const linked=context.workflowLinks?.some(item=>item.fromPath===process.env.BX_BEGIN&&item.toPath===process.env.BX_COMPLETE&&item.pointer==='/nonce');",
      " answer={flows:linked&&context.protectedReadRoutes?.includes(process.env.BX_PRIVATE)?[flow('guest','visitor')]:[]};",
      '}',
      "else if(system.startsWith('Revise at most one bounded, authorized HTTP experiment')){",
      " const hint=context.boundaryValueHints?.find(item=>item.label==='owner'&&item.source==='protected-response-field-name');",
      " fs.appendFileSync(process.env.BX_HINT_TRACE,JSON.stringify({hints:context.boundaryValueHints??[],boundaries:context.protectedReadBoundaries??[]})+'\\n');",
      " answer={verifierId:'',flows:hint?[flow(hint.label,'visitor')]:[]};",
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
    const trace = path.join(root, 'boundary-hints.json');
    const env = {PATH: `${bin}${path.delimiter}${process.env.PATH}`,
      OWNER_TOKEN: 'fixture-owner', BX_BEGIN: beginPath,
      BX_COMPLETE: completePath, BX_PRIVATE: privatePath, BX_HINT_TRACE: trace};
    const cli = async (...args) => {
      const done = await execFile(process.execPath,
        [CLI, 'blackbox', ...args, '--project', root, '--json', '--non-interactive'],
        {cwd: root, env, timeout: 90000});
      return {code: done.code, data: JSON.parse(done.stdout), stderr: done.stderr};
    };
    const audit = await cli(origin, '--scope', scopePath);
    assert.ok(audit.data.runDir, JSON.stringify(audit));
    const web = JSON.parse(fs.readFileSync(path.join(audit.data.runDir,
      'web-probes.json'), 'utf8'));
    const finding = audit.data.findings.find(item =>
      item.kind === 'model-access-boundary' && item.pattern === completePath);
    assert.ok(finding?.proof, JSON.stringify({findings: audit.data.findings,
      results: web.results, decisions: web.strategyDecisions, stderr: audit.stderr}));
    assert.ok(web.strategyDecisions.some(item =>
      item.mode === 'http-sequence-revision' && item.accepted &&
      item.boundaryValueHintsSent > 0));
    const sent = fs.readFileSync(trace, 'utf8');
    assert.match(sent, /"label":"owner"/);
    assert.doesNotMatch(sent, /fixture-owner|private-[0-9a-f]{24}/);
    assert.ok(beginCount >= 6, 'controls and proof need fresh setup nonces');
    assert.equal((await cli('verify', audit.data.run)).code, 1);
    vulnerable = false;
    assert.equal((await cli('verify', audit.data.run)).code, 0);
  });
