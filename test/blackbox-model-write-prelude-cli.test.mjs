import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import http from 'node:http';
import os from 'node:os';
import path from 'node:path';
import {randomBytes} from 'node:crypto';
import {CLI} from '../src/demo.mjs';
import {execFile} from '../src/util.mjs';

async function exerciseReviewedSetup(t, setupMethod) {
    const root = fs.mkdtempSync(path.join(os.tmpdir(), 'bypass-write-prelude-'));
    t.after(() => fs.rmSync(root, {recursive: true, force: true}));
    const suffix = randomBytes(4).toString('hex');
    const beginPath = `/api/${suffix}/begin`;
    const finishPath = `/api/${suffix}/finish`;
    const privatePath = `/api/${suffix}/private`;
    const privateBody = JSON.stringify({workspace: `owner-${suffix}`,
      private: true, owner: 'claim-one',
      note: 'Private owner workspace data for an independent content check.'});
    let vulnerable = true, observationMode = false;
    let freshBegins = 0;
    const nonces = new Set();
    const requests = [];
    const operation = (method, summary, required, properties, responseStatus = null,
      responseProperties = null) => ({[method.toLowerCase()]: {summary,
      requestBody: {required: true, content: {'application/json': {schema: {
        type: 'object', required, properties}}}},
      ...(responseProperties ? {responses: {[responseStatus]: {content: {
        'application/json': {schema: {type: 'object',
          properties: responseProperties}}}}}} : {})}});
    const server = http.createServer(async (request, response) => {
      const url = new URL(request.url, 'http://fixture');
      response.setHeader('content-type', 'application/json');
      response.setHeader('cache-control', 'no-store');
      if (url.pathname === '/') return response.end(JSON.stringify({
        links: ['/openapi.json']}));
      if (url.pathname === '/openapi.json') return response.end(JSON.stringify({
        openapi: '3.0.0', paths: {
          [privatePath]: {get: {summary: 'Read owner workspace'}},
          [beginPath]: operation(setupMethod, 'Start a disposable local workflow', ['kind'],
            {kind: {type: 'string', example: 'audit'}}, '201',
            {nonce: {type: 'string'}}),
          [finishPath]: operation('POST', 'Finish a disposable local workflow',
            ['nonce', 'claim'], {nonce: {type: 'string'},
              claim: {type: 'string', example: 'plain'}})}}));
      if (request.method === 'GET' && url.pathname === privatePath) {
        if (request.headers.authorization === 'Bearer fixture-owner')
          return response.end(privateBody);
        response.statusCode = 403;
        return response.end(JSON.stringify({error: 'forbidden'}));
      }
      if (request.method === setupMethod && url.pathname === beginPath ||
          request.method === 'POST' && url.pathname === finishPath) {
        let raw = '';
        for await (const chunk of request) raw += chunk;
        let body = null;
        try {body = JSON.parse(raw);} catch { /* fixture returns 400 below */ }
        requests.push({method: request.method, path: url.pathname, body});
        if (url.pathname === beginPath && body?.kind === 'audit') {
          const nonce = `n${randomBytes(3).toString('hex')}`;
          nonces.add(nonce);
          freshBegins++;
          response.statusCode = 201;
          return response.end(JSON.stringify({nonce}));
        }
        if (url.pathname === finishPath && nonces.delete(body?.nonce))
          return response.end(vulnerable &&
            (body?.claim === 'claim-one' || !observationMode &&
              body?.claim === 'claim-two') ? privateBody :
            JSON.stringify({workspace: 'public', private: false}));
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
      'let answer;',
      "if(system.startsWith('You are planning bounded, authorized HTTP research.')){",
      " const begin=context.routes.find(item=>item.path===process.env.BX_BEGIN&&item.kind==='json'&&item.methods.includes(process.env.BX_BEGIN_METHOD));",
      " const finish=context.routes.find(item=>item.path===process.env.BX_FINISH&&item.kind==='json'&&item.methods.includes('POST'));",
      ' const owner=context.protectedReadRoutes.find(item=>item===process.env.BX_PRIVATE);',
      " const link=context.workflowLinks?.find(item=>item.fromPath===process.env.BX_BEGIN&&item.fromMethod===process.env.BX_BEGIN_METHOD&&item.status===201&&item.pointer==='/nonce'&&item.toPath===process.env.BX_FINISH&&item.toMethod==='POST'&&item.toField==='nonce');",
      " answer={flows:begin&&finish&&owner&&link?[{family:'staged owner disclosure',why:'A reviewed setup workflow may expose owner content',priority:10,as:'anonymous',oracle:process.env.BX_OBSERVATION?'observation':'protected-body',protectedPath:owner,prelude:[{method:process.env.BX_BEGIN_METHOD,path:begin.path,as:'anonymous',placement:'json',key:'kind',value:'audit',fixedFields:[],bodyTemplate:'',headers:[]}],subject:{method:'POST',path:finish.path,placement:'json',key:'claim',fixedFields:[],bodyTemplate:'',headers:[]},observe:[],binding:{from:0,pointer:'/nonce',to:'subject',index:0,key:'nonce'},controlValue:'plain',firstValue:'claim-one',secondValue:'claim-two',marker:'',secondMarker:'',assertion:{step:'subject',index:0,location:'body',name:''}}]:[]};",
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
    const env = {PATH: `${bin}${path.delimiter}${process.env.PATH}`,
      OWNER_TOKEN: 'fixture-owner', BX_BEGIN: beginPath,
      BX_BEGIN_METHOD: setupMethod,
      BX_FINISH: finishPath, BX_PRIVATE: privatePath};
    const cli = async (...args) => {
      const completed = await execFile(process.execPath,
        [CLI, 'blackbox', ...args, '--project', root, '--json', '--non-interactive'],
        {cwd: root, env, timeout: 90000});
      return {code: completed.code, data: JSON.parse(completed.stdout),
        stderr: completed.stderr};
    };
    const audit = await cli(origin, '--scope', scopePath, '--rps', '20');
    assert.ok(audit.data.runDir, JSON.stringify(audit));
    const web = JSON.parse(fs.readFileSync(path.join(audit.data.runDir,
      'web-probes.json'), 'utf8'));
    const finding = audit.data.findings.find(item =>
      item.kind === 'model-access-boundary' && item.pattern === finishPath);
    assert.ok(web.strategyDecisions.some(item =>
      item.mode === 'http-sequence' && item.accepted),
    JSON.stringify(web.strategyDecisions));
    assert.ok(finding?.proof, JSON.stringify({findings: audit.data.findings,
      results: web.results, decisions: web.strategyDecisions}));
    assert.equal(finding.verdict, 'confirmed');
    assert.ok(requests.some(item => item.method === setupMethod &&
      item.path === beginPath && item.body?.kind === 'audit'));
    assert.ok(requests.some(item => item.path === finishPath &&
      item.body?.claim === 'claim-one' && typeof item.body?.nonce === 'string'));
    assert.ok(freshBegins >= 7, 'each control and replay must obtain a fresh nonce');
    assert.equal((await cli('verify', audit.data.run)).code, 1);
    const exported = await cli('export', audit.data.run, '--out', path.join(root, 'regression'));
    assert.equal(exported.code, 0);
    const regression = async () => (await execFile(process.execPath,
      ['--test', ...exported.data.files], {env: {...env, NODE_TEST_CONTEXT: undefined},
        timeout: 20000})).code;
    assert.equal(await regression(), 1);
    vulnerable = false;
    assert.equal((await cli('verify', audit.data.run)).code, 0);
    assert.equal(await regression(), 0);

    // Muse can initially classify the staged response as an observation.
    // The submitted value also appears in the owner document, so a simple
    // reflection heuristic must not discard an independently provable leak.
    vulnerable = true;
    observationMode = true;
    env.BX_OBSERVATION = '1';
    const observedAudit = await cli(origin, '--scope', scopePath, '--rps', '20');
    const observedFinding = observedAudit.data.findings.find(item =>
      item.kind === 'model-access-boundary' && item.pattern === finishPath);
    assert.ok(observedFinding?.proof, JSON.stringify({
      findings: observedAudit.data.findings,
      results: JSON.parse(fs.readFileSync(path.join(observedAudit.data.runDir,
        'web-probes.json'), 'utf8')).results, stderr: observedAudit.stderr}));
    assert.equal((await cli('verify', observedAudit.data.run)).code, 1);
    const observedExport = await cli('export', observedAudit.data.run,
      '--out', path.join(root, 'observed-regression'));
    assert.equal(observedExport.code, 0);
    const observedRegression = async () => (await execFile(process.execPath,
      ['--test', ...observedExport.data.files],
      {env: {...env, NODE_TEST_CONTEXT: undefined}, timeout: 20000})).code;
    assert.equal(await observedRegression(), 1);
    vulnerable = false;
    assert.equal((await cli('verify', observedAudit.data.run)).code, 0);
    assert.equal(await observedRegression(), 0);
}

test('CLI replays a Muse selected reviewed POST setup and bound POST subject',
  {timeout: 120000}, t => exerciseReviewedSetup(t, 'POST'));
test('CLI replays a Muse selected reviewed PATCH setup and bound POST subject',
  {timeout: 120000}, t => exerciseReviewedSetup(t, 'PATCH'));
