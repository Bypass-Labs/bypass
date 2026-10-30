import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import http from 'node:http';
import os from 'node:os';
import path from 'node:path';
import {randomBytes} from 'node:crypto';
import {CLI} from '../src/demo.mjs';
import {execFile} from '../src/util.mjs';

test('CLI replays a Muse selected state change with a required reviewed companion field',
  {timeout: 150000}, async t => {
    const root = fs.mkdtempSync(path.join(os.tmpdir(), 'bypass-state-companion-'));
    t.after(() => fs.rmSync(root, {recursive: true, force: true}));
    const suffix = randomBytes(5).toString('hex');
    const recordPath = `/api/record-${suffix}`;
    const writePath = `/api/review-${suffix}`;
    const baseline = `pending-${suffix}`;
    let state = baseline, vulnerable = true;
    const server = http.createServer(async (request, response) => {
      const url = new URL(request.url, 'http://fixture.invalid');
      const send = (status, body, type = 'application/json') => {
        response.writeHead(status, {'content-type': type, 'cache-control': 'no-store'});
        response.end(type === 'application/json' ? JSON.stringify(body) : body);
      };
      if (request.method === 'GET' && url.pathname === '/')
        return send(200, '<html><a href="/openapi.json">API</a><script src="/app.js"></script></html>', 'text/html');
      if (request.method === 'GET' && url.pathname === '/app.js')
        return send(200, `fetch('${writePath}',{method:'PATCH',headers:{'content-type':'application/json'},body:JSON.stringify({reviewState:'reviewed',channel:'review'})});`, 'application/javascript');
      if (request.method === 'GET' && url.pathname === '/openapi.json') return send(200,
        {openapi: '3.0.0', info: {title: 'Disposable review', version: '1.0.0'},
          paths: {[recordPath]: {get: {summary: 'Read owner-only disposable review record'}},
            [writePath]: {patch: {summary: 'Change review state of disposable record',
              requestBody: {required: true, content: {'application/json': {
                schema: {type: 'object', required: ['reviewState', 'channel'],
                  properties: {reviewState: {type: 'string'},
                    channel: {type: 'string', example: 'review'}}}}}}}}}});
      if (request.method === 'GET' && url.pathname === recordPath)
        return request.headers.authorization === 'Bearer fixture-owner' ?
          send(200, {record: {reviewState: state}}) : send(403, {error: 'owner only'});
      if (request.method === 'PATCH' && url.pathname === writePath) {
        const chunks = [];
        for await (const chunk of request) chunks.push(chunk);
        let body;
        try {body = JSON.parse(Buffer.concat(chunks).toString());}
        catch {return send(400, {error: 'invalid JSON'});}
        if (body?.channel !== 'review' || typeof body.reviewState !== 'string' ||
            Object.keys(body).length !== 2)
          return send(422, {error: 'review channel required'});
        if (!vulnerable && request.headers.authorization !== 'Bearer fixture-owner')
          return send(403, {error: 'owner only'});
        state = body.reviewState;
        return send(200, {updated: true});
      }
      return send(404, {error: 'missing'});
    });
    await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
    t.after(() => new Promise(resolve => server.close(resolve)));
    const origin = `http://127.0.0.1:${server.address().port}`;
    const scopeFile = path.join(root, 'scope.json');
    fs.writeFileSync(scopeFile, JSON.stringify({schemaVersion: 1, target: {origin},
      include: ['/'], identities: {identityPath: recordPath},
      probes: {writeOperations: [{method: 'PATCH', path: writePath,
        placement: 'json'}]}, limits: {rps: 50, maxUrls: 80, minutes: 3,
        modelCalls: 40, tasks: 100}}));
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
      " const write=context.routes.find(item=>item.path===process.env.BX_WRITE&&item.fields.includes('reviewState')&&item.fields.includes('channel'));",
      " const read=context.protectedReadRoutes.includes(process.env.BX_RECORD);",
      " answer={flows:write&&read?[{family:'unauthorized-record-write',why:'An owner-only disposable record has a reviewed anonymous PATCH contract',priority:10,as:'anonymous',oracle:'state-change',protectedPath:process.env.BX_RECORD,prelude:[],subject:{method:'PATCH',path:write.path,placement:'json',key:'reviewState',fixedFields:[{field:'channel',value:'review'}],bodyTemplate:'',headers:[]},observe:[],controlValue:'plain',firstValue:process.env.BX_BASELINE,secondValue:'bxsecond'+process.env.BX_SUFFIX,marker:context.marker,secondMarker:context.secondMarker,assertion:{step:'subject',index:0,location:'body',name:''}}]:[]};",
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
    const env = {...process.env, OWNER_TOKEN: 'fixture-owner',
      PATH: `${bin}${path.delimiter}${process.env.PATH}`, BX_WRITE: writePath,
      BX_RECORD: recordPath, BX_SUFFIX: suffix, BX_BASELINE: baseline};
    const cli = async (...args) => {
      const done = await execFile(process.execPath,
        [CLI, 'blackbox', ...args, '--project', root, '--json', '--non-interactive'],
        {cwd: root, env, timeout: 120000});
      return {code: done.code, data: JSON.parse(done.stdout)};
    };
    const audit = await cli(origin, '--scope', scopeFile);
    const finding = audit.data.findings?.find(item => item.kind === 'model-state-change' &&
      item.pattern === writePath);
    assert.ok(finding?.proof, JSON.stringify(audit.data));
    assert.equal(state, baseline, 'audit must restore the disposable record');
    const proof = JSON.parse((await execFile(process.execPath, [finding.proof],
      {env, timeout: 20000})).stdout);
    assert.equal(proof.verdict, 'confirmed', JSON.stringify(proof));
    assert.equal(state, baseline);
    const exported = await cli('export', audit.data.run, '--out', path.join(root, 'regression'));
    assert.equal(exported.code, 0);
    const regression = async () => (await execFile(process.execPath,
      ['--test', ...exported.data.files.filter(file => file.includes(finding.id))],
      {env: {...env, NODE_TEST_CONTEXT: undefined}, timeout: 30000})).code;
    assert.equal(await regression(), 1);
    const artifactFiles = fs.readdirSync(audit.data.runDir,
      {recursive: true, withFileTypes: true}).filter(item => item.isFile())
      .map(item => path.join(item.parentPath, item.name));
    const baselineArtifacts = artifactFiles.filter(file =>
      fs.readFileSync(file, 'utf8').includes(baseline))
      .map(file => path.relative(audit.data.runDir, file));
    // A queued Muse sequence keeps its exact synthetic input for resume.
    // The report, proof and other published artifacts must not contain it.
    assert.ok(baselineArtifacts.every(file =>
      /^http-sequence.*-checkpoint\.json$/.test(file)),
    JSON.stringify(baselineArtifacts));
    const artifacts = artifactFiles.map(file => fs.readFileSync(file, 'utf8')).join('\n');
    assert.ok(!artifacts.includes('fixture-owner'));
    vulnerable = false;
    const fixed = JSON.parse((await execFile(process.execPath,
      [finding.proof], {env, timeout: 20000})).stdout);
    assert.equal(fixed.verdict, 'not_reproduced');
    assert.equal(await regression(), 0);
    assert.equal(state, baseline);
  });
