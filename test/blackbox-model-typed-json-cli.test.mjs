import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import http from 'node:http';
import os from 'node:os';
import path from 'node:path';
import {randomBytes} from 'node:crypto';
import {CLI} from '../src/demo.mjs';
import {sequenceJsonBody} from '../src/blackbox/poc-runtime.mjs';
import {execFile} from '../src/util.mjs';

test('typed JSON body preserves object, array and scalar JSON values', () => {
  const fields = {hint: 'public'};
  for (const value of ['{"match":"owner"}', '[{"match":"owner"},2,true,null]',
    '1e2', 'false', 'null']) {
    const body = sequenceJsonBody(fields, 'selector', value, 'json');
    assert.equal(body, `{"hint":"public","selector":${value}}`);
    assert.deepEqual(JSON.parse(body), {hint: 'public', selector: JSON.parse(value)});
  }
  assert.deepEqual(JSON.parse(sequenceJsonBody(fields, 'selector', '{"match":"owner"}')),
    {hint: 'public', selector: '{"match":"owner"}'});
});

test('blind CLI sends a Muse-selected typed JSON body and replays its owner-content proof',
  {timeout: 120000}, async t => {
    if (process.platform === 'win32') return t.skip('Muse fixture uses a POSIX executable');
    const root = fs.mkdtempSync(path.join(os.tmpdir(), 'bypass-typed-json-'));
    const revisionFile = path.join(root, 'nested-revision.json');
    t.after(() => {if (!process.env.BX_KEEP_TEST_ROOT)
      fs.rmSync(root, {recursive: true, force: true});});
    const suffix = randomBytes(5).toString('hex');
    const privatePath = `/api/${suffix}/private`;
    const filterPath = `/api/${suffix}/filter`;
    const secret = `private-${randomBytes(18).toString('hex')}`;
    const privateDocument = {record: {private: true, owner: `owner-${suffix}`, secret}};
    let vulnerable = true;
    const submitted = [];
    const server = http.createServer(async (request, response) => {
      const url = new URL(request.url, 'http://fixture.invalid');
      const json = (status, document) => {
        response.writeHead(status, {'content-type': 'application/json',
          'cache-control': 'no-store'});
        response.end(JSON.stringify(document));
      };
      if (url.pathname === '/') return json(200, {docs: '/openapi.json'});
      if (url.pathname === '/openapi.json') return json(200, {openapi: '3.0.0', paths: {
        [privatePath]: {get: {summary: 'Read owner private record'}},
        [filterPath]: {post: {summary: 'Filter public records by selector', requestBody: {
          content: {'application/json': {schema: {type: 'object',
            properties: {selector: {type: 'object', properties: {
              match: {type: 'string'}, variant: {type: 'integer'}}},
            metadata: {type: 'object', properties: {contact: {type: 'string'}}}},
            required: ['selector']},
          example: {selector: {match: 'public', variant: 0},
            metadata: {contact: 'alice@company.com'}}}}}}}}});
      if (request.method === 'GET' && url.pathname === privatePath)
        return request.headers.authorization === 'Bearer fixture-owner' ?
          json(200, privateDocument) : json(403, {error: 'denied'});
      if (request.method === 'POST' && url.pathname === filterPath) {
        let body = '';
        for await (const chunk of request) body += chunk;
        const selector = JSON.parse(body).selector;
        submitted.push({type: typeof selector, array: Array.isArray(selector),
          match: selector && typeof selector === 'object' ? selector.match : null});
        return json(200, vulnerable && selector && typeof selector === 'object' &&
          selector.match === 'owner' ? {records: [{owner: `owner-${suffix}`, secret}]} :
          {records: [{owner: 'public', title: 'Public record'}]});
      }
      return json(404, {error: 'missing'});
    });
    await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
    t.after(() => new Promise(resolve => server.close(resolve)));
    const origin = `http://127.0.0.1:${server.address().port}`;
    const scopeFile = path.join(root, 'blackbox.scope.json');
    fs.writeFileSync(scopeFile, JSON.stringify({schemaVersion: 1,
      target: {origin}, include: ['/'], identities: {identityPath: privatePath},
      limits: {rps: 50, maxUrls: 70, minutes: 3, modelCalls: 50, tasks: 30}}));
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
      'const system=messages[0].content, context=JSON.parse(messages.at(-1).content);',
      'let answer;',
      "if(system.startsWith('You are planning bounded, authorized HTTP research.')){",
      " const post=context.routes.find(item=>item.path===process.env.BX_FILTER&&item.kind==='json'&&item.fields.includes('selector'));",
      ' const privateRead=context.protectedReadRoutes.find(item=>item===process.env.BX_PRIVATE);',
      " const typed=post?.fieldShapes?.selector?.properties?.match?.type==='string'&&post?.fieldShapes?.selector?.properties?.variant?.type==='integer'&&post?.fieldValueExamples?.selector?.includes('{\"match\":\"public\",\"variant\":0}')&&!JSON.stringify(context.routes).includes('alice@company.com');",
      " answer={flows:post&&privateRead&&typed?[{family:'object-valued owner record disclosure',why:'Observed JSON selector may return owner-only material',priority:9,as:'anonymous',oracle:'observation',protectedPath:privateRead,prelude:[],subject:{method:'POST',path:post.path,placement:'json',key:'selector',valueEncoding:'json',fixedFields:[],bodyTemplate:'',headers:[]},observe:[],controlValue:'{\"match\":\"public\",\"variant\":0}',firstValue:'{\"match\":\"public\",\"variant\":1}',secondValue:'{\"match\":\"public\",\"variant\":2}',marker:'',secondMarker:'',assertion:{step:'subject',index:0,location:'body',name:''}}]:[]};",
      '}',
      "else if(system.startsWith('Revise at most one bounded, authorized HTTP experiment')){",
      " const feedback=context.nestedObjectFeedback??null; const boundary=context.protectedReadBoundaries?.find(item=>item.path===process.env.BX_PRIVATE)??null; fs.writeFileSync(process.env.BX_REVISION,JSON.stringify({feedback,boundary,nextUnexploredInputs:context.nextUnexploredInputs??[],promptPrioritizes:system.includes('prioritize one such property'),promptUsesBoundaries:system.includes('protectedReadBoundaries')&&Array.isArray(context.protectedReadBoundaries)}));",
      " const route=context.observedRoutes.find(item=>item.path===process.env.BX_FILTER&&item.kind==='json');",
      " const privateRead=context.protectedReadRoutes.find(item=>item===process.env.BX_PRIVATE);",
      " const useful=feedback?.unchangedStringFields?.includes('selector.match')&&feedback?.variedOtherFields?.includes('selector.variant')&&feedback?.protectedReadAvailable&&boundary?.ownerStatus===200&&boundary?.anonymousStatus===403&&boundary?.ownerJsonFieldNames?.includes('record.owner')&&route&&privateRead;",
      " answer={flows:useful?[{family:'object-valued owner record disclosure',why:'A protected owner route suggests a synthetic ownership selector',priority:9,as:'anonymous',oracle:'protected-json-field',protectedPath:privateRead,prelude:[],subject:{method:'POST',path:route.path,placement:'json',key:'selector',valueEncoding:'json',fixedFields:[],bodyTemplate:'',headers:[]},observe:[],controlValue:'{\"match\":\"public\",\"variant\":0}',firstValue:'{\"match\":\"owner\",\"variant\":1}',secondValue:'{\"match\":\"owner\",\"variant\":2}',marker:'',secondMarker:'',assertion:{step:'subject',index:0,location:'body',name:''}}]:[]};",
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
    const env = {...process.env,
      PATH: `${bin}${path.delimiter}${process.env.PATH}`,
      OWNER_TOKEN: 'fixture-owner', BX_FILTER: filterPath, BX_PRIVATE: privatePath,
      BX_REVISION: revisionFile};
    const cli = async (...args) => {
      const done = await execFile(process.execPath,
        [CLI, 'blackbox', ...args, '--project', root, '--json', '--non-interactive'],
        {cwd: root, env, timeout: 90000});
      return {code: done.code, data: JSON.parse(done.stdout), stderr: done.stderr};
    };
    const audit = await cli(origin, '--scope', scopeFile, '--offline');
    assert.ok(audit.data.runDir, audit.stderr);
    const finding = audit.data.findings.find(item => item.kind === 'model-access-boundary' &&
      item.pattern === filterPath);
    const revision = JSON.parse(fs.readFileSync(revisionFile, 'utf8'));
    const {feedback} = revision;
    assert.deepEqual(feedback.unchangedStringFields, ['selector.match']);
    assert.deepEqual(feedback.variedOtherFields, ['selector.variant']);
    assert.equal(feedback.protectedReadAvailable, true);
    assert.deepEqual(revision.nextUnexploredInputs.map(item => item.field),
      ['selector.match']);
    assert.equal(revision.promptPrioritizes, true);
    assert.equal(revision.promptUsesBoundaries, true);
    assert.equal(revision.boundary.ownerStatus, 200);
    assert.equal(revision.boundary.anonymousStatus, 403);
    assert.ok(revision.boundary.ownerJsonFieldNames.includes('record.owner'));
    assert.ok(!revision.boundary.ownerJsonFieldNames.includes('record.secret'));
    assert.ok(!JSON.stringify(revision).includes(secret));
    assert.ok(!JSON.stringify(revision).includes('fixture-owner'));
    const decisions = JSON.parse(fs.readFileSync(path.join(audit.data.runDir,
      'web-probes.json'), 'utf8')).strategyDecisions;
    assert.ok(decisions.some(item => item.mode === 'http-sequence-revision' &&
      item.nextUnexploredInputsSent?.includes('selector.match')));
    assert.ok(decisions.some(item => item.mode === 'http-sequence-revision' &&
      item.protectedReadBoundariesSent === 1));
    assert.ok(decisions.some(item => item.mode === 'http-sequence-revision' &&
      item.protectedReadBoundariesAvailable === 1 &&
      item.protectedReadBoundariesCut === 0));
    assert.ok(!JSON.stringify(decisions).includes(secret));
    assert.ok(finding?.proof, JSON.stringify({findings: audit.data.findings,
      submitted: submitted.slice(0, 10)}));
    assert.equal(finding.verdict, 'confirmed');
    assert.equal(finding.webProof.subject.valueEncoding, 'json');
    assert.ok(submitted.some(item => item.type === 'object' && item.match === 'owner'));
    assert.ok(submitted.every(item => item.type === 'object' && !item.array),
      JSON.stringify(submitted));
    assert.equal((await cli('verify', audit.data.run)).code, 1);
    const exported = await cli('export', audit.data.run, '--out', path.join(root, 'regression'));
    assert.equal(exported.code, 0);
    const regression = async () => (await execFile(process.execPath,
      ['--test', ...exported.data.files.filter(file => file.includes(finding.id))],
      {cwd: root, env: {...env, NODE_TEST_CONTEXT: undefined}, timeout: 20000})).code;
    assert.equal(await regression(), 1);
    vulnerable = false;
    assert.equal((await cli('verify', audit.data.run)).code, 0);
    assert.equal(await regression(), 0);
    const saved = fs.readFileSync(path.join(audit.data.runDir, 'poc', finding.id, 'spec.json'), 'utf8');
    assert.ok(!saved.includes(secret));
  });
