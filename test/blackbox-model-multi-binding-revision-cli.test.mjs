import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import {spawn} from 'node:child_process';
import {CLI} from '../src/demo.mjs';
import {execFile} from '../src/util.mjs';

test('blind CLI revises a public chained workflow and repairs its binding shape',
  {timeout: 180000}, async t => {
    const root = fs.mkdtempSync(path.join(os.tmpdir(), 'bypass-multi-binding-'));
    t.after(() => fs.rmSync(root, {recursive: true, force: true}));
    const fixture = path.join(import.meta.dirname,
      'fixtures/blackbox-multi-binding-blind.mjs');
    const server = spawn(process.execPath, [fixture, root],
      {stdio: ['ignore', 'pipe', 'inherit']});
    t.after(() => server.kill());
    const origin = await new Promise((resolve, reject) => {
      server.stdout.once('data', chunk => resolve(String(chunk).trim()));
      server.once('error', reject);
      server.once('exit', code => reject(Error(`fixture exited ${code}`)));
    });
    const routes = JSON.parse(fs.readFileSync(path.join(root, 'fixture-routes.json')));
    const scopePath = path.join(root, 'blackbox.scope.json');
    fs.writeFileSync(scopePath, JSON.stringify({schemaVersion: 1,
      target: {origin}, include: ['/'], identities: {identityPath: routes.private},
      limits: {rps: 40, maxUrls: 50, minutes: 3, modelCalls: 35, tasks: 30}}));
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
      "const flow=(candidate,broken=false)=>({family:'staged access boundary',why:'Two observed response fields link three reviewed writes to an owner-only read',priority:10,as:'anonymous',oracle:'protected-body',protectedPath:process.env.BX_PRIVATE,prelude:[{method:'POST',path:process.env.BX_START,as:'anonymous',placement:'json',key:'kind',value:'audit',fixedFields:[],bodyTemplate:'',headers:[]},{method:'POST',path:process.env.BX_EXCHANGE,as:'anonymous',placement:'json',key:'nonce',value:'audit',fixedFields:[],bodyTemplate:'',headers:[]}],subject:{method:'POST',path:process.env.BX_FINISH,placement:'json',key:'claim',fixedFields:[{field:'claim',value:'redundant'}],bodyTemplate:'',headers:[]},observe:[],bindings:[{from:0,pointer:'/nonce',to:'prelude',index:broken?0:1,key:'nonce'},{from:1,pointer:'/ticket',to:'subject',index:0,key:'ticket'}],controlValue:'plain',firstValue:candidate,secondValue:'viewer',marker:'',secondMarker:'',assertion:{step:'subject',index:0,location:'body',name:''}});",
      'let answer;',
      "if(system.startsWith('You are planning bounded, authorized HTTP research.')){",
      " const start=context.routes.find(item=>item.path===process.env.BX_START&&item.kind==='json'&&item.methods.includes('POST'));",
      " const exchange=context.routes.find(item=>item.path===process.env.BX_EXCHANGE&&item.kind==='json'&&item.methods.includes('POST'));",
      " const finish=context.routes.find(item=>item.path===process.env.BX_FINISH&&item.kind==='json'&&item.methods.includes('POST'));",
      ' const owner=context.protectedReadRoutes.find(item=>item===process.env.BX_PRIVATE);',
      " const first=context.workflowLinks?.find(item=>item.fromPath===process.env.BX_START&&item.pointer==='/nonce'&&item.toPath===process.env.BX_EXCHANGE&&item.toField==='nonce');",
      " const second=context.workflowLinks?.find(item=>item.fromPath===process.env.BX_EXCHANGE&&item.pointer==='/ticket'&&item.toPath===process.env.BX_FINISH&&item.toField==='ticket');",
      " answer={flows:start&&exchange&&finish&&owner&&first&&second?[flow('member')]:[]};",
      '}',
      "else if(system.startsWith('Revise at most one bounded, authorized HTTP experiment')){",
      " if(!system.includes('ordered bindings')||!system.includes('to:\"prelude\"')||context.validatedBindings?.length!==2||context.validatedPrelude?.length!==2)process.exit(4);",
      " if(!context.rejected)answer={flows:[flow('owner',true)]};",
      " else {if(context.rejected.reason!=='binding-target'||context.rejected.shape?.component!=='binding-target'||context.rejected.bindingShape?.[0]?.count!==2||context.rejected.shape?.to!=='prelude')process.exit(5);answer={flows:[flow('owner')]};}",
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
      OWNER_TOKEN: 'fixture-owner', BX_START: routes.start,
      BX_EXCHANGE: routes.exchange, BX_FINISH: routes.finish,
      BX_PRIVATE: routes.private};
    const cli = async (...args) => {
      const completed = await execFile(process.execPath,
        [CLI, 'blackbox', ...args, '--project', root, '--json', '--non-interactive'],
        {cwd: root, env, timeout: 100000});
      return {code: completed.code, data: JSON.parse(completed.stdout),
        stderr: completed.stderr};
    };
    const audit = await cli(origin, '--scope', scopePath);
    assert.ok(audit.data.runDir, JSON.stringify(audit));
    const finding = audit.data.findings.find(item =>
      item.kind === 'model-access-boundary' && item.pattern === routes.finish);
    const web = JSON.parse(fs.readFileSync(path.join(audit.data.runDir,
      'web-probes.json'), 'utf8'));
    assert.ok(finding?.proof, JSON.stringify({findings: audit.data.findings,
      decisions: web.strategyDecisions, results: web.results, stderr: audit.stderr}));
    assert.ok(web.strategyDecisions.some(item =>
      item.normalizedSubjectFixedField && item.accepted));
    assert.ok(web.strategyDecisions.some(item =>
      item.mode === 'http-sequence-revision' && item.reason === 'binding-target'));
    assert.ok(web.strategyDecisions.some(item =>
      item.mode === 'http-sequence-repair' && item.accepted));
    assert.deepEqual(finding.webProof.bindings.map(item =>
      ({from: item.from, to: item.to, index: item.index, key: item.key})), [
      {from: 0, to: 'prelude', index: 1, key: 'nonce'},
      {from: 1, to: 'subject', index: 0, key: 'ticket'}]);
    assert.equal((await cli('verify', audit.data.run)).code, 1);
    const exported = await cli('export', audit.data.run,
      '--out', path.join(root, 'regression'));
    assert.equal(exported.code, 0);
    const regression = async () => (await execFile(process.execPath,
      ['--test', ...exported.data.files],
      {env: {...env, NODE_TEST_CONTEXT: undefined}, timeout: 20000})).code;
    assert.equal(await regression(), 1);
    fs.writeFileSync(path.join(root, 'mode'), 'fixed');
    assert.equal((await cli('verify', audit.data.run)).code, 0);
    assert.equal(await regression(), 0);
  });
