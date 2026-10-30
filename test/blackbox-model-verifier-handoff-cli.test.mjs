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

test('Muse hands an observed input to an existing proof oracle and changes the blind CLI result',
  {timeout: 180000}, async t => {
    const root = fs.mkdtempSync(path.join(os.tmpdir(), 'bypass-verifier-handoff-'));
    t.after(() => {if (!process.env.BX_KEEP_TEST_ROOT)
      fs.rmSync(root, {recursive: true, force: true});});
    const suffix = randomBytes(5).toString('hex');
    const route = `/api/preview-${suffix}`;
    let vulnerable = true;
    const server = http.createServer((request, response) => {
      const url = new URL(request.url, 'http://fixture.invalid');
      if (request.method === 'GET' && url.pathname === '/') {
        response.writeHead(200, {'content-type': 'text/html', 'cache-control': 'no-store'});
        return response.end(`<a href="${route}?q=hello">Preview</a>`);
      }
      if (request.method === 'GET' && url.pathname === route) {
        const input = url.searchParams.get('q') ?? '';
        const expression = /^\{\{(\d{4})\*(\d{4})\}\}$/.exec(input);
        response.writeHead(200, {'content-type': 'text/plain', 'cache-control': 'no-store'});
        return response.end(vulnerable && expression ?
          String(Number(expression[1]) * Number(expression[2])) : input);
      }
      response.writeHead(404, {'content-type': 'application/json', 'cache-control': 'no-store'});
      response.end('{"error":"missing"}');
    });
    await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
    t.after(() => new Promise(resolve => server.close(resolve)));
    const origin = `http://127.0.0.1:${server.address().port}`;
    const scopePath = path.join(root, 'scope.json');
    fs.writeFileSync(scopePath, JSON.stringify({schemaVersion: 1, target: {origin},
      include: ['/'], limits: {rps: 50, maxUrls: 80, minutes: 3, modelCalls: 32,
        tasks: 2}}));
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
      "if(system.startsWith('Allocate the next black-box investigation effort')){",
      " answer={priorities:context.tracks.map(row=>({name:row.name,weight:row.name==='sequence'||row.name==='web'?100:1,why:'Observed read input'})).sort((a,b)=>(b.weight-a.weight)||(a.name==='sequence'?-1:1))};",
      '}',
      "else if(system.startsWith('You are planning bounded, authorized HTTP research.')){",
      " const observed=[...(context.routes??[]),...(context.observedReadRoutes??[])].find(item=>item.path===process.env.BX_ROUTE);",
      " answer={flows:observed?[{family:'preview-processing',why:'Observed preview input may be processed server-side',priority:10,as:'anonymous',oracle:'observation',prelude:[],subject:{method:'GET',path:process.env.BX_ROUTE,placement:'query',key:'q',fixedFields:[],bodyTemplate:'',headers:[]},observe:[],controlValue:'hello',firstValue:'world',secondValue:'again',marker:'',secondMarker:'',assertion:{step:'subject',index:0,location:'body',name:''}}]:[]};",
      '}',
      "else if(system.startsWith('Revise at most one bounded, authorized HTTP experiment')){",
      " const selected=(context.verifierChoices??[]).find(item=>item.kind==='ssti-arithmetic'&&item.path===process.env.BX_ROUTE);",
      " answer={flows:[],...(process.env.BX_HANDOFF==='yes'&&selected?{verifierId:selected.id}:{})};",
      '}',
      "else if(system.includes('Rank only the supplied observed read-only web-test candidates'))answer={priorities:[],strategies:[],experiments:[]};",
      "else if(system.includes('Interpret only the extracted'))answer={files:[]};",
      "else if(system.includes('Assess only these independently proved'))answer={notes:[]};",
      "else if(system.includes('Continue mapping this authorized primary application'))answer={paths:[]};",
      "else if(system.includes('mapping an authorized web API'))answer={paths:[],notes:[]};",
      "else if(system.includes('Propose bounded GET access-control'))answer={tasks:[]};",
      'else {',
      " const schema=JSON.parse(fs.readFileSync(value('--output-schema'),'utf8'));",
      " const blank=s=>s?.type==='object'?Object.fromEntries((s.required??[]).map(key=>[key,blank(s.properties?.[key])])):s?.type==='array'?[]:s?.type==='integer'||s?.type==='number'?0:s?.type==='boolean'?false:s?.enum?.[0]??'';",
      ' answer=blank(schema);',
      '}',
      "console.log(JSON.stringify({payload:{kind:'run_terminal',terminal:'completed',text:JSON.stringify(answer)}}));",
    ].join('\n') + '\n', {mode: 0o700});
    const audit = async (project, handoff, ...args) => {
      fs.mkdirSync(project, {recursive: true});
      const env = {...process.env, PATH: `${bin}${path.delimiter}${process.env.PATH}`,
        BX_ROUTE: route, BX_HANDOFF: handoff ? 'yes' : 'no'};
      const result = await execFile(process.execPath,
        [CLI, 'blackbox', ...args, '--project', project, '--json', '--non-interactive'],
        {cwd: root, env, timeout: 120000});
      return {code: result.code, data: JSON.parse(result.stdout), env};
    };
    const without = await audit(path.join(root, 'without'), false,
      origin, '--scope', scopePath, '--offline');
    assert.ok(without.data.runDir, JSON.stringify(without));
    assert.ok(!without.data.findings.some(item => item.kind === 'ssti-arithmetic'),
      JSON.stringify(without.data.findings));
    const withHandoff = await audit(path.join(root, 'with'), true,
      origin, '--scope', scopePath, '--offline');
    assert.ok(withHandoff.data.runDir, JSON.stringify(withHandoff));
    const web = JSON.parse(fs.readFileSync(path.join(withHandoff.data.runDir,
      'web-probes.json'), 'utf8'));
    assert.ok(web.strategyDecisions.some(item => item.verifier?.kind === 'ssti-arithmetic' &&
      item.accepted), JSON.stringify(web.strategyDecisions));
    assert.ok(web.plan.some(item => item.kind === 'ssti-arithmetic' &&
      item.by === 'model-feedback'), JSON.stringify(web.plan));
    const finding = withHandoff.data.findings.find(item => item.kind === 'ssti-arithmetic');
    assert.ok(finding?.proof, JSON.stringify({findings: withHandoff.data.findings,
      results: web.results}));
    assert.ok(finding.tags.includes('model-verifier-handoff'));
    assert.equal((await audit(path.join(root, 'with'), true,
      'verify', withHandoff.data.run)).code, 1);
    const exported = await audit(path.join(root, 'with'), true,
      'export', withHandoff.data.run, '--out', path.join(root, 'regression'));
    assert.equal(exported.code, 0);
    const regression = () => new Promise((resolve, reject) => {
      const child = spawn(process.execPath, ['--test', ...exported.data.files],
        {env: Object.fromEntries(Object.entries(process.env).filter(([name]) =>
          name !== 'NODE_TEST_CONTEXT')), stdio: 'ignore'});
      child.once('error', reject);
      child.once('close', resolve);
    });
    assert.equal(await regression(), 1);
    vulnerable = false;
    assert.equal((await audit(path.join(root, 'with'), true,
      'verify', withHandoff.data.run)).code, 0);
    assert.equal(await regression(), 0);
  });
