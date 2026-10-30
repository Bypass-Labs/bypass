import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import http from 'node:http';
import os from 'node:os';
import path from 'node:path';
import {randomBytes} from 'node:crypto';
import {CLI} from '../src/demo.mjs';
import {execFile} from '../src/util.mjs';

test('actual CLI carries typed response feedback through more than five Muse revisions', async t => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'bypass-sequence-loop-'));
  t.after(() => {if (!process.env.BX_KEEP_TEST_ROOT)
    fs.rmSync(root, {recursive: true, force: true});});
  const route = `/api/examine-${randomBytes(4).toString('hex')}`;
  const codes = [];
  while (codes.length < 6) {
    const value = 1000 + randomBytes(2).readUInt16BE();
    if (!codes.includes(value)) codes.push(value);
  }
  const transitions = new Map([0, ...codes.slice(0, -1)].map((value, index) =>
    [value, codes[index]]));
  const finalCode = codes.at(-1);
  const seen = [];
  const server = http.createServer((request, response) => {
    const url = new URL(request.url, 'http://fixture');
    response.setHeader('content-type', 'application/json');
    response.setHeader('cache-control', 'no-store');
    if (url.pathname === '/') return response.end(JSON.stringify({app: 'numbered evaluator'}));
    if (url.pathname === '/openapi.json') return response.end(JSON.stringify({openapi: '3.0.0',
      paths: {[route]: {get: {summary: 'Examine an expression', parameters: [
        {in: 'query', name: 'expr', schema: {type: 'string'}}]}}}}));
    if (url.pathname !== route) {
      response.statusCode = 404;
      return response.end(JSON.stringify({error: 'missing'}));
    }
    const value = url.searchParams.get('expr') ?? '';
    const match = /^(\d+)\.(.*)$/.exec(value);
    const stage = Number(match?.[1] ?? NaN);
    seen.push(stage);
    if (transitions.has(stage)) return response.end(JSON.stringify({next: transitions.get(stage),
      accepted: false, privateToken: 'fixture-only-private-value'}));
    if (stage !== finalCode) {
      response.statusCode = 400;
      return response.end(JSON.stringify({error: 'invalid'}));
    }
    const expression = match[2];
    const numbers = /^String\.fromCharCode\(([0-9,]+)\)$/.exec(expression);
    const result = numbers ? String.fromCharCode(...numbers[1].split(',').map(Number)) : expression;
    response.end(JSON.stringify({result, accepted: true}));
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  t.after(() => new Promise(resolve => server.close(resolve)));
  const origin = `http://127.0.0.1:${server.address().port}`;
  const scopePath = path.join(root, 'blackbox.scope.json');
  fs.writeFileSync(scopePath, JSON.stringify({schemaVersion: 1, target: {origin},
    include: ['/'], limits: {rps: 50, modelCalls: 40, minutes: 2,
      researchCallsPerHypothesis: 20}}));
  const trace = path.join(root, 'revision-trace.jsonl');
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
    'const system=messages[0].content;',
    'const context=JSON.parse(messages[1].content);',
    'const encode=value=>`String.fromCharCode(${[...value].map(char=>char.charCodeAt(0)).join(\',\')})`;',
    "const flow=(ctx,stage)=>({family:'contextual-response-transform',why:'Follow the typed next value from the previous response',priority:10,as:'anonymous',prelude:[],subject:{method:'GET',path:process.env.BX_ROUTE,placement:'query',key:'expr',fixedFields:[],bodyTemplate:'',headers:[]},observe:[],controlValue:`${stage}.plain`,firstValue:`${stage}.${encode(ctx.marker)}`,secondValue:`${stage}.${encode(ctx.secondMarker)}`,marker:ctx.marker,secondMarker:ctx.secondMarker,assertion:{step:'subject',index:0,location:'body',name:''}});",
    'let answer;',
    "if(system.startsWith('You are planning bounded, authorized HTTP research.')){",
    " answer={flows:context.routes.some(item=>item.path===process.env.BX_ROUTE&&item.fields.includes('expr'))?[flow(context,0)]:[]};",
    '}',
    "else if(system.startsWith('Revise at most one bounded, authorized HTTP experiment')){",
    ' const latest=context.recentAttempts.at(-1);',
    " const next=latest?.responses?.[0]?.subject?.jsonPrimitives?.find(item=>item.name==='next')?.value;",
    " fs.appendFileSync(process.env.BX_TRACE,JSON.stringify({attempt:context.historySummary?.attempts,next,prior:context.historySummary?.verdicts?.not_reproduced,recent:context.recentAttempts.length,hasPrivateValue:JSON.stringify(context).includes('fixture-only-private-value')})+'\\n');",
    ' answer={flows:Number.isInteger(next)?[flow(context,next)]:[]};',
    '}',
    "else if(system.includes('Select up to five local stored-XSS tests'))answer={checks:[]};",
    "else if(system.includes('Select distinct harmless response-transformation experiments for the reviewed JSON POST routes'))answer={experiments:[]};",
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
    BX_ROUTE: route, BX_TRACE: trace};
  const completed = await execFile(process.execPath,
    [CLI, 'blackbox', origin, '--scope', scopePath, '--rps', '50', '--offline',
      '--project', root, '--json', '--non-interactive'],
    {cwd: root, env, timeout: 90000});
  const audit = JSON.parse(completed.stdout);
  const web = JSON.parse(fs.readFileSync(path.join(audit.runDir, 'web-probes.json')));
  const report = JSON.parse(fs.readFileSync(path.join(audit.runDir, 'report.json')));
  assert.ok(report.header.modelCalls <= 40, 'feedback stays within the configured Muse budget');
  assert.ok(web.modelCoverage.some(item => item.pagesSent >= 1),
    'a web planning page remains available after sequence feedback');
  const investigation = web.investigations.find(item => item.initial?.path === route);
  const revisions = fs.readFileSync(trace, 'utf8').trim().split('\n').map(JSON.parse);
  assert.equal(investigation?.attempts.length, 7, JSON.stringify(web.investigations));
  assert.equal(investigation.stopReason, 'observed');
  assert.equal(revisions.length, 7);
  assert.deepEqual(revisions.map(item => item.attempt), [1, 2, 3, 4, 5, 6, 7]);
  assert.deepEqual(revisions.slice(0, 6).map(item => item.next), codes);
  assert.equal(revisions.at(-1).next, undefined);
  assert.ok(revisions.every(item => !item.hasPrivateValue));
  assert.equal(revisions.at(-1).prior, 6);
  assert.equal(revisions.at(-1).recent, 4);
  assert.ok(seen.includes(finalCode));
  assert.equal(audit.findings.find(item => item.kind === 'model-http-sequence')?.verdict,
    'observed');
});
