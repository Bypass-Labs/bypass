import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import http from 'node:http';
import os from 'node:os';
import path from 'node:path';
import {spawn} from 'node:child_process';
import {pathToFileURL} from 'node:url';
import {runAudit} from '../src/blackbox/index.mjs';
import {DEFAULT_SCOPE, loadScope} from '../src/blackbox/scope.mjs';
import {createLedger} from '../src/blackbox/ledger.mjs';

const sleep = ms => new Promise(resolve => setTimeout(resolve, ms));
const blank = schema => schema?.type === 'object' ?
  Object.fromEntries((schema.required ?? []).map(key => [key, blank(schema.properties?.[key])])) :
  schema?.type === 'array' ? [] :
  schema?.type === 'integer' || schema?.type === 'number' ? 0 :
  schema?.type === 'boolean' ? false : schema?.enum?.[0] ?? '';

test('an interrupted descendant hint resumes only on its rediscovered authorized origin',
  {timeout: 60000}, async t => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'bypass-descendant-feedback-'));
    t.after(() => fs.rmSync(dir, {recursive: true, force: true}));
    const origin = 'https://app.example.test';
    const run = 'bx-20261029-abc12345';
    const checkpointFile = path.join(dir, 'descendant-test-feedback-checkpoint.json');
    const stateFile = path.join(dir, 'reveal');
    const requestsFile = path.join(dir, 'requests.jsonl');
    fs.writeFileSync(stateFile, 'yes');
    const script = path.join(dir, 'worker.mjs');
    const hostModule = pathToFileURL(path.resolve('src/blackbox/host-audit.mjs')).href;
    const indexModule = pathToFileURL(path.resolve('src/blackbox/index.mjs')).href;
    const scopeModule = pathToFileURL(path.resolve('src/blackbox/scope.mjs')).href;
    const ledgerModule = pathToFileURL(path.resolve('src/blackbox/ledger.mjs')).href;
    const storeModule = pathToFileURL(path.resolve('src/store.mjs')).href;
    fs.writeFileSync(script, `
      import fs from 'node:fs';
      import path from 'node:path';
      import {auditDiscoveredHosts} from ${JSON.stringify(hostModule)};
      import {loadDescendantFeedbackCheckpoint} from ${JSON.stringify(indexModule)};
      import {DEFAULT_SCOPE} from ${JSON.stringify(scopeModule)};
      import {createLedger} from ${JSON.stringify(ledgerModule)};
      import {atomic} from ${JSON.stringify(storeModule)};
      const dir=process.env.BX_DIR, origin=process.env.BX_HOST;
      const scope=structuredClone(DEFAULT_SCOPE);
      scope.domains=['example.test'];
      scope.discovery.auditDomains=['example.test'];
      scope.include=['/api'];
      const expiresAt=new Date(Date.now()+60000).toISOString();
      scope.authorizedDomains={'example.test':{
        url:'https://example.test',ownership:{status:'verified',expiresAt},
        authorization:{origin:'https://example.test',paths:['/api'],
          methods:scope.methods,expiresAt}}};
      const discovery={hosts:[{host:'app.example.test',origin,
        operations:[{method:'GET',path:'/api/seed',
          params:[{name:'q',in:'query',example:'plain'}],source:['document:/openapi.json']}],
        assets:null},{host:'other.example.test',origin:'https://other.example.test',
        operations:[{method:'GET',path:'/api/seed',
          params:[{name:'q',in:'query',example:'plain'}],source:['document:/openapi.json']}],
        assets:null}]};
      const ledger=createLedger(path.join(dir,process.env.BX_RESUME==='1'?'second':'first'));
      const checkpoint=path.join(dir,'descendant-test-feedback-checkpoint.json');
      const resume=process.env.BX_RESUME==='1'?
        loadDescendantFeedbackCheckpoint(checkpoint,{run:'bx-20261029-abc12345',
          scopeHash:'fixture-hash',scope}):[];
      const checked=await auditDiscoveredHosts(discovery,scope,{ledger,budget:80,
        model:{model:'fixture'},remainingModelCalls:()=>20,
        researchDeadline:Date.now()+30000,resumeHints:resume,
        onFeedbackCheckpoint:pending=>atomic(checkpoint,{version:1,
          kind:'descendant-test-feedback',run:'bx-20261029-abc12345',
          scopeHash:'fixture-hash',origin:'http://127.0.0.1:4329',
          pending:pending.map(({origin,path})=>({origin,path}))}),
        requester:async ({url})=>{
          const parsed=new URL(url,origin);
          fs.appendFileSync(path.join(dir,'requests.jsonl'),JSON.stringify({
            phase:process.env.BX_RESUME==='1'?'resume':'first',origin:parsed.origin,
            path:parsed.pathname,search:parsed.search})+'\\n');
          const reveal=fs.readFileSync(path.join(dir,'reveal'),'utf8')==='yes';
          const body=JSON.stringify(parsed.origin===origin&&parsed.pathname==='/api/seed'&&
            parsed.searchParams.has('q')&&reveal?
            {nextPath:'/api/hidden'}:{status:'ready'});
          return {status:200,type:'application/json',body,headers:{},
            evidenceId:ledger.append({step:'task',request:{url:parsed.href},response:{status:200}})};
        },
        infer:async (_model,messages)=>{
          const system=messages[0].content;
          if(system.includes('Continue mapping this authorized descendant application')&&
              JSON.parse(messages[1].content).observations.some(item=>item.path==='/api/hidden')){
            if(process.env.BX_RESUME!=='1') await new Promise(resolve=>setTimeout(resolve,20000));
            return {paths:[]};
          }
          return {paths:[],priorities:[],strategies:[],experiments:[],flows:[]};
        }});
      atomic(path.join(dir,'finished.json'),{pending:JSON.parse(fs.readFileSync(checkpoint)).pending,
        remaining:checked.responsePathHints.map(({origin,path})=>({origin,path})),
        tested:checked.tested});
    `);
    const runChild = resume => spawn(process.execPath, [script], {cwd: dir,
      env: {...process.env, BX_DIR: dir, BX_HOST: origin, BX_RESUME: resume ? '1' : '0'},
      stdio: 'ignore'});
    const first = runChild(false);
    t.after(() => {if (first.exitCode == null) first.kill('SIGKILL');});
    let pending;
    const deadline = Date.now() + 30000;
    while (Date.now() < deadline) {
      if (fs.existsSync(checkpointFile)) {
        const value = JSON.parse(fs.readFileSync(checkpointFile, 'utf8'));
        pending = value.pending;
        if (pending.some(item => item.origin === origin && item.path === '/api/hidden')) break;
      }
      if (first.exitCode != null) break;
      await sleep(30);
    }
    assert.deepEqual(pending, [{origin, path: '/api/hidden'}]);
    const checkpoint = JSON.parse(fs.readFileSync(checkpointFile, 'utf8'));
    assert.deepEqual(Object.keys(checkpoint.pending[0]).sort(), ['origin', 'path']);
    assert.equal(checkpoint.run, run);
    assert.equal(checkpoint.scopeHash, 'fixture-hash');
    first.kill('SIGKILL');
    await new Promise(resolve => first.once('exit', resolve));
    fs.writeFileSync(stateFile, 'no');
    const second = runChild(true);
    const exit = await new Promise(resolve => second.once('exit', code => resolve(code)));
    assert.equal(exit, 0, 'the resumed descendant audit should complete');
    const requests = fs.readFileSync(requestsFile, 'utf8').trim().split('\n').map(JSON.parse);
    assert.ok(requests.filter(item => item.phase === 'resume' && item.path === '/api/hidden')
      .some(item => item.origin === origin), 'the saved route must be revisited after the hint disappears');
    assert.ok(!requests.some(item => item.phase === 'resume' && item.path === '/api/hidden' &&
      item.origin === 'https://other.example.test'),
    'a saved route must not be sent to another authorized host');
    assert.deepEqual(JSON.parse(fs.readFileSync(checkpointFile, 'utf8')).pending, []);
    assert.deepEqual(JSON.parse(fs.readFileSync(path.join(dir, 'finished.json'), 'utf8')).remaining, []);

    // A changed scope cannot revive the saved hint. The check runs before network traffic.
    const project = path.join(dir, 'project');
    fs.mkdirSync(project);
    const scope = structuredClone(DEFAULT_SCOPE);
    scope.target.origin = 'http://127.0.0.1:4329';
    scope.credentialOrigins = [scope.target.origin];
    scope.domains = ['example.test'];
    scope.discovery.auditDomains = ['example.test'];
    scope.include = ['/api'];
    const scopeFile = path.join(project, 'blackbox.scope.json');
    fs.writeFileSync(scopeFile, JSON.stringify(scope));
    const loaded = loadScope({file: scopeFile, origin: scope.target.origin,
      overrides: {testResolver: true}});
    const priorDir = path.join(project, '.bypass/runs', run);
    fs.mkdirSync(priorDir, {recursive: true});
    createLedger(priorDir, {run}).append({step: 'recon', kind: 'fixture'});
    fs.writeFileSync(path.join(priorDir, 'run-start.json'), JSON.stringify({run,
      scopeHash: loaded.hash, origin: scope.target.origin}));
    fs.writeFileSync(path.join(priorDir, 'descendant-test-feedback-checkpoint.json'),
      JSON.stringify({...checkpoint, scopeHash: loaded.hash}));
    scope.include = ['/changed'];
    fs.writeFileSync(scopeFile, JSON.stringify(scope));
    await assert.rejects(runAudit({url: scope.target.origin, root: project,
      scopeFile, resumeFrom: run, resolve: async () => []}), /different scope or target/);
    scope.include = ['/api'];
    fs.writeFileSync(scopeFile, JSON.stringify(scope));
    fs.writeFileSync(path.join(priorDir, 'descendant-test-feedback-checkpoint.json'),
      JSON.stringify({...checkpoint, scopeHash: loaded.hash,
        pending: [{origin: 'https://outside.example.net', path: '/api/hidden'}]}));
    await assert.rejects(runAudit({url: scope.target.origin, root: project,
      scopeFile, resumeFrom: run, resolve: async () => []}),
    /invalid descendant test-feedback checkpoint/);
  });

test('runAudit keeps a resumed descendant hint pending when fresh discovery misses its host',
  {timeout: 90000}, async t => {
    const project = fs.mkdtempSync(path.join(os.tmpdir(), 'bypass-descendant-run-resume-'));
    t.after(() => fs.rmSync(project, {recursive: true, force: true}));
    const server = http.createServer((_request, response) => {
      response.writeHead(404, {'content-type': 'application/json'});
      response.end('{"error":"missing"}');
    });
    await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
    t.after(() => new Promise(resolve => server.close(resolve)));
    const origin = `http://127.0.0.1:${server.address().port}`;
    const descendant = 'https://app.example.test:8443';
    const run = 'bx-20261029-abc12345';
    const scope = structuredClone(DEFAULT_SCOPE);
    scope.target.origin = origin;
    scope.credentialOrigins = [origin];
    scope.domains = ['example.test'];
    scope.discovery.auditDomains = ['example.test'];
    scope.discovery.recurse = false;
    scope.discovery.knownHosts = ['app.example.test'];
    scope.discovery.sensitivePaths = false;
    scope.include = ['/api'];
    scope.discover = ['/'];
    scope.limits = {...scope.limits, rps: 100, modelCalls: 12, minutes: 2,
      tasks: 1, dnsQueries: 3, hosts: 2};
    const scopeFile = path.join(project, 'blackbox.scope.json');
    fs.writeFileSync(scopeFile, JSON.stringify(scope));
    const loaded = loadScope({file: scopeFile, origin,
      overrides: {testResolver: true}});
    const priorDir = path.join(project, '.bypass/runs', run);
    fs.mkdirSync(priorDir, {recursive: true});
    createLedger(priorDir, {run}).append({step: 'recon', kind: 'fixture'});
    fs.writeFileSync(path.join(priorDir, 'run-start.json'), JSON.stringify({run,
      scopeHash: loaded.hash, origin, effectiveLimits: loaded.scope.limits}));
    fs.writeFileSync(path.join(priorDir, 'descendant-test-feedback-checkpoint.json'),
      JSON.stringify({version: 1, kind: 'descendant-test-feedback', run,
        scopeHash: loaded.hash, origin,
        pending: [{origin: descendant, path: '/api/hidden'}]}));
    const requests = [];
    const audited = await runAudit({url: origin, root: project, scopeFile,
      resumeFrom: run, offline: true, env: {},
      resolve: async host => {requests.push(host); return [];},
      infer: async (_model, _messages, options) => blank(options.schema)});
    assert.ok(audited.runDir);
    assert.ok(requests.includes('app.example.test'), 'discovery must retry the saved host');
    const next = JSON.parse(fs.readFileSync(path.join(audited.runDir,
      'descendant-test-feedback-checkpoint.json'), 'utf8'));
    assert.equal(next.resumedFrom, run);
    assert.deepEqual(next.pending, [{origin: descendant, path: '/api/hidden'}],
      'a route must remain pending until its exact authorized host is rediscovered');
    const coverage = JSON.parse(fs.readFileSync(path.join(audited.runDir,
      'coverage.json'), 'utf8'));
    assert.deepEqual(coverage.descendantFeedbackPending, next.pending);
    const report = JSON.parse(fs.readFileSync(path.join(audited.runDir,
      'report.json'), 'utf8'));
    assert.ok(report.limitations.some(item => item.includes('descendant route hints remain pending')));
  });
