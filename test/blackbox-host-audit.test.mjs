import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import http from 'node:http';
import {randomBytes} from 'node:crypto';
import {temp} from './helpers.mjs';
import {DEFAULT_SCOPE, createRequester, createLimiter} from '../src/blackbox/scope.mjs';
import {createLedger, verifyLedger} from '../src/blackbox/ledger.mjs';
import {auditDiscoveredHosts, followupResponseHints, patternsFromOperations} from '../src/blackbox/host-audit.mjs';
import {buildFindings} from '../src/blackbox/report.mjs';
import {runWebProbes} from '../src/blackbox/web-probes.mjs';
import {proveFindings} from '../src/blackbox/poc.mjs';
import {execFile} from '../src/util.mjs';

test('independent recon responses reach Muse without waiting for a slow peer', async () => {
  const scope = structuredClone(DEFAULT_SCOPE);
  scope.limits.agents = 2;
  const origin = scope.target.origin;
  let releaseSlow;
  const slowPending = new Promise(resolve => {releaseSlow = resolve;});
  let slowDone = false, fastBeforeSlow = false;
  const patterns = ['/api/slow', '/api/fast'].map(pattern => ({pattern,
    source: ['fixture'], methods: ['GET'], params: {}}));
  const reviewed = [];
  const result = await followupResponseHints(origin, scope, patterns, {
    requester: async ({url}) => {
      const path = new URL(url, origin).pathname;
      if (path === '/api/slow') {
        await Promise.race([slowPending,
          new Promise(resolve => setTimeout(resolve, 350))]);
        slowDone = true;
      } else {
        fastBeforeSlow = !slowDone;
        releaseSlow();
      }
      return {status: 200, type: 'application/json', body: '{}',
        evidenceId: `fixture-${path}`};
    }, infer: async (_model, messages) => {
      reviewed.push(JSON.parse(messages[1].content).observations.map(item => item.path));
      return {paths: []};
    }, model: {model: 'fixture'}, maxModelPages: 1,
  });
  assert.ok(fastBeforeSlow, 'the second GET waited for the first');
  assert.deepEqual(reviewed, [['/api/slow', '/api/fast']]);
  assert.equal(result.coverage.routesReviewed, 2);
});

test('Muse response path cuts distinguish scope, duplicates, and HTTP errors without saving paths', async () => {
  const scope = structuredClone(DEFAULT_SCOPE);
  const origin = scope.target.origin;
  const response = pathname => pathname === '/missing' ?
    {status: 404, type: 'application/json', body: '{}'} :
    {status: 200, type: 'application/json', body: '{}'};
  const result = await followupResponseHints(origin, scope,
    [{pattern: '/start', source: ['fixture'], methods: ['GET'], params: {}}], {
      requester: async ({url}) => response(new URL(url, origin).pathname),
      infer: async () => ({paths: ['/safe', '/safe', '/missing',
        'https://outside.invalid/path', '/api/delete']}),
      model: {model: 'fixture'}, maxModelPages: 1,
    });
  assert.equal(result.coverage.pathsAccepted, 1);
  assert.equal(result.coverage.pathsRejected, 4);
  assert.equal(result.coverage.pathsProposed,
    result.coverage.pathsAccepted + result.coverage.pathsRejected);
  assert.deepEqual(result.coverage.pathsRejectedByReason,
    {duplicate: 1, 'http-4xx': 1, 'off-origin': 1, scope: 1});
  assert.ok(!JSON.stringify(result.coverage).includes('/safe'));
});

test('descendant response review leaves pending pages when the research deadline has passed', async () => {
  const scope = structuredClone(DEFAULT_SCOPE);
  let requests = 0, modelCalls = 0;
  const result = await followupResponseHints(scope.target.origin, scope,
    [{pattern: '/start', source: ['fixture'], methods: ['GET'], params: {}}], {
      requester: async () => {requests++; return {status: 200, type: 'application/json', body: '{}'};},
      infer: async () => {modelCalls++; return {paths: []};},
      model: {model: 'fixture'}, maxModelPages: 10, deadline: Date.now() - 1,
    });
  assert.equal(result.coverage.pagesAvailable, 1);
  assert.equal(result.coverage.pagesSent, 0);
  assert.equal(result.coverage.routesReviewed, 0);
  assert.equal(requests, 0);
  assert.equal(modelCalls, 0);
});

test('authorized descendants get independent web probes from observed GET parameters', async t => {
  const dir = temp();
  t.after(() => fs.rmSync(dir, {recursive: true, force: true}));
  const ledger = createLedger(dir);
  const scope = structuredClone(DEFAULT_SCOPE);
  scope.domains = ['example.test'];
  scope.discovery.auditDomains = ['example.test'];
  scope.include = ['/api'];
  const operation = {method: 'GET', path: '/api/next', params: [{name: 'after.path', in: 'query'}],
    source: ['document:/openapi.json'], purpose: 'Continue after login',
    parameterMeanings: [{name: 'after.path', meaning: 'destination URL for browser navigation'}]};
  const graphql = {method: 'GET', path: '/api/graphql', params: [], source: ['asset:client.js']};
  const discovery = {hosts: [
    {host: 'app.example.test', origin: 'https://app.example.test', operations: [operation, graphql], assets: null},
    {host: 'fixed.example.test', origin: 'https://fixed.example.test', operations: [operation], assets: null},
    {host: 'outside.example.net', origin: 'https://outside.example.net', operations: [operation, graphql], assets: null},
  ]};
  const calls = [];
  const requester = async ({url}) => {
    calls.push(url);
    const parsed = new URL(url);
    if (parsed.pathname === '/api/graphql') return {status: 200, type: 'application/json',
      body: JSON.stringify({data: {__schema: {queryType: {name: 'Query', fields: [
        {name: 'viewer', args: [], type: {name: 'Viewer'}}]}, mutationType: null}}}),
      evidenceId: ledger.append({step: 'recon', request: {url}, response: {status: 200}})};
    const redirect = parsed.hostname === 'app.example.test';
    return {status: redirect ? 302 : 200, headers: redirect ? {location: parsed.searchParams.get('after.path')} : {},
      evidenceId: ledger.append({step: 'task', request: {url}, response: {status: redirect ? 302 : 200}})};
  };
  const modelInputs = [];
  const checked = await auditDiscoveredHosts(discovery, scope, {requester, ledger, budget: 2,
    model: {model: 'fixture'}, infer: async (_model, messages) => {
      const context = JSON.parse(messages[1].content);
      modelInputs.push(context);
      return {priorities: [], strategies: context.candidates?.some(item =>
        item.kind === 'xss-reflected' && item.path === '/api/next' && item.parameter === 'after.path') ?
        [{family: 'open-redirect', path: '/api/next', parameter: 'after.path',
          priority: 9, why: 'Observed destination parameter'}] : []};
    }});
  assert.equal(checked.tested, 2);
  assert.equal(checked.findings.length, 1);
  assert.equal(checked.findings[0].host, 'app.example.test');
  assert.equal(checked.results.find(item => item.origin === 'https://fixed.example.test')?.verdict,
    'not_reproduced', JSON.stringify(checked.results));
  assert.ok(calls.every(url => ['app.example.test', 'fixed.example.test'].includes(new URL(url).hostname)));
  assert.equal(discovery.hosts[2].audit, undefined);
  assert.deepEqual(discovery.hosts[0].graphql.operations.map(item => item.name), ['viewer']);
  assert.ok(calls.some(url => new URL(url).hostname === 'app.example.test' &&
    new URL(url).pathname === '/api/graphql'));
  assert.ok(modelInputs.some(input => input.candidates?.some(candidate =>
    candidate.path === '/api/next' && candidate.purpose === 'Continue after login' &&
    candidate.parameterMeaning === 'destination URL for browser navigation')));
  assert.deepEqual(checked.strategyDecisions.filter(item => item.accepted)
    .map(item => item.origin).sort(), ['https://app.example.test', 'https://fixed.example.test']);
  assert.equal(verifyLedger(ledger.file).ok, true);
});

test('descendant response facts reach Muse after the former three-page cap', async () => {
  const scope = structuredClone(DEFAULT_SCOPE);
  scope.domains = ['example.test'];
  scope.discovery.auditDomains = ['example.test'];
  scope.include = ['/api'];
  const origin = 'https://app.example.test';
  const operations = Array.from({length: 25}, (_, index) => ({method: 'GET',
    path: `/api/route-${index}`, params: [], source: ['document:/openapi.json']}));
  const discovery = {hosts: [{host: 'app.example.test', origin, operations, assets: null}]};
  const responsePages = [];
  let modelCalls = 0;
  const checked = await auditDiscoveredHosts(discovery, scope, {
    budget: 1, model: {model: 'fixture'},
    remainingModelCalls: () => Math.max(0, 40 - modelCalls),
    requester: async () => ({status: 200, type: 'application/json', body: '{}',
      shape: {}, evidenceId: 'fixture-evidence'}),
    infer: async (_model, messages) => {
      modelCalls++;
      if (messages[0].content.includes('Continue mapping this authorized descendant application'))
        responsePages.push(JSON.parse(messages[1].content).page);
      return {paths: []};
    },
  });
  assert.deepEqual(responsePages, [1, 2, 3, 4, 5]);
  assert.equal(discovery.hosts[0].responseFollowup.routesReviewed, 25);
  assert.equal(discovery.hosts[0].responseFollowup.pagesSent, 5);
  assert.equal(discovery.hosts[0].responseFollowup.pagesAvailable, 5);
  assert.equal(checked.modelCoverage[0].responsePagesSent, 5);
});

test('descendant web checks return scoped response route hints with their host origin', async () => {
  const scope = structuredClone(DEFAULT_SCOPE);
  scope.domains = ['example.test'];
  scope.discovery.auditDomains = ['example.test'];
  scope.include = ['/api'];
  const origin = 'https://app.example.test';
  const discovery = {hosts: [{host: 'app.example.test', origin,
    operations: [{method: 'GET', path: '/api/lookup',
      params: [{name: 'q', in: 'query', example: 'plain'}],
      source: ['document:/openapi.json']}], assets: null}]};
  const checked = await auditDiscoveredHosts(discovery, scope, {budget: 1,
    requester: async () => ({status: 200, type: 'application/json',
      body: JSON.stringify({nextPath: '/api/later', otherPath: '/outside/private'}),
      evidenceId: 'hint-evidence'})});
  assert.ok(checked.tested > 0);
  assert.deepEqual(checked.responsePathHints,
    [{origin, path: '/api/later', evidenceId: 'hint-evidence'}]);
});

test('descendant test response reveals a new route that Muse tests in the same run', async t => {
  const dir = temp();
  t.after(() => fs.rmSync(dir, {recursive: true, force: true}));
  let vulnerable = true;
  const requested = [];
  const server = http.createServer((request, response) => {
    const url = new URL(request.url, 'http://local');
    requested.push(url.pathname + url.search);
    if (url.pathname === '/api/seed') {
      response.writeHead(200, {'content-type': 'application/json'});
      response.end(JSON.stringify(url.searchParams.has('q') ?
        {nextPath: '/api/hidden'} : {status: 'ready'}));
    } else if (url.pathname === '/api/hidden' && url.searchParams.has('next')) {
      response.writeHead(302, {location: vulnerable ? url.searchParams.get('next') : '/safe'});
      response.end();
    } else if (url.pathname === '/api/hidden') {
      response.writeHead(200, {'content-type': 'application/json'});
      response.end('{"status":"ready"}');
    } else {
      response.writeHead(404, {'content-type': 'application/json'});
      response.end('{}');
    }
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  t.after(() => new Promise(resolve => server.close(resolve)));
  const origin = `http://127.0.0.1:${server.address().port}`;
  const scope = structuredClone(DEFAULT_SCOPE);
  scope.domains = ['example.test'];
  scope.discovery.auditDomains = ['example.test'];
  scope.include = ['/api'];
  const discovery = {hosts: [{host: 'app.example.test', origin,
    operations: [{method: 'GET', path: '/api/seed',
      params: [{name: 'q', in: 'query', example: 'plain'}],
      source: ['document:/openapi.json']}], assets: null}]};
  const ledger = createLedger(dir);
  const requester = async ({url, step = 'task'}) => {
    const reply = await fetch(url, {redirect: 'manual'});
    const body = await reply.text();
    return {status: reply.status, type: reply.headers.get('content-type') ?? '', body,
      headers: Object.fromEntries(reply.headers),
      evidenceId: ledger.append({step, request: {method: 'GET', url},
        response: {status: reply.status}})};
  };
  const responsePages = [];
  const checked = await auditDiscoveredHosts(discovery, scope, {requester, ledger,
    budget: 12, researchDeadline: Date.now() + 30000,
    remainingModelCalls: () => 20, model: {model: 'fixture'},
    infer: async (_model, messages) => {
      const system = messages[0].content;
      const context = JSON.parse(messages[1].content);
      if (system.includes('Continue mapping this authorized descendant application')) {
        const paths = context.observations.map(item => item.path);
        responsePages.push(paths);
        return {paths: paths.includes('/api/hidden') ?
          ['/api/hidden?next=/safe'] : []};
      }
      const hidden = context.candidates?.find(item =>
        item.path === '/api/hidden' && item.parameter === 'next');
      return {priorities: [], strategies: hidden ? [{family: 'open-redirect',
        path: '/api/hidden', parameter: 'next', priority: 10,
        why: 'Observed response route and navigation input'}] : [], experiments: []};
    }});
  assert.ok(responsePages.some(paths => paths.includes('/api/seed')));
  assert.ok(responsePages.some(paths => paths.includes('/api/hidden')));
  assert.ok(discovery.hosts[0].testResponseFollowup.routesAdded > 0);
  assert.ok(discovery.hosts[0].testResponseFollowup.checksExecuted > 0);
  assert.ok(requested.some(value => value.startsWith('/api/hidden?next=') &&
    value.includes('.invalid')));
  assert.ok(checked.strategyDecisions.some(item => item.accepted &&
    item.path === '/api/hidden'));
  const finding = checked.findings.find(item => item.kind === 'open-redirect' &&
    item.pattern === '/api/hidden');
  assert.ok(finding, JSON.stringify(checked.results));
  const reportFindings = buildFindings([], {surface: {identity: {verified: false}}, scope,
    webFindings: checked.findings});
  const proved = await proveFindings(reportFindings, [], {runDir: dir,
    surface: {patterns: []}, scope, env: {}, ledger, web: checked});
  const proof = proved.find(item => item.pattern === '/api/hidden')?.proof;
  assert.ok(proof);
  assert.equal((await execFile(process.execPath, [proof])).code, 1);
  vulnerable = false;
  assert.equal((await execFile(process.execPath, [proof])).code, 0);
  assert.equal(verifyLedger(ledger.file).ok, true);
});

test('descendant feedback keeps a route pending when Muse cannot review its response', async () => {
  const scope = structuredClone(DEFAULT_SCOPE);
  scope.domains = ['example.test'];
  scope.discovery.auditDomains = ['example.test'];
  scope.include = ['/api'];
  const origin = 'https://app.example.test';
  const discovery = {hosts: [{host: 'app.example.test', origin,
    operations: [{method: 'GET', path: '/api/seed',
      params: [{name: 'q', in: 'query', example: 'plain'}],
      source: ['document:/openapi.json']}], assets: null}]};
  const checked = await auditDiscoveredHosts(discovery, scope, {
    budget: 12, researchDeadline: Date.now() + 30000,
    remainingModelCalls: () => 20, model: {model: 'fixture'},
    requester: async ({url}) => {
      const parsed = new URL(url);
      return {status: 200, type: 'application/json',
        body: JSON.stringify(parsed.pathname === '/api/seed' && parsed.searchParams.has('q') ?
          {nextPath: '/api/hidden'} : {status: 'ready'}), evidenceId: 'route-hint'};
    },
    infer: async (_model, messages) => {
      if (messages[0].content.includes('Continue mapping this authorized descendant application') &&
          JSON.parse(messages[1].content).observations.some(item => item.path === '/api/hidden'))
        return {unusable: true};
      return {paths: [], priorities: [], strategies: [], experiments: []};
    },
  });
  assert.equal(discovery.hosts[0].testResponseFollowup.hintsUntested, 1);
  assert.deepEqual(checked.responsePathHints,
    [{origin, path: '/api/hidden', evidenceId: 'route-hint'}]);
});

test('Muse derives a hidden descendant route from safe response facts and the host proof replays', async t => {
  const dir = temp();
  t.after(() => fs.rmSync(dir, {recursive: true, force: true}));
  const secret = 'sk_live_abcdefghijklmnopqrstuvwxyz012345';
  const slug = `proof-${randomBytes(4).toString('hex')}`;
  const hiddenPath = `/api/portal/${slug}`;
  const requested = [];
  let vulnerable = true;
  const server = http.createServer((request, response) => {
    const url = new URL(request.url, 'http://local');
    requested.push(url.pathname);
    if (/^\/api\/decoy-[0-6]$/.test(url.pathname)) {
      response.writeHead(200, {'content-type': 'application/json'});
      response.end(JSON.stringify({module: 'catalog', slug: 'public-item'}));
    } else if (url.pathname === '/api/portal') {
      response.writeHead(200, {'content-type': 'application/json'});
      response.end(JSON.stringify({module: 'redirect', slug, apiKey: secret}));
    } else if (url.pathname === hiddenPath) {
      response.writeHead(302, {location: vulnerable ? url.searchParams.get('next') ?? '/safe' : '/safe'});
      response.end();
    } else {
      response.writeHead(url.pathname === '/api/delete' ? 500 : 404);
      response.end();
    }
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  t.after(() => new Promise(resolve => server.close(resolve)));
  const origin = `http://127.0.0.1:${server.address().port}`;
  const scope = structuredClone(DEFAULT_SCOPE);
  scope.domains = ['example.test'];
  scope.discovery.auditDomains = ['example.test'];
  scope.include = ['/api'];
  const ledger = createLedger(dir);
  const requester = async ({url, step = 'task'}) => {
    const address = new URL(url, origin);
    const reply = await new Promise((resolve, reject) => {
      http.get(address, incoming => {
        const chunks = [];
        incoming.on('data', chunk => chunks.push(chunk));
        incoming.on('end', () => resolve({status: incoming.statusCode,
          headers: incoming.headers, body: Buffer.concat(chunks).toString('utf8')}));
        incoming.on('error', reject);
      }).on('error', reject);
    });
    return {...reply, type: reply.headers['content-type'] ?? '',
      evidenceId: ledger.append({step, request: {method: 'GET', url: address.href},
        response: {status: reply.status, headers: reply.headers}})};
  };
  const discovery = {hosts: [{host: 'app.example.test', origin,
    operations: [...Array.from({length: 7}, (_, index) => ({method: 'GET',
      path: `/api/decoy-${index}`, params: [], source: ['document:/openapi.json']})),
    {method: 'GET', path: '/api/portal', params: [], source: ['document:/openapi.json']}],
    assets: null}]};
  const baseline = await auditDiscoveredHosts(structuredClone(discovery), scope,
    {requester, ledger, budget: 3});
  assert.ok(!baseline.findings.some(item => item.kind === 'open-redirect'));
  const modelInputs = [];
  const checked = await auditDiscoveredHosts(discovery, scope, {requester, ledger, budget: 3,
    model: {model: 'fixture'}, infer: async (_profile, messages) => {
      const context = JSON.parse(messages[1].content);
      modelInputs.push(context);
      if (messages[0].content.includes('Continue mapping this authorized descendant application')) {
        const observed = context.observations.find(item => item.path === '/api/portal');
        if (!observed) return {paths: []};
        const hintedSlug = observed.hints.find(item => item.field === 'slug')?.value;
        return {paths: [`/api/portal/${hintedSlug}?next=/safe`, '/api/delete']};
      }
      return {priorities: [], strategies: []};
    }});
  const redirect = checked.findings.find(item => item.kind === 'open-redirect' &&
    item.pattern === hiddenPath);
  assert.ok(redirect, JSON.stringify(checked.results));
  assert.ok(modelInputs.some(input => input.observations?.some(item =>
    item.path === '/api/portal' && item.hints.some(hint => hint.value === slug))));
  assert.ok(!JSON.stringify(modelInputs).includes(secret));
  assert.equal(discovery.hosts[0].responseFollowup.pathsAccepted, 1);
  assert.equal(discovery.hosts[0].responseFollowup.pathsRejected, 1);
  assert.equal(discovery.hosts[0].responseFollowup.pathsProposed, 2);
  assert.deepEqual(discovery.hosts[0].responseFollowup.pathsRejectedByReason, {scope: 1});
  assert.equal(discovery.hosts[0].responseFollowup.pagesSent, 2);
  assert.equal(discovery.hosts[0].responseFollowup.routesReviewed, 8);
  assert.equal(discovery.hosts[0].responseFollowup.responsesWithoutHints, 1);
  assert.ok(!requested.includes('/api/delete'));
  const findings = buildFindings([], {surface: {identity: {verified: false}}, scope,
    webFindings: checked.findings});
  const proved = await proveFindings(findings, [], {runDir: dir, surface: {patterns: []}, scope,
    env: {}, ledger, web: checked});
  assert.equal(proved.length, 1);
  assert.equal((await execFile(process.execPath, [proved[0].proof])).code, 1);
  vulnerable = false;
  assert.equal((await execFile(process.execPath, [proved[0].proof])).code, 0);
  assert.equal(verifyLedger(ledger.file).ok, true);
});

test('same route on two hosts remains two findings', () => {
  const scope = structuredClone(DEFAULT_SCOPE);
  const first = {kind: 'open-redirect', host: 'a.example.test', pattern: '/api/next', url: 'https://a.example.test/api/next',
    severity: 'medium', reach: {observed: 1}};
  const second = {...first, host: 'b.example.test', url: 'https://b.example.test/api/next'};
  const findings = buildFindings([], {surface: {identity: {verified: false}}, scope,
    webFindings: [first, second]});
  assert.equal(findings.length, 2);
  assert.deepEqual(findings.map(item => item.host), ['a.example.test', 'b.example.test']);
});

test('operation patterns exclude writes, unknown query placement and templated routes', () => {
  const patterns = patternsFromOperations({operations: [
    {method: 'GET', path: '/api/search', params: [{name: 'query', in: 'query', example: 'record-42'}], source: ['document']},
    {method: 'GET', path: '/api/preview', params: [
      {name: 'source.file', in: 'query', example: 'guide.txt'},
      {name: 'auth.token', in: 'query', example: 'shortsecret'}], source: ['document']},
    {method: 'POST', path: '/api/create', params: [{name: 'name', in: 'query'}]},
    {method: 'GET', path: '/api/item/{id}', params: [{name: 'next', in: 'query'}]},
    {method: 'GET', path: '/api/unclear', params: [{name: 'next', in: null}]},
  ]});
  assert.deepEqual(patterns.map(item => item.pattern), ['/api/search', '/api/preview']);
  assert.deepEqual(patterns[0].params.query, ['record-42']);
  assert.deepEqual(patterns[1].params, {'source.file': ['guide.txt']});
  const client = patternsFromOperations({operations: [{method: 'GET', path: '/api/next',
    params: [{name: 'to', in: null, example: 'guide.txt'}], source: ['client-asset']}]});
  assert.deepEqual(client[0].params, {to: ['guide.txt']});
});

test('a finding on a second origin gets a proof pinned to that origin', async t => {
  const dir = temp();
  t.after(() => fs.rmSync(dir, {recursive: true, force: true}));
  const server = http.createServer((request, response) => {
    const url = new URL(request.url, 'http://127.0.0.1');
    if (url.pathname === '/api/go') {
      const destination = url.searchParams.get('after.path') ?? '/';
      if (/[\x00-\x1f\x7f]/.test(destination)) response.writeHead(400);
      else response.writeHead(302, {location: destination});
    } else response.writeHead(404);
    response.end();
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  t.after(() => new Promise(resolve => server.close(resolve)));
  const origin = `http://127.0.0.1:${server.address().port}`;
  const parentScope = structuredClone(DEFAULT_SCOPE);
  parentScope.include = ['/api'];
  const childScope = {...parentScope, target: {...parentScope.target, origin},
    probes: {...parentScope.probes, hostHeaderRedirect: false}};
  const ledger = createLedger(dir);
  const requester = createRequester(childScope, {ledger, allowLocal: true, limiter: createLimiter(100)});
  const surface = {patterns: [{pattern: '/api/go', params: {'after.path': []}}],
    modelNotes: [{path: '/api/go', method: 'GET', purpose: 'Continue after login',
      parameterMeanings: [{name: 'after.path', meaning: 'Destination URL for browser navigation'}]}]};
  const web = await runWebProbes(surface, childScope, {requester, ledger, budget: 1});
  assert.equal(web.findings.length, 1);
  assert.equal(web.findings[0].kind, 'open-redirect');
  const proved = await proveFindings(web.findings.map((item, index) => ({...item, id: `f-${index + 1}`})), [],
    {runDir: dir, surface, scope: parentScope, env: process.env, ledger,
      web: {results: web.results.map(item => ({...item, origin}))}});
  assert.equal(proved.length, 1);
  const spec = JSON.parse(fs.readFileSync(`${dir}/poc/f-1/spec.json`, 'utf8'));
  assert.equal(spec.origin, origin);
  assert.ok(new URL(spec.request.url, origin).searchParams.has('after.path'));
  assert.equal(verifyLedger(ledger.file).ok, true);
});

test('an authorized descendant account list can yield a replayable anonymous credential finding', async t => {
  const dir = temp();
  t.after(() => fs.rmSync(dir, {recursive: true, force: true}));
  let vulnerable = true;
  const hashes = [
    `$2b$12$${'a'.repeat(53)}`,
    `$2b$12$${'b'.repeat(53)}`,
  ];
  const server = http.createServer((request, response) => {
    const rows = [{id: 'person-a', ...(vulnerable ? {passwordHash: hashes[0]} : {})},
      {id: 'person-b', ...(vulnerable ? {passwordHash: hashes[1]} : {})}];
    response.writeHead(request.url === '/api/users' ? 200 : 404,
      {'content-type': 'application/json', 'cache-control': 'no-store'});
    response.end(JSON.stringify(request.url === '/api/users' ? rows : {error: 'missing'}));
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  t.after(() => new Promise(resolve => server.close(resolve)));
  const origin = `http://127.0.0.1:${server.address().port}`;
  const scope = structuredClone(DEFAULT_SCOPE);
  scope.domains = ['example.test'];
  scope.discovery.auditDomains = ['example.test'];
  scope.include = ['/api'];
  const ledger = createLedger(dir);
  const requester = async ({url, step = 'task'}) => {
    const address = new URL(url, origin);
    const body = await new Promise((resolve, reject) => {
      http.get(address, reply => {
        const chunks = [];
        reply.on('data', chunk => chunks.push(chunk));
        reply.on('end', () => resolve({status: reply.statusCode,
          body: Buffer.concat(chunks).toString('utf8'), headers: reply.headers}));
        reply.on('error', reject);
      }).on('error', reject);
    });
    return {...body, type: body.headers['content-type'],
      evidenceId: ledger.append({step, request: {method: 'GET', url: address.href},
        response: {status: body.status}})};
  };
  const discovery = {hosts: [{host: 'api.example.test', origin,
    operations: [{method: 'GET', path: '/api/users', params: [], source: ['document:/openapi.json']}], assets: null}]};
  const audit = await auditDiscoveredHosts(discovery, scope, {requester, ledger, budget: 4});
  const found = audit.findings.find(item => item.kind === 'anonymous-credential-data');
  assert.ok(found, JSON.stringify(audit.results));
  const findings = buildFindings([], {surface: {identity: {verified: false}}, scope,
    webFindings: audit.findings});
  const proved = await proveFindings(findings, [], {runDir: dir, surface: {patterns: []}, scope,
    env: {}, ledger, web: audit});
  assert.equal(proved.length, 1);
  const proof = proved[0].proof;
  assert.equal((await execFile(process.execPath, [proof])).code, 1);
  vulnerable = false;
  assert.equal((await execFile(process.execPath, [proof])).code, 0);
  const artifact = fs.readFileSync(`${dir}/poc/${proved[0].id}/spec.json`, 'utf8');
  hashes.forEach(value => assert.ok(!artifact.includes(value)));
});
