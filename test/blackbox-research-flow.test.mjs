import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import http from 'node:http';
import os from 'node:os';
import path from 'node:path';
import {randomBytes} from 'node:crypto';
import {createLedger} from '../src/blackbox/ledger.mjs';
import {proveFindings} from '../src/blackbox/poc.mjs';
import {createRequester, loadScope, validateUrl} from '../src/blackbox/scope.mjs';
import {mineOrigin} from '../src/blackbox/assets.mjs';
import {anonymousSurface, deriveLocalPostScope} from '../src/blackbox/anonymous.mjs';
import {reconConfirmedAccess} from '../src/blackbox/derived-session-recon.mjs';
import {executeResearchFlow, planResearchFlows, protectedReadBoundaryFacts,
  researchFlowInventory, runResearchFlows,
  validateResearchFlow} from '../src/blackbox/research-flow.mjs';
import {execFile} from '../src/util.mjs';

test('a proved request context remaps new scripts and lets Muse prove a second boundary', async t => {
  const gatePath = randomPath('entry');
  const newPage = randomPath('workspace');
  const scriptPath = `${randomPath('bundle')}.js`;
  const apiPath = randomPath('operation');
  const adminPath = randomPath('admin');
  const headerName = `x-entry-${randomBytes(3).toString('hex')}`;
  const accepted = `value_${randomBytes(6).toString('hex')}`;
  const sessionName = `session_${randomBytes(4).toString('hex')}`;
  const sessionValue = `issued_${randomBytes(6).toString('hex')}`;
  let vulnerable = true;
  const hits = [];
  const server = http.createServer((request, response) => {
    const url = new URL(request.url, 'http://fixture.invalid');
    const gateAccepted = request.headers[headerName] === accepted;
    const opened = gateAccepted && String(request.headers.cookie ?? '')
      .split(';').some(part => part.trim() === `${sessionName}=${sessionValue}`);
    if (url.pathname === gatePath && gateAccepted)
      response.setHeader('set-cookie', `${sessionName}=${sessionValue}; Path=/; HttpOnly`);
    hits.push({path: url.pathname, opened});
    response.setHeader('cache-control', 'no-store');
    if (url.pathname === scriptPath && opened) {
      response.setHeader('content-type', 'application/javascript');
      return response.end(`fetch('${apiPath}', {method:'POST', headers:{'content-type':'application/json'}, body:JSON.stringify({name:'demo'})}); fetch('${adminPath}?role=0')`);
    }
    if (url.pathname === apiPath) {
      response.setHeader('content-type', 'application/json');
      return response.end(JSON.stringify({ok: opened}));
    }
    response.setHeader('content-type', 'text/html');
    if (url.pathname === adminPath) return response.end(opened && vulnerable &&
      url.searchParams.get('role') === '1' ? '<main>Admin records</main>' :
      '<main>Denied</main>');
    if (url.pathname === gatePath || url.pathname === newPage || url.pathname === '/')
      return response.end((url.pathname === gatePath ? gateAccepted : opened) ?
        `<main>Application</main><script src="${scriptPath}"></script><a href="${newPage}">Workspace</a>` :
        '<main>Private gate</main>');
    response.statusCode = 404;
    response.end('missing');
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  t.after(() => new Promise(resolve => server.close(resolve)));
  const origin = `http://127.0.0.1:${server.address().port}`;
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'bypass-proved-access-'));
  t.after(() => fs.rmSync(dir, {recursive: true, force: true}));
  const scope = loadScope({origin, overrides: {acceptLocal: true}}).scope;
  const surface = {patterns: [{pattern: gatePath, methods: ['GET'], params: {},
    responseFacts: {status: 200}}]};
  const raw = (path, headers = []) => ({method: 'GET', path, headers, body: ''});
  const accessHeader = [{name: headerName, value: accepted}];
  const entry = {family: 'access boundary', why: 'Observed gate may trust one request value',
    priority: 9, as: 'anonymous', oracle: 'raw-proof',
    rawRequests: [raw(gatePath, accessHeader)],
    rawProof: {baseline: [raw(gatePath)],
      negative: [raw(gatePath, [{name: headerName, value: 'wrong'}])],
      closedText: 'Private gate', openText: 'Application'}};
  const firstPlan = await planResearchFlows(surface, scope, {model: 'fixture',
    budget: 1, modelCallsAvailable: 1,
    infer: async () => ({flows: [entry]})});
  const ledger = createLedger(dir);
  t.after(() => ledger.close());
  const requester = createRequester(scope, {ledger, allowLocal: true});
  const contexts = [];
  const first = await runResearchFlows(firstPlan.leads, scope, {surface, ledger,
    requester, modelCallsAvailable: 0,
    onConfirmedAccess: item => contexts.push(item)});
  assert.equal(first.findings[0]?.verdict, 'confirmed');
  assert.equal(contexts.length, 1);
  const {mapped, nextSurface} = await reconConfirmedAccess(scope, {
    context: contexts[0].context, requester, observedRoutes: [gatePath, '/'],
    publicSurface: surface});
  assert.ok(hits.some(hit => hit.path === scriptPath && hit.opened));
  assert.ok(hits.some(hit => hit.path === newPage && hit.opened));
  assert.ok(mapped.assets.some(item => item.path === scriptPath && item.kind === 'script'));
  assert.ok(mapped.contracts.some(item => item.path === apiPath && item.method === 'POST'));
  assert.ok(nextSurface.patterns.some(item => item.pattern === newPage));
  assert.ok(!JSON.stringify(mapped).includes(accepted));
  assert.ok(!JSON.stringify(mapped).includes(sessionValue));
  assert.ok(!JSON.stringify(nextSurface).includes(accepted));
  assert.ok(nextSurface.provedAccess.requests.at(-1).headers.some(item =>
    item.name === 'cookie' && item.value === `${sessionName}=${sessionValue}`));
  const followupHeaders = nextSurface.provedAccess.requests.at(-1).headers;
  const followup = {family: 'second access boundary', why: 'Test the newly exposed admin read',
    priority: 9, as: 'anonymous', oracle: 'raw-proof',
    rawRequests: [raw(`${adminPath}?role=1`, followupHeaders)],
    rawProof: {baseline: [raw(adminPath, followupHeaders)],
      negative: [raw(`${adminPath}?role=0`, followupHeaders)],
      closedText: 'Denied', openText: 'Admin records'}};
  let sawNewSurface = false;
  const secondPlan = await planResearchFlows(nextSurface, scope, {model: 'fixture',
    budget: 1, modelCallsAvailable: 1, infer: async (_model, messages) => {
      const context = JSON.parse(messages[1].content);
      sawNewSurface = context.provedAccess.requests.at(-1).headers.some(item =>
        item.name === headerName && item.value === accepted) &&
        context.routes.some(item => item.path === apiPath && item.methods.includes('POST'));
      return {flows: [followup]};
    }});
  assert.equal(sawNewSurface, true);
  assert.equal(secondPlan.leads.length, 1, JSON.stringify(secondPlan.decisions));
  const second = await runResearchFlows(secondPlan.leads, scope, {surface: nextSurface,
    ledger, requester, modelCallsAvailable: 0});
  assert.equal(second.findings[0]?.verdict, 'confirmed');
  const proved = await proveFindings([{...second.findings[0], id: 'f-002'}], [],
    {runDir: dir, surface: nextSurface, scope, env: {}, ledger, web: second});
  assert.equal(proved.length, 1);
  vulnerable = false;
  const fixed = await execFile(process.execPath, [proved[0].proof, '--expect-fixed'],
    {env: process.env, timeout: 20000});
  assert.equal(fixed.code, 0, fixed.stdout);
});

test('separate Muse planning calls execute distinct accepted HTTP leads', async t => {
  const routes = [randomPath('first'), randomPath('second')];
  const hits = [];
  const server = http.createServer((request, response) => {
    hits.push(request.url);
    response.writeHead(200, {'content-type': 'application/json',
      'cache-control': 'no-store'});
    response.end(JSON.stringify({path: request.url}));
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  t.after(() => new Promise(resolve => server.close(resolve)));
  const origin = `http://127.0.0.1:${server.address().port}`;
  const scope = loadScope({origin, overrides: {acceptLocal: true}}).scope;
  const surface = {patterns: routes.map(pattern =>
    ({pattern, methods: ['GET'], params: {}}))};
  const plans = await Promise.all(routes.map(route => planResearchFlows(surface,
    scope, {model: 'fixture', budget: 1, modelCallsAvailable: 1,
      infer: async () => ({flows: [{family: 'route investigation',
        why: 'Read the observed route', priority: 8, as: 'anonymous',
        oracle: 'raw-observation', rawRequests: [{method: 'GET', path: route}]}]})})));
  assert.ok(plans.every(plan => plan.leads.length === 1),
    JSON.stringify(plans.map(plan => plan.decisions)));
  assert.notEqual(plans[0].leads[0].proposalId, plans[1].leads[0].proposalId,
    'an accepted lead on a later planning page must not inherit an earlier ID');
  const repeated = await planResearchFlows(surface, scope, {model: 'fixture',
    budget: 1, modelCallsAvailable: 1,
    infer: async () => ({flows: [{family: 'route investigation',
      why: 'New evidence warrants another read', priority: 8, as: 'anonymous',
      oracle: 'raw-observation', rawRequests: [{method: 'GET', path: routes[0]}]}]})});
  assert.notEqual(plans[0].leads[0].proposalId, repeated.leads[0].proposalId,
    'a later Muse investigation keeps its own identity even on the same route');
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'bypass-research-ids-'));
  t.after(() => fs.rmSync(dir, {recursive: true, force: true}));
  const ledger = createLedger(dir);
  t.after(() => ledger.close());
  const run = await runResearchFlows(plans.flatMap(plan => plan.leads), scope,
    {surface, ledger, requester: createRequester(scope,
      {ledger, allowLocal: true}), modelCallsAvailable: 0});
  assert.deepEqual(hits.toSorted(), routes.toSorted());
  assert.equal(run.results.length, 2);
});

test('Muse-selected exact cookie request proves access and clears after a fix', async t => {
  const route = randomPath('workspace');
  const cookieName = `gate_${randomBytes(5).toString('hex')}`;
  const secretValue = `signed_${randomBytes(8).toString('hex')}`;
  let vulnerable = true;
  const requests = [];
  const server = http.createServer((request, response) => {
    requests.push({method: request.method, path: request.url,
      hasCookie: Boolean(request.headers.cookie)});
    const cookie = request.headers.cookie ?? '';
    const named = cookie.split(';').some(part => part.trim().startsWith(`${cookieName}=`));
    const authorized = named && (vulnerable || cookie.includes(`${cookieName}=${secretValue}`));
    response.writeHead(request.url === route ? 200 : 404,
      {'content-type': 'text/html', 'cache-control': 'no-store'});
    response.end(request.url !== route ? 'missing' : authorized ?
      '<main>private workspace</main>' : '<main>access code required</main>');
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  t.after(() => new Promise(resolve => server.close(resolve)));
  const origin = `http://127.0.0.1:${server.address().port}`;
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'bypass-cookie-access-'));
  t.after(() => fs.rmSync(dir, {recursive: true, force: true}));
  const scope = loadScope({origin, overrides: {acceptLocal: true}}).scope;
  const surface = {patterns: [{pattern: route, methods: ['GET'], params: {},
    responseFacts: {status: 200}}],
  assetSignals: [{file: `${origin}/client.js`, evidenceId: 'ev-script',
    authFlow: `After the access flow, the server sets cookie ${cookieName} and reloads ${route}.`}]};
  const candidateValue = `candidate_${randomBytes(5).toString('hex')}`;
  const rawRequest = (name, value) => ({method: 'GET', path: route,
    headers: name ? [{name: 'Cookie', value: `${name}=${value}`}] : [], body: ''});
  const proposal = {family: 'cookie-gate', why: 'Client source names the access cookie',
    priority: 9, as: 'anonymous', oracle: 'raw-proof',
    rawRequests: [rawRequest(cookieName, candidateValue)],
    rawProof: {baseline: [rawRequest(null)],
      negative: [rawRequest('other_gate', candidateValue)],
      closedText: '<main>access code required</main>',
      openText: '<main>private workspace</main>'}};
  let sawCookieClue = false;
  const planned = await planResearchFlows(surface, scope, {model: 'fixture',
    budget: 1, modelCallsAvailable: 1, infer: async (_model, messages) => {
      const context = JSON.parse(messages[1].content);
      sawCookieClue = context.assetSignals.some(item =>
        item.authFlow.includes(cookieName));
      return {flows: [proposal]};
    }});
  assert.equal(sawCookieClue, true);
  assert.equal(planned.leads.length, 1, JSON.stringify(planned.decisions));
  const ledger = createLedger(dir);
  t.after(() => ledger.close());
  const run = await runResearchFlows(planned.leads, scope, {surface, ledger,
    requester: createRequester(scope, {ledger, allowLocal: true}),
    modelCallsAvailable: 0});
  assert.equal(run.results[0].verdict, 'confirmed', JSON.stringify(run.results[0]));
  assert.equal(run.findings[0]?.kind, 'model-raw-boundary');
  assert.equal(requests.length, 6);
  const proved = await proveFindings([{...run.findings[0], id: 'f-001'}], [],
    {runDir: dir, surface, scope, env: {}, ledger, web: run});
  assert.equal(proved.length, 1);
  assert.equal(requests.length, 12);
  assert.ok(!fs.readFileSync(path.join(dir, 'poc/f-001/spec.json'), 'utf8')
    .includes(secretValue));
  vulnerable = false;
  const fixed = await execFile(process.execPath, [proved[0].proof, '--expect-fixed'],
    {env: process.env, timeout: 20000});
  assert.equal(fixed.code, 0, fixed.stdout);
});

test('Muse can execute a scoped mixed-method request sequence without placement templates', async t => {
  const route = randomPath('operation');
  const cookieName = `session_${randomBytes(4).toString('hex')}`;
  const cookieValue = `bx${randomBytes(9).toString('hex')}`;
  const bodyValue = `opaque:${randomBytes(6).toString('hex')}`;
  const operatorToken = `operator_${randomBytes(10).toString('hex')}`;
  const env = {OWNER_TOKEN: operatorToken};
  const received = [];
  const server = http.createServer(async (request, response) => {
    const chunks = [];
    for await (const chunk of request) chunks.push(chunk);
    received.push({method: request.method, url: request.url,
      cookie: request.headers.cookie, contentType: request.headers['content-type'],
      authorization: request.headers.authorization,
      custom: request.headers['x-workflow-input'],
      body: Buffer.concat(chunks).toString()});
    response.writeHead(200, {'content-type': 'application/json',
      'cache-control': 'no-store'});
    response.end(JSON.stringify({method: request.method,
      accepted: request.headers.cookie === `${cookieName}=${cookieValue}` &&
        Buffer.concat(chunks).toString() === bodyValue}));
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  t.after(() => new Promise(resolve => server.close(resolve)));
  const origin = `http://127.0.0.1:${server.address().port}`;
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'bypass-raw-flow-'));
  t.after(() => fs.rmSync(dir, {recursive: true, force: true}));
  const scope = loadScope({origin, overrides: {acceptLocal: true}}).scope;
  const surface = {patterns: [{pattern: route, methods: ['GET'], params: {}}]};
  const proposal = {family: 'opaque-workflow', why: 'Review response to a scoped method sequence',
    priority: 6, as: 'anonymous', oracle: 'raw-observation',
    rawRequests: [
      {method: 'GET', path: route},
      {method: 'PATCH', path: route, headers: [
        {name: 'Cookie', value: `${cookieName}=${cookieValue}`},
        {name: 'Authorization', value: `Bearer ${operatorToken}`},
        {name: 'Content-Type', value: 'application/octet-stream'},
        {name: 'X-Workflow-Input', value: 'custom'}], body: bodyValue},
      {method: 'GET', path: route}]};
  const planned = await planResearchFlows(surface, scope, {model: 'fixture',
    budget: 1, modelCallsAvailable: 1, env,
    infer: async (_model, messages, options) => {
      assert.match(messages[0].content, /exact values you choose/);
      assert.ok(!options.schema.properties.flows.items.required.includes('subject'));
      return {flows: [proposal]};
    }});
  assert.equal(planned.leads.length, 1, JSON.stringify(planned.decisions));
  assert.ok(!JSON.stringify(planned.leads).includes(operatorToken));
  const ledger = createLedger(dir);
  t.after(() => ledger.close());
  const requester = createRequester(scope, {ledger, allowLocal: true});
  const run = await runResearchFlows(planned.leads, scope, {surface, ledger,
    requester, model: 'fixture', modelCallsAvailable: 1, env,
    infer: async () => ({flows: []})});
  assert.equal(run.results[0].verdict, 'observed', JSON.stringify(run.results[0]));
  assert.equal(run.findings.length, 0);
  assert.deepEqual(received.map(item => item.method), ['GET', 'PATCH', 'GET']);
  assert.equal(received[1].cookie, `${cookieName}=${cookieValue}`);
  assert.equal(received[1].authorization, `Bearer ${operatorToken}`);
  assert.equal(received[1].contentType, 'application/octet-stream');
  assert.equal(received[1].custom, 'custom');
  assert.equal(received[1].body, bodyValue);
  const evidence = fs.readFileSync(ledger.file, 'utf8');
  assert.ok(!evidence.includes(cookieValue));
  assert.ok(!evidence.includes(bodyValue));
  assert.ok(!evidence.includes(operatorToken));
});

test('a minimal Muse request plan preserves exact values across scoped HTTP shapes', async t => {
  const route = randomPath('contract');
  const received = [];
  const server = http.createServer(async (request, response) => {
    const chunks = [];
    for await (const chunk of request) chunks.push(chunk);
    received.push({method: request.method, url: request.url,
      cookie: request.headers.cookie ?? '', custom: request.headers['x-contract'] ?? '',
      contentType: request.headers['content-type'] ?? '',
      body: Buffer.concat(chunks).toString()});
    response.writeHead(200, {'content-type': 'text/plain',
      'cache-control': 'no-store'});
    response.end('observed');
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  t.after(() => new Promise(resolve => server.close(resolve)));
  const origin = `http://127.0.0.1:${server.address().port}`;
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'bypass-raw-shapes-'));
  t.after(() => fs.rmSync(dir, {recursive: true, force: true}));
  const scope = loadScope({origin, overrides: {acceptLocal: true}}).scope;
  const surface = {patterns: [{pattern: route,
    methods: ['GET', 'HEAD', 'POST', 'PATCH', 'DELETE'], params: {code: []}}]};
  const requests = [
    {method: 'GET', path: `${route}?code=1%2B2`,
      headers: [{name: 'Cookie', value: 'gate=1'}]},
    {method: 'POST', path: route, headers: [
      {name: 'Content-Type', value: 'application/x-www-form-urlencoded'}],
    body: 'code=1%2B2&next=%2F'},
    {method: 'PATCH', path: route, headers: [
      {name: 'Content-Type', value: 'application/xml'}],
    body: '<request><code>1+2</code></request>'},
    {method: 'DELETE', path: route, headers: [
      {name: 'Content-Type', value: 'application/json'}],
    body: '{"code":"1;2"}'},
    {method: 'HEAD', path: route, headers: [
      {name: 'X-Contract', value: '1;2'}]},
  ];
  const proposal = {family: 'contract investigation',
    why: 'Compare exact requests across observed methods', priority: 6,
    as: 'anonymous', rawRequests: requests};
  const planned = await planResearchFlows(surface, scope, {
    model: 'fixture', budget: 1, modelCallsAvailable: 1,
    infer: async () => ({flows: [proposal]})});
  assert.equal(planned.leads.length, 1, JSON.stringify(planned.decisions));
  assert.equal(planned.leads[0].oracle, 'raw-observation');
  const ledger = createLedger(dir);
  t.after(() => ledger.close());
  const run = await runResearchFlows(planned.leads, scope, {surface,
    ledger, requester: createRequester(scope, {ledger, allowLocal: true}),
    modelCallsAvailable: 0});
  assert.equal(run.results[0].verdict, 'observed', JSON.stringify(run.results[0]));
  assert.deepEqual(received.map(item => item.method),
    ['GET', 'POST', 'PATCH', 'DELETE', 'HEAD']);
  assert.equal(received[0].url, `${route}?code=1%2B2`);
  assert.equal(received[0].cookie, 'gate=1');
  assert.equal(received[1].body, requests[1].body);
  assert.equal(received[2].body, requests[2].body);
  assert.equal(received[3].body, requests[3].body);
  assert.equal(received[4].custom, '1;2');
});

test('Muse refines an exact cookie request into a generic replayed access proof', async t => {
  const route = `/workspace-${randomBytes(4).toString('hex')}`;
  const cookieName = `entry_${randomBytes(5).toString('hex')}`;
  let vulnerable = true;
  const received = [];
  const server = http.createServer((request, response) => {
    received.push({path: request.url, cookie: request.headers.cookie ?? ''});
    const open = vulnerable && request.headers.cookie === `${cookieName}=1`;
    response.writeHead(200, {'content-type': 'text/html', 'cache-control': 'no-store'});
    response.end(open ? '<title>Workspace</title><main>Private workspace</main>' :
      '<title>Private Beta</title><main>Access code required</main>');
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  t.after(() => new Promise(resolve => server.close(resolve)));
  const origin = `http://127.0.0.1:${server.address().port}`;
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'bypass-raw-proof-'));
  t.after(() => fs.rmSync(dir, {recursive: true, force: true}));
  const scope = loadScope({origin, overrides: {acceptLocal: true}}).scope;
  const surface = {patterns: [{pattern: route, methods: ['GET'], params: {},
    responseFacts: {status: 200}}], assetSignals: [{file: `${origin}/client.js`,
      authFlow: `Successful access sets cookie ${cookieName} before loading ${route}.`}]};
  const request = value => ({method: 'GET', path: route,
    headers: value === null ? [] : [{name: 'Cookie', value: `${cookieName}=${value}`}],
    body: ''});
  const cookiePlan = {family: 'gated workspace', why: 'Client names the cookie',
    priority: 9, as: 'anonymous', oracle: 'cookie-access', prelude: [], observe: [],
    subject: {method: 'GET', path: route, placement: 'cookie', key: cookieName,
      fixedFields: [], bodyTemplate: '', headers: []}, controlValue: '0',
    firstValue: '1', secondValue: '', marker: '<title>Private Beta</title>',
    secondMarker: '<title>Workspace</title>',
    assertion: {step: 'subject', index: 0, location: 'body', name: ''}};
  const reviewedCookie = validateResearchFlow(cookiePlan, surface, scope);
  assert.equal(reviewedCookie.ok, true);
  assert.equal(reviewedCookie.lead.oracle, 'raw-proof');
  assert.equal(reviewedCookie.lead.rawRequests[0].headers.at(-1).value,
    `${cookieName}=1`);
  const flow = (oracle, value, proof = null) => ({family: 'gated workspace',
    why: 'Compare access with a model-chosen request value', priority: 9,
    as: 'anonymous', oracle, rawRequests: [request(value)],
    ...(proof ? {rawProof: proof} : {}), prelude: [], observe: [],
    subject: {method: 'GET', path: route, placement: 'request', key: 'request',
      fixedFields: [], bodyTemplate: '', headers: []}, controlValue: '',
    firstValue: '', secondValue: '', marker: '', secondMarker: '',
    assertion: {step: 'subject', index: 0, location: 'body', name: ''}});
  const planned = await planResearchFlows(surface, scope, {model: 'fixture',
    budget: 1, modelCallsAvailable: 1,
    infer: async () => ({flows: [flow('raw-observation', 'wrong')]})});
  assert.equal(planned.leads.length, 1, JSON.stringify(planned.decisions));
  const ledger = createLedger(dir);
  t.after(() => ledger.close());
  let modelCalls = 0;
  const run = await runResearchFlows(planned.leads, scope, {surface, ledger,
    requester: createRequester(scope, {ledger, allowLocal: true}), model: 'fixture',
    modelCallsAvailable: 2, infer: async (_model, messages) => {
      const context = JSON.parse(messages[1].content);
      modelCalls++;
      if (modelCalls === 1) {
        assert.ok(JSON.stringify(context).includes('Private Beta'));
        return {flows: [flow('raw-observation', '1')]};
      }
      assert.ok(JSON.stringify(context).includes('Workspace'));
      return {flows: [flow('raw-proof', '1', {baseline: [request(null)],
        negative: [request('0')], closedText: '<title>Private Beta</title>',
        openText: '<title>Workspace</title>'})]};
    }});
  assert.equal(modelCalls, 2);
  assert.equal(run.results[0].verdict, 'confirmed', JSON.stringify(run.results[0]));
  assert.equal(run.findings[0]?.kind, 'model-raw-boundary');
  assert.ok(received.some(item => item.cookie === `${cookieName}=1`));
  assert.ok(received.some(item => item.cookie === `${cookieName}=0`));
  const proved = await proveFindings([{...run.findings[0], id: 'f-001'}], [],
    {runDir: dir, surface, scope, env: {}, ledger, web: run});
  assert.equal(proved.length, 1);
  assert.ok(!fs.readFileSync(ledger.file, 'utf8').includes(`${cookieName}=1`));
  vulnerable = false;
  const fixed = await execFile(process.execPath, [proved[0].proof, '--expect-fixed'],
    {env: process.env, timeout: 20000});
  assert.equal(fixed.code, 0, fixed.stdout);
});

test('Muse can reconsider an uninformative raw request stop and prove a changed candidate', async t => {
  const route = randomPath('access-review');
  const cookieName = `access_${randomBytes(5).toString('hex')}`;
  const acceptedValue = randomBytes(5).toString('hex');
  const wrongValue = randomBytes(5).toString('hex');
  const received = [];
  const server = http.createServer((request, response) => {
    received.push(request.headers.cookie ?? '');
    const open = request.headers.cookie === `${cookieName}=${acceptedValue}`;
    response.writeHead(200, {'content-type': 'text/html', 'cache-control': 'no-store'});
    response.end(open ? '<title>Workspace</title><main>Private workspace</main>' :
      '<title>Access gate</title><main>Access code required</main>');
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  t.after(() => new Promise(resolve => server.close(resolve)));
  const origin = `http://127.0.0.1:${server.address().port}`;
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'bypass-stop-review-'));
  t.after(() => fs.rmSync(dir, {recursive: true, force: true}));
  const scope = loadScope({origin, overrides: {acceptLocal: true}}).scope;
  const surface = {patterns: [{pattern: route, methods: ['GET'], params: {}}]};
  const raw = value => ({method: 'GET', path: route,
    headers: value === null ? [] : [{name: 'Cookie', value: `${cookieName}=${value}`}],
    body: ''});
  const flow = (oracle, value, rawProof) => ({family: 'access gate',
    why: 'Client source names an access cookie', priority: 8, as: 'anonymous',
    oracle, rawRequests: [raw(value)], ...(rawProof ? {rawProof} : {})});
  const ledger = createLedger(dir);
  t.after(() => ledger.close());
  let calls = 0;
  const initial = validateResearchFlow(flow('raw-observation', wrongValue), surface, scope);
  assert.equal(initial.ok, true);
  const run = await runResearchFlows([initial.lead], scope,
    {surface, ledger, requester: createRequester(scope, {ledger, allowLocal: true}),
      model: 'fixture', modelCallsAvailable: 4, infer: async (_model, messages) => {
        const context = JSON.parse(messages[1].content);
        calls++;
        if (calls === 1) {
          assert.equal(context.recentAttempts.length, 1);
          return {flows: []};
        }
        if (calls === 2) {
          assert.equal(context.stopReview, true);
          assert.equal(context.recentAttempts[0].requests[0].status, 200);
          return {flows: [flow('raw-observation', acceptedValue)]};
        }
        return {flows: [flow('raw-proof', acceptedValue, {
          baseline: [raw(null)], negative: [raw(wrongValue)],
          closedText: '<title>Access gate</title>',
          openText: '<title>Workspace</title>'})]};
      }});
  assert.equal(calls, 3);
  assert.equal(run.results[0].verdict, 'confirmed', JSON.stringify(run.results[0]));
  assert.ok(received.includes(`${cookieName}=${acceptedValue}`));
  assert.ok(received.includes(`${cookieName}=${wrongValue}`));
  assert.equal(run.findings[0]?.kind, 'model-raw-boundary');
  const proved = await proveFindings([{...run.findings[0], id: 'f-001'}], [],
    {runDir: dir, surface, scope, env: {}, ledger, web: run});
  assert.equal(proved.length, 1);
});

test('Muse may stop a raw request after reviewing one negative candidate', async () => {
  const origin = 'http://127.0.0.1:4329';
  const route = randomPath('stop-review');
  const scope = loadScope({origin, overrides: {acceptLocal: true}}).scope;
  const surface = {patterns: [{pattern: route, methods: ['GET'], params: {}}]};
  const plan = validateResearchFlow({family: 'observed route', why: 'Review one route',
    priority: 5, as: 'anonymous', oracle: 'raw-observation',
    rawRequests: [{method: 'GET', path: route}]}, surface, scope);
  assert.equal(plan.ok, true);
  let calls = 0, requests = 0;
  const run = await runResearchFlows([plan.lead], scope, {surface, model: 'fixture',
    modelCallsAvailable: 20,
    requester: async () => ({status: 200, type: 'text/html',
      body: '<title>Ordinary page</title>', headers: {'cache-control': 'no-store'},
      evidenceId: `ev-${++requests}`}),
    infer: async (_model, messages) => {
      calls++;
      if (calls === 2) assert.equal(JSON.parse(messages[1].content).stopReview, true);
      return {flows: []};
    }});
  assert.equal(calls, 2);
  assert.equal(requests, 1);
  assert.equal(run.investigations[0].attempts.length, 1);
  assert.equal(run.investigations[0].stopReason, 'model-stopped');
  assert.equal(run.decisions[0].stopReviewRequested, true);
  assert.equal(run.decisions[1].stopReview, true);
});

test('generic raw proof preserves a model-authored POST body and header through replay', async t => {
  const route = randomPath('opaque');
  const headerName = `X-Probe-${randomBytes(3).toString('hex')}`;
  const bodyValue = `opaque:${randomBytes(7).toString('hex')}`;
  let vulnerable = true;
  const received = [];
  const server = http.createServer(async (request, response) => {
    const chunks = [];
    for await (const chunk of request) chunks.push(chunk);
    const body = Buffer.concat(chunks).toString();
    received.push({method: request.method, body,
      header: request.headers[headerName.toLowerCase()]});
    const allowed = vulnerable && request.method === 'POST' &&
      request.headers[headerName.toLowerCase()] === 'allow' && body === bodyValue;
    response.writeHead(allowed ? 200 : 403,
      {'content-type': 'application/json', 'cache-control': 'no-store'});
    response.end(allowed ? '{"resource":"private"}' : '{"error":"denied"}');
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  t.after(() => new Promise(resolve => server.close(resolve)));
  const origin = `http://127.0.0.1:${server.address().port}`;
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'bypass-raw-post-proof-'));
  t.after(() => fs.rmSync(dir, {recursive: true, force: true}));
  const scope = loadScope({origin, overrides: {acceptLocal: true}}).scope;
  const surface = {patterns: [{pattern: route, methods: ['POST'], params: {}}],
    methodOperations: [{path: route, method: 'POST', placement: 'raw',
      fields: [], contentType: 'application/octet-stream'}]};
  const request = value => ({method: 'POST', path: route,
    headers: [{name: 'Content-Type', value: 'application/octet-stream'},
      {name: headerName, value}], body: bodyValue});
  const proposal = {family: 'protected operation', why: 'Compare exact scoped POSTs',
    priority: 8, as: 'anonymous', oracle: 'raw-proof',
    rawRequests: [request('allow')], rawProof: {baseline: [request('plain')],
      negative: [request('deny')], closedText: '', openText: ''},
    prelude: [], subject: {method: 'POST', path: route, placement: 'request',
      key: 'request', fixedFields: [], bodyTemplate: '', headers: []}, observe: [],
    controlValue: '', firstValue: '', secondValue: '', marker: '', secondMarker: '',
    assertion: {step: 'subject', index: 0, location: 'body', name: ''}};
  const planned = await planResearchFlows(surface, scope, {model: 'fixture',
    budget: 1, modelCallsAvailable: 1, infer: async () => ({flows: [proposal]})});
  assert.equal(planned.leads.length, 1, JSON.stringify(planned.decisions));
  const ledger = createLedger(dir);
  t.after(() => ledger.close());
  const run = await runResearchFlows(planned.leads, scope, {surface, ledger,
    requester: createRequester(scope, {ledger, allowLocal: true}),
    modelCallsAvailable: 0});
  assert.equal(run.results[0].verdict, 'confirmed', JSON.stringify(run.results[0]));
  assert.equal(run.findings[0]?.kind, 'model-raw-boundary');
  const proved = await proveFindings([{...run.findings[0], id: 'f-001'}], [],
    {runDir: dir, surface, scope, env: {}, ledger, web: run});
  assert.equal(proved.length, 1);
  assert.equal(received.length, 12);
  assert.ok(received.every(item => item.method === 'POST' && item.body === bodyValue));
  assert.ok(received.some(item => item.header === 'allow'));
  vulnerable = false;
  const fixed = await execFile(process.execPath, [proved[0].proof, '--expect-fixed'],
    {env: process.env, timeout: 20000});
  assert.equal(fixed.code, 0, fixed.stdout);
});

const randomPath = suffix => `/api/${suffix}-${randomBytes(4).toString('hex')}`;

test('credential-shaped input names remain available to Muse as observed query and JSON fields', () => {
  const origin = 'http://127.0.0.1:4337';
  const readPath = randomPath('read');
  const writePath = randomPath('write');
  const writeKey = `json ${writePath}`;
  const scope = structuredClone(loadScope({origin, overrides: {acceptLocal: true}}).scope);
  scope.localAutoPostContracts = {[writeKey]:
    {contentType: 'application/json', fields: ['code']}};
  const surface = {patterns: [{pattern: readPath, methods: ['GET'], params: {code: []}}],
    jsonBodyOperations: [{path: writePath, method: 'POST',
      contentType: 'application/json', fields: ['code'], requiredFields: ['code']}],
    methodOperations: [{path: writePath, method: 'POST', placement: 'json',
      contentType: 'application/json', fields: ['code'], requiredFields: ['code']}]};
  const inventory = researchFlowInventory(surface, scope);
  assert.equal(inventory.reads.get(readPath)?.fields.has('code'), true);
  assert.deepEqual(inventory.posts.get(writeKey)?.fields, ['code']);
  assert.deepEqual(inventory.writeOperations.get(`POST ${writeKey}`)?.fields,
    ['code']);
  const base = {family: 'observed-code-field', why: 'Compare an observed input',
    priority: 5, as: 'anonymous', oracle: 'observation', prelude: [], observe: [],
    controlValue: 'audit-one', firstValue: 'audit-two', secondValue: 'audit-three',
    marker: '', secondMarker: '',
    assertion: {step: 'subject', index: 0, location: 'body', name: ''}};
  for (const subject of [
    {method: 'GET', path: readPath, placement: 'query', key: 'code',
      fixedFields: [], bodyTemplate: '', headers: []},
    {method: 'POST', path: writePath, placement: 'json', key: 'code',
      fixedFields: [], bodyTemplate: '', headers: []},
  ]) assert.equal(validateResearchFlow({...base, subject}, surface, scope).ok, true);
});

test('Muse research planning receives client-script state observations', async () => {
  const origin = 'http://127.0.0.1:4338';
  const cookieName = `gate_${randomBytes(5).toString('hex')}`;
  const scope = loadScope({origin, overrides: {acceptLocal: true}}).scope;
  const surface = {patterns: [{pattern: '/workspace', methods: ['GET'], params: {}}],
    assetSignals: [{file: `${origin}/client.js`,
      authFlow: `Client text names the ${cookieName} cookie after unlock`, evidenceId: 'ev-script'}]};
  let received = false;
  await planResearchFlows(surface, scope, {model: 'fixture', budget: 1,
    modelCallsAvailable: 1, infer: async (_model, messages) => {
      const context = JSON.parse(messages[1].content);
      received = context.assetSignals?.some(signal =>
        signal.authFlow.includes(cookieName) && signal.evidenceId === 'ev-script');
      return {flows: []};
    }});
  assert.equal(received, true);
});

test('a public HTML form becomes a reviewed Muse POST contract without OpenAPI or JavaScript',
  async t => {
    const route = randomPath('form-preview');
    const server = http.createServer((request, response) => {
      response.writeHead(request.url === '/' ? 200 : 404,
        {'content-type': 'text/html'});
      response.end(request.url === '/' ? `<form method="post" action="${route}">
        <input name="expression" required><input type="hidden" name="csrf"
          value="private-fixture-token-123"></form>` : 'missing');
    });
    await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
    t.after(() => new Promise(resolve => server.close(resolve)));
    const origin = `http://127.0.0.1:${server.address().port}`;
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'bypass-html-form-'));
    t.after(() => fs.rmSync(dir, {recursive: true, force: true}));
    const scopePath = path.join(dir, 'scope.json');
    fs.writeFileSync(scopePath, JSON.stringify({schemaVersion: 1, target: {origin},
      include: ['/'], limits: {rps: 50}}));
    const scope = loadScope({file: scopePath, origin}).scope;
    const requester = async ({url}) => {
      const response = await fetch(new URL(url, origin));
      return {status: response.status, type: response.headers.get('content-type'),
        body: await response.text(), evidenceId: 'fixture'};
    };
    const mined = await mineOrigin(origin, {requester});
    assert.ok(!JSON.stringify(mined).includes('private-fixture-token-123'));
    const prepared = await deriveLocalPostScope(scope, mined, requester);
    assert.deepEqual(prepared.admitted.map(item => item.path), [route]);
    const surface = await anonymousSurface(prepared.scope, requester, mined);
    const form = surface.formBodyOperations.find(item => item.path === route);
    assert.deepEqual([form.source, form.fields, form.requiredFields],
      ['public-html', ['expression', 'csrf'], ['expression']]);
    assert.deepEqual(researchFlowInventory(surface, prepared.scope).posts
      .get(`form ${route}`).fields, ['expression', 'csrf']);
    let presented = false;
    const planned = await planResearchFlows(surface, prepared.scope, {model: 'fixture',
      budget: 1, modelCallsAvailable: 1,
      infer: async (_model, messages) => {
        const context = JSON.parse(messages[1].content);
        presented = context.routes.some(item => item.path === route &&
          item.kind === 'form' && item.fields.includes('expression'));
        return {flows: []};
      }});
    assert.equal(presented, true);
    assert.equal(planned.leads.length, 0);
  });

test('reviewed operation purpose survives a shorter model note in planning and revision context',
  async t => {
    const route = randomPath('selector-purpose');
    const server = http.createServer(async (request, response) => {
      for await (const _chunk of request) { /* consume the request body */ }
      response.writeHead(200, {'content-type': 'application/json',
        'cache-control': 'no-store'});
      response.end(JSON.stringify({records: []}));
    });
    await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
    t.after(() => new Promise(resolve => server.close(resolve)));
    const origin = `http://127.0.0.1:${server.address().port}`;
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'bypass-purpose-context-'));
    t.after(() => fs.rmSync(dir, {recursive: true, force: true}));
    const scopePath = path.join(dir, 'scope.json');
    fs.writeFileSync(scopePath, JSON.stringify({schemaVersion: 1, target: {origin},
      include: ['/'], probes: {jsonPostPaths: [route]}, limits: {rps: 50}}));
    const scope = structuredClone(loadScope({file: scopePath, origin}).scope);
    scope.localAutoPostContracts = {[`json ${route}`]:
      {contentType: 'application/json', fields: ['selector']}};
    const documentedPurpose = 'Resolve a public record by literal name or glob selector';
    const interpretedPurpose = 'Resolve JSON selector';
    const surface = {patterns: [{pattern: route, methods: ['POST']}],
      jsonBodyOperations: [{path: route, method: 'POST',
        contentType: 'application/json', fields: ['selector'],
        requiredFields: ['selector'], purpose: documentedPurpose,
        source: 'public-openapi'}],
      modelNotes: [{path: route, purpose: interpretedPurpose}]};
    const rowFor = context => context.routes?.find(item =>
      item.path === route && item.methods?.includes('POST')) ??
      context.observedRoutes?.find(item => item.path === route &&
        item.methods?.includes('POST'));
    const assertPurpose = context => {
      const row = rowFor(context);
      assert.equal(row?.purpose, documentedPurpose);
      assert.equal(row.modelPurpose, interpretedPurpose);
      assert.equal(row.source, 'public-openapi');
    };
    const lead = {family: 'documented-selector', why: 'Compare observed JSON responses',
      priority: 5, as: 'anonymous', oracle: 'observation', prelude: [],
      subject: {method: 'POST', path: route, placement: 'json', key: 'selector',
        fixedFields: [], bodyTemplate: '', headers: []}, observe: [],
      controlValue: 'plain', firstValue: 'other', secondValue: 'another',
      marker: '', secondMarker: '',
      assertion: {step: 'subject', index: 0, location: 'body', name: ''}};
    let initialSeen = 0;
    const planned = await planResearchFlows(surface, scope, {model: 'fixture',
      budget: 1, modelCallsAvailable: 1,
      infer: async (_model, messages) => {
        assertPurpose(JSON.parse(messages[1].content));
        initialSeen++;
        return {flows: [lead]};
      }});
    assert.equal(initialSeen, 1);
    assert.equal(planned.leads.length, 1);
    const ledger = createLedger(dir);
    t.after(() => ledger.close());
    let revisionSeen = 0;
    const run = await runResearchFlows(planned.leads, scope, {surface,
      requester: createRequester(scope, {ledger, allowLocal: true}), ledger,
      model: 'fixture', modelCallsAvailable: 1,
      infer: async (_model, messages) => {
        const context = JSON.parse(messages[1].content);
        assertPurpose(context);
        revisionSeen++;
        return {flows: []};
      }});
    assert.equal(revisionSeen, 1);
    assert.equal(run.findings.length, 0);
  });

test('protected read context prioritizes the active route and omits private or dynamic field names', () => {
  const paths = Array.from({length: 10}, (_, index) => `/api/private-${index}`);
  const active = paths.at(-1);
  const patterns = paths.map(pattern => ({pattern, fingerprint: {
    owner: {status: 200, shape: {record: {
      owner: 'string', private: 'boolean', secret: 'string',
      customer_email: 'string', accessToken: 'string',
      'alice@company.com': 'string',
      a0123456789abcdef0123456789abcdef: 'string'}}},
    anonymous: {status: 403}}}));
  const facts = protectedReadBoundaryFacts({patterns}, paths, active);
  assert.equal(facts.length, 8);
  assert.equal(facts[0].path, active);
  assert.equal(facts[0].ownerStatus, 200);
  assert.equal(facts[0].anonymousStatus, 403);
  assert.deepEqual(facts[0].ownerJsonFieldNames, ['record.owner', 'record.private']);
  assert.ok(!JSON.stringify(facts).includes('alice@company.com'));
  assert.ok(!JSON.stringify(facts).includes('accessToken'));
});

test('Muse local callback on a reviewed random POST proves a server fetch and replays red/green', async t => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'bypass-callback-'));
  t.after(() => fs.rmSync(dir, {recursive: true, force: true}));
  const route = randomPath('fetch');
  let vulnerable = true;
  const server = http.createServer(async (request, response) => {
    if (request.method !== 'POST' || request.url !== route) {
      response.writeHead(404); response.end(); return;
    }
    const chunks = [];
    for await (const chunk of request) chunks.push(chunk);
    const destination = JSON.parse(Buffer.concat(chunks).toString()).destination;
    if (vulnerable && /^http:\/\/127\.0\.0\.1:\d+\/bx-ssrf\/[0-9a-f]{24}$/.test(destination))
      http.get(destination, fetched => fetched.resume()).on('error', () => {});
    response.writeHead(200, {'content-type': 'application/json', 'cache-control': 'no-store'});
    response.end(JSON.stringify({queued: true, echo: destination}));
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  t.after(() => new Promise(resolve => server.close(resolve)));
  const origin = `http://127.0.0.1:${server.address().port}`;
  const scopePath = path.join(dir, 'scope.json');
  fs.writeFileSync(scopePath, JSON.stringify({schemaVersion: 1,
    target: {origin}, include: ['/'], probes: {jsonPostPaths: [route]},
    limits: {rps: 50}}));
  const scope = structuredClone(loadScope({file: scopePath, origin}).scope);
  scope.localAutoPostContracts = {[`json ${route}`]:
    {contentType: 'application/json', fields: ['destination']}};
  const surface = {patterns: [{pattern: route, methods: ['POST']}],
    jsonBodyOperations: [{path: route, method: 'POST',
      contentType: 'application/json', fields: ['destination'],
      requiredFields: ['destination'], source: 'public-openapi'}]};
  const lead = {family: 'server-fetch', why: 'Observed URL field', priority: 8,
    as: 'anonymous', oracle: 'local-callback', prelude: [],
    subject: {method: 'POST', path: route, placement: 'json', key: 'destination',
      fixedFields: [], bodyTemplate: '', headers: []}, observe: [],
    controlValue: '', firstValue: '', secondValue: '', marker: '',
    secondMarker: '', assertion: {step: 'subject', index: 0,
      location: 'body', name: ''}};
  assert.equal(validateResearchFlow(lead, surface, scope).ok, true);
  const ledger = createLedger(dir);
  t.after(() => ledger.close());
  const requester = createRequester(scope, {ledger, allowLocal: true});
  const run = await runResearchFlows([lead], scope, {requester, surface,
    ledger, modelCallsAvailable: 0});
  assert.equal(run.results[0].verdict, 'confirmed');
  assert.equal(run.findings.length, 1);
  assert.equal(run.findings[0].kind, 'ssrf-loopback');
  assert.equal(run.investigations[0].attempts[0].controls.filter(item =>
    item.callback).length, 2);
  const proofLog = [];
  const proved = await proveFindings([{...run.findings[0], id: 'f-001'}], [],
    {runDir: dir, surface, scope, env: {}, ledger, web: run,
      log: item => proofLog.push(item)});
  assert.equal(proved.length, 1, JSON.stringify(proofLog));
  vulnerable = false;
  const fixed = await execFile(process.execPath, [proved[0].proof, '--expect-fixed'],
    {env: process.env, timeout: 20000});
  assert.equal(fixed.code, 0, fixed.stdout);
});

test('a large route inventory leaves Muse calls for first-page result feedback', async () => {
  const origin = 'http://127.0.0.1:4337';
  const scope = loadScope({origin, overrides: {acceptLocal: true}}).scope;
  const surface = {patterns: Array.from({length: 80}, (_, index) => ({
    pattern: `/r${index}`, methods: ['GET'], params: {q: ['plain']}}))};
  let pages = 0, feedbackAllowance = 0;
  const planned = await planResearchFlows(surface, scope, {model: 'fixture',
    budget: 2, modelCallsAvailable: 4,
    infer: async (_model, messages) => {
      pages++;
      const context = JSON.parse(messages[1].content);
      return {flows: pages === 1 ? [{family: 'response-check', why: 'Observed query input',
        priority: 5, as: 'anonymous', oracle: 'observation', protectedPath: '',
        prelude: [], subject: {method: 'GET', path: '/r0', placement: 'query',
          key: 'q', fixedFields: [], bodyTemplate: '', headers: []},
        observe: [], binding: null, controlValue: 'plain', firstValue: 'one',
        secondValue: 'two', marker: '', secondMarker: '',
        assertion: {step: 'subject', index: 0, location: 'body', name: ''}}] : []};
    }, onAcceptedPage: async (leads, page) => {
      assert.equal(leads.length, 1);
      feedbackAllowance = page.modelCallsAvailable;
      return {modelCalls: 1, results: [{proposalId: leads[0].proposalId,
        lead: {path: '/r0', method: 'GET', parameter: 'q',
          family: 'response-check'}, verdict: 'inconclusive',
        reason: 'sampled response', evidence: []}]};
    }});
  assert.ok(feedbackAllowance >= 1, 'the accepted response needs a Muse feedback call');
  assert.ok(pages >= 2, 'a later route page must still be reviewed');
  assert.ok(planned.modelCalls + planned.pageExecutionCalls <= 4);
});

test('a later Muse route page receives the prior page HTTP outcome before planning', async t => {
  const requested = [];
  const server = http.createServer((request, response) => {
    const url = new URL(request.url, 'http://fixture');
    requested.push(`${request.method} ${url.pathname}${url.search}`);
    const value = url.searchParams.get('probe');
    const status = value === 'first' ? 202 : value === 'second' ? 201 : 200;
    response.writeHead(status, {'content-type': 'application/json',
      'cache-control': 'no-store'});
    response.end(JSON.stringify({accepted: status === 202}));
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  t.after(() => new Promise(resolve => server.close(resolve)));
  const origin = `http://127.0.0.1:${server.address().port}`;
  const scope = loadScope({origin, overrides: {acceptLocal: true}}).scope;
  const paths = Array.from({length: 9}, (_, index) => `/r${index}`);
  const surface = {patterns: paths.map(pattern => ({pattern, methods: ['GET'],
    params: {probe: ['control']}, responseFacts: {status: 200}}))};
  let evidence = 0, pages = 0;
  const requester = async ({url, method = 'GET', headers = {}}) => {
    const response = await fetch(new URL(url, origin), {method, headers});
    return {status: response.status, type: response.headers.get('content-type'),
      body: await response.text(), headers: Object.fromEntries(response.headers),
      evidenceId: `ev-${String(++evidence).padStart(4, '0')}`};
  };
  const flow = (path, context) => ({family: 'route-feedback', why: 'Compare a bounded response',
    priority: 8, as: 'anonymous', oracle: 'observation', protectedPath: '',
    prelude: [], subject: {method: 'GET', path, placement: 'query', key: 'probe',
      fixedFields: [], bodyTemplate: '', headers: []}, observe: [], binding: null,
    controlValue: 'control', firstValue: 'first', secondValue: 'second',
    marker: context.marker, secondMarker: context.secondMarker,
    assertion: {step: 'subject', index: 0, location: 'body', name: ''}});
  const planned = await planResearchFlows(surface, scope, {model: 'fixture',
    budget: 4, modelCallsAvailable: 4, requester,
    infer: async (_model, messages) => {
      const context = JSON.parse(messages[1].content);
      pages++;
      if (pages === 2) assert.ok(context.priorSequenceResults?.some(item =>
        item.path === '/r0' && item.verdict === 'inconclusive' &&
        item.reason.includes('stable response difference') &&
        item.responseSignals.map(signal => signal.status).join(',') === '200,202,201'),
      'the first page result must reach Muse before the second page is planned');
      return {flows: [flow(pages === 1 ? '/r0' : '/r8', context)]};
    },
    onAcceptedPage: async leads => runResearchFlows(leads, scope, {
      requester, surface, modelCallsAvailable: 0})});
  assert.equal(pages, 2);
  assert.equal(planned.leads.length, 2);
  assert.equal(planned.pageRuns.length, 2);
  assert.equal(planned.pageRuns.flatMap(run => run.results).length, 2);
  assert.equal(requested.filter(item => item.startsWith('GET /r0?')).length, 6);
  assert.equal(requested.filter(item => item.startsWith('GET /r8?')).length, 6);
});

test('same-route hypotheses keep their own response signals on the next Muse page', async () => {
  const scope = loadScope({origin: 'http://127.0.0.1:4338',
    overrides: {acceptLocal: true}}).scope;
  const surface = {patterns: Array.from({length: 9}, (_, index) =>
    ({pattern: `/r${index}`, methods: ['GET'], params: {q: ['plain']}}))};
  const flow = (family, value) => ({family, why: 'Observe the scoped input',
    priority: 5, as: 'anonymous', oracle: 'observation', protectedPath: '',
    prelude: [], subject: {method: 'GET', path: '/r0', placement: 'query',
      key: 'q', fixedFields: [], bodyTemplate: '', headers: []},
    observe: [], binding: null, controlValue: 'plain', firstValue: value,
    secondValue: `${value}-other`, marker: '', secondMarker: '',
    assertion: {step: 'subject', index: 0, location: 'body', name: ''}});
  let pages = 0;
  const planned = await planResearchFlows(surface, scope, {model: 'fixture',
    budget: 3, modelCallsAvailable: 2,
    infer: async (_model, messages) => {
      const context = JSON.parse(messages[1].content);
      pages++;
      if (pages === 2) {
        const prior = context.priorSequenceResults;
        assert.equal(prior.find(item => item.family === 'alpha-hypothesis')
          ?.responseSignals[0]?.status, 201);
        assert.equal(prior.find(item => item.family === 'beta-hypothesis')
          ?.responseSignals[0]?.status, 202);
      }
      return {flows: pages === 1 ? [flow('alpha-hypothesis', 'alpha'),
        flow('beta-hypothesis', 'beta')] : []};
    }, onAcceptedPage: async leads => ({results: leads.map(lead => ({
      proposalId: lead.proposalId,
      lead: {path: lead.subject.path, parameter: lead.subject.key,
        family: lead.family, method: lead.subject.method},
      verdict: 'inconclusive', reason: 'observed', evidence: []})),
    investigations: [...leads].reverse().map(lead => ({
      proposalId: lead.proposalId,
      final: {path: lead.subject.path, field: lead.subject.key,
        family: lead.family},
      attempts: [{responses: [{subject: {status: lead.family ===
        'alpha-hypothesis' ? 201 : 202}}]}]}))})});
  assert.equal(pages, 2);
  assert.equal(planned.leads.length, 2);
});

test('an accepted HTTP page remains explicitly untested if its runner fails', async () => {
  const origin = 'http://127.0.0.1:4339';
  const scope = loadScope({origin, overrides: {acceptLocal: true}}).scope;
  const surface = {patterns: [{pattern: '/check', methods: ['GET'],
    params: {q: ['plain']}}]};
  let remaining = 1;
  const planned = await planResearchFlows(surface, scope, {model: 'fixture',
    budget: 1, modelCallsAvailable: 1,
    remainingModelCalls: () => remaining,
    infer: async (_model, messages) => {
      const context = JSON.parse(messages[1].content);
      return {flows: [{family: 'check', why: 'Observe a scoped response',
        priority: 5, as: 'anonymous', oracle: 'observation', protectedPath: '',
        prelude: [], subject: {method: 'GET', path: '/check', placement: 'query',
          key: 'q', fixedFields: [], bodyTemplate: '', headers: []}, observe: [],
        binding: null, controlValue: 'plain', firstValue: 'first',
        secondValue: 'second', marker: context.marker,
        secondMarker: context.secondMarker,
        assertion: {step: 'subject', index: 0, location: 'body', name: ''}}]};
    }, onAcceptedPage: async () => {
      remaining--;
      throw Error('fixture runner failed');
    }});
  assert.equal(planned.leads.length, 1);
  assert.equal(planned.pageRuns.length, 1);
  assert.equal(planned.pageRuns[0].results[0].verdict, 'untested');
  assert.equal(planned.pageRuns[0].results[0].reason, 'page-execution-error');
  assert.equal(planned.pageRuns[0].deferredLeads.length, 1);
  assert.equal(planned.pageExecutionCalls, 1);
});

test('authorized deployed scope admits an observed POST body, while GET-only authorization does not', async t => {
  const origin = 'https://app.example.test';
  const route = randomPath('calculate');
  const expiresAt = new Date(Date.now() + 86400000).toISOString();
  const target = {url: origin, environment: 'staging',
    ownership: {status: 'verified', method: 'dns', expiresAt},
    authorization: {origin, paths: ['/api'], methods: ['GET', 'HEAD', 'POST'],
      maxRequestsPerSecond: 2, expiresAt}};
  const readOnlyTarget = structuredClone(target);
  readOnlyTarget.authorization.methods = ['GET', 'HEAD'];
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'bypass-remote-post-'));
  t.after(() => fs.rmSync(dir, {recursive: true, force: true}));
  const file = path.join(dir, 'scope.json');
  fs.writeFileSync(file, JSON.stringify({schemaVersion: 1, target: {origin},
    include: ['/api'], limits: {rps: 2}}));
  const mined = {endpoints: [{method: 'POST', path: route, bodyEncoding: 'json',
    bodyFields: ['expression'], fieldExamples: {expression: ['2+3']}}]};
  const requester = async () => ({status: 404, body: ''});
  const scope = loadScope({file, origin, targets: [target]}).scope;
  const prepared = await deriveLocalPostScope(scope, mined, requester);
  assert.deepEqual(prepared.admitted.map(item => item.path), [route]);
  assert.equal(validateUrl(prepared.scope, route,
    {method: 'POST', purpose: 'json-body', identity: 'anonymous'}).ok, true);
  const surface = await anonymousSurface(prepared.scope, requester, mined);
  assert.deepEqual(surface.jsonBodyOperations.map(item => item.path), [route]);
  const readOnlyFile = path.join(dir, 'read-only-scope.json');
  fs.writeFileSync(readOnlyFile, JSON.stringify({schemaVersion: 1, target: {origin},
    include: ['/api'], methods: ['GET', 'HEAD'], limits: {rps: 2}}));
  const readOnly = loadScope({file: readOnlyFile, origin,
    targets: [readOnlyTarget]}).scope;
  const refused = await deriveLocalPostScope(readOnly, mined, requester);
  assert.equal(refused.admitted.length, 0);
  assert.ok(refused.skipped.some(item => item.path === route &&
    item.reason === 'post-not-authorized'));
  assert.equal(validateUrl(readOnly, route,
    {method: 'POST', purpose: 'json-body', identity: 'anonymous'}).reason, 'method');
});

test('an observed reset-password path is visible and a bounded POST honors an explicit exclusion', async () => {
  const origin = 'http://127.0.0.1:4329';
  const route = `${randomPath('account')}/reset-password`;
  const scope = loadScope({origin, overrides: {acceptLocal: true}}).scope;
  const mined = {endpoints: [{method: 'POST', path: route, bodyEncoding: 'json',
    bodyFields: ['email']}]};
  const requester = async () => ({status: 404, body: ''});
  assert.equal(validateUrl(scope, route, {method: 'GET'}).ok, true);

  const prepared = await deriveLocalPostScope(scope, mined, requester);
  assert.deepEqual(prepared.admitted.map(item => item.path), [route]);
  assert.equal(validateUrl(prepared.scope, route,
    {method: 'POST', purpose: 'json-body', identity: 'anonymous'}).ok, true);

  const excluded = structuredClone(scope);
  excluded.never.push(route);
  const refused = await deriveLocalPostScope(excluded, mined, requester);
  assert.equal(refused.admitted.length, 0);
  assert.ok(refused.skipped.some(item => item.path === route &&
    item.reason === 'outside-scope-or-never'));

  const excludedByVerb = structuredClone(scope);
  excludedByVerb.never.push('reset');
  const verbRefused = await deriveLocalPostScope(excludedByVerb, mined, requester);
  assert.equal(verbRefused.admitted.length, 0);
  assert.ok(verbRefused.skipped.some(item => item.path === route &&
    item.reason === 'outside-scope-or-never'));

  const outside = structuredClone(scope);
  outside.include = ['/other'];
  const outOfScope = await deriveLocalPostScope(outside, mined, requester);
  assert.equal(outOfScope.admitted.length, 0);
  assert.ok(outOfScope.skipped.some(item => item.path === route &&
    item.reason === 'outside-scope-or-never'));
});

test('an observed POST uses selected method scope without an extra path review', async () => {
  const origin = 'http://127.0.0.1:4329';
  const route = `${randomPath('delete')}/delete`;
  const scope = loadScope({origin, overrides: {acceptLocal: true}}).scope;
  const mined = {endpoints: [{method: 'POST', path: route, bodyEncoding: 'json',
    bodyFields: ['recordId']}]};
  const requester = async () => ({status: 404, body: ''});
  const prepared = await deriveLocalPostScope(scope, mined, requester);
  assert.deepEqual(prepared.admitted.map(item => item.path), [route]);
  assert.equal(validateUrl(prepared.scope, route,
    {method: 'POST', purpose: 'json-body'}).ok, true);
});

test('observed local JS JSON POST runs with known fields while an excluded decoy stays blocked', async t => {
  const reviewed = randomPath('calculate'), decoy = randomPath('decoy');
  const hits = [];
  const server = http.createServer((request, response) => {
    hits.push(`${request.method} ${request.url}`);
    if (request.url === '/') {
      response.writeHead(200, {'content-type': 'text/html'});
      response.end('<script src="/app.js"></script>');
    } else if (request.url === '/app.js') {
      response.writeHead(200, {'content-type': 'application/javascript'});
      response.end(`client.post("${reviewed}",{expression:"sample",optional:other});` +
        `client.post("${decoy}",{expression:"sample"});`);
    } else {
      response.writeHead(404, {'content-type': 'text/plain'});
      response.end('missing');
    }
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  t.after(() => new Promise(resolve => server.close(resolve)));
  const origin = `http://127.0.0.1:${server.address().port}`;
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'bypass-js-post-'));
  t.after(() => fs.rmSync(dir, {recursive: true, force: true}));
  const scopePath = path.join(dir, 'scope.json');
  fs.writeFileSync(scopePath, JSON.stringify({schemaVersion: 1, target: {origin},
    include: ['/'], never: [decoy]}));
  const scope = loadScope({file: scopePath, origin}).scope;
  const requester = async ({url}) => {
    const response = await fetch(new URL(url, origin));
    return {status: response.status, type: response.headers.get('content-type'),
      body: await response.text(), evidenceId: 'fixture'};
  };
  const mined = await mineOrigin(origin, {requester});
  const prepared = await deriveLocalPostScope(scope, mined, requester);
  assert.deepEqual(prepared.admitted.map(item => item.path), [reviewed]);
  assert.ok(prepared.skipped.some(item => item.path === decoy));
  const surface = await anonymousSurface(prepared.scope, requester, mined);
  const inventory = researchFlowInventory(surface, prepared.scope);
  assert.deepEqual(inventory.posts.get(`json ${reviewed}`)?.fields, ['expression', 'optional']);
  assert.deepEqual(inventory.posts.get(`json ${reviewed}`)?.fieldExamples.expression, ['sample']);
  assert.equal(inventory.posts.has(`json ${decoy}`), false);
  assert.equal(surface.jsonBodyOperations.some(item => item.path === decoy), false);
  assert.equal(validateUrl(prepared.scope, decoy,
    {identity: 'anonymous', method: 'POST', purpose: 'json-body'}).ok, false);
  const ledger = createLedger(dir);
  t.after(() => ledger.close());
  const guarded = createRequester(prepared.scope, {ledger, allowLocal: true});
  const sent = await guarded({url: reviewed, method: 'POST', purpose: 'json-body',
    identity: 'anonymous', step: 'task', noCache: true,
    headers: {'content-type': 'application/json'}, body: JSON.stringify({expression: 'sample'})});
  assert.equal(sent.status, 404);
  const blocked = await guarded({url: decoy, method: 'POST', purpose: 'json-body',
    identity: 'anonymous', step: 'task', noCache: true,
    headers: {'content-type': 'application/json'}, body: JSON.stringify({expression: 'sample'})});
  assert.equal(blocked.refused, true);
  const unobservedBody = await guarded({url: reviewed, method: 'POST', purpose: 'json-body',
    identity: 'anonymous', step: 'task', noCache: true,
    headers: {'content-type': 'application/json'}, body: JSON.stringify({unseen: 'sample'})});
  assert.equal(unobservedBody.status, 404);
  assert.deepEqual(hits.filter(item => item.startsWith('POST ')),
    [`POST ${reviewed}`, `POST ${reviewed}`]);
});

test('local auth-body uses an inferred credential contract and keeps returned token out of evidence', async t => {
  const route = randomPath('session');
  const token = `fixture-token-${randomBytes(12).toString('hex')}`;
  const server = http.createServer(async (request, response) => {
    if (request.url === '/') {
      response.writeHead(200, {'content-type': 'text/html'});
      response.end('<script src="/app.js"></script>');
    } else if (request.url === '/app.js') {
      response.writeHead(200, {'content-type': 'application/javascript'});
      response.end(`class AuthClient {hostServer=config.hostServer;login(value){return this.http.post(\`${'${'}this.hostServer}${route}\`,value)}}` +
        'view.login({username:form.user,password:form.pass});');
    } else if (request.method === 'POST' && request.url === route) {
      const chunks = [];
      for await (const chunk of request) chunks.push(chunk);
      const body = JSON.parse(Buffer.concat(chunks).toString());
      response.writeHead(200, {'content-type': 'application/json', 'x-test-token': token});
      response.end(JSON.stringify({token, username: body.username}));
    } else {response.writeHead(404); response.end();}
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  t.after(() => new Promise(resolve => server.close(resolve)));
  const origin = `http://127.0.0.1:${server.address().port}`;
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'bypass-auth-body-'));
  t.after(() => fs.rmSync(dir, {recursive: true, force: true}));
  const file = path.join(dir, 'scope.json');
  fs.writeFileSync(file, JSON.stringify({schemaVersion: 1, target: {origin}, include: ['/']}));
  const scope = loadScope({file, origin}).scope;
  const fetcher = async ({url}) => {
    const result = await fetch(new URL(url, origin));
    return {status: result.status, type: result.headers.get('content-type'),
      body: await result.text(), evidenceId: 'fixture'};
  };
  const mined = await mineOrigin(origin, {requester: fetcher});
  const prepared = await deriveLocalPostScope(scope, mined, fetcher);
  const surface = await anonymousSurface(prepared.scope, fetcher, mined);
  assert.deepEqual(surface.authBodyOperations.map(item =>
    [item.path, item.usernameField, item.passwordField]), [[route, 'username', 'password']]);
  const ledger = createLedger(dir);
  t.after(() => ledger.close());
  const guarded = createRequester(prepared.scope, {ledger, allowLocal: true});
  const result = await guarded({url: route, method: 'POST', purpose: 'auth-body',
    identity: 'anonymous', step: 'task', noCache: true, omitExcerpt: true,
    rawForAuthProof: true, headers: {'content-type': 'application/json'},
    body: JSON.stringify({username: 'unknown.invalid', password: 'invalid-password-123'})});
  assert.equal(result.status, 200);
  assert.equal(result.body, '');
  assert.match(result.rawBody, /fixture-token-/);
  assert.equal(JSON.stringify(result.headers), '{}');
  assert.ok(!fs.readFileSync(ledger.file, 'utf8').includes(token));
});

test('registration POST bodies are not classified as login contracts', async () => {
  const origin = 'http://127.0.0.1:4329';
  const scope = loadScope({origin, overrides: {acceptLocal: true}}).scope;
  const body = (path, fields, purpose = '') => ({method: 'POST', path,
    bodyEncoding: 'json', bodyFields: fields, purpose});
  const mined = {endpoints: [
    body('/api/Users', ['email', 'password', 'passwordRepeat']),
    body('/api/accounts', ['email', 'password']),
    body('/api/signup', ['email', 'password']),
    body('/api/profiles', ['email', 'password'], 'Create an account'),
    body('/rest/user/login', ['email', 'password']),
    body('/api/users/login', ['username', 'password'])]};
  const prepared = await deriveLocalPostScope(scope, mined,
    async () => ({status: 404, body: ''}));
  assert.deepEqual(prepared.authAdmitted.map(item => item.path).sort(),
    ['/api/users/login', '/rest/user/login']);
  assert.deepEqual(prepared.admitted.map(item => item.path).sort(),
    ['/api/Users', '/api/accounts', '/api/profiles', '/api/signup']);
});

test('Muse may use globally observed reads and reviewed POSTs, but not an unsupplied route', async () => {
  const origin = 'http://127.0.0.1:4329';
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'bypass-flow-page-'));
  try {
    const file = path.join(dir, 'scope.json');
    fs.writeFileSync(file, JSON.stringify({schemaVersion: 1, target: {origin},
      probes: {formPostPaths: ['/api/form']}}));
    const scope = loadScope({file, origin}).scope;
    const surface = {patterns: Array.from({length: 21}, (_, index) => ({
      pattern: `/api/read-${index}`, methods: ['GET'], params: {value: []}})),
    formBodyOperations: [{path: '/api/form', method: 'POST',
      contentType: 'application/x-www-form-urlencoded', fields: ['value']}]};
    const ledger = createLedger(dir);
    const planned = await planResearchFlows(surface, scope, {model: 'fixture',
      budget: 2, modelCallsAvailable: 1, ledger, infer: async (_model, messages) => {
        const context = JSON.parse(messages[1].content);
        assert.equal(context.routes.some(item => item.path === '/api/read-20'), false);
        assert.equal(context.observedReadRoutes.some(item => item.path === '/api/read-20'), true);
        assert.deepEqual(context.observedReadRoutes.find(item =>
          item.path === '/api/read-20').fields, ['value']);
        const proposal = (path, method, placement) => ({family: 'response-transform',
          why: 'Probe an observed input', priority: 5, as: 'anonymous', prelude: [],
          subject: {method, path, placement, key: 'value', fixedFields: [],
            bodyTemplate: '', headers: []}, observe: [], controlValue: 'plain',
          firstValue: 'first', secondValue: 'second', marker: context.marker,
          secondMarker: context.secondMarker,
          assertion: {step: 'subject', index: 0, location: 'body', name: ''}});
        return {flows: [proposal('/api/unsupplied', 'GET', 'query'),
          proposal('/api/form', 'POST', 'form'),
          {...proposal('/api/read-20', 'GET', 'query'),
            oracle: 'xpath-result-difference'}]};
      }});
    assert.deepEqual(planned.decisions.map(item => [item.accepted, item.reason]),
      [[false, 'unobserved-read-route'], [true, undefined], [true, undefined]]);
    assert.deepEqual(planned.leads.map(item => item.subject.path), ['/api/form', '/api/read-20']);
    assert.equal(planned.leads[1].oracle, 'observation');
    assert.equal(planned.decisions[2].translatedTo, 'observation');
    assert.deepEqual(planned.coverage.rejectedByReason, {'unobserved-read-route': 1});
    ledger.close();
    assert.match(fs.readFileSync(ledger.file, 'utf8'),
      /"kind":"model-http-sequence-plan-summary".*"rejectedByReason":\{"unobserved-read-route":1\}/);
  } finally {fs.rmSync(dir, {recursive: true, force: true});}
});

test('an early pass retains valid HTTP plans beyond its small share for later execution', async () => {
  const origin = 'http://127.0.0.1:4329';
  const scope = loadScope({origin, overrides: {acceptLocal: true}}).scope;
  const surface = {patterns: ['/api/first', '/api/second'].map(pattern => ({
    pattern, methods: ['GET'], params: {q: []}}))};
  const planned = await planResearchFlows(surface, scope, {model: 'fixture',
    budget: 1, modelCallsAvailable: 1, deferOverflow: true,
    infer: async (_model, messages) => {
      const context = JSON.parse(messages[1].content);
      const flow = path => ({family: 'response-shape', why: 'Observed query route',
        priority: 5, as: 'anonymous', oracle: 'observation', prelude: [],
        subject: {method: 'GET', path, placement: 'query', key: 'q',
          fixedFields: [], bodyTemplate: '', headers: []}, observe: [], binding: null,
        controlValue: 'plain', firstValue: 'one', secondValue: 'two',
        marker: '', secondMarker: '',
        assertion: {step: 'subject', index: 0, location: 'body', name: ''}});
      assert.equal(context.routes.length, 2);
      return {flows: [flow('/api/first'), flow('/api/second')]};
    }});
  assert.deepEqual(planned.leads.map(item => item.subject.path), ['/api/first']);
  assert.deepEqual(planned.deferredLeads.map(item => item.subject.path), ['/api/second']);
  assert.equal(planned.coverage.deferred, 1);
  assert.equal(planned.coverage.proposalsRejected, 0);
  assert.equal(planned.decisions[1].deferred, true);
  assert.ok(!Object.keys(planned).includes('deferredLeads'),
    'submitted values must stay in the transient handoff, not the saved summary');
});

test('Muse repairs a rejected sequence shape and executes the observed route', async t => {
  const route = randomPath('compute');
  const server = http.createServer((request, response) => {
    const url = new URL(request.url, 'http://localhost');
    if (request.method !== 'GET' || url.pathname !== route) {
      response.writeHead(404); response.end(); return;
    }
    const value = url.searchParams.get('expression') ?? '';
    const codes = /^String\.fromCharCode\((\d+(?:,\d+)*)\)$/.exec(value)?.[1];
    const result = codes ? String.fromCharCode(...codes.split(',').map(Number)) : value;
    response.writeHead(200, {'content-type': 'application/json'});
    response.end(JSON.stringify({result}));
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  t.after(() => new Promise(resolve => server.close(resolve)));
  const origin = `http://127.0.0.1:${server.address().port}`;
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'bypass-flow-repair-'));
  t.after(() => fs.rmSync(dir, {recursive: true, force: true}));
  const file = path.join(dir, 'scope.json');
  fs.writeFileSync(file, JSON.stringify({schemaVersion: 1, target: {origin},
    include: ['/'], limits: {rps: 50}}));
  const scope = loadScope({file, origin}).scope;
  const surface = {patterns: [{pattern: route, methods: ['GET'],
    params: {expression: []}, source: ['public-openapi']}],
  focus: {findingId: 'benign-expression-fixture', path: route, method: 'GET',
    sourceSnapshotMatches: true, source: {file: 'src/expression.ts', line: 1,
      quote: 'String.fromCharCode(...codes)'}}};
  let calls = 0;
  const infer = async (_model, messages) => {
    calls++;
    const context = JSON.parse(messages[1].content);
    const marker = context.marker, secondMarker = context.secondMarker;
    const submitted = text => `String.fromCharCode(${[...text]
      .map(char => char.charCodeAt(0)).join(',')})`;
    const flow = {family: 'new-expression-hypothesis', why: 'Observed expression input',
      priority: 7, as: 'anonymous', prelude: [],
      subject: {method: 'GET', path: route, placement: 'query', key: 'expression',
        fixedFields: [], bodyTemplate: '', headers: []}, observe: [],
      controlValue: 'plain', firstValue: submitted(marker),
      secondValue: submitted(secondMarker), marker, secondMarker,
      assertion: {step: 'subject', index: 0, location: 'body', name: ''}};
    if (calls === 1) return {flows: [{...flow,
      assertion: {...flow.assertion, location: 'header', name: 'x-unobserved'}}]};
    assert.equal(context.rejected[0].reason, 'assertion');
    assert.equal(context.routes[0].path, route);
    return {flows: [flow]};
  };
  const planned = await planResearchFlows(surface, scope, {infer, model: 'fixture',
    budget: 1, modelCallsAvailable: 2});
  assert.equal(calls, 2);
  assert.equal(planned.coverage.repairCalls, 1);
  assert.equal(planned.coverage.repairAccepted, 1);
  assert.deepEqual(planned.decisions.map(item => [item.accepted, item.reason]),
    [[false, 'assertion'], [true, undefined]]);
  const ledger = createLedger(dir);
  t.after(() => ledger.close());
  const requester = createRequester(scope, {ledger, allowLocal: true});
  let revisionCalls = 0;
  const tested = await runResearchFlows(planned.leads, scope, {requester,
    surface, ledger, model: 'fixture', modelCallsAvailable: 1,
    infer: async () => {revisionCalls++; return {flows: []};}});
  assert.equal(revisionCalls, 1);
  assert.equal(tested.results[0].verdict, 'observed');
  assert.equal(tested.findings.some(item => item.verdict === 'confirmed'), false);
  assert.equal(tested.findings[0].severity, 'unrated');
  assert.equal(requester.stats.sent, 3);
});

test('Muse proposal repair stops when the same validation failure repeats', async () => {
  const origin = 'http://127.0.0.1:4329';
  const scope = loadScope({origin, overrides: {acceptLocal: true}}).scope;
  const surface = {patterns: [{pattern: '/api/example', methods: ['GET'],
    params: {value: []}}]};
  let calls = 0;
  const planned = await planResearchFlows(surface, scope, {model: 'fixture',
    budget: 1, modelCallsAvailable: 8, infer: async (_model, messages) => {
      calls++;
      const context = JSON.parse(messages[1].content);
      return {flows: [{family: 'new-hypothesis', why: 'Try observed input',
        priority: 5, as: 'anonymous', prelude: [],
        subject: {method: 'GET', path: '/api/example', placement: 'query',
          key: 'value', fixedFields: [], bodyTemplate: '', headers: []}, observe: [],
        controlValue: 'plain', firstValue: 'one', secondValue: 'two',
        marker: context.marker, secondMarker: context.secondMarker,
        assertion: {step: 'subject', index: 0, location: 'header', name: 'x-unobserved'}}]};
    }});
  assert.equal(calls, 2);
  assert.equal(planned.coverage.repairCalls, 1);
  assert.equal(planned.coverage.repairStalled, 1);
  assert.equal(planned.leads.length, 0);
});

test('Muse repairs a rejected revision and executes the corrected sequence', async () => {
  const origin = 'http://127.0.0.1:4329';
  const scope = loadScope({origin, overrides: {acceptLocal: true}}).scope;
  const route = randomPath('revision-repair');
  const surface = {patterns: [{pattern: route, methods: ['GET'], params: {q: ['plain']}}]};
  const lead = {family: 'reviewed-response', why: 'Compare an observed query input',
    priority: 5, as: 'anonymous', oracle: 'observation', prelude: [], observe: [],
    subject: {method: 'GET', path: route, placement: 'query', key: 'q',
      fixedFields: [], bodyTemplate: '', headers: []},
    controlValue: 'plain', firstValue: 'alpha', secondValue: 'beta',
    marker: '', secondMarker: '',
    assertion: {step: 'subject', index: 0, location: 'body', name: ''}};
  let calls = 0, sent = 0;
  const run = await runResearchFlows([lead], scope, {surface, model: 'fixture',
    modelCallsAvailable: 3,
    requester: async () => ({status: 200, type: 'application/json', body: '{"value":"fixed"}',
      headers: {'cache-control': 'no-store'}, evidenceId: `ev-${++sent}`}),
    infer: async (_model, messages) => {
      calls++;
      const context = JSON.parse(messages[1].content);
      if (calls === 1) return {flows: [{...lead, firstValue: 'gamma', secondValue: 'delta',
        assertion: {...lead.assertion, location: 'header', name: 'x-unobserved'}}]};
      if (calls === 2) {
        assert.equal(context.rejected.reason, 'assertion');
        assert.equal(context.rejected.requestShape[0].path, route);
        return {flows: [{...lead, firstValue: 'gamma', secondValue: 'delta'}]};
      }
      return {flows: []};
    }});
  assert.equal(calls, 3);
  assert.equal(sent, 12, 'only the initial and repaired sequences make HTTP requests');
  assert.deepEqual(run.decisions.map(item => [item.mode, item.accepted, item.reason]), [
    ['http-sequence-revision', false, 'assertion'],
    ['http-sequence-repair', true, undefined],
    ['http-sequence-revision', false, 'model-stopped']]);
  assert.equal(run.investigations[0].attempts.length, 2);
  assert.equal(run.investigations[0].stopReason, 'model-stopped');
});

test('Muse can execute a model-authored query value without a syntax veto',
  async () => {
    const origin = 'http://127.0.0.1:4329';
    const scope = loadScope({origin, overrides: {acceptLocal: true}}).scope;
    const route = randomPath('value-repair');
    const surface = {patterns: [{pattern: route, methods: ['GET'], params: {q: ['plain']}}]};
    const lead = {family: 'reviewed-response', why: 'Compare a documented query',
      priority: 5, as: 'anonymous', oracle: 'observation', prelude: [], observe: [],
      subject: {method: 'GET', path: route, placement: 'query', key: 'q',
        fixedFields: [], bodyTemplate: '', headers: []}, binding: null,
      controlValue: 'plain', firstValue: 'alpha', secondValue: 'beta',
      marker: '', secondMarker: '',
      assertion: {step: 'subject', index: 0, location: 'body', name: ''}};
    let calls = 0, sent = 0;
    const run = await runResearchFlows([lead], scope, {surface, model: 'fixture',
      modelCallsAvailable: 3,
      requester: async () => ({status: 200, type: 'application/json',
        body: '{"value":"fixed"}', headers: {'cache-control': 'no-store'},
        evidenceId: `ev-${++sent}`}),
      infer: async (_model, messages) => {
        calls++;
        const context = JSON.parse(messages[1].content);
        if (calls === 1) return {flows: [{...lead, oracle: 'marker',
          firstValue: 'bad\nvalue', secondValue: 'other',
          marker: context.marker, secondMarker: context.secondMarker}]};
        if (calls === 2) assert.equal(context.rejected, undefined);
        return {flows: []};
      }});
    assert.equal(calls, 2);
    assert.equal(sent, 9);
    assert.deepEqual(run.decisions.map(item => [item.accepted, item.reason]), [
      [true, undefined], [false, 'model-stopped']]);
    assert.doesNotMatch(JSON.stringify(run.decisions), /bad\\nvalue/);
  });

test('revision repair stops after Muse repeats the same invalid proposal', async () => {
  const origin = 'http://127.0.0.1:4329';
  const scope = loadScope({origin, overrides: {acceptLocal: true}}).scope;
  const route = randomPath('revision-stall');
  const surface = {patterns: [{pattern: route, methods: ['GET'], params: {q: ['plain']}}]};
  const lead = {family: 'reviewed-response', why: 'Compare an observed query input',
    priority: 5, as: 'anonymous', oracle: 'observation', prelude: [], observe: [],
    subject: {method: 'GET', path: route, placement: 'query', key: 'q',
      fixedFields: [], bodyTemplate: '', headers: []},
    controlValue: 'plain', firstValue: 'alpha', secondValue: 'beta',
    marker: '', secondMarker: '',
    assertion: {step: 'subject', index: 0, location: 'body', name: ''}};
  let calls = 0, sent = 0;
  const run = await runResearchFlows([lead], scope, {surface, model: 'fixture',
    modelCallsAvailable: 10,
    requester: async () => ({status: 200, type: 'application/json', body: '{"value":"fixed"}',
      headers: {'cache-control': 'no-store'}, evidenceId: `ev-${++sent}`}),
    infer: async () => {
      calls++;
      return {flows: [{...lead, assertion: {...lead.assertion,
        location: 'header', name: 'x-unobserved'}}]};
    }});
  assert.equal(calls, 2);
  assert.equal(sent, 6);
  assert.equal(run.investigations[0].stopReason, 'repeated-invalid-revision');
  assert.deepEqual(run.decisions.map(item => item.reason), ['assertion', 'assertion']);
});

test('a timed-out Muse sequence page retries once with smaller observed context and records the cut', async () => {
  const origin = 'http://127.0.0.1:4329';
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'bypass-flow-timeout-'));
  try {
    const file = path.join(dir, 'scope.json');
    fs.writeFileSync(file, JSON.stringify({schemaVersion: 1, target: {origin}, include: ['/']}));
    const scope = loadScope({file, origin}).scope;
    const surface = {patterns: Array.from({length: 25}, (_, index) => ({
      pattern: `/api/read-${index}`, methods: ['GET'], params: {value: []}}))};
    const ledger = createLedger(dir);
    const sizes = [];
    const planned = await planResearchFlows(surface, scope, {model: 'fixture',
      budget: 1, modelCallsAvailable: 2, ledger, infer: async (_model, messages) => {
        sizes.push(JSON.parse(messages[1].content).observedReadRoutes.length);
        if (sizes.length === 1) throw Error('Model did not finish within 60 seconds.');
        return {flows: []};
      }});
    ledger.close();
    assert.deepEqual(sizes, [25, 16]);
    assert.equal(planned.modelCalls, 2);
    assert.equal(planned.coverage.sent, 8);
    assert.equal(planned.coverage.timeoutRetries, 1);
    assert.equal(planned.coverage.timeoutRecovered, 1);
    assert.equal(planned.coverage.retryReadRoutesCut, 9);
    assert.equal(planned.modelError, null);
    assert.match(fs.readFileSync(ledger.file, 'utf8'), /model-http-sequence-timeout-retry/);
    let cappedCalls = 0;
    const capped = await planResearchFlows(surface, scope, {model: 'fixture',
      budget: 1, modelCallsAvailable: 1, infer: async () => {
        cappedCalls++;
        throw Error('Model did not finish within 60 seconds.');
      }});
    assert.equal(cappedCalls, 1);
    assert.equal(capped.coverage.timeoutRetries, 0);
    assert.match(capped.modelError, /did not finish within/);
  } finally {fs.rmSync(dir, {recursive: true, force: true});}
});

test('HTTP sequence route pages record the unsent tail when only seven model calls remain', async () => {
  const origin = 'http://127.0.0.1:4329';
  const {scope} = loadScope({origin, overrides: {acceptLocal: true}});
  const surface = {patterns: Array.from({length: 132}, (_, index) => ({
    pattern: `/api/read-${index}`, methods: ['GET'], params: {value: []}}))};
  const seen = new Set();
  const planned = await planResearchFlows(surface, scope, {model: 'fixture',
    budget: 1, modelCallsAvailable: 7, infer: async (_model, messages) => {
      const context = JSON.parse(messages[1].content);
      context.routes.forEach(item => seen.add(item.path));
      assert.ok(Buffer.byteLength(messages[1].content) <= 20000);
      return {flows: []};
    }});
  assert.equal(planned.modelCalls, 7);
  assert.equal(planned.coverage.sent, 56);
  assert.equal(planned.coverage.nextRouteOffset, 56);
  assert.equal(seen.size, 56);
  assert.equal(planned.coverage.observedReadsSent, 132);
});

test('every observed route can receive one Muse HTTP experiment across three bounded pages', async () => {
  const origin = 'http://127.0.0.1:4329';
  const {scope} = loadScope({origin, overrides: {acceptLocal: true}});
  const surface = {patterns: Array.from({length: 20}, (_, index) => ({
    pattern: `/api/possible-${index}`, methods: ['GET'], params: {value: []}}))};
  const pages = [];
  const planned = await planResearchFlows(surface, scope, {model: 'fixture',
    budget: 20, modelCallsAvailable: 3, infer: async (_model, messages) => {
      const context = JSON.parse(messages[1].content);
      pages.push(context.routes.map(item => item.path));
      return {flows: context.routes.map(route => ({family: 'response-observation',
        why: 'Observed query input permits a bounded comparison', priority: 5,
        as: 'anonymous', oracle: 'observation', prelude: [],
        subject: {method: 'GET', path: route.path, placement: 'query', key: 'value',
          fixedFields: [], bodyTemplate: '', headers: []}, observe: [],
        controlValue: 'plain', firstValue: 'alpha', secondValue: 'beta',
        marker: '', secondMarker: '',
        assertion: {step: 'subject', index: 0, location: 'body', name: ''}}))};
    }});
  assert.deepEqual(pages.map(page => page.length), [8, 8, 4]);
  assert.equal(planned.modelCalls, 3);
  assert.equal(planned.coverage.available, 20);
  assert.equal(planned.coverage.sent, 20);
  assert.equal(planned.coverage.accepted, 20);
  assert.equal(planned.coverage.proposalsRejected, 0);
  assert.equal(planned.leads.length, 20);
  assert.equal(new Set(planned.leads.map(item => item.subject.path)).size, 20);
});

test('reviewed POST and PATCH reach the first Muse route page when one model call remains', async () => {
  const origin = 'http://127.0.0.1:4329';
  const route = randomPath('reviewed-post');
  const patchRoute = randomPath('reviewed-patch');
  const scope = structuredClone(loadScope({origin, overrides: {acceptLocal: true}}).scope);
  scope.probes.jsonPostPaths.push(route);
  scope.probes.writeOperations.push({method: 'PATCH', path: patchRoute, placement: 'json'});
  const surface = {patterns: Array.from({length: 70}, (_, index) => ({
    pattern: `/api/read-${index}`, methods: ['GET'], params: {value: []}})),
  jsonBodyOperations: [{path: route, method: 'POST', contentType: 'application/json',
    fields: ['expression'], requiredFields: [], source: 'public-js'}],
  methodOperations: [{path: patchRoute, method: 'PATCH', placement: 'json',
    contentType: 'application/json', fields: ['expression'], requiredFields: [],
    source: 'openapi'}]};
  assert.equal(researchFlowInventory(surface, scope).posts.size, 1);
  let firstPage = null;
  const planned = await planResearchFlows(surface, scope, {model: 'fixture',
    budget: 2, modelCallsAvailable: 1, infer: async (_model, messages) => {
      firstPage = JSON.parse(messages[1].content).routes;
      return {flows: []};
    }});
  assert.equal(planned.modelCalls, 1);
  assert.ok(firstPage.some(item => item.kind === 'json' && item.path === route),
    'the reviewed POST contract must be visible while Muse still has a call');
  assert.ok(firstPage.some(item => item.kind === 'json' && item.path === patchRoute &&
    item.methods.includes('PATCH')),
  'the reviewed PATCH contract must be visible while Muse still has a call');
});

test('observed API methods preserve exact method, placement and content type in research execution', async () => {
  const origin = 'http://127.0.0.1:4329';
  const scope = structuredClone(loadScope({origin, overrides: {acceptLocal: true}}).scope);
  scope.methods.push('PUT');
  const operations = [
    {method: 'PUT', path: '/api/update', placement: 'json', contentType: 'application/json',
      fields: ['expression'], requiredFields: []},
    {method: 'PATCH', path: '/api/patch', placement: 'form',
      contentType: 'application/x-www-form-urlencoded', fields: ['name'], requiredFields: []},
    {method: 'DELETE', path: '/api/delete', placement: 'query', contentType: '',
      fields: ['id'], requiredFields: []},
  ];
  scope.probes.writeOperations.push(...operations.map(({method, path, placement}) =>
    ({method, path, placement})));
  const surface = {patterns: [], methodOperations: operations};
  const inventory = researchFlowInventory(surface, scope);
  assert.equal(inventory.writeOperations.size, 3);
  for (const operation of operations) {
    const spec = {family: 'method-aware-observation', why: 'Observed API contract',
      priority: 8, as: 'anonymous', oracle: 'observation', prelude: [], observe: [],
      subject: {method: operation.method, path: operation.path,
        placement: operation.placement, key: operation.fields[0],
        fixedFields: [], bodyTemplate: '', headers: []},
      controlValue: 'plain', firstValue: 'first', secondValue: 'second',
      marker: '', secondMarker: '',
      assertion: {step: 'subject', index: 0, location: 'body', name: ''}};
    const checked = validateResearchFlow(spec, surface, scope, {inventory});
    assert.equal(checked.ok, true, `${operation.method}: ${checked.reason}`);
    if (operation.placement === 'json') {
      const withUnusedTemplate = validateResearchFlow({...spec, subject: {...spec.subject,
        bodyTemplate: '{"expression":"{{input}}"}'}}, surface, scope, {inventory});
      assert.equal(withUnusedTemplate.ok, true);
      assert.equal(withUnusedTemplate.lead.subject.bodyTemplate,
        '{"expression":"{{input}}"}');
      const templatedRequests = [];
      await executeResearchFlow(withUnusedTemplate.lead, async request => {
        templatedRequests.push(request);
        return {status: 200, type: 'application/json', body: '{"ok":true}',
          headers: {}, cached: false, evidenceId: `template-${templatedRequests.length}`};
      });
      assert.ok(templatedRequests.some(request => request.body ===
        '{"expression":"plain"}' && request.rawModelRequest === true));
    }
    const requests = [];
    await executeResearchFlow(checked.lead, async request => {
      requests.push(request);
      return {status: 200, type: 'application/json', body: '{"ok":true}',
        headers: {}, cached: false, evidenceId: `ev-${requests.length}`};
    });
    assert.equal(requests.length, 6);
    assert.ok(requests.every(request => request.method === operation.method));
    if (operation.placement === 'query')
      assert.ok(requests.every(request => request.body === undefined &&
        request.purpose === 'reviewed-method'));
    else assert.ok(requests.every(request => request.headers['content-type'] ===
      operation.contentType && request.body));
  }
  const sequence = {family: 'method-workflow-observation', why: 'Observed method workflow',
    priority: 8, as: 'anonymous', oracle: 'observation',
    prelude: [{method: 'DELETE', path: '/api/delete', placement: 'query',
      key: 'id', value: 'plain', fixedFields: [], bodyTemplate: '', headers: []}],
    subject: {method: 'PUT', path: '/api/update', placement: 'json',
      key: 'expression', fixedFields: [], bodyTemplate: '', headers: []},
    observe: [{method: 'PATCH', path: '/api/patch', placement: 'form',
      key: 'name', value: 'plain', fixedFields: [], bodyTemplate: '', headers: []}],
    controlValue: 'plain', firstValue: 'first', secondValue: 'second',
    marker: '', secondMarker: '',
    assertion: {step: 'subject', index: 0, location: 'body', name: ''}};
  const checked = validateResearchFlow(sequence, surface, scope, {inventory});
  assert.equal(checked.ok, true, checked.reason);
  const requests = [];
  await executeResearchFlow(checked.lead, async request => {
    requests.push(request);
    return {status: 200, type: 'application/json', body: '{"ok":true}',
      headers: {}, cached: false, evidenceId: `ev-${requests.length}`};
  });
  assert.ok(requests.length >= 9);
  for (let index = 0; index < requests.length; index += 3)
    assert.deepEqual(requests.slice(index, index + 3).map(request => request.method),
      ['DELETE', 'PUT', 'PATCH']);
});

test('Muse GET plans keep observed companion query inputs through execution', async () => {
  const origin = 'http://127.0.0.1:4329';
  const scope = loadScope({origin, overrides: {acceptLocal: true}}).scope;
  const surface = {patterns: [{pattern: '/api/search', methods: ['GET'],
    params: {term: ['plain'], category: ['fruit']}}]};
  const proposal = {family: 'observed-search-flow', why: 'Compare an observed filter',
    priority: 6, as: 'anonymous', oracle: 'observation', prelude: [], observe: [],
    subject: {method: 'GET', path: '/api/search', placement: 'query', key: 'term',
      fixedFields: [{field: 'category', value: 'fruit'}], bodyTemplate: '', headers: []},
    controlValue: 'plain', firstValue: 'first', secondValue: 'second',
    marker: '', secondMarker: '',
    assertion: {step: 'subject', index: 0, location: 'body', name: ''}};
  const checked = validateResearchFlow(proposal, surface, scope);
  assert.equal(checked.ok, true, JSON.stringify(checked));
  const novelOracle = validateResearchFlow({...proposal,
    oracle: 'xpath-result-difference'}, surface, scope);
  assert.equal(novelOracle.ok, true, JSON.stringify(novelOracle));
  assert.equal(novelOracle.normalizedOracle, true);
  assert.equal(novelOracle.lead.family, proposal.family);
  assert.equal(novelOracle.lead.oracle, 'observation',
    'an unknown impact label may run as feedback but cannot claim a finding');
  const numericFamily = validateResearchFlow({...proposal,
    family: '62e5720667-item'}, surface, scope);
  assert.equal(numericFamily.ok, true, JSON.stringify(numericFamily));
  assert.equal(numericFamily.lead.family, '62e5720667-item');
  const requests = [];
  await executeResearchFlow(checked.lead, async request => {
    requests.push(request);
    return {status: 200, type: 'application/json', body: '{}', headers: {},
      cached: false, evidenceId: `ev-${requests.length}`};
  });
  assert.equal(requests.length, 6);
  assert.ok(requests.every(request => request.method === 'GET' &&
    new URL(request.url, origin).searchParams.get('category') === 'fruit'));
  assert.ok(requests.some(request => new URL(request.url, origin)
    .searchParams.get('term') === 'first'));
  const novel = validateResearchFlow({...proposal, subject: {...proposal.subject,
    key: 'undocumented'}}, surface, scope);
  assert.equal(novel.ok, true, JSON.stringify(novel));
  assert.equal(novel.lead.queryKeySource, 'muse-hypothesis');
  assert.equal(checked.lead.queryKeySource, 'observed-route-field');
  assert.deepEqual(novel.lead.subject.fixedFields,
    [{field: 'category', value: 'fruit'}]);
  const unseen = validateResearchFlow({...proposal, subject: {...proposal.subject,
    fixedFields: [{field: 'unseen', value: 'fruit'}]}}, surface, scope);
  assert.equal(unseen.reason, 'unobserved-read-field');
  assert.equal(unseen.diagnostic.component, 'fixed-query-fields');
  assert.deepEqual(unseen.diagnostic.observedFields.sort(), ['category', 'term']);
  assert.deepEqual(unseen.diagnostic.fixedFieldNames, ['unseen']);
  const header = validateResearchFlow({...proposal, subject: {...proposal.subject,
    placement: 'header'}}, surface, scope);
  assert.equal(header.reason, 'read-shape');
});

test('markerless protected-body flow requires observed owner denial and a scoped public input', () => {
  const origin = 'http://127.0.0.1:4329';
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'bypass-flow-boundary-'));
  try {
    const file = path.join(dir, 'scope.json');
    fs.writeFileSync(file, JSON.stringify({schemaVersion: 1, target: {origin},
      include: ['/']}));
    const scope = loadScope({file, origin}).scope;
    const surface = {patterns: [
      {pattern: '/api/private', methods: ['GET'],
        fingerprint: {owner: {status: 200}, anonymous: {status: 403}}},
      {pattern: '/api/search', methods: ['GET'], params: {term: ['plain']},
        fingerprint: {anonymous: {status: 200}}}]};
    const proposal = {family: 'owner-content-disclosure', why: 'Observed private response',
      priority: 8, as: 'anonymous', oracle: 'protected-body',
      protectedPath: '/api/private', prelude: [], observe: [],
      subject: {method: 'GET', path: '/api/search', placement: 'query',
        key: 'term', fixedFields: [], bodyTemplate: '', headers: []},
      controlValue: 'plain', firstValue: 'wide-one', secondValue: 'wide-two',
      assertion: {step: 'subject', index: 0, location: 'body', name: ''}};
    const env = {OWNER_TOKEN: 'fixture-owner'};
    assert.equal(validateResearchFlow(proposal, surface, scope, {env}).ok, true);
    const normalized = validateResearchFlow({...proposal,
      family: 'Owner Content — Disclosure'}, surface, scope, {env});
    assert.equal(normalized.ok, true);
    assert.equal(normalized.lead.family, 'Owner Content - Disclosure');
    assert.equal(validateResearchFlow(proposal, surface, scope).reason, 'protected-boundary');
    assert.equal(validateResearchFlow({...proposal, protectedPath: '/api/missing'},
      surface, scope, {env}).reason, 'protected-boundary');
    assert.equal(validateResearchFlow({...proposal, as: 'owner'}, surface,
      scope, {env}).reason, 'protected-boundary');
    assert.equal(validateResearchFlow({...proposal, prelude: [{method: 'GET',
      path: '/api/private', headers: []}]}, surface, scope, {env}).ok, true);
    const novel = validateResearchFlow({...proposal, subject: {...proposal.subject,
      key: 'undocumented'}}, surface, scope, {env});
    assert.equal(novel.ok, true, JSON.stringify(novel));
    assert.equal(novel.lead.queryKeySource, 'muse-hypothesis');
  } finally {fs.rmSync(dir, {recursive: true, force: true});}
});

test('Muse derived query examples and body names run as observations without a false finding', async () => {
  const origin = 'http://127.0.0.1:4329';
  const scope = loadScope({origin, overrides: {acceptLocal: true}}).scope;
  const surface = {patterns: [{pattern: '/api/Cards', methods: ['GET'],
    params: {page: ['1']}, responseFacts: {status: 200,
      identity: 'derived-session', shape: {data: []}}}]};
  const planned = await planResearchFlows(surface, scope, {model: 'fixture',
    budget: 1, modelCallsAvailable: 1, derivedAvailable: true,
    infer: async () => ({flows: [{family: 'cards paging access',
      why: 'Check the authenticated paging response', priority: 7,
      as: 'derived', oracle: 'protected-body', protectedPath: '/api/Cards',
      prelude: [], observe: [],
      subject: {method: 'GET', path: '/api/Cards?page=1', placement: 'query',
        key: 'page', fixedFields: [], bodyTemplate: '', headers: []},
      controlValue: '1', firstValue: '2', secondValue: '3',
      marker: '', secondMarker: '',
      assertion: {step: 'subject', index: 0, location: 'body', name: 'status'}}]})});
  assert.equal(planned.leads.length, 1);
  assert.equal(planned.coverage.proposalsRejected, 0);
  assert.deepEqual({normalizedQueryExample: planned.decisions[0].normalizedQueryExample,
    normalizedBodyAssertion: planned.decisions[0].normalizedBodyAssertion,
    translatedTo: planned.decisions[0].translatedTo},
  {normalizedQueryExample: true, normalizedBodyAssertion: true,
    translatedTo: 'observation'});
  assert.equal(planned.leads[0].subject.path, '/api/Cards');
  assert.equal(planned.leads[0].oracle, 'observation');
  const requests = [];
  const run = await runResearchFlows(planned.leads, scope, {surface,
    requester: () => {throw Error('anonymous fallback must not run');},
    derivedSession: {loginProof: {kind: 'model-auth-login'},
      requestAuthenticated: async request => {
        requests.push(request);
        const page = new URL(request.url, origin).searchParams.get('page');
        return {status: page === '1' ? 200 : 206,
          type: 'application/json', body: JSON.stringify({page}),
          headers: {}, evidenceId: `ev-${requests.length}`, cached: false};
      }}});
  assert.equal(requests.length, 6, 'each value has a fresh repeated control');
  assert.deepEqual(requests.slice(0, 3).map(item => item.url),
    ['/api/Cards?page=1', '/api/Cards?page=2', '/api/Cards?page=3']);
  assert.equal(run.results[0].kind, 'model-http-observation');
  assert.equal(run.results[0].verdict, 'inconclusive');
  assert.equal(run.findings.length, 0);
});

test('local POST refusal subtype reaches Muse and can prompt a reviewed route pivot', async () => {
  const origin = 'http://127.0.0.1:4329';
  const post = randomPath('reviewed-post');
  const scope = structuredClone(loadScope({origin, overrides: {acceptLocal: true}}).scope);
  scope.probes.jsonPostPaths.push(post);
  const surface = {patterns: [{pattern: '/api/search', methods: ['GET'],
    params: {q: ['plain']}}], jsonBodyOperations: [{path: post, method: 'POST',
    contentType: 'application/json', fields: ['q'], requiredFields: []}]};
  const lead = {family: 'reviewed API response', why: 'Compare the observed input',
    priority: 6, as: 'anonymous', oracle: 'observation', prelude: [], observe: [],
    subject: {method: 'POST', path: post, placement: 'json', key: 'q',
      fixedFields: [], bodyTemplate: '', headers: []},
    controlValue: 'plain', firstValue: 'alpha', secondValue: 'beta',
    marker: '', secondMarker: '',
    assertion: {step: 'subject', index: 0, location: 'body', name: ''}};
  const methods = [];
  let modelCalls = 0;
  const run = await runResearchFlows([lead], scope, {surface, model: 'fixture',
    modelCallsAvailable: 1,
    requester: async request => {
      methods.push(request.method);
      if (request.method === 'POST') return {status: null, refused: true,
        reason: 'local-auto-post-contract', detail: 'unobserved-field',
        body: '', headers: {}, evidenceId: 'ev-post-refused'};
      return {status: 200, type: 'application/json', body: '{"result":"stable"}',
        headers: {}, evidenceId: `ev-${methods.length}`, cached: false};
    },
    infer: async (_model, messages) => {
      modelCalls++;
      const context = JSON.parse(messages[1].content);
      assert.equal(context.recentAttempts[0].reason,
        'request refused: local-auto-post-contract/unobserved-field');
      assert.deepEqual(context.recentAttempts[0].responses[0].subject.refusal,
        {rule: 'local-auto-post-contract', detail: 'unobserved-field'});
      return {flows: [{...lead, subject: {...lead.subject,
        method: 'GET', path: '/api/search', placement: 'query'},
      why: 'Pivot to observed GET after a refused POST'}]};
    }});
  assert.equal(modelCalls, 1);
  assert.deepEqual(methods, ['POST', ...Array(6).fill('GET')]);
  assert.equal(run.investigations[0].attempts[0].reason,
    'request refused: local-auto-post-contract/unobserved-field');
  assert.equal(run.results[0].verdict, 'not_reproduced');
  assert.equal(run.findings.length, 0);
  const blockedOnly = await runResearchFlows([lead], scope, {surface,
    requester: async () => ({status: null, refused: true,
      reason: 'local-auto-post-contract', detail: 'unobserved-field',
      body: '', headers: {}})});
  assert.equal(blockedOnly.results[0].verdict, 'blocked');
  assert.equal(blockedOnly.results[0].reason,
    'request refused: local-auto-post-contract/unobserved-field');
  const unsafeDetail = await executeResearchFlow(lead, async () => ({status: null,
    refused: true, reason: 'local-auto-post-contract',
    detail: 'unobserved-field token=private', body: '', headers: {}}));
  assert.equal(unsafeDetail.reason, 'request refused or blocked');
  assert.equal('refusal' in unsafeDetail.facts[0].subject, false);
});

test('blank bindings normalize and model-authored syntax remains executable', async () => {
  const origin = 'http://127.0.0.1:4329';
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'bypass-flow-binding-shape-'));
  try {
    const file = path.join(dir, 'scope.json');
    fs.writeFileSync(file, JSON.stringify({schemaVersion: 1, target: {origin},
      include: ['/']}));
    const scope = loadScope({file, origin}).scope;
    const surface = {patterns: [{pattern: '/api/search', methods: ['GET'],
      params: {term: ['plain']}}]};
    const base = {family: 'response-transform', why: 'Observed input', priority: 5,
      as: 'anonymous', prelude: [], subject: {method: 'GET', path: '/api/search',
        placement: 'query', key: 'term', fixedFields: [], bodyTemplate: '', headers: []},
      observe: [], controlValue: 'plain', firstValue: '1+1', secondValue: '2+2',
      marker: 'bx111111111111', secondMarker: 'bx222222222222',
      assertion: {step: 'subject', index: 0, location: 'body', name: ''}};
    const placeholder = {from: 0, pointer: '', to: 'subject', index: 0, key: ''};
    const direct = validateResearchFlow({...base, binding: placeholder}, surface, scope);
    assert.equal(direct.ok, true);
    assert.equal(direct.normalizedBinding, true);
    assert.equal('binding' in direct.lead, false);
    assert.equal(validateResearchFlow({...base, binding: {}}, surface, scope).ok, true);
    assert.equal(validateResearchFlow({...base, binding: {from: -1, pointer: '',
      to: 'observe', index: -1, key: ''}}, surface, scope).ok, true);
    const malformed = validateResearchFlow({...base,
      binding: {from: 0, pointer: '/id', to: 'subject', index: 0, key: 'term'}},
    surface, scope);
    assert.equal(malformed.reason, 'binding-shape');
    assert.deepEqual(malformed.diagnostic.fields,
      {from: 'number', pointer: 'string', to: 'string', index: 'number', key: 'string'});
    const planned = await planResearchFlows(surface, scope, {model: 'fixture',
      budget: 2, modelCallsAvailable: 1, infer: async (_model, messages, options) => {
        assert.deepEqual(options.schema.properties.flows.items.properties.binding.type,
          ['object', 'null']);
        assert.match(messages[0].content, /binding:null/);
        const context = JSON.parse(messages[1].content);
        return {flows: [
          {...base, firstValue: '<script>', marker: context.marker,
            secondMarker: context.secondMarker},
          {...base, binding: {from: 0, pointer: '/id', to: 'subject', index: 0,
            key: 'term'}, marker: context.marker, secondMarker: context.secondMarker},
          {...base, binding: placeholder, marker: context.marker,
            secondMarker: context.secondMarker}]};
      }});
    assert.deepEqual(planned.decisions.map(item => item.reason),
      [undefined, 'binding-shape', undefined]);
    assert.equal(planned.decisions[0].translatedTo, undefined);
    assert.equal(planned.leads[0].oracle, 'marker');
    assert.equal(planned.decisions[1].shape.component, 'binding-shape');
    assert.equal(planned.decisions[2].normalizedBinding, true);
    assert.equal(JSON.stringify(planned.decisions).includes('<script>'), false);
    assert.equal(JSON.stringify(planned.decisions).includes('/id'), false);
  } finally {fs.rmSync(dir, {recursive: true, force: true});}
});

test('a source-grounded two-write plan may omit an empty observe list and bind a fresh response', async () => {
  const origin = 'http://127.0.0.1:4334';
  const {scope} = loadScope({origin, overrides: {acceptLocal: true}});
  const login = randomPath('begin'), verify = randomPath('finish');
  const user = `user_${randomBytes(3).toString('hex')}`;
  const password = `phrase_${randomBytes(3).toString('hex')}`;
  const challenge = `challenge_${randomBytes(3).toString('hex')}`;
  const flag = `choice_${randomBytes(3).toString('hex')}`;
  const surface = {authBodyOperations: [{path: login, method: 'POST',
    contentType: 'application/json', fields: [user, password],
    requiredFields: [user, password]}], jsonBodyOperations: [{path: verify,
    method: 'POST', contentType: 'application/json',
    fields: [challenge, 'code', flag], requiredFields: [challenge, 'code', flag]}]};
  const step = (path, key, value, fixedFields = []) => ({method: 'POST', path,
    placement: 'json', key, value, fixedFields, bodyTemplate: '', headers: []});
  const proposal = {family: 'two-step access boundary',
    why: 'A fresh first response is required by the second write', priority: 8,
    as: 'anonymous', oracle: 'status-boundary',
    prelude: [step(login, user, 'fixture-user',
      [{field: password, value: 'fixture-password'}])],
    subject: {...step(verify, flag, '', [{field: 'code', value: 'wrong'}]),
      valueEncoding: 'json'},
    // Muse can omit this optional list when proof is in the subject response.
    bindings: [{from: 0, pointer: `/${challenge}`, to: 'subject', index: 0,
      key: challenge}],
    controlValue: 'false', firstValue: 'true', secondValue: 'null',
    marker: '', secondMarker: '',
    assertion: {step: 'subject', index: 0, location: 'body', name: ''}};
  const reviewed = validateResearchFlow(proposal, surface, scope);
  assert.equal(reviewed.ok, true, JSON.stringify(reviewed));
  assert.deepEqual(reviewed.lead.observe, []);
  assert.equal(validateResearchFlow({...proposal, observe: null}, surface, scope).ok,
    true, 'a null optional step list is also empty');
  let issued = 0;
  const fresh = new Set(), seen = [];
  await executeResearchFlow(reviewed.lead, async request => {
    const body = JSON.parse(request.body);
    seen.push({path: request.url, body});
    if (request.url === login) {
      assert.equal(body[user], 'fixture-user');
      assert.equal(body[password], 'fixture-password');
      issued++;
      const value = randomBytes(24).toString('hex');
      fresh.add(value);
      return {status: 200, type: 'application/json',
        headers: {'content-type': 'application/json'},
        body: JSON.stringify({[challenge]: value}), evidenceId: `e${issued}`};
    }
    assert.equal(request.url, verify);
    assert.equal(fresh.delete(body[challenge]), true,
      'each verification uses a new first-step response');
    assert.equal(body.code, 'wrong');
    return {status: body[flag] === true ? 200 : 401,
      type: 'application/json', headers: {'content-type': 'application/json'},
      body: JSON.stringify({ok: body[flag] === true}), evidenceId: `e${issued}`};
  });
  assert.ok(seen.some(item => item.path === verify && item.body[flag] === true));
  assert.equal(seen.filter(item => item.path === login).length,
    seen.filter(item => item.path === verify).length);
});

test('a bound POST prelude needs no separate value before an authenticated POST subject', async () => {
  const origin = 'http://127.0.0.1:4334';
  const {scope} = loadScope({origin, overrides: {acceptLocal: true}});
  const suffix = randomBytes(4).toString('hex');
  const login = `/api/${suffix}/begin`;
  const verify = `/api/${suffix}/confirm`;
  const submit = `/api/${suffix}/submit`;
  const userField = `user_${suffix}`;
  const challengeField = `challenge_${suffix}`;
  const codeField = `code_${suffix}`;
  const flagField = `flag_${suffix}`;
  const cookieName = `session_${suffix}`;
  const proposal = {family: 'fresh staged session',
    why: 'A fresh response supplies the next write and its session reaches the final write',
    priority: 8, as: 'anonymous', oracle: 'status-boundary',
    prelude: [
      {method: 'POST', path: login, placement: 'json', key: userField,
        value: 'fixture-user', fixedFields: [], bodyTemplate: '', headers: []},
      {method: 'POST', path: verify, placement: 'json', key: challengeField,
        fixedFields: [{field: codeField, value: '000000'}],
        bodyTemplate: '', headers: []},
    ],
    subject: {method: 'POST', path: submit, placement: 'json', key: flagField,
      valueEncoding: 'json', fixedFields: [], bodyTemplate: '', headers: []},
    bindings: [{from: 0, pointer: `/${challengeField}`,
      to: 'prelude', index: 1, key: challengeField}],
    controlValue: 'false', firstValue: 'true', secondValue: 'null',
    marker: '', secondMarker: '',
    assertion: {step: 'subject', index: 0, location: 'body', name: ''}};
  const reviewed = validateResearchFlow(proposal, {}, scope);
  assert.equal(reviewed.ok, true, JSON.stringify(reviewed));
  assert.equal(reviewed.lead.prelude[1].value, '');
  assert.deepEqual(reviewed.lead.proposedOperations.map(item => item.path),
    [login, verify, submit]);
  const unavailableIdentity = validateResearchFlow({...proposal, prelude: [
    proposal.prelude[0], {...proposal.prelude[1], as: 'owner'}]}, {}, scope);
  assert.equal(unavailableIdentity.reason, 'unobserved-read-step');
  assert.deepEqual(unavailableIdentity.diagnostic, {component: 'prelude-step',
    index: 1, valueReason: 'identity-unavailable', method: 'POST',
    placement: 'json', hasKey: true, hasValue: false});
  const unboundJson = validateResearchFlow({...proposal, bindings: [],
    prelude: [proposal.prelude[0],
      {...proposal.prelude[1], valueEncoding: 'json'}]}, {}, scope);
  assert.equal(unboundJson.reason, 'unobserved-read-step');
  assert.equal(unboundJson.diagnostic.valueReason, 'input-value');

  const issued = new Set(), sessions = new Set(), seen = [];
  const response = (status, body, evidenceId, rawSetCookie = []) => ({
    status, type: 'application/json', headers: {'cache-control': 'no-store'},
    body: JSON.stringify(body), evidenceId, rawSetCookie});
  const attempt = await executeResearchFlow(reviewed.lead, async request => {
    const body = JSON.parse(request.body);
    seen.push(request.url);
    if (request.url === login) {
      assert.equal(body[userField], 'fixture-user');
      assert.equal(request.headers.cookie, undefined,
        'each control starts without another session');
      const challenge = randomBytes(24).toString('hex');
      issued.add(challenge);
      return response(200, {[challengeField]: challenge}, `begin-${seen.length}`);
    }
    if (request.url === verify) {
      assert.equal(issued.delete(body[challengeField]), true,
        'verification must consume a fresh challenge');
      assert.equal(body[codeField], '000000');
      const session = randomBytes(16).toString('hex');
      sessions.add(session);
      return response(200, {verified: true}, `confirm-${seen.length}`,
        [`${cookieName}=${session}; Path=/api; HttpOnly`]);
    }
    assert.equal(request.url, submit);
    const session = request.headers.cookie?.split(';').map(part => part.trim())
      .find(part => part.startsWith(`${cookieName}=`))?.slice(cookieName.length + 1);
    assert.equal(sessions.delete(session), true,
      'the final POST must receive only the session from its own verification');
    return response(body[flagField] === true ? 200 : 401,
      {accepted: body[flagField] === true}, `submit-${seen.length}`);
  }, {origin});
  assert.equal(attempt.verdict, 'confirmed', attempt.reason);
  assert.equal(seen.filter(path => path === login).length,
    seen.filter(path => path === verify).length);
  assert.equal(seen.filter(path => path === verify).length,
    seen.filter(path => path === submit).length);
});

test('research preserves Muse request bytes and binds each fresh scalar into headers and cookies', async () => {
  const origin = 'http://127.0.0.1:4334';
  const {scope} = loadScope({origin, overrides: {acceptLocal: true}});
  const begin = randomPath('begin'), finish = randomPath('finish');
  const proposedField = `model_${randomBytes(3).toString('hex')}`;
  const nonce = `nonce_${randomBytes(3).toString('hex')}`;
  const header = `x-proof-${randomBytes(3).toString('hex')}`;
  const cookie = `proof_${randomBytes(3).toString('hex')}`;
  const bodyField = `derived_${randomBytes(3).toString('hex')}`;
  const surface = {jsonBodyOperations: [
    {path: begin, method: 'POST', contentType: 'application/json',
      fields: ['user', 'mode'], requiredFields: ['user', 'mode']},
    {path: finish, method: 'POST', contentType: 'application/json',
      fields: ['flag'], requiredFields: ['flag']} ]};
  const proposal = {family: 'fresh access flow', why: 'Use the setup response twice',
    priority: 8, as: 'anonymous', oracle: 'observation',
    prelude: [{method: 'POST', path: begin, placement: 'json', key: proposedField,
      value: 'muse-user', fixedFields: [{field: 'user', value: 'fixture-user'},
        {field: 'mode', value: 'muse-mode'}],
      bodyTemplate: '', headers: [{name: 'Content-Type',
        value: 'application/json; charset=utf-8'}]}],
    subject: {method: 'POST', path: finish, placement: 'json', key: 'flag',
      fixedFields: [], bodyTemplate:
        `{"flag":"{{input}}","${bodyField}":"{{binding:${bodyField}}}","source":"Muse"}`,
      headers: [{name: 'Content-Type', value: 'application/json; charset=utf-8'}]},
    bindings: [{from: 0, pointer: `/${nonce}`, to: 'subject', index: 0,
      key: header, placement: 'header'},
    {from: 0, pointer: `/${nonce}`, to: 'subject', index: 0,
      key: cookie, placement: 'cookie'},
    {from: 0, pointer: `/${nonce}`, to: 'subject', index: 0,
      key: bodyField}],
    controlValue: 'closed', firstValue: 'candidate', secondValue: 'other',
    marker: '', secondMarker: '',
    assertion: {step: 'subject', index: 0, location: 'body', name: ''}};
  const reviewed = validateResearchFlow(proposal, surface, scope);
  assert.equal(reviewed.ok, true, JSON.stringify(reviewed));
  assert.equal(reviewed.lead.prelude[0].key, proposedField);
  assert.equal(reviewed.lead.prelude[0].value, 'muse-user');
  assert.deepEqual(reviewed.lead.prelude[0].fixedFields,
    [{field: 'user', value: 'fixture-user'},
      {field: 'mode', value: 'muse-mode'}]);
  assert.equal(reviewed.lead.subject.bodyTemplate,
    proposal.subject.bodyTemplate);
  const issued = new Set(), received = [];
  await executeResearchFlow(reviewed.lead, async request => {
    assert.equal(request.headers['content-type'],
      'application/json; charset=utf-8');
    if (request.url === begin) {
      assert.deepEqual(JSON.parse(request.body),
        {user: 'fixture-user', mode: 'muse-mode', [proposedField]: 'muse-user'});
      const value = randomBytes(24).toString('hex');
      issued.add(value);
      return {status: 200, type: 'application/json',
        body: JSON.stringify({[nonce]: value}), headers: {},
        evidenceId: `begin-${issued.size}`};
    }
    assert.equal(request.url, finish);
    const value = request.headers[header];
    assert.equal(issued.delete(value), true);
    assert.equal(request.headers.cookie, `${cookie}=${value}`);
    assert.ok(request.redactValues.includes(value));
    assert.equal(request.body,
      `{"flag":"${JSON.parse(request.body).flag}","${bodyField}":"${value}","source":"Muse"}`);
    received.push({value, body: request.body});
    return {status: 200, type: 'application/json', body: '{"ok":true}',
      headers: {}, evidenceId: `finish-${received.length}`};
  });
  assert.ok(received.length >= 3);
  assert.equal(new Set(received.map(item => item.value)).size, received.length);
  assert.ok(received.some(item => item.body ===
    `{"flag":"candidate","${bodyField}":"${item.value}","source":"Muse"}`));
});

test('a staged access sequence carries only its own issued cookie into an observed read and fresh proof', async t => {
  const suffix = randomBytes(4).toString('hex');
  const login = `/api/${suffix}/begin`, verify = `/api/${suffix}/finish`;
  const read = `/api/${suffix}/state`;
  const challengeField = `challenge_${suffix}`;
  const flagField = `flag_${suffix}`;
  const queryField = `view_${suffix}`;
  const cookieName = `session_${suffix}`;
  const issued = new Set(), sessions = new Set(), tokens = [], reads = [];
  let vulnerable = true;
  const server = http.createServer(async (request, response) => {
    const url = new URL(request.url, 'http://fixture.invalid');
    response.setHeader('content-type', 'application/json');
    response.setHeader('cache-control', 'no-store');
    const send = (status, value) => {
      response.statusCode = status;
      response.end(JSON.stringify(value));
    };
    if (request.method === 'POST' && url.pathname === login) {
      const challenge = randomBytes(24).toString('hex');
      issued.add(challenge);
      return send(200, {[challengeField]: challenge});
    }
    if (request.method === 'POST' && url.pathname === verify) {
      const chunks = [];
      for await (const chunk of request) chunks.push(chunk);
      const body = JSON.parse(Buffer.concat(chunks).toString());
      const fresh = issued.delete(body[challengeField]);
      if (!fresh || !vulnerable || body[flagField] !== true)
        return send(401, {error: 'denied'});
      const token = randomBytes(20).toString('hex');
      tokens.push(token);
      sessions.add(token);
      response.setHeader('set-cookie', `${cookieName}=${token}; Path=/; HttpOnly`);
      return send(200, {ok: true});
    }
    if (request.method === 'GET' && url.pathname === read &&
        url.searchParams.get(queryField) === 'summary') {
      const token = String(request.headers.cookie ?? '').split(';').map(part =>
        part.trim()).find(part => part.startsWith(`${cookieName}=`))?.slice(cookieName.length + 1);
      const open = Boolean(token && sessions.has(token));
      reads.push({status: open ? 200 : 401, hasCookie: Boolean(token)});
      return send(open ? 200 : 401, open ? {state: 'open'} : {error: 'denied'});
    }
    return send(404, {error: 'missing'});
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  t.after(() => new Promise(resolve => server.close(resolve)));
  const origin = `http://127.0.0.1:${server.address().port}`;
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'bypass-sequence-cookie-'));
  t.after(() => fs.rmSync(dir, {recursive: true, force: true}));
  const scopeFile = path.join(dir, 'scope.json');
  const operations = [
    {method: 'POST', path: login, placement: 'json', contentType: 'application/json',
      fields: ['user'], requiredFields: ['user']},
    {method: 'POST', path: verify, placement: 'json', contentType: 'application/json',
      fields: [challengeField, 'code', flagField],
      requiredFields: [challengeField, 'code', flagField]},
  ];
  fs.writeFileSync(scopeFile, JSON.stringify({schemaVersion: 1, target: {origin},
    include: ['/api'], methods: ['GET', 'HEAD', 'POST'],
    probes: {jsonPostPaths: [login, verify], writeOperations: operations.map(
      ({method, path, placement}) => ({method, path, placement}))},
    limits: {rps: 100}}));
  const scope = loadScope({file: scopeFile, origin}).scope;
  const surface = {patterns: [{pattern: read, methods: ['GET'],
    params: {[queryField]: ['summary']}}], methodOperations: operations,
  authBodyOperations: [operations[0]], jsonBodyOperations: [operations[1]]};
  const proposal = {family: 'staged access boundary', why: 'A successful write issues a session',
    priority: 8, as: 'anonymous', oracle: 'status-boundary',
    prelude: [{method: 'POST', path: login, placement: 'json', key: 'user',
      value: 'fixture-user', fixedFields: [], bodyTemplate: '', headers: []}],
    subject: {method: 'POST', path: verify, placement: 'json', key: flagField,
      valueEncoding: 'json', fixedFields: [{field: 'code', value: 'wrong'}],
      bodyTemplate: '', headers: []},
    observe: [{method: 'GET', path: read, placement: 'query', key: queryField,
      value: 'summary', fixedFields: [], bodyTemplate: '', headers: []}],
    binding: {from: 0, pointer: `/${challengeField}`, to: 'subject', index: 0,
      key: challengeField},
    controlValue: 'false', firstValue: 'true', secondValue: 'null',
    marker: '', secondMarker: '',
    assertion: {step: 'observe', index: 0, location: 'body', name: ''}};
  const reviewed = validateResearchFlow(proposal, surface, scope);
  assert.equal(reviewed.ok, true, JSON.stringify(reviewed));
  const ledger = createLedger(dir);
  t.after(() => ledger.close());
  const requester = createRequester(scope, {ledger, allowLocal: true});
  const attempt = await executeResearchFlow(reviewed.lead, requester, {origin});
  assert.equal(attempt.verdict, 'confirmed', attempt.reason);
  assert.deepEqual(attempt.phases.map(phase => phase.observe[0].status),
    [401, 200, 401, 401, 200, 401]);
  assert.deepEqual(reads.slice(0, 6).map(item => item.hasCookie),
    [false, true, false, false, true, false],
  'each control starts without the candidate session');
  const finding = {id: 'f-001', kind: 'model-sequence-boundary', pattern: verify,
    url: `${origin}${verify}`, confirmation: attempt.evidence,
    webProof: {...reviewed.lead, kind: 'model-sequence-boundary'}};
  const proved = await proveFindings([finding], [], {runDir: dir, surface,
    scope, env: {}, ledger, web: {results: []}});
  assert.equal(proved.length, 1, 'fresh PoC replay must confirm the observed access');
  assert.deepEqual(reads.slice(6, 12).map(item => item.status),
    [401, 200, 401, 401, 200, 401]);
  const stored = [ledger.file, path.join(dir, 'poc/f-001/spec.json'),
    path.join(dir, 'poc/f-001/poc.mjs')].map(file => fs.readFileSync(file, 'utf8')).join('\n');
  assert.ok(tokens.every(token => !stored.includes(token)),
    'issued cookie values must remain transient');
  vulnerable = false;
  const fixed = await execFile(process.execPath, [proved[0].proof, '--expect-fixed'],
    {env: process.env, timeout: 20000});
  assert.equal(fixed.code, 0, fixed.stdout);
});

test('path-shaped model bindings to reviewed JSON fields preserve the three-step workflow', async t => {
  const origin = 'http://127.0.0.1:4334';
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'bypass-flow-body-binding-'));
  t.after(() => fs.rmSync(dir, {recursive: true, force: true}));
  const start = randomPath('start'), exchange = randomPath('exchange');
  const finish = randomPath('finish');
  const file = path.join(dir, 'scope.json');
  fs.writeFileSync(file, JSON.stringify({schemaVersion: 1, target: {origin},
    include: ['/'], probes: {jsonPostPaths: [start, exchange, finish]}}));
  const scope = structuredClone(loadScope({file, origin}).scope);
  scope.localAutoPostContracts = Object.fromEntries([
    [start, ['kind']], [exchange, ['nonce']], [finish, ['ticket', 'claim']]
  ].map(([route, fields]) => [`json ${route}`,
    {contentType: 'application/json', fields}]));
  const surface = {jsonBodyOperations: [
    {path: start, method: 'POST', contentType: 'application/json',
      fields: ['kind'], requiredFields: ['kind']},
    {path: exchange, method: 'POST', contentType: 'application/json',
      fields: ['nonce'], requiredFields: ['nonce']},
    {path: finish, method: 'POST', contentType: 'application/json',
      fields: ['ticket', 'claim'],
      requiredFields: ['ticket', 'claim']}], patterns: []};
  const step = (path, key, value) => ({method: 'POST', path,
    placement: 'json', key, value, fixedFields: [], bodyTemplate: '', headers: []});
  const proposal = {family: 'staged-workflow', why: 'Observed response fields link writes',
    priority: 8, as: 'anonymous', oracle: 'observation',
    prelude: [step(start, 'kind', 'audit'), step(exchange, 'nonce', 'audit')],
    subject: step(finish, 'claim', ''), observe: [],
    bindings: [{from: 0, pointer: '/nonce', to: 'prelude', index: 1,
      key: 'nonce', placement: 'path', segment: 0},
    {from: 1, pointer: '/ticket', to: 'subject', index: 0,
      key: 'ticket', placement: 'path', segment: 0}],
    controlValue: 'plain', firstValue: 'owner', secondValue: 'member',
    marker: '', secondMarker: '',
    assertion: {step: 'subject', index: 0, location: 'body', name: ''}};
  const misplaced = validateResearchFlow(proposal, surface, scope);
  assert.equal(misplaced.ok, false);
  assert.equal(misplaced.reason, 'binding-target');
  const corrected = {...proposal, bindings: proposal.bindings.map(
    ({placement, segment, ...binding}) => binding)};
  const reviewed = validateResearchFlow(corrected, surface, scope);
  assert.equal(reviewed.ok, true, JSON.stringify(reviewed));
  assert.equal(reviewed.normalizedBinding, undefined);
  assert.deepEqual(reviewed.lead.bindings.map(item => item.placement),
    [undefined, undefined]);
  let sequence = 0;
  const nonces = new Set(), tickets = new Set();
  const requested = [];
  await executeResearchFlow(reviewed.lead, async request => {
    const body = JSON.parse(request.body);
    requested.push({url: request.url, body});
    if (request.url === start) {
      const nonce = `n${++sequence}`;
      nonces.add(nonce);
      return {status: 201, type: 'application/json', headers: {},
        body: JSON.stringify({nonce}), evidenceId: `e${sequence}`};
    }
    if (request.url === exchange) {
      assert.equal(nonces.delete(body.nonce), true);
      const ticket = `t${sequence}`;
      tickets.add(ticket);
      return {status: 200, type: 'application/json', headers: {},
        body: JSON.stringify({ticket}), evidenceId: `e${sequence}`};
    }
    assert.equal(request.url, finish);
    assert.equal(tickets.delete(body.ticket), true);
    return {status: 200, type: 'application/json', headers: {},
      body: JSON.stringify({workspace: body.claim}), evidenceId: `e${sequence}`};
  });
  assert.ok(requested.length >= 9);
  assert.ok(requested.every(item => item.url === start ||
    item.url === exchange || item.url === finish));
  assert.equal(requested.filter(item => item.url === exchange).length,
    requested.filter(item => item.url === finish).length);
});

test('an observed query example can replace its own bound field without losing the subject probe', async () => {
  const origin = 'http://127.0.0.1:4329';
  const {scope} = loadScope({origin, overrides: {acceptLocal: true}});
  const surface = {patterns: [
    {pattern: '/api/product', methods: ['GET'],
      fingerprint: {anonymous: {status: 200, shape: {name: 'string'}, evidenceId: 'source'}}},
    {pattern: '/api/search', methods: ['GET'],
      params: {term: ['plain'], q: ['seed']}}]};
  const proposal = {family: 'observed-search-flow', why: 'Bind an observed product name',
    priority: 7, as: 'anonymous', prelude: [{method: 'GET', path: '/api/product', headers: []}],
    subject: {method: 'GET', path: '/api/search', placement: 'query', key: 'term',
      fixedFields: [], bodyTemplate: '', headers: []},
    observe: [{method: 'GET', path: '/api/search?q=seed', headers: []}],
    binding: {from: 0, pointer: '/name', to: 'observe', index: 0, key: 'q'},
    controlValue: 'plain', firstValue: '1+1', secondValue: '2+2',
    marker: 'bx111111111111', secondMarker: 'bx222222222222',
    assertion: {step: 'observe', index: 0, location: 'body', name: ''}};
  const reviewed = validateResearchFlow(proposal, surface, scope);
  assert.equal(reviewed.ok, true, JSON.stringify(reviewed));
  const requests = [];
  await executeResearchFlow(reviewed.lead, async request => {
    requests.push(request.url);
    return {status: 200, type: 'application/json', headers: {},
      body: request.url === '/api/product' ? '{"name":"apple"}' : '{"result":"plain"}',
      cached: false, evidenceId: `e-${requests.length}`};
  });
  assert.ok(requests.includes('/api/search?q=apple'), JSON.stringify(requests));
  const otherQuery = validateResearchFlow({...proposal,
    observe: [{method: 'GET', path: '/api/search?term=plain', headers: []}]},
  surface, scope);
  assert.equal(otherQuery.reason, 'binding-target');
});

test('a captured JSON ID replaces only a recorded read-route path slot', async () => {
  const origin = 'http://127.0.0.1:4330';
  const {scope} = loadScope({origin, overrides: {acceptLocal: true}});
  const surface = {patterns: [
    {pattern: '/api/context', methods: ['GET'],
      fingerprint: {anonymous: {status: 200, shape: {item: {id: 'number'}},
        evidenceId: 'source'}}},
    {pattern: '/api/items/{id}', representative: '/api/items/101',
      methods: ['GET'], params: {q: ['plain']}}]};
  const inventory = researchFlowInventory(surface, scope);
  assert.deepEqual(inventory.reads.get('/api/items/101').pathSlots,
    [{key: 'id', segment: 2, template: '/api/items/{id}'}]);
  const proposal = {family: 'contextual-item-read', why: 'Follow the observed item ID',
    priority: 8, as: 'anonymous',
    prelude: [{method: 'GET', path: '/api/context', headers: []}],
    subject: {method: 'GET', path: '/api/items/101', placement: 'query',
      key: 'q', fixedFields: [], bodyTemplate: '', headers: []},
    observe: [], binding: {from: 0, pointer: '/item/id', to: 'subject',
      index: 0, key: 'id', placement: 'path', segment: 2},
    controlValue: 'plain', firstValue: '1+1', secondValue: '2+2',
    marker: 'bx111111111111', secondMarker: 'bx222222222222',
    assertion: {step: 'subject', index: 0, location: 'body', name: ''}};
  const reviewed = validateResearchFlow(proposal, surface, scope);
  assert.equal(reviewed.ok, true, JSON.stringify(reviewed));
  const requests = [];
  const attempt = await executeResearchFlow(reviewed.lead, async request => {
    requests.push(request.url);
    return {status: 200, type: 'application/json', headers: {},
      body: request.url === '/api/context' ? '{"item":{"id":202}}' :
        '{"result":"plain"}', cached: false, evidenceId: `e-${requests.length}`};
  });
  assert.equal(attempt.phases.length, 3);
  assert.ok(requests.includes('/api/items/202?q=plain'), JSON.stringify(requests));
  assert.ok(!requests.some(item => item.includes('{id}') ||
    item.startsWith('/api/items/101?')));
  const unrelated = validateResearchFlow({...proposal,
    subject: {...proposal.subject, path: '/api/other/101'}}, surface, scope);
  assert.notEqual(unrelated.ok, true);
});

test('Muse pivots from a mapped GET to a reviewed form POST using response feedback', async t => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'bypass-flow-'));
  t.after(() => fs.rmSync(dir, {recursive: true, force: true}));
  const readPath = randomPath('read'), formPath = randomPath('calculate');
  const forbiddenPath = randomPath('decoy');
  const requests = [];
  let vulnerable = true;
  const server = http.createServer(async (request, response) => {
    const url = new URL(request.url, 'http://fixture');
    requests.push(`${request.method} ${url.pathname}`);
    response.setHeader('content-type', 'application/json');
    response.setHeader('cache-control', 'no-store');
    if (request.method === 'GET' && url.pathname === readPath) {
      response.end(JSON.stringify({result: url.searchParams.get('expression') ?? ''}));
      return;
    }
    if (request.method === 'POST' && url.pathname === formPath) {
      const chunks = [];
      for await (const chunk of request) chunks.push(chunk);
      const expression = new URLSearchParams(Buffer.concat(chunks).toString()).get('expression');
      let result;
      try {result = vulnerable ? Function(`return (${expression})`)() : expression;}
      catch {result = 'invalid';}
      response.end(JSON.stringify({result}));
      return;
    }
    response.statusCode = 404;
    response.end(JSON.stringify({error: 'missing'}));
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  t.after(() => new Promise(resolve => server.close(resolve)));
  const origin = `http://127.0.0.1:${server.address().port}`;
  const scopePath = path.join(dir, 'scope.json');
  fs.writeFileSync(scopePath, JSON.stringify({schemaVersion: 1, target: {origin},
    include: ['/'], probes: {formPostPaths: [formPath]}, limits: {rps: 50}}));
  const scope = loadScope({file: scopePath, origin}).scope;
  const surface = {patterns: [{pattern: readPath, methods: ['GET'],
    params: {expression: []}, source: ['public-openapi']}],
  formBodyOperations: [{path: formPath, method: 'POST',
    contentType: 'application/x-www-form-urlencoded', fields: ['expression'],
    requiredFields: ['expression'], source: 'public-openapi',
    purpose: 'Evaluate a supplied expression'}]};
  const flow = (context, subject) => ({family: 'expression-transform',
    why: 'The documented calculator may transform an input', priority: 8,
    as: 'anonymous', prelude: [], subject: {method: subject.method,
      path: subject.path, placement: subject.placement, key: 'expression',
      fixedFields: [], bodyTemplate: '', headers: []}, observe: [],
    controlValue: '7', firstValue: subject.placement === 'query' ? '1+1' :
      `String.fromCharCode(${[...context.marker].map(char => char.charCodeAt(0)).join(',')})`,
    secondValue: subject.placement === 'query' ? '2+2' :
      `String.fromCharCode(${[...context.secondMarker].map(char => char.charCodeAt(0)).join(',')})`,
    marker: context.marker, secondMarker: context.secondMarker,
    assertion: {step: 'subject', index: 0, location: 'body', name: ''}});
  const infer = async (_model, messages) => {
    const context = JSON.parse(messages[1].content);
    if (messages[0].content.startsWith('You are planning')) return {flows: [
      flow(context, {method: 'GET', path: forbiddenPath, placement: 'query'}),
      flow(context, {method: 'GET', path: readPath, placement: 'query'})]};
    assert.equal(context.recentAttempts[0].verdict, 'not_reproduced');
    assert.ok(context.recentAttempts[0].responses[0].subject.evidenceId);
    assert.deepEqual(context.recentAttempts[0].input,
      {controlValue: '7', firstValue: '1+1', secondValue: '2+2'});
    assert.equal('excerpt' in context.recentAttempts[0].responses[0].subject, false);
    return {flows: [flow(context, {method: 'GET', path: readPath, placement: 'query'}),
      flow(context, {method: 'POST', path: formPath, placement: 'form'})]};
  };
  const plan = await planResearchFlows(surface, scope, {infer, model: 'fixture',
    budget: 1, modelCallsAvailable: 1});
  assert.equal(plan.modelCalls, 1);
  assert.equal(plan.coverage.available, 2);
  assert.equal(plan.coverage.accepted, 1);
  assert.deepEqual(plan.decisions.map(item => [item.accepted, item.reason]),
    [[false, 'unobserved-read-route'], [true, undefined]]);
  const ledger = createLedger(dir);
  t.after(() => ledger.close());
  const requester = createRequester(scope, {ledger, allowLocal: true});
  const run = await runResearchFlows(plan.leads, scope, {requester, infer,
    model: 'fixture', surface, ledger, modelCallsAvailable: 1});
  assert.equal(run.modelCalls, 1);
  assert.equal(run.decisions[0].accepted, true);
  assert.equal(run.results[0].verdict, 'observed');
  assert.equal(run.findings[0].severity, 'unrated');
  assert.equal(run.findings[0].verdict, 'observed');
  assert.equal(run.findings[0].webProof.kind, 'model-http-sequence');
  assert.equal(run.findings[0].webProof.subject.placement, 'form');
  assert.equal(run.investigations[0].attempts.length, 2);
  assert.ok(run.investigations[0].attempts.every(item => item.evidence.length === 3));
  assert.ok(requests.filter(item => item === `POST ${formPath}`).length >= 3);
  assert.ok(!requests.some(item => item.endsWith(forbiddenPath)));
  const recorded = fs.readFileSync(ledger.file, 'utf8');
  assert.match(recorded, /model-http-sequence-attempt/);
  assert.match(recorded, /model-http-sequence-decision/);
  const proved = await proveFindings([{...run.findings[0], id: 'f-001'}], [],
    {runDir: dir, surface, scope, env: {}, ledger, web: run});
  assert.equal(proved.length, 1);
  assert.ok(fs.existsSync(proved[0].proof));
  vulnerable = false;
  const fixed = await execFile(process.execPath, [proved[0].proof, '--expect-fixed'],
    {env: process.env, timeout: 20000});
  assert.equal(fixed.code, 0, fixed.stdout);
});

test('Muse observation compares repeated scoped inputs and sends redirect evidence back without a finding', async t => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'bypass-observation-'));
  t.after(() => fs.rmSync(dir, {recursive: true, force: true}));
  const route = randomPath('choice');
  const seen = [];
  const server = http.createServer((request, response) => {
    const url = new URL(request.url, 'http://fixture');
    const value = url.searchParams.get('choice');
    seen.push(value);
    response.setHeader('cache-control', 'no-store');
    response.setHeader('content-type', 'text/plain');
    if (value === 'blue;safe') {
      response.writeHead(302, {location: '/next-blue'});
      response.end('moved');
    } else if (value === 'green') {
      response.writeHead(307, {location: '/next-green'});
      response.end('moved');
    } else {
      response.statusCode = 404;
      response.end('missing');
    }
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  t.after(() => new Promise(resolve => server.close(resolve)));
  const origin = `http://127.0.0.1:${server.address().port}`;
  const file = path.join(dir, 'scope.json');
  fs.writeFileSync(file, JSON.stringify({schemaVersion: 1, target: {origin},
    include: ['/'], limits: {rps: 50}}));
  const scope = loadScope({file, origin}).scope;
  const surface = {patterns: [{pattern: route, methods: ['GET'],
    params: {choice: ['plain']}, source: ['public-api-doc']} ]};
  const flow = {family: 'route-choice', why: 'The observed field may select a different response',
    priority: 5, as: 'anonymous', oracle: 'observation', prelude: [],
    subject: {method: 'GET', path: route, placement: 'query', key: 'choice',
      fixedFields: [], bodyTemplate: '', headers: []}, observe: [],
    controlValue: 'plain', firstValue: 'blue;safe', secondValue: 'green',
    marker: '', secondMarker: '',
    assertion: {step: 'subject', index: 0, location: 'body', name: ''}};
  assert.equal(validateResearchFlow(flow, surface, scope).ok, true);
  const plan = await planResearchFlows(surface, scope, {model: 'fixture', budget: 1,
    modelCallsAvailable: 1, infer: async () => ({flows: [flow]})});
  assert.equal(plan.coverage.accepted, 1);
  const ledger = createLedger(dir);
  t.after(() => ledger.close());
  const requester = createRequester(scope, {ledger, allowLocal: true});
  let revisionCalls = 0;
  const run = await runResearchFlows(plan.leads, scope, {requester, surface,
    ledger, model: 'fixture', modelCallsAvailable: 1,
    infer: async (_model, messages) => {
      revisionCalls++;
      const context = JSON.parse(messages[1].content);
      const attempt = context.recentAttempts[0];
      assert.equal(attempt.verdict, 'observed');
      assert.equal(attempt.oracle, 'observation');
      assert.equal(attempt.comparison.stable, true);
      assert.ok(attempt.comparison.differences.includes('status'));
      assert.ok(attempt.comparison.differences.includes('headers'));
      assert.equal(attempt.responses[1].subject.status, 302);
      assert.equal(attempt.responses[1].subject.headers.locationKind, 'relative');
      assert.ok(attempt.responses[1].subject.headers.location);
      assert.equal(JSON.stringify(context).includes('/next-blue'), false);
      return {flows: []};
    }});
  assert.equal(revisionCalls, 1);
  assert.deepEqual(seen, ['plain', 'blue;safe', 'green', 'plain', 'blue;safe', 'green']);
  assert.equal(run.findings.length, 0);
  assert.equal(run.results[0].verdict, 'inconclusive');
  assert.equal(run.results[0].kind, 'model-http-observation');
  assert.equal(run.investigations[0].attempts[0].evidence.length, 6);
  assert.match(fs.readFileSync(ledger.file, 'utf8'), /model-http-sequence-attempt/);
});

test('reflection and unstable bodies remain inconclusive observations', async t => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'bypass-observation-noise-'));
  t.after(() => fs.rmSync(dir, {recursive: true, force: true}));
  const reflected = randomPath('echo'), noisy = randomPath('noise');
  const server = http.createServer((request, response) => {
    const url = new URL(request.url, 'http://fixture');
    response.setHeader('cache-control', 'no-store');
    response.setHeader('content-type', 'text/plain');
    response.end(url.pathname === reflected ? url.searchParams.get('value') :
      randomBytes(8).toString('hex'));
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  t.after(() => new Promise(resolve => server.close(resolve)));
  const origin = `http://127.0.0.1:${server.address().port}`;
  const file = path.join(dir, 'scope.json');
  fs.writeFileSync(file, JSON.stringify({schemaVersion: 1, target: {origin},
    include: ['/'], limits: {rps: 50}}));
  const scope = loadScope({file, origin}).scope;
  const surface = {patterns: [reflected, noisy].map(pattern => ({pattern,
    methods: ['GET'], params: {value: []}}))};
  const makeFlow = route => ({family: 'response-shape', why: 'Compare observed input',
    priority: 5, as: 'anonymous', oracle: 'observation', prelude: [],
    subject: {method: 'GET', path: route, placement: 'query', key: 'value',
      fixedFields: [], bodyTemplate: '', headers: []}, observe: [],
    controlValue: 'plain', firstValue: 'blue', secondValue: 'green',
    marker: '', secondMarker: '',
    assertion: {step: 'subject', index: 0, location: 'body', name: ''}});
  const ledger = createLedger(dir);
  t.after(() => ledger.close());
  const requester = createRequester(scope, {ledger, allowLocal: true});
  const leads = [reflected, noisy].map(route =>
    validateResearchFlow(makeFlow(route), surface, scope).lead);
  const run = await runResearchFlows(leads, scope, {requester, surface, ledger});
  assert.deepEqual(run.results.map(item => item.verdict), ['inconclusive', 'inconclusive']);
  assert.equal(run.investigations[0].attempts[0].comparison.reflectionOnly, true);
  assert.equal(run.investigations[1].attempts[0].comparison.stable, false);
  assert.equal(run.findings.length, 0);
});

test('an observation can pivot to a fresh protected-body proof', async t => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'bypass-observation-pivot-'));
  t.after(() => fs.rmSync(dir, {recursive: true, force: true}));
  const protectedPath = randomPath('private'), publicPath = randomPath('lookup');
  const privateBody = JSON.stringify({id: 'record', owner: 'fixture owner',
    message: 'A private record with enough stable content for exact-body comparison.'});
  const server = http.createServer((request, response) => {
    const url = new URL(request.url, 'http://fixture');
    response.setHeader('cache-control', 'no-store');
    response.setHeader('content-type', 'application/json');
    if (url.pathname === protectedPath) {
      response.statusCode = request.headers.authorization === 'Bearer fixture-owner' ? 200 : 403;
      response.end(response.statusCode === 200 ? privateBody : '{"error":"denied"}');
      return;
    }
    if (url.pathname === publicPath) {
      const choice = url.searchParams.get('choice');
      response.end(['blue', 'green'].includes(choice) ? privateBody : '{"public":true}');
      return;
    }
    response.statusCode = 404;
    response.end('{"error":"missing"}');
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  t.after(() => new Promise(resolve => server.close(resolve)));
  const origin = `http://127.0.0.1:${server.address().port}`;
  const file = path.join(dir, 'scope.json');
  fs.writeFileSync(file, JSON.stringify({schemaVersion: 1, target: {origin},
    include: ['/'], identities: {identityPath: protectedPath}, limits: {rps: 50}}));
  const scope = loadScope({file, origin}).scope;
  const env = {OWNER_TOKEN: 'fixture-owner'};
  const surface = {patterns: [
    {pattern: protectedPath, methods: ['GET'],
      fingerprint: {owner: {status: 200}, anonymous: {status: 403}}},
    {pattern: publicPath, methods: ['GET'], params: {choice: ['plain']},
      fingerprint: {anonymous: {status: 200}}}]};
  const common = {family: 'content-boundary', why: 'Public response may match an owner-only body',
    priority: 7, as: 'anonymous', prelude: [], observe: [],
    subject: {method: 'GET', path: publicPath, placement: 'query', key: 'choice',
      fixedFields: [], bodyTemplate: '', headers: []},
    controlValue: 'plain', firstValue: 'blue', secondValue: 'green',
    marker: '', secondMarker: '',
    assertion: {step: 'subject', index: 0, location: 'body', name: ''}};
  const initial = {...common, oracle: 'observation'};
  assert.equal(validateResearchFlow(initial, surface, scope, {env}).ok, true);
  const ledger = createLedger(dir);
  t.after(() => ledger.close());
  const requester = createRequester(scope, {ledger, env, allowLocal: true});
  const run = await runResearchFlows([initial], scope, {requester, surface, env,
    ledger, model: 'fixture', modelCallsAvailable: 1,
    infer: async (_model, messages) => {
      const context = JSON.parse(messages[1].content);
      assert.equal(context.recentAttempts[0].oracle, 'observation');
      assert.equal(context.recentAttempts[0].comparison.stable, true);
      return {flows: [{...common, oracle: 'protected-body', protectedPath}]};
    }});
  assert.equal(run.decisions[0].accepted, true);
  assert.equal(run.results[0].verdict, 'confirmed');
  assert.equal(run.results[0].kind, 'model-access-boundary');
  assert.equal(run.findings.length, 1);
  assert.equal(run.findings[0].verdict, 'confirmed');
  assert.equal(run.investigations[0].attempts[0].oracle, 'observation');
  assert.equal(run.investigations[0].attempts[1].oracle, 'protected-body');
});

test('a marker observation reaches Muse for an impact pivot and keeps its unclassified evidence', async t => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'bypass-marker-impact-pivot-'));
  t.after(() => fs.rmSync(dir, {recursive: true, force: true}));
  const markerPath = randomPath('expression'), publicPath = randomPath('lookup');
  const protectedPath = randomPath('private');
  const privateBody = JSON.stringify({owner: 'fixture', visibility: 'private',
    content: 'An owner-only record with stable material for exact comparison.'});
  const scope = loadScope({origin: 'http://127.0.0.1:4329',
    overrides: {acceptLocal: true}}).scope;
  const env = {OWNER_TOKEN: 'fixture-owner'};
  const surface = {patterns: [
    {pattern: markerPath, methods: ['GET'], params: {q: ['plain']}},
    {pattern: publicPath, methods: ['GET'], params: {choice: ['plain']}},
    {pattern: protectedPath, methods: ['GET'], fingerprint: {
      owner: {status: 200}, anonymous: {status: 403}}}]};
  const firstMarker = 'bx112233445566', secondMarker = 'bx66778899aabb';
  const initial = {family: 'expression-output', why: 'Observed expression input',
    priority: 7, as: 'anonymous', oracle: 'marker', prelude: [], observe: [],
    subject: {method: 'GET', path: markerPath, placement: 'query', key: 'q',
      fixedFields: [], bodyTemplate: '', headers: []},
    controlValue: 'plain',
    firstValue: `hex:${Buffer.from(firstMarker).toString('hex')}`,
    secondValue: `hex:${Buffer.from(secondMarker).toString('hex')}`,
    marker: firstMarker, secondMarker,
    assertion: {step: 'subject', index: 0, location: 'body', name: ''}};
  const pivot = {...initial, family: 'content-boundary', why: 'Public lookup may expose owner body',
    oracle: 'protected-body', protectedPath,
    subject: {...initial.subject, path: publicPath, key: 'choice'},
    controlValue: 'plain', firstValue: 'blue', secondValue: 'green',
    marker: '', secondMarker: ''};
  let issued = 0;
  const requester = async request => {
    const url = new URL(request.url, scope.target.origin);
    let status = 200, body = '{"public":true}';
    if (url.pathname === protectedPath) {
      status = request.identity === 'owner' ? 200 : 403;
      body = status === 200 ? privateBody : '{"error":"denied"}';
    } else if (url.pathname === publicPath) {
      if (['blue', 'green'].includes(url.searchParams.get('choice'))) body = privateBody;
    } else if (url.pathname === markerPath) {
      const value = url.searchParams.get('q');
      body = value?.startsWith('hex:') ?
        Buffer.from(value.slice(4), 'hex').toString() : 'ordinary';
    }
    return {status, body, type: 'application/json',
      headers: {'cache-control': 'no-store'}, cached: false,
      evidenceId: `marker-impact-${++issued}`};
  };
  const run = await runResearchFlows([initial], scope, {requester, surface, env,
    model: 'fixture', modelCallsAvailable: 1,
    infer: async (_model, messages) => {
      const context = JSON.parse(messages[1].content);
      assert.equal(context.recentAttempts[0].verdict, 'observed');
      return {flows: [pivot]};
    }});
  assert.equal(run.investigations[0].attempts.length, 2);
  assert.equal(run.investigations[0].attempts[1].verdict, 'confirmed');
  assert.equal(run.results[0].verdict, 'confirmed');
  assert.deepEqual(run.findings.map(item => item.verdict), ['observed', 'confirmed']);
  assert.equal(run.findings[0].severity, 'unrated');
});

test('HTTP sequence validation executes scoped write hypotheses and checks observed read contracts', () => {
  const origin = 'http://127.0.0.1:4329';
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'bypass-flow-scope-'));
  try {
    const file = path.join(dir, 'scope.json');
    fs.writeFileSync(file, JSON.stringify({schemaVersion: 1, target: {origin},
      probes: {jsonPostPaths: ['/api/submit'], xmlPostPaths: ['/api/xml'],
        formPostPaths: ['/api/form']}}));
    const scope = loadScope({file, origin}).scope;
    const surface = {patterns: [{pattern: '/api/read', methods: ['GET'],
      params: {q: ['full', 'owner@example.com']}}], jsonBodyOperations: [{path: '/api/submit', method: 'POST',
      contentType: 'application/json; charset=utf-8', fields: ['value']}],
    xmlBodyOperations: [{path: '/api/xml', method: 'POST', contentType: 'application/xml',
      fields: ['payload'], rootElement: 'request'}],
    formBodyOperations: [{path: '/api/form', method: 'POST',
      contentType: 'application/x-www-form-urlencoded', fields: ['value']}]};
    const inventory = researchFlowInventory(surface, scope);
    assert.equal(inventory.posts.size, 3);
    assert.deepEqual([...inventory.reads.get('/api/read').queryExamples], ['/api/read?q=full']);
    const base = {family: 'response-transform', why: 'Observed behavior', priority: 5,
      as: 'anonymous', prelude: [], subject: {method: 'POST', path: '/api/submit',
        placement: 'json', key: 'value', fixedFields: [], bodyTemplate: '', headers: []},
      observe: [], controlValue: '7', firstValue: '1+1', secondValue: '2+2',
      marker: 'bx000000000001', secondMarker: 'bx000000000002',
      assertion: {step: 'subject', index: 0, location: 'body', name: ''}};
    assert.equal(validateResearchFlow(base, surface, scope).ok, true);
    const repeatedType = validateResearchFlow({...base, subject: {...base.subject,
      headers: [{name: 'Content-Type', value: 'application/json'}]}}, surface, scope);
    assert.equal(repeatedType.ok, true);
    assert.deepEqual(repeatedType.lead.subject.headers,
      [{name: 'Content-Type', value: 'application/json'}]);
    assert.equal(validateResearchFlow({...base, as: 'derived'}, surface, scope,
      {derivedAvailable: true}).ok, true);
    assert.equal(validateResearchFlow({...base, as: 'derived'}, surface, scope).reason,
      'metadata');
    const queryPrelude = {...base, prelude: [{method: 'GET',
      path: '/api/read?q=full', headers: []}]};
    assert.equal(validateResearchFlow(queryPrelude, surface, scope).ok, true);
    assert.equal(validateResearchFlow({...queryPrelude, prelude: [{method: 'GET',
      path: '/api/read?q=admin', headers: []}]}, surface, scope).ok, true);
    assert.equal(validateResearchFlow({...queryPrelude, prelude: [{method: 'GET',
      path: '/api/read?unknown=admin', headers: []}]}, surface, scope).reason,
    'unobserved-read-step');
    assert.equal(validateResearchFlow({...base, controlValue: 'owner-secret-abcdef'},
      surface, scope, {env: {OWNER_TOKEN: 'owner-secret-abcdef'}}).reason, 'credential-value');
    const proposedWrite = validateResearchFlow({...base, subject: {...base.subject,
      path: '/api/missing'}}, surface, scope);
    assert.equal(proposedWrite.ok, true);
    assert.equal(proposedWrite.lead.proposedOperations[0].source, 'model-proposed');
    assert.equal(proposedWrite.lead.proposedOperations[0].path, '/api/missing');
    const proposedField = validateResearchFlow({...base, subject: {...base.subject,
      key: 'password'}}, surface, scope);
    assert.equal(proposedField.ok, true);
    assert.equal(proposedField.lead.subject.key, 'password');
    const proposedHeader = validateResearchFlow({...base, subject: {...base.subject,
      headers: [{name: 'x-auth-token', value: 'demo'}]}}, surface, scope);
    assert.equal(proposedHeader.ok, true);
    assert.deepEqual(proposedHeader.lead.subject.headers,
      [{name: 'x-auth-token', value: 'demo'}]);
    const xml = {...base, subject: {method: 'POST', path: '/api/xml',
      placement: 'xml', key: 'payload', fixedFields: [], headers: [],
      bodyTemplate: '<request><payload>{{input}}</payload></request>'}};
    assert.equal(validateResearchFlow(xml, surface, scope).ok, true);
    assert.equal(validateResearchFlow({...xml, as: 'derived'}, surface, scope,
      {derivedAvailable: true}).ok, true);
    assert.equal(validateResearchFlow({...base, as: 'derived', subject: {...base.subject,
      path: '/api/form', placement: 'form'}}, surface, scope,
    {derivedAvailable: true}).ok, true);
    assert.equal(validateResearchFlow({...xml, subject: {...xml.subject,
      bodyTemplate: '<request><unknown>{{input}}</unknown></request>'}},
    surface, scope).reason, 'xml-template');
  } finally {fs.rmSync(dir, {recursive: true, force: true});}
});

test('derived session forwards an exact reviewed JSON POST with its body and content type', async t => {
  const origin = 'http://127.0.0.1:4329';
  const route = randomPath('derived-post');
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'bypass-flow-derived-post-'));
  t.after(() => fs.rmSync(dir, {recursive: true, force: true}));
  const file = path.join(dir, 'scope.json');
  fs.writeFileSync(file, JSON.stringify({schemaVersion: 1, target: {origin},
    probes: {jsonPostPaths: [route]}}));
  const scope = loadScope({file, origin}).scope;
  const surface = {jsonBodyOperations: [{path: route, method: 'POST',
    contentType: 'application/json', fields: ['value'], requiredFields: ['value']}]};
  const lead = {family: 'post-response-observation', why: 'Compare reviewed responses',
    priority: 5, as: 'derived', oracle: 'observation', prelude: [], observe: [],
    subject: {method: 'POST', path: route, placement: 'json', key: 'value',
      fixedFields: [], bodyTemplate: '', headers: []},
    controlValue: 'plain', firstValue: 'alpha', secondValue: 'beta',
    marker: '', secondMarker: '',
    assertion: {step: 'subject', index: 0, location: 'body', name: ''}};
  assert.equal(validateResearchFlow(lead, surface, scope, {derivedAvailable: true}).ok, true);
  const proposedWrite = validateResearchFlow({...lead, subject: {...lead.subject,
    path: '/outside'}}, surface, scope, {derivedAvailable: true});
  assert.equal(proposedWrite.ok, true);
  assert.equal(proposedWrite.lead.proposedOperations[0].path, '/outside');
  const requests = [];
  const run = await runResearchFlows([lead], scope, {surface,
    requester: () => {throw new Error('anonymous fallback must not run');},
    derivedSession: {loginProof: {kind: 'model-auth-login'},
      requestAuthenticated: async request => {
        requests.push(request);
        const value = JSON.parse(request.body).value;
        return {status: value === 'plain' ? 200 : value === 'alpha' ? 201 : 202,
          type: 'application/json', body: JSON.stringify({value}),
          headers: {'cache-control': 'no-store'}, cached: false,
          evidenceId: `derived-${requests.length}`};
      }}});
  assert.equal(run.results[0].verdict, 'inconclusive');
  assert.equal(run.investigations[0].attempts.length, 1);
  assert.deepEqual(requests.map(item => JSON.parse(item.body).value),
    ['plain', 'alpha', 'beta', 'plain', 'alpha', 'beta']);
  assert.ok(requests.every(item => item.method === 'POST' &&
    item.purpose === 'json-body' && item.headers['content-type'] === 'application/json' &&
    item.noCache === true && item.omitExcerpt === true));
});

test('HTTP research gives distinct observed inputs a turn before repeating one input', async t => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'bypass-flow-diverse-order-'));
  t.after(() => fs.rmSync(dir, {recursive: true, force: true}));
  const scope = loadScope({origin: 'http://127.0.0.1:4329',
    overrides: {acceptLocal: true}}).scope;
  const first = randomPath('first'), second = randomPath('second');
  const surface = {patterns: [first, second].map(pattern =>
    ({pattern, methods: ['GET'], params: {q: ['plain']}}))};
  const lead = (route, family) => ({family, why: 'Compare observed input',
    priority: 5, as: 'anonymous', oracle: 'observation', prelude: [], observe: [],
    subject: {method: 'GET', path: route, placement: 'query', key: 'q',
      fixedFields: [], bodyTemplate: '', headers: []},
    controlValue: 'plain', firstValue: 'alpha', secondValue: 'beta',
    marker: '', secondMarker: '',
    assertion: {step: 'subject', index: 0, location: 'body', name: ''}});
  let sent = 0;
  const run = await runResearchFlows([lead(first, 'first-hypothesis'),
    lead(first, 'second-hypothesis'), lead(second, 'third-hypothesis')], scope,
  {surface, requester: async () => ({status: 200, type: 'application/json',
    body: '{"ok":true}', headers: {'cache-control': 'no-store'}, cached: false,
    evidenceId: `response-${++sent}`})});
  assert.deepEqual(run.investigations.map(item => item.initial.path),
    [first, second, first]);
  assert.equal(run.results.length, 3);
});

test('a research deadline accounts for every accepted HTTP plan and keeps them resumable', async () => {
  const scope = loadScope({origin: 'http://127.0.0.1:4329',
    overrides: {acceptLocal: true}}).scope;
  const paths = ['/api/report-a', '/api/report-b', '/api/report-c'];
  const surface = {patterns: paths.map(pattern =>
    ({pattern, methods: ['GET'], params: {q: ['plain']}}))};
  const leads = paths.map((route, index) => ({
    proposalId: `accepted-${index}`, family: 'response-behavior',
    why: 'Observe a grounded input', priority: 5, as: 'anonymous',
    oracle: 'observation', prelude: [], observe: [],
    subject: {method: 'GET', path: route, placement: 'query', key: 'q',
      fixedFields: [], bodyTemplate: '', headers: []},
    controlValue: 'private-canary', firstValue: 'alpha', secondValue: 'beta',
    marker: '', secondMarker: '',
    assertion: {step: 'subject', index: 0, location: 'body', name: ''}}));
  const checkpoints = [];
  const run = await runResearchFlows(leads, scope, {surface,
    researchDeadline: 0,
    requester: () => {throw Error('the deadline must prevent requests');},
    onResearchCheckpoint: checkpoint => checkpoints.push(checkpoint)});
  assert.deepEqual(run.results.map(item => [item.proposalId, item.verdict]),
    leads.map(item => [item.proposalId, 'untested']));
  assert.equal(run.deferredLeads.length, leads.length);
  assert.equal(checkpoints.at(-1).cursor, 0);
  assert.equal(checkpoints.at(-1).leads.length, leads.length);
  assert.doesNotMatch(JSON.stringify(run.results), /private-canary/);
});

test('a sequence with no HTTP attempt remains deferred after its cursor advances', async () => {
  const scope = loadScope({origin: 'http://127.0.0.1:4329',
    overrides: {acceptLocal: true}}).scope;
  const route = '/api/deferred-input';
  const surface = {patterns: [{pattern: route, methods: ['GET'],
    params: {q: ['plain']}}]};
  const lead = {proposalId: 'accepted-deferred', family: 'response-behavior',
    why: 'Observe a grounded input', priority: 5, as: 'anonymous',
    oracle: 'observation', prelude: [], observe: [],
    subject: {method: 'GET', path: route, placement: 'query', key: 'q',
      fixedFields: [], bodyTemplate: '', headers: []},
    controlValue: 'plain', firstValue: 'alpha', secondValue: 'beta',
    marker: '', secondMarker: '',
    assertion: {step: 'subject', index: 0, location: 'body', name: ''}};
  const normalized = validateResearchFlow(lead, surface, scope);
  assert.equal(normalized.ok, true);
  const value = normalized.lead;
  const signature = JSON.stringify([value.oracle, value.protectedPath ?? null,
    value.as, value.prelude, value.subject, value.observe,
    value.rawRequests ?? null, value.rawProof ?? null,
    value.bindings ?? value.binding ?? null,
    value.controlValue, value.firstValue, value.secondValue,
    value.assertion]);
  const checkpoints = [];
  const run = await runResearchFlows([lead], scope, {surface,
    requester: () => {throw Error('a deferred lead must not issue HTTP');},
    resumeResearch: {kind: 'http-sequence', active: {phase: 'pending',
      currentLead: value, seen: [signature]}},
    onResearchCheckpoint: checkpoint => checkpoints.push(checkpoint)});
  assert.equal(run.results[0].verdict, 'untested');
  assert.equal(run.deferredLeads[0].proposalId, lead.proposalId);
  assert.equal(checkpoints.at(-1).cursor, 1);
  assert.deepEqual(checkpoints.at(-1).deferredProposalIds, [lead.proposalId]);
});

test('an unavailable verifier choice does not suppress a grounded HTTP revision', async () => {
  const route = randomPath('verifier-repair');
  const scope = loadScope({origin: 'http://127.0.0.1:4329',
    overrides: {acceptLocal: true}}).scope;
  const surface = {patterns: [{pattern: route, methods: ['GET'], params: {q: ['plain']}}]};
  const lead = {family: 'response-behavior', why: 'Observe an input', priority: 5,
    as: 'anonymous', oracle: 'observation', prelude: [], observe: [],
    subject: {method: 'GET', path: route, placement: 'query', key: 'q',
      fixedFields: [], bodyTemplate: '', headers: []},
    controlValue: 'plain', firstValue: 'alpha', secondValue: 'beta',
    marker: '', secondMarker: '',
    assertion: {step: 'subject', index: 0, location: 'body', name: ''}};
  let requests = 0, calls = 0;
  const run = await runResearchFlows([lead], scope, {surface, model: 'fixture',
    modelCallsAvailable: 2,
    verifierCandidates: [{kind: 'ssti-arithmetic',
      lead: {path: route, parameter: 'q', as: 'anonymous'}}],
    requester: async ({url}) => ({status: 200, type: 'text/plain',
      body: new URL(url, scope.target.origin).searchParams.get('q') ?? '',
      headers: {'cache-control': 'no-store'}, cached: false,
      evidenceId: `ev-${++requests}`}),
    infer: async () => ++calls === 1 ? {verifierId: 'not-offered',
      flows: [{...lead, controlValue: 'second', firstValue: 'gamma',
        secondValue: 'delta'}]} : {flows: []}});
  assert.equal(run.handoffs.length, 0);
  assert.equal(run.investigations[0].attempts.length, 2);
  assert.equal(run.decisions[0].verifierUnavailable, 'not-offered');
  assert.equal(run.decisions[0].accepted, true);
  assert.ok(requests > 6, `second revision sent only ${requests} requests`);
});

test('a selected verifier and grounded HTTP revision both continue', async () => {
  const route = randomPath('verifier-and-revision');
  const scope = loadScope({origin: 'http://127.0.0.1:4329',
    overrides: {acceptLocal: true}}).scope;
  const surface = {patterns: [{pattern: route, methods: ['GET'], params: {q: ['plain']}}]};
  const lead = {family: 'response-behavior', why: 'Observe an input', priority: 5,
    as: 'anonymous', oracle: 'observation', prelude: [], observe: [],
    subject: {method: 'GET', path: route, placement: 'query', key: 'q',
      fixedFields: [], bodyTemplate: '', headers: []},
    controlValue: 'plain', firstValue: 'alpha', secondValue: 'beta',
    marker: '', secondMarker: '',
    assertion: {step: 'subject', index: 0, location: 'body', name: ''}};
  let requests = 0, calls = 0;
  const run = await runResearchFlows([lead], scope, {surface, model: 'fixture',
    modelCallsAvailable: 2,
    verifierCandidates: [{kind: 'ssti-arithmetic',
      lead: {path: route, parameter: 'q', as: 'anonymous'}}],
    requester: async ({url}) => ({status: 200, type: 'text/plain',
      body: new URL(url, scope.target.origin).searchParams.get('q') ?? '',
      headers: {'cache-control': 'no-store'}, cached: false,
      evidenceId: `ev-${++requests}`}),
    infer: async () => ++calls === 1 ? {verifierId: 'ssti-arithmetic:1',
      flows: [{...lead, controlValue: 'second', firstValue: 'gamma',
        secondValue: 'delta'}]} : {flows: []}});
  assert.equal(run.handoffs.length, 1);
  assert.equal(run.handoffs[0].kind, 'ssti-arithmetic');
  assert.equal(run.investigations[0].attempts.length, 2);
  assert.equal(run.decisions[0].accepted, true);
  assert.equal(run.decisions[0].verifier.kind, 'ssti-arithmetic');
  assert.ok(requests > 6, `grounded revision sent only ${requests} requests`);
});

test('revised payloads with the same server error reach Muse for a stop decision', async t => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'bypass-flow-error-stall-'));
  t.after(() => fs.rmSync(dir, {recursive: true, force: true}));
  const scope = loadScope({origin: 'http://127.0.0.1:4329',
    overrides: {acceptLocal: true}}).scope;
  const route = randomPath('error');
  const surface = {patterns: [{pattern: route, methods: ['GET'],
    params: {q: ['plain']}}]};
  const lead = {family: 'error-observation', why: 'Inspect observed input',
    priority: 5, as: 'anonymous', oracle: 'observation', prelude: [], observe: [],
    subject: {method: 'GET', path: route, placement: 'query', key: 'q',
      fixedFields: [], bodyTemplate: '', headers: []},
    controlValue: 'plain', firstValue: 'alpha', secondValue: 'beta',
    marker: '', secondMarker: '',
    assertion: {step: 'subject', index: 0, location: 'body', name: ''}};
  let calls = 0, sent = 0;
  const run = await runResearchFlows([lead], scope, {surface,
    model: 'fixture', modelCallsAvailable: 20,
    requester: async request => ({status: 500, type: 'text/plain',
      body: `error: ${request.url}`, headers: {'cache-control': 'no-store'},
      cached: false, evidenceId: `error-${++sent}`}),
    infer: async () => {
      const revision = ++calls;
      if (revision === 3) return {flows: []};
      return {flows: [{...lead, controlValue: `plain${revision}`,
        firstValue: `alpha${revision}`, secondValue: `beta${revision}`}]};
    }});
  assert.equal(run.investigations[0].stopReason, 'model-stopped');
  assert.equal(run.investigations[0].attempts.length, 3);
  assert.equal(run.modelCalls, 3);
  assert.equal(sent, 3);
});

test('HTTP research sends repeated successful response shapes to Muse for a stop decision', async t => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'bypass-flow-success-stall-'));
  t.after(() => fs.rmSync(dir, {recursive: true, force: true}));
  const scope = loadScope({origin: 'http://127.0.0.1:4329',
    overrides: {acceptLocal: true}}).scope;
  const route = randomPath('records');
  const surface = {patterns: [{pattern: route, methods: ['GET'],
    params: {q: ['plain']}}]};
  const lead = {family: 'input-observation', why: 'Inspect an observed input',
    priority: 5, as: 'anonymous', oracle: 'observation', prelude: [], observe: [],
    subject: {method: 'GET', path: route, placement: 'query', key: 'q',
      fixedFields: [], bodyTemplate: '', headers: []},
    controlValue: 'plain', firstValue: 'alpha', secondValue: 'beta',
    marker: '', secondMarker: '',
    assertion: {step: 'subject', index: 0, location: 'body', name: ''}};
  let calls = 0, sent = 0;
  const run = await runResearchFlows([lead], scope, {surface,
    model: 'fixture', modelCallsAvailable: 20,
    requester: async request => {
      const q = new URL(request.url, scope.target.origin).searchParams.get('q');
      const body = JSON.stringify({data: {id: ++sent, q, role: 'customer'}});
      return {status: 200, type: 'application/json', body,
        headers: {'content-type': 'application/json'}, cached: false,
        evidenceId: `response-${sent}`};
    },
    infer: async (_model, messages) => {
      calls++;
      const context = JSON.parse(messages[1].content);
      if (calls === 3) {
        assert.match(context.noProgress, /same response status and structure/i);
        return {flows: []};
      }
      const next = context.historySummary.attempts;
      return {flows: [{...lead, controlValue: `plain${next}`,
        firstValue: `alpha${next}`, secondValue: `beta${next}`}]};
    }});
  assert.equal(run.investigations[0].stopReason, 'model-stopped');
  assert.equal(run.investigations[0].attempts.length, 3);
  assert.equal(calls, 3);
  assert.equal(sent, 18);
  assert.ok(run.decisions.slice(0, 2).every(item => item.accepted));
});

test('HTTP research keeps investigating while a server role signal changes', async () => {
  const scope = loadScope({origin: 'http://127.0.0.1:4329',
    overrides: {acceptLocal: true}}).scope;
  const route = randomPath('roles');
  const surface = {patterns: [{pattern: route, methods: ['GET'],
    params: {q: ['plain']}}]};
  const lead = {family: 'role-observation', why: 'Inspect an observed role response',
    priority: 5, as: 'anonymous', oracle: 'observation', prelude: [], observe: [],
    subject: {method: 'GET', path: route, placement: 'query', key: 'q',
      fixedFields: [], bodyTemplate: '', headers: []},
    controlValue: 'plain', firstValue: 'alpha', secondValue: 'beta',
    marker: '', secondMarker: '',
    assertion: {step: 'subject', index: 0, location: 'body', name: ''}};
  let sent = 0;
  const run = await runResearchFlows([lead], scope, {surface,
    model: 'fixture', modelCallsAvailable: 20,
    requester: async request => {
      const q = new URL(request.url, scope.target.origin).searchParams.get('q');
      const role = `role-${Math.floor(sent / 6)}`;
      const body = JSON.stringify({data: {id: ++sent, q, role}});
      return {status: 200, type: 'application/json', body,
        headers: {'content-type': 'application/json'}, cached: false,
        evidenceId: `response-${sent}`};
    },
    infer: async (_model, messages) => {
      const context = JSON.parse(messages[1].content);
      if (context.historySummary.attempts >= 7) return {flows: []};
      const next = context.historySummary.attempts;
      return {flows: [{...lead, controlValue: `plain${next}`,
        firstValue: `alpha${next}`, secondValue: `beta${next}`}]};
    }});
  assert.equal(run.investigations[0].attempts.length, 7);
  assert.equal(run.investigations[0].stopReason, 'model-stopped');
});

test('HTTP sequence read steps use separately scoped identities', async () => {
  const origin = 'http://127.0.0.1:4329';
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'bypass-flow-identities-'));
  try {
    const file = path.join(dir, 'scope.json');
    fs.writeFileSync(file, JSON.stringify({schemaVersion: 1, target: {origin},
      probes: {jsonPostPaths: ['/api/process']}, never: ['/api/forbidden']}));
    const scope = loadScope({file, origin}).scope;
    const surface = {patterns: [
      {pattern: '/api/prepare', methods: ['GET']},
      {pattern: '/api/state', methods: ['GET']},
      {pattern: '/api/forbidden', methods: ['GET']}],
    jsonBodyOperations: [{path: '/api/process', method: 'POST',
      contentType: 'application/json', fields: ['value']}]};
    const env = {OWNER_TOKEN: 'fixture-owner', OTHER_TOKEN: 'fixture-outsider'};
    const flow = {family: 'cross-identity-observation', why: 'Observe a reviewed workflow',
      priority: 5, as: 'anonymous',
      prelude: [{method: 'GET', path: '/api/prepare', as: 'owner', headers: []}],
      subject: {method: 'POST', path: '/api/process', placement: 'json',
        key: 'value', fixedFields: [], bodyTemplate: '', headers: []},
      observe: [{method: 'GET', path: '/api/state', as: 'outsider', headers: []}],
      controlValue: 'plain', firstValue: 'hex:626c7565', secondValue: 'hex:677265656e',
      marker: 'bx0123456789ab', secondMarker: 'bxabcdef012345',
      assertion: {step: 'observe', index: 0, location: 'body', name: ''}};
    const valid = validateResearchFlow(flow, surface, scope, {env});
    assert.equal(valid.ok, true);
    assert.deepEqual(valid.lead.prelude.map(step => step.as), ['owner']);
    assert.deepEqual(valid.lead.observe.map(step => step.as), ['outsider']);
    assert.equal(validateResearchFlow(flow, surface, scope,
      {env: {OWNER_TOKEN: env.OWNER_TOKEN}}).reason, 'unobserved-read-step');
    assert.equal(validateResearchFlow({...flow, observe: [{...flow.observe[0],
      path: '/api/forbidden'}]}, surface, scope, {env}).reason, 'unobserved-read-step');
    assert.equal(validateResearchFlow({...flow, observe: [{...flow.observe[0],
      path: '/api/unobserved'}]}, surface, scope, {env}).reason, 'unobserved-read-step');
    assert.equal(validateResearchFlow({...flow, observe: [{...flow.observe[0],
      as: 'admin'}]}, surface, scope, {env}).reason, 'unobserved-read-step');
    assert.equal(validateResearchFlow(flow, surface,
      {...scope, credentialOrigins: []}, {env}).reason, 'unobserved-read-step');
    const planned = await planResearchFlows(surface, scope, {env, model: 'fixture',
      budget: 1, modelCallsAvailable: 1, infer: async (_model, messages) => {
        const context = JSON.parse(messages[1].content);
        assert.equal(context.ownerAvailable, true);
        assert.equal(context.outsiderAvailable, true);
        return {flows: [{...flow, marker: context.marker,
          secondMarker: context.secondMarker}]};
      }});
    assert.equal(planned.coverage.accepted, 1);
    assert.equal(planned.leads[0].prelude[0].as, 'owner');
    assert.equal(planned.leads[0].observe[0].as, 'outsider');
  } finally {fs.rmSync(dir, {recursive: true, force: true});}
});

test('guarded sequence executor handles observed headers and reviewed XML bodies', async t => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'bypass-flow-transport-'));
  t.after(() => fs.rmSync(dir, {recursive: true, force: true}));
  const headerPath = randomPath('header'), xmlPath = randomPath('xml');
  const seen = [];
  const server = http.createServer(async (request, response) => {
    const url = new URL(request.url, 'http://fixture');
    let expression = '';
    if (url.pathname === headerPath) expression = request.headers['x-expression'] ?? '';
    if (url.pathname === xmlPath) {
      const chunks = [];
      for await (const chunk of request) chunks.push(chunk);
      const body = Buffer.concat(chunks).toString();
      assert.match(body, /^<request><payload>.*<\/payload><\/request>$/);
      expression = body.match(/<payload>(.*?)<\/payload>/)?.[1] ?? '';
    }
    seen.push({method: request.method, path: url.pathname, expression,
      contentType: request.headers['content-type'] ?? null});
    let result;
    try {result = Function(`return (${expression})`)();}
    catch {result = 'invalid';}
    response.setHeader('content-type', 'application/json');
    response.setHeader('cache-control', 'no-store');
    response.end(JSON.stringify({result}));
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  t.after(() => new Promise(resolve => server.close(resolve)));
  const origin = `http://127.0.0.1:${server.address().port}`;
  const file = path.join(dir, 'scope.json');
  fs.writeFileSync(file, JSON.stringify({schemaVersion: 1, target: {origin},
    probes: {xmlPostPaths: [xmlPath]}, limits: {rps: 50}}));
  const scope = loadScope({file, origin}).scope;
  const surface = {patterns: [{pattern: headerPath, methods: ['GET'], params: {}}],
    mined: {endpoints: [{path: headerPath, method: 'GET', params: [],
      headers: ['x-expression']}]},
    xmlBodyOperations: [{path: xmlPath, method: 'POST',
      contentType: 'application/xml', fields: ['payload'], rootElement: 'request'}]};
  const ledger = createLedger(dir);
  t.after(() => ledger.close());
  const requester = createRequester(scope, {ledger, allowLocal: true});
  const marker = 'bx111111111111', secondMarker = 'bx222222222222';
  const encoded = value => `String.fromCharCode(${[...value].map(char =>
    char.charCodeAt(0)).join(',')})`;
  const shared = {family: 'expression-transform', why: 'Response transform', priority: 5,
    as: 'anonymous', prelude: [], observe: [], controlValue: '7',
    firstValue: encoded(marker), secondValue: encoded(secondMarker),
    marker, secondMarker,
    assertion: {step: 'subject', index: 0, location: 'body', name: ''}};
  const header = {...shared, subject: {method: 'GET', path: headerPath,
    placement: 'header', key: 'x-expression', fixedFields: [],
    bodyTemplate: '', headers: []}};
  const xml = {...shared, subject: {method: 'POST', path: xmlPath,
    placement: 'xml', key: 'payload', fixedFields: [],
    bodyTemplate: '<request><payload>{{input}}</payload></request>',
    headers: [{name: 'Content-Type', value: 'application/xml; charset=utf-8'}]}};
  assert.equal(validateResearchFlow(header, surface, scope).ok, true);
  assert.equal(validateResearchFlow(xml, surface, scope).ok, true);
  assert.equal((await executeResearchFlow(header, requester)).verdict, 'observed');
  const xmlResult = await executeResearchFlow(xml, requester);
  assert.equal(xmlResult.verdict, 'observed', xmlResult.reason);
  assert.equal(seen.filter(item => item.path === headerPath).length, 3);
  assert.equal(seen.filter(item => item.path === xmlPath).length, 3);
  assert.ok(seen.filter(item => item.path === xmlPath)
    .every(item => item.contentType === 'application/xml; charset=utf-8'));
});

test('a reviewed PATCH can supply one scoped response sample for Muse follow-up', async () => {
  const origin = 'http://127.0.0.1:4329';
  const route = randomPath('patch-preview');
  const scope = structuredClone(loadScope({origin, overrides: {acceptLocal: true}}).scope);
  scope.probes.writeOperations.push({method: 'PATCH', path: route, placement: 'json'});
  const surface = {patterns: [], methodOperations: [{method: 'PATCH', path: route,
    placement: 'json', contentType: 'application/json', fields: ['value'],
    requiredFields: [], source: 'openapi'}]};
  const requests = [];
  let calls = 0;
  const plan = await planResearchFlows(surface, scope, {model: 'fixture', budget: 1,
    modelCallsAvailable: 3,
    infer: async (_model, messages) => {
      calls++;
      if (calls === 1) return {flows: []};
      if (calls === 2) {
        const context = JSON.parse(messages[1].content);
        assert.ok(context.reviewedMethods.some(item => item.path === route &&
          item.methods.includes('PATCH')));
        return {samples: [{subject: {method: 'PATCH', path: route,
          placement: 'json', key: 'value', fixedFields: [], bodyTemplate: '',
          headers: []}, value: 'plain', why: 'Observe reviewed response'}]};
      }
      return {flows: []};
    },
    requester: async request => {
      requests.push(request);
      return {status: 200, type: 'application/json', body: '{"result":"plain"}',
        headers: {}, evidenceId: 'sample', cached: false};
    }});
  assert.equal(plan.coverage.samplesSent, 1);
  assert.equal(requests.length, 1);
  assert.equal(requests[0].method, 'PATCH');
  assert.equal(requests[0].body, '{"value":"plain"}');
});

test('sample discovery refuses unreviewed POSTs and redacts rejected model text', async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'bypass-flow-reject-'));
  try {
    const origin = 'http://127.0.0.1:4329';
    const allowed = randomPath('allowed'), decoy = randomPath('decoy');
    const secret = 'operator-secret-random-value';
    const file = path.join(dir, 'scope.json');
    fs.writeFileSync(file, JSON.stringify({schemaVersion: 1, target: {origin},
      probes: {formPostPaths: [allowed]}}));
    const scope = loadScope({file, origin}).scope;
    const surface = {formBodyOperations: [{path: allowed, method: 'POST',
      contentType: 'application/x-www-form-urlencoded', fields: ['expression'],
      fieldExamples: {expression: ['2+3']}}]};
    let calls = 0, requests = 0;
    const infer = async (_model, messages) => {
      calls++;
      const context = JSON.parse(messages[1].content);
      if (calls === 1) return {flows: [{family: 'response-transform',
        why: `try ${secret}`, priority: 1, as: 'anonymous', prelude: [],
        subject: {method: 'POST', path: `/api/${secret}`, placement: 'form',
          key: 'expression', fixedFields: [], bodyTemplate: '', headers: []},
        observe: [], controlValue: '7', firstValue: '1+1', secondValue: '2+2',
        marker: context.marker, secondMarker: context.secondMarker,
        assertion: {step: 'subject', index: 0, location: 'body', name: ''}}]};
      assert.deepEqual(context.reviewedMethods[0].fieldExamples.expression, ['2+3']);
      return {samples: [{subject: {method: 'POST', path: decoy,
        placement: 'form', key: 'expression', fixedFields: [],
        bodyTemplate: '', headers: []}, value: '2+3', why: 'Try decoy'}]};
    };
    const plan = await planResearchFlows(surface, scope, {infer, model: 'fixture',
      env: {OWNER_TOKEN: secret}, budget: 1, modelCallsAvailable: 3,
      requester: async () => {requests++; throw Error('sample must not be sent');}});
    assert.equal(plan.modelCalls, 2);
    assert.equal(plan.coverage.samplesProposed, 1);
    assert.equal(plan.coverage.samplesSent, 0);
    assert.equal(plan.decisions[1].reason, 'unreviewed-method');
    assert.equal(requests, 0);
    assert.ok(!JSON.stringify(plan.decisions).includes(secret));
  } finally {fs.rmSync(dir, {recursive: true, force: true});}
});
