import test from 'node:test';
import assert from 'node:assert/strict';
import {spawnSync} from 'node:child_process';
import http from 'node:http';
import {loadScope} from '../src/blackbox/scope.mjs';
import {followupResponseHints} from '../src/blackbox/host-audit.mjs';
import {planWebLeads, runWebProbes, planAuthLogins, runAuthLogins,
  runAuthInvestigation} from '../src/blackbox/web-probes.mjs';
import {modelExperimentReason, safeAuthUserPayload,
  validModelExperiment} from '../src/blackbox/poc-runtime.mjs';
import {domXssFragment, nosqlEqUrl, nosqlOperatorOracle, redirectPollutionUrl,
  redirectPollutionOracle, sqlBooleanCanary, sqlBooleanOracle,
  renderCapturedHtml, xssPayload} from '../src/blackbox/poc-runtime.mjs';

test('observed access-code endpoints are checked for effective throttling without Muse', async () => {
  const {scope} = loadScope({origin: 'http://127.0.0.1:4329',
    overrides: {acceptLocal: true, rps: 20}});
  const surface = {patterns: [], jsonBodyOperations: [{path: '/api/beta/unlock',
    method: 'POST', contentType: 'application/json', fields: ['code'],
    requiredFields: [], source: 'public-js',
    purpose: 'Beta unlock API called with an access code.'}]};
  const requests = [];
  const requester = async options => {
    requests.push(options);
    const body = JSON.stringify({ok: false});
    return {status: 200, type: 'application/json', body, bytes: body.length,
      headers: {'content-type': 'application/json', 'cache-control': 'no-store'},
      evidenceId: `ev-${String(requests.length).padStart(4, '0')}`};
  };
  const run = await runWebProbes(surface, scope, {requester, budget: 1});
  const result = run.results.find(item => item.kind === 'rate-limit-auth-gate');
  const finding = run.findings.find(item => item.kind === 'rate-limit-auth-gate');
  assert.equal(result?.verdict, 'confirmed', JSON.stringify(result));
  assert.equal(requests.length, 20);
  assert.ok(requests.every(item => item.method === 'POST' && item.purpose === 'json-body'));
  assert.ok(requests.every(item => JSON.parse(item.body).code.startsWith('bypass-audit-invalid-')));
  assert.equal(finding?.cwe, 'CWE-307');
  assert.equal(finding?.webProof.attemptCount, 20);
});

test('queued web checks use reserved execution time after Muse planning ends', async () => {
  const {scope} = loadScope({origin: 'http://127.0.0.1:4329',
    overrides: {acceptLocal: true, rps: 20}});
  const surface = {patterns: [], jsonBodyOperations: [{path: '/api/beta/unlock',
    method: 'POST', contentType: 'application/json', fields: ['code'],
    requiredFields: [], source: 'public-js', purpose: 'Beta unlock access code.'}]};
  let requests = 0;
  const requester = async () => ({status: 401, type: 'application/json',
    body: '{}', headers: {}, evidenceId: `ev-${++requests}`});
  const researchDeadline = Date.now() - 1;
  const expired = await runWebProbes(surface, scope, {requester, budget: 1,
    researchDeadline});
  assert.equal(requests, 0);
  assert.equal(expired.results[0]?.verdict, 'untested');

  const reserved = await runWebProbes(surface, scope, {requester, budget: 1,
    researchDeadline, executionDeadline: Date.now() + 10_000});
  assert.ok(requests > 0);
  assert.notEqual(reserved.results[0]?.verdict, 'untested');
  assert.equal(reserved.modelCalls, 0);
});

test('an access-gate burst replaces one transport failure without exceeding its cap', async () => {
  const {scope} = loadScope({origin: 'http://127.0.0.1:4329',
    overrides: {acceptLocal: true, rps: 20}});
  const surface = {patterns: [], jsonBodyOperations: [{path: '/api/beta/unlock',
    method: 'POST', contentType: 'application/json', fields: ['code'],
    requiredFields: [], source: 'public-js', purpose: 'Beta unlock access code.'}]};
  let requests = 0;
  const run = await runWebProbes(surface, scope, {budget: 1, requester: async () => {
    requests++;
    if (requests === 7) return {blocked: true, reason: 'Request failed: ECONNRESET',
      evidenceId: `ev-${requests}`};
    return {status: 200, type: 'application/json', body: '{"ok":false}',
      headers: {'content-type': 'application/json'}, evidenceId: `ev-${requests}`};
  }});
  assert.equal(run.results.find(item => item.kind === 'rate-limit-auth-gate')?.verdict,
    'confirmed');
  assert.equal(requests, 21);
});

test('an explicit throttle prevents an authentication rate-limit finding', async () => {
  const loaded = loadScope({origin: 'http://127.0.0.1:4329',
    overrides: {acceptLocal: true, rps: 20}});
  const scope = structuredClone(loaded.scope);
  scope.target.environment = 'production';
  scope.authorizedOrigins = {[scope.target.origin]: {authorization: {
    methods: ['GET', 'HEAD', 'POST']}}};
  const surface = {patterns: [], jsonBodyOperations: [{path: '/api/login',
    method: 'POST', contentType: 'application/json', fields: ['email', 'password'],
    requiredFields: ['email', 'password'], source: 'public-openapi', purpose: 'User login.'}]};
  let requests = 0;
  const run = await runWebProbes(surface, scope, {budget: 1, requester: async () => {
    requests++;
    const throttled = requests >= 6;
    const body = JSON.stringify({ok: false});
    return {status: throttled ? 429 : 401, type: 'application/json', body,
      bytes: body.length, headers: throttled ? {'retry-after': '30'} : {},
      evidenceId: `ev-${requests}`};
  }});
  assert.equal(run.results.find(item => item.kind === 'rate-limit-auth-gate')?.verdict,
    'not_reproduced');
  assert.ok(!run.findings.some(item => item.kind === 'rate-limit-auth-gate'));
});

test('registration contracts are never selected for automatic rate-limit attempts', async () => {
  const {scope} = loadScope({origin: 'http://127.0.0.1:4329',
    overrides: {acceptLocal: true, rps: 20}});
  const surface = {patterns: [], jsonBodyOperations: [{path: '/api/register',
    method: 'POST', contentType: 'application/json', fields: ['email', 'password'],
    requiredFields: ['email', 'password'], source: 'public-openapi', purpose: 'Create account.'}]};
  const planned = await planWebLeads(surface, scope, {budget: 10});
  assert.ok(!planned.leads.some(item => item.kind === 'rate-limit-auth-gate'));
});

test('web audit executes each Muse HTTP page before the next page and does not repeat it', async () => {
  const {scope} = loadScope({origin: 'http://127.0.0.1:4329',
    overrides: {acceptLocal: true}});
  const paths = Array.from({length: 9}, (_, index) => `/research-${index}`);
  const surface = {patterns: paths.map(pattern => ({pattern, methods: ['GET'],
    params: {probe: ['control']}, responseFacts: {status: 200, type: 'application/json'}}))};
  let pages = 0, requests = 0;
  const flow = (path, context) => ({family: 'route-feedback', why: 'Check observed input',
    priority: 8, as: 'anonymous', oracle: 'observation', protectedPath: '',
    prelude: [], subject: {method: 'GET', path, placement: 'query', key: 'probe',
      fixedFields: [], bodyTemplate: '', headers: []}, observe: [], binding: null,
    controlValue: 'control', firstValue: 'first', secondValue: 'second',
    marker: context.marker, secondMarker: context.secondMarker,
    assertion: {step: 'subject', index: 0, location: 'body', name: ''}});
  const infer = async (_model, messages) => {
    const system = messages[0].content;
    const context = JSON.parse(messages[1].content);
    if (system.startsWith('Allocate the next black-box investigation effort'))
      return {priorities: [{name: 'sequence', weight: 100,
        why: 'Observed query inputs warrant a first pass'}]};
    if (system.startsWith('You are planning bounded, authorized HTTP research.')) {
      pages++;
      if (pages === 2) assert.ok(context.priorSequenceResults?.some(item =>
        item.path === paths[0] && item.reason.includes('stable response difference')),
      'the first sequence result must precede the next Muse plan');
      return {flows: [flow(pages === 1 ? paths[0] : paths[8], context)]};
    }
    if (system.startsWith('Revise at most one bounded, authorized HTTP experiment'))
      return {flows: []};
    return {priorities: [], strategies: [], experiments: [], flows: [],
      checks: [], tasks: [], plans: [], samples: []};
  };
  const requester = async ({url}) => {
    requests++;
    const value = new URL(url, scope.target.origin).searchParams.get('probe');
    const status = value === 'first' ? 202 : value === 'second' ? 201 : 200;
    const body = JSON.stringify({accepted: status === 202});
    return {status, type: 'application/json', body, bytes: body.length,
      headers: {'content-type': 'application/json', 'cache-control': 'no-store'},
      evidenceId: `ev-${String(requests).padStart(4, '0')}`};
  };
  const run = await runWebProbes(surface, scope, {requester, infer,
    model: {model: 'fixture'}, budget: 30, maxModelPages: 30});
  assert.equal(pages, 2);
  const sequences = run.results.filter(item => item.kind === 'model-http-observation');
  assert.equal(sequences.length, 2, 'accepted page tests must not execute twice');
  assert.equal(sequences.filter(item => item.verdict === 'inconclusive').length, 2);
  assert.equal(run.modelCoverage.httpSequenceAccepted, 2);
});

test('reallocated Muse calls execute HTTP pages with prior response feedback', async () => {
  const {scope} = loadScope({origin: 'http://127.0.0.1:4329',
    overrides: {acceptLocal: true}});
  const paths = Array.from({length: 9}, (_, index) => `/rollover-${index}`);
  const surface = {patterns: paths.map(pattern => ({pattern, methods: ['GET'],
    params: {probe: ['control']}, responseFacts: {status: 200, type: 'application/json'}}))};
  let pages = 0, requests = 0, modelCalls = 0;
  const infer = async (_model, messages) => {
    modelCalls++;
    const system = messages[0].content;
    const context = JSON.parse(messages[1].content);
    if (system.startsWith('Allocate the next black-box investigation effort'))
      return {priorities: [
        {name: 'sequence', weight: 1, why: 'Check observed inputs'},
        {name: 'session', weight: 100, why: 'Reserve calls that cannot be used without an account'},
      ]};
    if (system.startsWith('You are planning bounded, authorized HTTP research.')) {
      pages++;
      if (pages === 2) assert.ok(context.priorSequenceResults?.some(item =>
        item.path === paths[0] && item.reason.includes('stable response difference')),
      'the rollover first-page result must reach Muse before its second page');
      return {flows: [{family: 'rollover-feedback', why: 'Check observed input',
        priority: 8, as: 'anonymous', oracle: 'observation', protectedPath: '',
        prelude: [], subject: {method: 'GET', path: pages === 1 ? paths[0] : paths[8],
          placement: 'query', key: 'probe', fixedFields: [], bodyTemplate: '', headers: []},
        observe: [], binding: null, controlValue: 'control', firstValue: 'first',
        secondValue: 'second', marker: context.marker, secondMarker: context.secondMarker,
        assertion: {step: 'subject', index: 0, location: 'body', name: ''}}]};
    }
    if (system.startsWith('Revise at most one bounded, authorized HTTP experiment'))
      return {flows: []};
    return {priorities: [], strategies: [], experiments: [], flows: [],
      checks: [], tasks: [], plans: [], samples: []};
  };
  const requester = async ({url}) => {
    requests++;
    const value = new URL(url, scope.target.origin).searchParams.get('probe');
    const status = value === 'first' ? 202 : value === 'second' ? 201 : 200;
    const body = JSON.stringify({accepted: status === 202});
    return {status, type: 'application/json', body, bytes: body.length,
      headers: {'content-type': 'application/json', 'cache-control': 'no-store'},
      evidenceId: `ev-${String(requests).padStart(4, '0')}`};
  };
  const run = await runWebProbes(surface, scope, {requester, infer,
    model: {model: 'fixture'}, budget: 100, maxModelPages: 14});
  assert.equal(pages, 2, JSON.stringify(run.modelCoverage));
  const sequences = run.results.filter(item => item.kind === 'model-http-observation');
  assert.equal(sequences.length, 2, 'rollover pages must not execute twice');
  assert.equal(sequences.filter(item => item.verdict === 'inconclusive').length, 2);
  assert.equal(run.modelCalls, modelCalls, 'HTTP execution calls count once');
  assert.ok(requests >= 6);
});

test('a protected file finding carries the fresh derived-login proof recipe', async () => {
  const {scope} = loadScope({origin: 'http://127.0.0.1:4329',
    overrides: {acceptLocal: true}});
  const loginProof = {kind: 'model-auth-login', auth: 'cookie',
    loginPath: '/login', privatePath: '/private'};
  const surface = {patterns: [{pattern: '/private/file', methods: ['GET'],
    params: {path: []}, responseFacts: {identity: 'derived-session', status: 200,
      anonymousStatus: 401, type: 'text/plain'}}]};
  let evidence = 0;
  const reply = (status, body, hash = body) => ({status, body,
    type: 'text/plain', headers: {'cache-control': 'no-store'},
    hash, evidenceId: `ev-${++evidence}`});
  const run = await runWebProbes(surface, scope, {budget: 50, maxModelPages: 0,
    requester: async () => reply(401, 'denied'),
    derivedSession: {loginProof, requestAuthenticated: async ({url}) => {
      const value = new URL(url, scope.target.origin).searchParams.get('path') ?? '';
      return /^(?:\.\.\/){12,13}etc\/hosts$/.test(value) ?
        reply(200, '127.0.0.1 localhost\n127.0.1.1 fixture\n', 'hosts') :
        reply(404, 'missing');
    }}});
  const finding = run.findings.find(item => item.kind === 'path-traversal-hosts');
  assert.ok(finding, JSON.stringify(run.results.filter(item =>
    item.kind === 'path-traversal-hosts')));
  assert.equal(finding.webProof.request.as, 'derived');
  assert.deepEqual(finding.webProof.derivedLogin, loginProof);
  assert.equal(finding.webProof.auth, 'cookie');
});

test('Muse ranks only documented web leads and cannot add a new route or parameter', async () => {
  const {scope} = loadScope({origin: 'http://127.0.0.1:4329', overrides: {acceptLocal: true}});
  const surface = {patterns: [
    {pattern: '/api/go', params: {next: []}, source: ['public-openapi']},
    {pattern: '/api/fetch', params: {url: []}, source: ['public-openapi']},
  ], modelNotes: [{path: '/api/go', purpose: 'user navigation'}]};
  const baseline = await planWebLeads(surface, scope, {budget: 1});
  assert.deepEqual(baseline.selected.map(item => item.kind), ['ssrf-loopback']);
  let calls = 0;
  const modeled = await planWebLeads(surface, scope, {budget: 1, model: {model: 'fixture'},
    infer: async (_model, messages) => {
      calls++;
      assert.match(messages[1].content, /user navigation/);
      return {priorities: [
        {kind: 'open-redirect', path: '/api/go', parameter: 'next', priority: 10, why: 'Navigation destination'},
        {kind: 'ssrf-loopback', path: '/api/unknown', parameter: 'url', priority: 10, why: 'Invented'},
      ]};
    }});
  assert.equal(calls, 1);
  assert.deepEqual(modeled.selected.map(item => [item.kind, item.path, item.by]),
    [['open-redirect', '/api/go', 'model']]);
  assert.equal(modeled.cut, 14);
  const disabled = await planWebLeads(surface,
    {...scope, probes: {...scope.probes, crlfResponseHeader: false}}, {budget: 20});
  assert.ok(!disabled.selected.some(item => item.kind === 'crlf-header'));
});

test('web planning reserves time for executing queued checks', async () => {
  const {scope} = loadScope({origin: 'http://127.0.0.1:4329', overrides: {acceptLocal: true}});
  const surface = {patterns: [{pattern: '/api/go', methods: ['GET'],
    params: {next: []}, source: ['public-openapi']}]};
  const planned = await planWebLeads(surface, scope, {budget: 20, model: {model: 'fixture'},
    researchDeadline: 0,
    infer: async () => {throw Error('Model planning should have stopped before this call.');}});
  assert.equal(planned.modelCoverage.pagesSent, 0);
  assert.ok(planned.modelCoverage.pagesAvailable > 0);
  assert.ok(planned.selected.length > 0, 'observed baseline checks remain queued');
});

test('the web planner receives the observed response type from guarded recon', async () => {
  const {scope} = loadScope({origin: 'http://127.0.0.1:4329', overrides: {acceptLocal: true}});
  const surface = {patterns: [{pattern: '/api/preview', methods: ['GET'],
    params: {caption: ['hello']}, source: ['public-openapi'], label: {kind: 'unknown'}}]};
  await followupResponseHints(scope.target.origin, scope, surface.patterns, {
    requester: async () => ({status: 200, type: 'text/html; charset=utf-8',
      body: '<html>Preview</html>', evidenceId: 'ev-0001'}),
    infer: async () => ({paths: []}), model: {model: 'fixture'}, maxModelPages: 1});
  assert.equal(surface.patterns[0].responseFacts.status, 200);
  assert.equal(surface.patterns[0].responseFacts.type, 'text/html; charset=utf-8');
  let seen = false;
  await planWebLeads(surface, scope, {budget: 100, model: {model: 'fixture'},
    infer: async (_model, messages) => {
      const rows = JSON.parse(messages[1].content).candidates;
      const xss = rows.find(row => row.kind === 'xss-reflected' && row.path === '/api/preview');
      assert.deepEqual(xss?.observedResponse,
        {status: 200, contentType: 'text/html; charset=utf-8'});
      seen = true;
      return {priorities: [], strategies: [], experiments: []};
    }});
  assert.equal(seen, true);
});

test('Muse GET revisions receive recon facts for every observed alternative', async () => {
  const {scope} = loadScope({origin: 'http://127.0.0.1:4329', overrides: {acceptLocal: true}});
  const surface = {patterns: [
    {pattern: '/api/evaluate', params: {expression: []}, source: ['public-openapi'],
      responseFacts: {status: 200, type: 'application/json'}},
    {pattern: '/api/preview', params: {caption: []}, source: ['public-openapi'],
      responseFacts: {status: 200, type: 'text/html; charset=utf-8'}},
  ], modelNotes: [{path: '/api/evaluate', purpose: 'calculate an expression',
    parameterMeanings: [{name: 'expression', meaning: 'expression to evaluate'}]},
  {path: '/api/preview', purpose: 'render a caption',
    parameterMeanings: [{name: 'caption', meaning: 'caption rendered in HTML'}]}]};
  let revisions = 0, requests = 0;
  const infer = async (_model, messages) => {
    const context = JSON.parse(messages[1].content);
    if (messages[0].content.includes('Rank only the supplied observed read-only web-test candidates'))
      return {priorities: [], strategies: [], experiments: [{family: 'unlisted-evaluation',
        path: '/api/evaluate', parameter: 'expression', controlValue: '7',
        firstValue: `String.fromCharCode(${[...context.canary].map(char => char.charCodeAt(0)).join(',')})`,
        secondValue: `[${[...context.secondCanary].map(char => JSON.stringify(char)).join(',')}].join('')`,
        marker: context.canary, secondMarker: context.secondCanary,
        prelude: [], headers: [], priority: 10, why: 'Observed expression input'}]};
    if (messages[0].content.includes('Revise one inconclusive')) {
      revisions++;
      const inputs = new Map(context.observedInputs.map(item => [item.path, item]));
      assert.deepEqual(inputs.get('/api/evaluate')?.observedResponse,
        {status: 200, contentType: 'application/json'});
      assert.deepEqual(inputs.get('/api/preview')?.observedResponse,
        {status: 200, contentType: 'text/html; charset=utf-8'});
      assert.equal(inputs.get('/api/evaluate')?.parameterMeaning, 'expression to evaluate');
      assert.equal(inputs.get('/api/preview')?.purpose, 'render a caption');
      return {experiments: []};
    }
    return {paths: [], notes: [], tasks: [], proposals: []};
  };
  const requester = async () => {
    requests++;
    return {status: 200, type: 'application/json', body: '{"result":7}', bytes: 12,
      ms: 1, headers: {'content-type': 'application/json'}, cached: false,
      evidenceId: `ev-${String(requests).padStart(4, '0')}`};
  };
  const run = await runWebProbes(surface, scope, {requester, infer,
    model: {model: 'fixture'}, budget: 1, maxModelPages: 8});
  assert.equal(revisions, 1);
  assert.equal(run.investigations.length, 1);
});

test('Muse GET revision pages reach an alternative after the former 48-input window', async () => {
  const {scope} = loadScope({origin: 'http://127.0.0.1:4329', overrides: {acceptLocal: true}});
  const patterns = Array.from({length: 54}, (_, index) => ({
    pattern: `/api/ordinary-${index}`, methods: ['GET'],
    params: {expression: []}, source: ['public-openapi']}));
  patterns.push({pattern: '/api/late', methods: ['GET'], params: {expression: []},
    source: ['public-openapi']});
  const surface = {patterns};
  const encode = value => `hex:${Buffer.from(value).toString('hex')}`;
  const proposal = (context, path) => ({family: 'unlisted-evaluation', path,
    parameter: 'expression', controlValue: 'plain', firstValue: encode(context.canary),
    secondValue: encode(context.secondCanary), marker: context.canary,
    secondMarker: context.secondCanary, prelude: [], headers: [], priority: 10,
    why: 'Observed expression input may decode hex'});
  const revisionPages = [];
  let requests = 0;
  const infer = async (_model, messages) => {
    const context = JSON.parse(messages[1].content);
    if (messages[0].content.includes('Rank only the supplied observed read-only web-test candidates'))
      return {priorities: [], strategies: [], experiments:
        context.candidates.some(item => item.path === '/api/ordinary-0') ?
          [proposal(context, '/api/ordinary-0')] : []};
    if (messages[0].content.includes('Revise one inconclusive')) {
      revisionPages.push(context.observedInputs.map(item => item.path));
      assert.ok(Buffer.byteLength(messages[1].content) <= 20000);
      return {experiments: context.observedInputs.some(item => item.path === '/api/late') ?
        [proposal(context, '/api/late')] : []};
    }
    return {plans: [], checks: [], priorities: [], strategies: [], experiments: []};
  };
  const requester = async ({url}) => {
    requests++;
    const parsed = new URL(url, scope.target.origin);
    const input = parsed.searchParams.get('expression') ?? '';
    const result = parsed.pathname === '/api/late' && input.startsWith('hex:') ?
      Buffer.from(input.slice(4), 'hex').toString() : 'plain';
    const body = JSON.stringify({result});
    return {status: 200, type: 'application/json', body, bytes: body.length,
      headers: {'content-type': 'application/json'}, cached: false,
      evidenceId: `ev-${String(requests).padStart(4, '0')}`};
  };
  const run = await runWebProbes(surface, scope, {requester, infer,
    model: {model: 'fixture'}, budget: 1, maxModelPages: 40});
  assert.ok(revisionPages.length >= 2, JSON.stringify(revisionPages.map(page => page.length)));
  assert.ok(!revisionPages[0].includes('/api/late'));
  assert.ok(revisionPages.some(page => page.includes('/api/late')));
  assert.ok(run.investigations.some(item => item.final.path === '/api/late' &&
    item.final.verdict === 'confirmed'));
  assert.ok(run.modelCoverage.adaptiveObservedInputsSent >= 55);
  assert.equal(run.modelCoverage.adaptiveObservedInputsCut, 0);
});

test('anonymous auth proof requires two syntax probes with fresh invalid passwords and a private principal', async () => {
  const {scope} = loadScope({origin: 'http://127.0.0.1:4329', overrides: {acceptLocal: true}});
  const lead = {path: '/api/session', loginPath: '/api/session', userField: 'user',
    passwordField: 'password', userPayloads: ["' OR '1'='1", "') OR (1=1)--"],
    tokenPointer: '/authentication/token', privatePath: '/api/me',
    principalPointer: '/user/id', why: 'Observed login fields accept syntax probes'};
  const requests = [], passwords = new Set(), issued = new Set();
  const requester = async options => {
    requests.push(options);
    const evidenceId = `ev-${String(requests.length).padStart(4, '0')}`;
    if (options.method === 'POST') {
      assert.equal(options.purpose, 'auth-body');
      assert.equal(options.rawForAuthProof, true);
      const body = JSON.parse(options.body);
      passwords.add(body.password);
      const accepted = lead.userPayloads.includes(body.user);
      const token = accepted ? `bx-session-${String(requests.length).padStart(20, '0')}` : null;
      if (token) issued.add(token);
      return {status: accepted ? 200 : 401, type: 'application/json', body: '',
        rawBody: JSON.stringify(accepted ? {authentication: {token}} : {error: 'invalid'}),
        headers: {}, evidenceId};
    }
    const allowed = issued.has(options.derivedBearer);
    return {status: 200, type: 'application/json', body: JSON.stringify(allowed ?
      {user: {id: 47}} : {}), headers: {}, evidenceId};
  };
  const run = await runAuthLogins([lead], scope, {requester});
  assert.equal(run.results[0].verdict, 'confirmed');
  assert.equal(run.findings[0].webProof.principalPointer, '/user/id');
  assert.equal(passwords.size, 2);
  assert.equal(requests.length, 14);
  assert.ok(!JSON.stringify(run).includes('bx-session-'));
  assert.ok(!JSON.stringify(run).includes('bx-invalid-'));
});

test('Muse can select a cookie login and pass its transient session into protected recon', async () => {
  const {scope: loaded} = loadScope({origin: 'http://127.0.0.1:4329',
    overrides: {acceptLocal: true}});
  const scope = structuredClone(loaded);
  scope.identities.auth = 'cookie';
  scope.localAuthPostContracts = {'/api/session': {path: '/api/session',
    method: 'POST', contentType: 'application/json', fields: ['user', 'password'],
    usernameField: 'user', passwordField: 'password'}};
  const surface = {authBodyOperations: Object.values(scope.localAuthPostContracts),
    patterns: [{pattern: '/api/private', methods: ['GET'], params: {},
      responseFacts: {status: 401, type: 'application/json'}}]};
  const payload = "' OR '1'='1";
  const plan = await planAuthLogins(surface, scope, {model: {model: 'fixture'},
    modelCallsAvailable: 1, budget: 1, infer: async (_model, messages) => {
      const context = JSON.parse(messages[1].content);
      assert.equal(context.sessionKind, 'cookie');
      return {checks: [{loginPath: '/api/session', userField: 'user',
        passwordField: 'password', proofMode: 'protected-status',
        userPayloads: [payload], tokenPointer: '', privatePath: '/api/private',
        why: 'Observed login and denied private read'}]};
    }});
  assert.equal(plan.leads.length, 1, JSON.stringify(plan.decisions));
  assert.equal(plan.leads[0].tokenPointer, null);
  const issued = new Set(), calls = [];
  const requester = async options => {
    calls.push(options);
    const evidenceId = `ev-${String(calls.length).padStart(4, '0')}`;
    if (options.method === 'POST') {
      const input = JSON.parse(options.body);
      const accepted = input.user === payload;
      const pair = accepted ? `session=bx-cookie-${String(calls.length).padStart(20, '0')}` : null;
      if (pair) issued.add(pair);
      return {status: accepted ? 200 : 401, type: 'text/html',
        body: '', rawBody: '', headers: {}, rawSetCookie: pair ?
          [`${pair}; HttpOnly`, 'csrf=not-a-session; HttpOnly'] : [], evidenceId};
    }
    return {status: issued.has(options.derivedCookie) ? 200 : 401,
      type: 'application/json', body: issued.has(options.derivedCookie) ?
        '{"ok":true}' : '{}', headers: {}, evidenceId};
  };
  let handoff = null;
  const run = await runAuthLogins(plan.leads, scope, {requester, surface,
    onConfirmedSession: async session => {
      handoff = session.derivedCookie;
      const read = await session.requestAuthenticated({url: '/api/private'});
      assert.equal(read.status, 200);
      const callback = `http://127.0.0.1:34567/bx-ssrf/${'a'.repeat(24)}`;
      await session.requestAuthenticated({url: '/api/private', method: 'POST',
        purpose: 'json-body', headers: {'content-type': 'application/json'},
        body: JSON.stringify({url: callback}), auditCallback: callback});
      assert.equal(calls.at(-1).auditCallback, callback,
        'the derived wrapper must preserve the harness-owned callback');
    }});
  assert.equal(run.results[0].verdict, 'confirmed');
  assert.equal(run.findings[0].webProof.tokenPointer, null);
  assert.match(handoff, /^session=bx-cookie-/);
  assert.ok(calls.some(item => item.derivedCookie?.startsWith('session=bx-invalid-')),
    'invalid cookie controls must use the discovered session name');
  assert.ok(!JSON.stringify(run).includes('bx-cookie-'));
});

test('Muse auth planning accepts only an observed exact login body and private read', async () => {
  const {scope: loaded} = loadScope({origin: 'http://127.0.0.1:4329',
    overrides: {acceptLocal: true}});
  const scope = structuredClone(loaded);
  scope.localAuthPostContracts = {'/api/session': {path: '/api/session',
    method: 'POST', contentType: 'application/json', fields: ['user', 'password'],
    usernameField: 'user', passwordField: 'password'}};
  const surface = {authBodyOperations: Object.values(scope.localAuthPostContracts),
    modelNotes: [{path: '/api/session', method: 'POST', purpose: 'authenticate a user'}],
    patterns: [{pattern: '/api/me', methods: ['GET'], params: {},
      responseFacts: {status: 200, type: 'application/json', shape: {user: {id: 'number'}}}}]};
  let calls = 0;
  const infer = async (_model, messages) => {
    calls++;
    const context = JSON.parse(messages[1].content);
    assert.deepEqual(context.posts.map(item => [item.path, item.usernameField, item.passwordField]),
      [['/api/session', 'user', 'password']]);
    assert.equal(context.posts[0].purpose, 'authenticate a user');
    assert.deepEqual(context.reads.map(item => item.path), ['/api/me']);
    return {checks: [{loginPath: '/api/session', userField: 'user', passwordField: 'password',
      userPayloads: ["' OR '1'='1", "') OR (1=1)--"], tokenPointer: '/authentication/token',
      privatePath: '/api/me', principalPointer: '/user/id', why: 'Observed login syntax'}]};
  };
  const plan = await planAuthLogins(surface, scope, {infer, model: {model: 'fixture'},
    budget: 1, modelCallsAvailable: 1});
  assert.equal(calls, 1);
  assert.equal(plan.leads.length, 1);
  assert.equal(plan.decisions[0].accepted, true);
  const rejected = await planAuthLogins(surface, scope, {infer: async () => ({checks: [{
    loginPath: '/api/unobserved', userField: 'user', passwordField: 'password',
    userPayloads: ["' OR '1'='1", "') OR (1=1)--"], tokenPointer: '/authentication/token',
    privatePath: '/api/me', principalPointer: '/user/id', why: 'Unobserved route'}]}),
  model: {model: 'fixture'}, budget: 1, modelCallsAvailable: 1});
  assert.equal(rejected.leads.length, 0);
  assert.equal(rejected.decisions[0].reason, 'unobserved-contract-or-read');
});

test('Muse can plan an observed login on an explicitly authorized deployed origin', async () => {
  const {scope: loaded} = loadScope({origin: 'http://127.0.0.1:4329',
    overrides: {acceptLocal: true}});
  const scope = structuredClone(loaded);
  const origin = 'https://app.example.invalid';
  scope.target = {origin, environment: 'staging', acknowledged: 'verified-authorized'};
  scope.credentialOrigins = [origin];
  scope.authorizedOrigins = {[origin]: {authorization: {methods: ['GET', 'HEAD', 'POST']}}};
  scope.localAuthPostContracts = {'/api/session': {path: '/api/session',
    method: 'POST', contentType: 'application/json', fields: ['email', 'password'],
    usernameField: 'email', passwordField: 'password'}};
  const surface = {authBodyOperations: Object.values(scope.localAuthPostContracts),
    patterns: [{pattern: '/api/me', methods: ['GET'], params: {},
      responseFacts: {status: 401, type: 'application/json'}}]};
  const infer = async () => ({checks: [{loginPath: '/api/session', userField: 'email',
    passwordField: 'password', userPayloads: ["test@example.invalid' OR 1=1-- "],
    proofMode: 'protected-status', tokenPointer: '/token', privatePath: '/api/me',
    why: 'The observed login input may bypass a denied identity read'}]});
  const allowed = await planAuthLogins(surface, scope, {infer, model: {model: 'fixture'},
    budget: 1, modelCallsAvailable: 1});
  assert.equal(allowed.leads.length, 1);
  assert.equal(allowed.decisions[0].accepted, true);
  const unapproved = structuredClone(scope);
  delete unapproved.authorizedOrigins;
  const denied = await planAuthLogins(surface, unapproved, {infer,
    model: {model: 'fixture'}, budget: 1, modelCallsAvailable: 1});
  assert.equal(denied.coverage.postsAvailable, 0);
  assert.equal(denied.leads.length, 0);
});

test('auth planning rotates observed reads after an empty first model page', async () => {
  const {scope: loaded} = loadScope({origin: 'http://127.0.0.1:4329',
    overrides: {acceptLocal: true}});
  const scope = structuredClone(loaded);
  scope.localAuthPostContracts = {'/api/session': {path: '/api/session',
    method: 'POST', contentType: 'application/json', fields: ['user', 'password'],
    usernameField: 'user', passwordField: 'password'}};
  const paths = Array.from({length: 80}, (_, index) => `/api/view-${index}`);
  const surface = {authBodyOperations: Object.values(scope.localAuthPostContracts),
    patterns: paths.map(pattern => ({pattern, methods: ['GET'], params: {},
      responseFacts: {status: 200, type: 'application/json'}}))};
  const first = await planAuthLogins(surface, scope, {model: {model: 'fixture'},
    budget: 1, modelCallsAvailable: 1, infer: async () => ({checks: []})});
  assert.equal(first.coverage.readsSent, 48);
  const late = paths[79];
  assert.ok(!first.reviewedReadPaths.includes(late));
  const second = await planAuthLogins(surface, scope, {model: {model: 'fixture'},
    budget: 1, modelCallsAvailable: 1,
    reviewedReadPaths: first.reviewedReadPaths, infer: async (_model, messages) => {
      const context = JSON.parse(messages[1].content);
      assert.ok(context.reads.some(item => item.path === late));
      return {checks: [{loginPath: '/api/session', userField: 'user',
        passwordField: 'password', userPayloads: ["' OR 1=1--", "') OR 1=1--"],
        proofMode: 'principal', tokenPointer: '/token', privatePath: late,
        principalPointer: '/user/id', why: 'Test observed late read'}]};
    }});
  assert.equal(second.leads[0]?.privatePath, late);
});

test('Muse auth planning preserves requested payload syntax without saving values in decisions', async () => {
  const {scope: loaded} = loadScope({origin: 'http://127.0.0.1:4329',
    overrides: {acceptLocal: true}});
  const scope = structuredClone(loaded);
  scope.localAuthPostContracts = {'/api/session': {path: '/api/session',
    method: 'POST', contentType: 'application/json', fields: ['email', 'password'],
    usernameField: 'email', passwordField: 'password'}};
  const surface = {authBodyOperations: Object.values(scope.localAuthPostContracts),
    patterns: [{pattern: '/api/identity', methods: ['GET'], params: {},
      responseFacts: {status: 401, type: 'application/json', shape: null}}]};
  const synthetic = "bx-probe@example.invalid' OR 1=1--";
  const realAddress = "person@somewhere.com' OR 1=1--";
  assert.equal(safeAuthUserPayload(synthetic), true);
  assert.equal(safeAuthUserPayload(realAddress), true);
  const proposal = userPayloads => ({loginPath: '/api/session', userField: 'email',
    passwordField: 'password', userPayloads, proofMode: 'protected-status',
    tokenPointer: '/token', privatePath: '/api/identity', why: 'Observed denied identity route'});
  const planned = await planAuthLogins(surface, scope, {model: {model: 'fixture'},
    budget: 3, modelCallsAvailable: 1, retryEmpty: {rejectedReasons: ['auth-probe-non-synthetic-address']},
    infer: async (_model, messages) => {
      assert.match(messages[0].content, /observed contract and prior response feedback/);
      assert.equal(JSON.parse(messages[1].content).reconsideration.deniedReadIds[0], 'read-1');
      return {checks: [proposal([realAddress]), proposal([synthetic]),
        proposal(["' OR 1=1; DROP TABLE users"])]};
    }});
  assert.equal(planned.leads.length, 3);
  assert.deepEqual(planned.leads.map(item => item.userPayloads[0]),
    [realAddress, synthetic, "' OR 1=1; DROP TABLE users"]);
  assert.ok(planned.decisions.every(item => item.accepted));
  assert.deepEqual(planned.decisions[0].probeShape,
    {count: 1, lengths: [realAddress.length], addressShaped: [true]});
  assert.equal(JSON.stringify(planned.decisions).includes(realAddress), false);
  assert.equal(JSON.stringify(planned.decisions).includes(synthetic), false);
});

test('Muse login pointers are normalized or extracted transiently for status proofs', async () => {
  const {scope: loaded} = loadScope({origin: 'http://127.0.0.1:4329',
    overrides: {acceptLocal: true}});
  const scope = structuredClone(loaded);
  scope.localAuthPostContracts = {'/api/session': {path: '/api/session',
    method: 'POST', contentType: 'application/json', fields: ['user', 'password'],
    usernameField: 'user', passwordField: 'password'}};
  const surface = {authBodyOperations: Object.values(scope.localAuthPostContracts),
    patterns: [{pattern: '/api/identity', methods: ['GET'], params: {},
      responseFacts: {status: 401, type: 'application/json'}}]};
  const proposal = (tokenPointer, userPayloads) => ({loginPath: '/api/session',
    userField: 'user', passwordField: 'password', userPayloads,
    proofMode: 'protected-status', tokenPointer, privatePath: '/api/identity',
    why: 'A synthetic syntax probe may cross the observed login boundary'});
  const plan = await planAuthLogins(surface, scope, {model: {model: 'fixture'},
    budget: 3, modelCallsAvailable: 1, infer: async () => ({checks: [
      proposal('$.authentication.token', ["' OR 1=1--"]),
      proposal('token', ["') OR 1=1--"]),
      proposal('$[0].token', ["' OR TRUE--"])]})});
  assert.deepEqual(plan.leads.map(item => item.tokenPointer),
    ['/authentication/token', '/token', null]);
  assert.deepEqual(plan.decisions.map(item => item.proofShape.tokenPointer),
    ['normalized', 'normalized', 'automatic']);
  assert.ok(plan.decisions.every(item => item.accepted));
  assert.equal(JSON.stringify(plan.decisions).includes("' OR 1=1--"), false);

  const principal = await planAuthLogins(surface, scope, {model: {model: 'fixture'},
    budget: 1, modelCallsAvailable: 1, infer: async () => ({checks: [
      {...proposal('$[0].token', ["' OR 1=1--", "') OR 1=1--"]),
        proofMode: 'principal', principalPointer: '/user/id'}]})});
  assert.equal(principal.leads.length, 0);
  assert.equal(principal.decisions[0].reason, 'invalid-proof-token-pointer');
  assert.equal(principal.decisions[0].proofShape.tokenPointer, 'invalid');
});

test('Muse can propose an auth experiment before any successful-login response shape is observed', async () => {
  const {scope: loaded} = loadScope({origin: 'http://127.0.0.1:4329',
    overrides: {acceptLocal: true}});
  const scope = structuredClone(loaded);
  scope.localAuthPostContracts = {'/api/session': {path: '/api/session',
    method: 'POST', contentType: 'application/json', fields: ['user', 'password'],
    usernameField: 'user', passwordField: 'password'}};
  const surface = {authBodyOperations: Object.values(scope.localAuthPostContracts),
    modelNotes: [{path: '/api/session', method: 'POST', purpose: 'authenticate a user'}],
    patterns: [{pattern: '/api/identity', methods: ['GET'], params: {},
      responseFacts: {status: 401, type: 'application/json', shape: null}}]};
  const proposal = {loginPath: '/api/session', userField: 'user', passwordField: 'password',
    userPayloads: ["' OR '1'='1", "') OR (1=1)--"], tokenPointer: '/authentication/token',
    privatePath: '/api/identity', principalPointer: '/user/id', why: 'Observed login and denied identity route'};
  const inferred = await planAuthLogins(surface, scope, {infer: async (_model, messages) => {
    assert.match(messages[0].content, /testable hypotheses, not facts requiring an already successful login/);
    assert.equal(messages[0].content.includes('up to three distinct'), true);
    const context = JSON.parse(messages[1].content);
    assert.deepEqual(context.reads.map(item => [item.path, item.anonymousStatus, item.responseShape]),
      [['/api/identity', 401, null]]);
    return {checks: [proposal, {...proposal, tokenPointer: '/token'},
      {...proposal, principalPointer: '/id'}]};
  }, model: {model: 'fixture'}, budget: 3, modelCallsAvailable: 1});
  assert.equal(inferred.leads.length, 3);
  assert.equal(inferred.decisions[0].accepted, true);
  assert.equal(inferred.decisions[2].accepted, true);
  const abstained = await planAuthLogins(surface, scope, {infer: async () => ({checks: []}),
    model: {model: 'fixture'}, budget: 3, modelCallsAvailable: 1});
  assert.equal(abstained.leads.length, 0);
  assert.equal(abstained.coverage.postsSent, 1);
  const repeated = await planAuthLogins(surface, scope, {infer: async () => ({checks: [proposal, proposal]}),
    model: {model: 'fixture'}, budget: 3, modelCallsAvailable: 1});
  assert.equal(repeated.leads.length, 1);
  assert.equal(repeated.decisions[1].accepted, false);
  assert.equal(repeated.decisions[1].reason, 'duplicate-lead');
  assert.equal(repeated.decisions[1].coalesced, true);
  assert.equal(repeated.decisions[1].coalescedInto, 'prior-auth-experiment');
});

test('protected-status auth mode retries a second syntax and confirms a denied-to-success route twice', async () => {
  const {scope: loaded} = loadScope({origin: 'http://127.0.0.1:4329',
    overrides: {acceptLocal: true}});
  const scope = structuredClone(loaded);
  scope.localAuthPostContracts = {'/api/session': {path: '/api/session',
    method: 'POST', contentType: 'application/json', fields: ['user', 'password'],
    usernameField: 'user', passwordField: 'password'}};
  const surface = {authBodyOperations: Object.values(scope.localAuthPostContracts),
    patterns: [{pattern: '/api/private', methods: ['GET'], params: {},
      responseFacts: {status: 401, type: 'application/json', shape: null}}]};
  const lead = {path: '/api/session', loginPath: '/api/session', userField: 'user',
    passwordField: 'password', userPayloads: ["' AND 1=0--", "' OR 1=1--"],
    proofMode: 'protected-status', tokenPointer: null, privatePath: '/api/private',
    why: 'Observed login and denied private route'};
  const plan = await planAuthLogins(surface, scope, {infer: async () => ({checks: [lead]}),
    model: {model: 'fixture'}, budget: 1, modelCallsAvailable: 1});
  assert.equal(plan.leads.length, 1);
  assert.equal(plan.decisions[0].accepted, true);
  assert.equal(plan.decisions[0].proofShape.tokenPointer, 'automatic');
  const issued = new Set(), passwords = new Set();
  let sequence = 0;
  const requester = async options => {
    const evidenceId = `ev-${String(++sequence).padStart(4, '0')}`;
    if (options.method === 'POST') {
      const body = JSON.parse(options.body);
      passwords.add(body.password);
      const accepted = body.user === lead.userPayloads[1];
      const token = accepted ? `bx-session-${String(sequence).padStart(20, '0')}` : null;
      if (token) issued.add(token);
      return {status: accepted ? 200 : 401, type: 'application/json', body: '',
        rawBody: JSON.stringify(accepted ? {token} : {}), headers: {}, evidenceId};
    }
    return {status: issued.has(options.derivedBearer) ? 200 : 401,
      type: 'application/json', body: '{}', headers: {}, evidenceId};
  };
  const run = await runAuthLogins(plan.leads, scope, {requester});
  assert.equal(run.results[0].verdict, 'confirmed');
  assert.equal(run.findings[0].webProof.proofMode, 'protected-status');
  assert.deepEqual(run.findings[0].webProof.userPayloads, [lead.userPayloads[1]]);
  assert.equal(passwords.size, 2);
  assert.equal(sequence, 11);
  assert.ok(!JSON.stringify(run).includes('bx-session-'));
});

test('a confirmed login preserves the protected follow-up window within the current Muse batch', async () => {
  const {scope} = loadScope({origin: 'http://127.0.0.1:4329',
    overrides: {acceptLocal: true}});
  const lead = {loginPath: '/api/session', userField: 'user', passwordField: 'password',
    userPayloads: ["' OR 1=1--"], proofMode: 'protected-status', tokenPointer: '/token',
    privatePath: '/api/private', why: 'Observed login and denied private route'};
  const issued = new Set();
  let requests = 0, sessionCallbacks = 0;
  const requester = async options => {
    requests++;
    if (options.method === 'POST') {
      const user = JSON.parse(options.body).user;
      const token = user === lead.userPayloads[0] ?
        `bx-session-${String(requests).padStart(20, '0')}` : null;
      if (token) issued.add(token);
      return {status: token ? 200 : 401, type: 'application/json', body: '',
        rawBody: JSON.stringify(token ? {token} : {}), headers: {},
        evidenceId: `ev-${requests}`};
    }
    return {status: issued.has(options.derivedBearer) ? 200 : 401,
      type: 'application/json', body: '{}', headers: {}, evidenceId: `ev-${requests}`};
  };
  const run = await runAuthLogins([lead, {...lead, loginPath: '/api/other'}], scope,
    {requester, onConfirmedSession: async () => {sessionCallbacks++;},
      researchDeadlineAfterConfirmation: () => 0});
  assert.equal(run.findings.length, 1);
  assert.equal(run.results[0].verdict, 'confirmed');
  assert.equal(run.results[1].verdict, 'untested');
  assert.equal(sessionCallbacks, 1);
  assert.equal(requests, 10, 'the second accepted login lead must make no request after the deadline');
});

test('a 500 from another auth syntax does not stop a successful status proof from repeating', async () => {
  const {scope} = loadScope({origin: 'http://127.0.0.1:4329', overrides: {acceptLocal: true}});
  const lead = {path: '/api/session', loginPath: '/api/session', userField: 'user',
    passwordField: 'password', userPayloads: ["' OR 1=1--", "') OR (1=1)--"],
    proofMode: 'protected-status', tokenPointer: '/token', privatePath: '/api/private',
    why: 'Observed login and denied private route'};
  const issued = new Set(), passwords = new Set();
  let requests = 0, errors = 0;
  const requester = async options => {
    const evidenceId = `ev-${String(++requests).padStart(4, '0')}`;
    if (options.method === 'POST') {
      const body = JSON.parse(options.body);
      passwords.add(body.password);
      if (body.user === lead.userPayloads[1]) {
        errors++;
        return {status: 500, type: 'application/json', body: '', rawBody: '{}', headers: {}, evidenceId};
      }
      const accepted = body.user === lead.userPayloads[0];
      const token = accepted ? `bx-session-${String(requests).padStart(20, '0')}` : null;
      if (token) issued.add(token);
      return {status: accepted ? 200 : 401, type: 'application/json', body: '',
        rawBody: JSON.stringify(accepted ? {token} : {}), headers: {}, evidenceId};
    }
    return {status: issued.has(options.derivedBearer) ? 200 : 401,
      type: 'application/json', body: '{}', headers: {}, evidenceId};
  };
  const run = await runAuthLogins([lead], scope, {requester});
  assert.equal(errors, 1);
  assert.equal(passwords.size, 2);
  assert.equal(run.results[0].verdict, 'confirmed');
  assert.deepEqual(run.findings[0].webProof.userPayloads, [lead.userPayloads[0]]);
  assert.ok(!JSON.stringify(run).includes('bx-session-'));
});

test('one Muse auth revision uses redacted feedback and fresh controls on the same observed contract', async () => {
  const {scope: loaded} = loadScope({origin: 'http://127.0.0.1:4329',
    overrides: {acceptLocal: true}});
  const scope = structuredClone(loaded);
  scope.localAuthPostContracts = {'/api/session': {path: '/api/session',
    method: 'POST', contentType: 'application/json', fields: ['user', 'password'],
    usernameField: 'user', passwordField: 'password'}};
  const surface = {authBodyOperations: Object.values(scope.localAuthPostContracts),
    patterns: [{pattern: '/api/private', methods: ['GET'], params: {},
      responseFacts: {status: 401, type: 'application/json', shape: null}}]};
  const first = "' AND 1=0--", second = "' OR 1=1--";
  let modelCalls = 0, requests = 0;
  const issued = new Set(), passwords = new Set();
  const infer = async (_model, messages) => {
    if (!messages[0].content.startsWith('From only the observed authorized JSON login operations'))
      return {priorities: [], strategies: [], experiments: [], plans: []};
    modelCalls++;
    const context = JSON.parse(messages[1].content);
    if (modelCalls === 2) {
      assert.equal(context.priorAttempts[0].userPayloads[0], first);
      assert.equal(context.priorAttempts[0].observations.some(item => item.status === 401), true);
      assert.ok(!messages[1].content.includes('bx-invalid-'));
      assert.ok(!messages[1].content.includes('bx-session-'));
    }
    return {checks: [{loginPath: '/api/session', userField: 'user', passwordField: 'password',
      userPayloads: [modelCalls === 1 ? first : second], proofMode: 'protected-status',
      tokenPointer: '/token', privatePath: '/api/private',
      why: 'Observed login and denied private route'}]};
  };
  const requester = async options => {
    const evidenceId = `ev-${String(++requests).padStart(4, '0')}`;
    if (options.method === 'POST') {
      const body = JSON.parse(options.body);
      passwords.add(body.password);
      const accepted = body.user === second;
      const token = accepted ? `bx-session-${String(requests).padStart(20, '0')}` : null;
      if (token) issued.add(token);
      return {status: accepted ? 200 : 401, type: 'application/json', body: '',
        rawBody: JSON.stringify(accepted ? {token} : {}),
        shape: accepted ? {token: 'string'} : {error: 'string'},
        headers: {}, evidenceId};
    }
    return {status: issued.has(options.derivedBearer) ? 200 : 401,
      type: 'application/json', body: '{}', shape: {}, headers: {}, evidenceId};
  };
  const run = await runWebProbes(surface, scope, {requester, infer,
    model: {model: 'fixture'}, budget: 2, maxModelPages: 2});
  assert.equal(modelCalls, 2);
  assert.equal(run.modelCoverage.authFollowupCalls, 1);
  assert.equal(run.modelCoverage.authFollowupAccepted, 1);
  assert.equal(run.results.filter(item => item.kind === 'model-auth-login').length, 2);
  assert.equal(run.findings.find(item => item.kind === 'model-auth-login')?.webProof.userPayloads[0], second);
  assert.ok(passwords.size >= 2);
  assert.ok(!JSON.stringify(run).includes('bx-session-'));
  assert.ok(!JSON.stringify(run).includes('bx-invalid-'));
});

test('protected-session model calls reduce the remaining primary planning allowance', async () => {
  const {scope: loaded} = loadScope({origin: 'http://127.0.0.1:4329',
    overrides: {acceptLocal: true}});
  const scope = structuredClone(loaded);
  scope.localAuthPostContracts = {'/api/session': {path: '/api/session',
    method: 'POST', contentType: 'application/json', fields: ['user', 'password'],
    usernameField: 'user', passwordField: 'password'}};
  const surface = {authBodyOperations: Object.values(scope.localAuthPostContracts),
    patterns: [
      {pattern: '/api/private', methods: ['GET'], params: {},
        responseFacts: {status: 401, type: 'application/json'}},
      {pattern: '/api/echo', methods: ['GET'], params: {q: ['plain']},
        responseFacts: {status: 200, type: 'application/json'}},
    ]};
  let modelCalls = 0, protectedSessions = 0, requests = 0;
  const issued = new Set();
  const infer = async (_model, messages) => {
    modelCalls++;
    if (messages[0].content.startsWith('From only the observed authorized JSON login operations'))
      return {checks: [{loginPath: '/api/session', userField: 'user',
        passwordField: 'password', userPayloads: ["' OR '1'='1"],
        proofMode: 'protected-status', tokenPointer: '/token',
        privatePath: '/api/private', why: 'Observed login and denied private route'}]};
    return {tasks: [], checks: [], paths: [], notes: [], priorities: [],
      strategies: [], experiments: [], flows: []};
  };
  const requester = async options => {
    const evidenceId = `ev-${String(++requests).padStart(4, '0')}`;
    if (options.method === 'POST') {
      const accepted = JSON.parse(options.body).user === "' OR '1'='1";
      const token = accepted ? `bx-session-${String(requests).padStart(20, '0')}` : null;
      if (token) issued.add(token);
      return {status: accepted ? 200 : 401, type: 'application/json', body: '',
        rawBody: JSON.stringify(token ? {token} : {error: 'invalid'}),
        headers: {}, evidenceId};
    }
    const accepted = options.url?.endsWith('/api/private') && issued.has(options.derivedBearer);
    return {status: accepted ? 200 : options.url?.endsWith('/api/private') ? 401 : 200,
      type: 'application/json', body: '{}', rawBody: '{}', headers: {}, evidenceId};
  };
  const run = await runWebProbes(surface, scope, {requester, infer,
    model: {model: 'fixture'}, budget: 2, maxModelPages: 4,
    remainingModelCalls: () => Math.max(0, 4 - modelCalls - 1),
    onConfirmedSession: async () => {
      protectedSessions++;
      modelCalls += 2; // A protected recon/planning callback consumes the shared model budget.
    }});
  assert.equal(protectedSessions, 1);
  assert.ok(run.findings.some(item => item.kind === 'model-auth-login'));
  assert.equal(modelCalls, 3,
    'the primary planner must not consume the call reserved for later protected follow-up');
});

test('web audit executes more than 20 Muse HTTP sequences within the configured task budget', async () => {
  const {scope: loaded} = loadScope({origin: 'http://127.0.0.1:4329',
    overrides: {acceptLocal: true}});
  const scope = structuredClone(loaded);
  const methods = Array.from({length: 3}, (_, index) => ({
    path: `/api/write-${index}`, method: 'POST', placement: 'json',
    fields: ['value'], requiredFields: [], contentType: 'application/json',
    source: 'public-openapi'}));
  scope.probes.writeOperations = methods.map(({path, method, placement}) =>
    ({path, method, placement}));
  const surface = {methodOperations: methods, patterns: Array.from({length: 77},
    (_, index) => ({pattern: `/api/read-${index}`, methods: ['GET'],
      params: {q: ['plain']}, source: ['public-openapi']}))};
  let requests = 0, planningPages = 0;
  const infer = async (_model, messages) => {
    const system = messages[0].content;
    if (!system.startsWith('You are planning bounded, authorized HTTP research.'))
      return {checks: [], tasks: [], paths: [], notes: [], priorities: [],
        strategies: [], experiments: [], flows: []};
    planningPages++;
    const context = JSON.parse(messages[1].content);
    return {flows: context.routes.slice(0, 8).map(route => ({
      family: 'observed-input-behavior', why: 'The observed input accepts controlled values',
      priority: 5, as: 'anonymous', oracle: 'observation',
      prelude: [], observe: [], binding: null,
      subject: {method: route.methods[0], path: route.path,
        placement: route.kind === 'read' ? 'query' : route.kind,
        key: route.kind === 'read' ? 'q' : 'value',
        fixedFields: [], bodyTemplate: '', headers: []},
      controlValue: 'plain', firstValue: 'first', secondValue: 'second',
      marker: '', secondMarker: '',
      assertion: {step: 'subject', index: 0, location: 'body', name: ''}}))};
  };
  const requester = async request => {
    requests++;
    const value = request.method === 'POST' ? JSON.parse(request.body).value :
      new URL(request.url, scope.target.origin).searchParams.get('q');
    const body = JSON.stringify({value});
    return {status: 200, type: 'application/json', body, rawBody: body,
      bytes: body.length, hash: body, ms: 1, cached: false,
      headers: {'content-type': 'application/json'},
      evidenceId: `ev-${String(requests).padStart(4, '0')}`};
  };
  const run = await runWebProbes(surface, scope, {requester, infer,
    model: {model: 'fixture'}, budget: 24, maxModelPages: 36});
  const sequences = run.results.filter(item => item.kind === 'model-http-observation');
  assert.ok(planningPages >= 3);
  assert.equal(run.modelCoverage.httpSequenceAccepted, 23);
  assert.equal(sequences.length, 23);
  assert.ok(sequences.every(item => item.verdict !== 'untested'));
  assert.ok(sequences.some(item => item.lead.method === 'POST'));
  assert.ok(sequences.some(item => item.lead.method === 'GET'));
  assert.equal(run.modelCoverage.httpSequenceAvailable, 80);
  assert.ok(run.modelCoverage.httpSequenceSent >= 24 &&
    run.modelCoverage.httpSequenceSent <= 32,
  'the remaining observed routes must be visible as a model-budget cut');
  assert.ok(requests >= 72);
});

test('accepted HTTP research deferred by time is carried into the later pass', async () => {
  const {scope} = loadScope({origin: 'http://127.0.0.1:4329',
    overrides: {acceptLocal: true}});
  const surface = {patterns: [{pattern: '/api/echo', methods: ['GET'],
    params: {q: ['plain']}, source: ['public-openapi'],
    responseFacts: {status: 200, type: 'application/json'}}]};
  const lead = {family: 'observed-echo', why: 'Compare an observed input', priority: 5,
    as: 'anonymous', oracle: 'observation', prelude: [], observe: [],
    subject: {method: 'GET', path: '/api/echo', placement: 'query', key: 'q',
      fixedFields: [], bodyTemplate: '', headers: []},
    controlValue: 'plain', firstValue: 'carry-secret-probe-42', secondValue: 'second',
    marker: '', secondMarker: '',
    assertion: {step: 'subject', index: 0, location: 'body', name: ''}};
  let requests = 0;
  const requester = async request => {
    requests++;
    const value = new URL(request.url, scope.target.origin).searchParams.get('q');
    const body = JSON.stringify({value});
    return {status: 200, type: 'application/json', body, bytes: body.length,
      hash: body, ms: 1, cached: false, headers: {'content-type': 'application/json'},
      evidenceId: `ev-${String(requests).padStart(4, '0')}`};
  };
  const first = await runWebProbes(surface, scope, {requester, budget: 1,
    researchDeadline: 0, carryForward: [{kind: 'model-http-sequence', lead}]});
  assert.equal(requests, 0);
  assert.equal(first.results.filter(item => item.verdict === 'untested').length, 1);
  assert.equal(first.deferredLeads.length, 1);
  assert.ok(!Object.keys(first).includes('deferredLeads'));
  assert.doesNotMatch(JSON.stringify(first), /carry-secret-probe-42/);
  const second = await runWebProbes(surface, scope, {requester, budget: 1,
    carryForward: first.deferredLeads});
  assert.ok(requests >= 3);
  assert.equal(second.results.filter(item => item.verdict === 'untested').length, 0);
  assert.equal(second.deferredLeads.length, 1,
    'an inconclusive observation remains available for later Muse feedback');
  assert.equal(second.deferredLeads[0].proposalId, first.results[0].proposalId);
  assert.equal(second.results[0].proposalId, first.results[0].proposalId);
});

test('a protected planning window defers ordinary web leads and later executes each exact lead', async () => {
  const {scope} = loadScope({origin: 'http://127.0.0.1:4329',
    overrides: {acceptLocal: true}});
  const paths = ['/go-one', '/go-two', '/go-three'];
  const surface = {patterns: paths.map(pattern => ({pattern, methods: ['GET'],
    params: {next: ['/safe']}, source: ['public-openapi']}))};
  const carryForward = paths.map(path => ({kind: 'open-redirect',
    lead: {path, parameter: 'next', as: 'anonymous'}}));
  let requests = 0;
  const requester = async request => {
    requests++;
    const url = new URL(request.url, scope.target.origin);
    return {status: 302, headers: {location: url.searchParams.get('next'),
      'cache-control': 'no-store'}, type: 'text/plain', body: '',
      evidenceId: `ev-${String(requests).padStart(4, '0')}`};
  };
  const early = await runWebProbes(surface, scope, {requester,
    budget: carryForward.length, researchDeadline: 0, carryForward});
  assert.equal(requests, 0);
  assert.equal(early.results.filter(item => item.verdict === 'untested').length, 3);
  assert.equal(early.deferredLeads.length, 3);
  assert.ok(!Object.keys(early).includes('deferredLeads'));
  const later = await runWebProbes(surface, scope, {requester,
    budget: carryForward.length, carryForward: early.deferredLeads});
  assert.deepEqual(later.results.map(item => item.verdict),
    ['confirmed', 'confirmed', 'confirmed']);
  assert.equal(later.deferredLeads.length, 0);
  assert.equal(requests, 6);
  assert.deepEqual(later.results.map(item => item.leadKey),
    early.results.map(item => item.leadKey));
});

test('web audit counts every accepted HTTP sequence left unstarted by time', async () => {
  const {scope} = loadScope({origin: 'http://127.0.0.1:4329',
    overrides: {acceptLocal: true}});
  const paths = ['/api/first', '/api/second', '/api/third'];
  const surface = {patterns: paths.map(pattern => ({pattern, methods: ['GET'],
    params: {q: ['plain']}, source: ['public-openapi'],
    responseFacts: {status: 200, type: 'application/json'}}))};
  const carryForward = paths.map((route, index) => ({kind: 'model-http-sequence',
    lead: {proposalId: `accepted-${index}`, family: 'observed-response',
      why: 'Compare an observed input', priority: 5, as: 'anonymous',
      oracle: 'observation', prelude: [], observe: [],
      subject: {method: 'GET', path: route, placement: 'query', key: 'q',
        fixedFields: [], bodyTemplate: '', headers: []},
      controlValue: 'plain', firstValue: 'alpha', secondValue: 'beta',
      marker: '', secondMarker: '',
      assertion: {step: 'subject', index: 0, location: 'body', name: ''}}}));
  const run = await runWebProbes(surface, scope, {
    requester: () => {throw Error('no request should run past the deadline');},
    budget: 3, researchDeadline: 0, carryForward});
  assert.equal(run.tested, 3);
  assert.deepEqual(run.results.map(item => [item.proposalId, item.verdict]),
    carryForward.map(item => [item.lead.proposalId, 'untested']));
  assert.equal(run.deferredLeads.length, 3);
});

test('Muse can refine an auth hypothesis beyond one follow-up until fresh controls prove it', async () => {
  const {scope: loaded} = loadScope({origin: 'http://127.0.0.1:4329',
    overrides: {acceptLocal: true}});
  const scope = structuredClone(loaded);
  scope.localAuthPostContracts = {'/api/session': {path: '/api/session',
    method: 'POST', contentType: 'application/json', fields: ['user', 'password'],
    usernameField: 'user', passwordField: 'password'}};
  const surface = {authBodyOperations: Object.values(scope.localAuthPostContracts),
    patterns: [{pattern: '/api/private', methods: ['GET'], params: {},
      responseFacts: {status: 401, type: 'application/json', shape: null}}]};
  const probes = ["' AND 1=0--", "' OR 1=0--", "' OR 1=1", "' OR 1=1--"];
  let modelCalls = 0, requests = 0;
  const issued = new Set();
  const infer = async (_model, messages) => {
    modelCalls++;
    const context = JSON.parse(messages[1].content);
    if (modelCalls > 1) {
      assert.equal(context.priorAttempts.at(-1).userPayloads[0], probes[modelCalls - 2]);
      assert.equal(context.priorAttempts.at(-1).observations.some(item => item.status === 401), true);
      assert.ok(!messages[1].content.includes('bx-invalid-'));
    }
    return {checks: [{loginPath: '/api/session', userField: 'user', passwordField: 'password',
      userPayloads: [probes[modelCalls - 1]], proofMode: 'protected-status',
      tokenPointer: '/token', privatePath: '/api/private', why: 'Observed denied read'}]};
  };
  const requester = async options => {
    const evidenceId = `ev-${String(++requests).padStart(4, '0')}`;
    if (options.method === 'POST') {
      const user = JSON.parse(options.body).user;
      const token = user === probes.at(-1) ? `bx-session-${String(requests).padStart(20, '0')}` : null;
      if (token) issued.add(token);
      return {status: token ? 200 : 401, type: 'application/json', body: '',
        rawBody: JSON.stringify(token ? {token} : {}), headers: {}, evidenceId};
    }
    return {status: issued.has(options.derivedBearer) ? 200 : 401,
      type: 'application/json', body: '{}', headers: {}, evidenceId};
  };
  const {plan, run, stats} = await runAuthInvestigation(surface, scope, {requester, infer,
    model: {model: 'fixture'}, budget: 4, maxModelPages: 4});
  assert.equal(modelCalls, 4);
  assert.equal(plan.leads.length, 4);
  assert.equal(stats.followupCalls, 3);
  assert.equal(stats.followupAccepted, 3);
  assert.equal(stats.executionRounds, 4);
  assert.equal(stats.stopReason, 'confirmed');
  assert.deepEqual(run.results.map(item => item.verdict),
    ['not_reproduced', 'not_reproduced', 'not_reproduced', 'confirmed']);
  assert.equal(run.findings.length, 1);
  assert.ok(!JSON.stringify(run).includes('bx-session-'));
});

test('auth investigation stops when Muse repeats an already tested hypothesis', async () => {
  const {scope: loaded} = loadScope({origin: 'http://127.0.0.1:4329',
    overrides: {acceptLocal: true}});
  const scope = structuredClone(loaded);
  scope.localAuthPostContracts = {'/api/session': {path: '/api/session',
    method: 'POST', contentType: 'application/json', fields: ['user', 'password'],
    usernameField: 'user', passwordField: 'password'}};
  const surface = {authBodyOperations: Object.values(scope.localAuthPostContracts),
    patterns: [{pattern: '/api/private', methods: ['GET'], params: {},
      responseFacts: {status: 401, type: 'application/json', shape: null}}]};
  let calls = 0, requests = 0;
  const infer = async () => {
    calls++;
    return {checks: [{loginPath: '/api/session', userField: 'user', passwordField: 'password',
      userPayloads: ["' OR 1=1--"], proofMode: 'protected-status',
      tokenPointer: '/token', privatePath: '/api/private', why: 'Observed denied read'}]};
  };
  const requester = async options => ({status: 401, type: 'application/json', body: '{}',
    rawBody: '{}', headers: {}, evidenceId: `ev-${++requests}`});
  const {plan, stats} = await runAuthInvestigation(surface, scope, {requester, infer,
    model: {model: 'fixture'}, budget: 20, maxModelPages: 10});
  assert.equal(calls, 2);
  assert.equal(plan.leads.length, 1);
  assert.equal(stats.stopReason, 'no-novel-hypothesis');
  assert.equal(requests > 0, true);
});

test('an empty Muse auth answer gets one exact-contract reconsideration before web paging', async () => {
  const {scope: loaded} = loadScope({origin: 'http://127.0.0.1:4329',
    overrides: {acceptLocal: true}});
  const scope = structuredClone(loaded);
  scope.localAuthPostContracts = {'/api/session': {path: '/api/session',
    method: 'POST', contentType: 'application/json', fields: ['user', 'password'],
    usernameField: 'user', passwordField: 'password'}};
  const surface = {authBodyOperations: Object.values(scope.localAuthPostContracts),
    patterns: [{pattern: '/api/private', methods: ['GET'], params: {},
      responseFacts: {status: 401, type: 'application/json', shape: null}}]};
  let authModelCalls = 0, requests = 0;
  const issued = new Set();
  const infer = async (_model, messages) => {
    if (!messages[0].content.startsWith('From only the observed authorized JSON login operations'))
      return {priorities: [], strategies: [], experiments: [], plans: []};
    authModelCalls++;
    const context = JSON.parse(messages[1].content);
    if (authModelCalls === 1) return {checks: []};
    assert.deepEqual(context.reconsideration.deniedReadIds, ['read-1']);
    assert.equal(context.posts[0].id, 'post-1');
    assert.equal(context.posts[0].path, '/api/session');
    return {checks: [{loginPath: '/api/session', userField: 'user', passwordField: 'password',
      userPayloads: ["' OR 1=1--"], proofMode: 'protected-status', tokenPointer: '/token',
      privatePath: '/api/private', why: 'Observed login and denied private route'}]};
  };
  const requester = async options => {
    const evidenceId = `ev-${String(++requests).padStart(4, '0')}`;
    if (options.method === 'POST') {
      const username = JSON.parse(options.body).user;
      const accepted = username === "' OR 1=1--";
      const token = accepted ? `bx-session-${String(requests).padStart(20, '0')}` : null;
      if (token) issued.add(token);
      return {status: accepted ? 200 : 401, type: 'application/json', body: '',
        rawBody: JSON.stringify(accepted ? {token} : {}), headers: {}, evidenceId};
    }
    return {status: issued.has(options.derivedBearer) ? 200 : 401,
      type: 'application/json', body: '{}', headers: {}, evidenceId};
  };
  const run = await runWebProbes(surface, scope, {requester, infer,
    model: {model: 'fixture'}, budget: 1, maxModelPages: 2});
  assert.equal(authModelCalls, 2);
  assert.equal(run.modelCoverage.authEmptyRetryCalls, 1);
  assert.equal(run.modelCoverage.authEmptyRetryAccepted, 1);
  assert.equal(run.modelCoverage.authFollowupCalls, 0);
  assert.equal(run.findings.find(item => item.kind === 'model-auth-login')?.verdict, 'confirmed');
  assert.equal(requests, 10);
  assert.ok(!JSON.stringify(run).includes('bx-session-'));
});

test('a Muse auth lead executes before later web-planning model pages', async () => {
  const {scope: loaded} = loadScope({origin: 'http://127.0.0.1:4329',
    overrides: {acceptLocal: true}});
  const scope = structuredClone(loaded);
  scope.localAuthPostContracts = {'/api/session': {path: '/api/session',
    method: 'POST', contentType: 'application/json', fields: ['user', 'password'],
    usernameField: 'user', passwordField: 'password'}};
  const surface = {authBodyOperations: Object.values(scope.localAuthPostContracts),
    patterns: [{pattern: '/api/me', methods: ['GET'], params: {}},
      {pattern: '/api/search', methods: ['GET'], params: {q: ['one']}}]};
  const issued = new Set();
  let authRequests = 0, laterModelCalls = 0;
  const requester = async options => {
    const pathname = new URL(options.url, scope.target.origin).pathname;
    if (pathname === '/api/session') {
      authRequests++;
      const user = JSON.parse(options.body).user;
      const accepted = ["' OR '1'='1", "') OR (1=1)--"].includes(user);
      const token = accepted ? `bx-session-${String(authRequests).padStart(20, '0')}` : null;
      if (token) issued.add(token);
      return {status: accepted ? 200 : 401, type: 'application/json', body: '',
        rawBody: JSON.stringify(accepted ? {authentication: {token}} : {}), headers: {},
        evidenceId: `ev-${authRequests}`};
    }
    if (pathname === '/api/me') {
      authRequests++;
      return {status: 200, type: 'application/json', body: JSON.stringify(issued.has(options.derivedBearer) ?
        {user: {id: 47}} : {}), headers: {}, evidenceId: `ev-${authRequests}`};
    }
    return {status: 200, type: 'application/json', body: '{"data":[]}', ids: [],
      hash: 'empty', headers: {}, evidenceId: `other-${laterModelCalls}`};
  };
  const infer = async (_model, messages) => {
    if (messages[0].content.startsWith('From only the observed authorized JSON login operations'))
      return {checks: [{loginPath: '/api/session', userField: 'user', passwordField: 'password',
        userPayloads: ["' OR '1'='1", "') OR (1=1)--"], tokenPointer: '/authentication/token',
        privatePath: '/api/me', principalPointer: '/user/id', why: 'Observed login syntax'}]};
    laterModelCalls++;
    assert.equal(authRequests, 14);
    return {priorities: [], strategies: [], experiments: [], plans: [], checks: []};
  };
  const run = await runWebProbes(surface, scope, {requester, infer,
    model: {model: 'fixture'}, budget: 2, maxModelPages: 5});
  assert.ok(laterModelCalls > 0);
  assert.equal(run.results.find(item => item.kind === 'model-auth-login')?.verdict, 'confirmed');
});

test('Muse can propose a new read-only experiment without a family allowlist', async () => {
  const {scope} = loadScope({origin: 'http://127.0.0.1:4329', overrides: {acceptLocal: true}});
  const surface = {patterns: [{pattern: '/api/processor', params: {expression: []},
    source: ['public-openapi']}]};
  const planned = await planWebLeads(surface, scope, {budget: 100, model: {model: 'fixture'},
    infer: async (_model, messages) => {
      const context = JSON.parse(messages[1].content);
      const marker = context.canary;
      const secondMarker = context.secondCanary;
      const valid = {family: 'unlisted-evaluation', path: '/api/processor', parameter: 'expression',
        controlValue: '7', firstValue: `String.fromCharCode(${[...marker].map(char => char.charCodeAt(0)).join(',')})`,
        secondValue: `[${[...secondMarker].map(char => JSON.stringify(char)).join(',')}].join('')`,
        marker, secondMarker, priority: 10, why: 'Observed input reaches an evaluator'};
      return {priorities: [], strategies: [], experiments: [valid,
        {...valid, path: '/api/unknown'}, {...valid, marker: 'bx000000000000'},
        {...valid, firstValue: marker}, {...valid, firstValue: 'token=secret'},
        {...valid, firstValue: 'process.exit()'}]};
    }});
  const experiments = planned.selected.filter(item => item.kind === 'model-differential');
  assert.equal(experiments.length, 4);
  assert.ok(experiments.every(item => item.path === '/api/processor' &&
    item.parameter === 'expression' && item.basis === 'model-experiment'));
  const decisions = planned.strategyDecisions.filter(item => item.mode === 'experiment');
  assert.equal(decisions.filter(item => item.accepted).length, 4);
  assert.deepEqual(decisions.filter(item => !item.accepted).map(item => item.reason),
    ['unobserved-pair-or-unread-page', 'duplicate']);
  assert.ok(planned.leads.some(item => item.lead?.firstValue === 'token=secret'));
  assert.ok(planned.leads.some(item => item.lead?.firstValue === 'process.exit()'));
  assert.equal(decisions.filter(item => item.accepted &&
    item.translatedTo === 'model-observation').length, 1);
});

test('Muse family metadata normalizes a typographic dash without discarding an observed experiment', async () => {
  const {scope} = loadScope({origin: 'http://127.0.0.1:4329', overrides: {acceptLocal: true}});
  const surface = {patterns: [{pattern: '/api/processor', methods: ['GET'],
    params: {expression: []}, source: ['public-openapi']}]};
  const planned = await planWebLeads(surface, scope, {budget: 100, model: {model: 'fixture'},
    infer: async (_model, messages) => {
      const context = JSON.parse(messages[1].content);
      const marker = context.canary, secondMarker = context.secondCanary;
      const encoded = value => `String.fromCharCode(${[...value].map(char => char.charCodeAt(0)).join(',')})`;
      return {priorities: [], experiments: [], strategies: [{
        family: 'SQL Injection — Boolean-Based', path: '/api/processor', parameter: 'expression',
        controlValue: '7', firstValue: encoded(marker), secondValue: encoded(secondMarker),
        marker, secondMarker, priority: 10, why: 'Observed expression field'}]};
    }});
  assert.ok(planned.leads.some(item => item.kind === 'model-differential' &&
    item.lead.family === 'SQL Injection - Boolean-Based'), JSON.stringify(planned.strategyDecisions));
  assert.ok(planned.strategyDecisions.some(item => item.mode === 'experiment' && item.accepted &&
    item.family === 'SQL Injection - Boolean-Based'));
});

test('a scoped Muse GET observation executes but cannot become a finding from reflection alone', async () => {
  const {scope} = loadScope({origin: 'http://127.0.0.1:4329', overrides: {acceptLocal: true}});
  const surface = {patterns: [{pattern: '/api/echo', methods: ['GET'],
    params: {expression: []}, source: ['public-openapi']}]};
  let requests = 0;
  const run = await runWebProbes(surface, scope, {budget: 1, maxModelPages: 8,
    model: {model: 'fixture'}, infer: async (_model, messages) => {
      if (messages[0].content.startsWith('Rank only the supplied observed read-only web-test candidates')) {
        const context = JSON.parse(messages[1].content);
        return {priorities: [], strategies: [], experiments: [{family: 'unlisted-formatting',
          path: '/api/echo', parameter: 'expression', oracle: 'observation',
          controlValue: 'plain', firstValue: '<b>first</b>', secondValue: '<i>second</i>',
          marker: context.canary, secondMarker: context.secondCanary,
          prelude: [], headers: [], priority: 10, why: 'Observed formatting input'}]};
      }
      return {priorities: [], strategies: [], experiments: [], flows: [], plans: [], checks: []};
    }, requester: async ({url}) => {
      requests++;
      const value = new URL(url, scope.target.origin).searchParams.get('expression');
      return {status: 200, type: 'application/json', body: JSON.stringify({value}),
        hash: `hash-${value}`, headers: {'content-type': 'application/json'},
        evidenceId: `ev-${requests}`};
    }});
  assert.ok(requests >= 3);
  assert.ok(run.strategyDecisions.some(item => item.accepted &&
    item.translatedTo === 'model-observation'));
  assert.equal(run.results.find(item => item.kind === 'model-differential')?.verdict, 'inconclusive');
  assert.ok(!run.findings.some(item => item.kind === 'model-differential'));
});

test('Muse Open Redirect on an unusual observed parameter uses the independent Location oracle', async () => {
  const {scope} = loadScope({origin: 'http://127.0.0.1:4329', overrides: {acceptLocal: true}});
  const surface = {patterns: [{pattern: '/go', methods: ['GET'],
    params: {destino: []}, source: ['public-openapi']}]};
  let requests = 0;
  const run = await runWebProbes(surface, scope, {budget: 1, maxModelPages: 8,
    model: {model: 'fixture'}, infer: async (_model, messages) => {
      if (messages[0].content.startsWith('Rank only the supplied observed read-only web-test candidates'))
        return {priorities: [], strategies: [{family: 'Open Redirect', path: '/go',
          parameter: 'destino', priority: 10, why: 'Observed navigation parameter'}],
        experiments: []};
      return {priorities: [], strategies: [], experiments: [], flows: [], plans: [], checks: []};
    }, requester: async ({url}) => {
      requests++;
      const location = new URL(url, scope.target.origin).searchParams.get('destino');
      return {status: 302, type: 'text/plain', body: '',
        headers: {location}, evidenceId: `ev-${requests}`};
    }});
  assert.equal(requests, 2);
  assert.ok(run.strategyDecisions.some(item => item.accepted &&
    item.family === 'open-redirect' && item.translatedFrom === 'Open Redirect'));
  assert.equal(run.results.find(item => item.kind === 'open-redirect')?.verdict, 'confirmed');
  assert.ok(run.findings.some(item => item.kind === 'open-redirect' &&
    item.webProof?.kind === 'open-redirect'));
});

test('a local scoped GET with punctuation executes as an observation without repair', async () => {
  const {scope} = loadScope({origin: 'http://127.0.0.1:4329', overrides: {acceptLocal: true}});
  const surface = {patterns: [{pattern: '/render', methods: ['GET'],
    params: {template: []}, source: ['public-openapi']}]};
  let repairs = 0;
  const planned = await planWebLeads(surface, scope, {budget: 100, maxModelPages: 3,
    model: {model: 'fixture'}, infer: async (_model, messages) => {
      const context = JSON.parse(messages[1].content);
      if (messages[0].content.startsWith('Rank only the supplied observed read-only web-test candidates'))
        return {priorities: [], strategies: [], experiments: [{family: 'unlisted-template',
          path: '/render', parameter: 'template', controlValue: 'plain',
          firstValue: ';unsafe', secondValue: 'second', oracle: 'observation', marker: context.canary,
          secondMarker: context.secondCanary, prelude: [], headers: [],
          priority: 10, why: 'Observed template input'}]};
      if (messages[0].content.startsWith('Repair the supplied observed GET experiments')) {
        repairs++;
        throw Error('A scoped printable request must not need repair.');
      }
      return {experiments: []};
    }});
  assert.equal(repairs, 0);
  assert.ok(planned.strategyDecisions.some(item => item.accepted &&
    item.translatedTo === 'model-observation'));
  assert.ok(planned.leads.some(item => item.kind === 'model-differential' &&
    item.lead.oracle === 'observation'));
});

test('GET repair keeps refining changed candidates and stops when Muse repeats one', async () => {
  const {scope} = loadScope({origin: 'http://127.0.0.1:4329', overrides: {acceptLocal: true}});
  const surface = {patterns: [{pattern: '/render', methods: ['GET'],
    params: {template: []}, source: ['public-openapi']}]};
  const first = {family: 'unlisted-template', path: '/render', parameter: 'template',
    controlValue: 'plain', firstValue: 'plain', secondValue: 'second',
    prelude: [], headers: [], priority: 10, why: 'Observed template input'};
  let repairs = 0;
  const planned = await planWebLeads(surface, scope, {budget: 100, maxModelPages: 5,
    model: {model: 'fixture'}, infer: async (_model, messages) => {
      const context = JSON.parse(messages[1].content);
      if (messages[0].content.startsWith('Rank only the supplied observed read-only web-test candidates'))
        return {priorities: [], strategies: [], experiments: [{...first,
          marker: context.canary, secondMarker: context.secondCanary}]};
      repairs++;
      return {experiments: [{...first, secondValue: 'third',
        marker: context.marker, secondMarker: context.secondMarker}]};
    }});
  assert.equal(repairs, 2);
  assert.equal(planned.modelCoverage.repairCalls, 2);
  assert.equal(planned.modelCoverage.repairProposed, 1);
  assert.equal(planned.modelCoverage.repairStalled, 1);
});

test('GET repair can succeed after several changed proposals within the model budget', async () => {
  const {scope} = loadScope({origin: 'http://127.0.0.1:4329', overrides: {acceptLocal: true}});
  const surface = {patterns: [{pattern: '/render', methods: ['GET'],
    params: {template: []}, source: ['public-openapi']}]};
  const first = {family: 'unlisted-template', path: '/render', parameter: 'template',
    controlValue: 'plain', firstValue: 'plain', secondValue: 'second',
    prelude: [], headers: [], priority: 10, why: 'Observed template input'};
  let repairs = 0;
  const planned = await planWebLeads(surface, scope, {budget: 100, maxModelPages: 5,
    model: {model: 'fixture'}, infer: async (_model, messages) => {
      const context = JSON.parse(messages[1].content);
      if (messages[0].content.startsWith('Rank only the supplied observed read-only web-test candidates'))
        return {priorities: [], strategies: [], experiments: [{...first,
          marker: context.canary, secondMarker: context.secondCanary}]};
      repairs++;
      return {experiments: [{...first,
        firstValue: repairs === 1 ? 'plain' : '{{7*7}}',
        secondValue: repairs === 1 ? 'third' : '{{8*8}}',
        oracle: 'observation', marker: context.marker,
        secondMarker: context.secondMarker}]};
    }});
  assert.equal(repairs, 2);
  assert.equal(planned.modelCoverage.repairCalls, 2);
  assert.equal(planned.modelCoverage.repairAccepted, 1);
  assert.ok(planned.leads.some(item => item.kind === 'model-differential' &&
    item.lead.oracle === 'observation'));
});

test('model values preserve printable syntax while literal proof markers remain observations', () => {
  const firstMarker = 'bx123456789abc', secondMarker = 'bxabcdef123456';
  const template = marker => `\${String.fromCharCode(${[...marker].map(char => char.charCodeAt(0)).join(',')})}`;
  const values = {parameter: 'expression', marker: firstMarker, secondMarker,
    controlValue: '7', firstValue: template(firstMarker), secondValue: template(secondMarker),
    headers: []};
  assert.equal(validModelExperiment({...values, origin: 'http://127.0.0.1:4329'}), true);
  assert.equal(modelExperimentReason({...values, origin: 'https://example.test'}), null);
  assert.equal(modelExperimentReason({...values, origin: 'http://127.0.0.1:4329',
    firstValue: ';rm -rf /'}), null);
  const encoded = marker => `<b>${[...marker].map(char => `&#${char.charCodeAt(0)};`).join('')}</b>`;
  assert.equal(validModelExperiment({...values, origin: 'http://127.0.0.1:4329',
    firstValue: encoded(firstMarker), secondValue: encoded(secondMarker)}), true);
  assert.equal(modelExperimentReason({...values, origin: 'http://127.0.0.1:4329',
    firstValue: `<b>${firstMarker}</b>`}), 'literal-marker');
  assert.equal(modelExperimentReason({...values, origin: 'http://127.0.0.1:4329',
    firstValue: '<img src=x onerror=alert(1)>'}), null);
  assert.equal(modelExperimentReason({...values, origin: 'http://127.0.0.1:4329',
    firstValue: '<b>&#59;</b>'}), null);
});

test('an unlisted Muse strategy gets executable details and uses the generic independent oracle', async () => {
  const {scope} = loadScope({origin: 'http://127.0.0.1:4329', overrides: {acceptLocal: true}});
  const surface = {patterns: [{pattern: '/api/processor', params: {expression: []},
    methods: ['GET'], source: ['public-openapi']}]};
  let detailCalls = 0, requests = 0;
  const infer = async (_model, messages) => {
    const system = messages[0].content;
    const context = JSON.parse(messages[1].content);
    if (system.startsWith('Rank only the supplied observed read-only web-test candidates'))
      return {priorities: [], strategies: [{family: 'unlisted-evaluation',
        path: '/api/processor', parameter: 'expression', priority: 10,
        why: 'Observed input may decode an expression'}], experiments: []};
    if (system.startsWith('Turn only the supplied observed GET input hypotheses')) {
      detailCalls++;
      assert.equal(context.hypotheses[0].family, 'unlisted-evaluation');
      return {experiments: [{family: 'unlisted-evaluation', path: '/api/processor',
        parameter: 'expression', controlValue: 'plain',
        firstValue: `hex:${Buffer.from(context.marker).toString('hex')}`,
        secondValue: `hex:${Buffer.from(context.secondMarker).toString('hex')}`,
        marker: context.marker, secondMarker: context.secondMarker,
        prelude: [], headers: [], priority: 10,
        why: 'Two distinct inputs may decode on the server'}]};
    }
    if (system.startsWith('Revise one inconclusive')) return {experiments: []};
    return {plans: [], checks: [], priorities: [], strategies: [], experiments: []};
  };
  const requester = async ({url}) => {
    requests++;
    const value = new URL(url, scope.target.origin).searchParams.get('expression');
    const decoded = value?.startsWith('hex:') ? Buffer.from(value.slice(4), 'hex').toString() : 'plain';
    return {status: 200, type: 'application/json', body: JSON.stringify({result: decoded}),
      bytes: decoded.length + 14, headers: {'content-type': 'application/json'}, cached: false,
      evidenceId: `ev-${String(requests).padStart(4, '0')}`};
  };
  const run = await runWebProbes(surface, scope, {requester, infer,
    model: {model: 'fixture'}, budget: 1, maxModelPages: 8});
  assert.equal(detailCalls, 1);
  assert.ok(run.strategyDecisions.some(item => item.family === 'unlisted-evaluation' &&
    item.accepted && item.proofOracle?.includes('canaries absent from control')));
  assert.equal(run.results.find(item => item.kind === 'model-differential')?.verdict, 'confirmed');
  assert.equal(run.findings.find(item => item.kind === 'model-differential')?.verdict, 'observed');
  assert.equal(requests, 3);

  let reflected = 0;
  const reflection = await runWebProbes(surface, scope, {infer, model: {model: 'fixture'},
    budget: 1, maxModelPages: 8, requester: async ({url}) => {
      reflected++;
      const value = new URL(url, scope.target.origin).searchParams.get('expression');
      return {status: 200, type: 'application/json', body: JSON.stringify({result: value}),
        bytes: value.length + 14, headers: {'content-type': 'application/json'}, cached: false,
        evidenceId: `ref-${reflected}`};
    }});
  assert.equal(reflection.results.find(item => item.kind === 'model-differential')?.verdict,
    'not_reproduced');
  assert.ok(!reflection.findings.some(item => item.kind === 'model-differential'));
});

test('repeated identical server errors stop a generic Muse experiment before it consumes the model budget', async () => {
  const {scope} = loadScope({origin: 'http://127.0.0.1:4329', overrides: {acceptLocal: true}});
  const surface = {patterns: [{pattern: '/api/calculate', params: {expression: []},
    source: ['public-openapi']}]};
  let requests = 0, revisions = 0;
  const proposal = (context, suffix = '') => ({family: 'unclassified-evaluation',
    path: '/api/calculate', parameter: 'expression', controlValue: '7',
    firstValue: `String.fromCharCode(${[...context.canary].map(char => char.charCodeAt(0)).join(',')})${suffix}`,
    secondValue: `[${[...context.secondCanary].map(char => JSON.stringify(char)).join(',')}].join('')${suffix}`,
    marker: context.canary, secondMarker: context.secondCanary,
    prelude: [], headers: [], priority: 10, why: 'Try the observed expression field'});
  const infer = async (_model, messages) => {
    const system = messages[0].content;
    const context = JSON.parse(messages[1].content);
    if (system.includes('Rank only the supplied observed read-only web-test candidates'))
      return {priorities: [], strategies: [], experiments: [proposal(context)]};
    if (system.includes('Revise one inconclusive')) {
      revisions++;
      return {experiments: [proposal(context, `+${revisions}`)]};
    }
    return {paths: [], notes: [], tasks: [], proposals: []};
  };
  const requester = async ({url}) => {
    requests++;
    const value = new URL(url, scope.target.origin).searchParams.get('expression');
    const status = value === '7' ? 200 : 500;
    const body = status === 200 ? '{"result":7}' : '{"error":"invalid expression"}';
    return {status, type: 'application/json', body, bytes: body.length, ms: 1,
      headers: {'content-type': 'application/json'}, cached: false,
      evidenceId: `ev-${String(requests).padStart(4, '0')}`};
  };
  const run = await runWebProbes(surface, scope, {requester, infer,
    model: {model: 'fixture'}, budget: 1, maxModelPages: 20});
  const investigation = run.investigations.find(item => item.initial.path === '/api/calculate');
  assert.ok(investigation, JSON.stringify(run.investigations));
  assert.equal(investigation.stopReason, 'repeated-server-error');
  assert.equal(investigation.attempts.length, 4);
  assert.equal(revisions, 3);
  assert.equal(requests, 12);
  assert.equal(run.findings.length, 0);
  assert.match(investigation.attempts[0].reason, /server error/);
});

test('Muse GET follow-up executes a later valid alternative after rejecting the first proposal', async () => {
  const {scope} = loadScope({origin: 'http://127.0.0.1:4329', overrides: {acceptLocal: true}});
  const surface = {patterns: [{pattern: '/api/evaluate', params: {expression: []},
    source: ['public-openapi']}]};
  const proposal = (context, suffix = '') => ({family: 'unlisted-evaluation',
    path: '/api/evaluate', parameter: 'expression', controlValue: '7',
    firstValue: `String.fromCharCode(${[...context.canary].map(char => char.charCodeAt(0)).join(',')})${suffix}`,
    secondValue: `[${[...context.secondCanary].map(char => JSON.stringify(char)).join(',')}].join('')${suffix}`,
    marker: context.canary, secondMarker: context.secondCanary,
    prelude: [], headers: [], priority: 10, why: 'Test the documented expression input'});
  let revisions = 0, requests = 0;
  const infer = async (_model, messages) => {
    const context = JSON.parse(messages[1].content);
    if (messages[0].content.includes('Rank only the supplied observed read-only web-test candidates'))
      return {priorities: [], strategies: [], experiments: [proposal(context)]};
    if (messages[0].content.includes('Revise one inconclusive')) {
      revisions++;
      return revisions === 1 ? {experiments: [
        {...proposal(context), path: '/api/unobserved'}, proposal(context, '+1')]} :
        {experiments: []};
    }
    return {paths: [], notes: [], tasks: [], proposals: []};
  };
  const requester = async () => {
    requests++;
    return {status: 200, type: 'application/json', body: '{"result":7}', bytes: 12,
      ms: 1, headers: {'content-type': 'application/json'}, cached: false,
      evidenceId: `ev-${String(requests).padStart(4, '0')}`};
  };
  const run = await runWebProbes(surface, scope, {requester, infer,
    model: {model: 'fixture'}, budget: 1, maxModelPages: 8});
  const investigation = run.investigations.find(item => item.initial.path === '/api/evaluate');
  assert.equal(investigation?.attempts.length, 2);
  assert.equal(revisions, 2);
  assert.equal(requests, 6);
  assert.ok(run.strategyDecisions.some(item => item.mode === 'experiment-revision' &&
    item.accepted && item.attempt === 2));
});

test('observed web probes run before open-ended Muse research', async () => {
  const {scope} = loadScope({origin: 'http://127.0.0.1:4329', overrides: {acceptLocal: true}});
  const surface = {patterns: [
    {pattern: '/api/go', params: {next: []}, source: ['public-openapi']},
    {pattern: '/api/calculate', params: {expression: []}, source: ['public-openapi']},
  ]};
  const requests = [];
  const infer = async (_model, messages) => {
    const context = JSON.parse(messages[1].content);
    if (messages[0].content.includes('Rank only the supplied observed read-only web-test candidates'))
      return {priorities: [], strategies: [], experiments: [{family: 'unclassified-evaluation',
        path: '/api/calculate', parameter: 'expression', controlValue: '7',
        firstValue: `String.fromCharCode(${[...context.canary].map(char => char.charCodeAt(0)).join(',')})`,
        secondValue: `[${[...context.secondCanary].map(char => JSON.stringify(char)).join(',')}].join('')`,
        marker: context.canary, secondMarker: context.secondCanary,
        prelude: [], headers: [], priority: 10, why: 'Observed expression field'}]};
    if (messages[0].content.includes('Revise one inconclusive')) return {experiments: []};
    return {paths: [], notes: [], tasks: [], proposals: []};
  };
  const requester = async ({url}) => {
    const parsed = new URL(url, scope.target.origin);
    requests.push(`${parsed.pathname}${parsed.search}`);
    const body = '{"ok":true}';
    return {status: 200, type: 'application/json', body, bytes: body.length, ms: 1,
      headers: {'content-type': 'application/json'}, cached: false,
      evidenceId: `ev-${String(requests.length).padStart(4, '0')}`};
  };
  const run = await runWebProbes(surface, scope, {requester, infer,
    model: {model: 'fixture'}, budget: 100, maxModelPages: 20});
  assert.ok(run.investigations.some(item => item.initial.path === '/api/calculate'));
  const observedAt = requests.findIndex(url => url.startsWith('/api/go?'));
  const researchAt = requests.findIndex(url => url === '/api/calculate?expression=7');
  assert.ok(observedAt >= 0 && researchAt >= 0, JSON.stringify(requests));
  assert.ok(observedAt < researchAt, JSON.stringify({observedAt, researchAt}));
  const checkpoints = [];
  const reserved = await runWebProbes(surface, scope, {requester, infer,
    model: {model: 'fixture'}, budget: 100, maxModelPages: 20,
    researchDeadline: 0, onResearchCheckpoint: item => checkpoints.push(item)});
  assert.equal(reserved.investigations.length, 0);
  assert.equal(reserved.modelCoverage.pagesSent, 0);
  assert.ok(reserved.results.length > 0, 'observed baseline checks still execute');
  assert.equal(checkpoints.at(-1)?.cursor, 0);
});

test('Muse cannot add an unobserved or never-listed prelude to a GET sequence', async () => {
  const {scope} = loadScope({origin: 'http://127.0.0.1:4329', overrides: {acceptLocal: true}});
  const surface = {patterns: [{pattern: '/api/processor', params: {expression: []},
    source: ['public-openapi']}, {pattern: '/api/delete', params: {}, source: ['public-openapi']},
    {pattern: '/api/create', methods: ['POST'], params: {}, source: ['public-openapi']}]};
  const planned = await planWebLeads(surface, scope, {budget: 100, model: {model: 'fixture'},
    infer: async (_model, messages) => {
      const context = JSON.parse(messages[1].content);
      assert.ok(!context.preludeRoutes.includes('/api/delete'));
      assert.ok(!context.preludeRoutes.includes('/api/create'));
      const proposal = {family: 'stateful-evaluation',
        path: '/api/processor', parameter: 'expression', prelude: ['/api/delete'],
        controlValue: '7', firstValue: '8', secondValue: '9',
        marker: context.canary, secondMarker: context.secondCanary,
        priority: 10, why: 'Untrusted prelude'};
      return {priorities: [], strategies: [], experiments: [proposal,
        {...proposal, prelude: ['/api/create']}]};
    }});
  assert.deepEqual(planned.strategyDecisions.filter(item => item.mode === 'experiment')
    .map(item => item.reason), ['unobserved-or-out-of-scope-prelude',
    'unobserved-or-out-of-scope-prelude']);
  assert.ok(!planned.selected.some(item => item.kind === 'model-differential'));
});

test('search SQL lead can start from a benign query and needs an expanded true set plus an empty false set', async () => {
  const {scope} = loadScope({origin: 'http://127.0.0.1:4329', overrides: {acceptLocal: true}});
  const surface = {patterns: [{pattern: '/rest/products/search', params: {q: []}, source: ['public-asset']}]};
  const planned = await planWebLeads(surface, scope, {budget: 100});
  const lead = planned.leads.find(item => item.kind === 'sql-boolean')?.lead;
  assert.deepEqual([lead?.base, lead?.style, lead?.basis],
    ['a', 'search-quote-close-or', 'benign-search-baseline']);
  const pair = sqlBooleanCanary(lead.base, lead.style);
  assert.match(pair.yes, /^a'\)\) OR (\d+)=\1--$/);
  const baseline = {status: 200, type: 'application/json', ids: ['1', '2'], hash: 'baseline'};
  const yes = {status: 200, type: 'application/json', ids: ['1', '2', '3'], hash: 'all'};
  const no = {status: 200, type: 'application/json', ids: [], hash: 'empty'};
  assert.equal(sqlBooleanOracle(baseline, yes, no, lead.style), true);
  assert.equal(sqlBooleanOracle(baseline, {...yes, ids: ['3']}, no, lead.style), false);
  assert.equal(sqlBooleanOracle(baseline, yes, {...no, ids: ['2']}, lead.style), false);
  assert.equal(sqlBooleanOracle(baseline, {...baseline, ids: []}, yes, no, lead.style), false);
});

test('SQL search tries observed example baselines and prioritizes routes with a JSON record oracle', async () => {
  const {scope} = loadScope({origin: 'http://127.0.0.1:4329', overrides: {acceptLocal: true}});
  const surface = {patterns: [
    {pattern: '/page/search', params: {q: ['text']}, source: ['public-asset'],
      responseFacts: {status: 200, type: 'text/html'}},
    {pattern: '/api/catalog/search', params: {q: ['absent', 'present']},
      source: ['public-openapi'], responseFacts: {status: 200, type: 'application/json'},
      publicIds: ['1']},
  ]};
  const planned = await planWebLeads(surface, scope, {budget: 1});
  assert.deepEqual(planned.selected.map(item => [item.kind, item.path, item.priority]),
    [['sql-boolean', '/api/catalog/search', 6]]);
  const values = [];
  const requester = async ({url}) => {
    const value = new URL(url, scope.target.origin).searchParams.get('q');
    values.push(value);
    const condition = /\bOR (\d+)=(\d+)--$/.exec(value ?? '');
    const ids = condition ? condition[1] === condition[2] ? ['1', '2'] : [] :
      value === 'present' ? ['1'] : [];
    const body = JSON.stringify({data: ids.map(id => ({id}))});
    return {status: 200, type: 'application/json', body, ids, hash: body,
      bytes: body.length, ms: 1, headers: {}, cached: false,
      evidenceId: `ev-${String(values.length).padStart(4, '0')}`};
  };
  const run = await runWebProbes(surface, scope, {requester, budget: 1});
  assert.equal(run.results.find(item => item.kind === 'sql-boolean')?.verdict, 'confirmed');
  assert.equal(run.findings.find(item => item.kind === 'sql-boolean')?.webProof.base, 'present');
  assert.deepEqual(values.slice(0, 2), ['absent', 'present']);
  assert.equal(values.length, 7);
});

test('Cloudflare challenge is reported as blocked SQL proof, not a negative app result',async()=>{
  const {scope}=loadScope({origin:'http://127.0.0.1:4329',overrides:{acceptLocal:true}});
  const surface={patterns:[{pattern:'/api/telemetry/search',params:{q:['present']},
    source:['public-asset'],responseFacts:{status:200,type:'application/json'},
    publicIds:['1']}]};
  let calls=0;
  const requester=async ({url})=>{
    calls++;
    const baseline=new URL(url,scope.target.origin).searchParams.get('q')==='present';
    const body=baseline?'{"items":[{"id":1}]}':'<title>Attention Required! | Cloudflare</title>';
    return {status:baseline?200:403,type:baseline?'application/json':'text/html',
      body,ids:baseline?['1']:[],hash:body,headers:{server:'cloudflare'},
      evidenceId:`ev-${String(calls).padStart(4,'0')}`};
  };
  const run=await runWebProbes(surface,scope,{requester,budget:1});
  const result=run.results.find(item=>item.kind==='sql-boolean');
  assert.equal(result?.verdict,'blocked',JSON.stringify(run.results));
  assert.match(result.reason,/Cloudflare blocked/);
  assert.equal(run.findings.length,0);
});

test('Muse reviews late web candidates in bounded pages and cannot rank an unseen page', async () => {
  const {scope} = loadScope({origin: 'http://127.0.0.1:4329', overrides: {acceptLocal: true}});
  const patterns = Array.from({length: 41}, (_, index) => ({
    pattern: `/api/go-${String(index).padStart(2, '0')}`,
    params: {next: []}, source: ['public-openapi']}));
  const late = patterns.at(-1).pattern;
  const surface = {patterns, operationNotes: [{path: late, purpose: 'user navigation',
    parameters: [{name: 'next', meaning: 'destination URL'}]}]};
  const seen = new Set();
  const modeled = await planWebLeads(surface, scope, {budget: 1, maxModelPages: 8,
    model: {model: 'fixture'}, infer: async (_model, messages) => {
      const context = JSON.parse(messages[1].content);
      assert.ok(Buffer.byteLength(messages[1].content) <= 20000);
      assert.ok(context.candidates.length <= 40);
      if (context.page === 1) assert.equal(context.catalogReference.length, 35);
      for (const row of context.candidates) seen.add(`${row.kind} ${row.path} ${row.parameter}`);
      const target = context.candidates.find(row => row.kind === 'open-redirect' && row.path === late);
      if (target) {
        assert.equal(target.purpose, 'user navigation');
        assert.equal(target.parameterMeaning, 'destination URL');
      }
      return {priorities: target ? [{kind: target.kind, path: target.path,
        parameter: target.parameter, priority: 10, why: 'Observed destination parameter'}] : []};
    }});
  assert.equal(modeled.modelCalls, 8);
  assert.deepEqual(modeled.modelCoverage, {pagesAvailable: 8, pagesSent: 8,
    candidatesAvailable: 287, candidatesSent: 287, alreadyCompleted: 0,
    preludeRoutesAvailable: 41, preludeRoutesSent: 41,
    catalogAvailable: 35, catalogSent: 35});
  assert.equal(seen.size, 287);
  assert.ok(modeled.modelCoverage.candidatesSent / modeled.modelCalls > 35);
  assert.deepEqual(modeled.selected.map(item => [item.kind, item.path, item.by]),
    [['open-redirect', late, 'model']]);

  const limited = await planWebLeads(surface, scope, {budget: 1, maxModelPages: 1,
    model: {model: 'fixture'}, infer: async () => ({priorities: [
      {kind: 'open-redirect', path: late, parameter: 'next', priority: 10, why: 'Unseen route'}]})});
  assert.equal(limited.modelCoverage.pagesSent, 1);
  assert.equal(limited.modelCoverage.candidatesSent, 40);
  assert.equal(limited.selected[0].path, patterns[0].pattern);
  assert.equal(limited.selected[0].by, 'baseline');

  const crossPage = await planWebLeads(surface, scope, {budget: 1, maxModelPages: 1,
    model: {model: 'fixture'}, infer: async () => ({priorities: [],
      strategies: [{family: 'open-redirect', path: late, parameter: 'next',
        priority: 10, why: 'The observed navigation input is relevant across pages'}],
      experiments: []})});
  assert.equal(crossPage.strategyDecisions[0].accepted, true);
  assert.deepEqual(crossPage.selected.map(item => [item.path, item.by]), [[late, 'model']]);
});

test('dense first web-planning page retains the runtime catalog reference', async () => {
  const {scope} = loadScope({origin: 'http://127.0.0.1:4329',
    overrides: {acceptLocal: true}});
  const patterns = Array.from({length: 12}, (_, index) => ({
    pattern: `/api/dense-${index}`, params: {q: []}, source: ['public-openapi']}));
  const surface = {patterns, operationNotes: patterns.map(item => ({path: item.pattern,
    purpose: `Observed behavior ${'context '.repeat(35)}`,
    parameters: [{name: 'q', meaning: `Observed input ${'detail '.repeat(35)}`}]}))};
  const contexts = [];
  const planned = await planWebLeads(surface, scope, {budget: 1, maxModelPages: 5,
    model: {model: 'fixture'}, infer: async (_model, messages) => {
      assert.ok(Buffer.byteLength(messages[1].content) <= 20000);
      contexts.push(JSON.parse(messages[1].content));
      return {priorities: [], strategies: [], experiments: []};
    }});
  assert.ok(contexts.length > 1);
  assert.equal(contexts[0].catalogReference.length, 35);
  assert.equal(planned.modelCoverage.catalogAvailable, 35);
  assert.equal(planned.modelCoverage.catalogSent, 35);
});

test('duplicate redirect oracle requires a scalar denial and a duplicate-only external Location', () => {
  const origin = 'http://127.0.0.1:4329';
  const destination = 'https://bypass-audit.invalid/0123456789abcdef-a';
  const positive = redirectPollutionUrl('/api/go', origin, 'next', destination, 'safe-first');
  assert.deepEqual(new URL(positive).searchParams.getAll('next'), ['/safe', destination]);
  const safe = {status: 302, headers: {location: '/safe'}};
  const scalar = {status: 302, headers: {location: '/safe'}};
  const duplicate = {status: 302, headers: {location: destination}};
  assert.equal(redirectPollutionOracle(safe, scalar, duplicate, destination, origin), true);
  assert.equal(redirectPollutionOracle(safe, duplicate, duplicate, destination, origin), false);
  assert.equal(redirectPollutionOracle(safe, scalar, scalar, destination, origin), false);
  assert.equal(redirectPollutionOracle(safe, scalar,
    {...duplicate, headers: {...duplicate.headers, age: '4'}}, destination, origin), false);
});

test('a recorded Muse URL meaning can queue a local SSRF probe for an unconventional parameter', async () => {
  const {scope} = loadScope({origin: 'http://127.0.0.1:4329', overrides: {acceptLocal: true}});
  const pattern = {pattern: '/api/preview', params: {resource: [], ordinary: []}, source: ['public-asset']};
  const baseline = await planWebLeads({patterns: [pattern]}, scope, {budget: 100});
  assert.ok(!baseline.selected.some(item => item.kind === 'ssrf-loopback'));
  const notes = [{path: '/api/preview', method: 'GET', purpose: 'Fetches a remote page for preview',
    parameterMeanings: [{name: 'resource', meaning: 'URL to fetch from the server'},
      {name: 'invented', meaning: 'URL to fetch from the server'}]}];
  const planned = await planWebLeads({patterns: [pattern], modelNotes: notes}, scope, {budget: 100});
  assert.deepEqual(planned.selected.filter(item => item.kind === 'ssrf-loopback')
    .map(item => [item.path, item.parameter, item.basis]),
  [['/api/preview', 'resource', 'model-parameter-meaning']]);
  const navigation = await planWebLeads({patterns: [pattern], modelNotes: [{...notes[0],
    purpose: 'Navigate the browser', parameterMeanings: [{name: 'resource', meaning: 'redirect URL'}]}]},
  scope, {budget: 100});
  assert.ok(!navigation.selected.some(item => item.kind === 'ssrf-loopback'));
  const mixed = await planWebLeads({patterns: [pattern], modelNotes: [
    {...notes[0], purpose: 'Navigate the browser',
      parameterMeanings: [{name: 'resource', meaning: 'redirect URL'}]}, notes[0]]},
  scope, {budget: 100, model: {model: 'fixture'}, infer: async (_model, messages) => {
    const candidates = JSON.parse(messages[1].content).candidates;
    assert.ok(candidates.some(item => item.kind === 'ssrf-loopback' && item.parameter === 'resource' &&
      item.parameterMeaning === 'URL to fetch from the server'));
    return {priorities: []};
  }});
  assert.ok(mixed.selected.some(item => item.kind === 'ssrf-loopback' && item.parameter === 'resource'));
});

test('a recorded Muse navigation meaning can queue an observed redirect parameter with a dotted name', async () => {
  const {scope} = loadScope({origin: 'http://127.0.0.1:4329', overrides: {acceptLocal: true}});
  const pattern = {pattern: '/api/continue', params: {'after.path': [], unrelated: []},
    source: ['public-asset']};
  const baseline = await planWebLeads({patterns: [pattern]}, scope, {budget: 100});
  assert.ok(!baseline.selected.some(item => item.kind === 'open-redirect'));
  const notes = [{path: '/api/continue', method: 'GET', purpose: 'Redirect the browser after sign-in',
    parameterMeanings: [{name: 'after.path', meaning: 'Destination URL for browser navigation'},
      {name: 'invented', meaning: 'Destination URL for browser navigation'}]}];
  const planned = await planWebLeads({patterns: [pattern], modelNotes: notes}, scope, {budget: 100});
  assert.deepEqual(planned.selected.filter(item => item.kind === 'open-redirect')
    .map(item => [item.path, item.parameter, item.basis]),
  [['/api/continue', 'after.path', 'model-parameter-meaning']]);
  const fetching = await planWebLeads({patterns: [pattern], modelNotes: [{...notes[0],
    purpose: 'Fetch a remote page for preview',
    parameterMeanings: [{name: 'after.path', meaning: 'URL to fetch from the server'}]}]},
  scope, {budget: 100});
  assert.ok(!fetching.selected.some(item => item.kind === 'open-redirect'));
  const mixed = await planWebLeads({patterns: [pattern], modelNotes: [
    {...notes[0], purpose: 'Fetch a remote page for preview',
      parameterMeanings: [{name: 'after.path', meaning: 'URL to fetch from the server'}]}, notes[0]]},
  scope, {budget: 100, model: {model: 'fixture'}, infer: async (_model, messages) => {
    const candidates = JSON.parse(messages[1].content).candidates;
    assert.ok(candidates.some(item => item.kind === 'open-redirect' && item.parameter === 'after.path' &&
      item.parameterMeaning === 'Destination URL for browser navigation'));
    return {priorities: []};
  }});
  assert.ok(mixed.selected.some(item => item.kind === 'open-redirect' && item.parameter === 'after.path'));
  assert.equal(new URL(redirectPollutionUrl('/api/continue', scope.target.origin,
    'after.path', 'https://bypass-audit.invalid/0123456789abcdef-a', 'external'))
    .searchParams.get('after.path'), 'https://bypass-audit.invalid/0123456789abcdef-a');
});

test('command-output planning requires an enabled probe and a documented parameter', async () => {
  const {scope} = loadScope({origin: 'http://127.0.0.1:4329', overrides: {acceptLocal: true}});
  const surface = {patterns: [
    {pattern: '/api/run', params: {input: []}, source: ['public-openapi']},
    {pattern: '/api/other', params: {ordinary: []}, source: ['public-openapi']},
  ]};
  const enabled = await planWebLeads(surface, scope, {budget: 100});
  assert.deepEqual(enabled.selected.filter(item => item.kind === 'command-output')
    .map(item => [item.path, item.parameter]), [['/api/run', 'input']]);
  const disabled = await planWebLeads(surface,
    {...scope, probes: {...scope.probes, commandExecution: false}}, {budget: 100});
  assert.ok(!disabled.selected.some(item => item.kind === 'command-output'));
});

test('hosts-file traversal planning requires an enabled probe and a documented file parameter', async () => {
  const {scope} = loadScope({origin: 'http://127.0.0.1:4329', overrides: {acceptLocal: true}});
  const surface = {patterns: [
    {pattern: '/api/view', params: {file: []}, source: ['public-openapi']},
    {pattern: '/api/other', params: {ordinary: []}, source: ['public-openapi']},
  ]};
  const enabled = await planWebLeads(surface, scope, {budget: 100});
  assert.deepEqual(enabled.selected.filter(item => item.kind === 'path-traversal-hosts')
    .map(item => [item.path, item.parameter]), [['/api/view', 'file']]);
  const disabled = await planWebLeads(surface,
    {...scope, probes: {...scope.probes, pathTraversal: false}}, {budget: 100});
  assert.ok(!disabled.selected.some(item => item.kind === 'path-traversal-hosts'));
});

test('Muse parameter meanings can select guarded command and local-file profiles on unusual names', async () => {
  const {scope} = loadScope({origin: 'http://127.0.0.1:4329', overrides: {acceptLocal: true}});
  const patterns = [
    {pattern: '/api/resolve', params: {operand: [], ordinary: []}, source: ['public-asset']},
    {pattern: '/api/preview', params: {resource: [], ordinary: []}, source: ['public-asset']},
  ];
  const baseline = await planWebLeads({patterns}, scope, {budget: 100});
  assert.ok(!baseline.selected.some(item => item.kind === 'command-output' ||
    item.kind === 'path-traversal-hosts'));
  const modelNotes = [
    {path: '/api/resolve', method: 'GET', purpose: 'Runs a DNS lookup command',
      parameterMeanings: [{name: 'operand', meaning: 'Hostname argument passed to the ping command'},
        {name: 'invented', meaning: 'Hostname argument passed to the ping command'}]},
    {path: '/api/preview', method: 'GET', purpose: 'Reads a local document',
      parameterMeanings: [{name: 'resource', meaning: 'Local file path to read from disk'},
        {name: 'invented', meaning: 'Local file path to read from disk'}]},
  ];
  const modeled = await planWebLeads({patterns, modelNotes}, scope, {budget: 100});
  assert.deepEqual(modeled.selected.filter(item => item.kind === 'command-output' ||
    item.kind === 'path-traversal-hosts').map(item => [item.kind, item.path,
    item.parameter, item.basis]), [
    ['command-output', '/api/resolve', 'operand', 'model-parameter-meaning'],
    ['path-traversal-hosts', '/api/preview', 'resource', 'model-parameter-meaning'],
  ]);
  await planWebLeads({patterns, modelNotes: [
    {path: '/api/preview', method: 'GET', purpose: 'Fetches a remote document',
      parameterMeanings: [{name: 'resource', meaning: 'Remote URL to fetch'}]},
    modelNotes[1]]}, scope, {budget: 100, model: {model: 'fixture'},
    infer: async (_model, messages) => {
      const candidates = JSON.parse(messages[1].content).candidates;
      assert.ok(candidates.some(item => item.kind === 'path-traversal-hosts' &&
        item.parameter === 'resource' && item.parameterMeaning === 'Local file path to read from disk'));
      return {priorities: []};
    }});
  const remote = await planWebLeads({patterns: [patterns[1]], modelNotes: [{...modelNotes[1],
    purpose: 'Fetches a remote document',
    parameterMeanings: [{name: 'resource', meaning: 'Remote URL to fetch'}]}]}, scope,
  {budget: 100});
  assert.ok(!remote.selected.some(item => item.kind === 'path-traversal-hosts'));
  const disabled = await planWebLeads({patterns, modelNotes}, {...scope, probes: {...scope.probes,
    commandExecution: false, pathTraversal: false}}, {budget: 100});
  assert.ok(!disabled.selected.some(item => item.kind === 'command-output' ||
    item.kind === 'path-traversal-hosts'));
});

test('Muse shortcut strategies require an observed GET input and unknown families receive details', async () => {
  const {scope} = loadScope({origin: 'http://127.0.0.1:4329', overrides: {acceptLocal: true}});
  const surface = {patterns: [{pattern: '/api/preview', params: {resource: []},
    methods: ['GET'], source: ['public-openapi']},
  {pattern: '/api/write', params: {resource: []}, methods: ['POST'], source: ['public-openapi']}],
  modelNotes: [{path: '/api/preview', purpose: 'Reads a local document'}]};
  const baseline = await planWebLeads(surface, scope, {budget: 100});
  assert.ok(!baseline.selected.some(item => item.kind === 'path-traversal-hosts'));
  const proposals = [{family: 'path-traversal-hosts', path: '/api/preview',
    parameter: 'resource', priority: 10, why: 'Local document path'},
  {family: 'path-traversal-hosts', path: '/api/invented',
    parameter: 'resource', priority: 10, why: 'Invented route'},
  {family: 'path-traversal-hosts', path: '/api/preview',
    parameter: 'invented', priority: 10, why: 'Invented parameter'},
  {family: 'path-traversal-hosts', path: '/api/write',
    parameter: 'resource', priority: 10, why: 'POST route'},
  {family: 'unknown', path: '/api/preview',
    parameter: 'resource', priority: 10, why: 'Unsupported family'}];
  const modeled = await planWebLeads(surface, scope, {budget: 1, model: {model: 'fixture'},
    infer: async (_model, messages) => {
      const context = JSON.parse(messages[1].content);
      assert.ok(context.candidates.some(item => item.kind === 'xss-reflected' &&
        item.path === '/api/preview' && item.parameter === 'resource'));
      return {priorities: [], strategies: proposals};
    }});
  assert.deepEqual(modeled.selected.map(item => [item.kind, item.path, item.parameter,
    item.basis, item.by]), [['path-traversal-hosts', '/api/preview', 'resource',
    'model-strategy', 'model']]);
  assert.deepEqual(modeled.strategyDecisions.map(item => [item.accepted, item.reason ?? null]),
    [[true, null], [false, 'unobserved-pair-or-unread-page'],
      [false, 'unobserved-pair-or-unread-page'],
      [false, 'unobserved-pair-or-unread-page'], [false, 'needs-executable-experiment']]);
  assert.deepEqual([modeled.strategyDecisions[0].control, modeled.strategyDecisions[0].proofOracle,
    modeled.strategyDecisions[0].page], ['missing-file control and two relative depths',
    'two-depth-hosts-file-differential', 1]);
  const disabled = await planWebLeads(surface, {...scope, probes: {...scope.probes,
    pathTraversal: false}}, {budget: 100, model: {model: 'fixture'},
    infer: async () => ({priorities: [], strategies: proposals.slice(0, 1)})});
  assert.ok(!disabled.selected.some(item => item.kind === 'path-traversal-hosts'));
  assert.equal(disabled.strategyDecisions[0].reason, 'probe-disabled');
});

test('XML entity planning requires an enabled probe and a documented XML input', async () => {
  const {scope} = loadScope({origin: 'http://127.0.0.1:4329', overrides: {acceptLocal: true}});
  const surface = {patterns: [
    {pattern: '/api/xml', params: {document: []}, source: ['public-openapi']},
    {pattern: '/api/ordinary', params: {ordinary: []}, source: ['public-openapi']},
  ]};
  const enabled = await planWebLeads(surface, scope, {budget: 100});
  assert.deepEqual(enabled.selected.filter(item => item.kind === 'xxe-hosts')
    .map(item => [item.path, item.parameter]), [['/api/xml', 'document']]);
  const disabled = await planWebLeads(surface,
    {...scope, probes: {...scope.probes, xmlExternalEntity: false}}, {budget: 100});
  assert.ok(!disabled.selected.some(item => item.kind === 'xxe-hosts'));
  const unusual = {pattern: '/api/parse', params: {blob: [], ordinary: []}, source: ['public-openapi']};
  const before = await planWebLeads({patterns: [unusual]}, scope, {budget: 100});
  assert.ok(!before.selected.some(item => item.kind === 'xxe-hosts'));
  const notes = [{path: '/api/parse', method: 'GET', purpose: 'Parses submitted XML',
    parameterMeanings: [{name: 'blob', meaning: 'XML document parsed on the server'},
      {name: 'invented', meaning: 'XML document parsed on the server'}]}];
  const interpreted = await planWebLeads({patterns: [unusual], modelNotes: notes}, scope,
    {budget: 100, model: {model: 'fixture'}, infer: async (_model, messages) => {
      const candidates = JSON.parse(messages[1].content).candidates;
      assert.ok(candidates.some(item => item.kind === 'xxe-hosts' && item.parameter === 'blob' &&
        item.parameterMeaning === 'XML document parsed on the server'));
      assert.ok(!candidates.some(item => item.kind === 'xxe-hosts' && item.parameter === 'invented'));
      return {priorities: []};
    }});
  assert.deepEqual(interpreted.selected.filter(item => item.kind === 'xxe-hosts')
    .map(item => [item.path, item.parameter, item.basis]),
  [['/api/parse', 'blob', 'model-parameter-meaning']]);
});

test('NoSQL-style equality leads need two identities, a documented ID value and a cross-account oracle', async () => {
  const {scope} = loadScope({origin: 'http://127.0.0.1:4329', overrides: {acceptLocal: true}});
  const surface = {identity: {principals: {owner: 'u-1', outsider: 'u-2'}}, patterns: [
    {pattern: '/api/lookup', params: {id: ['rec-101']}, source: ['public-openapi']},
  ]};
  const planned = await planWebLeads(surface, scope, {budget: 20});
  assert.ok(planned.selected.some(item => item.kind === 'nosql-operator-bypass' &&
    item.path === '/api/lookup' && item.parameter === 'id'));
  const noIdentity = await planWebLeads({...surface, identity: null}, scope, {budget: 20});
  assert.ok(!noIdentity.selected.some(item => item.kind === 'nosql-operator-bypass'));
  const countOnly = await planWebLeads(surface,
    {...scope, harvest: {...scope.harvest, thirdParty: 'count-only'}}, {budget: 20});
  assert.ok(!countOnly.selected.some(item => item.kind === 'nosql-operator-bypass'));
  const modeled = await planWebLeads(surface, scope, {budget: 1, model: {model: 'fixture'},
    infer: async (_model, messages) => {
      const context = JSON.parse(messages[1].content);
      assert.ok(context.candidates.some(item => item.kind === 'nosql-operator-bypass' &&
        item.path === '/api/lookup' && item.parameter === 'id'));
      return {priorities: [{kind: 'nosql-operator-bypass', path: '/api/lookup', parameter: 'id',
        priority: 10, why: 'A documented ID lookup may parse an operator object.'}]};
    }});
  assert.deepEqual(modeled.selected.map(item => [item.kind, item.by]),
    [['nosql-operator-bypass', 'model']]);
  const url = nosqlEqUrl('/api/lookup?id=rec-101', scope.target.origin, 'id', 'rec-101');
  assert.equal(new URL(url).searchParams.get('id[$eq]'), 'rec-101');
  assert.equal(new URL(url).searchParams.has('id'), false);
  const owner = {status: 200, json: true, ids: ['rec-101'], hash: 'owner-record'};
  const plain = {status: 403, json: true, ids: [], hash: 'denied'};
  const yes = {...owner};
  const no = {status: 404, json: true, ids: [], hash: 'missing'};
  assert.equal(nosqlOperatorOracle(owner, plain, yes, no, 'rec-101'), true);
  assert.equal(nosqlOperatorOracle(owner, yes, yes, no, 'rec-101'), false);
  assert.equal(nosqlOperatorOracle(owner, plain, yes, yes, 'rec-101'), false);
});

test('isolated browser proof respects the captured response CSP', async t => {
  const chrome = process.env.BYPASS_CHROME ?? 'google-chrome';
  if (spawnSync(chrome, ['--version']).error) {t.skip('Chrome is unavailable'); return;}
  const marker = '0123456789abcdef01234567';
  const body = `<html><body>${xssPayload('html-double', marker)}</body></html>`;
  assert.equal((await renderCapturedHtml(body, null, marker)).executed, true);
  assert.equal((await renderCapturedHtml(body, "script-src 'none'", marker)).executed, false);
});

test('captured HTML cannot navigate Chrome to another local service', async t => {
  const chrome = process.env.BYPASS_CHROME ?? 'google-chrome';
  if (spawnSync(chrome, ['--version']).error) {t.skip('Chrome is unavailable'); return;}
  let hits = 0;
  const target = http.createServer((_request, response) => {hits++;response.end('unexpected');});
  await new Promise(resolve => target.listen(0, '127.0.0.1', resolve));
  t.after(() => new Promise(resolve => target.close(resolve)));
  const marker = 'fedcba9876543210fedcba98';
  const destination = `http://127.0.0.1:${target.address().port}/`;
  const body = `<html><body><script>location.href=${JSON.stringify(destination)}</script></body></html>`;
  await renderCapturedHtml(body, null, marker);
  await renderCapturedHtml('<html><body><script src="/app.js"></script></body></html>', null, marker,
    {sourceUrl: 'http://127.0.0.1:4329/', scripts: [{url: 'http://127.0.0.1:4329/app.js',
      body: `location.href=${JSON.stringify(destination)}`, type: 'application/javascript'}]});
  assert.equal(hits, 0);
});

test('captured same-origin script executes a fragment DOM canary but textContent does not', async t => {
  const chrome = process.env.BYPASS_CHROME ?? 'google-chrome';
  if (spawnSync(chrome, ['--version']).error) {t.skip('Chrome is unavailable'); return;}
  const marker = '0123456789abcdef01234567';
  const sourceUrl = 'http://127.0.0.1:4329/';
  const body = `<html><body><main id="out"></main><script data-src="/decoy.js" src="${sourceUrl}app.js"></script></body></html>`;
  const scripts = code => [{url: `${sourceUrl}app.js`, body: code, type: 'application/javascript'}];
  const input = domXssFragment(marker);
  const vulnerable = `document.getElementById('out').innerHTML=decodeURIComponent(location.hash.slice(1));`;
  const fixed = `document.getElementById('out').textContent=decodeURIComponent(location.hash.slice(1));`;
  assert.equal((await renderCapturedHtml(body, null, marker,
    {sourceUrl, fragment: input, scripts: scripts(vulnerable)})).executed, true);
  assert.equal((await renderCapturedHtml(body, null, marker,
    {sourceUrl, fragment: input, scripts: scripts(fixed)})).executed, false);
  assert.equal((await renderCapturedHtml(body, "script-src 'none'", marker,
    {sourceUrl, fragment: input, scripts: scripts(vulnerable)})).executed, false);
  assert.equal((await renderCapturedHtml(body, ["script-src 'self'", "script-src 'none'"], marker,
    {sourceUrl, fragment: input, scripts: scripts(vulnerable)})).executed, false);
});
