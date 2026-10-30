import test from 'node:test';
import assert from 'node:assert/strict';
import {scheduleResearchTracks} from '../src/blackbox/research-scheduler.mjs';
import {loadScope} from '../src/blackbox/scope.mjs';
import {runWebProbes} from '../src/blackbox/web-probes.mjs';

const tracks = [
  {name: 'access', count: 2, evidence: ['Two denied-to-allowed routes']},
  {name: 'sequence', count: 18, evidence: ['POST /api/records has a JSON body contract']},
  {name: 'web', count: 40, evidence: ['GET /search has a query input']},
];

test('Muse orders existing research tools and allocates remaining calls by observed priority', async () => {
  let calls = 0;
  const result = await scheduleResearchTracks({tracks, facts: ['Protected routes changed after login'],
    infer: async (_model, messages, {schema}) => {
      calls++;
      const context = JSON.parse(messages[1].content);
      assert.equal(context.tracks.length, 3);
      assert.ok(context.facts.includes('Protected routes changed after login'));
      assert.equal(schema.properties.priorities.type, 'array');
      return {priorities: [
        {name: 'sequence', weight: 6, why: 'Observed JSON body contract'},
        {name: 'access', weight: 2, why: 'Observed access transition'},
        {name: 'web', weight: 1, why: 'Observed search input'},
      ]};
    }, model: {model: 'fixture'}, modelCallsAvailable: 10,
    taskBudgetAvailable: 30});
  assert.equal(calls, 1);
  assert.equal(result.modelCalls, 1);
  assert.deepEqual(result.order, ['sequence', 'access', 'web']);
  assert.deepEqual(result.weightsByTrack, {sequence: 6, access: 2, web: 1});
  assert.deepEqual(result.callsByTrack, {sequence: 6, access: 2, web: 1});
  assert.deepEqual(result.tasksByTrack, {sequence: 20, access: 7, web: 3});
  assert.equal(result.decision.priorities[0].why, 'Observed JSON body contract');
});

test('a partial Muse rank never removes an available research tool', async () => {
  const result = await scheduleResearchTracks({tracks, infer: async () => ({priorities: [
    {name: 'web', weight: 3, why: 'Observed query'},
  ]}), model: {model: 'fixture'}, modelCallsAvailable: 7});
  assert.deepEqual(result.order, ['web', 'access', 'sequence']);
  assert.deepEqual(result.callsByTrack, {web: 4, access: 1, sequence: 1});
});

test('a low Muse weight retains one planning call and task for an observed web input', async () => {
  const result = await scheduleResearchTracks({tracks, infer: async () => ({priorities: [
    {name: 'access', weight: 100, why: 'Observed access transition'},
    {name: 'sequence', weight: 100, why: 'Observed method contract'},
    {name: 'web', weight: 1, why: 'Observed search input'},
  ]}), model: {model: 'fixture'}, modelCallsAvailable: 10,
  taskBudgetAvailable: 9});
  assert.equal(result.callsByTrack.web, 1);
  assert.equal(result.tasksByTrack.web, 1);
  assert.equal(Object.values(result.callsByTrack).reduce((sum, count) => sum + count), 9);
  assert.equal(Object.values(result.tasksByTrack).reduce((sum, count) => sum + count), 9);
});

test('ample task allowance keeps every observed lead despite a low Muse weight', async () => {
  const result = await scheduleResearchTracks({tracks, infer: async () => ({priorities: [
    {name: 'sequence', weight: 100, why: 'Observed method contract'},
    {name: 'access', weight: 1, why: 'Observed access transition'},
    {name: 'web', weight: 1, why: 'Observed search input'},
  ]}), model: {model: 'fixture'}, modelCallsAvailable: 10,
  taskBudgetAvailable: 80});
  assert.ok(result.tasksByTrack.access >= 2);
  assert.ok(result.tasksByTrack.sequence >= 18);
  assert.ok(result.tasksByTrack.web >= 40);
  assert.equal(Object.values(result.tasksByTrack)
    .reduce((sum, count) => sum + count), 80);
});

test('without Muse, all available research tools remain scheduled', async () => {
  const result = await scheduleResearchTracks({tracks, modelCallsAvailable: 6});
  assert.equal(result.modelCalls, 0);
  assert.deepEqual(result.order, ['access', 'sequence', 'web']);
  assert.deepEqual(result.callsByTrack, {access: 2, sequence: 2, web: 2});
});

test('tracks with no observed surface do not strand Muse calls or task slots', async () => {
  const sparse = [
    {name: 'access', count: 0, evidence: []},
    {name: 'sequence', count: 1, evidence: ['Observed query input']},
    {name: 'web', count: 1, evidence: ['Observed query input']},
    {name: 'stored', count: 0, evidence: []},
  ];
  let names;
  const result = await scheduleResearchTracks({tracks: sparse,
    infer: async (_model, messages) => {
      names = JSON.parse(messages[1].content).tracks.map(item => item.name);
      return {priorities: []};
    }, model: {model: 'fixture'}, modelCallsAvailable: 19,
    taskBudgetAvailable: 10});
  assert.deepEqual(names, ['access', 'sequence', 'web', 'stored']);
  assert.equal(result.callsByTrack.access, 0);
  assert.equal(result.callsByTrack.stored, 0);
  assert.equal(result.callsByTrack.sequence + result.callsByTrack.web, 18);
  assert.equal(result.tasksByTrack.sequence + result.tasksByTrack.web, 10);
});

test('Muse scheduling errors keep the full fallback schedule and charge the attempted call', async () => {
  const result = await scheduleResearchTracks({tracks, infer: async () => {
    throw Error('temporary model failure');
  }, model: {model: 'fixture'}, modelCallsAvailable: 4});
  assert.equal(result.modelCalls, 1);
  assert.match(result.modelError, /temporary model failure/);
  assert.deepEqual(result.order, ['access', 'sequence', 'web']);
  assert.deepEqual(result.callsByTrack, {access: 1, sequence: 1, web: 1});
});

test('a derived authenticated response is not described to Muse as anonymous access', async () => {
  const origin = 'http://127.0.0.1:49383';
  const scope = loadScope({origin, overrides: {acceptLocal: true}}).scope;
  let context;
  const infer = async (_model, messages) => {
    if (messages[0].content.startsWith('Allocate the next black-box investigation effort')) {
      context = JSON.parse(messages[1].content);
      return {priorities: []};
    }
    return {priorities: [], strategies: [], experiments: [], flows: []};
  };
  await runWebProbes({patterns: [{pattern: '/private/item', methods: ['GET'],
    params: {q: ['1']}, responseFacts: {identity: 'derived-session',
      status: 200, anonymousStatus: 401}}]}, scope, {
    requester: async () => {throw Error('No request was queued');},
    infer, model: {model: 'fixture'}, budget: 0, maxModelPages: 2,
    derivedSession: {loginProof: {}, requestAuthenticated: async () => {}}});
  assert.ok(context.facts.some(fact => fact.includes('anonymous=401 authenticated=200')));
  assert.ok(context.tracks.find(track => track.name === 'sequence')
    .evidence.includes('derived session available'));
  assert.equal(context.tracks.find(track => track.name === 'access').count, 1,
    'a confirmed derived bearer makes the observed protected read eligible for access planning');
});

test('a slow first-ranked access attempt cannot prevent the first Muse web page', async () => {
  const origin = 'http://127.0.0.1:49384';
  const scope = loadScope({origin, overrides: {acceptLocal: true}}).scope;
  const surface = {patterns: [
    {pattern: '/private/item', methods: ['GET'], params: {},
      responseFacts: {identity: 'derived-session', status: 200,
        anonymousStatus: 401, type: 'application/json'}},
    {pattern: '/search', methods: ['GET'], params: {q: ['plain']},
      responseFacts: {status: 200, type: 'application/json'}}]};
  const events = [];
  let requests = 0;
  const infer = async (_model, messages) => {
    const prompt = messages[0].content;
    if (prompt.startsWith('Allocate the next black-box investigation effort'))
      return {priorities: [
        {name: 'access', weight: 100, why: 'Observed protected read'},
        {name: 'web', weight: 1, why: 'Observed search input'},
        {name: 'sequence', weight: 1, why: 'Observed read routes'}]};
    if (prompt.startsWith('You are investigating whether an observed anonymous GET')) {
      events.push('access-page');
      return {tests: [{family: 'Access boundary', why: 'Observed filter and denied read',
        priority: 8, comparison: 'exact-body', protectedPath: '/private/item',
        subject: {method: 'GET', path: '/search', placement: 'query',
          key: 'q', fixedFields: []}, controlValue: 'plain',
        firstValue: 'one', secondValue: 'two', ownerPointer: '',
        candidatePointer: '', identityField: '', matchFields: []}]};
    }
    if (prompt.startsWith('Rank only the supplied observed read-only web-test candidates')) {
      events.push('web-page');
      return {priorities: [], strategies: [], experiments: []};
    }
    if (prompt.startsWith('You are planning bounded, authorized HTTP research'))
      return {flows: []};
    return {priorities: [], strategies: [], experiments: [], flows: [],
      checks: [], tests: []};
  };
  const response = (url, status) => {
    const body = status === 200 ? JSON.stringify({value: 'ordinary response'}) :
      '{"error":"denied"}';
    return {status, type: 'application/json', body, bytes: body.length,
      headers: {'content-type': 'application/json'},
      evidenceId: `ev-${String(++requests).padStart(4, '0')}`};
  };
  const requester = async ({url}) => {
    const pathname = new URL(url, origin).pathname;
    if (pathname === '/search') {
      events.push('access-attempt');
      await new Promise(resolve => setTimeout(resolve, 90));
    }
    return response(url, pathname === '/private/item' ? 401 : 200);
  };
  const run = await runWebProbes(surface, scope, {requester, infer,
    model: {model: 'fixture'}, budget: 6, maxModelPages: 10,
    researchDeadline: Date.now() + 60,
    derivedSession: {loginProof: {kind: 'fixture'},
      requestAuthenticated: async ({url}) => response(url, 200)}});
  assert.ok(events.includes('access-page'));
  assert.ok(events.includes('web-page'));
  assert.ok(events.includes('access-attempt'));
  assert.ok(events.indexOf('web-page') < events.indexOf('access-attempt'),
    'the first web planning page runs before deep access execution');
  assert.ok(run.modelCoverage.pagesSent >= 1);
});

test('an accepted access boundary runs before later web pages and sequence feedback', async () => {
  const origin = 'http://127.0.0.1:49386';
  const scope = loadScope({origin, overrides: {acceptLocal: true}}).scope;
  const surface = {patterns: [
    {pattern: '/private/member', methods: ['GET'], params: {},
      responseFacts: {identity: 'derived-session', status: 200,
        anonymousStatus: 401, type: 'application/json'}},
    ...Array.from({length: 24}, (_, index) => ({
      pattern: `/catalog/${index}`, methods: ['GET'],
      params: {q: ['ordinary']},
      responseFacts: {status: 200, type: 'application/json'}})),
  ]};
  const events = [];
  let evidence = 0;
  const privateRecord = {id: 'member', title: 'private',
    note: 'Only the authenticated fixture session may read this private record.'};
  const respond = (status, body) => ({status, body: JSON.stringify(body),
    type: 'application/json', headers: {'cache-control': 'no-store'},
    evidenceId: `ev-${++evidence}`});
  const requester = async ({url}) => {
    const target = new URL(url, origin);
    if (target.pathname === '/private/member') return respond(401, {error: 'denied'});
    if (target.pathname === '/catalog/0') {
      const q = target.searchParams.get('q');
      if (q === '*') events.push('access-http');
      else if (q?.startsWith('seq-')) events.push('sequence-http');
      return respond(200, q === '*' ? privateRecord :
        {id: 'public', title: 'ordinary'});
    }
    return respond(200, {items: [{id: 'public'}]});
  };
  const infer = async (_model, messages, {schema} = {}) => {
    const prompt = messages[0].content;
    const context = JSON.parse(messages[1].content);
    if (prompt.startsWith('Allocate the next black-box investigation effort'))
      return {priorities: [
        {name: 'access', weight: 100, why: 'Denied-to-allowed private record'},
        {name: 'sequence', weight: 30, why: 'Observed query contract'},
        {name: 'web', weight: 20, why: 'Observed public queries'}]};
    if (prompt.startsWith('You are investigating whether an observed anonymous GET'))
      return {tests: [{family: 'record boundary', why: 'Public query may leak the private record',
        priority: 10, comparison: 'exact-body', protectedPath: '/private/member',
        subject: {method: 'GET', path: '/catalog/0', placement: 'query',
          key: 'q', fixedFields: []}, controlValue: 'ordinary',
        firstValue: '*', secondValue: 'other', ownerPointer: '',
        candidatePointer: '', identityField: '', matchFields: []}]};
    if (prompt.startsWith('Rank only the supplied observed read-only web-test candidates')) {
      events.push('web-page');
      return {priorities: [], strategies: [], experiments: []};
    }
    if (prompt.startsWith('You are planning bounded, authorized HTTP research.'))
      return {flows: [{family: 'observed-query', why: 'Compare the observed query response',
        priority: 8, as: 'anonymous', oracle: 'observation', protectedPath: '',
        prelude: [], observe: [], binding: null,
        subject: {method: 'GET', path: '/catalog/0', placement: 'query',
          key: 'q', fixedFields: [], bodyTemplate: '', headers: []},
        controlValue: 'ordinary', firstValue: 'seq-one', secondValue: 'seq-two',
        marker: context.marker, secondMarker: context.secondMarker,
        assertion: {step: 'subject', index: 0, location: 'body', name: ''}}]};
    if (prompt.startsWith('Revise at most one bounded, authorized HTTP experiment')) {
      events.push('sequence-feedback');
      return {flows: []};
    }
    const blank = item => item?.type === 'object' ? Object.fromEntries(
      (item.required ?? []).map(key => [key, blank(item.properties?.[key])])) :
      item?.type === 'array' ? [] : item?.type === 'integer' ||
      item?.type === 'number' ? 0 : item?.type === 'boolean' ? false :
      item?.enum?.[0] ?? '';
    return blank(schema);
  };
  const run = await runWebProbes(surface, scope, {requester, infer,
    model: {model: 'fixture'}, budget: 100, maxModelPages: 24,
    remainingModelCalls: () => 24, researchDeadline: Date.now() + 10000,
    derivedSession: {loginProof: {kind: 'fixture'},
      requestAuthenticated: async () => respond(200, privateRecord)}});
  assert.ok(events.filter(item => item === 'web-page').length > 1,
    `web pagination was not exercised: ${events}`);
  assert.ok(events.includes('access-http'), `accepted access plan was not run: ${JSON.stringify({events, accessResults: run.results.filter(item => item.kind === 'model-access-boundary'), accessInvestigations: run.investigations.filter(item => item.kind === 'model-access-boundary')})}`);
  assert.ok(events.indexOf('access-http') < events.lastIndexOf('web-page'),
    `later web pages ran before Muse's top-ranked access plan: ${events}`);
  assert.ok(!events.includes('sequence-feedback') ||
    events.indexOf('access-http') < events.indexOf('sequence-feedback'),
  `deep sequence feedback ran before Muse's top-ranked access plan: ${events}`);
  assert.ok(run.results.some(item => item.kind === 'model-access-boundary' &&
    item.verdict === 'confirmed'));
});

test('unused calls continue one attempted HTTP sequence after other tracks get a page', async () => {
  const origin = 'http://127.0.0.1:49385';
  const scope = loadScope({origin, overrides: {acceptLocal: true}}).scope;
  const surface = {patterns: [
    {pattern: '/private/item', methods: ['GET'], params: {},
      responseFacts: {identity: 'derived-session', status: 200,
        anonymousStatus: 403, type: 'application/json'}},
    {pattern: '/query', methods: ['GET'], params: {q: ['plain']},
      responseFacts: {status: 200, type: 'application/json'}}]};
  const events = [];
  let modelCalls = 0, revisions = 0, requests = 0;
  const flow = (context, number) => ({family: 'observed-query',
    why: 'Follow the observed query response', priority: 8,
    as: 'anonymous', oracle: 'observation', protectedPath: '',
    prelude: [], observe: [], binding: null,
    subject: {method: 'GET', path: '/query', placement: 'query', key: 'q',
      fixedFields: [], bodyTemplate: '', headers: []},
    controlValue: `control-${number}`, firstValue: `first-${number}`,
    secondValue: `second-${number}`, marker: context.marker,
    secondMarker: context.secondMarker,
    assertion: {step: 'subject', index: 0, location: 'body', name: ''}});
  const infer = async (_model, messages) => {
    modelCalls++;
    const prompt = messages[0].content;
    const context = JSON.parse(messages[1].content);
    if (prompt.startsWith('Allocate the next black-box investigation effort'))
      return {priorities: [
        {name: 'access', weight: 100, why: 'Protected read changed after login'},
        {name: 'sequence', weight: 12, why: 'Observed query merits research'},
        {name: 'web', weight: 1, why: 'Documented query input'}]};
    if (prompt.startsWith('You are investigating whether an observed anonymous GET')) {
      events.push('access-page');
      return {tests: []};
    }
    if (prompt.startsWith('Rank only the supplied observed read-only web-test candidates')) {
      events.push('web-page');
      return {priorities: [], strategies: [], experiments: []};
    }
    if (prompt.startsWith('You are planning bounded, authorized HTTP research.'))
      return {flows: [flow(context, 0)]};
    if (prompt.startsWith('Revise at most one bounded, authorized HTTP experiment')) {
      revisions++;
      events.push(`revision-${revisions}`);
      return {flows: revisions < 12 ? [flow(context, revisions)] : []};
    }
    return {priorities: [], strategies: [], experiments: [], flows: [], tests: []};
  };
  const response = (status, value = '') => {
    const body = JSON.stringify({value});
    return {status, type: 'application/json', body, bytes: body.length,
      headers: {'content-type': 'application/json', 'cache-control': 'no-store'},
      evidenceId: `ev-${String(++requests).padStart(4, '0')}`};
  };
  const run = await runWebProbes(surface, scope, {
    requester: async ({url}) => {
      const parsed = new URL(url, origin);
      return parsed.pathname === '/private/item' ? response(403, 'denied') :
        response(200, parsed.searchParams.get('q') ?? 'plain');
    },
    derivedSession: {loginProof: {kind: 'fixture'},
      requestAuthenticated: async () => response(200, 'owner record')},
    infer, model: {model: 'fixture'}, budget: 12, maxModelPages: 50,
    remainingModelCalls: () => 50 - modelCalls});
  assert.ok(revisions > 8, `sequence stopped after only ${revisions} feedback calls`);
  assert.ok(events.includes('access-page') && events.includes('web-page'));
  assert.ok(events.indexOf('web-page') < events.indexOf('revision-9'),
    'the web track must see its first page before sequence rollover');
  assert.ok(run.modelCoverage.httpSequenceFeedbackRolloverCalls > 0);
  assert.equal(run.modelCalls, modelCalls, 'research calls must be charged exactly once');
  assert.equal(run.results.filter(item => item.proposalId &&
    item.kind.startsWith('model-http')).length, 1,
  'a continued sequence remains one task');
});
