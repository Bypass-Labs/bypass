import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import {randomBytes} from 'node:crypto';
import {loadScope} from '../src/blackbox/scope.mjs';
import {planAccessBoundaries, runAccessBoundaries} from '../src/blackbox/access-boundary.mjs';

test('Muse selects a reviewed public POST and code independently proves owner-only data crossed it', async t => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'bypass-boundary-'));
  t.after(() => fs.rmSync(dir, {recursive: true, force: true}));
  const suffix = randomBytes(4).toString('hex');
  const privateId = `prv-${suffix}`;
  const privatePath = `/api/${suffix}/records/${privateId}`;
  const postPath = `/api/${suffix}/filter`;
  const decoy = `/api/${suffix}/delete`;
  const origin = 'http://127.0.0.1:49991';
  const scopeFile = path.join(dir, 'scope.json');
  fs.writeFileSync(scopeFile, JSON.stringify({schemaVersion: 1, target: {origin},
    include: ['/'], identities: {identityPath: privatePath},
    probes: {jsonPostPaths: [postPath]}, limits: {rps: 100}}));
  const scope = loadScope({file: scopeFile, origin}).scope;
  const surface = {patterns: [{pattern: privatePath, methods: ['GET'],
    fingerprint: {owner: {status: 200, shape: {id: 'string', title: 'string'}},
      anonymous: {status: 403}}}],
  jsonBodyOperations: [{path: postPath, method: 'POST', contentType: 'application/json',
    fields: ['term'], requiredFields: ['term'], fieldExamples: {term: ['apple']},
    purpose: 'Search public catalog; owner-only records must be excluded'}]};
  const payload = (context, pathValue = postPath) => ({family: 'query boundary',
    why: 'A public filter may return an owner-only record', priority: 8,
    protectedPath: privatePath,
    subject: {method: 'POST', path: pathValue, placement: 'json', key: 'term',
      fixedFields: []}, controlValue: 'apple',
    firstValue: "apple' OR 1=1 --", secondValue: "pear' OR 2=2 --",
    ownerPointer: '', candidatePointer: '/records', identityField: 'id',
    matchFields: ['id', 'title']});
  const infer = async (_model, messages) => {
    const context = JSON.parse(messages[1].content);
    assert.equal(context.protectedReads[0].path, privatePath);
    assert.deepEqual(context.publicPosts[0].fieldExamples.term, ['apple']);
    const wrongShape = payload(context);
    wrongShape.subject = {...wrongShape.subject, method: 'GET',
      placement: 'query', key: 'unobserved'};
    return {tests: [payload(context, decoy), wrongShape]};
  };
  const env = {OWNER_TOKEN: `owner-${suffix}`};
  const planned = await planAccessBoundaries(surface, scope, {infer,
    model: 'fixture', env, budget: 4, modelCallsAvailable: 1});
  assert.equal(planned.leads.length, 1);
  assert.deepEqual(planned.decisions.map(item => [item.accepted, item.reason]),
    [[false, 'unobserved-route'], [true, undefined]]);
  assert.equal(planned.decisions[1].requestShapeNormalized, true);
  let evidence = 0, decoyHits = 0, flakyPositive = false, positiveHits = 0;
  const privateRecord = {id: privateId, title: `internal-${suffix}`};
  const requester = async request => {
    assert.ok(new Set(['control', 'task', 'reverify']).has(request.step),
      `Unsupported ledger step: ${request.step}`);
    const pathname = new URL(request.url, origin).pathname;
    if (pathname === decoy) decoyHits++;
    let status, body;
    if (request.method === 'GET' && pathname === privatePath) {
      status = request.identity === 'owner' ? 200 : 403;
      body = status === 200 ? privateRecord : {error: 'owner session required'};
    } else if (request.method === 'POST' && pathname === postPath) {
      status = 200;
      const term = JSON.parse(request.body).term;
      const injected = term.includes(' OR ');
      if (injected && flakyPositive) positiveHits++;
      body = {records: injected && (!flakyPositive || positiveHits === 1) ?
        [{id: `pub-${suffix}`, title: 'apple'}, privateRecord] :
        term.startsWith('decoy-') ?
          [{id: privateId, title: 'public decoy'}] :
        [{id: `pub-${suffix}`, title: 'apple'}]};
    } else {status = 404; body = {error: 'missing'};}
    return {status, body: JSON.stringify(body), type: 'application/json',
      headers: {'cache-control': 'no-store'}, evidenceId: `ev-${++evidence}`};
  };
  const run = await runAccessBoundaries(planned.leads, scope, {requester,
    surface, env, modelCallsAvailable: 0});
  assert.equal(run.results[0].verdict, 'confirmed');
  assert.equal(run.findings.length, 1);
  assert.equal(run.findings[0].webProof.request.method, 'POST');
  assert.equal(run.investigations[0].attempts.length, 1);
  assert.equal(decoyHits, 0);

  const ordinary = {...planned.leads[0], firstValue: 'banana', secondValue: 'pear'};
  const revise = async (_model, messages) => {
    const context = JSON.parse(messages[1].content);
    assert.equal(context.comparator.protectedPath, privatePath);
    assert.deepEqual(context.history[0].input, {field: 'term', controlValue: 'apple',
      firstValue: 'banana', secondValue: 'pear'});
    return {tests: [{...payload(context), protectedPath: '/unobserved',
      subject: {method: 'GET', path: postPath, placement: 'query', key: 'other',
        fixedFields: []}, ownerPointer: '/wrong', candidatePointer: '/wrong',
      identityField: 'wrong', matchFields: ['wrong'],
      firstValue: "apple' OR 1=1 --", secondValue: "pear' OR 2=2 --"}]};
  };
  const revised = await runAccessBoundaries([ordinary], scope, {requester, surface,
    env, infer: revise, model: 'fixture', modelCallsAvailable: 2});
  assert.equal(revised.investigations[0].attempts.length, 2);
  assert.equal(revised.decisions[0].accepted, true);
  assert.equal(revised.results[0].verdict, 'confirmed');
  assert.equal(revised.findings.length, 1);
  assert.equal(decoyHits, 0);

  const single = await runAccessBoundaries([{...planned.leads[0],
    firstValue: 'decoy-one'}], scope, {requester, surface, env,
    modelCallsAvailable: 0});
  const oneAttempt = single.investigations[0].attempts[0];
  const oneBoundary = oneAttempt.controls.find(item => item.label === 'object-boundary');
  assert.equal(single.results[0].verdict, 'confirmed');
  assert.match(single.findings[0].rule, /fresh-repeat/);
  assert.deepEqual([oneBoundary.first, oneBoundary.second,
    oneBoundary.repeatMatch, oneBoundary.repeatControlExcluded,
    oneBoundary.finalOwnerStable, oneBoundary.finalAnonymousDenied],
  [false, true, true, true, true, true]);
  assert.ok(oneAttempt.controls.some(item => item.label === 'candidate-recheck'));
  assert.ok(oneAttempt.controls.some(item => item.label === 'public-recheck'));
  assert.ok(oneAttempt.controls.some(item => item.label === 'anonymous-final'));
  assert.equal(single.findings[0].webSteps.find(item =>
    item.probe === 'public-recheck').method, 'POST');

  flakyPositive = true;
  positiveHits = 0;
  const unstable = await runAccessBoundaries([{...planned.leads[0],
    firstValue: 'decoy-one'}], scope, {requester, surface, env,
    modelCallsAvailable: 0});
  assert.equal(unstable.results[0].verdict, 'inconclusive');
  assert.equal(unstable.findings.length, 0);
  assert.equal(unstable.investigations[0].attempts[0].controls
    .find(item => item.label === 'object-boundary').repeatMatch, false);
  flakyPositive = false;

  const decoyOnly = await runAccessBoundaries([{...planned.leads[0],
    firstValue: 'decoy-one', secondValue: 'decoy-two'}], scope,
  {requester, surface, env, modelCallsAvailable: 0});
  assert.equal(decoyOnly.results[0].verdict, 'not_reproduced');
  assert.equal(decoyOnly.findings.length, 0);
  assert.equal(decoyHits, 0);
});

test('Muse repairs an unobserved access-revision field before a second HTTP attempt', async t => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'bypass-boundary-repair-'));
  t.after(() => fs.rmSync(dir, {recursive: true, force: true}));
  const origin = 'http://127.0.0.1:49992', postPath = '/api/filter';
  const privatePath = '/api/private';
  const scopeFile = path.join(dir, 'scope.json');
  fs.writeFileSync(scopeFile, JSON.stringify({schemaVersion: 1, target: {origin},
    include: ['/'], identities: {identityPath: privatePath},
    probes: {jsonPostPaths: [postPath]}, limits: {rps: 100}}));
  const scope = loadScope({file: scopeFile, origin}).scope;
  const surface = {patterns: [{pattern: privatePath, methods: ['GET'],
    fingerprint: {owner: {status: 200}, anonymous: {status: 403}}}],
  jsonBodyOperations: [{path: postPath, method: 'POST',
    contentType: 'application/json', fields: ['term', 'mode'],
    requiredFields: ['mode']}]};
  const base = {family: 'query boundary', why: 'Public filter may expose private data',
    priority: 8, comparison: 'object', protectedPath: privatePath,
    subject: {method: 'POST', path: postPath, placement: 'json', key: 'term',
      fixedFields: [{field: 'mode', value: 'preview'}]},
    controlValue: 'plain', firstValue: 'wrong-one', secondValue: 'wrong-two',
    ownerPointer: '', candidatePointer: '/records', identityField: 'id',
    matchFields: ['id', 'title']};
  let requests = 0, calls = 0;
  const requester = async request => {
    requests++;
    let status = 200, body;
    if (request.url === privatePath) {
      status = request.identity === 'owner' ? 200 : 403;
      body = JSON.stringify(request.identity === 'owner' ?
        {id: 'private-1', title: 'owner'} : {error: 'denied'});
    } else {
      const submitted = JSON.parse(request.body);
      assert.deepEqual(Object.keys(submitted).sort(), ['mode', 'term']);
      body = JSON.stringify({records: ['candidate-one', 'candidate-two']
        .includes(submitted.term) ? [{id: 'private-1', title: 'owner'}] : []});
    }
    return {status, body, type: 'application/json', headers: {},
      evidenceId: `ev-${requests}`};
  };
  const run = await runAccessBoundaries([base], scope, {requester, surface,
    env: {OWNER_TOKEN: 'owner-fixture'}, model: 'fixture', modelCallsAvailable: 2,
    infer: async (_model, messages, options) => {
      calls++;
      if (calls === 1) return {tests: [{...base,
        subject: {...base.subject, key: 'unseen'},
        firstValue: 'candidate-one', secondValue: 'candidate-two'}]};
      const repair = JSON.parse(messages[1].content);
      assert.equal(repair.rejectedSubject.key, 'unseen');
      assert.deepEqual(repair.observedInputs[0].fields, ['term', 'mode']);
      assert.deepEqual(options?.schema?.properties?.tests?.items?.properties?.subject
        ?.properties?.key?.enum, ['term', 'mode']);
      return {tests: [{...base, firstValue: 'candidate-one',
        secondValue: 'candidate-two'}]};
    }});
  assert.equal(calls, 2);
  assert.equal(run.decisions[0].accepted, true);
  assert.equal(run.decisions[0].repairedByMuse, true);
  assert.equal(run.investigations[0].attempts.length, 2);
});

test('Muse repairs access-boundary values using the observed contract before execution', async t => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'bypass-boundary-values-'));
  t.after(() => fs.rmSync(dir, {recursive: true, force: true}));
  const origin = 'http://127.0.0.1:49993';
  const privatePath = '/api/private', postPath = '/api/filter';
  const scopeFile = path.join(dir, 'scope.json');
  fs.writeFileSync(scopeFile, JSON.stringify({schemaVersion: 1, target: {origin},
    include: ['/'], identities: {identityPath: privatePath},
    probes: {jsonPostPaths: [postPath]}, limits: {rps: 100}}));
  const scope = loadScope({file: scopeFile, origin}).scope;
  const surface = {patterns: [{pattern: privatePath, methods: ['GET'],
    fingerprint: {owner: {status: 200}, anonymous: {status: 403}}}],
  jsonBodyOperations: [{path: postPath, method: 'POST', contentType: 'application/json',
    fields: ['term', 'mode'], requiredFields: ['mode']}]};
  const proposal = {family: 'query boundary', why: 'Public filter may expose owner data',
    priority: 8, comparison: 'object', protectedPath: privatePath,
    subject: {method: 'POST', path: postPath, placement: 'json', key: 'term',
      fixedFields: [{field: 'mode', value: 'preview'}]},
    controlValue: 'plain', firstValue: 'bad;value', secondValue: 'other',
    ownerPointer: '', candidatePointer: '/records', identityField: 'id',
    matchFields: ['id', 'title']};
  let calls = 0;
  const planned = await planAccessBoundaries(surface, scope, {
    env: {OWNER_TOKEN: 'fixture-owner'}, model: 'fixture', budget: 1,
    modelCallsAvailable: 2, infer: async (_model, messages, options) => {
      calls++;
      if (calls === 1) return {tests: [proposal]};
      const repair = JSON.parse(messages[1].content);
      assert.equal(repair.failure, 'invalid-boundary-values');
      assert.deepEqual(options.schema.properties.tests.items.properties.subject
        .properties.key.enum, ['term', 'mode']);
      return {tests: [{...proposal, firstValue: 'candidate-one',
        secondValue: 'candidate-two'}]};
    }});
  assert.equal(calls, 2);
  assert.equal(planned.modelCalls, 2);
  assert.equal(planned.leads.length, 1);
  assert.equal(planned.decisions[0].accepted, true);
  assert.equal(planned.decisions[0].repairedByMuse, true);
  assert.equal(planned.leads[0].firstValue, 'candidate-one');
  let requests = 0;
  const run = await runAccessBoundaries(planned.leads, scope, {
    surface, env: {OWNER_TOKEN: 'fixture-owner'}, modelCallsAvailable: 0,
    requester: async request => {
      requests++;
      if (request.url === privatePath) return {status: request.identity === 'owner' ? 200 : 403,
        body: JSON.stringify(request.identity === 'owner' ?
          {id: 'private', title: 'owner'} : {error: 'denied'}),
        type: 'application/json', headers: {}, evidenceId: `ev-${requests}`};
      const body = JSON.parse(request.body);
      assert.deepEqual(Object.keys(body).sort(), ['mode', 'term']);
      assert.notEqual(body.term, 'bad;value');
      return {status: 200, body: JSON.stringify({records:
        body.term === 'plain' ? [] : [{id: 'private', title: 'owner'}]}),
      type: 'application/json', headers: {}, evidenceId: `ev-${requests}`};
    }});
  assert.equal(run.results[0].verdict, 'confirmed');
  assert.ok(requests >= 7);
});

test('Muse repairs an initial access-boundary field against the observed POST contract', async t => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'bypass-boundary-initial-field-'));
  t.after(() => fs.rmSync(dir, {recursive: true, force: true}));
  const origin = 'http://127.0.0.1:49994';
  const privatePath = '/api/private', postPath = '/api/filter';
  const scopeFile = path.join(dir, 'scope.json');
  fs.writeFileSync(scopeFile, JSON.stringify({schemaVersion: 1, target: {origin},
    include: ['/'], identities: {identityPath: privatePath},
    probes: {jsonPostPaths: [postPath]}, limits: {rps: 100}}));
  const scope = loadScope({file: scopeFile, origin}).scope;
  const surface = {patterns: [{pattern: privatePath, methods: ['GET'],
    fingerprint: {owner: {status: 200}, anonymous: {status: 403}}}],
  jsonBodyOperations: [{path: postPath, method: 'POST', contentType: 'application/json',
    fields: ['term', 'mode'], requiredFields: ['mode']}]};
  const proposal = {family: 'query boundary', why: 'Public filter may expose owner data',
    priority: 8, comparison: 'object', protectedPath: privatePath,
    subject: {method: 'POST', path: postPath, placement: 'json', key: 'missing',
      fixedFields: [{field: 'mode', value: 'preview'}]},
    controlValue: 'plain', firstValue: 'candidate-one', secondValue: 'candidate-two',
    ownerPointer: '', candidatePointer: '/records', identityField: 'id',
    matchFields: ['id', 'title']};
  let calls = 0;
  const planned = await planAccessBoundaries(surface, scope, {
    env: {OWNER_TOKEN: 'fixture-owner'}, model: 'fixture', budget: 1,
    modelCallsAvailable: 2, infer: async (_model, messages, options) => {
      calls++;
      if (calls === 1) return {tests: [proposal]};
      const repair = JSON.parse(messages[1].content);
      assert.equal(repair.failure, 'unobserved-field');
      assert.deepEqual(options.schema.properties.tests.items.properties.subject
        .properties.key.enum, ['term', 'mode']);
      return {tests: [{...proposal, subject: {...proposal.subject, key: 'term'}}]};
    }});
  assert.equal(calls, 2);
  assert.equal(planned.leads.length, 1);
  assert.equal(planned.leads[0].subject.key, 'term');
  assert.equal(planned.decisions[0].accepted, true);
  assert.equal(planned.decisions[0].repairedByMuse, true);
  assert.equal(planned.decisions[0].repairCalls, 1);
  let requests = 0;
  const run = await runAccessBoundaries(planned.leads, scope, {
    surface, env: {OWNER_TOKEN: 'fixture-owner'}, modelCallsAvailable: 0,
    requester: async request => {
      requests++;
      if (request.url === privatePath) return {
        status: request.identity === 'owner' ? 200 : 403,
        body: JSON.stringify(request.identity === 'owner' ?
          {id: 'private', title: 'owner'} : {error: 'denied'}),
        type: 'application/json', headers: {}, evidenceId: `ev-${requests}`};
      const body = JSON.parse(request.body);
      assert.deepEqual(Object.keys(body).sort(), ['mode', 'term']);
      assert.ok(!Object.hasOwn(body, 'missing'));
      return {status: 200, body: JSON.stringify({records: []}),
        type: 'application/json', headers: {}, evidenceId: `ev-${requests}`};
    }});
  assert.ok(requests >= 6);
  assert.equal(run.results[0].verdict, 'not_reproduced');
});

test('Muse reaches a protected read after 32 entries without repeating input coverage or skipping a page after repair', async t => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'bypass-boundary-read-pages-'));
  t.after(() => fs.rmSync(dir, {recursive: true, force: true}));
  const origin = 'http://127.0.0.1:49995', postPath = '/api/filter';
  const privatePaths = Array.from({length: 40}, (_, index) => `/api/private-${index}`);
  const target = privatePaths[35];
  const scopeFile = path.join(dir, 'scope.json');
  fs.writeFileSync(scopeFile, JSON.stringify({schemaVersion: 1, target: {origin},
    include: ['/'], identities: {identityPath: privatePaths[0]},
    probes: {jsonPostPaths: [postPath]}, limits: {rps: 100}}));
  const scope = loadScope({file: scopeFile, origin}).scope;
  const surface = {patterns: privatePaths.map(pattern => ({pattern, methods: ['GET'],
    fingerprint: {owner: {status: 200, shape: {id: 'string', title: 'string'}},
      anonymous: {status: 403}}})),
  jsonBodyOperations: [{path: postPath, method: 'POST', contentType: 'application/json',
    fields: ['term'], requiredFields: ['term']}]};
  const proposal = (protectedPath, firstValue = 'candidate-one') => ({
    family: 'query boundary', why: 'Public filter may expose owner data',
    priority: 8, comparison: 'object', protectedPath,
    subject: {method: 'POST', path: postPath, placement: 'json', key: 'term',
      fixedFields: []}, controlValue: 'plain', firstValue,
    secondValue: 'candidate-two', ownerPointer: '', candidatePointer: '/records',
    identityField: 'id', matchFields: ['id', 'title']});
  const seen = [];
  const env = {OWNER_TOKEN: 'fixture-owner'};
  const first = await planAccessBoundaries(surface, scope, {env, model: 'fixture',
    budget: 1, modelCallsAvailable: 2, infer: async (_model, messages) => {
      const context = JSON.parse(messages[1].content);
      if (context.failure) {
        assert.equal(context.failure, 'invalid-boundary-values');
        return {tests: [proposal(privatePaths[0])]};
      }
      seen.push(context.protectedReads.map(item => item.path));
      assert.ok(context.protectedReads.length <= 16);
      assert.ok(Buffer.byteLength(messages[1].content) < 20000);
      return {tests: [proposal(privatePaths[0], 'bad;value')]};
    }});
  assert.equal(first.modelCalls, 2);
  assert.equal(first.coverage.privateReadCoverage.pairPagesSent, 1,
    'repair call must not advance the protected-read window');
  assert.deepEqual(first.coverage.privateReadCoverage,
    {available: 40, sent: 16, cut: 24, windowsAvailable: 3,
      pairPagesAvailable: 3, pairPagesSent: 1});
  assert.equal(first.coverage.postsSent, 1);
  const later = await planAccessBoundaries(surface, scope, {env, model: 'fixture',
    budget: 1, modelCallsAvailable: 2,
    startOffset: 8 * first.coverage.privateReadCoverage.pairPagesSent,
    infer: async (_model, messages) => {
      const context = JSON.parse(messages[1].content);
      seen.push(context.protectedReads.map(item => item.path));
      assert.ok(context.protectedReads.length <= 16);
      return {tests: context.protectedReads.some(item => item.path === target) ?
        [proposal(target)] : []};
    }});
  assert.equal(later.leads.length, 1);
  assert.equal(later.leads[0].protectedPath, target);
  assert.ok(!seen[0].includes(target) && !seen[1].includes(target));
  assert.deepEqual(seen[1], privatePaths.slice(16, 32));
  assert.ok(seen[2].includes(target));
  assert.equal(later.coverage.privateReadCoverage.sent, 40);
  assert.equal(later.coverage.privateReadCoverage.cut, 0);
  assert.equal(later.coverage.privateReadCoverage.pairPagesSent, 3);
  assert.equal(later.coverage.postsSent, 0);
  let requests = 0;
  const run = await runAccessBoundaries(later.leads, scope, {surface, env,
    modelCallsAvailable: 0, requester: async request => {
      requests++;
      if (request.url === target) return {status: request.identity === 'owner' ? 200 : 403,
        body: JSON.stringify(request.identity === 'owner' ?
          {id: 'private-35', title: 'owner'} : {error: 'denied'}),
        type: 'application/json', headers: {}, evidenceId: `ev-${requests}`};
      assert.equal(request.url, postPath);
      const body = JSON.parse(request.body);
      return {status: 200, body: JSON.stringify({records:
        body.term === 'plain' ? [] : [{id: 'private-35', title: 'owner'}]}),
      type: 'application/json', headers: {}, evidenceId: `ev-${requests}`};
    }});
  assert.equal(run.results[0].verdict, 'confirmed');
  assert.equal(run.findings[0].webProof.protectedPath, target);
});

test('verified deployed access-boundary planning uses an observed authorized POST', async t => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'bypass-boundary-deployed-'));
  t.after(() => fs.rmSync(dir, {recursive: true, force: true}));
  const origin = 'https://app.example.test', postPath = '/api/filter';
  const privatePath = '/api/private';
  const expiresAt = new Date(Date.now() + 86400000).toISOString();
  const target = {url: origin, environment: 'staging',
    ownership: {status: 'verified', method: 'dns', expiresAt},
    authorization: {origin, paths: ['/api'], methods: ['GET', 'HEAD', 'POST'],
      maxRequestsPerSecond: 2, expiresAt}};
  const file = path.join(dir, 'scope.json');
  fs.writeFileSync(file, JSON.stringify({schemaVersion: 1, target: {origin},
    include: ['/api'], identities: {identityPath: privatePath},
    probes: {jsonPostPaths: [postPath]}, limits: {rps: 2}}));
  const {scope} = loadScope({file, origin, targets: [target]});
  const surface = {patterns: [{pattern: privatePath, methods: ['GET'],
    fingerprint: {owner: {status: 200, shape: {id: 'string', title: 'string'}},
      anonymous: {status: 403}}}],
  jsonBodyOperations: [{path: postPath, method: 'POST', contentType: 'application/json',
    fields: ['term'], requiredFields: ['term']}]};
  const proposal = {family: 'owner record boundary', why: 'Public filter may return owner data',
    priority: 8, comparison: 'object', protectedPath: privatePath,
    subject: {method: 'POST', path: postPath, placement: 'json', key: 'term',
      fixedFields: []}, controlValue: 'plain', firstValue: 'candidate-one',
    secondValue: 'candidate-two', ownerPointer: '', candidatePointer: '/records',
    identityField: 'id', matchFields: ['id', 'title']};
  let modelCalls = 0;
  const infer = async () => {modelCalls++; return {tests: [proposal]};};
  const env = {OWNER_TOKEN: 'fixture-owner'};
  const planned = await planAccessBoundaries(surface, scope, {env, model: 'fixture',
    budget: 1, modelCallsAvailable: 1, infer});
  assert.equal(planned.leads.length, 1);
  assert.equal(modelCalls, 1);
  let requests = 0;
  const run = await runAccessBoundaries(planned.leads, scope, {surface, env,
    modelCallsAvailable: 0, requester: async request => {
      requests++;
      if (request.url === privatePath) return {status: request.identity === 'owner' ? 200 : 403,
        body: JSON.stringify(request.identity === 'owner' ?
          {id: 'private', title: 'owner'} : {error: 'denied'}),
        type: 'application/json', headers: {}, evidenceId: `ev-${requests}`};
      assert.equal(request.url, postPath);
      assert.equal(request.purpose, 'json-body');
      const body = JSON.parse(request.body);
      return {status: 200, body: JSON.stringify({records:
        body.term === 'plain' ? [] : [{id: 'private', title: 'owner'}]}),
      type: 'application/json', headers: {}, evidenceId: `ev-${requests}`};
    }});
  assert.equal(run.results[0].verdict, 'confirmed');
  assert.ok(requests >= 7);

  const noPostFile = path.join(dir, 'scope-no-post.json');
  fs.writeFileSync(noPostFile, JSON.stringify({schemaVersion: 1, target: {origin},
    include: ['/api'], identities: {identityPath: privatePath},
    probes: {jsonPostPaths: []}, limits: {rps: 2}}));
  const {scope: unreviewed} = loadScope({file: noPostFile, origin, targets: [target]});
  const excluded = await planAccessBoundaries(surface, unreviewed, {env,
    model: 'fixture', budget: 1, modelCallsAvailable: 1, infer});
  assert.equal(excluded.coverage.postsAvailable, 1);
  assert.equal(excluded.leads.length, 1);
  assert.equal(modelCalls, 2, 'the observed authorized POST reaches Muse without a duplicate scope gate');
});
