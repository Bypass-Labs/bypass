import test from 'node:test';
import assert from 'node:assert/strict';
import {randomBytes} from 'node:crypto';
import {interpretAssets, applyAssetProposals} from '../src/blackbox/asset-interpret.mjs';
import {extractFromScript} from '../src/blackbox/assets.mjs';

function fixture() {
  const files = Array.from({length: 5}, (_, index) => ({
    url: `https://app.example.test/static/file-${index}.js${index === 4 ? '?token=not-for-muse' : ''}`,
    hash: `sha256:file-${index}`, evidenceId: `ev-${index + 1}`, sourceMap: 'absent',
    endpoints: [{path: `/api/record-${index}`, method: 'GET', params: ['view'], headers: ['Authorization']}],
    hosts: [{host: 'api.example.test', kind: 'url'}],
    env: [{kind: 'flag', value: index === 4 ? 'sk_live_12345678901234567890' : 'beta'}],
    secrets: [{name: 'stripe-secret-key', masked: 'sk_l…(28)'}],
  }));
  return {files, endpoints: files.map(file => ({...file.endpoints[0], files: [file.url]}))};
}

test('Muse interprets every paged asset file but cannot invent routes or parameters or receive a secret', async () => {
  const mined = fixture();
  mined.files[0].endpoints[0].sources = ['webpack:///./src/api/records.js',
    'webpack:///./src/sk_live_12345678901234567890.js'];
  const prompts = [];
  const result = await interpretAssets(mined, {model: {model: 'fixture'}, maxPages: 2,
    infer: async (_model, messages) => {
      const context = JSON.parse(messages[1].content);
      prompts.push(context);
      return {files: context.files.map(file => ({id: file.id, role: 'app', why: 'Client API call sites',
        authFlow: 'Authorization header', routes: [
          ...file.routes.map(route => ({path: route.path, method: route.method,
            purpose: `Reads ${route.path}`, parameters: [
              {name: 'view', meaning: 'selects a view'}, {name: 'invented', meaning: 'not observed'}]})),
          {path: '/api/invented', method: 'GET', purpose: 'invented', parameters: []},
        ]}))};
    }});
  assert.equal(prompts.length, 2);
  assert.equal(result.coverage.filesSent, 5);
  assert.equal(result.coverage.routesSent, 5);
  assert.equal(result.coverage.pagesAvailable, 2);
  assert.equal(result.notes.length, 5);
  assert.deepEqual(result.notes[0].sourceFiles, ['webpack:///./src/api/records.js', '[redacted]']);
  assert.ok(result.notes.every(note => note.parameters.join(',') === 'view'));
  assert.ok(!result.notes.some(note => note.path === '/api/invented'));
  assert.equal(mined.files[4].analysis.role, 'app');
  assert.equal(mined.endpoints[4].purpose, 'Reads /api/record-4');
  const sent = JSON.stringify(prompts);
  assert.ok(!sent.includes('not-for-muse'));
  assert.ok(!sent.includes('sk_live_12345678901234567890'));
  assert.ok(!sent.includes('sk_l…(28)'));
});

test('asset model-call cuts are counted without claiming unseen files were interpreted', async () => {
  const mined = fixture();
  const result = await interpretAssets(mined, {model: {model: 'fixture'}, maxPages: 1,
    infer: async () => ({files: []})});
  assert.equal(result.coverage.pagesAvailable, 2);
  assert.equal(result.coverage.pagesSent, 1);
  assert.equal(result.coverage.filesSent, 4);
  assert.equal(result.coverage.routesAvailable, 5);
  assert.equal(result.coverage.routesSent, 4);
  assert.equal(result.coverage.pagesWithoutAcceptedUnits, 1);
  assert.match(result.modelError, /no usable file interpretations/);
});

test('a large client asset reaches Muse in practical pages without losing late source or route facts', async () => {
  const lateMarker = `late_${randomBytes(6).toString('hex')}`;
  const source = 'const ordinary = 1;\n'.repeat(145000) + `// ${lateMarker}\n`;
  const endpoint = {path: '/api/items', method: 'POST', params: [],
    bodyEncoding: 'json', bodyFields: ['name']};
  const file = {url: 'https://app.example.test/main.js', hash: 'sha256:large',
    endpoints: [endpoint], modelSource: [{name: 'main.js', text: source}]};
  const chunks = [];
  let sawRoute = false;
  const result = await interpretAssets({files: [file], endpoints: [endpoint]},
    {model: {model: 'fixture'}, maxPages: 200,
      infer: async (_model, messages) => {
        const context = JSON.parse(messages[1].content);
        for (const unit of context.files) {
          if (unit.sourceText) chunks.push({offset: unit.sourceOffset, text: unit.sourceText});
          if (unit.routes.some(route => route.path === endpoint.path && route.method === 'POST'))
            sawRoute = true;
        }
        return {files: context.files.map(unit => ({id: unit.id, role: 'app',
          why: '', authFlow: '', routes: unit.routes.map(route => ({path: route.path,
            method: route.method, purpose: 'Observed client request', parameters: []})),
          proposals: []}))};
      }});
  assert.ok(result.coverage.pagesAvailable <= 50,
    `Large asset required ${result.coverage.pagesAvailable} Muse calls`);
  assert.equal(result.coverage.pagesSent, result.coverage.pagesAvailable);
  assert.equal(result.coverage.sourceChunksSent, result.coverage.sourceChunksAvailable);
  assert.equal(sawRoute, true);
  assert.ok(chunks.some(chunk => chunk.text.includes(lateMarker)));
  chunks.sort((a, b) => a.offset - b.offset);
  let end = 0;
  for (const chunk of chunks) {
    assert.ok(chunk.offset <= end, 'source chunks must leave no gap');
    assert.equal(chunk.text, source.slice(chunk.offset, chunk.offset + chunk.text.length));
    end = Math.max(end, chunk.offset + chunk.text.length);
  }
  assert.equal(end, source.length);
});

test('an incomplete asset page does not hide later files from Muse', async () => {
  const mined = fixture();
  let calls = 0;
  const result = await interpretAssets(mined, {model: {model: 'fixture'}, maxPages: 2,
    infer: async (_model, messages) => {
      if (++calls === 1) throw new Error('Provider response incomplete; no action executed.');
      const files = JSON.parse(messages[1].content).files;
      return {files: files.map(file => ({id: file.id, role: 'app', why: 'Client route',
        authFlow: '', routes: file.routes.map(route => ({path: route.path,
          method: route.method, purpose: 'Observed record read', parameters: []})), proposals: []}))};
    }});
  assert.equal(calls, 2);
  assert.equal(result.coverage.pagesAvailable, 2);
  assert.equal(result.coverage.pagesSent, 1);
  assert.equal(result.coverage.filesSent, 1);
  assert.equal(result.notes[0].path, '/api/record-4');
  assert.match(result.modelError, /incomplete/);
});

test('an output-limited asset page is retried in smaller pages', async () => {
  const mined = fixture();
  let calls = 0;
  const result = await interpretAssets(mined, {model: {model: 'fixture'}, maxPages: 4,
    infer: async (_model, messages) => {
      if (++calls === 1) {
        const error = new Error('Provider response incomplete; no action executed.');
        error.details = {reason: 'incomplete_output'};
        throw error;
      }
      const files = JSON.parse(messages[1].content).files;
      return {files: files.map(file => ({id: file.id, role: 'app', why: 'Client route',
        authFlow: '', routes: file.routes.map(route => ({path: route.path,
          method: route.method, purpose: 'Observed record read', parameters: []})), proposals: []}))};
    }});
  assert.equal(calls, 4);
  assert.equal(result.coverage.pagesAvailable, 3);
  assert.equal(result.coverage.pagesSent, 3);
  assert.equal(result.coverage.filesSent, 5);
  assert.equal(result.notes.length, 5);
  assert.equal(result.modelError, null);
});

test('a malformed multi-file asset answer is retried in smaller pages', async () => {
  const mined = fixture();
  let calls = 0;
  const result = await interpretAssets(mined, {model: {model: 'fixture'}, maxPages: 4,
    infer: async (_model, messages) => {
      if (++calls === 1) throw new Error('Invalid type for security_action.files.');
      const files = JSON.parse(messages[1].content).files;
      return {files: files.map(file => ({id: file.id, role: 'app', why: 'Client route',
        authFlow: '', routes: file.routes.map(route => ({path: route.path,
          method: route.method, purpose: 'Observed record read', parameters: []})), proposals: []}))};
    }});
  assert.equal(calls, 4);
  assert.equal(result.coverage.filesSent, 5);
  assert.equal(result.modelError, null);
});

test('a constrained Muse page share still reviews a late application source-map route', async () => {
  const mined = fixture();
  const mapRoute = {path: '/api/late-from-source-map', method: 'GET', params: [], headers: [],
    source: 'webpack:///./src/client.js'};
  mined.files.push({url: 'https://app.example.test/static/bundle.js.map',
    hash: 'sha256:late-map', evidenceId: 'ev-map', foundBy: 'sourcemap:/static/bundle.js',
    sourceSelection: {appLikelySelected: 1, appLikelyCut: 0, appLikelyUnavailable: 0,
      vendorSelected: 0, vendorCut: 0, vendorUnavailable: 0}, endpoints: [mapRoute]});
  mined.endpoints.push({...mapRoute, files: [mined.files.at(-1).url]});
  const sent = [];
  const result = await interpretAssets(mined, {model: {model: 'fixture'}, maxPages: 1,
    infer: async (_model, messages) => {
      const context = JSON.parse(messages[1].content);
      sent.push(...context.files.flatMap(file => file.routes.map(route => route.path)));
      return {files: context.files.map(file => ({id: file.id, role: 'app', why: '',
        authFlow: '', routes: file.routes.map(route => ({path: route.path, method: route.method,
          purpose: 'Observed client request', parameters: []})), proposals: []}))};
    }});
  assert.ok(result.coverage.pagesAvailable > result.coverage.pagesSent);
  assert.ok(sent.includes('/api/late-from-source-map'), JSON.stringify({sent, coverage: result.coverage}));
  assert.ok(result.notes.some(note => note.path === '/api/late-from-source-map'));
});

test('Muse receives observed JSON body fields separately from query parameters', async () => {
  const endpoint = {path: '/api/review', method: 'POST', params: ['locale', 'rating', 'message'],
    bodyEncoding: 'json', bodyFields: ['rating', 'message', 'token'],
    fieldExamples: {rating: ['5'], message: ['nice'], token: ['sk_live_12345678901234567890']}};
  const mined = {files: [{url: 'https://app.example.test/main.js', hash: 'sha256:review',
    endpoints: [endpoint]}], endpoints: [endpoint]};
  let observed;
  await interpretAssets(mined, {model: {model: 'fixture'}, infer: async (_model, messages) => {
    observed = JSON.parse(messages[1].content).files[0].routes[0];
    return {files: [{id: JSON.parse(messages[1].content).files[0].id, role: 'app',
      why: '', authFlow: '', routes: [], proposals: []}]};
  }});
  assert.equal(observed.method, 'POST');
  assert.equal(observed.bodyEncoding, 'json');
  assert.deepEqual(observed.bodyFields, ['rating', 'message', 'token']);
  assert.deepEqual(observed.bodyExamples, {rating: ['5'], message: ['nice']});
  assert.ok(!JSON.stringify(observed).includes('sk_live_12345678901234567890'));
});

test('an empty asset reply gets one exact-id retry and recovered notes remain attributable', async () => {
  const mined = fixture();
  mined.files = mined.files.slice(0, 1);
  mined.endpoints = mined.endpoints.slice(0, 1);
  const schemas = [], prompts = [];
  const result = await interpretAssets(mined, {model: {model: 'fixture'}, maxPages: 2,
    infer: async (_model, messages, {schema}) => {
      schemas.push(schema);
      prompts.push(messages[0].content);
      if (schemas.length === 1) return {files: []};
      const unit = JSON.parse(messages[1].content).files[0];
      return {files: [{id: unit.id, role: 'app', why: 'Client route', authFlow: '',
        routes: [{path: unit.routes[0].path, method: 'GET', purpose: 'Read a record',
          parameters: [{name: 'view', meaning: 'Selects the response view'}]}], proposals: []}]};
    }});
  assert.equal(result.modelCalls, 2);
  assert.equal(result.modelError, null);
  assert.equal(result.coverage.unitsAccepted, 1);
  assert.equal(result.notes.length, 1);
  assert.deepEqual(schemas[0].properties.files.items.properties.id.enum, ['1.1']);
  assert.ok(schemas[0].properties.files.items.properties.role.enum.includes('app'));
  assert.match(prompts[1], /previous response had no usable file entries/);
  assert.deepEqual(result.pageDiagnostics, [{page: 1, unitsSent: 1,
    unitsReturned: 1, unitsAccepted: 1, calls: 2}]);
});

test('asset interpretation keeps target and discovered-host route notes attributed to their own summaries', async () => {
  const target = fixture();
  target.files = target.files.slice(0, 1);
  target.endpoints = target.endpoints.slice(0, 1);
  const host = {files: [{url: 'https://api.example.test/client.js', hash: 'sha256:host',
    evidenceId: 'ev-host', endpoints: [{path: '/v2/accounts', method: 'GET', params: ['region'],
      examples: {region: ['eu']}, headers: []}], hosts: [], env: []}],
  endpoints: [{path: '/v2/accounts', method: 'GET', params: ['region'], examples: {region: ['eu']},
    files: ['https://api.example.test/client.js']}]};
  const result = await interpretAssets([target, host], {model: {model: 'fixture'},
    infer: async (_model, messages) => {
      const context = JSON.parse(messages[1].content);
      return {files: context.files.map(file => ({id: file.id, role: 'api', why: 'Observed route facts',
        authFlow: '', routes: file.routes.map(route => ({path: route.path, method: route.method,
          purpose: `Purpose of ${route.path}`, parameters: []}))}))};
    }});
  assert.equal(result.coverage.filesSent, 2);
  assert.deepEqual(result.notes.find(note => note.path === '/api/record-0').summaryIndexes, [0]);
  assert.deepEqual(result.notes.find(note => note.path === '/v2/accounts').summaryIndexes, [1]);
  assert.equal(host.endpoints[0].purpose, 'Purpose of /v2/accounts');
  assert.equal(target.endpoints[0].purpose, 'Purpose of /api/record-0');
});

test('asset notes stay with the right summary when a URL serves different bundle hashes', async () => {
  const url = 'https://cdn.example.test/main.js';
  const summaries = ['scope', 'view'].map((param, index) => ({
    files: [{url, hash: `sha256:bundle-${index}`, endpoints: [{path: '/api/items',
      method: 'GET', params: [param], headers: []}]}],
    endpoints: [{path: '/api/items', method: 'GET', params: [param], files: [url]}],
  }));
  const result = await interpretAssets(summaries, {model: {model: 'fixture'},
    infer: async (_model, messages) => ({files: JSON.parse(messages[1].content).files.map(file => ({
      id: file.id, role: 'app', why: '', authFlow: '', routes: file.routes.map(route => ({
        path: route.path, method: route.method, purpose: route.params[0], parameters: [],
      })),
    }))})});
  assert.equal(result.notes.length, 2);
  assert.equal(summaries[0].endpoints[0].purpose, 'scope');
  assert.equal(summaries[1].endpoints[0].purpose, 'view');
});

test('Muse can propose only literal-grounded GET paths from redacted indirect asset calls', async () => {
  const secret = 'sk_live_12345678901234567890';
  const source = `const base='/api'; const secret='${secret}'; const privatePath='?auth.token=shortsecret'; ` +
    "const jump=[base,'jump-abc123'].join('/'); fetch(jump+'?next=/safe'); " +
    "const write=[base,'write-abc123'].join('/'); fetch(write,{method:'POST'});";
  const extracted = extractFromScript(source, {url: 'https://app.example.test/app.js'});
  assert.ok(!extracted.endpoints.some(item => item.path === '/api/jump-abc123'));
  assert.deepEqual(extracted.routeHints.map(item => item.method), ['GET', 'POST']);
  assert.ok(!JSON.stringify(extracted.routeHints).includes(secret));
  assert.ok(!JSON.stringify(extracted.routeHints).includes('shortsecret'));
  const summary = {files: [{url: 'https://app.example.test/app.js', hash: 'sha256:one',
    evidenceId: 'ev-1', ...extracted}], endpoints: extracted.endpoints};
  const result = await interpretAssets(summary, {model: {provider: 'test'}, infer: async (_model, messages) => {
    const context = JSON.parse(messages[1].content);
    assert.ok(!JSON.stringify(context).includes(secret));
    assert.ok(!JSON.stringify(context).includes('shortsecret'));
    const file = context.files[0];
    return {files: [{id: file.id, role: 'app', why: 'Indirect navigation', authFlow: '', routes: [],
      proposals: [
        {hintId: file.hints[0].id, path: '/api/jump-abc123?next=/safe'},
        {hintId: file.hints[0].id, path: '/api/invented?next=/safe'},
        {hintId: file.hints[1].id, path: '/api/write-abc123'},
        {hintId: file.hints[0].id, path: 'https://off-origin.invalid/api/jump-abc123'},
      ]}]};
  }});
  assert.deepEqual(result.proposals.map(item => ({path: item.path, params: item.params})),
    [{path: '/api/jump-abc123', params: ['next']}]);
  assert.equal(result.coverage.hintsSent, 2);
  assert.equal(result.coverage.pathProposalsReceived, 4);
  assert.equal(result.coverage.pathProposalsAccepted, 1);
  assert.deepEqual(result.coverage.pathProposalsRejectedByReason,
    {'ungrounded-path': 2, 'non-get-hint': 1});
  assert.ok(!JSON.stringify(result.coverage).includes(secret));
});

test('asset route hypotheses stay on their producing origin and become descendant GET operations', () => {
  const target = {endpoints: []};
  const hosts = [
    {assets: {endpoints: []}, operations: [], operationCut: 0},
    {assets: {endpoints: []}, operations: [], operationCut: 0},
  ];
  applyAssetProposals(target, hosts, [
    {path: '/api/target', method: 'GET', params: ['next'], file: 'https://app.test/app.js', summaryIndexes: [0]},
    {path: '/api/host', method: 'GET', params: ['next'], file: 'https://cdn.test/app.js', summaryIndexes: [2]},
  ]);
  assert.deepEqual(target.endpoints.map(item => item.path), ['/api/target']);
  assert.deepEqual(hosts[0].operations, []);
  assert.deepEqual(hosts[1].assets.endpoints.map(item => item.path), ['/api/host']);
  assert.deepEqual(hosts[1].operations[0].params, [{name: 'next', in: 'query'}]);
});

test('indirect asset call hints report a cut instead of implying later calls were reviewed', () => {
  const source = Array.from({length: 40}, (_, index) =>
    `{const base='/api';const jump=[base,'jump-${index}'].join('/');fetch(jump+'?next=/safe');}`)
    .join(' ');
  const extracted = extractFromScript(source, {url: 'https://app.example.test/app.js'});
  assert.equal(extracted.routeHints.length, 32);
  assert.equal(extracted.routeHintsCut, 8);
});

test('Muse asset pages include indirect hints beyond the first eight when its page budget allows', async () => {
  const source = Array.from({length: 20}, (_, index) =>
    `{const base='/api';const jump=[base,'jump-${index}'].join('/');fetch(jump+'?next=/safe');}`)
    .join(' ');
  const file = extractFromScript(source, {url: 'https://app.example.test/app.js'});
  file.url = 'https://app.example.test/app.js';
  file.hash = 'fixture';
  let sawLate = false;
  const result = await interpretAssets({files: [file], endpoints: []}, {model: {model: 'fixture'},
    infer: async (_model, messages) => {
      const context = JSON.parse(messages[1].content);
      if (context.files.some(unit => unit.hints.some(hint => hint.id === 'h20'))) sawLate = true;
      return {files: []};
    }});
  assert.equal(result.coverage.hintsAvailable, 20);
  assert.equal(result.coverage.hintsSent, 20);
  assert.equal(sawLate, true);
});

test('redacted indirect-call windows do not start inside an arbitrary JavaScript string', () => {
  const privateText = `PRIVATE_SENTINEL_${'Z'.repeat(380)}`;
  const source = `const arbitrary='${privateText}';const base='/api';` +
    "const jump=[base,'records'].join('/');fetch(jump+'?next=/safe');";
  const extracted = extractFromScript(source, {url: 'https://app.example.test/app.js'});
  assert.equal(extracted.routeHints.length, 1);
  assert.ok(!extracted.routeHints[0].excerpt.includes('Z'.repeat(30)));
  assert.ok(extracted.routeHints[0].literals.includes('/api'));
});

test('indirect-call mining ignores call-shaped text inside a string', () => {
  const source = 'const base="/api"; const note="fetch(jump)";';
  const extracted = extractFromScript(source, {url: 'https://app.example.test/app.js'});
  assert.equal(extracted.routeHints.length, 0);
});
