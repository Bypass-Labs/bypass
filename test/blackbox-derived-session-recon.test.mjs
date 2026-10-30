import test from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import {randomBytes} from 'node:crypto';
import {loadScope} from '../src/blackbox/scope.mjs';
import {reconDerivedSession, derivedAnonymousSurface} from '../src/blackbox/derived-session-recon.mjs';

test('derived session walks protected assets and routes without exposing its bearer or leaving origin', async t => {
  const token = `private-${randomBytes(24).toString('hex')}`;
  const requests = [];
  const server = http.createServer((request, response) => {
    requests.push(request.url);
    if (request.headers.authorization !== `Bearer ${token}`) {
      response.writeHead(401, {'content-type': 'application/json'});
      response.end('{"error":"unauthorized"}');
      return;
    }
    if (request.url === '/private') {
      response.writeHead(200, {'content-type': 'text/html'});
      response.end(`<html data-token="${token}"><script src="/private/app.js"></script>` +
        '<script src="https://other.example.invalid/off.js"></script></html>');
    } else if (request.url === '/private/app.js') {
      response.writeHead(200, {'content-type': 'text/javascript'});
      response.end(`const config={secret:"${token}"}; fetch('/private/records?id=7');\n` +
        `fetch('/private/update',{method:'PATCH',headers:{'content-type':'application/json'},` +
        `body:JSON.stringify({title:'x'})});\n` +
        '//# sourceMappingURL=/private/app.js.map');
    } else if (request.url === '/private/app.js.map') {
      response.writeHead(200, {'content-type': 'application/json'});
      response.end(JSON.stringify({version: 3, sources: ['app.ts'],
        sourcesContent: [`fetch('/private/from-map'); const token='${token}';`]}));
    } else if (request.url === '/private/records' || request.url === '/private/records?id=7') {
      response.writeHead(200, {'content-type': 'application/json'});
      response.end(JSON.stringify({records: [{id: 7, token}], token}));
    } else if (request.url === '/private/from-map') {
      response.writeHead(200, {'content-type': 'application/json'});
      response.end(JSON.stringify({status: 'ok'}));
    } else {
      response.writeHead(404, {'content-type': 'application/json'});
      response.end('{}');
    }
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  t.after(() => new Promise(resolve => server.close(resolve)));
  const origin = `http://127.0.0.1:${server.address().port}`;
  const scope = loadScope({origin, overrides: {acceptLocal: true}}).scope;
  let modelCalls = 0;
  const result = await reconDerivedSession(scope, {
    observedRoutes: ['/private'], maxRequests: 10,
    requestAuthenticated: async ({url, method, noCache, omitExcerpt}) => {
      assert.equal(new URL(url).origin, origin);
      assert.equal(method, 'GET');
      assert.equal(noCache, true);
      assert.equal(omitExcerpt, true);
      const reply = await fetch(url, {headers: {authorization: `Bearer ${token}`}, redirect: 'manual'});
      return {status: reply.status, type: reply.headers.get('content-type'), body: await reply.text(),
        evidenceId: `e-${requests.length}`};
    },
    infer: async (_model, messages) => {
      modelCalls++;
      assert.ok(!JSON.stringify(messages).includes(token), 'bearer must never enter Muse prompt');
      return {paths: ['/private/records?id=7', 'https://other.example.invalid/off.js']};
    },
    model: {name: 'fixture'},
  });
  assert.ok(requests.includes('/private'));
  assert.ok(requests.includes('/private/app.js'));
  assert.ok(requests.some(path => path.startsWith('/private/records')));
  assert.ok(requests.includes('/private/app.js.map'));
  assert.ok(requests.includes('/private/from-map'));
  assert.ok(!requests.some(path => path.includes('off.js')));
  assert.ok(result.coverage.offOriginRejected >= 1);
  assert.ok(result.routes.some(route => route.path === '/private/records'));
  assert.ok(result.assets.some(asset => asset.path === '/private/app.js'));
  assert.ok(result.assets.some(asset => asset.path === '/private/app.js.map'));
  assert.ok(result.contracts.some(contract =>
    contract.path === '/private/records' && contract.method === 'GET'));
  assert.ok(result.contracts.some(contract => contract.path === '/private/update' &&
    contract.method === 'PATCH' && contract.bodyEncoding === 'json' &&
    contract.bodyFields.includes('title')));
  assert.ok(modelCalls > 0);
  assert.ok(!JSON.stringify(result).includes(token), 'bearer must never enter persisted summary');
  assert.ok(!Object.hasOwn(result, 'findings'));
});

test('derived recon overlaps independent GETs and commits route evidence in discovery order', async t => {
  const active = {count: 0, peak: 0};
  const seen = [];
  const server = http.createServer(async (request, response) => {
    active.count++;
    active.peak = Math.max(active.peak, active.count);
    seen.push(request.url);
    const wait = {'/first': 120, '/second': 60, '/third': 10}[request.url] ?? 0;
    await new Promise(resolve => setTimeout(resolve, wait));
    response.writeHead(200, {'content-type': request.url === '/first' ?
      'text/html' : 'application/json'});
    response.end(request.url === '/first' ? '<a href="/later">Later route</a>' : '{}');
    active.count--;
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  t.after(() => new Promise(resolve => server.close(resolve)));
  const origin = `http://127.0.0.1:${server.address().port}`;
  const scope = loadScope({origin, overrides: {acceptLocal: true, agents: 3}}).scope;
  let evidence = 0;
  const result = await reconDerivedSession(scope, {observedRoutes: [
    '/first', '/second', '/third'], maxRequests: 4,
  requestAuthenticated: async ({url}) => {
    const response = await fetch(url, {redirect: 'manual'});
    return {status: response.status, type: response.headers.get('content-type'),
      body: await response.text(), evidenceId: `ev-${++evidence}`};
  }});
  assert.ok(active.peak > 1, 'independent GETs should overlap');
  assert.ok(active.peak <= 3, 'recon must honor the configured agent bound');
  assert.deepEqual(result.routes.map(route => route.path),
    ['/first', '/second', '/third', '/later']);
  assert.ok(seen.indexOf('/later') > seen.indexOf('/third'),
    'a discovered route must run in the next batch');
  assert.equal(result.coverage.requested, 4);
  assert.equal(result.coverage.budgetCut, 0);
});

test('a reviewed action GET is serialized between independent recon reads', async () => {
  const origin = 'http://127.0.0.1:43997';
  const scope = structuredClone(loadScope({origin, overrides: {acceptLocal: true,
    agents: 3}}).scope);
  scope.discover.push('/logout');
  let active = 0, peak = 0;
  const order = [];
  const result = await reconDerivedSession(scope, {observedRoutes: [
    '/first', '/logout', '/third'], maxRequests: 3,
  requestAuthenticated: async ({url}) => {
    active++;
    peak = Math.max(peak, active);
    order.push(new URL(url).pathname);
    await new Promise(resolve => setTimeout(resolve, 20));
    active--;
    return {status: 200, type: 'application/json', body: '{}'};
  }});
  assert.deepEqual(order, ['/first', '/logout', '/third']);
  assert.equal(peak, 1);
  assert.equal(result.coverage.requested, 3);
});

test('derived recon reads later application originals after vendor entries in a source map', async () => {
  const origin = 'http://127.0.0.1:43993';
  const scope = loadScope({origin, overrides: {acceptLocal: true}}).scope;
  const vendor = Array.from({length: 20}, (_, index) =>
    `webpack:///./node_modules/dependency-${index}/index.js`);
  const app = Array.from({length: 15}, (_, index) => `webpack:///./src/client-${index}.js`);
  const map = JSON.stringify({version: 3, mappings: 'AAAA', sources: [...vendor, ...app],
    sourcesContent: [...vendor.map(() => 'export const dependency = true;'),
      ...app.map((_, index) => index === app.length - 1 ?
        'export const final = () => fetch("/private/late-map-route");' :
        'export const client = true;')]});
  const requested = [];
  const result = await reconDerivedSession(scope, {observedRoutes: ['/private/app.js.map'],
    maxRequests: 4, requestAuthenticated: async ({url}) => {
      requested.push(new URL(url).pathname);
      return new URL(url).pathname.endsWith('.map') ?
        {status: 200, type: 'application/json', body: map, evidenceId: 'map-evidence'} :
        {status: 200, type: 'application/json', body: '{}', evidenceId: 'route-evidence'};
    }});
  assert.ok(requested.includes('/private/late-map-route'));
  assert.ok(result.contracts.some(item => item.path === '/private/late-map-route'));
  assert.deepEqual(result.assets.find(item => item.kind === 'source-map'),
    {path: '/private/app.js.map', kind: 'source-map', sources: 35,
      sourcesCut: 0, sourcesUnavailable: 0, sourcesRecovered: 0,
      evidenceId: 'map-evidence'});
});

test('derived recon fetches a late reachable source-map original through its fresh session', async () => {
  const origin = 'http://127.0.0.1:43994';
  const scope = loadScope({origin, overrides: {acceptLocal: true}}).scope;
  const vendor = Array.from({length: 205}, (_, index) =>
    `webpack:///./node_modules/dependency-${index}/index.js`);
  const map = JSON.stringify({version: 3, mappings: 'AAAA',
    sources: [...vendor, '../src/late-client.ts', '../src/missing-client.ts'],
    sourcesContent: []});
  const requested = [];
  const result = await reconDerivedSession(scope, {observedRoutes: ['/private/assets/app.js.map'],
    maxRequests: 4, requestAuthenticated: async ({url}) => {
      const path = new URL(url).pathname;
      requested.push(path);
      if (path.endsWith('.map')) return {status: 200, type: 'application/json', body: map,
        evidenceId: 'map-evidence'};
      if (path.endsWith('/late-client.ts')) return {status: 200, type: 'text/plain',
        body: 'export const late = () => fetch("/private/late-original-route");',
        evidenceId: 'original-evidence'};
      if (path.endsWith('/missing-client.ts')) return {status: 200, type: 'text/html',
        body: '<html>application fallback</html>', evidenceId: 'fallback-evidence'};
      return {status: 200, type: 'application/json', body: '{}', evidenceId: 'route-evidence'};
    }});
  assert.ok(requested.includes('/private/src/late-client.ts'));
  assert.ok(requested.includes('/private/src/missing-client.ts'));
  assert.ok(!requested.some(path => path.includes('node_modules')));
  assert.ok(requested.includes('/private/late-original-route'));
  assert.ok(result.contracts.some(item => item.path === '/private/late-original-route'));
  const asset = result.assets.find(item => item.kind === 'source-map');
  assert.equal(asset.sourcesRecovered, 1);
  assert.equal(asset.sourcesCut, 206);
  assert.equal(asset.sourcesUnavailable, 206);
  assert.equal(result.coverage.sourceMapSourcesCut, 206);
  assert.equal(result.coverage.sourceMapOriginalsRecovered, 1);
});

test('derived planning surface keeps changed access boundaries and protected method inputs', () => {
  const mapped = {origin: 'http://127.0.0.1:43997', routes: [
    {path: '/private/record', method: 'GET', status: 200, type: 'application/json',
      shape: {record: {id: 'number', title: 'string'}}, evidenceId: 'derived-1'},
    {path: '/private/new', method: 'GET', status: 200, type: 'application/json',
      shape: {id: 'number'}, evidenceId: 'derived-2'},
  ], contracts: [{path: '/private/update', method: 'PATCH', params: ['title'],
    bodyEncoding: 'json', bodyFields: ['title'], bodyStringFields: ['title'],
    source: 'protected-script'}]};
  const publicSurface = {patterns: [{pattern: '/private/record', methods: ['GET'],
    responseFacts: {status: 401, type: 'application/json', evidenceId: 'anonymous-1'}}]};
  const surface = derivedAnonymousSurface(mapped, publicSurface);
  assert.deepEqual(surface.patterns.map(route => route.pattern), ['/private/record', '/private/new']);
  assert.equal(surface.patterns[0].responseFacts.anonymousStatus, 401);
  assert.deepEqual(surface.patterns[0].responseFacts.shape,
    {record: {id: 'number', title: 'string'}});
  assert.ok(surface.modelNotes[0].purpose.includes('401 anonymously'));
  assert.ok(surface.methodOperations.some(item => item.path === '/private/update' &&
    item.method === 'PATCH' && item.placement === 'json' && item.fields.includes('title')));
});

test('derived planning keeps already public routes and merges authenticated method fields', () => {
  const origin = 'http://127.0.0.1:43995';
  const mapped = {origin, routes: [
    {path: '/workspace/items?page=1', method: 'GET', status: 200,
      type: 'application/json', shape: {items: 'array'}, evidenceId: 'auth-1'},
    {path: '/workspace/profile', method: 'GET', status: 200,
      type: 'application/json', shape: {profile: {id: 'number'}}, evidenceId: 'auth-2'},
  ], contracts: [{path: '/workspace/items', method: 'POST', params: [],
    bodyEncoding: 'json', bodyFields: ['note'], bodyStringFields: ['note'],
    source: 'protected-script'}]};
  const publicSurface = {patterns: [
    {pattern: '/workspace/items', methods: ['GET'], params: {page: ['1']},
      responseFacts: {status: 200, type: 'application/json', shape: {items: 'array'}}},
    {pattern: '/workspace/profile', methods: ['GET'],
      responseFacts: {status: 200, type: 'application/json', shape: {profile: null}}},
  ], jsonBodyOperations: [{path: '/workspace/items', method: 'POST', placement: 'json',
    contentType: 'application/json', fields: ['title'], requiredFields: ['title'],
    source: 'public-api'}], methodOperations: [{path: '/workspace/items', method: 'POST',
    placement: 'json', contentType: 'application/json', fields: ['title'],
    requiredFields: ['title'], source: 'public-api'}]};
  const surface = derivedAnonymousSurface(mapped, publicSurface);
  assert.deepEqual(surface.patterns.map(item => item.pattern),
    ['/workspace/items', '/workspace/profile']);
  assert.equal(surface.patterns[0].responseFacts.anonymousStatus, 200);
  assert.deepEqual(surface.patterns[0].responseFacts.anonymousShape, {items: 'array'});
  assert.deepEqual(surface.patterns[0].params.page, ['1']);
  assert.ok(surface.modelNotes.every(item => item.purpose.includes('same path returned 200 anonymously')));
  for (const operations of [surface.jsonBodyOperations, surface.methodOperations]) {
    const operation = operations.find(item => item.path === '/workspace/items' &&
      item.method === 'POST');
    assert.deepEqual(operation.fields, ['title', 'note']);
    assert.deepEqual(operation.requiredFields, ['title']);
  }
});

test('derived session obeys request and time budget callbacks', async () => {
  const scope = loadScope({origin: 'http://127.0.0.1:43999', overrides: {acceptLocal: true}}).scope;
  const result = await reconDerivedSession(scope, {
    observedRoutes: ['/private', '/private/second'], remainingRequests: () => 0,
    requestAuthenticated: () => { throw new Error('request must not run'); },
  });
  assert.equal(result.coverage.requested, 0);
  assert.equal(result.coverage.budgetCut, 2);
});

test('authenticated recon pages every mapped route while global Muse calls remain', async () => {
  const origin = 'http://127.0.0.1:43994';
  const scope = loadScope({origin, overrides: {acceptLocal: true}}).scope;
  const observedRoutes = Array.from({length: 300}, (_, index) => `/protected/item-${index}`);
  let modelCalls = 0;
  const mapped = await reconDerivedSession(scope, {observedRoutes,
    maxRequests: 350, maxModelCalls: 20,
    requestAuthenticated: async () => ({status: 200, type: 'application/json',
      body: '{}', evidenceId: 'ev-test'}),
    model: 'fixture', infer: async () => {modelCalls++; return {paths: []};}});
  assert.equal(mapped.routes.length, 300);
  assert.equal(mapped.coverage.modelRoutesReviewed, 300);
  assert.equal(mapped.coverage.modelRoutesCut, 0);
  assert.ok(modelCalls > 4);
});

test('zero authenticated recon URL cap visits the full observed queue', async () => {
  const scope = loadScope({origin: 'http://127.0.0.1:43999', overrides: {acceptLocal: true}}).scope;
  const observedRoutes = ['/private/a', '/private/b', '/private/c'];
  const requestAuthenticated = async () => ({status: 404, type: 'application/json', body: '{}'});
  const capped = await reconDerivedSession(scope, {observedRoutes, requestAuthenticated,
    maxRequests: 2});
  assert.equal(capped.coverage.requested, 2);
  assert.equal(capped.coverage.budgetCut, 1);
  assert.equal(capped.coverage.cutReason, 'url-count-cap');
  const uncapped = await reconDerivedSession(scope, {observedRoutes, requestAuthenticated,
    maxRequests: 0});
  assert.equal(uncapped.coverage.requested, 3);
  assert.equal(uncapped.coverage.budgetCut, 0);
});

test('derived session continues past the former 32-route cap when scope permits', async () => {
  const scope = loadScope({origin: 'http://127.0.0.1:43998', overrides: {acceptLocal: true}}).scope;
  const paths = Array.from({length: 40}, (_, index) => `/inside/route-${index}`);
  const requested = [];
  const result = await reconDerivedSession(scope, {
    observedRoutes: paths,
    requestAuthenticated: async ({url}) => {
      requested.push(new URL(url).pathname);
      return {status: 200, type: 'application/json', body: '{}'};
    },
  });
  assert.equal(new Set(requested).size, 40);
  assert.equal(result.routes.length, 40);
  assert.equal(result.coverage.budgetCut, 0);
});

test('authenticated recon recognizes a private JSON response above 64 KiB', async () => {
  const scope = loadScope({origin: 'http://127.0.0.1:43998',
    overrides: {acceptLocal: true}}).scope;
  const body = JSON.stringify({private: true, ownerId: 7,
    note: 'fixture-data', padding: 'x'.repeat(70 * 1024)});
  const result = await reconDerivedSession(scope, {
    observedRoutes: ['/private/large'], maxRequests: 1,
    requestAuthenticated: async request => {
      assert.ok(request.maxBytes >= Buffer.byteLength(body));
      return {status: 200, type: 'application/json', body,
        hash: 'sha256:fixture', evidenceId: 'ev-large'};
    },
  });
  assert.equal(result.routes[0].privateSignal?.markerKey, 'private');
  assert.equal(result.routes[0].privateSignal?.materialField, 'note');
  assert.ok(!JSON.stringify(result).includes('fixture-data'));
});

test('authenticated recon records responses beyond 16 MiB as size cuts', async () => {
  const scope = loadScope({origin: 'http://127.0.0.1:43998',
    overrides: {acceptLocal: true}}).scope;
  const result = await reconDerivedSession(scope, {
    observedRoutes: ['/private/oversized.js'], maxRequests: 1,
    requestAuthenticated: async () => ({blocked: true,
      reason: 'Request failed: Response exceeds size limit'}),
  });
  assert.equal(result.coverage.blocked, 0);
  assert.equal(result.coverage.sizeCut, 1);
  assert.deepEqual(result.coverage.sizeCutPaths, ['/private/oversized.js']);
});

test('authenticated response facts reach Muse across the configured call pages', async () => {
  const scope = loadScope({origin: 'http://127.0.0.1:43996', overrides: {acceptLocal: true}}).scope;
  const paths = Array.from({length: 100}, (_, index) => `/inside/route-${index}`);
  const sent = [];
  const result = await reconDerivedSession(scope, {
    observedRoutes: paths, maxRequests: 100, maxModelCalls: 4,
    requestAuthenticated: async () => ({status: 200, type: 'application/json',
      body: '{"status":"ok"}', shape: {status: 'string'}}),
    infer: async (_model, messages) => {
      const context = JSON.parse(messages[1].content);
      sent.push(...context.observations.map(item => item.path));
      assert.ok(Buffer.byteLength(messages[1].content) < 20000);
      return {paths: []};
    },
    model: {name: 'fixture'},
  });
  assert.equal(result.coverage.modelCalls, 3);
  assert.equal(result.coverage.modelRoutesAvailable, 100);
  assert.equal(result.coverage.modelRoutesSent, 100);
  assert.equal(result.coverage.modelRoutesReviewed, 100);
  assert.equal(result.coverage.modelRoutesCut, 0);
  assert.equal(new Set(sent).size, 100);
  assert.equal(result.modelDecisions[0].observations, 8,
    'the first Muse page should still be early enough to expand the crawl');
});
