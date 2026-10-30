import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import {temp} from './helpers.mjs';
import {DEFAULT_SCOPE} from '../src/blackbox/scope.mjs';
import {createLedger, verifyLedger} from '../src/blackbox/ledger.mjs';
import {discover} from '../src/blackbox/discovery.mjs';
import {interpretDiscovery} from '../src/blackbox/discovery-interpret.mjs';
import {hash} from '../src/util.mjs';

test('independent seeded hosts are inspected concurrently within the host cap', async t => {
  const dir = temp();
  t.after(() => fs.rmSync(dir, {recursive: true, force: true}));
  const ledger = createLedger(dir);
  const scope = structuredClone(DEFAULT_SCOPE);
  scope.target.origin = 'https://slow.example.test';
  scope.domains = ['example.test'];
  scope.discovery.knownHosts = ['fast.example.test'];
  scope.discovery.recurse = false;
  scope.discovery.sensitivePaths = false;
  scope.limits.hosts = 3;
  scope.limits.agents = 2;
  scope.limits.requestsPerHost = 1;
  let releaseSlow;
  const slowPending = new Promise(resolve => {releaseSlow = resolve;});
  let fastBeforeSlow = false, slowDone = false;
  const result = await discover(scope, {ledger,
    resolve: async () => ['203.0.113.10'],
    connectTls: async host => ({subjectaltname: `DNS:${host}`}),
    requester: async ({url}) => {
      const host = new URL(url).hostname;
      if (host === 'slow.example.test') {
        await Promise.race([slowPending,
          new Promise(resolve => setTimeout(resolve, 350))]);
        slowDone = true;
      } else if (host === 'example.test') {
        fastBeforeSlow = !slowDone;
        releaseSlow();
      }
      const body = '<html>seed</html>';
      return {status: 200, body, type: 'text/html',
        headers: {'content-type': 'text/html'}, bytes: body.length,
        hash: `sha256:${hash(body)}`,
        evidenceId: ledger.append({step: 'discovery', request: {url},
          response: {status: 200}})};
    }});
  assert.ok(fastBeforeSlow, 'the next seeded host waited for the slow peer');
  assert.equal(result.hosts.length, 3);
  assert.deepEqual(result.hosts.map(host => host.host),
    ['slow.example.test', 'example.test', 'fast.example.test']);
  assert.equal(verifyLedger(ledger.file).ok, true);
});

test('recursive discovery follows CT and bundle hosts, stays under the apex, and records DNS evidence', async t => {
  const dir = temp();
  t.after(() => fs.rmSync(dir, {recursive: true, force: true}));
  const ledger = createLedger(dir);
  const scope = structuredClone(DEFAULT_SCOPE);
  scope.target.origin = 'http://127.0.0.1:4329';
  scope.domains = ['example.test'];
  scope.discovery.sensitivePaths = false;
  scope.discovery.external.certificateTransparency = true;
  scope.limits.hosts = 10;
  scope.limits.dnsQueries = 200;
  scope.limits.requestsPerHost = 8;
  const names = new Set(['example.test', 'api.example.test', 'deep.api.example.test',
    'api.api.example.test', 'api.api.api.example.test', 'api.api.api.api.example.test']);
  const resolve = async name => names.has(name) ? ['203.0.113.10'] : [];
  const calls = [];
  const requester = async ({url, purpose}) => {
    const parsed = new URL(url);
    calls.push({host: parsed.hostname, path: parsed.pathname, purpose});
    let status = 404, body = '';
    if (parsed.pathname === '/' && names.has(parsed.hostname)) {
      status = 200;
      body = parsed.hostname === 'api.example.test' ? '<html><script src="/app.js"></script></html>' : '<html>OK</html>';
    } else if (parsed.hostname === 'api.example.test' && parsed.pathname === '/app.js') {
      status = 200;
      body = 'const service="https://deep.api.example.test/v1/users"; const off="https://third-party.invalid/v1"; fetch("/v1/next?to=guide.txt");';
    } else if (parsed.hostname === 'api.example.test' && parsed.pathname === '/openapi.json') {
      status = 200;
      body = JSON.stringify({openapi: '3.0.0', paths: {'/v1/users': {get: {parameters: [
        {name: 'owner', in: 'query', example: 'u-1'},
        {name: 'source.file', in: 'query', example: 'guide.txt'},
        {name: 'auth.token', in: 'query', example: 'shortsecret'}]}}}});
    }
    return {status, body, type: parsed.pathname.endsWith('.js') ? 'application/javascript' : 'text/html',
      headers: {'content-type': 'text/html'}, bytes: body.length, hash: `sha256:${hash(body)}`,
      evidenceId: ledger.append({step: 'discovery', kind: 'http', request: {url}, response: {status}})};
  };
  const result = await discover(scope, {requester, ledger, resolve,
    ct: async () => ({status: 200, body: '[{"name_value":"api.example.test"}]'})});
  assert.ok(result.hosts.some(host => host.host === 'api.example.test' && host.live.https === 200));
  assert.ok(result.hosts.some(host => host.host === 'deep.api.example.test'), 'bundle host re-enters discovery');
  assert.ok(result.hosts.some(host => host.host === 'api.api.api.api.example.test'),
    'recursive discovery continues beyond three descendant labels');
  assert.ok(result.hosts.find(host => host.host === 'api.example.test').operations.some(item =>
    item.method === 'GET' && item.path === '/v1/users' && item.params.some(param =>
      param.name === 'owner' && param.example === 'u-1')),
  'API document methods, parameters and safe examples are retained for each discovered host');
  const operation = result.hosts.find(host => host.host === 'api.example.test').operations
    .find(item => item.path === '/v1/users' && item.method === 'GET');
  assert.ok(operation.params.some(param => param.name === 'source.file' && param.example === 'guide.txt'));
  assert.ok(operation.params.some(param => param.name === 'auth.token' && param.example === undefined));
  assert.ok(result.hosts.find(host => host.host === 'api.example.test').operations.some(item =>
    item.path === '/v1/next' && item.source.includes('client-asset') &&
    item.params.some(param => param.name === 'to' && param.example === 'guide.txt')));
  assert.ok(!JSON.stringify(result).includes('shortsecret'));
  assert.ok(result.external.includes('third-party.invalid'));
  assert.ok(calls.every(call => call.host === 'example.test' || call.host.endsWith('.example.test')));
  assert.ok(result.stats.dnsQueries <= scope.limits.dnsQueries);
  assert.equal(verifyLedger(ledger.file).ok, true);
});

test('configured target and apex keep host slots when CT returns more names than the host limit', async t => {
  const dir = temp();
  t.after(() => fs.rmSync(dir, {recursive: true, force: true}));
  const ledger = createLedger(dir);
  const scope = structuredClone(DEFAULT_SCOPE);
  scope.target.origin = 'https://app.example.test';
  scope.domains = ['example.test'];
  scope.discovery.sensitivePaths = false;
  scope.discovery.external.certificateTransparency = true;
  scope.limits.hosts = 3;
  scope.limits.requestsPerHost = 8;
  const contacted = [];
  let ctCalls = 0;
  const result = await discover(scope, {ledger,
    ct: async () => {
      ctCalls++;
      assert.ok(contacted.includes('app.example.test'), 'target root was probed before the external CT lookup');
      return {status: 200, body: JSON.stringify(['a', 'b', 'c', 'd'].map(label =>
        ({name_value: `${label}.example.test`})))};
    },
    resolve: async () => ['203.0.113.10'],
    connectTls: async host => ({subjectaltname: `DNS:${host}`}),
    requester: async ({url}) => {
      contacted.push(new URL(url).hostname);
      const body = new URL(url).pathname === '/' ? '<html>seed</html>' : '';
      const status = body ? 200 : 404;
      return {status, body, type: 'text/html', headers: {'content-type': 'text/html'},
        bytes: body.length, hash: `sha256:${hash(body)}`,
        evidenceId: ledger.append({step: 'discovery', request: {url}, response: {status}})};
    }});
  assert.deepEqual(result.hosts.map(host => host.host), ['app.example.test', 'example.test', 'a.example.test']);
  assert.equal(ctCalls, 1);
  assert.ok(contacted.every(host => ['app.example.test', 'example.test', 'a.example.test'].includes(host)));
  assert.ok(result.stats.cut > 0, 'unvisited CT and wordlist leads remain visible as cuts');
  assert.equal(verifyLedger(ledger.file).ok, true);
});

test('Muse naming runs before wordlist guesses fill the last host slot', async t => {
  const dir = temp();
  t.after(() => fs.rmSync(dir, {recursive: true, force: true}));
  const ledger = createLedger(dir);
  const scope = structuredClone(DEFAULT_SCOPE);
  scope.target.origin = 'https://app.example.test';
  scope.domains = ['example.test'];
  scope.discovery.sensitivePaths = false;
  scope.limits.hosts = 3;
  scope.limits.requestsPerHost = 8;
  const blue = 'blue.staging.api.example.test';
  const available = new Set(['app.example.test', 'example.test', 'api.example.test', blue]);
  const resolved = [], prompts = [];
  const result = await discover(scope, {ledger,
    resolve: async host => {resolved.push(host); return available.has(host) ? ['203.0.113.10'] : [];},
    connectTls: async host => ({subjectaltname: `DNS:${host}`}),
    requester: async ({url}) => {
      const body = new URL(url).pathname === '/' ? '<html>seed</html>' : '';
      const status = body ? 200 : 404;
      return {status, body, type: 'text/html', headers: {'content-type': 'text/html'},
        bytes: body.length, hash: `sha256:${hash(body)}`,
        evidenceId: ledger.append({step: 'discovery', request: {url}, response: {status}})};
    },
    model: {model: 'fixture'}, infer: async (_model, messages) => {
      prompts.push(JSON.parse(messages[1].content));
      return {names: prompts.length === 1 ? [blue] : []};
    }});
  assert.deepEqual(result.hosts.map(host => host.host), ['app.example.test', 'example.test', blue]);
  assert.ok(result.hosts[2].foundBy.includes('model:naming'));
  assert.ok(!resolved.includes('api.example.test'), 'speculative wordlist DNS did not preempt Muse');
  assert.equal(result.modelNaming.newHosts, 1);
  assert.equal(result.modelNaming.hostsCut, 1, 'the new host was not sent back for interpretation');
  assert.ok(result.stats.cut > 0, 'wordlist leads cut by the host budget are recorded');
});

test('a wordlist name already resolved as a seed reuses its DNS evidence', async t => {
  const dir = temp();
  t.after(() => fs.rmSync(dir, {recursive: true, force: true}));
  const ledger = createLedger(dir);
  const scope = structuredClone(DEFAULT_SCOPE);
  scope.target.origin = 'https://app.example.test';
  scope.domains = ['example.test'];
  scope.discovery.knownHosts = ['api.example.test'];
  scope.discovery.sensitivePaths = false;
  scope.limits.hosts = 4;
  scope.limits.dnsQueries = 250;
  scope.limits.requestsPerHost = 8;
  const available = new Set(['app.example.test', 'example.test', 'api.example.test']);
  const counts = new Map();
  const result = await discover(scope, {ledger,
    resolve: async host => {
      counts.set(host, (counts.get(host) ?? 0) + 1);
      return available.has(host) ? ['203.0.113.10'] : [];
    },
    connectTls: async host => ({subjectaltname: `DNS:${host}`}),
    requester: async ({url}) => {
      const body = new URL(url).pathname === '/' ? '<html>seed</html>' : '';
      const status = body ? 200 : 404;
      return {status, body, type: 'text/html', headers: {'content-type': 'text/html'},
        bytes: body.length, hash: `sha256:${hash(body)}`,
        evidenceId: ledger.append({step: 'discovery', request: {url}, response: {status}})};
    }});
  assert.equal(result.hosts.length, 3);
  assert.equal(counts.get('app.example.test'), 1);
  assert.equal(counts.get('api.example.test'), 1);
  assert.equal(result.stats.dnsQueries, [...counts.values()].reduce((sum, count) => sum + count, 0));
  assert.equal(verifyLedger(ledger.file).ok, true);
});

test('operator DNS words reach a deep observed parent within the same guarded budget', async t => {
  const dir = temp();
  t.after(() => fs.rmSync(dir, {recursive: true, force: true}));
  const ledger = createLedger(dir);
  const scope = structuredClone(DEFAULT_SCOPE);
  scope.target.origin = 'https://app.example.test';
  scope.domains = ['example.test'];
  scope.discovery.knownHosts = ['api.example.test'];
  scope.discovery.sensitivePaths = false;
  scope.seeds.dnsWords = ['blue'];
  scope.limits.hosts = 5;
  scope.limits.requestsPerHost = 8;
  const deep = 'blue.api.example.test';
  const available = new Set(['app.example.test', 'example.test', 'api.example.test', deep]);
  const resolved = [];
  const result = await discover(scope, {ledger,
    resolve: async host => {resolved.push(host); return available.has(host) ? ['203.0.113.10'] : [];},
    connectTls: async host => ({subjectaltname: `DNS:${host}`}),
    requester: async ({url}) => {
      const body = new URL(url).pathname === '/' ? '<html>seed</html>' : '';
      const status = body ? 200 : 404;
      return {status, body, type: 'text/html', headers: {'content-type': 'text/html'},
        bytes: body.length, hash: `sha256:${hash(body)}`,
        evidenceId: ledger.append({step: 'discovery', request: {url}, response: {status}})};
    }});
  assert.ok(result.hosts.some(host => host.host === deep && host.foundBy.includes('wordlist')));
  assert.ok(resolved.includes(deep));
  assert.ok(!resolved.includes('admin.api.example.test'));
  assert.equal(verifyLedger(ledger.file).ok, true);
});

test('HTML links and URL-bearing response headers feed only in-scope host discovery', async t => {
  const dir = temp();
  t.after(() => fs.rmSync(dir, {recursive: true, force: true}));
  const ledger = createLedger(dir);
  const scope = structuredClone(DEFAULT_SCOPE);
  scope.target.origin = 'https://app.example.test';
  scope.domains = ['example.test'];
  scope.discovery.sensitivePaths = false;
  scope.seeds.dnsWords = [];
  scope.limits.hosts = 8;
  scope.limits.requestsPerHost = 8;
  const names = ['app.example.test', 'example.test',
    ...['html', 'link', 'header', 'csp', 'cors', 'redirect'].map(label => `${label}.deep.example.test`)];
  const available = new Set(names), requested = [], resolved = [];
  const result = await discover(scope, {ledger,
    resolve: async host => {resolved.push(host); return available.has(host) ? ['203.0.113.10'] : [];},
    connectTls: async host => ({subjectaltname: `DNS:${host}`}),
    requester: async ({url}) => {
      const parsed = new URL(url);
      requested.push(parsed.hostname);
      const appRoot = parsed.hostname === 'app.example.test' && parsed.pathname === '/';
      const body = appRoot ? '<html><script src="https://html.deep.example.test/app.js"></script>' +
        '<a href="https://link.deep.example.test/home">link</a></html>' :
        parsed.pathname === '/' ? '<html>host</html>' : '';
      const status = body ? 200 : 404;
      const headers = appRoot ? {
        link: '<https://header.deep.example.test/api>; rel="preload"',
        'content-security-policy': 'connect-src https://csp.deep.example.test https://outside.invalid',
        'access-control-allow-origin': 'https://cors.deep.example.test',
        location: 'https://redirect.deep.example.test/next',
        'x-untrusted': 'https://outside.invalid/hidden'} : {'content-type': 'text/html'};
      return {status, body, type: appRoot ? '' : 'text/html', headers, bytes: body.length,
        hash: `sha256:${hash(body)}`,
        evidenceId: ledger.append({step: 'discovery', request: {url}, response: {status}})};
    }});
  assert.deepEqual(new Set(result.hosts.map(host => host.host)), available);
  assert.ok(result.hosts.find(host => host.host === 'html.deep.example.test').foundBy
    .includes('html:app.example.test'));
  assert.ok(result.hosts.find(host => host.host === 'header.deep.example.test').foundBy
    .includes('header:link:app.example.test'));
  assert.ok(resolved.every(host => available.has(host) || host.endsWith('.example.test')));
  assert.ok(requested.every(host => available.has(host)));
  assert.ok(result.external.includes('outside.invalid'));
  assert.ok(!resolved.includes('outside.invalid') && !requested.includes('outside.invalid'));
  assert.equal(verifyLedger(ledger.file).ok, true);
});

test('a verified HTTPS certificate adds exact deep SAN hosts without resolving wildcard or off-domain names', async t => {
  const dir = temp();
  t.after(() => fs.rmSync(dir, {recursive: true, force: true}));
  const ledger = createLedger(dir);
  const scope = structuredClone(DEFAULT_SCOPE);
  scope.domains = ['example.test'];
  scope.discovery.knownHosts = ['api.example.test'];
  scope.discovery.sensitivePaths = false;
  scope.limits.hosts = 6;
  scope.limits.dnsQueries = 250;
  scope.limits.requestsPerHost = 8;
  const deep = 'blue.staging.api.example.test';
  const names = new Set(['example.test', 'api.example.test', deep]);
  const resolved = [], certificates = [];
  const result = await discover(scope, {ledger,
    resolve: async host => {resolved.push(host); return names.has(host) ? ['203.0.113.10'] : [];},
    connectTls: async (host, addresses) => {
      certificates.push({host, addresses});
      return {issuer: {O: 'Fixture CA'}, valid_to: 'Jan 10 00:00:00 2027 GMT',
        subjectaltname: host === 'api.example.test' ?
          `DNS:${deep}, DNS:outside.invalid, DNS:*.ghost.example.test, DNS:api.example.test` :
          `DNS:${host}`};
    },
    requester: async ({url}) => {
      const parsed = new URL(url);
      const status = parsed.pathname === '/' && names.has(parsed.hostname) ? 200 : 404;
      const body = status === 200 ? '<html>Certificate fixture</html>' : '';
      return {status, body, type: 'text/html', headers: {'content-type': 'text/html'},
        bytes: body.length, hash: `sha256:${hash(body)}`,
        evidenceId: ledger.append({step: 'discovery', kind: 'http', request: {url}, response: {status}})};
    }});
  const api = result.hosts.find(host => host.host === 'api.example.test');
  const discovered = result.hosts.find(host => host.host === deep);
  assert.ok(discovered?.foundBy.includes('tls:api.example.test'));
  assert.equal(discovered.live.https, 200);
  assert.ok(api.certificate.sans.includes(deep));
  assert.deepEqual(api.certificate.wildcardSans, ['ghost.example.test']);
  assert.equal(api.certificate.issuer, 'Fixture CA');
  assert.ok(api.certificate.evidenceId);
  assert.ok(result.external.includes('outside.invalid'));
  assert.ok(!resolved.includes('outside.invalid') && !resolved.includes('ghost.example.test'));
  assert.ok(certificates.every(item => item.addresses[0] === '203.0.113.10'));
  assert.equal(result.stats.tlsFailures, 0);
  assert.equal(result.stats.tlsHandshakes, result.stats.hostsLive);
  assert.equal(verifyLedger(ledger.file).ok, true);
});

test('non-recursive discovery records certificate names but probes only listed hosts', async t => {
  const dir = temp();
  t.after(() => fs.rmSync(dir, {recursive: true, force: true}));
  const ledger = createLedger(dir);
  const scope = structuredClone(DEFAULT_SCOPE);
  scope.domains = ['example.test'];
  scope.discovery.knownHosts = ['api.example.test'];
  scope.discovery.recurse = false;
  scope.discovery.sensitivePaths = false;
  scope.discovery.external.certificateTransparency = true;
  scope.limits.requestsPerHost = 8;
  const resolved = [];
  let ctCalls = 0;
  const result = await discover(scope, {ledger,
    resolve: async host => {resolved.push(host); return ['example.test', 'api.example.test',
      'deep.api.example.test'].includes(host) ? ['203.0.113.10'] : [];},
    ct: async () => {ctCalls++; return {status: 200, body: '[]'};},
    connectTls: async host => ({subjectaltname: `DNS:${host}, DNS:deep.api.example.test`}),
    requester: async ({url}) => {
      const parsed = new URL(url);
      const status = parsed.pathname === '/' ? 200 : 404;
      return {status, body: '', headers: {}, bytes: 0, hash: `sha256:${hash('')}`,
        evidenceId: ledger.append({step: 'discovery', request: {url}, response: {status}})};
    }});
  assert.equal(ctCalls, 0);
  assert.deepEqual(new Set(resolved), new Set(['example.test', 'api.example.test']));
  assert.ok(!result.hosts.some(host => host.host === 'deep.api.example.test'));
  assert.ok(result.hosts.find(host => host.host === 'api.example.test').certificate.sans.includes('deep.api.example.test'));
  assert.equal(verifyLedger(ledger.file).ok, true);
});

test('a failed certificate lookup leaves discovery incomplete with a ledger reason', async t => {
  const dir = temp();
  t.after(() => fs.rmSync(dir, {recursive: true, force: true}));
  const ledger = createLedger(dir);
  const scope = structuredClone(DEFAULT_SCOPE);
  scope.domains = ['example.test'];
  scope.discovery.recurse = false;
  scope.discovery.sensitivePaths = false;
  scope.limits.requestsPerHost = 8;
  const result = await discover(scope, {ledger,
    resolve: async () => ['203.0.113.10'],
    connectTls: async () => {throw Error('certificate unavailable');},
    requester: async ({url}) => {
      const status = new URL(url).pathname === '/' ? 200 : 404;
      return {status, body: '', headers: {}, bytes: 0, hash: `sha256:${hash('')}`,
        evidenceId: ledger.append({step: 'discovery', request: {url}, response: {status}})};
    }});
  assert.equal(result.stats.tlsFailures, 1);
  assert.equal(result.incomplete, true);
  assert.ok(result.hosts[0].evidence.length > 1);
  assert.match(fs.readFileSync(ledger.file, 'utf8'), /certificate unavailable/);
  assert.equal(verifyLedger(ledger.file).ok, true);
});

test('Muse labels only observed hosts, operations and parameters in the discovery inventory', async () => {
  const discovery = {hosts: [{host: 'api.example.test', live: {https: 200}, title: 'Example API', stack: [],
    operations: [{method: 'GET', path: '/v1/users', params: [{name: 'owner', in: 'query'}], source: ['document:/openapi.json']}]}]};
  const analysis = await interpretDiscovery(discovery, {model: {model: 'fixture'}, infer: async (_model, messages) => {
    assert.match(messages[1].content, /\/v1\/users/);
    return {hosts: [
      {host: 'other.example.test', role: 'api', why: 'invented', operations: []},
      {host: 'api.example.test', role: 'api', why: 'documented API', operations: [
        {method: 'GET', path: '/v1/users', purpose: 'Lists users', parameters: [
          {name: 'owner', meaning: 'filters by owner'}, {name: 'secret', meaning: 'invented'}]},
        {method: 'POST', path: '/v1/delete', purpose: 'invented', parameters: []},
      ]},
    ]};
  }});
  assert.equal(analysis.modelCalls, 1);
  assert.equal(discovery.hosts[0].analysis.role, 'api');
  assert.equal(discovery.hosts[0].operations[0].purpose, 'Lists users');
  assert.deepEqual(discovery.hosts[0].operations[0].parameterMeanings,
    [{name: 'owner', meaning: 'filters by owner'}]);
  assert.equal(discovery.hosts.length, 1);
});

test('Muse discovery interpretation pages beyond the first twelve operations', async () => {
  const operations = Array.from({length: 15}, (_, index) => ({method: 'GET', path: `/api/item-${index}`,
    params: [{name: 'query', in: 'query'}], source: ['document:/openapi.json']}));
  const discovery = {hosts: [{host: 'api.example.test', live: {https: 200}, title: 'API', stack: [], operations}]};
  const seen = [];
  const analysis = await interpretDiscovery(discovery, {model: {model: 'fixture'}, maxCalls: 2,
    infer: async (_model, messages) => {
      const context = JSON.parse(messages[1].content);
      seen.push(context.hosts[0].operations.map(item => item.path));
      return {hosts: context.hosts.map(host => ({host: host.host, role: 'api', why: 'documented operations',
        operations: host.operations.map(item => ({method: item.method, path: item.path,
          purpose: `Purpose of ${item.path}`, parameters: [{name: 'query', meaning: 'search term'}]}))}))};
    }});
  assert.equal(analysis.modelCalls, 2);
  assert.equal(analysis.operationsSent, 15);
  assert.equal(analysis.operationsCut, 0);
  assert.equal(seen[0].length, 12);
  assert.deepEqual(seen[1], ['/api/item-12', '/api/item-13', '/api/item-14']);
  assert.equal(operations[14].purpose, 'Purpose of /api/item-14');
});

test('an HTTP-only descendant is inventoried after HTTPS cannot connect', async t => {
  const dir = temp();
  t.after(() => fs.rmSync(dir, {recursive: true, force: true}));
  const ledger = createLedger(dir);
  const scope = structuredClone(DEFAULT_SCOPE);
  scope.domains = ['example.test'];
  scope.discovery.knownHosts = ['api.example.test'];
  scope.discovery.recurse = false;
  scope.discovery.sensitivePaths = false;
  scope.limits.requestsPerHost = 10;
  const calls = [];
  const requester = async ({url}) => {
    calls.push(url);
    const parsed = new URL(url);
    if (parsed.protocol === 'https:') return {blocked: true, reason: 'TLS unavailable',
      evidenceId: ledger.append({step: 'discovery', request: {url}, blocked: {reason: 'TLS unavailable'}})};
    const body = parsed.pathname === '/openapi.json' ? JSON.stringify({openapi: '3.0.0', paths: {
      '/api/status': {get: {}}}}) : '<html>HTTP application</html>';
    return {status: 200, body, type: parsed.pathname.endsWith('.json') ? 'application/json' : 'text/html',
      headers: {'content-type': 'text/html'}, bytes: body.length, hash: `sha256:${hash(body)}`,
      evidenceId: ledger.append({step: 'discovery', request: {url}, response: {status: 200}})};
  };
  const result = await discover(scope, {requester, ledger,
    resolve: async name => ['example.test', 'api.example.test'].includes(name) ? ['203.0.113.10'] : []});
  const host = result.hosts.find(item => item.host === 'api.example.test');
  assert.equal(host.origin, 'http://api.example.test');
  assert.equal(host.live.http, 200);
  assert.ok(host.operations.some(item => item.method === 'GET' && item.path === '/api/status'));
  assert.ok(calls.includes('http://api.example.test/openapi.json'));
  assert.equal(verifyLedger(ledger.file).ok, true);
});

test('Muse naming proposes a deep in-scope host that rejoins guarded discovery', async t => {
  const dir = temp();
  t.after(() => fs.rmSync(dir, {recursive: true, force: true}));
  const ledger = createLedger(dir);
  const scope = structuredClone(DEFAULT_SCOPE);
  scope.domains = ['example.test'];
  scope.discovery.knownHosts = ['api.example.test'];
  scope.discovery.sensitivePaths = false;
  scope.limits.hosts = 5;
  scope.limits.dnsQueries = 500;
  scope.limits.requestsPerHost = 8;
  const deep = 'blue.staging.api.example.test';
  const names = new Set(['example.test', 'api.example.test', deep]);
  const resolved = [], httpCalls = [], prompts = [];
  const resolve = async name => {
    resolved.push(name);
    return names.has(name) ? ['203.0.113.10'] : [];
  };
  const requester = async ({url}) => {
    httpCalls.push(url);
    const parsed = new URL(url);
    const status = parsed.pathname === '/' ? 200 : 404;
    const body = status === 200 ? `<html><title>${parsed.hostname}</title></html>` : '';
    return {status, body, type: 'text/html', headers: {'content-type': 'text/html'}, bytes: body.length,
      hash: `sha256:${hash(body)}`, evidenceId: ledger.append({step: 'discovery', request: {url}, response: {status}})};
  };
  const infer = async (_model, messages) => {
    const context = JSON.parse(messages[1].content);
    prompts.push(context);
    return {names: prompts.length === 1 ? [deep, 'outside.invalid', 'api.example.test', 'bad..example.test', '*.example.test'] : []};
  };
  const result = await discover(scope, {requester, ledger, resolve, infer, model: {model: 'fixture'}});
  assert.ok(result.hosts.some(host => host.host === deep && host.foundBy.includes('model:naming')));
  assert.ok(httpCalls.some(url => new URL(url).hostname === deep));
  assert.ok(!resolved.includes('outside.invalid') && !resolved.includes('bad..example.test'));
  assert.equal(result.modelNaming.accepted, 1);
  assert.equal(result.modelNaming.rejected, 4);
  assert.equal(result.modelNaming.newHosts, 1);
  assert.equal(result.modelNaming.hostsCut, 0);
  assert.ok(prompts[0].hosts.some(host => host.host === 'api.example.test'));
  assert.equal(verifyLedger(ledger.file).ok, true);
});
