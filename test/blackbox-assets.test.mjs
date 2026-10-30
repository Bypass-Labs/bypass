// Tests for src/blackbox/assets.mjs: the secret scanner, normalization, extraction from the
// fixture bundle and HTML, and mineOrigin against a loopback site (design sections 5.4 and 6.3).
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import http from 'node:http';
import { createHash } from 'node:crypto';
import { SECRET_PATTERNS, maskSecrets, normalizeScript, extractFromScript, extractFromHtml, libraryAdvisoryKey, mineOrigin } from '../src/blackbox/assets.mjs';
import {interpretAssets} from '../src/blackbox/asset-interpret.mjs';
import { safeRequest } from '../src/network.mjs';
import { port } from './helpers.mjs';

const BUNDLE = fs.readFileSync(new URL('./fixtures/blackbox/bundle.js', import.meta.url), 'utf8');
const ORIGIN = 'http://127.0.0.1:4329';
const sha256 = value => `sha256:${createHash('sha256').update(value).digest('hex')}`;
const lineOf = (text, needle) => text.slice(0, text.indexOf(needle)).split('\n').length;
const columnOf = (text, needle) => { const at = text.indexOf(needle); return at - text.lastIndexOf('\n', at - 1); };
const b64url = value => Buffer.from(JSON.stringify(value)).toString('base64url');
// Provider-shaped fakes are assembled at runtime so no key-shaped literal is committed.
const fake = (...parts) => parts.join('');

// Raw values that must never appear in any result, in plain or JSON-escaped form.
function assertNoRawValues(result, values) {
  const json = JSON.stringify(result);
  for (const value of values) {
    assert.ok(!json.includes(value), `raw value leaked: ${value.slice(0, 4)}…`);
    assert.ok(!json.includes(JSON.stringify(value).slice(1, -1)), `escaped value leaked: ${value.slice(0, 4)}…`);
  }
}

const BUNDLE_SECRETS = ['AKIAIOSFODNN7EXAMPLE', 'pk_live_51FAKEpublishableKEY0000TEST', 'pk.eyJ1IjoiYWNtZSIsImEiOiJmYWtlLXRva2VuLWlkIn0.FAKE0000TEST',
  BUNDLE.match(/eyJhbGci[\w.-]+/)[0], 's3cretPassw0rd', 'shh-this-is-not-a-real-secret-123', 'cfg-token-0123456789abcdef'];

const JWT = [b64url({alg: 'HS256', typ: 'JWT'}), b64url({iss: 'https://auth.example.test', aud: 'scanner-test', exp: 1900000000, sub: 'u-1'}), 'c2lnbmF0dXJlLWZha2U'].join('.');
const SECRETS = {
  'aws-access-key': fake('AKIA', 'Z7Q2FAKEFAKEK3Y9'),
  'stripe-secret-key': fake('sk_', 'live_', 'FAKE0000000000000000TEST'),
  'stripe-restricted-key': fake('rk_', 'live_', 'FAKE0000000000000000TEST'),
  'stripe-publishable-key': fake('pk_', 'live_', 'FAKE0000000000000000TEST'),
  'github-token': fake('gh', 'p_', 'FAKE', '0'.repeat(28), 'TEST'),
  'slack-token': fake('xo', 'xb-', '000000000000-0000000000000-', 'FAKE0000TEST'),
  'sendgrid-key': fake('SG', '.', 'FAKE'.padEnd(22, '0'), '.', 'TEST'.padEnd(43, '0')),
  'twilio-key': fake('S', 'K', 'deadbeef'.repeat(4)),
  'mailgun-key': fake('key', '-', 'deadbeef'.repeat(4)),
  'mapbox-secret-token': fake('sk', '.eyJ', 'FAKE0000TEST', '.', 'FAKE0000TEST'),
  'mapbox-public-token': fake('pk', '.eyJ', 'FAKE0000TEST', '.', 'FAKE0000TEST'),
  'google-api-key': fake('AI', 'za', 'Sy', 'FAKE'.padEnd(33, '0')),
  jwt: JWT,
  'private-key': fake('-----BEGIN RSA ', 'PRIVATE KEY-----\\nMIIEfakeKEYmaterial\\n-----END RSA ', 'PRIVATE KEY-----'),
  'basic-auth-url': 'https://deploy:FAKEpass123@git.example.test',
};
const SUFFIX = {'basic-auth-url': '/acme.git'}; // the credential is scheme://user:pass@host; the path is not part of it
const FIREBASE_KEY = fake('AI', 'za', 'Sy', 'FIREBASE'.padEnd(33, '0'));
const GENERIC_VALUE = 'tok-1234abcd5678';
const PUBLIC = ['stripe-publishable-key', 'mapbox-public-token', 'firebase-config'];

test('SECRET_PATTERNS is a frozen list with a confidence per pattern and publishable keys marked public', () => {
  assert.ok(Object.isFrozen(SECRET_PATTERNS));
  for (const pattern of SECRET_PATTERNS) {
    assert.ok(pattern.regex instanceof RegExp && !pattern.regex.global, pattern.name);
    assert.ok(['high', 'medium', 'low'].includes(pattern.confidence), pattern.name);
    assert.equal(pattern.public, PUBLIC.includes(pattern.name), pattern.name);
  }
  const names = SECRET_PATTERNS.map(pattern => pattern.name);
  for (const name of [...Object.keys(SECRETS), 'firebase-config', 'generic']) assert.ok(names.includes(name), name);
  assert.equal(SECRET_PATTERNS.find(pattern => pattern.name === 'generic').confidence, 'low');
});

test('the secret scanner finds every pattern, masks values, hashes them and ignores look-alikes', () => {
  const script = [
    `var keys={${Object.entries(SECRETS).map(([name, value], index) => `k${index}:"${value}${SUFFIX[name] ?? ''}"`).join(',')}};`,
    `firebase.initializeApp({apiKey:"${FIREBASE_KEY}",authDomain:"acme-prod.firebaseapp.com",projectId:"acme-prod"});`,
    `var conf={apiToken:"${GENERIC_VALUE}"};`,
    'var decoys={uuid:"123e4567-e89b-12d3-a456-426614174000",sha:"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",',
    'png:"iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNkYPhfDwAChwGA60e6kgAAAABJRU5ErkJggg==",label:{password:"Password",hint:"Enter your password"},',
    `dsn:"https://abc123@o123.ingest.sentry.io/456",short:"ghp_short",test:"${fake('sk_', 'test_', 'FAKE0000000000000000TEST')}",lower:"AKIAlowercase000000"};`,
  ].join('\n');
  const result = extractFromScript(script, {url: `${ORIGIN}/static/keys.js`});
  const lines = script.split('\n');
  for (const [name, value] of Object.entries(SECRETS)) {
    const found = result.secrets.filter(secret => secret.name === name);
    assert.equal(found.length, 1, name);
    assert.equal(found[0].masked, `${value.slice(0, 4)}…(${value.length})`, name);
    assert.equal(found[0].hash, sha256(value), name);
    assert.ok(lines[found[0].line - 1].slice(found[0].column - 1).startsWith(value), `${name} location`);
    assert.equal(found[0].public, PUBLIC.includes(name), name);
  }
  const firebase = result.secrets.find(secret => secret.name === 'firebase-config');
  assert.deepEqual([firebase.public, firebase.masked, firebase.hash], [true, 'AIza…(39)', sha256(FIREBASE_KEY)]);
  const generic = result.secrets.find(secret => secret.name === 'generic');
  assert.deepEqual([generic.confidence, generic.hash], ['low', sha256(GENERIC_VALUE)]);
  assert.deepEqual(result.secrets.find(secret => secret.name === 'jwt').claims, {alg: 'HS256', iss: 'https://auth.example.test', aud: 'scanner-test', exp: 1900000000});
  assert.equal(result.secrets.length, Object.keys(SECRETS).length + 2, result.secrets.map(secret => secret.name).join(','));
  assertNoRawValues(result, [...Object.values(SECRETS), FIREBASE_KEY, GENERIC_VALUE, 'FAKEpass123']);
});

test('maskSecrets replaces each secret with its first four characters and length', () => {
  const aws = SECRETS['aws-access-key'];
  assert.equal(maskSecrets(`key ${aws} and ${JWT}.`), `key AKIA…(20) and eyJh…(${JWT.length}).`);
  assert.equal(maskSecrets('nothing to see /api/users'), 'nothing to see /api/users');
});

test('normalizeScript joins concatenations, keeps template slots as {id} and appends decoded base64 text', () => {
  const config = Buffer.from(JSON.stringify({apiBase: '/api/v9', note: 'decoded configuration'})).toString('base64');
  const png = 'iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNkYPhfDwAChwGA60e6kgAAAABJRU5ErkJggg==';
  const source = [
    'a("/api/" + "users" + "/list");',
    "b('/v1/' + 'teams');",
    'c(`/api/invoices/${e.id}/pdf?x=${t}`);',
    'd("/api/users/".concat(e, "/posts"));',
    `e="${config}";f="${png}";`,
  ].join('\n');
  const out = normalizeScript(source).split('\n');
  assert.deepEqual(out.slice(0, 4), [
    'a("/api/users/list");',
    "b('/v1/teams');",
    'c(`/api/invoices/{id}/pdf?x={id}`);',
    'd("/api/users/"+e+"/posts");',
  ]);
  assert.equal(out.length, 6, 'one decoded block appended; the image literal is not text');
  assert.deepEqual(JSON.parse(out[5]), {apiBase: '/api/v9', note: 'decoded configuration'});
});

test('extractFromScript mines endpoints with methods, parameters and headers from the fixture bundle', () => {
  const result = extractFromScript(BUNDLE, {url: `${ORIGIN}/static/bundle.js`, origin: ORIGIN});
  const endpoint = (method, path) => result.endpoints.find(item => item.method === method && item.path === path);
  assert.ok(result.endpoints.length >= 20, `only ${result.endpoints.length} endpoints`);
  const create = endpoint('POST', '/api/invoices');
  assert.deepEqual([create.kind, create.params, create.headers], ['callsite', ['customerId', 'amount'], ['Content-Type', 'Authorization', 'X-Tenant-Id']]);
  assert.equal(create.line, lineOf(BUNDLE, 'fetch("/api/invoices",'));
  assert.deepEqual(endpoint('GET', '/api/invoices').params, ['page', 'limit'], 'URLSearchParams keys');
  assert.equal(endpoint('DELETE', '/api/users/{id}').kind, 'callsite');
  assert.deepEqual(endpoint('POST', '/api/auth/session').params, ['email', 'password']);
  assert.deepEqual(endpoint('GET', '/api/search').params, ['q', 'limit']);
  assert.deepEqual(endpoint('GET', '/api/teams/{id}/members').params, ['role']);
  assert.deepEqual(endpoint('GET', '/api/export').params, ['format']);
  for (const path of ['/api/me', '/api/invoices/{id}', '/api/invoices/{id}/pdf', '/api/users/{id}', '/api/users/{id}/posts', '/api/projects/{id}/tasks/{id}', '/api/status', '/api/plans/{id}', '/api/files/{id}/download']) {
    assert.equal(endpoint('GET', path)?.kind, 'callsite', path);
  }
  assert.ok(endpoint('PUT', '/api/settings'));
  assert.equal(endpoint('UNKNOWN', '/api/orders/{id}/items')?.kind, 'template');
  for (const path of ['/login', '/invoices/{id}', '/settings/profile', '/admin', '/admin/users/{id}', '/impersonate/{id}']) assert.equal(endpoint('UNKNOWN', path)?.kind, 'route', path);
  for (const path of ['/api/admin/users', '/api/billing/charge', '/internal/debug/flags', '/graphql', '/api/plans', '/api/v1', '/api/v2']) assert.equal(endpoint('UNKNOWN', path)?.kind, 'literal', path);
  assert.equal(endpoint('UNKNOWN', '/api/v2').line, lineOf(BUNDLE, 'atob('), 'decoded base64 config keeps the literal line');
  const paths = result.endpoints.map(item => item.path);
  for (const path of ['/static/logo.png', '/static/fonts/inter.woff2', '/static/app.css', '/static/chunk-1.js', '/tasks', '/posts', '/reports/{id}', '/api/v1/query', '/']) assert.ok(!paths.includes(path), path);
  assert.equal(new Set(result.endpoints.map(item => `${item.method} ${item.path}`)).size, result.endpoints.length, 'deduplicated');
});

test('asset mining recognizes config-object HTTP clients and XHR methods', () => {
  const script = [
    'axios({url:"/api/records?scope=global",method:"GET",params:{tenant:"east"},headers:{Authorization:"Bearer", "X-Trace":"x"}});',
    'client.request({url:"/api/items/"+id,method:"PATCH",data:{label:"new"}});',
    '$.ajax({url:"/api/search?q=widgets",type:"GET"});',
    'xhr.open("DELETE","/api/items/"+id);',
    'window.open("/api/marketing");',
  ].join('\n');
  const found = extractFromScript(script, {url: `${ORIGIN}/app.js`, origin: ORIGIN});
  const endpoint = (method, route) => found.endpoints.find(item => item.method === method && item.path === route);
  assert.deepEqual(endpoint('GET', '/api/records').params, ['scope', 'tenant']);
  assert.deepEqual(endpoint('GET', '/api/records').examples.scope, ['global']);
  assert.deepEqual(endpoint('GET', '/api/records').headers, ['Authorization', 'X-Trace']);
  assert.equal(endpoint('PATCH', '/api/items/{id}').kind, 'config-call');
  assert.equal(endpoint('GET', '/api/search').kind, 'config-call');
  assert.equal(endpoint('DELETE', '/api/items/{id}').kind, 'xhr-open');
  assert.equal(endpoint('GET', '/api/marketing'), undefined);
});

test('asset mining retains observed JSON body fields and only safe literal examples', () => {
  const script = [
    'fetch("/api/search",{method:"POST",body:JSON.stringify({query:"sample",limit:10,secret:"hidden123"})});',
    'axios.post("/api/search",{query:"second",active:true});',
    'client.request({url:"/api/submit",method:"POST",data:{message:"hello",role:currentRole}});',
    'fetch("/api/nested",{method:"POST",body:JSON.stringify({selector:{match:"public",variant:0}})});',
    '$.ajax({url:"/api/form",type:"POST",data:{message:"hello"}});',
    'class Local {hostServer=config.hostServer;send(value){return this.http.post(`${this.hostServer}/api/class`,{message:value})}}',
  ].join('\n');
  const found = extractFromScript(script, {url: `${ORIGIN}/app.js`, origin: ORIGIN});
  const at = path => found.endpoints.find(item => item.method === 'POST' && item.path === path);
  assert.deepEqual(at('/api/search').bodyFields, ['query', 'limit', 'secret', 'active']);
  assert.deepEqual(at('/api/search').bodyStringFields, ['query', 'secret']);
  assert.deepEqual(at('/api/search').fieldExamples.query, ['sample', 'second']);
  assert.equal(at('/api/search').fieldExamples.secret, undefined);
  assert.deepEqual(at('/api/submit').bodyFields, ['message', 'role']);
  assert.deepEqual(at('/api/submit').bodyStringFields, ['message']);
  assert.deepEqual(at('/api/nested').fieldValueExamples.selector,
    ['{"match":"public","variant":0}']);
  assert.deepEqual(at('/api/nested').fieldShapes.selector.properties,
    {match: {type: 'string'}, variant: {type: 'integer'}});
  assert.equal(at('/api/form').bodyEncoding, undefined, 'jQuery object data does not establish JSON encoding');
  assert.deepEqual(at('/api/class').bodyFields, ['message']);
  assert.deepEqual(at('/api/class').bodyStringFields, []);
});

test('asset mining keeps a query route behind a public hostServer prefix as an inferred GET candidate', () => {
  const source = [
    'class Products {hostServer=config.hostServer; search(q) {',
    '  return this.http.get(`${this.hostServer}/rest/products/search?q=${q}`);',
    '}}',
    'class External {get() {return this.http.get(`${this.foreignServer}/remote/search?q=${q}`);}}',
  ].join('\n');
  const found = extractFromScript(source, {url: `${ORIGIN}/app.js`, origin: ORIGIN});
  const search = found.endpoints.find(item => item.path === '/rest/products/search' && item.method === 'GET');
  assert.deepEqual([search?.params, search?.kind], [['q'], 'callsite-inferred-base']);
  assert.equal(found.endpoints.some(item => item.path === '/remote/search'), false);
});

test('asset mining recovers methods and parameters from a client class host alias without crossing classes', () => {
  const source = [
    "class Invoices {hostServer=config.hostServer; host=this.hostServer+'/api/v1/invoices';",
    "list(){return this.http.get(this.host+'/?state=open',{params:{page:1}})}",
    'get(id){return this.http.get(`${this.host}/${id}`)}',
    'create(){return this.http.post(this.host,{amount:10})}',
    "info(){return this.http.get(this.hostServer+'/rest/info?view=summary')}",
    '}',
    "class Remote {host='https://remote.example/api';read(){return this.http.get(this.host+'/private')}}",
    "class Mutable {host=this.hostServer+'/api/mutable';read(){this.host='/elsewhere';return this.http.get(this.host)}}",
  ].join('\n');
  const found = extractFromScript(source, {url: `${ORIGIN}/app.js`, origin: ORIGIN});
  const endpoint = (method, path) => found.endpoints.find(item => item.method === method && item.path === path);
  assert.deepEqual(endpoint('GET', '/api/v1/invoices')?.params.sort(), ['page', 'state']);
  assert.equal(endpoint('GET', '/api/v1/invoices/{id}')?.kind, 'callsite-inferred-base');
  assert.deepEqual(endpoint('POST', '/api/v1/invoices')?.params, ['amount']);
  assert.deepEqual(endpoint('GET', '/rest/info')?.params, ['view']);
  assert.equal(endpoint('GET', '/api/private'), undefined);
  assert.equal(endpoint('GET', '/api/mutable'), undefined);
});

test('asset mining connects an opaque POST body to a unique same-file caller object', () => {
  const source = [
    'class SessionClient {hostServer=config.hostServer;',
    'login(payload){return this.http.post(`${this.hostServer}/api/session`,payload)}}',
    'view.login({username:form.user,password:form.pass});',
    'class First {hostServer=config.hostServer;save(value){return this.http.post(`${this.hostServer}/api/first`,value)}}',
    'class Second {hostServer=config.hostServer;save(value){return this.http.post(`${this.hostServer}/api/second`,value)}}',
    'view.save({comment:"hello"});',
  ].join('');
  const found = extractFromScript(source, {url: `${ORIGIN}/app.js`, origin: ORIGIN});
  const at = route => found.endpoints.find(item => item.path === route && item.method === 'POST');
  assert.deepEqual(at('/api/session').bodyFields, ['username', 'password']);
  assert.equal(at('/api/session').bodyEvidence, 'same-file-caller-object');
  assert.equal(at('/api/first').bodyEncoding, undefined, 'ambiguous service method is not inferred');
  assert.equal(at('/api/second').bodyEncoding, undefined);
});

test('asset mining attributes same-named service method bodies by their injected receiver', () => {
  const source = [
    'var Alpha=(()=>{class a{hostServer=cfg.hostServer;host=this.hostServer+"/api/Alpha";',
    'save(x){return this.http.post(this.host+"/",x)}}return a})();',
    'var Beta=(()=>{class b{hostServer=cfg.hostServer;host=this.hostServer+"/api/Beta";',
    'save(x){return this.http.post(this.host+"/",x)}}return b})();',
    'class Page{alphaService=inject(Alpha);betaService=inject(Beta);submit(){',
    'this.alphaService.save({alpha:"one",label:"public"});',
    'this.betaService.save({beta:"two"})}}',
  ].join('');
  const found = extractFromScript(source, {url: `${ORIGIN}/app.js`, origin: ORIGIN});
  const at = route => found.endpoints.find(item => item.path === route && item.method === 'POST');
  assert.deepEqual(at('/api/Alpha').bodyFields, ['alpha', 'label']);
  assert.deepEqual(at('/api/Beta').bodyFields, ['beta']);
  assert.equal(at('/api/Alpha').bodyEvidence, 'same-file-receiver-object');
  assert.equal(at('/api/Beta').bodyEvidence, 'same-file-receiver-object');
});

test('asset mining records a query key constructed in a local suffix without retaining credential keys', () => {
  const source = [
    "class Profile {hostServer=config.hostServer;read(fields){let suffix=fields.length?`?view=${fields.join(',')}`:``;return this.http.get(this.hostServer+`/api/profile`+suffix)}",
    "private(token){let query=token?`?auth.token=${token}`:``;return this.http.get(this.hostServer+`/api/check`+query)}}",
  ].join('');
  const found = extractFromScript(source, {url: `${ORIGIN}/app.js`, origin: ORIGIN});
  const endpoint = path => found.endpoints.find(item => item.method === 'GET' && item.path === path);
  assert.deepEqual(endpoint('/api/profile')?.params, ['view']);
  assert.deepEqual(endpoint('/api/check')?.params, []);
});

test('asset mining reports inferred route and class cuts instead of silently dropping candidates', () => {
  const direct = Array.from({length: 130}, (_, index) =>
    'this.http.get(`${this.hostServer}/api/direct/' + index + '`);').join('');
  const aliased = Array.from({length: 130}, (_, index) =>
    "this.http.get(this.host+'/" + index + "');").join('');
  const source = direct + "class Client{host=this.hostServer+'/api/class';" + aliased + '}' +
    Array.from({length: 520}, (_, index) => `class Empty${index}{}`).join('');
  const found = extractFromScript(source, {url: `${ORIGIN}/app.js`, origin: ORIGIN});
  assert.equal(found.inferredRoutesCut, 20);
  assert.equal(found.inferredClassesCut, 9);
});

test('asset mining resolves same-origin fetch URL constructors with relative paths', () => {
  const script = [
    `fetch(new URL("go?next=/safe", "${ORIGIN}/tenant/one/"));`,
    `fetch(new URL("search?q="+term, "${ORIGIN}/tenant/one/").href);`,
    'fetch(new URL("/api/status", window.location.origin));',
    `fetch(new URL("${ORIGIN}/api/profile"));`,
    `fetch(new URL("off?next=/safe", "https://elsewhere.example/tenant/one/"));`,
    'fetch(new URL("https://elsewhere.example/api/offsite"));',
    'fetch(new URL("/api/off", foreignOrigin));',
    'fetch(new URL("dynamic?next=/safe", apiBase));',
    `fetch(new URL("altered?next=/safe", "${ORIGIN}/tenant/one/")+suffix);`,
  ].join('\n');
  const found = extractFromScript(script, {url: `${ORIGIN}/app.js`, origin: ORIGIN});
  const endpoint = (method, route) => found.endpoints.find(item => item.method === method && item.path === route);
  assert.deepEqual(endpoint('GET', '/tenant/one/go')?.params, ['next']);
  assert.deepEqual(endpoint('GET', '/tenant/one/search')?.params, ['q']);
  assert.equal(endpoint('GET', '/tenant/one/go')?.kind, 'callsite');
  assert.equal(endpoint('GET', '/api/status')?.kind, 'callsite');
  assert.equal(endpoint('GET', '/api/profile')?.kind, 'callsite');
  for (const route of ['/tenant/one/off', '/tenant/one/dynamic', '/tenant/one/altered', '/api/off', '/api/offsite'])
    assert.equal(endpoint('GET', route), undefined, route);
});

test('asset mining resolves static axios instance bases and suppresses uncertain destinations', () => {
  const script = [
    'const api=axios.create({baseURL:"/tenant/one"});',
    'api.get("jump?next=/safe");',
    'api.request({url:"search?q=widgets",method:"GET",params:{page:1}});',
    'api.post("records", {ownerId:"u-1"});',
    'api.get("records/"+recordId);',
    `const same=axios.create({baseURL:"${ORIGIN}/api/v2/"}); same.get("/status");`,
    `const ALIAS_BASE="${ORIGIN}/api/v3"; const aliased=axios.create({baseURL:ALIAS_BASE}); aliased.get("info");`,
    'const remote=axios.create({baseURL:"https://elsewhere.example/api"}); remote.get("/foreign");',
    'const dynamic=axios.create({baseURL:runtimeBase}); dynamic.get("/unknown");',
    'api.get("override", {baseURL:"/different"});',
    'api.get("override2", {"baseURL":"/different"});',
  ].join('\n');
  const found = extractFromScript(script, {url: `${ORIGIN}/app.js`, origin: ORIGIN});
  const endpoint = (method, route) => found.endpoints.find(item => item.method === method && item.path === route);
  assert.deepEqual(endpoint('GET', '/tenant/one/jump')?.params, ['next']);
  assert.deepEqual(endpoint('GET', '/tenant/one/search')?.params, ['q', 'page']);
  assert.equal(endpoint('GET', '/tenant/one/search')?.kind, 'config-call');
  assert.deepEqual(endpoint('POST', '/tenant/one/records')?.params, ['ownerId']);
  assert.equal(endpoint('GET', '/tenant/one/records/{id}')?.kind, 'callsite');
  assert.equal(endpoint('GET', '/api/v2/status')?.kind, 'callsite');
  assert.equal(endpoint('GET', '/api/v3/info')?.kind, 'callsite');
  for (const route of ['/foreign', '/api/foreign', '/unknown', '/tenant/one/unknown',
    '/tenant/one/override', '/different/override', '/tenant/one/override2', '/different/override2'])
    assert.equal(found.endpoints.some(item => item.path === route), false, route);
});

test('asset extraction retains bounded literal query values but never credential values', () => {
  const value = 'sk_live_12345678901234567890';
  const compound = 'shortsecret';
  const source = `fetch('/api/records?scope=global&token=${value}');\n` +
    `fetch('/api/records?scope=mine&view=private&source.file=guide.txt&auth.token=${compound}');`;
  const found = extractFromScript(source, {url: `${ORIGIN}/app.js`, origin: ORIGIN});
  const endpoint = found.endpoints.find(item => item.path === '/api/records' && item.method === 'GET');
  assert.deepEqual(endpoint.examples.scope, ['global', 'mine']);
  assert.deepEqual(endpoint.examples.view, ['private']);
  assert.deepEqual(endpoint.examples['source.file'], ['guide.txt']);
  assert.equal(endpoint.examples.token, undefined);
  assert.equal(endpoint.examples['auth.token'], undefined);
  assert.ok(!JSON.stringify(found).includes(value));
  assert.ok(!JSON.stringify(found).includes(compound));
});

test('extractFromScript reports hosts, masked secrets, libraries, environment leakage, the source map and comments', () => {
  const result = extractFromScript(BUNDLE, {url: `${ORIGIN}/static/bundle.js`, origin: ORIGIN});
  const host = name => result.hosts.find(item => item.host === name);
  assert.deepEqual(host('live.example.test'), {host: 'live.example.test', kind: 'ws'});
  assert.deepEqual(host('acme-uploads.s3.us-east-1.amazonaws.com'), {host: 'acme-uploads.s3.us-east-1.amazonaws.com', kind: 'bucket', bucket: 'acme-uploads'});
  assert.deepEqual(host('storage.googleapis.com'), {host: 'storage.googleapis.com', kind: 'bucket', bucket: 'acme-assets'});
  for (const name of ['metrics.corp.example.internal', '10.0.12.7', 'vault.ops.example.local']) assert.equal(host(name)?.kind, 'internal', name);
  for (const name of ['acme-prod.firebaseio.com', 'acme-prod.firebaseapp.com']) assert.equal(host(name)?.kind, 'firebase', name);
  for (const name of ['acme-auth.auth0.com', 'o123.ingest.sentry.io']) assert.equal(host(name)?.kind, 'service', name);
  for (const name of ['cdn.example.test', 'git.example.test', 'staging-api.example.test']) assert.equal(host(name)?.kind, 'url', name);
  for (const name of ['localhost', '127.0.0.1', 'www.w3.org', 'deploy']) assert.equal(host(name), undefined, name);

  assert.deepEqual(result.secrets.map(secret => secret.name).sort(), ['aws-access-key', 'basic-auth-url', 'generic', 'generic', 'jwt', 'mapbox-public-token', 'stripe-publishable-key']);
  const secret = name => result.secrets.find(item => item.name === name);
  assert.deepEqual([secret('aws-access-key').masked, secret('aws-access-key').public, secret('aws-access-key').confidence], ['AKIA…(20)', false, 'high']);
  assert.equal(secret('stripe-publishable-key').public, true);
  assert.equal(secret('mapbox-public-token').public, true);
  assert.deepEqual(secret('jwt').claims, {alg: 'HS256', iss: 'https://auth.example.test', aud: 'bundle-test', exp: 1900000000});
  const codeLine = BUNDLE.split('\n')[lineOf(BUNDLE, 'atob(') - 1];
  assert.deepEqual(result.secrets.filter(item => item.name === 'generic').map(item => item.column).sort((a, b) => a - b),
    [columnOf(codeLine, '"eyJhcGlC'), columnOf(codeLine, 'shh-this')].sort((a, b) => a - b), 'the decoded config secret points at its base64 literal');
  assertNoRawValues(result, BUNDLE_SECRETS);

  assert.deepEqual(result.libraries.map(lib => `${lib.name}@${lib.version}`).sort(), ['axios@0.21.1', 'jquery@1.12.4', 'lodash@4.17.15', 'react@17.0.2']);
  assert.equal(result.libraries.find(lib => lib.name === 'jquery').line, 1);
  const env = kind => result.env.filter(item => item.kind === kind).map(item => item.value);
  assert.deepEqual(env('environment').sort(), ['localhost:3000', 'staging-api.example.test']);
  assert.deepEqual(env('flag').sort(), ['debugMode', 'enableBeta', 'isAdmin']);
  for (const path of ['/admin', '/admin/users/{id}', '/impersonate/{id}', '/internal/debug/flags', '/api/admin/users']) assert.ok(env('hidden-route').includes(path), path);
  assert.deepEqual(env('debug'), ['console.log("user session",e.user)']);
  assert.ok(result.env.every(item => Number.isInteger(item.line) && item.line > 0));
  assert.equal(result.sourceMapUrl, `${ORIGIN}/static/bundle.js.map`);
  assert.deepEqual(result.comments, [{text: 'TODO(OPS-1234): remove legacy /api/v0/export before Q3, ask alice@example.test', line: 8}]);
});

test('extractFromHtml returns absolute scripts, preloads, links, inline scripts and inline JSON', () => {
  const html = `<!doctype html><html><head>
<script src="/static/app.js"></script>
<script src=https://cdn.thirdparty.test/w.js async></script>
<link rel="modulepreload" href="/static/vendor.js">
<link rel="preload" as="script" href="static/late.js">
<link rel="stylesheet" href="/static/app.css">
<script id="__NEXT_DATA__" type="application/json">{"page":"/dashboard","props":{"apiUrl":"/api/v1/session"}}</script>
<script type="application/ld+json">{"@context":"https://schema.org"}</script>
<script>window.__INITIAL_STATE__={"user":null,"links":["/api/announcements"]};fetch("/api/inline/ping").then(function(){})</script>
<script type="text/template"><div>{{name}}</div></script>
</head><body><a href="/pricing#top">Pricing</a><a href="mailto:a@b.test">Mail</a><a href="javascript:void(0)">X</a><a href='../docs?a=1&amp;b=2'>Docs</a></body></html>`;
  const out = extractFromHtml(html, {url: 'http://127.0.0.1:9/app/index.html'});
  assert.deepEqual(out.scripts, ['http://127.0.0.1:9/static/app.js', 'https://cdn.thirdparty.test/w.js']);
  assert.deepEqual(out.modulepreload, ['http://127.0.0.1:9/static/vendor.js', 'http://127.0.0.1:9/app/static/late.js']);
  assert.deepEqual(out.links, ['http://127.0.0.1:9/static/app.css', 'http://127.0.0.1:9/pricing', 'http://127.0.0.1:9/docs?a=1&b=2']);
  assert.equal(out.inline.length, 1);
  assert.match(out.inline[0], /fetch\("\/api\/inline\/ping"\)/);
  assert.deepEqual(out.json, [{page: '/dashboard', props: {apiUrl: '/api/v1/session'}}, {user: null, links: ['/api/announcements']}]);
});

test('libraryAdvisoryKey maps a detected library to an npm advisory query', () => {
  assert.deepEqual(libraryAdvisoryKey({name: 'jQuery', version: 'v1.12.4', line: 1}), {ecosystem: 'npm', name: 'jquery', version: '1.12.4'});
  assert.deepEqual(libraryAdvisoryKey({name: 'angularjs', version: '1.5.8'}), {ecosystem: 'npm', name: 'angular', version: '1.5.8'});
});

const SOURCE_MAP = JSON.stringify({
  version: 3, file: 'bundle.js', mappings: 'AAAA',
  sources: ['webpack:///./src/api/admin.js', 'webpack:///./node_modules/axios/lib/axios.js'],
  sourcesContent: [
    '// Admin API client\n// TODO(SEC-42): drop /api/internal/export before launch\nexport function adminSettings() {\n  return fetch("/api/admin/settings");\n}\n',
    '/* axios v0.21.1 */\nmodule.exports = {};\n',
  ],
});
const PAGE = `<!doctype html><html><head><title>Acme</title>
<script src="/static/bundle.js"></script>
<script src="https://cdn.thirdparty.test/widget.js"></script>
<script src="/static/blocked.js"></script>
<link rel="modulepreload" href="/static/vendor.js">
<script id="__NEXT_DATA__" type="application/json">{"props":{"apiUrl":"/api/v1/session"}}</script>
<script>window.__INITIAL_STATE__={"links":["/api/announcements"]};fetch("/api/inline/ping")</script>
</head><body><a href="/pricing">Pricing</a></body></html>`;
const SITE = {
  '/': ['text/html; charset=utf-8', PAGE],
  '/static/bundle.js': ['application/javascript', BUNDLE],
  '/static/bundle.js.map': ['application/json', SOURCE_MAP],
  '/static/vendor.js': ['application/javascript', '/*! lodash v4.17.21 */\nfetch("/api/vendor/ping");\n'],
  '/static/chunk-1.js': ['application/javascript', '(self.webpackChunk=self.webpackChunk||[]).push([[1],{7:function(e,t,n){fetch("/api/chunk/one");n.e(2).then(function(){return import("./chunk-2.js")})}}]);\n'],
  '/static/chunk-2.js': ['application/javascript', 'fetch("/api/chunk/two");import("/static/chunk-3.js");\n//# sourceMappingURL=https://maps.thirdparty.test/chunk-2.js.map\n'],
  '/static/chunk-3.js': ['application/javascript', 'fetch("/api/chunk/three");\n'],
};

// Loopback site: known paths from SITE, anything else answers a catch-all 200 HTML page.
async function serveSite(t) {
  const hits = [];
  const server = http.createServer((req, res) => {
    hits.push(req.url);
    const [type, body] = SITE[req.url] ?? ['text/html', '<!doctype html><title>Acme</title><p>Not found, but 200.</p>'];
    res.writeHead(200, {'content-type': type, 'cache-control': 'no-store'});
    res.end(body);
  });
  const listenPort = await port();
  await new Promise(resolve => server.listen(listenPort, '127.0.0.1', resolve));
  t.after(() => new Promise(resolve => server.close(resolve)));
  return {origin: `http://127.0.0.1:${listenPort}`, hits};
}

// A requester following the T1 contract: refused/blocked results instead of throws, an evidence ID per call.
function fakeRequester({refused = [], blocked = []} = {}) {
  const calls = [];
  const requester = async options => {
    calls.push(options);
    const evidenceId = `ev-${String(calls.length).padStart(4, '0')}`;
    if (refused.some(suffix => options.url.endsWith(suffix))) return {refused: true, reason: 'never', evidenceId};
    if (blocked.some(suffix => options.url.endsWith(suffix))) return {blocked: true, reason: 'Request failed: timeout', evidenceId};
    const response = await safeRequest(options.url, {allowLocal: true, headers: options.headers, maxBytes: options.maxBytes});
    return {status: response.status, type: response.headers['content-type'], bytes: Buffer.byteLength(response.body), hash: sha256(response.body),
      body: response.body, headers: {'content-type': response.headers['content-type']}, ms: 1, evidenceId};
  };
  return {requester, calls};
}
const pathsOf = calls => calls.map(call => new URL(call.url).pathname);

test('independent public scripts download concurrently without losing route evidence', async () => {
  const origin = 'http://127.0.0.1:43199';
  let releaseSlow;
  const slowPending = new Promise(resolve => {releaseSlow = resolve;});
  let slowDone = false, fastBeforeSlow = false;
  const requested = [];
  const requester = async ({url}) => {
    const path = new URL(url).pathname;
    requested.push(path);
    if (path === '/slow.js') {
      await Promise.race([slowPending,
        new Promise(resolve => setTimeout(resolve, 350))]);
      slowDone = true;
    } else if (path === '/fast.js') {
      fastBeforeSlow = !slowDone;
      releaseSlow();
    }
    const body = path === '/' ?
      '<script src="/slow.js"></script><script src="/fast.js"></script>' :
      path === '/slow.js' ? 'fetch("/api/from-slow")' :
      path === '/fast.js' ? 'fetch("/api/from-fast")' : '';
    return {status: body ? 200 : 404, body,
      type: path === '/' ? 'text/html' : 'application/javascript',
      bytes: Buffer.byteLength(body), hash: sha256(body),
      evidenceId: `ev-${requested.length}`};
  };
  const mined = await mineOrigin(origin, {requester, workers: 2, maxFiles: 4});
  assert.ok(fastBeforeSlow, 'the second script waited for the slow first script');
  assert.ok(mined.endpoints.some(item => item.path === '/api/from-slow'));
  assert.ok(mined.endpoints.some(item => item.path === '/api/from-fast'));
  assert.ok(requested.length <= 5, 'the script and map request cap was exceeded');
});

test('concurrent asset requests cannot multiply the shared byte allowance', async () => {
  const origin = 'http://127.0.0.1:43199';
  const page = '<script src="/a.js"></script><script src="/b.js"></script><script src="/c.js"></script>';
  const calls = [];
  const mined = await mineOrigin(origin, {workers: 3, maxFiles: 3,
    maxTotal: 100, requester: async options => {
      const path = new URL(options.url).pathname;
      calls.push({path, maxBytes: options.maxBytes});
      const body = path === '/' ? page : 'x'.repeat(329);
      return {status: 200, body, type: path === '/' ? 'text/html' : 'application/javascript',
        bytes: Buffer.byteLength(body), hash: sha256(body),
        evidenceId: `ev-${calls.length}`};
    }});
  assert.ok(mined.stats.bytes <= 100,
    `asset byte budget grew to ${mined.stats.bytes} across concurrent responses`);
  assert.ok(mined.stats.assetByteBudgetCuts > 0,
    'the unbounded fake response must remain visible as a budget cut');
  assert.ok(calls.filter(item => item.path !== '/').every(item =>
    item.maxBytes <= 100 - Buffer.byteLength(page)),
  'each script must receive only its reserved share of the remaining budget');
});

test('a failed asset worker drains its active peer before the miner rejects', async () => {
  const origin = 'http://127.0.0.1:43199';
  let peerFinished = false;
  const requester = async ({url}) => {
    const path = new URL(url).pathname;
    if (path === '/a.js') throw Error('injected asset failure');
    if (path === '/b.js') {
      await new Promise(resolve => setTimeout(resolve, 70));
      peerFinished = true;
    }
    const body = path === '/' ?
      '<script src="/a.js"></script><script src="/b.js"></script>' :
      'fetch("/api/peer")';
    return {status: 200, body, type: path === '/' ? 'text/html' : 'application/javascript',
      bytes: Buffer.byteLength(body), hash: sha256(body), evidenceId: `ev-${path}`};
  };
  await assert.rejects(mineOrigin(origin, {requester, workers: 2}),
    /injected asset failure/);
  assert.ok(peerFinished, 'the miner returned while a peer request was still active');
});

test('mineOrigin mines a page, its same-origin scripts, chunks to the depth limit and an exposed source map', async t => {
  const site = await serveSite(t);
  const {requester, calls} = fakeRequester({blocked: ['/static/blocked.js']});
  const events = [];
  const summary = await mineOrigin(site.origin, {requester, log: event => events.push(event)});

  assert.deepEqual(pathsOf(calls), ['/', '/static/bundle.js', '/static/bundle.js.map', '/static/blocked.js', '/static/vendor.js', '/static/vendor.js.map',
    '/static/chunk-1.js', '/static/chunk-1.js.map', '/static/chunk-2.js', '/static/chunk-2.js.map']);
  assert.ok(calls.every(call => call.identity === 'anonymous' && call.step === 'recon' && call.purpose === 'asset'));
  assert.equal(calls[0].maxBytes, undefined, 'pages keep the requester default body cap');
  assert.match(calls[0].headers.accept, /^text\/html/);
  assert.ok(calls.slice(1).every(call => call.maxBytes === 16 * 1024 * 1024));
  assert.ok(!site.hits.includes('/static/chunk-3.js'), 'depth 3 stops before chunk-3');
  assert.ok(calls.every(call => call.url.startsWith(site.origin)), 'third-party hosts are never requested');

  const file = path => summary.files.find(item => item.url === site.origin + path);
  assert.deepEqual(summary.files.map(item => [new URL(item.url).pathname, item.foundBy]), [
    ['/', 'page'], ['/static/bundle.js', 'page:/'], ['/static/bundle.js.map', 'sourcemap:/static/bundle.js'], ['/static/vendor.js', 'page:/'],
    ['/static/chunk-1.js', 'chunk:/static/bundle.js'], ['/static/chunk-2.js', 'chunk:/static/chunk-1.js']]);
  assert.deepEqual(['/static/bundle.js', '/static/vendor.js', '/static/chunk-1.js', '/static/chunk-2.js'].map(path => file(path).sourceMap), ['exposed', 'absent', 'absent', 'off-origin']);
  assert.deepEqual([file('/static/bundle.js').bytes, file('/static/bundle.js').hash, file('/static/bundle.js').evidenceId], [Buffer.byteLength(BUNDLE), sha256(BUNDLE), 'ev-0002']);
  assert.deepEqual(summary.sourceMaps, [{url: `${site.origin}/static/bundle.js.map`, script: `${site.origin}/static/bundle.js`, sources: JSON.parse(SOURCE_MAP).sources, evidenceId: 'ev-0003'}]);
  assert.deepEqual(file('/static/bundle.js.map').comments, [{text: 'TODO(SEC-42): drop /api/internal/export before launch', line: 2, source: 'webpack:///./src/api/admin.js'}]);

  const endpoint = (method, path) => summary.endpoints.find(item => item.method === method && item.path === path);
  assert.deepEqual(endpoint('GET', '/api/admin/settings').files, [`${site.origin}/static/bundle.js.map`]);
  assert.deepEqual(endpoint('GET', '/api/admin/settings').sources, ['webpack:///./src/api/admin.js']);
  assert.deepEqual(endpoint('GET', '/api/inline/ping').files, [`${site.origin}/`]);
  for (const path of ['/api/chunk/one', '/api/chunk/two', '/api/vendor/ping', '/api/me']) assert.ok(endpoint('GET', path), path);
  for (const path of ['/api/v1/session', '/api/announcements', '/pricing']) assert.ok(endpoint('UNKNOWN', path), path);
  assert.deepEqual(endpoint('POST', '/api/invoices'), {path: '/api/invoices', method: 'POST', params: ['customerId', 'amount'], headers: ['Content-Type', 'Authorization', 'X-Tenant-Id'], files: [`${site.origin}/static/bundle.js`],
    bodyEncoding: 'json', bodyFields: ['customerId', 'amount'], bodyStringFields: []});
  assert.ok(!summary.endpoints.some(item => item.path === '/api/chunk/three'));
  assert.equal(new Set(summary.endpoints.map(item => `${item.method} ${item.path}`)).size, summary.endpoints.length);

  const host = name => summary.hosts.find(item => item.host === name);
  assert.deepEqual(host('cdn.thirdparty.test'), {host: 'cdn.thirdparty.test', kind: 'url', files: [`${site.origin}/`]});
  assert.equal(host('maps.thirdparty.test').kind, 'url');
  const aws = summary.secrets.filter(item => item.name === 'aws-access-key');
  assert.deepEqual(aws.map(item => [item.masked, item.url, item.files]), [['AKIA…(20)', `${site.origin}/static/bundle.js`, [`${site.origin}/static/bundle.js`]]]);
  assert.equal(summary.secrets.find(item => item.name === 'stripe-publishable-key').public, true);
  const library = key => summary.libraries.find(item => `${item.name}@${item.version}` === key);
  assert.deepEqual(library('axios@0.21.1').files, [`${site.origin}/static/bundle.js`, `${site.origin}/static/bundle.js.map`]);
  assert.ok(library('lodash@4.17.21') && library('jquery@1.12.4'));
  assert.deepEqual(summary.stats, {files: 6, bytes: summary.stats.bytes, pages: 1,
    pagesCut: 0, sourceMapSourcesCut: 0, sourceMapBudgetCut: 0, routeHintsCut: 0,
    sourceMapAppSourcesSelected: 1, sourceMapAppSourcesCut: 0,
    sourceMapVendorSourcesSelected: 1, sourceMapVendorSourcesCut: 0,
    inferredRoutesCut: 0, inferredClassesCut: 0});
  assert.ok(summary.stats.bytes > BUNDLE.length + SOURCE_MAP.length);
  assertNoRawValues(summary, BUNDLE_SECRETS);
  assert.ok(events.some(event => event.stage === 'assets' && /blocked/.test(event.message) && event.url.endsWith('/static/blocked.js')));
  assert.ok(events.some(event => event.stage === 'assets' && /mined 6 files/.test(event.message)));
});

test('mineOrigin respects maxFiles and depth and returns an empty summary when the page is refused', async t => {
  const site = await serveSite(t);
  const limited = fakeRequester();
  const events = [];
  const summary = await mineOrigin(site.origin, {requester: limited.requester, maxFiles: 1, log: event => events.push(event)});
  assert.deepEqual(pathsOf(limited.calls), ['/', '/static/bundle.js']);
  assert.equal(summary.files.find(item => item.url.endsWith('/static/bundle.js')).sourceMap, 'budget-cut');
  assert.equal(summary.stats.sourceMapBudgetCut, 1);
  assert.ok(events.some(event => event.reason === 'asset-budget' &&
    event.script === '/static/bundle.js'));

  const shallow = fakeRequester();
  await mineOrigin(site.origin, {requester: shallow.requester, depth: 1});
  assert.ok(pathsOf(shallow.calls).includes('/static/vendor.js'));
  assert.ok(!pathsOf(shallow.calls).includes('/static/chunk-1.js'), 'depth 1 fetches page scripts only');

  const refused = fakeRequester({refused: ['/']});
  const empty = await mineOrigin(site.origin, {requester: refused.requester});
  assert.deepEqual(empty, {files: [], endpoints: [], hosts: [], secrets: [], libraries: [], sourceMaps: [],
    stats: {files: 0, bytes: 0, pages: 1, pagesCut: 0, sourceMapSourcesCut: 0,
      sourceMapBudgetCut: 0,
      sourceMapAppSourcesSelected: 0, sourceMapAppSourcesCut: 0,
      sourceMapVendorSourcesSelected: 0, sourceMapVendorSourcesCut: 0,
      routeHintsCut: 0, inferredRoutesCut: 0, inferredClassesCut: 0}});
  assert.equal(refused.calls.length, 1);
  await assert.rejects(mineOrigin(site.origin, {}), /requester/);
});

test('mineOrigin fetches only listed off-origin static scripts, chunks and source maps anonymously', async t => {
  const cdnHits = [];
  const cdn = http.createServer((request, response) => {
    cdnHits.push({path: request.url, authorization: request.headers.authorization, cookie: request.headers.cookie});
    const files = {
      '/static/app.js': ['application/javascript', 'fetch("/api/from-cdn");import("/static/chunk.js");\n//# sourceMappingURL=app.js.map'],
      '/static/chunk.js': ['application/javascript', 'fetch("/api/from-chunk");'],
      '/static/app.js.map': ['application/json', JSON.stringify({version: 3, sources: ['src/api.js'],
        sourcesContent: ['fetch("/api/from-map");'], names: [], mappings: ''})],
    };
    const [type, body] = files[request.url] ?? ['text/plain', 'missing'];
    response.writeHead(files[request.url] ? 200 : 404, {'content-type': type});
    response.end(body);
  });
  await new Promise(resolve => cdn.listen(0, '127.0.0.1', resolve));
  t.after(() => new Promise(resolve => cdn.close(resolve)));
  const cdnOrigin = `http://127.0.0.1:${cdn.address().port}`;
  const app = http.createServer((_request, response) => {
    response.writeHead(200, {'content-type': 'text/html'});
    response.end(`<script src="${cdnOrigin}/static/app.js"></script><script src="http://localhost:${cdn.address().port}/third-party.js"></script>`);
  });
  await new Promise(resolve => app.listen(0, '127.0.0.1', resolve));
  t.after(() => new Promise(resolve => app.close(resolve)));
  const appOrigin = `http://127.0.0.1:${app.address().port}`;
  const baseline = fakeRequester();
  const unapproved = await mineOrigin(appOrigin, {requester: baseline.requester});
  assert.equal(unapproved.endpoints.length, 0);
  assert.ok(baseline.calls.every(call => call.url.startsWith(appOrigin)));
  assert.deepEqual(cdnHits, []);

  const allowed = fakeRequester();
  const summary = await mineOrigin(appOrigin, {requester: allowed.requester, assetHosts: ['127.0.0.1']});
  for (const path of ['/api/from-cdn', '/api/from-chunk', '/api/from-map'])
    assert.ok(summary.endpoints.some(endpoint => endpoint.path === path), path);
  assert.deepEqual(cdnHits.map(hit => hit.path), ['/static/app.js', '/static/app.js.map', '/static/chunk.js', '/static/chunk.js.map']);
  assert.ok(cdnHits.every(hit => !hit.authorization && !hit.cookie));
  assert.ok(allowed.calls.every(call => call.identity === 'anonymous' && call.purpose === 'asset'));
  assert.ok(!allowed.calls.some(call => new URL(call.url).hostname === 'localhost'));
  assert.equal(summary.sourceMaps[0].url, `${cdnOrigin}/static/app.js.map`);
});

test('mineOrigin follows approved HTML links, mines their scripts and records pages cut by budget', async t => {
  const hits = [];
  const server = http.createServer((request, response) => {
    hits.push(request.url);
    const pages = {
      '/': ['text/html', '<a href="/app">App</a><a href="/outside">Outside</a><a href="https://thirdparty.test/app">Third party</a>'],
      '/app': ['text/html', '<a href="/app/deep">Deep</a><script src="/static/late.js"></script>'],
      '/app/deep': ['text/html', '<script>fetch("/api/too-deep")</script>'],
      '/static/late.js': ['application/javascript',
        'fetch("/api/from-linked-page"); client.post("/api/from-linked-post",{message:"hello"})'],
    };
    const [type, body] = pages[request.url] ?? ['text/plain', 'missing'];
    response.writeHead(pages[request.url] ? 200 : 404, {'content-type': type});
    response.end(body);
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  t.after(() => new Promise(resolve => server.close(resolve)));
  const origin = `http://127.0.0.1:${server.address().port}`;
  const {requester, calls} = fakeRequester();
  const summary = await mineOrigin(origin, {requester, crawlPaths: ['/app'], maxPages: 2});
  assert.deepEqual(hits, ['/', '/app', '/static/late.js', '/static/late.js.map']);
  assert.ok(calls.every(call => call.identity === 'anonymous' && call.purpose === 'asset'));
  assert.ok(summary.endpoints.some(endpoint => endpoint.path === '/api/from-linked-page'));
  assert.deepEqual(summary.endpoints.find(endpoint => endpoint.path === '/api/from-linked-post')?.bodyFields,
    ['message'], 'the fetched bundle contract reaches the aggregate inventory');
  assert.ok(!summary.endpoints.some(endpoint => endpoint.path === '/api/too-deep'));
  assert.deepEqual(summary.stats, {files: 3, bytes: summary.stats.bytes, pages: 2,
    pagesCut: 1, sourceMapSourcesCut: 0, sourceMapBudgetCut: 0, routeHintsCut: 0,
    sourceMapAppSourcesSelected: 0, sourceMapAppSourcesCut: 0,
    sourceMapVendorSourcesSelected: 0, sourceMapVendorSourcesCut: 0,
    inferredRoutesCut: 0, inferredClassesCut: 0});
});

test('source-map mining inspects application originals and redacts sensitive source names', async () => {
  const origin = 'http://127.0.0.1:9123';
  const secret = 'sk_live_12345678901234567890';
  const sources = Array.from({length: 202}, (_, index) => index === 0 ?
    'src/start.js?token=private' : index === 1 ? `src/${secret}.js` : `src/route-${index}.js`);
  const map = JSON.stringify({version: 3, mappings: 'AAAA', sources,
    sourcesContent: sources.map((_, index) => `fetch('/api/map-${index}')`)});
  const pages = {'/': ['text/html', '<script src="/app.js"></script>'],
    '/app.js': ['application/javascript', '//# sourceMappingURL=/app.js.map'],
    '/app.js.map': ['application/json', map]};
  const requester = async ({url}) => {
    const [type, body] = pages[new URL(url).pathname] ?? ['text/plain', 'missing'];
    return {status: body === 'missing' ? 404 : 200, type, body, evidenceId: 'ev-map'};
  };
  const summary = await mineOrigin(origin, {requester});
  const file = summary.files.find(item => item.url === `${origin}/app.js.map`);
  assert.equal(file.sourcesCut, 0);
  assert.equal(summary.stats.sourceMapSourcesCut, 0);
  assert.deepEqual(file.sources.slice(0, 2), ['src/start.js', '[redacted]']);
  assert.ok(summary.endpoints.some(item => item.path === '/api/map-199'));
  assert.ok(summary.endpoints.some(item => item.path === '/api/map-200'));
  assert.ok(!JSON.stringify(summary).includes(secret));
  assert.ok(!JSON.stringify(summary).includes('token=private'));
});

test('source-map mining reaches an app source after more than 200 vendor entries', async () => {
  const origin = 'http://127.0.0.1:9124';
  const vendorCount = 205;
  const sources = Array.from({length: vendorCount}, (_, index) =>
    `webpack:///./node_modules/vendor-${index}/index.js`);
  sources.push('webpack:///./src/api/late-client.js');
  const map = JSON.stringify({version: 3, mappings: 'AAAA', sources,
    sourcesContent: sources.map((_, index) => index === vendorCount ?
      'export const late = () => fetch("/api/late-from-map");' :
      index === vendorCount - 1 ?
      'export const tail = () => fetch("/api/vendor-tail"); const apiKey="sk_live_AB12CD34EF56GH78IJ90KL12MN34";' :
      `export const vendor${index} = true;`)});
  const pages = {'/': ['text/html', '<script src="/app.js"></script>'],
    '/app.js': ['application/javascript', '//# sourceMappingURL=/app.js.map'],
    '/app.js.map': ['application/json', map]};
  const requester = async ({url}) => {
    const [type, body] = pages[new URL(url).pathname] ?? ['text/plain', 'missing'];
    return {status: body === 'missing' ? 404 : 200, type, body, evidenceId: 'ev-map'};
  };
  const summary = await mineOrigin(origin, {requester});
  const file = summary.files.find(item => item.url === `${origin}/app.js.map`);
  assert.ok(summary.endpoints.some(item => item.path === '/api/late-from-map' &&
    item.sources?.includes('webpack:///./src/api/late-client.js')));
  assert.ok(summary.endpoints.some(item => item.path === '/api/vendor-tail'));
  assert.ok(summary.secrets.some(item => item.name === 'stripe-secret-key'));
  assert.ok(!JSON.stringify(summary).includes('sk_live_AB12CD34EF56GH78IJ90KL12MN34'));
  assert.equal(file.sources[0], 'webpack:///./src/api/late-client.js');
  assert.equal(file.sources.length, 206);
  assert.equal(file.sourcesCut, 0);
  assert.deepEqual(file.sourceSelection, {appLikelySelected: 1, appLikelyCut: 0,
    appLikelyUnavailable: 0, vendorSelected: 205, vendorCut: 0,
    vendorUnavailable: 0});
  assert.equal(summary.stats.sourceMapAppSourcesSelected, 1);
  assert.equal(summary.stats.sourceMapVendorSourcesCut, 0);
});

test('source-map mining inspects app entries beyond the old 200-entry limit', async () => {
  const origin = 'http://127.0.0.1:9125';
  const appCount = 240;
  const sources = Array.from({length: appCount}, (_, index) =>
    `webpack:///./src/client/module-${index}.js`);
  sources.push('webpack:///./node_modules/vendor/index.js');
  sources.push('webpack:///./src/client/unavailable.js');
  const map = JSON.stringify({version: 3, mappings: 'AAAA', sources,
    sourcesContent: sources.map((_, index) => index === sources.length - 1 ? null :
      index === appCount - 1 ?
      'export const late = () => fetch("/api/late-application-source");' :
      `export const module${index} = true;`)});
  const pages = {'/': ['text/html', '<script src="/app.js"></script>'],
    '/app.js': ['application/javascript', '//# sourceMappingURL=/app.js.map'],
    '/app.js.map': ['application/json', map]};
  const requester = async ({url}) => {
    const [type, body] = pages[new URL(url).pathname] ?? ['text/plain', 'missing'];
    return {status: body === 'missing' ? 404 : 200, type, body, evidenceId: 'ev-map-tail'};
  };
  const summary = await mineOrigin(origin, {requester});
  const file = summary.files.find(item => item.url === `${origin}/app.js.map`);
  assert.ok(summary.endpoints.some(item => item.path === '/api/late-application-source'));
  assert.equal(file.sourceSelection.appLikelySelected, appCount);
  assert.equal(file.sourceSelection.appLikelyCut, 0);
  assert.equal(file.sourceSelection.appLikelyUnavailable, 1);
  assert.equal(file.sourceSelection.vendorCut, 0);
  assert.equal(file.sourcesCut, 1);
});

test('a 1933-name map still mines and sends its last embedded app source to Muse', async () => {
  const origin = 'http://127.0.0.1:9130';
  const absent = Array.from({length: 1933}, (_, index) =>
    `webpack:///./node_modules/dependency-${index}/index.js`);
  const map = JSON.stringify({version: 3, mappings: 'AAAA',
    sources: [...absent, 'webpack:///./src/late-client.js'],
    sourcesContent: [...absent.map(() => null),
      'export const late = () => fetch("/api/late-map-original");']});
  const pages = {'/': ['text/html', '<script src="/app.js"></script>'],
    '/app.js': ['application/javascript',
      `${Array.from({length: 50}, (_, index) => `fetch("/api/early-${index}");`).join('')}\n//# sourceMappingURL=/app.js.map`],
    '/app.js.map': ['application/json', map]};
  const summary = await mineOrigin(origin, {requester: async ({url}) => {
    const [type, body] = pages[new URL(url).pathname] ?? ['text/plain', 'missing'];
    return {status: body === 'missing' ? 404 : 200, type, body, evidenceId: 'ev-map-late'};
  }});
  assert.ok(summary.endpoints.some(item => item.path === '/api/late-map-original'));
  assert.equal(summary.stats.sourceMapSourcesCut, 1933);
  assert.equal(summary.stats.sourceMapOriginalsUnresolvable, 1933,
    'virtual source names without embedded text are unavailable, not a scanner selection cut');
  assert.equal(summary.stats.sourceMapVendorSourcesUnavailable, 1933);
  assert.equal(summary.stats.sourceMapAppSourcesSelected, 1);
  let sentLate = false;
  const interpreted = await interpretAssets([summary], {model: 'fixture', maxPages: 1,
    infer: async (_model, messages) => {
      const context = JSON.parse(messages.at(-1).content);
      sentLate ||= context.files.some(unit => unit.routes.some(route =>
        route.path === '/api/late-map-original'));
      return {files: context.files.map(unit => ({id: unit.id, role: 'app',
        why: '', authFlow: '', routes: unit.routes.map(route => ({path: route.path,
          method: route.method, purpose: 'client route', parameters: []})), proposals: []}))};
    }});
  assert.equal(sentLate, true);
  assert.ok(interpreted.notes.some(note => note.path === '/api/late-map-original'));
});

test('namespace-only maps without embedded source report unavailable originals, not missed app code', async () => {
  const origin = 'http://127.0.0.1:9131';
  const sources = ['webpack://DocsBundle/./node_modules/ui/index.js',
    'webpack://DocsBundle/./src/core/index.js',
    'webpack://DocsBundle/./src/core/late.js'];
  const map = JSON.stringify({version: 3, mappings: 'AAAA', sources});
  const pages = {'/': ['text/html', '<script src="/docs.js"></script>'],
    '/docs.js': ['application/javascript',
      'fetch("/api/from-generated-script");\n//# sourceMappingURL=/docs.js.map'],
    '/docs.js.map': ['application/json', map]};
  const requests = [];
  const summary = await mineOrigin(origin, {requester: async ({url}) => {
    requests.push(url);
    const [type, body] = pages[new URL(url).pathname] ?? ['text/plain', 'missing'];
    return {status: body === 'missing' ? 404 : 200, type, body,
      evidenceId: 'ev-map-names-only'};
  }});
  assert.ok(summary.endpoints.some(item => item.path === '/api/from-generated-script'));
  assert.deepEqual(requests, [origin + '/', origin + '/docs.js', origin + '/docs.js.map']);
  assert.equal(summary.stats.sourceMapSourcesCut, sources.length);
  assert.equal(summary.stats.sourceMapOriginalsUnresolvable, sources.length);
  assert.equal(summary.stats.sourceMapNamespacedSourcesUnavailable, 2);
  assert.equal(summary.stats.sourceMapVendorSourcesUnavailable, 1);
  assert.equal(summary.stats.sourceMapAppSourcesCut, 0);
  assert.equal(summary.stats.sourceMapAppSourcesSelected, 0);
});

test('source-map mining recovers a later public original but never requests virtual names or HTML fallbacks', async () => {
  const origin = 'http://127.0.0.1:9127';
  const virtual = Array.from({length: 205}, (_, index) =>
    `webpack:///./node_modules/vendor-${index}/index.js`);
  const sources = [...virtual, '/src/late-client.js', '/src/missing-client.js', '/',
    'https://other.example/src/off-origin.js'];
  const map = JSON.stringify({version: 3, mappings: 'AAAA', sourceRoot: '/', sources});
  const pages = {'/': ['text/html', '<script src="/app.js"></script>'],
    '/app.js': ['application/javascript', '//# sourceMappingURL=/app.js.map'],
    '/app.js.map': ['application/json', map],
    '/src/late-client.js': ['application/javascript', 'export const late = () => fetch("/api/recovered-late");'],
    '/src/missing-client.js': ['text/html', '<html>single-page fallback</html>']};
  const requests = [];
  const requester = async ({url}) => {
    const path = new URL(url).pathname;
    requests.push(url);
    const [type, body] = pages[path] ?? ['text/plain', 'missing'];
    return {status: body === 'missing' ? 404 : 200, type, body, evidenceId: 'ev-map-recovered'};
  };
  const summary = await mineOrigin(origin, {requester});
  const file = summary.files.find(item => item.url === `${origin}/app.js.map`);
  assert.ok(summary.endpoints.some(item => item.path === '/api/recovered-late'));
  assert.ok(summary.endpoints.some(item => item.path === '/api/recovered-late' &&
    item.sources?.includes('/src/late-client.js')));
  assert.ok(requests.some(url => url.endsWith('/src/late-client.js')));
  assert.ok(requests.some(url => url.endsWith('/src/missing-client.js')));
  assert.ok(!requests.some(url => url.includes('webpack:') || url.includes('other.example')));
  assert.equal(summary.stats.sourceMapOriginalsAttempted, 3);
  assert.equal(summary.stats.sourceMapOriginalsRecovered, 1);
  assert.equal(file.sourceSelection.appLikelySelected, 1);
  assert.equal(file.sourcesCut, sources.length - 1);
  assert.equal(summary.stats.sourceMapSourcesCut, sources.length - 1);
});

test('source-map mining recovers a late relative public original beside virtual entries', async () => {
  const origin = 'http://127.0.0.1:9129';
  const virtual = Array.from({length: 205}, (_, index) =>
    `webpack:///./node_modules/vendor-${index}/index.js`);
  const sources = [...virtual, '../src/late-client.js', 'webpack:///./src/virtual.js'];
  const map = JSON.stringify({version: 3, mappings: 'AAAA', sources});
  const pages = {'/': ['text/html', '<script src="/static/app.js"></script>'],
    '/static/app.js': ['application/javascript', '//# sourceMappingURL=app.js.map'],
    '/static/app.js.map': ['application/json', map],
    '/src/late-client.js': ['application/javascript',
      'export const late = () => fetch("/api/from-late-relative-original");']};
  const requests = [];
  const summary = await mineOrigin(origin, {requester: async ({url}) => {
    requests.push(url);
    const [type, body] = pages[new URL(url).pathname] ?? ['text/plain', 'missing'];
    return {status: body === 'missing' ? 404 : 200, type, body,
      evidenceId: 'ev-map-relative'};
  }});
  assert.ok(summary.endpoints.some(item =>
    item.path === '/api/from-late-relative-original' &&
    item.sources?.includes('../src/late-client.js')));
  assert.ok(requests.some(url => url === `${origin}/src/late-client.js`));
  assert.ok(!requests.some(url => url.startsWith('webpack:')));
  assert.equal(summary.stats.sourceMapOriginalsRecovered, 1);
  assert.equal(summary.stats.sourceMapSourcesCut, sources.length - 1);
});

test('source-map original recovery reports an existing asset budget cut', async () => {
  const origin = 'http://127.0.0.1:9128';
  const map = JSON.stringify({version: 3, mappings: 'AAAA', sources: ['/src/late.js']});
  const pages = {'/': ['text/html', '<script src="/app.js"></script>'],
    '/app.js': ['application/javascript', '//# sourceMappingURL=/app.js.map'],
    '/app.js.map': ['application/json', map]};
  const requests = [];
  const summary = await mineOrigin(origin, {maxFiles: 2, requester: async ({url}) => {
    requests.push(url);
    const [type, body] = pages[new URL(url).pathname] ?? ['text/plain', 'missing'];
    return {status: body === 'missing' ? 404 : 200, type, body, evidenceId: 'ev-map-budget'};
  }});
  assert.ok(!requests.some(url => url.endsWith('/src/late.js')));
  assert.equal(summary.stats.sourceMapOriginalsBudgetCut, 1);
  assert.equal(summary.stats.sourceMapOriginalsRecovered ?? 0, 0);
  assert.equal(summary.stats.sourceMapSourcesCut, 1);
});

test('source-map mining and Muse input retain indirect hints from later application originals', async () => {
  const origin = 'http://127.0.0.1:9126';
  const sources = Array.from({length: 40}, (_, index) =>
    `webpack:///./src/client/module-${index}.js`);
  const map = JSON.stringify({version: 3, mappings: 'AAAA', sources,
    sourcesContent: sources.map((_, index) =>
      `const route = '/api/indirect-${index}'; fetch(route);`)});
  const pages = {'/': ['text/html', '<script src="/app.js"></script>'],
    '/app.js': ['application/javascript', '//# sourceMappingURL=/app.js.map'],
    '/app.js.map': ['application/json', map]};
  const requester = async ({url}) => {
    const [type, body] = pages[new URL(url).pathname] ?? ['text/plain', 'missing'];
    return {status: body === 'missing' ? 404 : 200, type, body, evidenceId: 'ev-map-hints'};
  };
  const summary = await mineOrigin(origin, {requester});
  const file = summary.files.find(item => item.url === `${origin}/app.js.map`);
  assert.equal(file.routeHints.length, 40);
  assert.equal(file.routeHintsCut, 0);
  assert.equal(file.routeHints[39].source, sources[39]);
  assert.ok(file.routeHints[39].literals.includes('/api/indirect-39'));
  const modelPages = [];
  const interpreted = await interpretAssets([summary], {model: 'fixture', maxPages: 3,
    infer: async (_model, messages) => {
      const context = JSON.parse(messages.at(-1).content);
      modelPages.push(context);
      return {files: context.files.map(unit => ({id: unit.id, role: 'app',
        why: '', authFlow: '', routes: [], proposals: unit.hints.some(hint =>
          hint.literals.includes('/api/indirect-39')) ?
          [{hintId: unit.hints.find(hint => hint.literals.includes('/api/indirect-39')).id,
            path: '/api/indirect-39'}] : []}))};
    }});
  assert.equal(interpreted.coverage.hintsAvailable, 40);
  assert.equal(interpreted.coverage.pagesAvailable, 3);
  assert.equal(interpreted.coverage.hintsSent, 40);
  assert.ok(modelPages.flatMap(page => page.files).flatMap(unit => unit.hints)
    .some(hint => hint.literals.includes('/api/indirect-39')));
  assert.ok(interpreted.proposals.some(item => item.path === '/api/indirect-39'));
});
