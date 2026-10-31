import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import http from 'node:http';
import path from 'node:path';
import {temp, cli} from './helpers.mjs';
import {reviewSource} from '../src/blackbox/source.mjs';

test('source-assisted review extracts routes and sends only redacted excerpts to Muse', async t => {
  const root = temp();
  t.after(() => fs.rmSync(root, {recursive: true, force: true}));
  const secret = 'sk_live_abcdefghijklmnopqrstuvwxyz012345';
  fs.writeFileSync(path.join(root, 'app.js'), `app.get('/api/accounts/:id', (req, res) => {\n  const limit = req.query.limit;\n  const key = '${secret}';\n  const privatePath = '/api/lookup?auth.token=shortsecret';\n  return res.json({id:req.params.id, limit});\n});\napp.get('/api/unlock?code=shortsecret', (_req, res) => res.end());\napp.get('/api/${secret}', (_req, res) => res.end());\n`);
  fs.writeFileSync(path.join(root, '.env'), `TOKEN=${secret}\n`);
  const prompts = [];
  const infer = async (_model, messages) => {
    prompts.push(JSON.stringify(messages));
    return {paths: ['/api/accounts/a-1'], notes: [{path: '/api/accounts/:id', purpose: `Read account ${secret}`,
      methods: ['GET'], parameters: ['limit'], why: `Handler uses ${secret}`}]};
  };
  const result = await reviewSource(root, {infer, model: {provider: 'test'}});
  assert.ok(result.endpoints.some(item => item.path === '/api/accounts/:id' && item.method === 'GET'));
  assert.ok(result.endpoints.some(item => item.params.includes('limit')));
  assert.ok(result.endpoints.some(item => item.path === '/api/unlock?code='));
  assert.ok(!result.endpoints.some(item => item.path.includes(secret)));
  assert.equal(result.files.length, 1, '.env is never read as source');
  assert.deepEqual(result.secretLeads.map(({file, line, name, confidence}) =>
    ({file, line, name, confidence})),
    [{file: 'app.js', line: 3, name: 'stripe-secret-key', confidence: 'high'}]);
  assert.equal(result.modelCalls, 1);
  assert.ok(!prompts[0].includes(secret));
  assert.ok(!prompts[0].includes('shortsecret'));
  assert.ok(!JSON.stringify(result).includes(secret));
  assert.ok(!JSON.stringify(result).includes('shortsecret'));
});

test('source credential leads are bounded and contain neither values nor reversible fingerprints', async t => {
  const root = temp();
  t.after(() => fs.rmSync(root, {recursive: true, force: true}));
  const values = Array.from({length: 10}, (_, index) => `sk_live_abcdefghi${index}jklmnop`);
  fs.writeFileSync(path.join(root, 'config.py'), values.map(value => `TOKEN = '${value}'`).join('\n'));
  const result = await reviewSource(root);
  assert.equal(result.secretLeads.length, 8);
  assert.equal(result.stats.secretLeadsCut, 2);
  assert.ok(result.secretLeads.every(lead =>
    Object.keys(lead).sort().join(',') === 'column,confidence,file,line,name'));
  for (const value of values) assert.ok(!JSON.stringify(result).includes(value));
});

test('source routes retain a credential-shaped field when its literal value looks secret', async t => {
  const root = temp();
  t.after(() => fs.rmSync(root, {recursive: true, force: true}));
  const value = 'sk_live_abcdefghijklmnopqrstuvwxyz012345';
  fs.writeFileSync(path.join(root, 'app.js'),
    `app.get('/api/unlock?code=${value}', (_req, res) => res.end());\n`);
  const result = await reviewSource(root);
  assert.ok(result.endpoints.some(item => item.path === '/api/unlock?code='));
  assert.ok(!JSON.stringify(result).includes(value));
});

test('source-assisted review inspects routes in files larger than the old 128 KiB cap', async t => {
  const root = temp();
  t.after(() => fs.rmSync(root, {recursive: true, force: true}));
  fs.writeFileSync(path.join(root, 'large-app.js'),
    `${'// filler line\n'.repeat(11000)}app.get('/api/large-source', (req, res) => res.json({ok:true}));\n`);
  const result = await reviewSource(root);
  assert.ok(result.endpoints.some(item => item.path === '/api/large-source'));
  assert.equal(result.stats.skipped, 0);
});

test('blackbox CLI saves local source credential leads without claiming a public finding', async t => {
  const root = temp(), source = path.join(root, 'source');
  t.after(() => fs.rmSync(root, {recursive: true, force: true}));
  fs.mkdirSync(source);
  const value = 'sk_live_abcdefghijklmnopqrstuvwxyz012345';
  fs.writeFileSync(path.join(source, 'config.js'), `export const billingKey = '${value}';\n`);
  const server = http.createServer((_request, response) => {
    response.writeHead(200, {'content-type': 'text/html'});
    response.end('<!doctype html><title>source fixture</title>');
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  t.after(() => new Promise(resolve => server.close(resolve)));
  const origin = `http://127.0.0.1:${server.address().port}`;
  const scope = await cli(root, 'blackbox', 'scope', origin);
  assert.equal(scope.code, 0);
  const audit = await cli(root, 'blackbox', origin, '--accept-local', '--no-model', '--offline',
    '--source', source);
  assert.equal(audit.data.kind, 'blackbox-audit', JSON.stringify(audit.data));
  const report = JSON.parse(fs.readFileSync(path.join(audit.data.runDir, 'report.json'), 'utf8'));
  const sourceArtifact = fs.readFileSync(path.join(audit.data.runDir, 'source.json'), 'utf8');
  const markdown = fs.readFileSync(audit.data.reportPath, 'utf8');
  assert.equal(report.surface.application.sourceReview.secretLeads.length, 1);
  assert.equal(report.surface.application.sourceReview.secretLeads[0].name, 'stripe-secret-key');
  assert.equal(report.coverage.requestedClasses.find(row => row.name === 'Hardcoded Credentials').status,
    'partial');
  assert.ok(markdown.includes('Local source credential leads: 1'));
  assert.ok(!audit.data.findings.some(finding => finding.kind === 'public-api-credential'));
  for (const artifact of [sourceArtifact, JSON.stringify(report), markdown])
    assert.ok(!artifact.includes(value), 'raw credential must not be saved');
});

test('source-assisted review resolves static Axios bases against the audited origin', async t => {
  const root = temp();
  t.after(() => fs.rmSync(root, {recursive: true, force: true}));
  fs.writeFileSync(path.join(root, 'client.js'),
    'const API_ROOT="https://app.example.test/tenant/api"; ' +
    'const client=axios.create({baseURL:API_ROOT}); client.get("jump?next=/safe");');
  const own = await reviewSource(root, {origin: 'https://app.example.test'});
  assert.ok(own.endpoints.some(item => item.method === 'GET' && item.path === '/tenant/api/jump' &&
    item.params.includes('next')));
  const other = await reviewSource(root, {origin: 'https://other.example.test'});
  assert.ok(!other.endpoints.some(item => item.path === '/tenant/api/jump'));
});

test('source-assisted review recognizes literal Laravel, Spring, ASP.NET and FastAPI routes', async t => {
  const root = temp();
  t.after(() => fs.rmSync(root, {recursive: true, force: true}));
  fs.writeFileSync(path.join(root, 'api.php'),
    "Route::get('/api/php-first', function () { return 'ok'; });\n" +
    "Route::get('/api/php-jump', function ($request) { return redirect($request->query('next')); });\n" +
    "Route::post('/api/php-write', function ($request) { return $request->input('body'); });\n");
  fs.writeFileSync(path.join(root, 'Api.java'),
    '@GetMapping(path = "/api/java-jump")\n' +
    'public String jump(@RequestParam("returnUrl") String dest) { return dest; }\n' +
    '@DeleteMapping("/api/java-delete")\npublic void delete() {}\n');
  fs.writeFileSync(path.join(root, 'Program.cs'),
    'app.MapGet("/api/csharp-jump", (HttpRequest request) => request.Query["next"]);\n' +
    'app.MapPost("/api/csharp-write", () => "ok");\n' +
    'customEndpoints.MapGet("/api/csharp-group", () => "ok");\n');
  fs.writeFileSync(path.join(root, 'api.py'),
    '@api_router.get("/api/python-jump")\n' +
    'def jump(request): return request.query_params.get("next")\n');
  const result = await reviewSource(root);
  const route = path => result.endpoints.find(item => item.path === path);
  assert.equal(route('/api/php-first').method, 'GET');
  assert.deepEqual(route('/api/php-first').params, [], 'query names from the next handler must not bleed backward');
  assert.deepEqual(route('/api/php-jump').params, ['next']);
  assert.equal(route('/api/php-write').method, 'POST');
  assert.deepEqual(route('/api/php-write').params, ['body']);
  assert.equal(route('/api/java-jump').method, 'GET');
  assert.deepEqual(route('/api/java-jump').params, ['returnUrl']);
  assert.equal(route('/api/java-delete').method, 'DELETE');
  assert.equal(route('/api/csharp-jump').method, 'GET');
  assert.deepEqual(route('/api/csharp-jump').params, ['next']);
  assert.equal(route('/api/csharp-write').method, 'POST');
  assert.equal(route('/api/csharp-group').method, 'GET');
  assert.equal(route('/api/python-jump').method, 'GET');
  assert.deepEqual(route('/api/python-jump').params, ['next']);
});

test('source-assisted review composes explicit literal route prefixes without crossing scope boundaries', async t => {
  const root = temp();
  t.after(() => fs.rmSync(root, {recursive: true, force: true}));
  fs.writeFileSync(path.join(root, 'routes.php'),
    "Route::prefix('api')->group(function () {\n" +
    "  Route::prefix('v2')->group(function () {\n" +
    "    Route::get('php-jump', function ($request) { return $request->query('next'); });\n" +
    "  });\n" +
    "  Route::post('/php-write', function () { return 'ok'; });\n" +
    "});\n" +
    "Route::get('/php-outside', function () { return 'ok'; });\n");
  fs.writeFileSync(path.join(root, 'Api.java'),
    '@RestController\n@RequestMapping(path = "/api")\n' +
    'public class Api {\n@GetMapping("java-jump")\n' +
    'public String jump(@RequestParam("next") String next) { return next; }\n}\n' +
    '@RestController\n@RequestMapping("/other")\n' +
    'public class Other {\n@GetMapping("/java-outside")\npublic String outside() { return "ok"; }\n}\n');
  fs.writeFileSync(path.join(root, 'Program.cs'),
    'var api = app.MapGroup("/api");\n' +
    'var v2 = api.MapGroup("/v2");\n' +
    'v2.MapGet("csharp-jump", (HttpRequest request) => request.Query["next"]);\n' +
    'api.MapPost("/csharp-write", () => "ok");\n' +
    'app.MapGet("/csharp-outside", () => "ok");\n');
  fs.writeFileSync(path.join(root, 'api.py'),
    'router = APIRouter(\n    tags=["api"],\n    prefix="/api",\n)\n' +
    '@router.get("/python-jump")\n' +
    'def jump(request): return request.query_params.get("next")\n' +
    '@app.get("/python-outside")\ndef outside(): return "ok"\n');
  const result = await reviewSource(root);
  const route = value => result.endpoints.find(item => item.path === value);
  assert.deepEqual(route('/api/v2/php-jump').params, ['next']);
  assert.equal(route('/api/php-write').method, 'POST');
  assert.equal(route('/php-outside').method, 'GET');
  assert.deepEqual(route('/api/java-jump').params, ['next']);
  assert.equal(route('/other/java-outside').method, 'GET');
  assert.deepEqual(route('/api/v2/csharp-jump').params, ['next']);
  assert.equal(route('/api/csharp-write').method, 'POST');
  assert.equal(route('/csharp-outside').method, 'GET');
  assert.deepEqual(route('/api/python-jump').params, ['next']);
  assert.equal(route('/python-outside').method, 'GET');
  for (const wrong of ['/php-jump', '/java-jump', '/csharp-jump', '/python-jump'])
    assert.ok(!route(wrong), `unprefixed ${wrong} is not a live route`);
});

test('source-assisted review composes imported FastAPI routers with multiple explicit include prefixes', async t => {
  const root = temp();
  t.after(() => fs.rmSync(root, {recursive: true, force: true}));
  fs.mkdirSync(path.join(root, 'app', 'routers'), {recursive: true});
  fs.writeFileSync(path.join(root, 'app', 'main.py'),
    'from .routers import items\n' +
    'from app.routers.admin import router as admin_router\n' +
    'app = FastAPI()\n' +
    'app.include_router(items.router, prefix="/api/v1")\n' +
    'app.include_router(items.router, prefix="/api/latest")\n' +
    'app.include_router(admin_router, prefix="/admin")\n' +
    '# app.include_router(items.router, prefix="/ghost")\n' +
    'app.include_router(items.router, prefix=dynamic_prefix)\n' +
    'app.include_router(missing.router, prefix="/unresolved")\n');
  fs.writeFileSync(path.join(root, 'app', 'routers', 'items.py'),
    'router = APIRouter(prefix="/items")\n' +
    '@router.get("/jump")\n' +
    'def jump(request): return request.query_params.get("next")\n' +
    '@router.post("/delete")\n' +
    'def delete(): return "ok"\n');
  fs.writeFileSync(path.join(root, 'app', 'routers', 'admin.py'),
    'router = APIRouter()\n' +
    '@router.get("/status")\n' +
    'def status(): return "ok"\n');
  const modelPaths = [];
  const result = await reviewSource(root, {model: {provider: 'test'}, infer: async (_model, messages) => {
    modelPaths.push(...JSON.parse(messages[1].content).snippets.map(item => item.path));
    return {notes: [], paths: []};
  }});
  const route = value => result.endpoints.find(item => item.path === value);
  assert.deepEqual(route('/api/v1/items/jump').params, ['next']);
  assert.deepEqual(route('/api/latest/items/jump').params, ['next']);
  assert.equal(route('/api/v1/items/delete').method, 'POST');
  assert.equal(route('/api/latest/items/delete').method, 'POST');
  assert.equal(route('/admin/status').method, 'GET');
  for (const wrong of ['/items/jump', '/status', '/ghost/items/jump', '/unresolved/items/jump'])
    assert.ok(!route(wrong), `unregistered ${wrong} is not a live route`);
  assert.ok(modelPaths.includes('/api/v1/items/jump'));
  assert.ok(modelPaths.includes('/api/latest/items/jump'));
  assert.ok(!modelPaths.includes('/items/jump'));
});

test('imported router expansion stays within the route budget and records the cut', async t => {
  const root = temp();
  t.after(() => fs.rmSync(root, {recursive: true, force: true}));
  fs.mkdirSync(path.join(root, 'app', 'routers'), {recursive: true});
  fs.writeFileSync(path.join(root, 'app', 'main.py'),
    'from .routers import items\napp = FastAPI()\n' +
    Array.from({length: 1202}, (_, at) =>
      `app.include_router(items.router, prefix="/v${at}")`).join('\n'));
  fs.writeFileSync(path.join(root, 'app', 'routers', 'items.py'),
    'router = APIRouter()\n@router.get("/jump")\ndef jump(): return "ok"\n');
  const result = await reviewSource(root);
  assert.equal(result.endpoints.length, 1200);
  assert.equal(result.stats.routesCut, 2);
  assert.equal(result.files.find(item => item.path === 'app/routers/items.py').routes, 1202);
  assert.ok(result.endpoints.some(item => item.path === '/v1199/jump'));
  assert.ok(!result.endpoints.some(item => item.path === '/v1200/jump'));
});

test('Muse receives bounded redacted excerpts for source routes with dynamic paths', async t => {
  const root = temp();
  t.after(() => fs.rmSync(root, {recursive: true, force: true}));
  const secret = 'sk_live_abcdefghijklmnopqrstuvwxyz012345';
  fs.writeFileSync(path.join(root, 'routes.php'),
    "$base = '/api';\n" +
    `// token ${secret}\n` +
    "Route::get($base . '/dynamic-jump', function ($request) { return redirect($request->query('next')); });\n" +
    "Route::post($base . '/delete', function () { return 'ok'; });\n");
  const prompts = [];
  const result = await reviewSource(root, {model: {provider: 'test'}, infer: async (_model, messages) => {
    prompts.push(JSON.stringify(messages));
    const snippets = JSON.parse(messages[1].content).snippets;
    assert.ok(snippets.some(item => item.path === null && item.method === 'GET' &&
      item.excerpt.includes("$base = '/api'")));
    assert.ok(snippets.some(item => item.path === null && item.method === 'POST'));
    return {notes: [], paths: ['/api/dynamic-jump?next=/safe',
      'https://off-origin.invalid/', '/api/secret?token=value']};
  }});
  assert.equal(result.stats.unresolvedRoutes, 2);
  assert.equal(result.stats.unresolvedRoutesCut, 0);
  assert.equal(result.endpoints.length, 0);
  assert.deepEqual(result.proposals, ['/api/dynamic-jump?next=/safe', '/api/secret?token=']);
  assert.equal(result.modelCoverage.snippetsAvailable, 2);
  assert.equal(result.modelCoverage.snippetsSent, 2);
  assert.ok(!prompts.join('\n').includes(secret));
});

test('source-assisted Muse review reaches late routes through complete bounded pages', async t => {
  const root = temp();
  t.after(() => fs.rmSync(root, {recursive: true, force: true}));
  fs.writeFileSync(path.join(root, 'server.js'), Array.from({length: 19}, (_, index) =>
    `app.get('/api/route-${index}', (req, res) => res.json({next: req.query.next}));`).join('\n'));
  const seen = [];
  const infer = async (_model, messages) => {
    assert.ok(Buffer.byteLength(messages[1].content) <= 20000);
    const page = JSON.parse(messages[1].content);
    seen.push(...page.snippets.map(item => item.path));
    const late = page.snippets.find(item => item.path === '/api/route-18');
    return {notes: late ? [{path: late.path, purpose: 'Redirect route', methods: ['GET', 'DELETE'],
      parameters: ['next', 'invented'], why: 'The next query parameter reaches a handler.'},
    {path: '/api/invented', purpose: 'Invented', methods: ['GET'], parameters: [], why: 'Invented'}] : [],
    paths: late ? ['/api/route-18', 'https://off-origin.invalid/'] : []};
  };
  const result = await reviewSource(root, {model: {provider: 'test'}, infer});
  assert.ok(result.modelCalls > 1);
  assert.deepEqual(result.modelCoverage, {pagesAvailable: result.modelCalls, pagesSent: result.modelCalls,
    snippetsAvailable: seen.length, snippetsSent: seen.length});
  assert.ok(seen.includes('/api/route-18'));
  assert.ok(result.notes.some(note => note.path === '/api/route-18'));
  assert.deepEqual(result.notes.find(note => note.path === '/api/route-18').methods, ['GET']);
  assert.deepEqual(result.notes.find(note => note.path === '/api/route-18').parameters, ['next']);
  assert.ok(!result.notes.some(note => note.path === '/api/invented'));
  assert.deepEqual(result.proposals, ['/api/route-18']);
});

test('source-assisted review accounts for file, route and model page limits', async t => {
  const root = temp();
  t.after(() => fs.rmSync(root, {recursive: true, force: true}));
  fs.writeFileSync(path.join(root, 'a.js'), Array.from({length: 1201}, (_, index) =>
    `app.get('/api/route-${index}', (_req, res) => res.end());`).join('\n'));
  fs.writeFileSync(path.join(root, 'b.js'), "app.get('/api/other', (_req, res) => res.end());\n");
  const result = await reviewSource(root, {maxFiles: 1, maxModelPages: 1,
    model: {provider: 'test'}, infer: async () => ({notes: [], paths: []})});
  assert.equal(result.stats.filesCut, 1);
  assert.ok(result.stats.routesCut > 0);
  assert.equal(result.modelCoverage.pagesSent, 1);
  assert.ok(result.modelCoverage.snippetsSent < result.modelCoverage.snippetsAvailable);
  assert.ok(result.endpoints.some(item => item.path === '/api/route-1199'));
  assert.ok(!result.endpoints.some(item => item.path === '/api/route-1200'));
  assert.ok(!result.endpoints.some(item => item.path === '/api/other'));
});
