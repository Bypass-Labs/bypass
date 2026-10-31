import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import http from 'node:http';
import os from 'node:os';
import path from 'node:path';
import {randomBytes} from 'node:crypto';
import {runAudit} from '../src/blackbox/index.mjs';
import {verifyRun} from '../src/blackbox/poc.mjs';

const blank = schema => schema?.type === 'object' ?
  Object.fromEntries((schema.required ?? []).map(key => [key, blank(schema.properties?.[key])])) :
  schema?.type === 'array' ? [] : schema?.type === 'integer' || schema?.type === 'number' ? 0 :
  schema?.type === 'boolean' ? false : schema?.enum?.[0] ?? '';

test('full audit remaps assets behind a proved request and presents them to Muse',
  {timeout: 90000}, async t => {
    const suffix = randomBytes(5).toString('hex');
    const scriptPath = `/bundle-${suffix}.js`;
    const newPage = `/workspace-${suffix}`;
    const operation = `/operation-${suffix}`;
    const headerName = `x-entry-${suffix}`;
    const value = `proof_${randomBytes(5).toString('hex')}`;
    const root = fs.mkdtempSync(path.join(os.tmpdir(), 'bypass-access-recon-'));
    t.after(() => fs.rmSync(root, {recursive: true, force: true}));
    const requests = [];
    const server = http.createServer((request, response) => {
      const url = new URL(request.url, 'http://fixture.invalid');
      const opened = request.headers[headerName] === value;
      requests.push({path: url.pathname, opened});
      response.setHeader('cache-control', 'no-store');
      if (url.pathname === scriptPath && opened) {
        response.setHeader('content-type', 'application/javascript');
        return response.end(`fetch('${operation}', {method:'POST', headers:{'content-type':'application/json'}, body:JSON.stringify({item:'demo'})});`);
      }
      if (url.pathname === '/' || url.pathname === newPage) {
        response.setHeader('content-type', 'text/html');
        return response.end(opened ?
          `<main>Opened workspace</main><script src="${scriptPath}"></script><a href="${newPage}">Work</a>` :
          '<main>Private entry</main>');
      }
      response.statusCode = 404;
      response.end('missing');
    });
    await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
    t.after(() => new Promise(resolve => server.close(resolve)));
    const origin = `http://127.0.0.1:${server.address().port}`;
    let firstPlanned = false;
    let sawProvedSurface = false;
    const request = (headers = []) => ({method: 'GET', path: '/', headers, body: ''});
    const infer = async (_profile, messages, options) => {
      if (messages[0].content.startsWith('You are planning bounded, authorized HTTP research.')) {
        const context = JSON.parse(messages[1].content);
        if (context.provedAccess) {
          sawProvedSurface ||= context.provedAccess.requests.at(-1).headers.some(item =>
            item.name === headerName && item.value === value) &&
            context.routes.some(route => route.path === operation &&
              route.methods.includes('POST'));
          return {flows: []};
        }
        if (!firstPlanned) {
          firstPlanned = true;
          return {flows: [{family: 'access boundary', why: 'Test an observed gate',
            priority: 9, as: 'anonymous', oracle: 'raw-proof',
            rawRequests: [request([{name: headerName, value}])],
            rawProof: {baseline: [request()],
              negative: [request([{name: headerName, value: 'wrong'}])],
              closedText: 'Private entry', openText: 'Opened workspace'}}]};
        }
        return {flows: []};
      }
      return blank(options.schema);
    };
    const audit = await runAudit({url: origin, root, infer, env: {}, offline: true,
      noDiscovery: true, modelProfileOverride: {provider: 'fixture', model: 'fixture'},
      overrides: {acceptLocal: true, rps: 80, modelCalls: 80,
        maxUrls: 100, maxTasks: 0, minutes: 2}});
    const coverage = JSON.parse(fs.readFileSync(path.join(audit.runDir, 'coverage.json'), 'utf8'));
    const mapped = JSON.parse(fs.readFileSync(path.join(audit.runDir,
      'confirmed-access-recon.json'), 'utf8'));
    assert.ok(firstPlanned);
    assert.ok(audit.findings.some(item => item.kind === 'model-raw-boundary'));
    assert.equal(coverage.confirmedAccessRecon.contexts, 1);
    assert.ok(coverage.confirmedAccessRecon.newRoutes >= 1);
    assert.ok(coverage.confirmedAccessRecon.changedRoutes >= 1);
    assert.ok(coverage.confirmedAccessRecon.newContracts >= 1);
    assert.ok(requests.some(item => item.path === scriptPath && item.opened));
    assert.ok(requests.some(item => item.path === newPage && item.opened));
    assert.ok(sawProvedSurface, 'the new method contract and exact access request reached Muse');
    assert.ok(!JSON.stringify(mapped).includes(value), 'the access value stays out of recon artifacts');
    const replay = await verifyRun(root, audit.run, {env: {}});
    assert.ok(replay.proofs.some(item => item.verdict === 'confirmed'));
  });
