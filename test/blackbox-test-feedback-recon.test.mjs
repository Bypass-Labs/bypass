import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import http from 'node:http';
import os from 'node:os';
import path from 'node:path';
import {runAudit} from '../src/blackbox/index.mjs';

const blank = schema => schema?.type === 'object' ?
  Object.fromEntries((schema.required ?? []).map(key => [key, blank(schema.properties?.[key])])) :
  schema?.type === 'array' ? [] :
  schema?.type === 'integer' || schema?.type === 'number' ? 0 :
  schema?.type === 'boolean' ? false : schema?.enum?.[0] ?? '';

test('a new route in an anonymous test response reopens scoped recon and gets tested',
  {timeout: 90000}, async t => {
    const root = fs.mkdtempSync(path.join(os.tmpdir(), 'bypass-test-feedback-'));
    t.after(() => fs.rmSync(root, {recursive: true, force: true}));
    const requested = [];
    const server = http.createServer((request, response) => {
      const url = new URL(request.url, 'http://fixture');
      requested.push(`${url.pathname}${url.search}`);
      response.setHeader('cache-control', 'no-store');
      if (url.pathname === '/') {
        response.setHeader('content-type', 'text/html');
        return response.end('<html><script src="/app.js"></script></html>');
      }
      if (url.pathname === '/app.js') {
        response.setHeader('content-type', 'application/javascript');
        return response.end('fetch("/probe?item=baseline");');
      }
      response.setHeader('content-type', 'application/json');
      if (url.pathname === '/probe') return response.end(JSON.stringify(
        url.searchParams.get('item') === 'baseline' || !url.searchParams.has('item') ?
          {status: 'ready'} : {status: 'changed', nextRoute: '/late'}));
      if (url.pathname === '/late') return response.end(JSON.stringify({status: 'ready'}));
      response.statusCode = 404;
      response.end(JSON.stringify({error: 'missing'}));
    });
    await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
    t.after(() => new Promise(resolve => server.close(resolve)));
    const origin = `http://127.0.0.1:${server.address().port}`;
    let testFeedbackSeen = false, calls = 0, feedbackAt = null;
    const infer = async (_model, messages, options) => {
      calls++;
      if (messages[0].content.includes('Continue mapping this authorized test-feedback')) {
        testFeedbackSeen = true;
        feedbackAt ??= calls;
        const context = JSON.parse(messages[1].content);
        assert.ok(context.observations.some(item => item.path === '/late'),
          'new route must reach Muse after the test response');
        return {paths: ['/late?probe=baseline']};
      }
      return blank(options.schema);
    };
    const audit = await runAudit({url: origin, root, infer, env: {}, offline: true,
      overrides: {acceptLocal: true, rps: 80, modelCalls: 36, minutes: 2}});
    const surface = JSON.parse(fs.readFileSync(path.join(audit.runDir, 'surface.json'), 'utf8'));
    const coverage = JSON.parse(fs.readFileSync(path.join(audit.runDir, 'coverage.json'), 'utf8'));
    assert.ok(testFeedbackSeen, 'the guarded test-response recon used Muse');
    assert.ok(surface.testResponseFollowup.routesAdded >= 1,
      JSON.stringify(surface.testResponseFollowup));
    assert.deepEqual(coverage.testResponseFollowup, surface.testResponseFollowup);
    assert.ok(requested.some(url => url.startsWith('/late?probe=') &&
      url !== '/late?probe=baseline'), 'the new input received a security check');
    assert.ok(!requested.some(url => url.startsWith('https://')));
    assert.ok(feedbackAt > 1);
    const tightBudget = feedbackAt;
    const tightRoot = path.join(root, 'one-call');
    fs.mkdirSync(tightRoot);
    calls = 0;
    feedbackAt = null;
    testFeedbackSeen = false;
    const tight = await runAudit({url: origin, root: tightRoot, infer, env: {}, offline: true,
      overrides: {acceptLocal: true, rps: 80, modelCalls: tightBudget, minutes: 2}});
    const tightSurface = JSON.parse(fs.readFileSync(path.join(tight.runDir, 'surface.json'), 'utf8'));
    assert.ok(testFeedbackSeen, 'one remaining web Muse call must be usable for route feedback');
    assert.equal(tightBudget - (feedbackAt - 1) - 2, 1,
      'the feedback call had exactly one web model call available after the two-call assessment reserve');
    assert.ok(tightSurface.testResponseFollowup.routesAdded >= 1);
  });
