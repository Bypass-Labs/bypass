import test from 'node:test';
import assert from 'node:assert/strict';
import {loadScope} from '../src/blackbox/scope.mjs';
import {reconObservedRoutes} from '../src/blackbox/robots-directory.mjs';

test('independent public route observations overlap and keep their discovery order', async () => {
  const origin = 'http://127.0.0.1:43199';
  const scope = structuredClone(loadScope({origin,
    overrides: {acceptLocal: true, httpWorkers: 2}}).scope);
  scope.discover = ['/api/slow', '/api/fast'];
  let releaseSlow;
  const slowPending = new Promise(resolve => {releaseSlow = resolve;});
  let slowDone = false, fastBeforeSlow = false;
  const requested = [];
  const requester = async ({url}) => {
    const path = new URL(url, origin).pathname;
    requested.push(path);
    if (path === '/api/slow') {
      await Promise.race([slowPending,
        new Promise(resolve => setTimeout(resolve, 350))]);
      slowDone = true;
    } else if (path === '/api/fast') {
      fastBeforeSlow = !slowDone;
      releaseSlow();
    }
    const status = path === '/api/slow' || path === '/api/fast' ? 200 : 404;
    const body = status === 200 ? '{"ok":true}' : '';
    return {status, body, type: 'application/json',
      evidenceId: `ev-${requested.length}`};
  };
  const run = await reconObservedRoutes(scope, requester);
  assert.ok(fastBeforeSlow, 'the later public GET waited behind a slow peer');
  assert.ok(run.routes.some(item => item.path === '/api/slow' && item.status === 200));
  assert.ok(run.routes.some(item => item.path === '/api/fast' && item.status === 200));
  assert.ok(run.routes.findIndex(item => item.path === '/api/slow') <
    run.routes.findIndex(item => item.path === '/api/fast'));
  assert.equal(run.stats.requested, requested.length);
});
