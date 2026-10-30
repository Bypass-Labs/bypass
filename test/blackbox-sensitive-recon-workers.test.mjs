import test from 'node:test';
import assert from 'node:assert/strict';
import {DEFAULT_SCOPE} from '../src/blackbox/scope.mjs';
import {scanSensitivePaths} from '../src/blackbox/recon.mjs';

test('independent sensitive path signatures are checked concurrently', async () => {
  const scope = structuredClone(DEFAULT_SCOPE);
  scope.discovery.sensitivePaths = true;
  scope.limits.agents = 2;
  let releaseSlow;
  const slowPending = new Promise(resolve => {releaseSlow = resolve;});
  let requests = 0, slowDone = false, secondBeforeSlow = false;
  const result = await scanSensitivePaths(scope, async () => {
    requests++;
    if (requests === 1) {
      await Promise.race([slowPending,
        new Promise(resolve => setTimeout(resolve, 350))]);
      slowDone = true;
    } else if (requests === 2) {
      secondBeforeSlow = !slowDone;
      releaseSlow();
    }
    return {status: 404, body: '', type: 'text/plain'};
  });
  assert.ok(secondBeforeSlow, 'the second signature check waited for the first');
  assert.equal(result.stats.total, requests);
  assert.deepEqual(result.exposures, []);
});
