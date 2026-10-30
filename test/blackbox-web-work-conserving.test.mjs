import test from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import {createHash} from 'node:crypto';
import {loadScope} from '../src/blackbox/scope.mjs';
import {runWebProbes} from '../src/blackbox/web-probes.mjs';

test('a free web worker starts the next ranked read before a slow peer finishes',
  {timeout: 10000}, async t => {
    let releaseSlow, slowFinished = false, fastTwoBeforeSlow = false;
    const fastTwoStarted = new Promise(resolve => {releaseSlow = resolve;});
    const seen = [];
    const server = http.createServer(async (request, response) => {
      const route = new URL(request.url, 'http://fixture.invalid').pathname;
      seen.push(route);
      if (route === '/slow') {
        let timer;
        try {
          await Promise.race([fastTwoStarted,
            new Promise(resolve => {timer = setTimeout(resolve, 1500);})]);
        } finally {clearTimeout(timer);}
        slowFinished = true;
      }
      if (route === '/fast-two') {
        fastTwoBeforeSlow = !slowFinished;
        releaseSlow();
      }
      response.writeHead(200, {'content-type': 'application/json',
        'cache-control': 'no-store'});
      response.end('{"ok":true}');
    });
    await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
    t.after(() => new Promise(resolve => server.close(resolve)));
    const origin = `http://127.0.0.1:${server.address().port}`;
    const {scope} = loadScope({origin, overrides: {acceptLocal: true,
      httpWorkers: 2, rps: 100}});
    assert.equal(scope.limits.agents, 2);
    let evidence = 0;
    const requester = async ({url, method = 'GET', headers = {}}) => {
      const response = await fetch(new URL(url, origin), {method, headers,
        redirect: 'manual'});
      const body = await response.text();
      return {status: response.status, type: response.headers.get('content-type'),
        body, bytes: Buffer.byteLength(body),
        hash: createHash('sha256').update(body).digest('hex'),
        headers: Object.fromEntries(response.headers), cached: false,
        evidenceId: `ev-${String(++evidence).padStart(4, '0')}`};
    };
    const paths = ['/warmup', '/slow', '/fast-one', '/fast-two'];
    const carryForward = paths.map((path, index) => ({
      kind: 'anonymous-credential-data', lead: {path, as: 'anonymous'},
      priority: 100 - index * 10}));
    const run = await runWebProbes({patterns: []}, scope, {requester,
      carryForward, budget: 4, researchDeadline: Date.now() + 8000});
    assert.equal(seen[0], '/warmup', 'the ranked first check keeps its serial turn');
    assert.ok(fastTwoBeforeSlow,
      'the third independent read started while the slow read remained active');
    assert.deepEqual(run.results.filter(item => paths.includes(item.lead?.path))
      .map(item => item.lead.path), paths,
    'completed findings and verdicts retain Muse-ranked order');
    assert.equal(run.modelCoverage.webWorkersPeak, 2);
  });
