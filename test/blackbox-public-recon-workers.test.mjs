import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import http from 'node:http';
import {temp} from './helpers.mjs';
import {loadScope, createLimiter, createRequester} from '../src/blackbox/scope.mjs';
import {createLedger} from '../src/blackbox/ledger.mjs';
import {recon} from '../src/blackbox/recon.mjs';

test('public recon overlaps observed GETs and commits discovered route facts in queue order',
  {timeout: 10000}, async t => {
    const dir = temp();
    t.after(() => fs.rmSync(dir, {recursive: true, force: true}));
    const active = {count: 0, peak: 0};
    const completed = [];
    const api = {openapi: '3.0.0', paths: Object.fromEntries(
      ['/route/a', '/route/b', '/route/c'].map(route => [route, {get: {}}]))};
    const server = http.createServer(async (request, response) => {
      if (request.url === '/openapi.json') {
        response.writeHead(200, {'content-type': 'application/json'});
        return response.end(JSON.stringify(api));
      }
      if (['/route/a', '/route/b', '/route/c'].includes(request.url)) {
        active.count++;
        active.peak = Math.max(active.peak, active.count);
        await new Promise(resolve => setTimeout(resolve,
          {'/route/a': 120, '/route/b': 60, '/route/c': 10}[request.url]));
        completed.push(request.url);
        active.count--;
        response.writeHead(200, {'content-type': 'application/json'});
        return response.end(JSON.stringify(request.url === '/route/a' ?
          {next: '/route/later'} : {ok: true}));
      }
      response.writeHead(request.url === '/route/later' ? 200 : 404,
        {'content-type': 'application/json'});
      response.end('{}');
    });
    await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
    t.after(() => new Promise(resolve => {
      server.closeAllConnections();
      server.close(resolve);
    }));
    const origin = `http://127.0.0.1:${server.address().port}`;
    const scope = structuredClone(loadScope({origin, overrides: {
      acceptLocal: true, agents: 3}}).scope);
    scope.include = ['/route', '/openapi.json'];
    scope.discover = ['/openapi.json'];
    scope.seeds.openapi = '/openapi.json';
    scope.discovery.sensitivePaths = false;
    scope.limits.maxUrls = 5;
    const env = {OWNER_TOKEN: 'fixture-owner', OTHER_TOKEN: 'fixture-outsider'};
    const ledger = createLedger(dir, {run: 'bx-public-recon-workers',
      secrets: Object.values(env)});
    const requester = createRequester(scope, {ledger, limiter: createLimiter(1000),
      env, allowLocal: true, run: 'bx-public-recon-workers'});
    const surface = await recon(scope, {requester, env});
    assert.ok(active.peak > 1, 'independent observed GETs should overlap');
    assert.ok(active.peak <= scope.limits.agents, 'recon must honor the agent limit');
    assert.deepEqual(completed.slice(0, 3), ['/route/c', '/route/b', '/route/a'],
      'the fixture must finish responses out of queue order');
    assert.deepEqual(surface.patterns.map(item => item.pattern)
      .filter(pattern => pattern.startsWith('/route/')),
    ['/route/a', '/route/b', '/route/c', '/route/later']);
    assert.equal(surface.stats.urls, 5,
      'OpenAPI plus four observed paths must use exactly five URL slots');
    assert.ok(surface.patterns.find(item => item.pattern === '/route/later')
      ?.source.includes('link'), 'a route discovered in a response must reach the next batch');
  });
