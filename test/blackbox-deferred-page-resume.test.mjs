import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import http from 'node:http';
import {spawn} from 'node:child_process';

const sleep = ms => new Promise(resolve => setTimeout(resolve, ms));

test('SIGKILL after a deferred sequence page resumes its accepted lead once',
  {timeout: 65000}, async t => {
    const root = fs.mkdtempSync(path.join(os.tmpdir(), 'bypass-deferred-page-'));
    t.after(() => fs.rmSync(root, {recursive: true, force: true}));
    const hits = [];
    let slowPost = true;
    const server = http.createServer((request, response) => {
      const url = new URL(request.url, 'http://fixture.invalid');
      hits.push(`${request.method} ${url.pathname}${url.search}`);
      const json = value => {
        if (response.destroyed) return;
        response.writeHead(200, {'content-type': 'application/json',
          'cache-control': 'no-store'});
        response.end(JSON.stringify(value));
      };
      if (url.pathname === '/api/transform' && request.method === 'POST') {
        if (!slowPost) return json({result: 'plain'});
        const timer = setTimeout(() => json({result: 'plain'}), 30000);
        response.on('close', () => clearTimeout(timer));
        return;
      }
      return json({result: url.searchParams.get('q') ?? 'plain'});
    });
    await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
    t.after(() => server.close());
    const origin = `http://127.0.0.1:${server.address().port}`;
    fs.writeFileSync(path.join(root, 'scope.json'), JSON.stringify({
      schemaVersion: 1, target: {origin}, include: ['/'],
      probes: {jsonPostPaths: ['/api/transform']},
      limits: {rps: 100, modelConcurrency: 3, modelCalls: 40,
        tasks: 100, minutes: 1}}));
    const runner = path.join(import.meta.dirname,
      'fixtures/blackbox-deferred-page-runner.mjs');
    const launch = mode => spawn(process.execPath, [runner, root, origin, mode],
      {stdio: ['ignore', 'ignore', 'pipe']});
    const first = launch('first');
    t.after(() => {if (first.exitCode == null) first.kill('SIGKILL');});
    const checkpointFile = path.join(root, 'deferred-page.json');
    let checkpoint = null;
    const until = Date.now() + 14000;
    while (Date.now() < until) {
      if (fs.existsSync(checkpointFile)) {
        checkpoint = JSON.parse(fs.readFileSync(checkpointFile, 'utf8'));
        if (checkpoint.nextRouteOffset > 0 && checkpoint.pendingLeads?.length) break;
      }
      if (first.exitCode != null) break;
      await sleep(30);
    }
    assert.ok(checkpoint?.pendingLeads?.length,
      `deferred accepted lead was not checkpointed: ${JSON.stringify(checkpoint)}`);
    const lead = checkpoint.pendingLeads[0];
    const leadPath = lead.subject.path;
    assert.ok(checkpoint.nextRouteOffset > 0 && lead.proposalId);
    assert.equal(hits.filter(hit => hit.startsWith(`GET ${leadPath}?q=one`)).length, 0,
      'the accepted lead has not reached HTTP before the interruption');
    first.kill('SIGKILL');
    await new Promise(resolve => first.once('exit', resolve));

    slowPost = false;
    const resumed = launch('resume');
    let stderr = '';
    resumed.stderr.on('data', chunk => {stderr += chunk;});
    const exit = await new Promise(resolve => resumed.once('exit', resolve));
    assert.equal(exit, 0, stderr);
    const result = JSON.parse(fs.readFileSync(path.join(root,
      'deferred-result.json'), 'utf8'));
    const matches = result.results.filter(item => item.proposalId === lead.proposalId);
    assert.equal(matches.length, 1, JSON.stringify(result.results));
    assert.notEqual(matches[0].verdict, 'untested');
    assert.equal(hits.filter(hit => hit === `GET ${leadPath}?q=one`).length, 2,
      `the saved lead's distinct first input is replayed once with its fresh control: ${JSON.stringify({
        leadPath, hits: hits.filter(hit => hit.startsWith(`GET ${leadPath}?q=`)), result})}`);
    const finalPage = JSON.parse(fs.readFileSync(checkpointFile, 'utf8'));
    assert.ok(!(finalPage.pendingLeads ?? []).some(item =>
      item.proposalId === lead.proposalId));
  });
