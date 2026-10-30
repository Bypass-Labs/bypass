import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import http from 'node:http';
import os from 'node:os';
import path from 'node:path';
import {randomBytes} from 'node:crypto';
import {createLedger} from '../src/blackbox/ledger.mjs';
import {createRequester, loadScope} from '../src/blackbox/scope.mjs';
import {planResearchFlows, runResearchFlows,
  validateResearchFlow} from '../src/blackbox/research-flow.mjs';
import {exportRun, proveFindings} from '../src/blackbox/poc.mjs';
import {execFile} from '../src/util.mjs';

test('Muse state-change plans prove anonymous and outsider mutations of a disposable owner record with restoration',
  {timeout: 30000}, async t => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'bypass-state-change-'));
    t.after(() => fs.rmSync(dir, {recursive: true, force: true}));
    const runId = `bx-20261029-${randomBytes(4).toString('hex')}`;
    const runDir = path.join(dir, '.bypass/runs', runId);
    fs.mkdirSync(runDir, {recursive: true});
    const suffix = randomBytes(5).toString('hex');
    const protectedPath = `/api/record-${suffix}`;
    const writePath = `/api/update-${suffix}`;
    const baseline = `private-pending-${suffix}`;
    let state = baseline, vulnerable = true, failSecond = false;
    let outsiderReadOpen = false;
    let denyAnonymousRestore = false, denyOwnerRestore = false;
    const server = http.createServer(async (request, response) => {
      response.setHeader('content-type', 'application/json');
      response.setHeader('cache-control', 'no-store');
      if (request.url === protectedPath && request.method === 'GET') {
        if (request.headers.authorization !== 'Bearer fixture-owner' &&
            !(outsiderReadOpen &&
              request.headers.authorization === 'Bearer fixture-outsider')) {
          response.statusCode = 403;
          response.end('{"error":"denied"}');
        } else response.end(JSON.stringify({record: {reviewState: state}}));
        return;
      }
      if (request.url === writePath && request.method === 'PATCH') {
        const chunks = [];
        for await (const chunk of request) chunks.push(chunk);
        const body = JSON.parse(Buffer.concat(chunks).toString());
        if (body.channel !== 'review') {
          response.statusCode = 422;
          response.end('{"error":"review channel required"}');
          return;
        }
        if (state !== baseline && body.reviewState === baseline &&
            ((denyAnonymousRestore &&
              request.headers.authorization !== 'Bearer fixture-owner') ||
             (denyOwnerRestore &&
              request.headers.authorization === 'Bearer fixture-owner'))) {
          response.statusCode = 403;
          response.end('{"error":"restoration refused"}');
          return;
        }
        if (!vulnerable && request.headers.authorization !== 'Bearer fixture-owner') {
          response.statusCode = 403;
          response.end('{"error":"denied"}');
        } else {
          if (failSecond && String(body.reviewState).startsWith('bxsecond')) {
            response.statusCode = 500;
            response.end('{"error":"temporary"}');
            return;
          }
          state = body.reviewState;
          response.end('{"updated":true}');
        }
        return;
      }
      response.statusCode = 404;
      response.end('{"error":"missing"}');
    });
    await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
    t.after(() => new Promise(resolve => server.close(resolve)));
    const origin = `http://127.0.0.1:${server.address().port}`;
    const file = path.join(dir, 'scope.json');
    fs.writeFileSync(file, JSON.stringify({schemaVersion: 1, target: {origin},
      include: ['/api'], identities: {identityPath: protectedPath},
      probes: {writeOperations: [{method: 'PATCH', path: writePath,
        placement: 'json'}]}, limits: {rps: 50}}));
    const scope = structuredClone(loadScope({file, origin}).scope);
    scope.localAutoMethodContracts = {[`PATCH json ${writePath}`]:
      {contentType: 'application/json', fields: ['reviewState', 'channel']}};
    const surface = {patterns: [{pattern: protectedPath, methods: ['GET'],
      fingerprint: {owner: {status: 200}, anonymous: {status: 403}}}],
    methodOperations: [{method: 'PATCH', path: writePath,
      placement: 'json', contentType: 'application/json',
      fields: ['reviewState', 'channel'], requiredFields: ['reviewState', 'channel']} ]};
    const lead = {family: 'unauthorized-record-write', priority: 9,
      why: 'The owner-only record has a reviewed write route', as: 'anonymous',
      oracle: 'state-change', protectedPath, prelude: [], observe: [],
      subject: {method: 'PATCH', path: writePath, placement: 'json',
        key: 'reviewState', fixedFields: [{field: 'channel', value: 'review'}],
        bodyTemplate: '', headers: []},
      binding: null, controlValue: 'plain', firstValue: `bxfirst${suffix}`,
      secondValue: `bxsecond${suffix}`, marker: 'bx111111111111',
      secondMarker: 'bx222222222222', assertion: {step: 'subject', index: 0,
        location: 'body', name: ''}};
    const env = {...process.env, OWNER_TOKEN: 'fixture-owner',
      OTHER_TOKEN: 'fixture-outsider'};
    assert.equal(validateResearchFlow(lead, surface, scope, {env}).ok, true);
    const planned = await planResearchFlows(surface, scope, {env, model: 'fixture',
      budget: 1, modelCallsAvailable: 1,
      infer: async (_model, messages) => {
        const context = JSON.parse(messages[1].content);
        assert.ok(context.protectedReadRoutes.includes(protectedPath));
        assert.ok(context.routes.some(item => item.path === writePath &&
          item.methods.includes('PATCH')));
        return {flows: [{...lead, marker: context.marker,
          secondMarker: context.secondMarker}]};
      }});
    assert.equal(planned.leads.length, 1, JSON.stringify(planned.decisions));
    const ledger = createLedger(runDir);
    t.after(() => ledger.close());
    const requester = createRequester(scope, {ledger, env, allowLocal: true});
    const run = await runResearchFlows(planned.leads, scope, {requester, surface,
      ledger, env, modelCallsAvailable: 0});
    assert.equal(run.results[0].verdict, 'confirmed', JSON.stringify(run.results));
    assert.equal(run.findings[0]?.kind, 'model-state-change');
    assert.equal(run.findings[0]?.severity, 'medium');
    assert.equal(state, baseline, 'audit must restore the disposable record');
    const proved = await proveFindings([{...run.findings[0], id: 'f-001'}], [],
      {runDir, surface, scope, env, ledger, web: run});
    assert.equal(proved.length, 1, JSON.stringify(run.findings));
    assert.equal(state, baseline, 'fresh proof must restore the record');
    const proof = JSON.parse((await execFile(process.execPath,
      [proved[0].proof], {env, timeout: 20000})).stdout);
    assert.equal(proof.verdict, 'confirmed', JSON.stringify(proof));
    assert.equal(state, baseline);
    const collidingLead = {...lead, firstValue: baseline};
    assert.equal(validateResearchFlow(collidingLead, surface, scope, {env}).ok, true);
    const collision = await runResearchFlows([collidingLead], scope,
      {requester, surface, ledger, env, modelCallsAvailable: 0});
    assert.equal(collision.results[0].verdict, 'confirmed', JSON.stringify(collision.results));
    assert.equal(collision.findings[0].webProof.secondValue, collidingLead.secondValue,
      'the noncolliding Muse value must be preserved');
    assert.notEqual(collision.findings[0].webProof.firstValue, baseline,
      'a local canary must replace only the baseline collision');
    assert.ok(collision.investigations[0].attempts[0].canaryAdjustment ===
      'baseline-collision');
    assert.equal(state, baseline);
    const collisionRunDir = path.join(dir, 'collision-run');
    fs.mkdirSync(collisionRunDir, {recursive: true});
    const collisionProved = await proveFindings([{
      ...collision.findings[0], id: 'f-002'}], [],
    {runDir: collisionRunDir, surface, scope, env, ledger, web: collision});
    assert.equal(collisionProved.length, 1, 'collision adjusted proof must replay');
    assert.equal(state, baseline);
    state = `pending;${suffix}`;
    const unsafeBaseline = await runResearchFlows(planned.leads, scope,
      {requester, surface, ledger, env, modelCallsAvailable: 0});
    assert.equal(unsafeBaseline.results[0].verdict, 'inconclusive');
    assert.equal(unsafeBaseline.results[0].reason,
      'owner field cannot be safely restored: unsafe-syntax');
    assert.ok(!unsafeBaseline.investigations[0].attempts[0].controls.some(item =>
      item.label === 'first-write'), 'unsafe baseline must not be changed');
    state = baseline;
    denyAnonymousRestore = true;
    const fallback = await runResearchFlows(planned.leads, scope,
      {requester, surface, ledger, env, modelCallsAvailable: 0});
    assert.equal(fallback.results[0].verdict, 'confirmed',
      JSON.stringify(fallback.results));
    assert.ok(fallback.investigations[0].attempts[0].controls.some(item =>
      item.label === 'restore-owner-write' && item.status === 200));
    assert.ok(fallback.findings[0].webSteps.some(item =>
      item.probe === 'restore-owner-write' && item.identity === 'owner'));
    assert.equal(state, baseline, 'owner fallback must restore the record');
    const fallbackProof = JSON.parse((await execFile(process.execPath,
      [proved[0].proof], {env, timeout: 20000})).stdout);
    assert.equal(fallbackProof.verdict, 'confirmed', JSON.stringify(fallbackProof));
    assert.ok(fallbackProof.controls.some(item => item.label === 'restore-owner-write' &&
      item.status === 200));
    assert.equal(state, baseline, 'standalone owner fallback must restore the record');
    denyOwnerRestore = true;
    const failedRollback = await runResearchFlows(planned.leads, scope,
      {requester, surface, ledger, env, modelCallsAvailable: 0});
    assert.equal(failedRollback.results[0].verdict, 'inconclusive',
      'a failed owner fallback cannot confirm the finding');
    assert.ok(failedRollback.investigations[0].attempts[0].controls.some(item =>
      item.label === 'restore-owner-write' && item.status === 403));
    state = baseline; // Dispose of the local fixture after the deliberate failed rollback.
    const failedRollbackProof = JSON.parse((await execFile(process.execPath,
      [proved[0].proof], {env, timeout: 20000})).stdout);
    assert.equal(failedRollbackProof.verdict, 'inconclusive',
      'a standalone proof must also withhold confirmation after failed cleanup');
    assert.ok(failedRollbackProof.controls.some(item =>
      item.label === 'restore-owner-write' && item.status === 403));
    state = baseline;
    denyOwnerRestore = false;
    denyAnonymousRestore = false;
    failSecond = true;
    const interrupted = await runResearchFlows(planned.leads, scope,
      {requester, surface, ledger, env, modelCallsAvailable: 0});
    assert.equal(interrupted.results[0].verdict, 'inconclusive');
    assert.equal(state, baseline, 'cleanup must run after a failing probe response');
    failSecond = false;
    fs.writeFileSync(path.join(runDir, 'run.json'), JSON.stringify({run: runId}));
    const exported = exportRun(dir, runId, {out: path.join(dir, 'regression')});
    assert.equal(exported.files.length, 1);
    const regression = async () => (await execFile(process.execPath,
      ['--test', exported.files[0]], {env: {...env, NODE_TEST_CONTEXT: undefined},
        timeout: 20000})).code;
    assert.equal(await regression(), 1, 'regression must fail while anonymous writes persist');
    const outsiderLead = {...lead, family: 'cross-account-record-write',
      why: 'A distinct outsider may modify the owner-only record', as: 'outsider'};
    assert.equal(validateResearchFlow(outsiderLead, surface, scope, {env}).ok, true);
    const outsiderPlanned = await planResearchFlows(surface, scope,
      {env, model: 'fixture', budget: 1, modelCallsAvailable: 1,
        infer: async (_model, messages) => {
          const context = JSON.parse(messages[1].content);
          assert.equal(context.ownerAvailable, true);
          assert.equal(context.outsiderAvailable, true);
          return {flows: [{...outsiderLead, marker: context.marker,
            secondMarker: context.secondMarker}]};
        }});
    assert.equal(outsiderPlanned.leads.length, 1,
      JSON.stringify(outsiderPlanned.decisions));
    const outsiderRunId = `bx-20261029-${randomBytes(4).toString('hex')}`;
    const outsiderRunDir = path.join(dir, '.bypass/runs', outsiderRunId);
    fs.mkdirSync(outsiderRunDir, {recursive: true});
    const outsiderLedger = createLedger(outsiderRunDir);
    t.after(() => outsiderLedger.close());
    const outsiderRequester = createRequester(scope,
      {ledger: outsiderLedger, env, allowLocal: true});
    const outsiderRun = await runResearchFlows(outsiderPlanned.leads, scope,
      {requester: outsiderRequester, surface, ledger: outsiderLedger, env,
        modelCallsAvailable: 0});
    assert.equal(outsiderRun.results[0].verdict, 'confirmed',
      JSON.stringify(outsiderRun.results));
    assert.equal(outsiderRun.findings[0].owasp,
      'API1 Broken Object Level Authorization');
    assert.ok(outsiderRun.investigations[0].attempts[0].controls.some(item =>
      item.label === 'outsider-denial' && item.status === 403));
    assert.ok(outsiderRun.investigations[0].attempts[0].controls.some(item =>
      item.label === 'outsider-recheck' && item.status === 403));
    assert.ok(outsiderRun.findings[0].webSteps.some(item =>
      item.probe === 'first-write' && item.identity === 'outsider'));
    assert.equal(state, baseline, 'outsider audit must restore the record');
    const outsiderProved = await proveFindings([{
      ...outsiderRun.findings[0], id: 'f-001'}], [],
    {runDir: outsiderRunDir, surface, scope, env,
      ledger: outsiderLedger, web: outsiderRun});
    assert.equal(outsiderProved.length, 1, 'outsider proof must freshly replay');
    assert.equal(state, baseline, 'outsider proof must restore the record');
    fs.writeFileSync(path.join(outsiderRunDir, 'run.json'),
      JSON.stringify({run: outsiderRunId}));
    const outsiderExport = exportRun(dir, outsiderRunId,
      {out: path.join(dir, 'outsider-regression')});
    assert.equal(outsiderExport.files.length, 1);
    const outsiderRegression = async () => (await execFile(process.execPath,
      ['--test', outsiderExport.files[0]],
      {env: {...env, NODE_TEST_CONTEXT: undefined}, timeout: 20000})).code;
    assert.equal(await outsiderRegression(), 1,
      'outsider write regression must fail while the bug exists');
    outsiderReadOpen = true;
    const publicToOutsider = await runResearchFlows(outsiderPlanned.leads, scope,
      {requester: outsiderRequester, surface, ledger: outsiderLedger, env,
        modelCallsAvailable: 0});
    assert.equal(publicToOutsider.results[0].verdict, 'inconclusive',
      'readable record cannot establish a cross-account write boundary');
    assert.ok(!publicToOutsider.investigations[0].attempts[0].controls.some(item =>
      item.label === 'first-write'), 'no probe write should follow a missing boundary');
    assert.equal(state, baseline);
    outsiderReadOpen = false;
    const artifacts = fs.readdirSync(runDir, {recursive: true, withFileTypes: true})
      .filter(item => item.isFile()).map(item => fs.readFileSync(
        path.join(item.parentPath, item.name), 'utf8')).join('\n');
    assert.ok(!artifacts.includes(baseline), 'owner field value must stay out of artifacts');
    const outsiderArtifacts = fs.readdirSync(outsiderRunDir,
      {recursive: true, withFileTypes: true}).filter(item => item.isFile())
      .map(item => fs.readFileSync(path.join(item.parentPath, item.name), 'utf8'))
      .concat(outsiderExport.files.map(file => fs.readFileSync(file, 'utf8')))
      .join('\n');
    assert.ok(!outsiderArtifacts.includes('fixture-owner'));
    assert.ok(!outsiderArtifacts.includes('fixture-outsider'));
    assert.ok(!outsiderArtifacts.includes(baseline));
    vulnerable = false;
    const fixed = await execFile(process.execPath,
      [proved[0].proof, '--expect-fixed'], {env, timeout: 20000});
    assert.equal(fixed.code, 0, fixed.stdout);
    assert.equal(JSON.parse(fixed.stdout).verdict, 'not_reproduced');
    assert.equal(await regression(), 0, 'regression must pass after authorization fix');
    const outsiderFixed = await execFile(process.execPath,
      [outsiderProved[0].proof, '--expect-fixed'], {env, timeout: 20000});
    assert.equal(outsiderFixed.code, 0, outsiderFixed.stdout);
    assert.equal(JSON.parse(outsiderFixed.stdout).verdict, 'not_reproduced');
    assert.equal(await outsiderRegression(), 0,
      'outsider write regression must pass after authorization fix');
    assert.equal(state, baseline);
  });
