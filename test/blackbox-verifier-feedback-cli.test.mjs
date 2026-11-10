import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import http from 'node:http';
import os from 'node:os';
import path from 'node:path';
import {spawn} from 'node:child_process';
import {CLI} from '../src/demo.mjs';
import {execFile} from '../src/util.mjs';
import {execute} from '../src/service.mjs';

test('later protected Muse planning receives an earlier verifier result and pivots',
  {timeout: 180000}, async t => {
    const root = fs.mkdtempSync(path.join(os.tmpdir(), 'bypass-verifier-feedback-'));
    t.after(() => {if (!process.env.BX_KEEP_TEST_ROOT)
      fs.rmSync(root, {recursive: true, force: true});});
    const target = path.join(root, 'target');
    const fixture = path.join(import.meta.dirname, 'fixtures/blackbox-cookie-blind.mjs');
    const server = spawn(process.execPath, [fixture, target],
      {stdio: ['ignore', 'pipe', 'inherit']});
    t.after(() => server.kill());
    const origin = await new Promise((resolve, reject) => {
      server.stdout.once('data', chunk => resolve(String(chunk).trim()));
      server.once('error', reject);
      server.once('exit', code => reject(Error(`fixture exited ${code}`)));
    });
    const {loginPath, identityPath, renderPath} = JSON.parse(fs.readFileSync(
      path.join(target, 'routes.json'), 'utf8'));
    const feedbackLog = path.join(root, 'feedback.jsonl');
    const choiceLog = path.join(root, 'choices.jsonl');
    const blank = schema => schema?.type === 'object' ?
      Object.fromEntries((schema.required ?? []).map(key =>
        [key, blank(schema.properties?.[key])])) :
      schema?.type === 'array' ? [] :
      ['integer', 'number'].includes(schema?.type) ? 0 :
      schema?.type === 'boolean' ? false : schema?.enum?.[0] ?? '';
    const modelServer = http.createServer(async (request, response) => {
      let raw = '';
      for await (const chunk of request) raw += chunk;
      const call = JSON.parse(raw);
      const system = call.input.find(item => item.role === 'system')?.content ?? '';
      const context = call.input.filter(item => item.role === 'user').toReversed()
        .map(item => {try {return JSON.parse(item.content);} catch {return null;}})
        .find(Boolean) ?? {};
      let answer;
      if (system.startsWith('From only the observed authorized JSON login operations')) {
        const post = context.posts.find(item => item.path === loginPath);
        const read = context.reads.find(item => item.path === identityPath);
        answer = {checks: post && read ? [{loginPath: post.path,
          userField: 'username', passwordField: 'password',
          proofMode: 'protected-status', userPayloads: ["admin' OR '1'='1"],
          tokenPointer: '', privatePath: read.path,
          why: 'Synthetic invalid-password experiment on an observed login contract'}] : []};
      } else if (system.startsWith('Allocate the next black-box investigation effort')) {
        answer = {priorities: context.tracks.map(row => ({name: row.name,
          weight: row.name === 'sequence' ? 100 : 1,
          why: 'Observed protected read input'}))
          .sort((a, b) => b.weight - a.weight)};
      } else if (system.startsWith('You are planning bounded, authorized HTTP research.')) {
        const route = context.routes.find(item => item.path === renderPath &&
          item.kind === 'read' && item.fields.includes('q'));
        if ((context.priorVerifierResults ?? []).length)
          fs.appendFileSync(feedbackLog, JSON.stringify(context.priorVerifierResults) + '\n');
        answer = {flows: route ? [{family: 'render-processing',
          why: 'Observed protected render input can alter a response',
          priority: 10, as: 'derived', oracle: 'observation', prelude: [],
          subject: {method: 'GET', path: route.path, placement: 'query',
            key: 'q', fixedFields: [], bodyTemplate: '', headers: []},
          observe: [], controlValue: 'hello', firstValue: 'world',
          secondValue: 'again', marker: '', secondMarker: '',
          assertion: {step: 'subject', index: 0, location: 'body', name: ''}}] : []};
      } else if (system.startsWith('Revise at most one bounded, authorized HTTP experiment')) {
        const prior = context.priorVerifierResults ?? [];
        if (prior.length) fs.appendFileSync(feedbackLog, JSON.stringify(prior) + '\n');
        const choices = context.verifierChoices ?? [];
        if (prior.length) fs.appendFileSync(choiceLog, JSON.stringify(choices) + '\n');
        const previousXss = choices.some(item => item.kind === 'xss-reflected' &&
          item.path === renderPath && item.parameter === 'q' &&
          item.prior?.verdict === 'not_reproduced');
        const kind = previousXss ? 'ssti-arithmetic' : 'xss-reflected';
        const selected = choices.find(item => item.kind === kind &&
          item.path === renderPath);
        answer = {flows: [], ...(selected ? {verifierId: selected.id} : {})};
      } else if (system.includes('Interpret only the extracted')) {
        answer = {files: context.files.map(file => ({id: file.id, role: 'app',
          why: 'Observed asset', authFlow: '', routes: [], proposals: []}))};
      } else answer = blank(call.text.format.schema);
      response.setHeader('content-type', 'application/json');
      response.end(JSON.stringify({status: 'completed', output: [{type: 'message',
        role: 'assistant', content: [{type: 'output_text', text: JSON.stringify(answer)}]}]}));
    });
    await new Promise(resolve => modelServer.listen(0, '127.0.0.1', resolve));
    t.after(() => {modelServer.closeAllConnections(); modelServer.close();});
    const project = path.join(root, 'project');
    fs.mkdirSync(project);
    await execute('init', [project]);
    await execute('model add', ['verifier-fixture'], {project, provider: 'custom',
      'base-url': `http://127.0.0.1:${modelServer.address().port}/v1`,
      model: 'fixture', 'secret-env': 'BYPASS_VERIFIER_FIXTURE_KEY',
      transport: 'responses', 'response-mode': 'json-schema', stream: false});
    const env = {...process.env, BYPASS_VERIFIER_FIXTURE_KEY: 'unit-fixture-key'};
    const cli = async (...args) => {
      const done = await execFile(process.execPath,
        [CLI, 'blackbox', ...args, '--project', project, '--json', '--non-interactive'],
        {cwd: root, env, timeout: 120000});
      return {code: done.code, data: JSON.parse(done.stdout)};
    };
    const audit = await cli(origin, '--accept-local', '--rps', '30',
      '--model-calls', '60', '--max-tasks', '32', '--max-urls', '80',
      '--minutes', '3', '--offline');
    assert.ok(audit.data.runDir, JSON.stringify(audit));
    const web = JSON.parse(fs.readFileSync(path.join(audit.data.runDir,
      'web-probes.json'), 'utf8'));
    const feedback = fs.existsSync(feedbackLog) ? fs.readFileSync(feedbackLog, 'utf8')
      .trim().split('\n').filter(Boolean).map(line => JSON.parse(line)) : [];
    const choicePages = fs.existsSync(choiceLog) ? fs.readFileSync(choiceLog, 'utf8')
      .trim().split('\n').filter(Boolean).map(line => JSON.parse(line)) : [];
    assert.ok(feedback.some(page => page.some(item => item.kind === 'xss-reflected' &&
      item.path === renderPath && item.parameter === 'q' &&
      item.as === 'derived' && item.verdict === 'not_reproduced' &&
      Array.isArray(item.evidenceIds))), JSON.stringify({feedback, results: web.results}));
    const lateChoices = choicePages.find(page => page.some(item => item.kind ===
      'xss-reflected' && item.path === renderPath && item.prior?.verdict === 'not_reproduced'));
    assert.ok(lateChoices, JSON.stringify({choicePages, decisions: web.strategyDecisions}));
    const xssIndex = lateChoices.findIndex(item => item.kind === 'xss-reflected' &&
      item.path === renderPath);
    const sstiIndex = lateChoices.findIndex(item => item.kind === 'ssti-arithmetic' &&
      item.path === renderPath);
    assert.ok(sstiIndex >= 0 && sstiIndex < xssIndex,
      'untried SSTI choice should precede the retained negative XSS choice');
    assert.equal(typeof lateChoices[xssIndex].prior.reason, 'string');
    assert.ok(Array.isArray(lateChoices[xssIndex].prior.evidenceIds));
    assert.ok(web.strategyDecisions.some(item => item.verifier?.kind === 'xss-reflected' &&
      item.accepted), 'early Muse choice should run the XSS verifier');
    assert.ok(web.strategyDecisions.some(item => item.verifier?.kind === 'ssti-arithmetic' &&
      item.accepted && item.priorVerifierFactsSent > 0),
    'later Muse choice should receive the XSS-negative feedback');
    const ssti = audit.data.findings.find(item => item.kind === 'ssti-arithmetic' &&
      item.pattern === renderPath);
    assert.ok(ssti?.proof, JSON.stringify({findings: audit.data.findings,
      decisions: web.strategyDecisions, feedback}));
    assert.equal((await cli('verify', audit.data.run)).code, 1);
    const exported = await cli('export', audit.data.run,
      '--out', path.join(root, 'regression'));
    assert.equal(exported.code, 0);
    const regressionEnv = {...env, NODE_TEST_CONTEXT: undefined};
    const regression = async () => await execFile(process.execPath,
      ['--test', ...exported.data.files], {env: regressionEnv, timeout: 30000});
    const vulnerableRegression = await regression();
    assert.equal(vulnerableRegression.code, 1, vulnerableRegression.stdout);
    fs.writeFileSync(path.join(target, 'mode'), 'fixed');
    const fixedSsti = await execFile(process.execPath, [ssti.proof, '--expect-fixed'],
      {env, timeout: 30000});
    assert.equal(fixedSsti.code, 0, fixedSsti.stdout);
    // This fixture's mode switch fixes the rendered expression, not its
    // separately proved lack of login throttling.
    assert.equal((await cli('verify', audit.data.run)).code, 1);
    assert.equal((await regression()).code, 1);
  });
