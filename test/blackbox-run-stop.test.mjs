import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import http from 'node:http';
import {spawn} from 'node:child_process';
import {runAudit} from '../src/blackbox/index.mjs';

test('an audit error leaves a sanitized stop record with its current phase', async t => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'bypass-run-stop-'));
  t.after(() => fs.rmSync(root, {recursive: true, force: true}));
  await assert.rejects(runAudit({url: 'http://127.0.0.1:43997', root,
    overrides: {acceptLocal: true}, noModel: true,
    log: event => {
      if (event.stage === 'progress' && event.type === 'phase' && event.state === 'doing')
        throw new Error('synthetic audit failure');
    }}), /synthetic audit failure/);
  const runs = fs.readdirSync(path.join(root, '.bypass/runs'));
  assert.equal(runs.length, 1);
  const folder = path.join(root, '.bypass/runs', runs[0]);
  const stop = JSON.parse(fs.readFileSync(path.join(folder, 'run-stop.json'), 'utf8'));
  assert.equal(stop.status, 'failed');
  assert.deepEqual(stop.phase, {step: 1, title: 'Scope and host discovery'});
  assert.equal(stop.error.message, 'synthetic audit failure');
  assert.ok(Number.isInteger(stop.evidenceEntries));
  assert.ok(fs.existsSync(path.join(folder, 'run-start.json')));
});

test('SIGTERM leaves an interruption record while a request is pending',
  {timeout: 10000}, async t => {
    const root = fs.mkdtempSync(path.join(os.tmpdir(), 'bypass-run-interrupt-'));
    t.after(() => fs.rmSync(root, {recursive: true, force: true}));
    const server = http.createServer(() => {});
    await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
    t.after(() => new Promise(resolve => server.close(resolve)));
    const origin = `http://127.0.0.1:${server.address().port}`;
    const source = "import {runAudit} from './src/blackbox/index.mjs';" +
      "await runAudit({url:process.env.BX_ORIGIN,root:process.env.BX_ROOT," +
      "overrides:{acceptLocal:true},noModel:true,log:event=>{" +
      "if(event.type==='phase'&&event.state==='doing')console.log('READY')}});";
    const child = spawn(process.execPath, ['--input-type=module', '-e', source], {
      cwd: path.resolve('.'), env: {...process.env, BX_ORIGIN: origin, BX_ROOT: root},
      stdio: ['ignore', 'pipe', 'pipe'],
    });
    t.after(() => {if (child.exitCode == null) child.kill('SIGKILL');});
    await new Promise((resolve, reject) => {
      let output = '';
      const timeout = setTimeout(() => reject(new Error('audit did not start')), 5000);
      child.stdout.on('data', chunk => {
        output += chunk;
        if (output.includes('READY')) {clearTimeout(timeout); resolve();}
      });
      child.on('exit', (code, signal) => {
        clearTimeout(timeout);
        reject(new Error(`audit exited before signal: ${code} ${signal}`));
      });
    });
    child.kill('SIGTERM');
    const exit = await new Promise(resolve => child.on('exit', (code, signal) =>
      resolve({code, signal})));
    assert.equal(exit.signal, 'SIGTERM');
    const run = fs.readdirSync(path.join(root, '.bypass/runs'))[0];
    const stop = JSON.parse(fs.readFileSync(path.join(root, '.bypass/runs', run,
      'run-stop.json'), 'utf8'));
    assert.equal(stop.status, 'interrupted');
    assert.equal(stop.signal, 'SIGTERM');
    assert.ok(stop.phase.step >= 1 && stop.phase.step <= 6);
  });
