import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import {spawn} from 'node:child_process';

const fixture = path.join(import.meta.dirname,
  'fixtures/blackbox-protected-sql-blind.mjs');

async function start(root, port = 0) {
  const child = spawn(process.execPath, [fixture, root], {
    env: {...process.env, BX_FIXTURE_PORT: String(port)},
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  const origin = await new Promise((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error('Fixture start timed out')), 5000);
    child.stdout.once('data', chunk => {
      clearTimeout(timer);
      resolve(String(chunk).trim());
    });
    child.once('error', reject);
    child.once('exit', code => reject(new Error(`Fixture exited ${code}`)));
  });
  return {child, origin};
}

async function stop(child) {
  if (child.exitCode !== null) return;
  const closed = new Promise(resolve => child.once('exit', resolve));
  child.kill('SIGTERM');
  await closed;
}

test('protected blind fixture restarts on the same origin with the same random routes',
  {timeout: 20000}, async t => {
    const root = fs.mkdtempSync(path.join(os.tmpdir(), 'bypass-protected-restart-'));
    t.after(() => fs.rmSync(root, {recursive: true, force: true}));
    const first = await start(root);
    t.after(() => first.child.kill('SIGTERM'));
    const firstPaths = Object.keys((await (await fetch(`${first.origin}/openapi.json`)).json()).paths);
    const savedSuffix = fs.readFileSync(path.join(root, 'route-suffix'), 'utf8').trim();
    assert.match(savedSuffix, /^[0-9a-f]{10}$/);
    await stop(first.child);

    const second = await start(root, Number(new URL(first.origin).port));
    t.after(() => second.child.kill('SIGTERM'));
    assert.equal(second.origin, first.origin);
    assert.deepEqual(Object.keys((await (await fetch(`${second.origin}/openapi.json`)).json()).paths),
      firstPaths);
    assert.equal(fs.readFileSync(path.join(root, 'route-suffix'), 'utf8').trim(), savedSuffix);
    await stop(second.child);

    // Keep the login fixture available while isolating the fixed HTML renderer.
    fs.writeFileSync(path.join(root, 'mode'), 'fixed-html');
    const third = await start(root, Number(new URL(first.origin).port));
    t.after(() => third.child.kill('SIGTERM'));
    const loginPath = firstPaths.find(item => item.startsWith('/api/login-'));
    const login = await fetch(`${third.origin}${loginPath}`, {method: 'POST',
      headers: {'content-type': 'application/json'}, body: JSON.stringify({
        username: "admin' OR '1'='1", password: `bx-invalid-${'a'.repeat(24)}`})});
    assert.equal(login.status, 200);
    const token = (await login.json()).authentication.token;
    const injection = '<svg onload=alert(1)>';
    const render = new URL(`/api/${savedSuffix}/render`, third.origin);
    render.searchParams.set('q', injection);
    const response = await fetch(render, {headers: {authorization: `Bearer ${token}`}});
    assert.equal(response.status, 200);
    const body = await response.text();
    assert.ok(body.includes('&lt;svg onload=alert(1)&gt;'));
    assert.ok(!body.includes(injection));
    await stop(third.child);
  });
