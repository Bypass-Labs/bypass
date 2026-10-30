#!/usr/bin/env node
// Real Muse + CLI acceptance check. Requires META_API_KEY in this shell.
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import {spawn} from 'node:child_process';
import {randomBytes} from 'node:crypto';
import {fileURLToPath} from 'node:url';
import {execFile} from '../src/util.mjs';

if (!process.env.META_API_KEY) {
  process.stderr.write('Set META_API_KEY privately before running this live check.\n');
  process.exit(2);
}

const repository = path.dirname(path.dirname(fileURLToPath(import.meta.url)));
const id = randomBytes(4).toString('hex');
const project = path.join(repository, '.tmp', `blind-boundary-${id}`);
const secrets = fs.mkdtempSync(path.join(os.tmpdir(), 'bypass-blind-boundary-'));
const scopeFile = path.join(secrets, 'scope.json');
const authFile = path.join(secrets, 'owner');
const decoyFile = path.join(secrets, 'decoy-count');
fs.mkdirSync(project, {recursive: true, mode: 0o700});
const fixture = path.join(repository, 'scripts', 'blackbox-blind-post-fixture.mjs');
const cli = path.join(repository, 'bin', 'bypass.mjs');
const fixtureEnv = Object.fromEntries(Object.entries(process.env).filter(([name]) =>
  name !== 'META_API_KEY' && name !== 'OWNER_TOKEN'));

function startFixture({fixed = false, port = 0} = {}) {
  return new Promise((resolve, reject) => {
    const args = [fixture, '--id', id, '--port', String(port), '--scope', scopeFile,
      '--auth-file', authFile, '--decoy-file', decoyFile];
    if (fixed) args.push('--fixed');
    const child = spawn(process.execPath, args, {cwd: repository,
      env: fixtureEnv, stdio: ['ignore', 'pipe', 'pipe']});
    let line = '', error = '', settled = false;
    const timeout = setTimeout(() => {
      if (!settled) {settled = true; child.kill('SIGTERM'); reject(new Error('Fixture start timed out'));}
    }, 10000);
    child.stderr.on('data', chunk => {error += chunk.toString();});
    child.stdout.on('data', chunk => {
      line += chunk.toString();
      if (!settled && line.includes('\n')) {
        settled = true;
        clearTimeout(timeout);
        try {resolve({child, info: JSON.parse(line.split('\n')[0])});}
        catch (cause) {child.kill('SIGTERM'); reject(cause);}
      }
    });
    child.once('error', cause => {if (!settled) {settled = true; clearTimeout(timeout); reject(cause);}});
    child.once('close', code => {if (!settled) {settled = true; clearTimeout(timeout);
      reject(new Error(`Fixture exited ${code}: ${error.slice(0, 300)}`));}});
  });
}

const stopFixture = ({child}) => new Promise(resolve => {
  if (child.exitCode !== null) return resolve();
  child.once('close', resolve);
  child.kill('SIGTERM');
});
const call = async (env, ...args) => {
  const result = await execFile(process.execPath, [cli, 'blackbox', ...args,
    '--project', project, '--json', '--non-interactive'],
  {cwd: repository, env, timeout: 8 * 60_000});
  let data;
  try {data = JSON.parse(result.stdout);} catch {
    throw new Error(`CLI did not return JSON (exit ${result.code}): ${result.stderr.slice(0, 500)}`);
  }
  return {code: result.code, data};
};
const regression = (file, env) => execFile(process.execPath, ['--test', file],
  {cwd: repository, env: Object.fromEntries(Object.entries(env).filter(([name]) =>
    name !== 'NODE_TEST_CONTEXT')), timeout: 30000});
const assert = (condition, message) => {if (!condition) throw new Error(message);};

let vulnerable;
try {
  vulnerable = await startFixture();
  const {origin, searchPath, privatePath, privateId, decoy} = vulnerable.info;
  const ownerToken = fs.readFileSync(authFile, 'utf8').trim();
  const env = {...process.env, OWNER_TOKEN: ownerToken};
  const publicRead = await fetch(`${origin}${privatePath}`);
  const ownerRead = await fetch(`${origin}${privatePath}`,
    {headers: {authorization: `Bearer ${ownerToken}`}});
  const injected = await fetch(`${origin}${searchPath}`, {method: 'POST',
    headers: {'content-type': 'application/json'},
    body: JSON.stringify({term: "' OR 1=1 -- "})});
  const leaked = await injected.json();
  assert(publicRead.status === 403 && ownerRead.status === 200 &&
    leaked.records?.some(row => row.id === privateId), 'Fixture boundary is not vulnerable');

  const audit = await call(env, origin, '--scope', scopeFile, '--rps', '20', '--offline');
  const runDir = audit.data.runDir;
  assert(typeof runDir === 'string',
    `Audit returned no runDir (exit ${audit.code}): ${JSON.stringify(audit.data).slice(0, 1200)}`);
  const run = JSON.parse(fs.readFileSync(path.join(runDir, 'run.json'), 'utf8'));
  const web = JSON.parse(fs.readFileSync(path.join(runDir, 'web-probes.json'), 'utf8'));
  const finding = audit.data.findings?.find(item => item.verdict === 'confirmed' &&
    item.pattern === searchPath && item.proof && item.webProof?.request?.method === 'POST');
  assert(audit.code === 1, `Audit exited ${audit.code} without a confirmed bug`);
  assert(run.stats.modelCalls > 0, 'No real Muse calls were recorded');
  assert(web.strategyDecisions?.some(item =>
    item.mode === 'access-boundary' && item.accepted), 'Muse did not select the boundary test');
  assert(finding, `No confirmed POST finding on ${searchPath}; inspect ${runDir}`);
  assert(fs.readFileSync(decoyFile, 'utf8').trim() === '0' &&
    !fs.readFileSync(path.join(runDir, 'evidence.jsonl'), 'utf8').includes(decoy),
  'Protected decoy was requested');
  const firstVerify = await call(env, 'verify', audit.data.run);
  assert(firstVerify.code === 1 && firstVerify.data.proofs?.some(item =>
    item.id === finding.id && item.verdict === 'confirmed'), 'Saved proof did not reproduce');
  const exported = await call(env, 'export', audit.data.run, '--out', path.join(project, 'regression'));
  const testFile = exported.data.files?.find(file => file.endsWith(`-${finding.id}.test.mjs`));
  assert(exported.code === 0 && testFile, 'Regression export failed');
  const red = await regression(testFile, env);
  assert(red.code === 1, 'Regression should fail while vulnerable');

  await stopFixture(vulnerable);
  vulnerable = null;
  const fixed = await startFixture({fixed: true, port: Number(new URL(origin).port)});
  try {
    const secondVerify = await call(env, 'verify', audit.data.run);
    const green = await regression(testFile, env);
    assert(secondVerify.code === 0 && secondVerify.data.proofs?.some(item =>
      item.id === finding.id && item.verdict === 'not_reproduced'),
    'Saved proof did not clear after the fix');
    assert(green.code === 0, 'Regression should pass after the fix');
    assert(fs.readFileSync(decoyFile, 'utf8').trim() === '0', 'Fixed decoy was requested');
    process.stdout.write(`${JSON.stringify({ok: true, run: audit.data.run, runDir,
      finding: {id: finding.id, kind: finding.kind, pattern: finding.pattern},
      modelCalls: run.stats.modelCalls, requests: run.stats.requests,
      decisions: web.strategyDecisions?.length ?? 0,
      verify: ['confirmed', 'not_reproduced'], regression: ['red', 'green']})}\n`);
  } finally {await stopFixture(fixed);}
} catch (error) {
  process.stderr.write(`${error.message}\nProject: ${project}\n`);
  process.exitCode = 1;
} finally {
  if (vulnerable) await stopFixture(vulnerable);
}
