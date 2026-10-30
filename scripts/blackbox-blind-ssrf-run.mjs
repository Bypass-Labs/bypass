#!/usr/bin/env node
// Real Muse + actual CLI blind SSRF check. META_API_KEY stays in this shell.
import fs from 'node:fs';
import http from 'node:http';
import os from 'node:os';
import path from 'node:path';
import {spawn} from 'node:child_process';
import {randomBytes} from 'node:crypto';
import {fileURLToPath} from 'node:url';
import {execFile} from '../src/util.mjs';

const existingIndex = process.argv.indexOf('--existing');
const existingRunDir = existingIndex >= 0 ? path.resolve(process.argv[existingIndex + 1] ?? '') : null;
if (!existingRunDir && !process.env.META_API_KEY) {
  process.stderr.write('Set META_API_KEY privately before this live check.\n');
  process.exit(2);
}
const repository = path.dirname(path.dirname(fileURLToPath(import.meta.url)));
const project = existingRunDir ? path.dirname(path.dirname(path.dirname(existingRunDir))) :
  path.join(repository, '.tmp', `blind-ssrf-${randomBytes(4).toString('hex')}`);
const id = path.basename(project).replace(/^blind-ssrf-/, '');
if (!/^[a-f0-9]{8}$/.test(id)) throw new Error('Existing run must belong to a blind-ssrf-<8hex> project.');
const savedRun = existingRunDir ? JSON.parse(fs.readFileSync(path.join(existingRunDir, 'run.json'), 'utf8')) : null;
const privateDir = fs.mkdtempSync(path.join(os.tmpdir(), 'bypass-blind-ssrf-'));
const scopeFile = path.join(privateDir, 'scope.json');
const decoyFile = path.join(privateDir, 'decoy');
const fixture = path.join(repository, 'scripts', 'blackbox-blind-ssrf-fixture.mjs');
const cli = path.join(repository, 'bin', 'bypass.mjs');
fs.mkdirSync(project, {recursive: true, mode: 0o700});
const fixtureEnv = Object.fromEntries(Object.entries(process.env).filter(([name]) =>
  name !== 'META_API_KEY' && name !== 'OWNER_TOKEN' && name !== 'OTHER_TOKEN'));
const assert = (ok, message) => {if (!ok) throw new Error(message);};

function startFixture({fixed = false, port = 0} = {}) {
  return new Promise((resolve, reject) => {
    const args = [fixture, '--id', id, '--port', String(port), '--scope', scopeFile,
      '--decoy-file', decoyFile];
    if (fixed) args.push('--fixed');
    const child = spawn(process.execPath, args, {cwd: repository, env: fixtureEnv,
      stdio: ['ignore', 'pipe', 'pipe']});
    let output = '', error = '', settled = false;
    const timer = setTimeout(() => {
      if (!settled) {settled = true; child.kill('SIGTERM'); reject(new Error('Fixture timed out'));}
    }, 10000);
    child.stdout.on('data', chunk => {
      output += chunk;
      if (!settled && output.includes('\n')) {
        settled = true; clearTimeout(timer);
        try {resolve({child, info: JSON.parse(output.split('\n')[0])});}
        catch (cause) {child.kill('SIGTERM'); reject(cause);}
      }
    });
    child.stderr.on('data', chunk => {error += chunk;});
    child.once('error', cause => {if (!settled) {settled = true; clearTimeout(timer); reject(cause);}});
    child.once('close', code => {if (!settled) {settled = true; clearTimeout(timer);
      reject(new Error(`Fixture exited ${code}: ${error.slice(0, 300)}`));}});
  });
}
const stopFixture = ({child}) => new Promise(resolve => {
  if (child.exitCode !== null) return resolve();
  child.once('close', resolve);
  child.kill('SIGTERM');
});
async function call(...args) {
  const result = await execFile(process.execPath, [cli, 'blackbox', ...args,
    '--project', project, '--json', '--non-interactive'],
  {cwd: repository, env: process.env, timeout: 8 * 60_000});
  let data;
  try {data = JSON.parse(result.stdout);} catch {
    throw new Error(`CLI returned non-JSON (exit ${result.code}): ${result.stderr.slice(0, 500)}`);
  }
  return {code: result.code, data};
}
const regression = file => execFile(process.execPath, ['--test', file],
  {cwd: repository, env: Object.fromEntries(Object.entries(process.env).filter(([name]) =>
    name !== 'NODE_TEST_CONTEXT')), timeout: 30000});

let vulnerable, callback;
try {
  vulnerable = await startFixture({port: savedRun ? Number(new URL(savedRun.scope.target.origin).port) : 0});
  const {origin, route, parameter, decoy} = vulnerable.info;
  const token = randomBytes(12).toString('hex');
  let hits = 0, received;
  const hit = new Promise(resolve => {received = resolve;});
  callback = http.createServer((request, response) => {
    if (request.url === `/bx-ssrf/${token}`) {hits++; received();}
    response.writeHead(204); response.end();
  });
  await new Promise(resolve => callback.listen(0, '127.0.0.1', resolve));
  const canary = `http://127.0.0.1:${callback.address().port}/bx-ssrf/${token}`;
  const manual = new URL(route, origin);
  manual.searchParams.set(parameter, canary);
  const baseline = await fetch(manual);
  await Promise.race([hit, new Promise(resolve => setTimeout(resolve, 1500))]);
  assert(baseline.status === 200 && hits === 1, 'Vulnerable fixture did not fetch a local callback');

  const audit = existingRunDir ? {code: 1, data: {run: savedRun.run,
    runDir: existingRunDir, findings: JSON.parse(fs.readFileSync(path.join(existingRunDir, 'findings.json'), 'utf8'))}} :
    await call(origin, '--scope', scopeFile, '--rps', '20', '--offline');
  const runDir = audit.data.runDir;
  assert(typeof runDir === 'string',
    `Audit returned no runDir (exit ${audit.code}): ${JSON.stringify(audit.data).slice(0, 1000)}`);
  const run = JSON.parse(fs.readFileSync(path.join(runDir, 'run.json'), 'utf8'));
  const surface = JSON.parse(fs.readFileSync(path.join(runDir, 'surface.json'), 'utf8'));
  const web = JSON.parse(fs.readFileSync(path.join(runDir, 'web-probes.json'), 'utf8'));
  const finding = audit.data.findings?.find(item => item.verdict === 'confirmed' &&
    item.kind === 'ssrf-loopback' && item.pattern === route && item.proof);
  assert(run.stats.modelCalls > 0, 'Real Muse was not called');
  assert(surface.patterns?.some(item => item.pattern === route &&
    Object.hasOwn(item.params ?? {}, parameter)), 'The SSRF route and parameter were not observed');
  assert(web.strategyDecisions?.some(item => item.family === 'ssrf-loopback' &&
    item.path === route && item.parameter === parameter && item.accepted),
  'Muse did not select the SSRF strategy');
  assert(web.plan?.some(item => item.kind === 'ssrf-loopback' && item.path === route &&
    item.parameter === parameter && item.by === 'model' && item.basis === 'model-strategy'),
  'Muse-selected SSRF strategy did not enter the task queue');
  assert(audit.code === 1 && finding, `No proved SSRF in ${runDir}`);
  const ledgerRows = fs.readFileSync(path.join(runDir, 'evidence.jsonl'), 'utf8')
    .trim().split('\n').map(JSON.parse);
  assert(fs.readFileSync(decoyFile, 'utf8').trim() === '0' &&
    !ledgerRows.some(item => item.request?.url?.includes(decoy)),
  'Protected decoy was requested');
  const firstVerify = await call('verify', audit.data.run);
  assert(firstVerify.code === 1 && firstVerify.data.proofs?.some(item =>
    item.id === finding.id && item.verdict === 'confirmed'), 'Saved proof did not reproduce');
  const exported = await call('export', audit.data.run, '--out', path.join(project, 'regression'));
  const testFile = exported.data.files?.find(file => file.endsWith(`-${finding.id}.test.mjs`));
  assert(exported.code === 0 && testFile, 'Regression export failed');
  assert((await regression(testFile)).code === 1, 'Regression should fail while vulnerable');
  await stopFixture(vulnerable);
  vulnerable = null;
  const fixed = await startFixture({fixed: true, port: Number(new URL(origin).port)});
  try {
    const fixedVerify = await call('verify', audit.data.run);
    assert(fixedVerify.code === 0 && fixedVerify.data.proofs?.some(item =>
      item.id === finding.id && item.verdict === 'not_reproduced'),
    'Saved proof did not clear after loopback was blocked');
    assert((await regression(testFile)).code === 0, 'Regression should pass after fix');
    assert(fs.readFileSync(decoyFile, 'utf8').trim() === '0', 'Fixed decoy was requested');
    process.stdout.write(`${JSON.stringify({ok: true, run: audit.data.run, runDir,
      finding: {id: finding.id, kind: finding.kind, pattern: finding.pattern},
      modelCalls: run.stats.modelCalls, requests: run.stats.requests,
      verify: ['confirmed', 'not_reproduced'], regression: ['red', 'green']})}\n`);
  } finally {await stopFixture(fixed);}
} catch (error) {
  process.stderr.write(`${error.message}\nProject: ${project}\n`);
  process.exitCode = 1;
} finally {
  if (vulnerable) await stopFixture(vulnerable);
  if (callback) await new Promise(resolve => callback.close(resolve));
}
