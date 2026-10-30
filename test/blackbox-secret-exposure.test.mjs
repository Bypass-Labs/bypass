import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import http from 'node:http';
import path from 'node:path';
import {spawn} from 'node:child_process';
import {createHash, generateKeyPairSync, randomBytes} from 'node:crypto';
import {temp} from './helpers.mjs';
import {execFile} from '../src/util.mjs';
import {CLI} from '../src/demo.mjs';
import {publicPrivateKeyFingerprints, publicCredentialFingerprints} from '../src/blackbox/poc-runtime.mjs';

function randomCredential() {
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
  return `ghp_${[...randomBytes(36)].map(byte => alphabet[byte % alphabet.length]).join('')}`;
}

test('private-key oracle requires a complete parseable key and understands source-map content', () => {
  const pem = generateKeyPairSync('ed25519').privateKey.export({format: 'pem', type: 'pkcs8'}).toString();
  const fingerprint = publicPrivateKeyFingerprints(pem)[0];
  assert.match(fingerprint, /^sha256:[0-9a-f]{64}$/);
  assert.deepEqual(publicPrivateKeyFingerprints(`export const key = \`${pem}\`;`), [fingerprint]);
  assert.deepEqual(publicPrivateKeyFingerprints(JSON.stringify({sourcesContent: [pem]})), [fingerprint]);
  assert.deepEqual(publicPrivateKeyFingerprints(JSON.stringify({
    sourcesContent: [...Array(205).fill('export const safe = true;'), pem]})),
  [fingerprint], 'proof replay must inspect a source-map original after the former 200-entry cap');
  assert.deepEqual(publicPrivateKeyFingerprints('-----BEGIN PRIVATE KEY-----\nfake\n-----END PRIVATE KEY-----'), []);
  assert.deepEqual(publicPrivateKeyFingerprints('-----BEGIN PRIVATE KEY-----'), []);
});

test('actual CLI proves a public private-key leak and its regression clears after removal', async t => {
  const root = temp();
  t.after(() => fs.rmSync(root, {recursive: true, force: true}));
  const pem = generateKeyPairSync('ed25519').privateKey.export({format: 'pem', type: 'pkcs8'}).toString();
  const keyLine = pem.split('\n').find(line => /^[A-Za-z0-9+/=]{30,}$/.test(line));
  assert.ok(keyLine);
  let vulnerable = true;
  const requested = [];
  const server = http.createServer((request, response) => {
    const pathname = new URL(request.url, 'http://local').pathname;
    requested.push(pathname);
    if (pathname === '/') {
      response.writeHead(200, {'content-type': 'text/html'});
      return response.end('<html><script src="/assets/app.js"></script><script src="/assets/fake.js"></script></html>');
    }
    if (pathname === '/assets/app.js') {
      response.writeHead(200, {'content-type': 'application/javascript', 'cache-control': 'no-store'});
      return response.end((vulnerable ? `export const key = \`${pem}\`;` : 'export const key = null;') +
        "\nexport const protectedUrl = '/api/delete';");
    }
    if (pathname === '/assets/fake.js') {
      response.writeHead(200, {'content-type': 'application/javascript', 'cache-control': 'no-store'});
      return response.end('export const decoy = `-----BEGIN PRIVATE KEY-----\\nfake\\n-----END PRIVATE KEY-----`;');
    }
    if (pathname === '/api/delete') {
      response.writeHead(500);
      return response.end('Protected decoy');
    }
    response.writeHead(404);
    response.end();
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  t.after(() => new Promise(resolve => server.close(resolve)));
  const origin = `http://127.0.0.1:${server.address().port}`;
  const cli = async (...args) => {
    const done = await execFile(process.execPath,
      [CLI, 'blackbox', ...args, '--project', root, '--json', '--non-interactive'],
      {cwd: root, timeout: 90000});
    return {code: done.code, data: JSON.parse(done.stdout)};
  };
  const audit = await cli(origin, '--accept-local', '--no-model');
  assert.equal(audit.code, 1, JSON.stringify(audit.data));
  const findings = audit.data.findings.filter(item => item.kind === 'public-private-key');
  assert.equal(findings.length, 1, JSON.stringify(audit.data.findings));
  const finding = findings[0];
  assert.equal(finding.pattern, '/assets/app.js');
  assert.ok(fs.existsSync(finding.proof));
  assert.equal(audit.data.coverage.requestedClasses.find(item => item.name === 'Secret Leakage').status, 'partial');
  const apiKey = audit.data.coverage.requestedClasses.find(item => item.name === 'API Key Exposure');
  assert.equal(apiKey.status, 'not tested');
  assert.match(apiKey.reason, /validity and privileges were not checked/);
  const web = JSON.parse(fs.readFileSync(path.join(audit.data.runDir, 'web-probes.json'), 'utf8'));
  assert.ok(web.results.some(item => item.kind === 'public-private-key' && item.lead.path === '/assets/fake.js' &&
    item.verdict === 'not_reproduced'));
  for (const file of ['assets.json', 'findings.json', 'evidence.jsonl', 'poc/f-001/spec.json']) {
    const saved = fs.readFileSync(path.join(audit.data.runDir, file), 'utf8');
    assert.ok(!saved.includes(pem), `${file} stored the private key`);
    assert.ok(!saved.includes(keyLine), `${file} stored private-key material`);
  }
  assert.ok(!requested.includes('/api/delete'));
  assert.equal((await cli('verify', audit.data.run)).code, 1);
  const exported = await cli('export', audit.data.run, '--out', path.join(root, 'regressions'));
  assert.equal(exported.code, 0);
  const runExport = () => new Promise((resolve, reject) => {
    const child = spawn(process.execPath, ['--test', ...exported.data.files],
      {env: Object.fromEntries(Object.entries(process.env).filter(([key]) => key !== 'NODE_TEST_CONTEXT')),
        stdio: 'ignore'});
    child.once('error', reject);
    child.once('close', resolve);
  });
  assert.equal(await runExport(), 1);
  vulnerable = false;
  assert.equal((await cli('verify', audit.data.run)).code, 0);
  assert.equal(await runExport(), 0);
  const fixed = await cli(origin, '--accept-local', '--no-model');
  assert.ok(!fixed.data.findings.some(item => item.kind === 'public-private-key'));
});

test('actual CLI proves a private key exposed only through source-map content', async t => {
  const root = temp();
  t.after(() => fs.rmSync(root, {recursive: true, force: true}));
  const pem = generateKeyPairSync('ed25519').privateKey.export({format: 'pem', type: 'pkcs8'}).toString();
  let vulnerable = true;
  const server = http.createServer((request, response) => {
    const pathname = new URL(request.url, 'http://local').pathname;
    if (pathname === '/') {
      response.writeHead(200, {'content-type': 'text/html'});
      return response.end('<html><script src="/assets/app.js"></script></html>');
    }
    if (pathname === '/assets/app.js') {
      response.writeHead(200, {'content-type': 'application/javascript'});
      return response.end("console.log('safe');\n//# sourceMappingURL=app.js.map");
    }
    if (pathname === '/assets/app.js.map') {
      response.writeHead(200, {'content-type': 'application/json', 'cache-control': 'no-store'});
      const vendors = Array.from({length: 205}, (_, index) =>
        `node_modules/dependency-${index}/index.js`);
      return response.end(JSON.stringify({version: 3,
        sources: [...vendors, 'src/key.js'], mappings: '',
        sourcesContent: [...vendors.map(() => 'export const safe = true;'),
          vulnerable ? `export const key = \`${pem}\`;` : 'export const key = null;']}));
    }
    response.writeHead(404);
    response.end();
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  t.after(() => new Promise(resolve => server.close(resolve)));
  const origin = `http://127.0.0.1:${server.address().port}`;
  const cli = async (...args) => {
    const done = await execFile(process.execPath,
      [CLI, 'blackbox', ...args, '--project', root, '--json', '--non-interactive'],
      {cwd: root, timeout: 90000});
    return {code: done.code, data: JSON.parse(done.stdout)};
  };
  const audit = await cli(origin, '--accept-local', '--no-model');
  assert.equal(audit.code, 1, JSON.stringify(audit.data));
  const finding = audit.data.findings.find(item => item.kind === 'public-private-key');
  assert.equal(finding?.pattern, '/assets/app.js.map');
  assert.ok(fs.existsSync(finding.proof));
  assert.equal((await cli('verify', audit.data.run)).code, 1);
  vulnerable = false;
  assert.equal((await cli('verify', audit.data.run)).code, 0);
  const fixed = await cli(origin, '--accept-local', '--no-model');
  assert.ok(!fixed.data.findings.some(item => item.kind === 'public-private-key'));
});

test('public credential oracle rejects placeholders and public key prefixes', () => {
  const token = randomCredential();
  const stripe = `sk_live_${randomBytes(24).toString('hex')}`;
  const sendgrid = `SG.${randomBytes(16).toString('base64url')}.${randomBytes(32).toString('base64url')}`;
  assert.deepEqual(publicCredentialFingerprints(`const key = '${token}';`),
    [{name: 'github-token', fingerprint: `sha256:${createHash('sha256').update(token).digest('hex')}`}]);
  assert.deepEqual(publicCredentialFingerprints(`${stripe} ${sendgrid}`).map(item => item.name),
    ['stripe-secret-key', 'sendgrid-key']);
  assert.deepEqual(publicCredentialFingerprints(`const key = 'ghp_${'A'.repeat(36)}';`), []);
  assert.deepEqual(publicCredentialFingerprints(`const key = 'pk_live_${randomBytes(20).toString('hex')}';`), []);
  assert.deepEqual(publicCredentialFingerprints('sk_live_abcdefghijklmnopqrstuvwxyz012345'), []);
});

test('actual CLI proves a public API credential and its regression clears after removal', async t => {
  const root = temp();
  t.after(() => fs.rmSync(root, {recursive: true, force: true}));
  const token = randomCredential();
  const suffix = randomBytes(5).toString('hex');
  const asset = `/assets/client-${suffix}.js`;
  const fake = `/assets/placeholder-${suffix}.js`;
  let vulnerable = true;
  const requested = [];
  const server = http.createServer((request, response) => {
    const pathname = new URL(request.url, 'http://local').pathname;
    requested.push(pathname);
    if (pathname === '/') {
      response.writeHead(200, {'content-type': 'text/html'});
      return response.end(`<html><script src="${asset}"></script><script src="${fake}"></script></html>`);
    }
    if (pathname === asset) {
      response.writeHead(200, {'content-type': 'application/javascript', 'cache-control': 'no-store'});
      return response.end(vulnerable ? `export const apiToken = '${token}';` : 'export const apiToken = null;');
    }
    if (pathname === fake) {
      response.writeHead(200, {'content-type': 'application/javascript', 'cache-control': 'no-store'});
      return response.end(`export const decoy = 'ghp_${'A'.repeat(36)}';\n` +
        `export const publicKey = 'pk_live_${randomBytes(20).toString('hex')}';`);
    }
    if (pathname === '/api/delete') {
      response.writeHead(500);
      return response.end('Protected decoy');
    }
    response.writeHead(404);
    response.end();
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  t.after(() => new Promise(resolve => server.close(resolve)));
  const origin = `http://127.0.0.1:${server.address().port}`;
  const cli = async (...args) => {
    const done = await execFile(process.execPath,
      [CLI, 'blackbox', ...args, '--project', root, '--json', '--non-interactive'],
      {cwd: root, timeout: 90000});
    return {code: done.code, data: JSON.parse(done.stdout)};
  };
  const prepared = await cli('scope', origin, '--include', '/api');
  assert.equal(prepared.code, 0);
  const audit = await cli(origin, '--accept-local', '--no-model');
  assert.equal(audit.code, 1, JSON.stringify(audit.data.findings));
  const finding = audit.data.findings.find(item => item.kind === 'public-api-credential');
  assert.equal(finding?.pattern, asset);
  assert.ok(fs.existsSync(finding.proof));
  assert.equal(audit.data.coverage.requestedClasses.find(item => item.name === 'API Key Exposure').status,
    'partial');
  const web = JSON.parse(fs.readFileSync(path.join(audit.data.runDir, 'web-probes.json'), 'utf8'));
  assert.ok(web.results.some(item => item.kind === 'public-api-credential' && item.lead.path === fake &&
    item.verdict === 'not_reproduced'));
  for (const file of ['assets.json', 'findings.json', 'evidence.jsonl', 'web-probes.json',
    'poc/f-001/spec.json', 'report.md']) {
    const saved = fs.readFileSync(path.join(audit.data.runDir, file), 'utf8');
    assert.ok(!saved.includes(token), `${file} stored the credential`);
  }
  assert.ok(!requested.includes('/api/delete'));
  assert.equal((await cli('verify', audit.data.run)).code, 1);
  const exported = await cli('export', audit.data.run, '--out', path.join(root, 'regressions'));
  assert.equal(exported.code, 0);
  const runExport = () => new Promise((resolve, reject) => {
    const child = spawn(process.execPath, ['--test', ...exported.data.files],
      {env: Object.fromEntries(Object.entries(process.env).filter(([key]) => key !== 'NODE_TEST_CONTEXT')),
        stdio: 'ignore'});
    child.once('error', reject);
    child.once('close', resolve);
  });
  assert.equal(await runExport(), 1);
  vulnerable = false;
  assert.equal((await cli('verify', audit.data.run)).code, 0);
  assert.equal(await runExport(), 0);
  const fixed = await cli(origin, '--accept-local', '--no-model');
  assert.ok(!fixed.data.findings.some(item => item.kind === 'public-api-credential'));
  assert.ok(!requested.includes('/api/delete'));
});

test('actual CLI finds a credential exposed only through source-map content', async t => {
  const root = temp();
  t.after(() => fs.rmSync(root, {recursive: true, force: true}));
  const token = randomCredential();
  let vulnerable = true;
  const server = http.createServer((request, response) => {
    const pathname = new URL(request.url, 'http://local').pathname;
    if (pathname === '/') {
      response.writeHead(200, {'content-type': 'text/html'});
      return response.end('<html><script src="/assets/client.js"></script></html>');
    }
    if (pathname === '/assets/client.js') {
      response.writeHead(200, {'content-type': 'application/javascript'});
      return response.end("console.log('client');\n//# sourceMappingURL=client.js.map");
    }
    if (pathname === '/assets/client.js.map') {
      response.writeHead(200, {'content-type': 'application/json', 'cache-control': 'no-store'});
      return response.end(JSON.stringify({version: 3, sources: ['src/client.js'], mappings: '',
        sourcesContent: [vulnerable ? `export const apiToken = '${token}';` :
          'export const apiToken = null;']}));
    }
    response.writeHead(404);
    response.end();
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  t.after(() => new Promise(resolve => server.close(resolve)));
  const origin = `http://127.0.0.1:${server.address().port}`;
  const cli = async (...args) => {
    const done = await execFile(process.execPath,
      [CLI, 'blackbox', ...args, '--project', root, '--json', '--non-interactive'],
      {cwd: root, timeout: 90000});
    return {code: done.code, data: JSON.parse(done.stdout)};
  };
  const audit = await cli(origin, '--accept-local', '--no-model');
  assert.equal(audit.code, 1, JSON.stringify(audit.data.findings));
  const finding = audit.data.findings.find(item => item.kind === 'public-api-credential');
  assert.equal(finding?.pattern, '/assets/client.js.map');
  assert.ok(fs.existsSync(finding.proof));
  const artifacts = ['assets.json', 'findings.json', 'evidence.jsonl', 'web-probes.json',
    'poc/f-001/spec.json', 'report.md'];
  for (const file of artifacts)
    assert.ok(!fs.readFileSync(path.join(audit.data.runDir, file), 'utf8').includes(token),
      `${file} stored the credential`);
  assert.equal((await cli('verify', audit.data.run)).code, 1);
  vulnerable = false;
  assert.equal((await cli('verify', audit.data.run)).code, 0);
  const fixed = await cli(origin, '--accept-local', '--no-model');
  assert.ok(!fixed.data.findings.some(item => item.kind === 'public-api-credential'));
});
