import test from 'node:test';
import assert from 'node:assert/strict';
import {additionalSensitivePathEntries, selectSensitivePathEntries} from '../src/blackbox/sensitive-path-catalog.mjs';

const entry = path => additionalSensitivePathEntries.find(item => item.path === path);

test('catalog keeps broad leads distinct and signatures reject a catch-all page', () => {
  assert.ok(additionalSensitivePathEntries.length > 150);
  assert.equal(new Set(additionalSensitivePathEntries.map(item => item.path)).size,
    additionalSensitivePathEntries.length);
  for (const path of ['/.env.local', '/.aws/credentials', '/config/database.yml', '/wp-config.php.bak',
    '/storage/logs/laravel.log', '/sites/default/settings.php', '/app/etc/env.php', '/backup.sql.gz'])
    assert.ok(entry(path), `${path} is present`);
  for (const item of additionalSensitivePathEntries)
    assert.equal(item.matches('<!doctype html><html><title>App</title></html>', 'text/html'), false,
      `${item.path} must reject a generic HTML fallback`);
});

test('configuration candidates require secret-bearing values, not just a key name or status', () => {
  assert.equal(entry('/.env.local').matches('NODE_ENV=production\nAPP_NAME=shop', 'text/plain'), false);
  assert.equal(entry('/.env.local').matches('APP_KEY=replace-with-secret-value', 'text/plain'), true);
  assert.equal(entry('/config/database.yml').matches('database: example\nhost: localhost', 'text/plain'), false);
  assert.equal(entry('/config/database.yml').matches('database:\n  password: actual-test-secret-123', 'text/plain'), true);
  assert.equal(entry('/appsettings.json').matches('{"ConnectionStrings":"public"}', 'application/json'), false);
  assert.equal(entry('/appsettings.json').matches('{"ApiKey":"actual-test-secret-123"}', 'application/json'), true);
  assert.equal(entry('/.npmrc').matches('registry=https://registry.npmjs.org/', 'text/plain'), false);
  assert.equal(entry('/.npmrc').matches('//registry.npmjs.org/:_authToken=actual-test-secret-123', 'text/plain'), true);
  assert.equal(entry('/.ssh/id_rsa').matches('-----BEGIN OPENSSH PRIVATE KEY-----\nexample', 'text/plain'), true);
});

test('selection uses a small baseline and expands from observed and accepted Muse evidence', () => {
  const unknown = selectSensitivePathEntries();
  assert.ok(unknown.selected < 20, 'unknown stack does not spray the full catalog');
  assert.equal(unknown.available, additionalSensitivePathEntries.length);
  assert.equal(unknown.skipped.length + unknown.selected, unknown.available);
  assert.ok(unknown.entries.some(item => item.path === '/.env.local'));
  assert.ok(!unknown.entries.some(item => item.path === '/wp-config.php.bak'));

  const observed = selectSensitivePathEntries({mined: {files: [{url: 'https://target.test/index.php'}]},
    routes: [{path: '/wp-content/uploads/photo.jpg', status: 200}]});
  assert.ok(observed.entries.some(item => item.path === '/wp-config.php.bak'));
  assert.ok(observed.entries.some(item => item.path === '/config.inc.php'));
  assert.ok(observed.heuristicFingerprints.includes('wordpress'));
  assert.ok(observed.heuristicFingerprints.includes('php'));

  const failedWordPress = selectSensitivePathEntries({routes: [{path: '/wp-login.php', status: 404}],
    observedPaths: ['/wp-content/uploads/photo.jpg']});
  assert.ok(!failedWordPress.heuristicFingerprints.includes('wordpress'),
    'a requested or failed path cannot fingerprint a framework');

  const muse = selectSensitivePathEntries({modelNotes: [{by: 'asset-model', purpose: 'Laravel app route'}]});
  assert.ok(muse.entries.some(item => item.path === '/storage/logs/laravel.log'));
  assert.ok(muse.modelFingerprints.includes('laravel'));
  assert.ok(muse.entries.find(item => item.path === '/artisan').selectionReason.endsWith(':muse'));

  const explicit = selectSensitivePathEntries({routes: [{path: '/backup.tgz'}], maxCandidates: 1});
  assert.deepEqual(explicit.entries.map(item => item.path), ['/backup.tgz']);
  assert.ok(explicit.skipped.some(item => item.reason === 'candidate-budget'));
});
