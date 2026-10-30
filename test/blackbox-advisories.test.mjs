import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import http from 'node:http';
import path from 'node:path';
import {temp} from './helpers.mjs';
import {DEFAULT_SCOPE} from '../src/blackbox/scope.mjs';
import {createLedger, verifyLedger} from '../src/blackbox/ledger.mjs';
import {lookupAdvisories} from '../src/blackbox/advisories.mjs';
import {runAudit} from '../src/blackbox/index.mjs';

const file = (url, libraries) => ({url, libraries});
const answer = (vulns, next_page_token) => ({status: 200,
  body: JSON.stringify({vulns, ...(next_page_token ? {next_page_token} : {})})});

test('OSV version lookups deduplicate public assets, page bounded results and retain ledger evidence', async t => {
  const dir = temp();
  t.after(() => fs.rmSync(dir, {recursive: true, force: true}));
  const ledger = createLedger(dir);
  const summaries = [{files: [file('https://app.example.test/a.js?token=secret-query-value', [
    {name: 'Lodash', version: 'v4.17.15'}, {name: 'React', version: 'not-a-version'}])]},
  {files: [file('https://cdn.example.test/b.js', [{name: 'lodash', version: '4.17.15'}])]}];
  const requests = [];
  const first = {id: 'GHSA-abcd-1234', summary: 'Prototype pollution in lodash',
    database_specific: {severity: 'HIGH'}, affected: [{package: {name: 'lodash'},
      ranges: [{type: 'SEMVER', events: [{introduced: '0'}, {fixed: '4.17.21'}]}]}]};
  const second = {id: 'GHSA-efgh-5678', summary: 'Unsafe template expansion', affected: []};
  const result = await lookupAdvisories(summaries, {enabled: true, ledger, query: async payload => {
    requests.push(payload);
    return payload.page_token ? answer([first, second]) : answer([first], 'page-2');
  }});
  assert.equal(result.status, 'checked');
  assert.deepEqual(result.stats, {available: 1, checked: 1, requests: 2, cut: 0, errors: 0, matches: 2});
  assert.deepEqual(requests, [
    {package: {name: 'lodash', ecosystem: 'npm'}, version: '4.17.15'},
    {package: {name: 'lodash', ecosystem: 'npm'}, version: '4.17.15', page_token: 'page-2'},
  ]);
  assert.deepEqual(result.records[0].files,
    ['https://app.example.test/a.js', 'https://cdn.example.test/b.js']);
  assert.ok(!JSON.stringify(result).includes('secret-query-value'));
  assert.deepEqual(result.records[0].advisories.map(item => item.id), [first.id, second.id]);
  assert.deepEqual(result.records[0].advisories[0].fixedVersions, ['4.17.21']);
  assert.equal(result.records[0].advisories[0].rating, 'HIGH');
  assert.equal(result.records[0].evidence.length, 2);
  assert.equal(verifyLedger(ledger.file).ok, true);
});

test('OSV disables network work offline and reports failed or cut lookups as incomplete', async t => {
  const dir = temp();
  t.after(() => fs.rmSync(dir, {recursive: true, force: true}));
  const ledger = createLedger(dir);
  const summaries = {files: [file('https://app.example.test/a.js', [{name: 'lodash', version: '4.17.15'}])]};
  const never = async () => {throw Error('network must stay silent');};
  assert.equal((await lookupAdvisories(summaries, {ledger, query: never})).status, 'disabled');
  assert.equal((await lookupAdvisories(summaries, {enabled: true, offline: true, ledger, query: never})).status, 'offline');
  const failed = await lookupAdvisories(summaries, {enabled: true, ledger,
    query: async () => ({status: 503, body: '{}'})});
  assert.equal(failed.stats.errors, 1);
  assert.equal(failed.incomplete, true);
  assert.equal(failed.records[0].status, 'error');
  const cut = await lookupAdvisories(summaries, {enabled: true, ledger,
    query: async () => answer([], 'another-page')});
  assert.equal(cut.stats.requests, 2);
  assert.equal(cut.stats.cut, 1);
  assert.equal(cut.incomplete, true);
  const malformed = await lookupAdvisories(summaries, {enabled: true, ledger,
    query: async () => ({status: 200, body: JSON.stringify({vulns: [
      {id: 'GHSA-safe-0001', affected: {unexpected: true}}], next_page_token: ['bad']})})});
  assert.equal(malformed.records[0].advisories.length, 1);
  assert.equal(malformed.records[0].status, 'cut');
  assert.equal(malformed.incomplete, true);
  const many = {files: Array.from({length: 51}, (_, index) =>
    file(`https://app.example.test/${index}.js`, [{name: `lib${index}`, version: '1.0.0'}]))};
  let calls = 0;
  const capped = await lookupAdvisories(many, {enabled: true, ledger,
    query: async () => {calls++; return answer([]);}});
  assert.equal(calls, 50);
  assert.equal(capped.stats.available, 51);
  assert.equal(capped.stats.cut, 1);
  assert.equal(capped.incomplete, true);
});

test('the audit pipeline records advisory leads without turning them into unproved findings', async t => {
  const root = temp();
  t.after(() => fs.rmSync(root, {recursive: true, force: true}));
  const server = http.createServer((request, response) => {
    const url = new URL(request.url, 'http://local');
    const body = url.pathname === '/' ? '<html><script src="/vendor.js"></script></html>' :
      url.pathname === '/vendor.js' ? '/*! lodash v4.17.15 */' : 'not found';
    const status = ['/', '/vendor.js'].includes(url.pathname) ? 200 : 404;
    response.writeHead(status, {'content-type': url.pathname === '/' ? 'text/html' :
      url.pathname === '/vendor.js' ? 'application/javascript' : 'text/plain'});
    response.end(body);
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  t.after(() => new Promise(resolve => server.close(resolve)));
  const origin = `http://127.0.0.1:${server.address().port}`;
  const scope = structuredClone(DEFAULT_SCOPE);
  scope.target.origin = origin;
  scope.credentialOrigins = [origin];
  scope.discovery.external.osv = true;
  scope.limits.minutes = 2;
  fs.writeFileSync(path.join(root, 'blackbox.scope.json'), JSON.stringify(scope));
  const result = await runAudit({url: origin, root, noModel: true, dryRun: true,
    overrides: {acceptLocal: true}, osvQuery: async payload => {
      assert.deepEqual(payload, {package: {name: 'lodash', ecosystem: 'npm'}, version: '4.17.15'});
      return answer([{id: 'GHSA-abcd-1234', summary: 'Prototype pollution in lodash', affected: []}]);
    }});
  const artifact = JSON.parse(fs.readFileSync(path.join(result.runDir, 'advisories.json'), 'utf8'));
  const report = JSON.parse(fs.readFileSync(path.join(result.runDir, 'report.json'), 'utf8'));
  const markdown = fs.readFileSync(result.reportPath, 'utf8');
  assert.equal(artifact.stats.matches, 1);
  assert.equal(result.advisories.matches, 1);
  assert.equal(report.surface.external.advisories.records[0].advisories[0].id, 'GHSA-abcd-1234');
  assert.ok(report.evidence.some(item => item.id === artifact.records[0].evidence[0] &&
    item.method === 'POST' && item.url === 'https://api.osv.dev/v1/query' && item.status === 200));
  assert.match(markdown, /Known advisory leads/);
  assert.match(markdown, /Matches are not exploit proofs/);
  assert.equal(report.coverage.rows.find(row => row.family === 'dependency').status, 'partial');
  assert.deepEqual(result.findings, []);
  assert.equal(verifyLedger(path.join(result.runDir, 'evidence.jsonl')).ok, true);
});
