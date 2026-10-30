#!/usr/bin/env node
// Randomized local black-box benchmark. The app answers are held by this scorer, never passed to the audit.
import fs from 'node:fs';
import http from 'node:http';
import os from 'node:os';
import path from 'node:path';
import {createHmac, randomBytes} from 'node:crypto';
import {DatabaseSync} from 'node:sqlite';
import {fileURLToPath} from 'node:url';
import {execFile, need} from '../src/util.mjs';

const CLI = fileURLToPath(new URL('../bin/bypass.mjs', import.meta.url));
const BUGS = ['idor', 'list-leak', 'open-redirect', 'nosql-operator-bypass',
  'http-parameter-pollution', 'graphql-bola', 'host-header-redirect', 'jwt-unsigned',
  'ssrf-loopback', 'ssti-arithmetic', 'missing-auth', 'anonymous-credential-data',
  'sql-boolean', 'xxe-hosts', 'xxe-body-hosts', 'public-api-credential'];

function randomCredential() {
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
  return `ghp_${[...randomBytes(36)].map(byte => alphabet[byte % alphabet.length]).join('')}`;
}

function renderFixtureXml(xml, externalEntities) {
  const declaration = /<!ENTITY\s+([A-Za-z][A-Za-z0-9]*)\s+(?:SYSTEM\s+"(file:\/\/\/[^"\s]+)"|"([^"<>]*)")\s*>/i.exec(xml);
  const body = /<audit>([\s\S]{0,200}?)<\/audit>/.exec(xml);
  if (!declaration || !body || !body[1].includes(`&${declaration[1]};`)) return null;
  if (declaration[3] !== undefined) return body[1].replace(`&${declaration[1]};`, declaration[3]);
  if (!externalEntities) return body[1].replace(`&${declaration[1]};`, '');
  try {return body[1].replace(`&${declaration[1]};`, fs.readFileSync(new URL(declaration[2]), 'utf8'));}
  catch {return null;}
}

const encode = value => Buffer.from(JSON.stringify(value)).toString('base64url');
function signedJwt(principal, secret) {
  const input = `${encode({alg: 'HS256', typ: 'JWT'})}.${encode({sub: principal,
    exp: Math.floor(Date.now() / 1000) + 3600})}`;
  return `${input}.${createHmac('sha256', secret).update(input).digest('base64url')}`;
}

function options(args) {
  const result = {trials: 3, seed: Date.now() >>> 0, out: null, model: false, json: false};
  for (let at = 0; at < args.length; at++) {
    const flag = args[at];
    if (flag === '--model' || flag === '--json') result[flag.slice(2)] = true;
    else if (['--trials', '--seed', '--out'].includes(flag)) result[flag.slice(2)] = args[++at];
    else throw Error(`Unknown scorer option: ${flag}`);
  }
  result.trials = Number(result.trials);
  result.seed = Number(result.seed);
  need(Number.isInteger(result.trials) && result.trials >= 2 && result.trials <= 10,
    'Use --trials with an integer from 2 to 10.');
  need(Number.isSafeInteger(result.seed) && result.seed >= 0 && result.seed <= 0xffffffff,
    'Use --seed with an unsigned 32-bit integer.');
  return result;
}

function random(seed) {
  let state = seed || 0x6d2b79f5;
  return () => {
    state ^= state << 13;
    state ^= state >>> 17;
    state ^= state << 5;
    return state >>> 0;
  };
}

function target(next, enabled) {
  const suffix = next().toString(16).padStart(8, '0');
  const prefix = `/api/cohort-${suffix}`;
  const list = `${prefix}/records`;
  const item = `${list}/{id}`;
  const go = `${prefix}/go`;
  const polluted = `${prefix}/polluted`;
  const lookup = `${prefix}/lookup`;
  const sqlLookup = `${prefix}/sql-lookup`;
  const graphql = `${prefix}/graphql`;
  const hostRedirect = `${prefix}/host-redirect`;
  const jwtProfile = `${prefix}/jwt-profile`;
  const preview = `${prefix}/preview`;
  const render = `${prefix}/render`;
  const users = `${prefix}/users`;
  const xmlParse = `${prefix}/xml/parse`;
  const xmlImport = `${prefix}/xml/import`;
  const publicAsset = `/assets/client-${suffix}.js`;
  const publicToken = randomCredential();
  const principal = [`user-${next().toString(16)}`, `user-${next().toString(16)}`];
  const ids = [`rec-${suffix}-101`, `rec-${suffix}-202`];
  const records = ids.map((id, index) => ({id, ownerId: principal[index], balance: (index + 1) * 20}));
  const sqlId = `sql-${suffix}-${next().toString(16)}`;
  const db = new DatabaseSync(':memory:');
  db.exec('CREATE TABLE sql_records (id TEXT PRIMARY KEY, label TEXT)');
  db.prepare('INSERT INTO sql_records VALUES (?, ?)').run(sqlId, `record-${next().toString(16)}`);
  const passwordHashes = [0, 1].map(() => `$2b$12$${randomBytes(32).toString('hex').slice(0, 53)}`);
  const signingKey = randomBytes(24).toString('hex');
  const tokens = principal.map(value => signedJwt(value, signingKey));
  const requested = [];
  const signedPrincipal = token => {
    if (typeof token !== 'string') return null;
    const parts = token.split('.');
    if (parts.length !== 3) return null;
    try {
      const header = JSON.parse(Buffer.from(parts[0], 'base64url').toString('utf8'));
      const claims = JSON.parse(Buffer.from(parts[1], 'base64url').toString('utf8'));
      const signature = createHmac('sha256', signingKey)
        .update(`${parts[0]}.${parts[1]}`).digest('base64url');
      return header.alg === 'HS256' && parts[2] === signature &&
        Number.isInteger(claims.exp) && claims.exp > Math.floor(Date.now() / 1000) &&
        principal.includes(claims.sub) ? claims.sub : null;
    } catch {return null;}
  };
  const server = http.createServer(async (request, response) => {
    const url = new URL(request.url, 'http://local');
    requested.push(url.pathname);
    const who = signedPrincipal(/^Bearer (.+)$/.exec(request.headers.authorization ?? '')?.[1]);
    let status = 404, body = {error: 'Not found'}, headers = {'content-type': 'application/json',
      'cache-control': 'no-store'};
    if (url.pathname === '/') {
      status = 200; body = `<html><script src="${publicAsset}"></script></html>`;
      headers = {'content-type': 'text/html', 'cache-control': 'no-store'};
    }
    else if (url.pathname === publicAsset) {
      status = 200;
      body = enabled.has('public-api-credential') ? `export const apiToken = '${publicToken}';` :
        'export const apiToken = null;';
      headers = {'content-type': 'application/javascript', 'cache-control': 'no-store'};
    }
    else if (url.pathname === '/openapi.json') {status = 200; body = {openapi: '3.0.0', paths: {
      '/api/me': {get: {}}, '/api/whoami': {get: {}},
      [list]: {get: {parameters: [{name: 'all', in: 'query'}]}},
      [item]: {get: {}}, [go]: {get: {parameters: [{name: 'next', in: 'query'}]}},
      [polluted]: {get: {parameters: [{name: 'next', in: 'query'}]}},
      [lookup]: {get: {parameters: [{name: 'id', in: 'query', example: ids[0]}]}},
      [sqlLookup]: {get: {parameters: [{name: 'lookup', in: 'query', example: sqlId}]}},
      [hostRedirect]: {get: {parameters: [{name: 'next', in: 'query'}]}},
      [jwtProfile]: {get: {}},
      [preview]: {get: {parameters: [{name: 'url', in: 'query'}]}},
      [render]: {get: {parameters: [{name: 'template', in: 'query'}]}},
      [users]: {get: {}},
      [xmlParse]: {get: {parameters: [{name: 'document', in: 'query'}]}},
      [xmlImport]: {post: {requestBody: {content: {'application/xml': {schema: {type: 'string'}}}}}},
      [graphql]: {get: {}},
      '/api/delete': {get: {}}}};}
    else if (url.pathname === '/api/me') {
      const identity = who ?? (enabled.has('missing-auth') ? principal[0] : null);
      status = identity ? 200 : 401;
      body = identity ? {id: identity, role: 'member'} : {error: 'Sign in'};
    }
    else if (url.pathname === '/api/whoami') {
      status = who ? 200 : 401;
      body = who ? {id: who, role: 'member'} : {error: 'Sign in'};
    }
    else if (url.pathname === users) {status = 200;
      body = principal.map((id, index) => ({id,
        ...(enabled.has('anonymous-credential-data') ? {passwordHash: passwordHashes[index]} : {})}));}
    else if (url.pathname === jwtProfile) {
      let unsignedWho = null;
      if (!who && enabled.has('jwt-unsigned')) {
        const token = /^Bearer (.+)$/.exec(request.headers.authorization ?? '')?.[1];
        if (token) try {
          const [header, payload, signature] = token.split('.');
          const details = JSON.parse(Buffer.from(header, 'base64url').toString('utf8'));
          const claims = JSON.parse(Buffer.from(payload, 'base64url').toString('utf8'));
          if (details.alg === 'none' && signature === '' && principal.includes(claims.sub))
            unsignedWho = claims.sub;
        } catch { /* malformed JWTs are denied */ }
      }
      const caller = who ?? unsignedWho;
      status = caller ? 200 : 401;
      body = caller ? {id: caller, ownerId: caller, profile: 'private'} : {error: 'Sign in'};
    }
    else if (url.pathname === list) {status = who ? 200 : 401;
      body = who ? enabled.has('list-leak') && url.searchParams.get('all') === '1' ? records :
        records.filter(record => record.ownerId === who) : {error: 'Sign in'};}
    else if (url.pathname.startsWith(`${list}/`)) {
      const record = records.find(item => url.pathname === `${list}/${item.id}`);
      status = !who ? 401 : !record ? 404 : record.ownerId === who || enabled.has('idor') ? 200 : 403;
      body = status === 200 ? record : {error: 'Denied'};
    } else if (url.pathname === lookup) {
      const operator = url.searchParams.has('id[$eq]');
      const selected = url.searchParams.get(operator ? 'id[$eq]' : 'id');
      const record = records.find(item => item.id === selected);
      status = !who ? 401 : operator && !enabled.has('nosql-operator-bypass') ? 400 :
        !selected ? 400 : !record ? 404 : record.ownerId === who || operator ? 200 : 403;
      body = status === 200 ? record : {error: status === 400 ? 'Invalid filter' : 'Denied'};
    } else if (url.pathname === sqlLookup) {
      const input = url.searchParams.get('lookup') ?? '';
      try {
        const row = enabled.has('sql-boolean') ?
          db.prepare(`SELECT id, label FROM sql_records WHERE id='${input}'`).get() :
          db.prepare('SELECT id, label FROM sql_records WHERE id=?').get(input);
        status = row ? 200 : 404;
        body = row ?? {error: 'Not found'};
      } catch {status = 400; body = {error: 'Invalid lookup'};}
    } else if (url.pathname === go) {
      const destination = enabled.has('open-redirect') ? url.searchParams.get('next') ?? '/safe' : '/safe';
      if (/[\r\n]/.test(destination)) {status = 400; body = {error: 'Invalid destination'};}
      else {status = 302; body = ''; headers = {location: destination, 'cache-control': 'no-store'};}
    } else if (url.pathname === hostRedirect) {
      const host = enabled.has('host-header-redirect') ? request.headers.host :
        `127.0.0.1:${server.address().port}`;
      status = 302; body = '';
      headers = {location: `http://${host}/safe`, 'cache-control': 'no-store'};
    } else if (url.pathname === polluted) {
      const values = url.searchParams.getAll('next');
      const allowed = values.length && !/^https?:\/\//i.test(values[0]);
      const destination = allowed && enabled.has('http-parameter-pollution') ? values.at(-1) : '/safe';
      if (/[\r\n]/.test(destination)) {status = 400; body = {error: 'Invalid destination'};}
      else {status = 302; body = ''; headers = {location: destination, 'cache-control': 'no-store'};}
    } else if (url.pathname === preview) {
      const destination = url.searchParams.get('url');
      status = 200;
      body = {preview: 'No remote content fetched'};
      if (enabled.has('ssrf-loopback') && destination) try {
        const target = new URL(destination);
        if (target.protocol !== 'http:' || target.hostname !== '127.0.0.1') throw Error('Destination refused');
        await fetch(target, {redirect: 'manual', signal: AbortSignal.timeout(1500)});
        body = {preview: 'Remote content fetched'};
      } catch {status = 400; body = {error: 'Preview fetch failed'};}
    } else if (url.pathname === render) {
      const template = url.searchParams.get('template') ?? '';
      const output = enabled.has('ssti-arithmetic') ? template.replace(/\{\{(\d{1,6})\*(\d{1,6})\}\}/g,
        (_whole, left, right) => String(Number(left) * Number(right))) : template;
      status = 200; body = `Rendered: ${output}`;
      headers = {'content-type': 'text/plain', 'cache-control': 'no-store'};
    } else if (url.pathname === xmlParse) {
      const result = renderFixtureXml(url.searchParams.get('document') ?? '', enabled.has('xxe-hosts'));
      status = result === null ? 400 : 200;
      body = result ?? 'Invalid XML';
      headers = {'content-type': 'text/plain', 'cache-control': 'no-store'};
    } else if (url.pathname === xmlImport && request.method === 'POST') {
      let xml = '';
      for await (const chunk of request) xml += chunk;
      const result = renderFixtureXml(xml, enabled.has('xxe-body-hosts'));
      status = result === null ? 400 : 200;
      body = result ?? 'Invalid XML';
      headers = {'content-type': 'text/plain', 'cache-control': 'no-store'};
    } else if (url.pathname === graphql) {
      const query = url.searchParams.get('query') ?? '';
      if (query.startsWith('query BypassSchemaInventory')) {status = 200; body = {data: {__schema: {
        queryType: {name: 'Query', fields: [
          {name: 'records', args: [], type: {kind: 'LIST', ofType: {kind: 'OBJECT', name: 'Record'}}},
          {name: 'record', args: [{name: 'id', type: {kind: 'NON_NULL', ofType: {kind: 'SCALAR', name: 'ID'}}}],
            type: {kind: 'OBJECT', name: 'Record'}},
        ]}, mutationType: {name: 'Mutation', fields: [{name: 'deleteRecord', args: []}]}}}};}
      else if (query.startsWith('query BypassObjectType')) {status = 200; body = {data: {__type: {
        name: 'Record', fields: [{name: 'id', type: {kind: 'SCALAR', name: 'ID'}},
          {name: 'ownerId', type: {kind: 'SCALAR', name: 'ID'}}]}}};}
      else if (query.startsWith('query BypassOwnerList')) {status = who ? 200 : 401;
        body = who ? {data: {records: records.filter(record => record.ownerId === who)}} :
          {errors: [{extensions: {code: 'UNAUTHENTICATED'}}]};}
      else if (query.startsWith('query BypassObjectCheck')) {
        const id = /record\(id:"([A-Za-z0-9_.-]+)"\)/.exec(query)?.[1];
        const record = records.find(item => item.id === id);
        status = who ? 200 : 401;
        body = !who ? {errors: [{extensions: {code: 'UNAUTHENTICATED'}}]} :
          record && (record.ownerId === who || enabled.has('graphql-bola')) ? {data: {record}} :
          {data: {record: null}, errors: [{extensions: {code: 'FORBIDDEN'}}]};
      } else {status = 400; body = {errors: [{message: 'Unknown query'}]};}
    } else if (url.pathname === `${prefix}/public`) {status = 200;
      body = {message: 'Public by design'};}
    else if (url.pathname === '/api/delete') {status = 500; body = {error: 'Protected decoy'};}
    response.writeHead(status, headers);
    response.end(typeof body === 'string' ? body : JSON.stringify(body));
  });
  return {server, db, tokens, requested, paths: {identity: '/api/me', list, item, go, hostRedirect, jwtProfile,
    lookup, sqlLookup, polluted, graphql, preview, render, users, xmlParse, xmlImport, publicAsset}, enabled};
}

async function cli(root, env, ...args) {
  const completed = await execFile(process.execPath,
    [CLI, 'blackbox', ...args, '--project', root, '--json', '--non-interactive'],
    {cwd: root, env, timeout: 90000});
  let data;
  try {data = JSON.parse(completed.stdout);} catch {
    throw Error(`Black-box CLI returned non-JSON output: ${completed.stderr || completed.stdout}`);
  }
  if (data.error) throw Error(data.error);
  return {code: completed.code, data};
}

function modelStatus(audit) {
  const state = JSON.parse(fs.readFileSync(path.join(audit.data.runDir, 'run.json'), 'utf8'));
  const cuts = (state.limitations ?? []).filter(value => /\bMuse\b/.test(value) &&
    /(?:\bof\b|did not|failed|exhausted|incomplete)/i.test(value));
  return {calls: state.stats?.modelCalls ?? 0, error: !!state.modelError, cuts: cuts.length};
}

function assess(expected, findings) {
  const actual = findings.map(item => ({kind: item.kind, pattern: item.pattern}));
  const key = item => `${item.kind} ${item.pattern}`;
  const wanted = new Set(expected.map(key));
  const observed = new Set(actual.map(key));
  return {found: expected.filter(item => observed.has(key(item))),
    missed: expected.filter(item => !observed.has(key(item))),
    falsePositives: actual.filter(item => !wanted.has(key(item)))};
}

async function scoreTrial(root, index, next, enabled, model) {
  const app = target(next, enabled);
  const enabledNames = [...enabled];
  await new Promise((resolve, reject) => app.server.listen(0, '127.0.0.1', error =>
    error ? reject(error) : resolve()));
  const origin = `http://127.0.0.1:${app.server.address().port}`;
  const project = path.join(root, `trial-${String(index + 1).padStart(2, '0')}`);
  fs.mkdirSync(project, {recursive: true});
  const env = {OWNER_TOKEN: app.tokens[0], OTHER_TOKEN: app.tokens[1]};
  try {
    const prepared = await cli(project, env, 'scope', origin, '--include', '/api', '--identity-path', '/api/me');
    const reviewed = JSON.parse(fs.readFileSync(prepared.data.file, 'utf8'));
    reviewed.probes.xmlPostPaths = [app.paths.xmlImport];
    fs.writeFileSync(prepared.data.file, JSON.stringify(reviewed));
    const expected = [
      {kind: 'idor', pattern: app.paths.item},
      {kind: 'list-leak', pattern: app.paths.list},
      {kind: 'open-redirect', pattern: app.paths.go},
      {kind: 'nosql-operator-bypass', pattern: app.paths.lookup},
      {kind: 'http-parameter-pollution', pattern: app.paths.polluted},
      {kind: 'graphql-bola', pattern: app.paths.graphql},
      {kind: 'host-header-redirect', pattern: app.paths.hostRedirect},
      {kind: 'jwt-unsigned', pattern: app.paths.jwtProfile},
      {kind: 'ssrf-loopback', pattern: app.paths.preview},
      {kind: 'ssti-arithmetic', pattern: app.paths.render},
      {kind: 'missing-auth', pattern: app.paths.identity},
      {kind: 'anonymous-credential-data', pattern: app.paths.users},
      {kind: 'sql-boolean', pattern: app.paths.sqlLookup},
      {kind: 'xxe-hosts', pattern: app.paths.xmlParse},
      {kind: 'xxe-body-hosts', pattern: app.paths.xmlImport},
      {kind: 'public-api-credential', pattern: app.paths.publicAsset},
    ].filter(item => enabled.has(item.kind));
    const modes = model ? ['code', 'model'] : ['code'];
    const runs = [];
    for (const mode of modes) {
      const started = Date.now();
      const requestedBefore = app.requested.length;
      const audit = await cli(project, env, origin, '--accept-local', ...(mode === 'code' ? ['--no-model'] : []));
      for (const finding of audit.data.findings ?? [])
        need(finding.proof && fs.existsSync(finding.proof),
          `A ${finding.kind} finding in trial ${index + 1} had no executed proof.`);
      const replay = (audit.data.findings ?? []).length ?
        await cli(project, env, 'verify', audit.data.run) : null;
      need(!replay || replay.code === 1,
        `Proof replay did not agree with the live finding set in trial ${index + 1}.`);
      const score = assess(expected, audit.data.findings ?? []);
      const modelState = mode === 'model' ? modelStatus(audit) : null;
      runs.push({mode, run: audit.data.run, exitCode: audit.code, elapsedMs: Date.now() - started,
        modelCalls: audit.data.stats?.modelCalls ?? 0, modelState,
        found: score.found, missed: score.missed, falsePositives: score.falsePositives,
        neverHits: app.requested.slice(requestedBefore).filter(pathname => pathname === '/api/delete').length,
        replayExitCode: replay?.code ?? null, report: audit.data.reportPath});
    }
    const fixedControls = [];
    if (enabled.size) {
      enabled.clear();
      for (const mode of modes) {
        const started = Date.now();
        const requestedBefore = app.requested.length;
        const fixed = await cli(project, env, origin, '--accept-local', ...(mode === 'code' ? ['--no-model'] : []));
        const modelState = mode === 'model' ? modelStatus(fixed) : null;
        fixedControls.push({mode, run: fixed.data.run, exitCode: fixed.code,
          elapsedMs: Date.now() - started, findings: fixed.data.findings ?? [],
          modelState,
          neverHits: app.requested.slice(requestedBefore).filter(pathname => pathname === '/api/delete').length,
          report: fixed.data.reportPath});
        const prior = runs.find(run => run.mode === mode);
        if (prior.replayExitCode === 1)
          prior.afterFixReplayExitCode = (await cli(project, env, 'verify', prior.run)).code;
      }
    }
    return {trial: index + 1, origin, paths: app.paths, enabled: enabledNames, expected, runs, fixedControls};
  } finally {await new Promise(resolve => app.server.close(resolve)); app.db.close();}
}

export async function scoreBlackbox({trials = 3, seed = Date.now() >>> 0, out = null, model = false} = {}) {
  need(Number.isInteger(trials) && trials >= 2 && trials <= 10,
    'Use a trial count from 2 to 10.');
  need(Number.isSafeInteger(seed) && seed >= 0 && seed <= 0xffffffff,
    'Use an unsigned 32-bit seed.');
  const root = out ? path.resolve(out) : fs.mkdtempSync(path.join(os.tmpdir(), 'bypass-blackbox-score-'));
  need(!fs.existsSync(root) || fs.readdirSync(root).length === 0,
    `Scorer output folder must be new or empty: ${root}.`);
  fs.mkdirSync(root, {recursive: true, mode: 0o700});
  const next = random(seed);
  const results = [];
  for (let index = 0; index < trials; index++) {
    const mask = index === 0 ? (1 << BUGS.length) - 1 : index === 1 ? 0 :
      1 + (next() % ((1 << BUGS.length) - 2));
    const enabled = new Set(BUGS.filter((_, bit) => mask & (1 << bit)));
    results.push(await scoreTrial(root, index, next, enabled, model));
  }
  const rows = ['code', ...(model ? ['model'] : [])].map(mode => {
    const runs = results.flatMap(item => item.runs.filter(run => run.mode === mode));
    const fixed = results.flatMap(item => item.fixedControls.filter(control => control.mode === mode));
    const found = runs.reduce((count, run) => count + run.found.length, 0);
    const missed = runs.reduce((count, run) => count + run.missed.length, 0);
    const falsePositives = runs.reduce((count, run) => count + run.falsePositives.length, 0) +
      fixed.reduce((count, control) => count + control.findings.length, 0);
    const proofRegressions = runs.filter(run => run.afterFixReplayExitCode != null &&
      run.afterFixReplayExitCode !== 0).length;
    const modelRuns = [...runs, ...fixed];
    const modelReadyRuns = mode === 'model' ? modelRuns.filter(run =>
      run.modelState?.calls > 0 && !run.modelState.error && run.modelState.cuts === 0).length : null;
    const rawModelAdds = mode === 'model' ? results.reduce((count, trial) => {
      const codeFound = new Set(trial.runs.find(run => run.mode === 'code').found
        .map(item => `${item.kind} ${item.pattern}`));
      return count + trial.runs.find(run => run.mode === 'model').found
        .filter(item => !codeFound.has(`${item.kind} ${item.pattern}`)).length;
    }, 0) : null;
    const valid = mode !== 'model' || modelReadyRuns === modelRuns.length;
    const modelAdds = valid ? rawModelAdds : null;
    return {mode, valid, found, missed, falsePositives,
      precision: valid && found + falsePositives ? found / (found + falsePositives) : null,
      recall: valid && found + missed ? found / (found + missed) : null,
      neverHits: [...runs, ...fixed].reduce((count, run) => count + run.neverHits, 0),
      proofRegressions,
      elapsedMs: [...runs, ...fixed].reduce((count, run) => count + run.elapsedMs, 0),
      modelCalls: runs.reduce((count, run) => count + run.modelCalls, 0),
      modelRuns: mode === 'model' ? modelRuns.length : null, modelReadyRuns, modelAdds};
  });
  const result = {schemaVersion: 1, seed, trials, root, rows, results,
    note: 'Generated local fixtures are known to this scorer. A model row is valid only when every model run completes without an error or cut. Invalid model rows retain raw finding counts but suppress precision, recall and model adds. Model adds counts expected findings absent from the code-only row. A stubbed Muse process tests transport, not model quality. This is a randomized acceptance check, not independent blind-app evidence.'};
  fs.writeFileSync(path.join(root, 'score.json'), JSON.stringify(result, null, 2) + '\n', {mode: 0o600});
  return result;
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try {
    const config = options(process.argv.slice(2));
    const result = await scoreBlackbox(config);
    if (config.json) console.log(JSON.stringify(result));
    else {
      console.log('Mode    Valid  Found  Missed  False positives  Never hits  Proof regressions  Model runs  Model adds  Precision  Recall');
      for (const row of result.rows) console.log(`${row.mode.padEnd(7)} ${String(row.valid).padEnd(5)}  ${String(row.found).padStart(5)}  ${String(row.missed).padStart(6)}  ${String(row.falsePositives).padStart(15)}  ${String(row.neverHits).padStart(10)}  ${String(row.proofRegressions).padStart(17)}  ${row.modelRuns == null ? '-' : `${row.modelReadyRuns}/${row.modelRuns}`.padStart(10)}  ${row.modelAdds == null ? '-' : String(row.modelAdds).padStart(10)}  ${row.precision?.toFixed(2) ?? '-'}       ${row.recall?.toFixed(2) ?? '-'}`);
      console.log(`Evidence: ${path.join(result.root, 'score.json')}`);
    }
    process.exitCode = result.rows.some(row => !row.valid || row.missed || row.falsePositives ||
      row.neverHits || row.proofRegressions) ? 1 : 0;
  } catch (error) {
    console.error(`Black-box scorer failed: ${error.message}`);
    process.exitCode = 2;
  }
}
