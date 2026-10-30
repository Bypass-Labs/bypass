import test from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import {randomBytes} from 'node:crypto';
import {check, validModelHttpSequence} from '../src/blackbox/poc-runtime.mjs';

test('fresh cookie login replays protected injection, file and HTTP-sequence proofs', async t => {
  const sessions = new Set();
  let sinksFixed = false, loginFixed = false, logins = 0;
  const hostsText = '127.0.0.1 localhost\n127.0.1.1 fixture\n';
  const send = (response, status, body, headers = {}) => {
    response.writeHead(status, {'content-type': 'application/json',
      'cache-control': 'no-store', ...headers});
    response.end(JSON.stringify(body));
  };
  const sendText = (response, status, body) => {
    response.writeHead(status, {'content-type': 'text/plain', 'cache-control': 'no-store'});
    response.end(body);
  };
  const server = http.createServer(async (request, response) => {
    const url = new URL(request.url, 'http://fixture');
    if (request.method === 'POST' && url.pathname === '/login') {
      if (loginFixed) return send(response, 401, {error: 'denied'});
      let text = '';
      for await (const chunk of request) text += chunk;
      const body = JSON.parse(text);
      if (body.username !== "admin' OR '1'='1" ||
          !/^bx-invalid-[0-9a-f]{24}$/.test(body.password ?? ''))
        return send(response, 401, {error: 'denied'});
      const value = randomBytes(24).toString('hex');
      sessions.add(`opaque=${value}`);
      logins++;
      return send(response, 200, {ok: true},
        {'set-cookie': `opaque=${value}; HttpOnly; SameSite=Lax; Path=/`});
    }
    const authorized = sessions.has(request.headers.cookie ?? '');
    if (url.pathname === '/private')
      return send(response, authorized ? 200 : 401,
        authorized ? {member: true} : {error: 'denied'});
    if (!authorized) return send(response, 401, {error: 'denied'});
    if (url.pathname === '/lookup') {
      const q = url.searchParams.get('q') ?? '';
      const match = /^record-1' AND '(\d+)'='(\d+)$/.exec(q);
      const found = q === 'record-1' || !sinksFixed && match && match[1] === match[2];
      return send(response, found ? 200 : 404,
        found ? {id: 'record-1', value: 'controlled'} : {error: 'missing'});
    }
    if (url.pathname === '/template') {
      const q = url.searchParams.get('q') ?? '';
      const match = /^\{\{(\d+)\*(\d+)\}\}$/.exec(q);
      return send(response, 200, {result: !sinksFixed && match ?
        String(Number(match[1]) * Number(match[2])) : q});
    }
    if (url.pathname === '/command') {
      const q = url.searchParams.get('q') ?? '';
      const command = /^bx;printf '((?:\\[0-7]{3})+)'$/.exec(q);
      const decoded = command?.[1].match(/\\[0-7]{3}/g)
        .map(value => String.fromCharCode(Number.parseInt(value.slice(1), 8))).join('');
      return sendText(response, 200, !sinksFixed && command ? `bx${decoded}` : q);
    }
    if (url.pathname === '/file') {
      const q = url.searchParams.get('q') ?? '';
      return !sinksFixed && /^(?:\.\.\/){12,13}etc\/hosts$/.test(q) ?
        sendText(response, 200, hostsText) : sendText(response, 404, 'missing');
    }
    if (url.pathname === '/xml') {
      const q = url.searchParams.get('q') ?? '';
      if (sinksFixed) return sendText(response, 400, 'DTD disabled');
      const literal = /<!ENTITY bxcontrol "(bx[0-9a-f]{20})">/.exec(q);
      if (literal) return sendText(response, 200, literal[1]);
      if (/SYSTEM "file:\/\/\/etc\/hosts"/.test(q))
        return sendText(response, 200, hostsText);
      return sendText(response, 400, 'invalid XML');
    }
    if (url.pathname === '/preview') {
      const q = url.searchParams.get('q') ?? '';
      const result = !sinksFixed && q.startsWith('hex:') ?
        Buffer.from(q.slice(4), 'hex').toString('utf8') : q;
      return send(response, 200, {result});
    }
    return send(response, 404, {error: 'missing'});
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  t.after(() => new Promise(resolve => server.close(resolve)));
  const origin = `http://127.0.0.1:${server.address().port}`;
  const login = {kind: 'model-auth-login', proofMode: 'protected-status',
    request: {method: 'POST', url: '/login', as: 'anonymous'},
    loginPath: '/login', privatePath: '/private', userField: 'username',
    passwordField: 'password', userPayloads: ["admin' OR '1'='1"],
    tokenPointer: null, reviewedAuthPosts: [{path: '/login',
      usernameField: 'username', passwordField: 'password'}]};
  const base = {origin, include: ['/'], never: [], rps: 100,
    expiresAt: null, identities: {}, auth: 'cookie', targetEnvironment: 'local'};
  const sql = {...base, kind: 'sql-boolean', parameter: 'q', base: 'record-1',
    style: 'quoted', request: {method: 'GET', url: '/lookup', as: 'derived'},
    derivedLogin: login};
  const ssti = {...base, kind: 'ssti-arithmetic', parameter: 'q',
    request: {method: 'GET', url: '/template', as: 'derived'},
    derivedLogin: login};
  const command = {...base, kind: 'command-output', parameter: 'q',
    request: {method: 'GET', url: '/command', as: 'derived'},
    style: 'semicolon-printf', enabled: true, derivedLogin: login};
  const file = {...base, kind: 'path-traversal-hosts', parameter: 'q',
    request: {method: 'GET', url: '/file', as: 'derived'},
    style: 'etc-hosts-relative', enabled: true, derivedLogin: login};
  const xxe = {...base, kind: 'xxe-hosts', parameter: 'q',
    request: {method: 'GET', url: '/xml', as: 'derived'},
    style: 'xml-entity-etc-hosts', enabled: true, derivedLogin: login};
  const firstMarker = `bx${randomBytes(6).toString('hex')}`;
  const secondMarker = `bx${randomBytes(6).toString('hex')}`;
  const sequence = {...base, kind: 'model-http-sequence', as: 'derived',
    prelude: [], subject: {method: 'GET', path: '/preview', placement: 'query',
      key: 'q', fixedFields: [], bodyTemplate: '', headers: []}, observe: [],
    controlValue: 'plain',
    firstValue: `hex:${Buffer.from(firstMarker).toString('hex')}`,
    secondValue: `hex:${Buffer.from(secondMarker).toString('hex')}`,
    marker: firstMarker, secondMarker,
    assertion: {step: 'subject', index: 0, location: 'body', name: ''},
    derivedLogin: login};
  assert.equal(validModelHttpSequence(sequence), true);
  assert.equal((await check(sql, {})).verdict, 'confirmed');
  assert.equal((await check(ssti, {})).verdict, 'confirmed');
  for (const proof of [command, file, xxe]) {
    const replay = await check(proof, {});
    assert.equal(replay.verdict, 'confirmed', `${proof.kind}: ${replay.reason ?? ''}`);
    assert.ok(replay.controls.some(control => control.label === 'fresh-login-boundary' &&
      control.verdict === 'confirmed'), `${proof.kind} did not refresh the session`);
  }
  assert.equal((await check(sequence, {})).verdict, 'observed');
  const beforeFix = logins;
  sinksFixed = true;
  assert.equal((await check(sql, {})).verdict, 'not_reproduced');
  assert.equal((await check(ssti, {})).verdict, 'not_reproduced');
  for (const proof of [command, file, xxe])
    assert.equal((await check(proof, {})).verdict, 'not_reproduced', proof.kind);
  assert.equal((await check(sequence, {})).verdict, 'not_reproduced');
  assert.ok(logins > beforeFix, 'each post-fix replay must refresh its cookie');
  loginFixed = true;
  const callback = {...base, kind: 'ssrf-loopback', parameter: 'q',
    request: {method: 'GET', url: '/preview', as: 'derived'},
    subject: {method: 'GET', path: '/preview', placement: 'query', key: 'q',
      fixedFields: [], headers: []}, controlValue: 'plain',
    reviewedReadInputs: [{path: '/preview', methods: ['GET']}],
    derivedLogin: login};
  const fixedLoginProof = await check(callback, {});
  assert.equal(fixedLoginProof.verdict, 'not_reproduced', JSON.stringify(fixedLoginProof));
  assert.ok(fixedLoginProof.controls.some(control =>
    control.label === 'fresh-login-boundary' && control.verdict === 'not_reproduced'));
});
