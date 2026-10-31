import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import http from 'node:http';
import os from 'node:os';
import path from 'node:path';
import {CLI} from '../src/demo.mjs';
import {execFile} from '../src/util.mjs';

test('CLI sends late source-map route facts to Muse when the model-call budget allows more than eight asset pages',
  {timeout: 120000}, async t => {
    if (process.platform === 'win32') {
      t.skip('the Muse process fixture uses an executable POSIX script');
      return;
    }
    const root = fs.mkdtempSync(path.join(os.tmpdir(), 'bypass-asset-model-pages-'));
    t.after(() => fs.rmSync(root, {recursive: true, force: true}));
    const packageSources = Array.from({length: 230}, (_, index) =>
      `webpack://DocsBundle/./src/package-${index}.js`);
    const sourceMap = JSON.stringify({version: 3, mappings: 'AAAA',
      sources: [...packageSources, 'webpack:///./src/late-client.js'],
      sourcesContent: [...packageSources.map(() => null), "fetch('/api/from-late-map')"]});
    const scripts = Array.from({length: 10}, (_, index) =>
      `<script src="/s${index}.js"></script>`).join('');
    const server = http.createServer((request, response) => {
      const pathname = new URL(request.url, 'http://fixture.invalid').pathname;
      if (pathname === '/') {
        response.writeHead(200, {'content-type': 'text/html'});
        return response.end(`<html>${scripts}</html>`);
      }
      const script = /^\/s(\d)\.js$/.exec(pathname);
      if (script) {
        const calls = Array.from({length: 60}, (_, index) =>
          `fetch('/api/r${index}');`).join('\n');
        response.writeHead(200, {'content-type': 'application/javascript'});
        return response.end(`const serial = ${script[1]};\n${calls}\n` +
          (script[1] === '9' ? '//# sourceMappingURL=/s9.js.map\n' : ''));
      }
      if (pathname === '/s9.js.map') {
        response.writeHead(200, {'content-type': 'application/json'});
        return response.end(sourceMap);
      }
      response.writeHead(404, {'content-type': 'application/json'});
      response.end('{"error":"missing"}');
    });
    await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
    t.after(() => new Promise(resolve => server.close(resolve)));
    const origin = `http://127.0.0.1:${server.address().port}`;
    const bin = path.join(root, 'bin');
    fs.mkdirSync(bin);
    fs.writeFileSync(path.join(bin, 'muse'), [
      '#!' + process.execPath,
      "const fs=require('node:fs');",
      'const args=process.argv.slice(2);',
      'const value=flag=>args[args.indexOf(flag)+1];',
      "if(args.includes('--version')){console.log('muse fixture');process.exit(0);}",
      "if(args[0]!=='exec'||!args.includes('--disable-shell')||!args.includes('--output-schema')||value('--provider')!=='meta')process.exit(2);",
      "const messages=JSON.parse(fs.readFileSync(value('--prompt-file'),'utf8'));",
      'const system=messages[0].content;',
      'let answer;',
      "if(system.includes('client-asset facts')){",
      ' const context=JSON.parse(messages.at(-1).content);',
      " fs.appendFileSync(process.env.BX_ASSET_PAGE_LOG,JSON.stringify({page:context.page,routes:context.files.flatMap(file=>file.routes.map(route=>route.path))})+'\\n');",
      " answer={files:context.files.map(file=>({id:file.id,role:'app',why:'Observed client requests',authFlow:'',routes:file.routes.map(route=>({path:route.path,method:route.method,purpose:'Observed request',parameters:[]})),proposals:[]}))};",
      '} else {',
      " const schema=JSON.parse(fs.readFileSync(value('--output-schema'),'utf8'));",
      " const blank=s=>s?.type==='object'?Object.fromEntries((s.required??[]).map(key=>[key,blank(s.properties?.[key])])):s?.type==='array'?[]:s?.type==='integer'||s?.type==='number'?0:s?.type==='boolean'?false:s?.enum?.[0]??'';",
      ' answer=blank(schema);',
      '}',
      "console.log(JSON.stringify({payload:{kind:'run_terminal',terminal:'completed',text:JSON.stringify(answer)}}));",
    ].join('\n') + '\n', {mode: 0o700});
    const modelLog = path.join(root, 'asset-pages.jsonl');
    const env = {...process.env, BYPASS_TEST_LEGACY_MUSE: '1',
      PATH: `${bin}${path.delimiter}${process.env.PATH}`,
      BX_ASSET_PAGE_LOG: modelLog};
    const done = await execFile(process.execPath,
      [CLI, 'blackbox', origin, '--project', root, '--accept-local', '--rps', '50',
        '--model-calls', '100', '--max-tasks', '1', '--minutes', '2', '--offline',
        '--json', '--non-interactive'], {cwd: root, env, timeout: 90000});
    const audit = JSON.parse(done.stdout);
    assert.ok(audit.runDir, JSON.stringify({code: done.code, audit}));
    const analysis = JSON.parse(fs.readFileSync(path.join(audit.runDir,
      'asset-analysis.json'), 'utf8'));
    const assets = JSON.parse(fs.readFileSync(path.join(audit.runDir, 'assets.json'), 'utf8'));
    const map = assets.files.find(file => file.url.endsWith('/s9.js.map'));
    assert.equal(map.sourceSelection.appLikelySelected, 1);
    assert.equal(map.sourceSelection.appLikelyUnavailable, 0);
    assert.equal(map.sourceSelection.namespaceUnavailable, packageSources.length);
    assert.equal(map.sourcesCut, packageSources.length,
      'missing package originals remain uninspected despite the late app route');
    const contexts = fs.readFileSync(modelLog, 'utf8').trim().split('\n')
      .map(line => JSON.parse(line));
    const late = contexts.find(context => context.routes.includes('/api/from-late-map'));
    assert.ok(analysis.coverage.pagesAvailable > 8);
    assert.ok(late?.page > 8, `late source-map facts were not sent: ` +
      JSON.stringify({pages: analysis.coverage.pagesAvailable,
        sent: analysis.coverage.pagesSent}));
    assert.equal(analysis.coverage.pagesSent, analysis.coverage.pagesAvailable);
    assert.equal(analysis.coverage.routesSent, analysis.coverage.routesAvailable);
    assert.ok(analysis.notes.some(note => note.path === '/api/from-late-map'));

    const constrainedRoot = path.join(root, 'constrained');
    const constrainedLog = path.join(root, 'asset-pages-constrained.jsonl');
    const constrained = await execFile(process.execPath,
      [CLI, 'blackbox', origin, '--project', constrainedRoot, '--accept-local', '--rps', '50',
        '--model-calls', '32', '--max-tasks', '1', '--minutes', '2', '--offline',
        '--json', '--non-interactive'], {cwd: root,
        env: {...env, BX_ASSET_PAGE_LOG: constrainedLog}, timeout: 90000});
    const constrainedAudit = JSON.parse(constrained.stdout);
    assert.ok(constrainedAudit.runDir, JSON.stringify({code: constrained.code,
      audit: constrainedAudit}));
    const constrainedAnalysis = JSON.parse(fs.readFileSync(path.join(constrainedAudit.runDir,
      'asset-analysis.json'), 'utf8'));
    const constrainedContexts = fs.readFileSync(constrainedLog, 'utf8').trim().split('\n')
      .map(line => JSON.parse(line));
    assert.ok(constrainedAnalysis.coverage.pagesSent < constrainedAnalysis.coverage.pagesAvailable);
    assert.ok(constrainedContexts.some(context => context.routes.includes('/api/from-late-map')));
    assert.ok(constrainedAnalysis.notes.some(note => note.path === '/api/from-late-map'));
  });
