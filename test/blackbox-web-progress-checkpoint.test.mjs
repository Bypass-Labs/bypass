import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import {spawnSync} from 'node:child_process';

test('web pass checkpoints a completed task before the process stops', () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'bypass-web-progress-'));
  try {
    const checkpoint = path.join(root, 'checkpoint.json');
    const program = `
      import fs from 'node:fs';
      import {loadScope} from './src/blackbox/scope.mjs';
      import {runWebProbes} from './src/blackbox/web-probes.mjs';
      const scope = loadScope({origin:'http://127.0.0.1:4329',
        overrides:{acceptLocal:true}}).scope;
      const surface = {patterns:[{pattern:'/go',methods:['GET'],
        params:{next:[]},source:['public-openapi']}],modelNotes:[]};
      let count = 0;
      await runWebProbes(surface,scope,{budget:2,
        requester:async()=>({status:404,type:'text/plain',body:'missing',
          bytes:7,headers:{},hash:'sha256:missing',evidenceId:'ev-'+(++count)}),
        onProgressCheckpoint:snapshot=>{
          fs.writeFileSync(process.argv.at(-1),JSON.stringify(snapshot));
          if(snapshot.phase==='running'&&snapshot.completed===1)process.exit(91);
        }});
      process.exit(0);
    `;
    const child = spawnSync(process.execPath,
      ['--input-type=module', '-e', program, checkpoint],
      {cwd: path.resolve('.'), encoding: 'utf8', timeout: 10000});
    assert.equal(child.status, 91, child.stderr);
    const saved = JSON.parse(fs.readFileSync(checkpoint, 'utf8'));
    assert.equal(saved.phase, 'running');
    assert.equal(saved.completed, 1);
    assert.ok(saved.planned >= 2);
    assert.ok(saved.remaining >= 1);
    assert.equal(saved.lastResult.path, '/go');
    assert.equal(saved.verdicts[saved.lastResult.verdict], 1);
  } finally {
    fs.rmSync(root, {recursive: true, force: true});
  }
});
