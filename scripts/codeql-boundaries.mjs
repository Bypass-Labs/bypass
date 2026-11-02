/** Opt-in Docker checks for offline/network-helper isolation and durable recovery. */
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import assert from 'node:assert/strict';
import { connectScanner } from '../src/scanner/runtime.mjs';
import { execFile } from '../src/util.mjs';

const root=fs.mkdtempSync(path.join(os.tmpdir(),'bypass-codeql-boundaries-'));
fs.writeFileSync(path.join(root,'main.py'),"from Crypto.Cipher import DES\ncipher=DES.new(b'12345678',DES.MODE_ECB)\ncipher.encrypt(b'12345678')\n");
console.log('Artifacts: '+root);
const terminal=run=>['completed','incomplete','failed','cancelled','interrupted'].includes(run.status);
const sleep=ms=>new Promise(resolve=>setTimeout(resolve,ms));
const input=config=>({detector:'codeql',executionMode:'standalone-api',config:{evaluation:'off',languages:['python'],includeRules:['py/weak-cryptographic-algorithm'],resources:{timeoutSeconds:180},...config}});
async function wait(client,id,predicate=terminal){
  const deadline=Date.now()+240000;
  while(Date.now()<deadline){
    const response=await client.call('status',{run:id});
    assert.ok(response.run,JSON.stringify(response));
    await client.pumpBuild(response.run);
    if(predicate(response.run))return response.run;
    await sleep(250);
  }
  throw new Error('Timed out waiting for '+id);
}
const clients=[];
async function connect(){const client=await connectScanner({root,onProgress:step=>console.log(step.message)});clients.push(client);return client;}
try{
  for(const network of ['off','on']){
    const client=await connect();
    // Inspect actual network topology without contacting any external service.
    const check=[
      'import os,pathlib,sys',
      "assert sys.stdin.read()=='', 'build inherited the MCP input pipe'",
      "routes=pathlib.Path('/proc/net/route').read_text().splitlines()[1:]",
      "online=any(line.split()[1]=='00000000' for line in routes if line.split())",
      `assert online is ${network==='on'?'True':'False'}, routes`,
      ...(network==='on'?["assert not pathlib.Path('/inputs/source').exists(), 'network helper received the original source mount'"]:[]),
      'assert os.getuid()!=0',
      "assert 'BYPASS_BOUNDARY_SECRET' not in os.environ",
      'try:',
      " pathlib.Path('/inputs/source/forbidden-write').write_text('invalid')",
      "except OSError: pass",
      "else: raise AssertionError('source mount was writable')",
      "print('boundary checks passed')",
    ].join('\n');
    const started=await client.call('start',input({builds:{python:{network,prepare:[['python','-c',check]]}}}));
    assert.ok(started.run,JSON.stringify(started));
    const run=await wait(client,started.run.id);
    assert.ok(run.languages.every(value=>value.queryComplete),JSON.stringify(run));
    assert.ok(run.signalCount>0);assert.equal(run.modelCalls,0);
    const inspection=await execFile('docker',['inspect',client.child.spawnargs.at(-1),'--format','{{.HostConfig.NetworkMode}}']);
    assert.equal(inspection.stdout,'none');
    assert.equal(fs.existsSync(path.join(root,'forbidden-write')),false);
    await client.close();
    console.log('PASS '+network+': actual build networking, offline controller, read-only source, unprivileged user, no host secret');
  }

  for(const network of ['off','on']){
    const client=await connect();
    const started=await client.call('start',input({resources:{timeoutSeconds:1},builds:{python:{network,prepare:[['python','-c','import time; time.sleep(60)']]}}}));
    const run=await wait(client,started.run.id);
    assert.equal(run.status,'incomplete',JSON.stringify(run));
    assert.ok(run.languages.some(value=>value.message.includes('configured timeout')),JSON.stringify(run));
    assert.equal(run.modelCalls,0);
    await client.close();
    console.log('PASS '+network+': configured build deadline stops extraction and preserves incomplete artifacts');
  }

  const client=await connect();
  const started=await client.call('start',input({builds:{python:{prepare:[['python','-c','import time; time.sleep(60)']]}}}));
  const id=started.run.id;
  await wait(client,id,run=>run.phase==='extract/python');
  const observer=await connect();
  await observer.call('cancel',{run:id});
  assert.equal((await wait(client,id)).status,'cancelled');
  await observer.close();await client.close();
  console.log('PASS cross-container cancellation');

  const interrupted=await connect();
  const initial=await interrupted.call('start',input({}));
  await wait(interrupted,initial.run.id,run=>run.phase==='analyze/python');
  const removed=await execFile('docker',['rm','--force',interrupted.child.spawnargs.at(-1)]);
  assert.equal(removed.code,0);await interrupted.close();
  const recovery=await connect();
  assert.equal((await recovery.call('status',{run:initial.run.id})).run.status,'interrupted');
  assert.ok((await recovery.call('resume',{run:initial.run.id})).run);
  const run=await wait(recovery,initial.run.id);
  assert.ok(run.languages.every(value=>value.queryComplete),JSON.stringify(run));
  assert.ok(run.signalCount>0);assert.equal(run.modelCalls,0);
  console.log('PASS force-stopped container, durable interruption, resumed finalized database');
}finally{await Promise.allSettled(clients.map(client=>client.close()));}
