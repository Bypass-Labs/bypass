import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import {execFileSync,spawnSync} from 'node:child_process';
import {fileURLToPath} from 'node:url';
import {discoverTests,planTests,documentationOnly,changedFiles,checkGate,runTests,shardCount} from '../scripts/ci-tests.mjs';

const root=fileURLToPath(new URL('../',import.meta.url));
const temporary=t=>{const dir=fs.mkdtempSync(path.join(os.tmpdir(),'bypass-ci-'));t.after(()=>fs.rmSync(dir,{recursive:true,force:true}));return dir;};
const weights=JSON.parse(fs.readFileSync(new URL('../scripts/ci-test-timings.json',import.meta.url))).milliseconds;

test('every discovered test file belongs to exactly one shard, including new unmeasured files',()=>{
  const files=[...discoverTests(), 'test/new-unmeasured-fixture.test.mjs'];
  const groups=planTests(files,weights);
  assert.equal(groups.length,shardCount);
  assert.deepEqual(groups.flatMap(group=>group.files).sort(),[...files].sort());
  assert.equal(new Set(groups.flatMap(group=>group.files)).size,files.length);
  assert.ok(groups.every(group=>group.files.length>0));
  assert.deepEqual(planTests([...files].reverse(),weights),groups);
  assert.ok(Math.max(...groups.map(g=>g.estimatedMs))-Math.min(...groups.map(g=>g.estimatedMs))<60000,'current timing sample should distribute within one minute');
});

test('stale estimates cannot suppress tests, and malformed inventories fail closed',()=>{
  const files=['test/a.test.mjs','test/b.test.mjs','test/c.test.mjs','test/d.test.mjs'];
  assert.deepEqual(planTests(files,{'test/deleted.test.mjs':999999}).flatMap(g=>g.files).sort(),files);
  for(const bad of [[],[...files,files[0]],['--test-name-pattern=skip',...files],['test/../outside.test.mjs',...files]])assert.throws(()=>planTests(bad,weights));
  for(const count of [0,-1,1.5,17,5])assert.throws(()=>planTests(files,weights,count));
  for(const value of [-1,NaN,Infinity,'100'])assert.throws(()=>planTests(files,{'test/a.test.mjs':value}));
});

test('discovery includes only regular test files and rejects disguised test entries',t=>{
  const dir=temporary(t);fs.mkdirSync(path.join(dir,'test'));
  fs.writeFileSync(path.join(dir,'test/real.test.mjs'),'');fs.writeFileSync(path.join(dir,'test/helper.mjs'),'');
  assert.deepEqual(discoverTests(dir),['test/real.test.mjs']);
  fs.mkdirSync(path.join(dir,'test/unexpected.test.mjs'));
  assert.throws(()=>discoverTests(dir),/regular file/);
});

test('only ordinary documentation can skip integrations; runtime Markdown and unknown paths run everything',()=>{
  assert.equal(documentationOnly(['README.md','docs/CI.md','docs/guides/setup.md']),true);
  for(const files of [[],['src/ui.mjs'],['package.json'],['.github/workflows/check.yml'],['plugin/skills/bypass/SKILL.md'],['docs/muse_spark_bug_bounty_tier_1_tier_2.md'],['scanner/README.md'],['docs/fixture.json'],['docs/../src/notes.md'],['README.md','test/x.test.mjs'],['docs/a.md\nother']])assert.equal(documentationOnly(files),false,JSON.stringify(files));
});

test('Git change classification includes additions, deletions, and both sides of renames',t=>{
  const dir=temporary(t);
  const git=(...args)=>execFileSync('git',args,{cwd:dir,encoding:'utf8',stdio:['ignore','pipe','pipe']}).trim();
  git('init','-q');git('config','user.email','ci-test@example.invalid');git('config','user.name','CI fixture');
  fs.writeFileSync(path.join(dir,'README.md'),'initial\n');fs.writeFileSync(path.join(dir,'deleted.mjs'),'source\n');
  git('add','.');git('commit','-qm','base');const base=git('rev-parse','HEAD');
  fs.writeFileSync(path.join(dir,'README.md'),'documentation\n');git('commit','-qam','docs');const docs=git('rev-parse','HEAD');
  assert.equal(documentationOnly(changedFiles(base,docs,dir)),true);
  fs.mkdirSync(path.join(dir,'src'));fs.renameSync(path.join(dir,'README.md'),path.join(dir,'src/code.mjs'));fs.unlinkSync(path.join(dir,'deleted.mjs'));
  git('add','-A');git('commit','-qm','code');const head=git('rev-parse','HEAD');
  assert.deepEqual(changedFiles(docs,head,dir).sort(),['README.md','deleted.mjs','src/code.mjs']);
  assert.equal(documentationOnly(changedFiles(docs,head,dir)),false);
  assert.throws(()=>changedFiles('--help',head,dir),/exact base/);
});

const successful=()=>({fast:{result:'success',outputs:{full:'true'}},regression:{result:'success'},policy:{result:'success'},codeql:{result:'success'}});
test('the required check rejects failed, cancelled, skipped, or missing code gates',()=>{
  assert.doesNotThrow(()=>checkGate(successful()));
  for(const name of ['fast','regression','policy','codeql'])for(const result of ['failure','cancelled','skipped',undefined]){
    const needs=successful();needs[name].result=result;assert.throws(()=>checkGate(needs));
  }
  for(const full of [undefined,'','TRUE',true]){const needs=successful();needs.fast.outputs.full=full;assert.throws(()=>checkGate(needs));}
  assert.throws(()=>checkGate(null));
  const docs=successful();docs.fast.outputs.full='false';for(const name of ['regression','policy','codeql'])docs[name].result='skipped';
  assert.doesNotThrow(()=>checkGate(docs));docs.fast.result='failure';assert.throws(()=>checkGate(docs));
});

test('the planner defaults to full coverage when comparison metadata is unavailable',t=>{
  const dir=temporary(t),output=path.join(dir,'outputs');
  const env={...process.env,GITHUB_OUTPUT:output,CI_BASE_SHA:'invalid',CI_HEAD_SHA:'invalid'};delete env.GITHUB_STEP_SUMMARY;delete env.NODE_TEST_CONTEXT;
  const result=spawnSync(process.execPath,['scripts/ci-tests.mjs','plan'],{cwd:root,env,encoding:'utf8',timeout:10000});
  assert.equal(result.status,0,result.stderr);const plan=JSON.parse(result.stdout);
  assert.equal(plan.full,true);assert.match(plan.reason,/running all checks/);
  const lines=fs.readFileSync(output,'utf8').trim().split('\n');assert.equal(lines[0],'full=true');
  assert.deepEqual(JSON.parse(lines[1].slice('matrix='.length)),{shard:[1,2,3,4]});
});

test('shard execution preserves Docker opt-in, runs every selected file, and propagates failure',async t=>{
  const dir=temporary(t);fs.mkdirSync(path.join(dir,'test'));fs.writeFileSync(path.join(dir,'test/legacy-muse-env.mjs'),'');
  const log=path.join(dir,'executed');
  for(const name of ['a','b'])fs.writeFileSync(path.join(dir,`test/${name}.test.mjs`),`import fs from 'node:fs'; import assert from 'node:assert/strict'; assert.equal(process.env.BYPASS_DOCKER_TESTS,'1'); fs.appendFileSync(${JSON.stringify(log)},'${name}');`);
  const group={shard:1,estimatedMs:1,files:['test/a.test.mjs','test/b.test.mjs']};
  const options={root:dir,env:{...process.env,BYPASS_DOCKER_TESTS:'1'}};
  assert.equal(await runTests(group,options),0);assert.equal(fs.readFileSync(log,'utf8'),'ab');
  fs.appendFileSync(path.join(dir,'test/a.test.mjs'),'process.exitCode=1;');fs.writeFileSync(log,'');
  assert.equal(await runTests(group,options),1);assert.equal(fs.readFileSync(log,'utf8'),'ab');
  await assert.rejects(runTests({...group,files:[]},options),/empty/);
});
