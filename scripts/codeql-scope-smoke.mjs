/** Opt-in real CodeQL extraction: default scope vs explicit inclusion. */
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import assert from 'node:assert/strict';
import { execute } from '../src/service.mjs';
import { manifest } from '../src/scanner/contracts.mjs';
import { validateJSON } from '../src/schema.mjs';

const fixture=JSON.parse(fs.readFileSync(new URL('../scanner/tests/fixtures/cases.json',import.meta.url))).cases.find(item=>item.name==='javascript');
const root=fs.mkdtempSync(path.join(os.tmpdir(),'bypass-codeql-scope-'));
const paths=['src/main.js','tests/main.js','src/helper.test.js','examples/main.js','plugin/runtime/main.js','generated/main.js'];
for(const name of paths){const file=path.join(root,name);fs.mkdirSync(path.dirname(file),{recursive:true});fs.writeFileSync(file,fixture.files['main.js']);}
fs.writeFileSync(path.join(root,'package.json'),fixture.files['package.json']);
await execute('init',[root]);
console.log('Artifacts: '+root);
const results=[];
for(const include of [false,true]){
  const result=await execute('discover',[],{project:root,'discovery-only':true,languages:'javascript',rule:fixture.rule,
    ...(include?{'include-tests':true,'include-examples':true,'include-generated':true}:{})},
    {onProgress:step=>console.log(step.message)});
  assert.ok(result.run,JSON.stringify(result));
  assert.equal(result.run.status,'completed',JSON.stringify(result.run));
  assert.equal(result.run.modelCalls,0);
  const folder=path.join(root,'.bypass/scanner',result.run.id);
  const signals=JSON.parse(fs.readFileSync(path.join(folder,'signals.json')));
  for(const signal of signals)validateJSON(manifest.schemas.signal,signal);
  assert.equal(signals.length,include?6:1);
  const raw=JSON.parse(fs.readFileSync(path.join(folder,'languages/javascript/raw.sarif')));
  // Verify native CodeQL path filtering, independently of SARIF post-filtering.
  const alerts=raw.runs.flatMap(run=>run.results||[]).filter(item=>item.ruleId===fixture.rule);
  assert.equal(alerts.length,include?6:1);
  assert.ok(fs.existsSync(path.join(folder,'languages/javascript/work/tests/main.js')));
  assert.equal(result.run.scope.excludedFiles,include?0:5);
  assert.equal(result.run.scope.analysisFiles,result.run.scope.contextFiles-(include?0:5));
  const scope=JSON.parse(fs.readFileSync(path.join(folder,'analysis-scope.json')));
  assert.deepEqual(scope.summary,result.run.scope);
  assert.equal(scope.includedPaths.filter(name=>paths.includes(name)).length,include?6:1);
  results.push({run:result.run.id,include,signals:signals.length,scope:result.run.scope});
  console.log(`PASS ${include?'explicit inclusion':'default exclusions'}: ${signals.length} signals; build context retained`);
}
fs.writeFileSync(path.join(root,'scope-results.json'),JSON.stringify(results,null,2)+'\n');
