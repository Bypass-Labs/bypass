/** Opt-in actual Docker/CodeQL fixtures; no hosted LLM or customer source. */
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import assert from 'node:assert/strict';
import { execute } from '../src/service.mjs';
import { mcpClient } from '../test/mcp-client.mjs';
import { manifest } from '../src/scanner/contracts.mjs';
import { validateJSON } from '../src/schema.mjs';

const definitions=JSON.parse(fs.readFileSync(new URL('../scanner/tests/fixtures/cases.json',import.meta.url)));
const filter=process.env.BYPASS_CODEQL_CASES?.split(',');
const cases=definitions.cases.filter(item=>!filter||filter.includes(item.name));
assert.ok(cases.length,'No selected acceptance fixtures');
const concurrency=Number(process.env.BYPASS_CODEQL_CONCURRENCY||2);
assert.ok([1,2].includes(concurrency),'CodeQL fixture concurrency must be 1 or 2');
const output=fs.mkdtempSync(path.join(os.tmpdir(),'bypass-codeql-acceptance-'));
console.log('Artifacts: '+output);
const results=[], failures=[];
async function runCase(item,variant){
 const root=path.join(output,item.name+'-'+variant);fs.mkdirSync(root);
 for(const [name,text] of Object.entries({...item.files,...(variant==='safe'?item.safe:{})})){
  fs.mkdirSync(path.dirname(path.join(root,name)),{recursive:true});fs.writeFileSync(path.join(root,name),text);
 }
 await execute('init',[root]);
 const config={evaluation:'off',languages:[item.language],includeRules:[item.rule],resources:{timeoutSeconds:180},...(item.build?{builds:{[item.language]:item.build}}:{})};
 fs.writeFileSync(path.join(root,'scanner.json'),JSON.stringify(config));
 const result=await execute('discover',[],{project:root,config:'scanner.json'}, {onProgress:step=>console.log(`${item.name}/${variant}: ${step.message}`)});
 const run=result.run;
 assert.ok(run,item.name+': '+JSON.stringify(result));
 assert.equal(run.modelCalls,0);
 assert.equal(run.evaluation,'not_run');
 assert.ok(run.languages.every(language=>language.queryComplete),`${item.name}/${variant}: extraction/query incomplete: ${JSON.stringify(run)}`);
 const signals=JSON.parse(fs.readFileSync(path.join(root,'.bypass/scanner',run.id,'signals.json')));
 for(const signal of signals)validateJSON(manifest.schemas.signal,signal,'normalized signal');
 const count=signals.filter(signal=>signal.ruleId===item.rule).length;
 assert.ok(variant==='safe'?count===0:count>0,`${item.name}/${variant}: expected ${variant==='safe'?'no':'a'} ${item.rule} signal; got ${count}`);
 if(variant==='vulnerable')assert.ok(signals.some(signal=>signal.ruleId===item.rule&&signal.evidence.length>0),'Expected citable source evidence');
 results.push({case:item.name,variant,runId:run.id,root,status:run.status,signals:count});
 console.log(`PASS ${item.name}/${variant}: ${count} signals`);
}
// Stay within the default Docker memory budget, including CodeQL's JVM overhead.
for(let start=0;start<cases.length;start+=concurrency){
 await Promise.all(cases.slice(start,start+concurrency).map(async item=>{for(const variant of ['vulnerable','safe']){try{await runCase(item,variant);}catch(error){failures.push({case:item.name,variant,message:error.message});console.error(`FAIL ${item.name}/${variant}: ${error.message}`);}}}));
 fs.writeFileSync(path.join(output,'results.json'),JSON.stringify({results,failures},null,2));
}
if(results.some(item=>item.case==='javascript'&&item.variant==='vulnerable')){
 const root=results.find(item=>item.case==='javascript'&&item.variant==='vulnerable').root;
 const client=await mcpClient(root,{stateDir:path.join(output,'plugin-state'),packaged:true});
 try{
  await client.call('bypass_connect_repository',{repository:root,confirmed:true});
  const started=await client.call('bypass_discover',{detector:'codeql',languages:'javascript',rule:'js/command-line-injection','discovery-only':true});
  let run=started.run;
  const deadline=Date.now()+240000;
  while(!['completed','incomplete','failed','cancelled','interrupted'].includes(run.status)){
   assert.equal(run.evaluation,'not_run','Packaged MCP discovery-only scan must not start evaluation');
   assert.ok(Date.now()<deadline,'Packaged MCP scan timed out');
   await new Promise(resolve=>setTimeout(resolve,500));
   const message=await client.raw('bypass_discover_status',{run:run.id});
   run=JSON.parse(message.result.content[0].text).run;
  }
  assert.ok(run.languages.every(language=>language.queryComplete));assert.ok(run.signalCount>0);assert.equal(run.modelCalls,0);assert.equal(run.evaluation,'not_run');
  console.log('PASS packaged Muse MCP discovery');
 }finally{await client.close();}
}
console.log(JSON.stringify({passed:results.length,failures,output},null,2));
assert.equal(failures.length,0,'CodeQL acceptance failures; inspect retained artifacts');
