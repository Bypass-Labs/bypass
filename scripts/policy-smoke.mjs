/** Real Docker/packaged MCP orchestration with scripted host responses, not an AI quality benchmark. */
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import {execute} from '../src/service.mjs';
import {prepareScanner,connectScanner} from '../src/scanner/runtime.mjs';
import {manifest} from '../src/scanner/contracts.mjs';
import {validateJSON} from '../src/schema.mjs';
import {mcpClient} from '../test/mcp-client.mjs';

const combined=process.argv.includes('--combined')||process.env.BYPASS_POLICY_TEST_COMBINED==='1';
const detector=combined?'both':'policy';
await prepareScanner({detector:combined?'codeql':'policy',onProgress:event=>console.log(event.message)});
if(!combined){
  const inspector=await connectScanner({detector:'policy'});
  try{const caps=await inspector.call('capabilities');assert.equal(caps.features.aiDiscovery,true);assert.equal(caps.features.codeqlReady,false);}
  finally{await inspector.close();}
}
const output=fs.mkdtempSync(path.join(os.tmpdir(),'bypass-policy-acceptance-'));
console.log('Artifacts: '+output);
for(const vulnerable of [true,false]){
  const root=path.join(output,vulnerable?'vulnerable':'safe');fs.mkdirSync(root);
  const body=vulnerable?'def invoice(request, invoices):\n    return invoices[request.invoice_id]\n':
    'def invoice(request, invoices):\n    item = invoices[request.invoice_id]\n    if item.owner_id != request.user_id:\n        raise PermissionError()\n    return item\n';
  fs.writeFileSync(path.join(root,'app.py'),body);
  fs.mkdirSync(path.join(root,'tests'));fs.writeFileSync(path.join(root,'tests/ignored.py'),'EXCLUDED_FIXTURE');
  await execute('init',[root]);
  const stateFile=path.join(root,'.bypass/state.json'),state=JSON.parse(fs.readFileSync(stateFile));
  state.models=[{name:'broken',provider:'invalid',secretEnv:'NEVER_READ_THIS'}];state.activeModel='broken';fs.writeFileSync(stateFile,JSON.stringify(state));
  const client=await mcpClient(root,{packaged:true,stateDir:path.join(output,'plugin-state-'+vulnerable)});
  try{
    await client.call('bypass_connect_repository',{repository:root,confirmed:true});
    const options={detector,policy:'authz/object-access,filesystem/path-containment','exclude-policy':'filesystem/path-containment'};
    if(combined){
      const page=await client.call('bypass_scanner_rules',{language:'python',limit:100});
      const other=page.rules.find(r=>r.id!=='py/weak-cryptographic-algorithm').id;
      options.rule='py/weak-cryptographic-algorithm,'+other;options['exclude-rule']=other;
    }
    let result=await client.call('bypass_discover',options),run=result.run;
    const deadline=Date.now()+300000;
    while(!['completed','incomplete','failed','cancelled','interrupted'].includes(run.status)){
      assert.ok(Date.now()<deadline,'Policy smoke timed out');
      if(run.status!=='awaiting_reasoning'){
        await new Promise(resolve=>setTimeout(resolve,250));run=(await client.call('bypass_discover_status',{run:run.id})).run;continue;
      }
      const leased=await client.call('bypass_discover_next_task',{run:run.id});
      if(!leased.task){run=leased.run;continue;}
      const task=leased.task;
      const evidence=await client.call('bypass_discover_evidence',{run:run.id,task:task.id,operation:'read',arguments:{path:'app.py'}});
      const ref=evidence.evidence.reference.id;
      const submission=task.kind!=='discovery'?{
        caseId:task.caseId,outcome:'needs_review',severity:'unknown',
        severityRationale:'Deployment reachability and upstream enforcement are unknown.',
        rationale:'The cited function returns a selected invoice without an owner binding; the caller is not established.',
        evidence:[ref],counterevidence:'Upstream authorization may exist outside the inspected function.',
        prerequisites:['An unprivileged caller can reach the function without another owner check.'],
        impact:'Private invoice contents could cross the ownership boundary.',
        openQuestions:['Is authorization enforced by the caller or deployment?'],
        nextAction:'Review callers and deployment controls before accepting the source hypothesis.',
        followUpQuestions:[]
      }:task.phase==='mapping'?{
        summary:'Invoice read with caller-selected identifier.',assumptions:['Deployment exposure unknown'],openQuestions:[],reviewedEvidence:[ref],
        surfaces:[{id:'invoice',title:'Invoice read',paths:['app.py'],policies:['authz/object-access'],evidence:[ref]}]
      }:{outcome:vulnerable?'candidates':'no_candidate',reviewedEvidence:[ref],rationale:vulnerable?'Object returned without an observed owner binding.':'Owner comparison precedes the return.',openQuestions:[],followUps:[],
        candidates:vulnerable?[{title:'Invoice ownership hypothesis',hypothesis:'The caller selects an invoice without an observed ownership binding.',attackerInput:'request.invoice_id',impact:'Another owner invoice could be returned.',
          evidence:[ref],counterevidence:'No binding in the cited handler; deployment and upstream controls are unknown.',assumptions:['Unprivileged caller reaches this handler.'],openQuestions:['Is upstream enforcement present?'],
          trace:[{role:'entrypoint',evidenceId:ref},{role:'sink',evidenceId:ref}]}]:[]};
      validateJSON(task.resultSchema,submission);
      const submitted=await client.raw('bypass_discover_submit',{run:run.id,task:task.id,sourceRevision:task.sourceRevision,result:submission});
      const accepted=JSON.parse(submitted.result.content[0].text);
      assert.ok(accepted.run,JSON.stringify(accepted));
      assert.equal(submitted.result.isError,accepted.run.status==='incomplete');
      run=accepted.run;
    }
    assert.equal(run.status,vulnerable?'incomplete':'completed',JSON.stringify(run));assert.equal(run.signalCount,vulnerable?1:0);
    assert.equal(run.evaluation,vulnerable?'incomplete':'completed');
    assert.equal(run.evaluationSummary.needs_review,vulnerable?1:0);
    assert.equal(run.reasoning.independentModelRequests,0);assert.equal(run.reasoning.hostTokens,null);
    const folder=path.join(root,'.bypass/scanner',run.id),signals=JSON.parse(fs.readFileSync(path.join(folder,'signals.json')));
    signals.forEach(signal=>validateJSON(manifest.schemas.signal,signal));
    assert.ok(signals.every(signal=>signal.detector==='policy'&&signal.evaluation==='not_run'));
    const cases=JSON.parse(fs.readFileSync(path.join(folder,'evaluation/cases.json')));
    cases.forEach(item=>validateJSON(manifest.schemas.evaluationCase,item));
    assert.equal(cases.length,signals.length);
    if(vulnerable)assert.equal(cases[0].evaluation.runtimeReproduced,false);
    assert.equal(fs.readFileSync(path.join(root,'app.py'),'utf8'),body);
    const selected=JSON.parse(fs.readFileSync(path.join(folder,'policy/selection.json')));
    assert.deepEqual(selected.policies.map(p=>p.id),['authz/object-access']);
    if(combined){
      const rules=JSON.parse(fs.readFileSync(path.join(folder,'rule-selection.json')));
      assert.deepEqual(rules.selected.map(r=>r.id),['py/weak-cryptographic-algorithm']);
      assert.ok(run.languages.every(language=>language.queryComplete));
    }
    console.log(`PASS ${detector}/${vulnerable?'vulnerable':'safe'}: ${signals.length} signals, automatic source evaluation ${run.evaluation}, zero independent requests, source preserved`);
  }finally{await client.close();}
}
