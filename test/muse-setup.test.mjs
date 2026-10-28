import test from 'node:test';
import assert from 'node:assert/strict';
import { finishMuseSetup, setupPrompt, setupTerminal } from '../src/muse-setup.mjs';

function fixture({answer='yes',status='review_needed',active=true}={}){
  const value={valid:true,active,record:{package_sha256:'package-a',cache_path:'/fixture/cache'},runtime_capabilities:['hook:session-context','mcp_server:security'].map(id=>({candidate:{stable_id:'plugin:bypass:'+id,definition_hash:'hash-'+id},status}))};
  const calls=[],output=[];
  const options={cwd:"/fixture/customer app & Ω",inspect:async()=>structuredClone(value),write:line=>output.push(line),ask:async()=>{calls.push('ask');return answer;},approve:async id=>{calls.push(id);value.runtime_capabilities.find(row=>row.candidate.stable_id===id).status='trusted_enabled';},launch:async prompt=>{calls.push(['launch',prompt]);return 0;}};
  return {value,calls,output,options};
}

test('one explicit consent approves only the two declared capabilities and opens onboarding',async()=>{
  const f=fixture();const result=await finishMuseSetup(f.options);
  assert.equal(result.opened,true);
  assert.deepEqual(f.calls,['ask','plugin:bypass:mcp_server:security','plugin:bypass:hook:session-context',['launch',setupPrompt]]);
  assert.match(f.output.join('\n'),/Security tools \(needs permission\)/);
  assert.match(f.output.join('\n'),/test approved app routes/);
  assert.match(f.output.join('\n'),/Security memory \(needs permission\)/);
  assert.match(f.output.join('\n'),/saved project security context/);
  assert.match(f.output.join('\n'),/verified ownership and an approved scope/);
  assert.match(f.output.join('\n'),/2 \/ n.*Keep installed.*Enter/);
  assert.match(f.output.join('\n'),/customer app & Ω/);
});

test('numbered consent and customize options behave distinctly',async()=>{
  const yes=fixture({answer:'1'});assert.equal((await finishMuseSetup(yes.options)).opened,true);
  const defer=fixture({answer:'2'});assert.equal((await finishMuseSetup(defer.options)).state,'deferred');assert.deepEqual(defer.calls,['ask']);
  const custom=fixture({answer:'3'});assert.equal((await finishMuseSetup(custom.options)).state,'manual_review');assert.deepEqual(custom.calls,['ask']);assert.ok(custom.value.runtime_capabilities.every(row=>row.status==='review_needed'));
});

test('decline, empty input and cancellation leave permissions unchanged and do not launch',async()=>{
  for(const answer of ['n','',null,'anything else']){
    const f=fixture({answer});const result=await finishMuseSetup(f.options);
    assert.equal(result.opened,false);assert.deepEqual(f.calls,['ask']);
    assert.ok(f.value.runtime_capabilities.every(row=>row.status==='review_needed'));
  }
});

test('headless installation never approves or launches, even with piped input',async()=>{
  const f=fixture();delete f.options.ask;
  assert.equal((await finishMuseSetup(f.options)).state,'review_required');assert.deepEqual(f.calls,[]);
  assert.equal(setupTerminal({env:{CI:'true'}}),null);
  assert.equal(setupTerminal({env:{BYPASS_NO_OPEN_MUSE:'1'}}),null);
});

test('approved rerun opens after consent without changing previous approval',async()=>{
  const f=fixture({status:'trusted_enabled'});await finishMuseSetup(f.options);
  assert.deepEqual(f.calls,['ask',['launch',setupPrompt]]);
});

test('partial permission approval identifies the remaining choice and only enables that capability',async()=>{
  const f=fixture();f.value.runtime_capabilities[0].status='trusted_enabled';
  await finishMuseSetup(f.options);
  assert.match(f.output.join('\n'),/Security memory \(already enabled\)/);
  assert.deepEqual(f.calls,['ask','plugin:bypass:mcp_server:security',['launch',setupPrompt]]);
});

test('cancelling after yes stops further approvals and never opens Muse',async()=>{
  const f=fixture(),controller=new AbortController();let approved=0;
  f.options.signal=controller.signal;
  const original=f.options.approve;
  f.options.approve=async id=>{await original(id);approved++;controller.abort();};
  await assert.rejects(finishMuseSetup(f.options),error=>error.code===130);
  assert.equal(approved,1);assert.ok(!f.calls.some(call=>Array.isArray(call)));
});

test('disabled, rejected, missing and unknown capabilities require manual attention',async()=>{
  for(const mutate of [v=>{v.active=false;},v=>{v.runtime_capabilities[0].status='trusted_disabled';},v=>{v.runtime_capabilities=[];},v=>{v.runtime_capabilities.push({candidate:{stable_id:'plugin:bypass:hook:extra'},status:'review_needed'});}]){
    const f=fixture();mutate(f.value);
    assert.equal((await finishMuseSetup(f.options)).state,'manual_review');assert.deepEqual(f.calls,[]);
  }
});

test('package or permission changes during the prompt invalidate the consent',async()=>{
  for(const mutate of [v=>{v.record.package_sha256='package-b';},v=>{v.runtime_capabilities[0].candidate.definition_hash='changed';},v=>{v.runtime_capabilities[0].status='trusted_disabled';},v=>{v.active=false;}]){
    const f=fixture();f.options.ask=async()=>{mutate(f.value);return 'yes';};
    await assert.rejects(finishMuseSetup(f.options),/changed during permission review/);assert.deepEqual(f.calls,[]);
  }
});

test('failed or unconfirmed native approval never starts Muse',async()=>{
  for(const fail of [true,false]){
    const f=fixture();f.options.approve=async()=>{if(fail)throw new Error('native approval failed');};
    await assert.rejects(finishMuseSetup(f.options),/approval failed|not confirmed/);
    assert.ok(!f.calls.some(call=>Array.isArray(call)));
  }
});
