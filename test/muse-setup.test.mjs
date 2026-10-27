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
  assert.deepEqual(f.calls,['ask','plugin:bypass:hook:session-context','plugin:bypass:mcp_server:security',['launch',setupPrompt]]);
  assert.match(f.output.join('\n'),/Security tools:.*authorized app requests/);
  assert.match(f.output.join('\n'),/Session context:.*saved security context/);
  assert.match(f.output.join('\n'),/customer app & Ω/);
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
