import test from 'node:test';
import assert from 'node:assert/strict';
import { EventEmitter } from 'node:events';
import { createInstallProgress, createSetupActivity } from '../src/install-progress.mjs';
import { stripVTControlCharacters } from 'node:util';

function fixture(env={},isTTY=true){
  let time=0;const chunks=[],output=Object.assign(new EventEmitter(),{isTTY,columns:80,write:value=>chunks.push(value)});
  const progress=createInstallProgress({output,env:{TERM:'xterm-256color',...env},clock:()=>time});
  return {progress,output,chunks,tick:ms=>{time=ms;output.emit('resize');},text:()=>stripVTControlCharacters(chunks.at(-1))};
}
test('a long Muse wait never advances stages or invents a percentage',()=>{
  const f=fixture();
  try{
    f.progress.update({phase:'install',operation:'install'});f.tick(61000);
    assert.match(f.text(),/✓ Check setup/);assert.match(f.text(),/Install plugin · 1m 1s/);
    assert.match(f.text(),/○ Verify installation/);assert.doesNotMatch(f.text(),/✓ Install plugin|\d+%|remaining/);
    assert.match(f.text(),/Waiting for Muse to return/);assert.match(f.text(),/Ctrl\+C cancel/);
    f.progress.update({phase:'verify',operation:'inspect'});
    assert.match(f.text(),/✓ Install plugin/);assert.doesNotMatch(f.text(),/✓ Verify installation/);
    f.progress.finish({result:{reviewRequired:true}});assert.match(f.text(),/Plugin installed and verified/);
  }finally{f.progress.finish({error:new Error('test cleanup')});}
});
test('failure and cancellation clear live progress without reporting success',()=>{
  for(const code of [3,130]){
    const f=fixture();
    f.progress.update({phase:'install',operation:'install'});f.progress.cancel();
    f.progress.update({phase:'restore',operation:'install'});assert.match(f.text(),/Restoring the previous plugin/);
    f.progress.finish({error:{code}});
    assert.match(f.text(),code===130?/Setup cancelled/:/needs attention/);
    assert.doesNotMatch(f.text(),/installed and verified/);
    assert.equal(f.output.listenerCount('resize'),0);
    const before=f.chunks.length;f.output.emit('resize');f.progress.finish();assert.equal(f.chunks.length,before);
  }
});
test('logs, CI and plain mode have no cursor escapes; NO_COLOR keeps status legible',()=>{
  for(const [env,tty] of [[{},false],[{CI:'true'},true],[{TERM:'dumb'},true],[{BYPASS_PLAIN:'1',NO_COLOR:'1'},true]]){
    const f=fixture(env,tty);f.progress.update({phase:'install',operation:'install'});f.progress.finish({result:{alreadyInstalled:true}});
    assert.doesNotMatch(f.chunks.join(''),/\x1b|\r/);
    assert.match(f.chunks.join(''),/Existing plugin verified/);
  }
  const f=fixture({NO_COLOR:'1'});f.tick(1000);f.progress.finish();assert.doesNotMatch(f.chunks.join(''),/\x1b\[[0-9;]*m/);
});
test('narrow terminal retains next steps and timeout without wrapping the checklist',()=>{
  const f=fixture();
  try{
    f.output.columns=40;f.progress.update({phase:'install',operation:'install'});
    const frame=f.text();assert.ok(frame.split('\n').every(line=>line.length<40));
    assert.match(frame,/Next: permissions → open Muse/);assert.match(frame,/Muse timeout: 2m/);
  }finally{f.progress.finish();}
});

test('approval progress starts before waiting and never marks rejected approval as completed',async()=>{
  const chunks=[],output={isTTY:false,write:text=>chunks.push(text)};
  const activity=createSetupActivity({output});
  let release;const pending=activity('Enable security tools',()=>new Promise(resolve=>{release=resolve;}));
  assert.match(chunks.join(''),/Enable security tools…/);assert.doesNotMatch(chunks.join(''),/✓/);
  release();await pending;assert.match(chunks.join(''),/✓ Enable security tools/);
  chunks.length=0;
  await assert.rejects(activity('Enable security memory',async()=>{throw new Error('native rejection');}),/native rejection/);
  assert.doesNotMatch(chunks.join(''),/✓/);assert.match(chunks.join(''),/not completed/);
});
