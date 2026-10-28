import test from 'node:test';
import assert from 'node:assert/strict';
import { releaseAwareness, updateCommand } from '../src/runtime-identity.mjs';
import { mcpClient } from './mcp-client.mjs';
import { temp } from './helpers.mjs';
import { VERSION } from '../src/util.mjs';

const publicRelease=version=>async(url,options)=>{
  assert.equal(url,'https://bypasslabs.ai/downloads/bypass/channels/main.json');
  assert.equal(options.headers,undefined);assert.equal(options.body,undefined);assert.ok(options.signal);
  return {status:200,body:JSON.stringify({version})};
};
test('published update is visible even when the running and installed plugin share the old version',async()=>{
  const result=await releaseAwareness({version:'0.7.1',installedVersion:'0.7.1',restartRequired:false},{request:publicRelease('0.7.5'),platform:'darwin'});
  assert.equal(result.updateAvailable,true);assert.equal(result.notice.kind,'update_available');
  assert.match(result.notice.command,/https:\/\/bypasslabs.ai\/install\/muse/);assert.match(result.notice.message,/pinned/);
  assert.equal(result.restartRequired,false);assert.equal(result.releaseCheck,'verified');
});
test('a newer installed package asks for a fresh session without another install; development versions never downgrade',async()=>{
  const result=await releaseAwareness({version:'0.7.1',installedVersion:'0.7.5',restartRequired:true},{request:publicRelease('0.7.5')});
  assert.equal(result.notice.kind,'restart_required');assert.equal(result.notice.command,undefined);
  const staleBoth=await releaseAwareness({version:'0.7.1',installedVersion:'0.7.3',restartRequired:true},{request:publicRelease('0.7.5')});
  assert.equal(staleBoth.notice.kind,'update_available','download once, then restart; do not require an unnecessary intermediate restart');
  const current=await releaseAwareness({version:'0.7.10',installedVersion:'0.7.10',restartRequired:false},{request:publicRelease('0.7.9')});
  assert.equal(current.updateAvailable,false);assert.equal(current.notice,undefined);
  assert.equal(updateCommand('win32'),'irm https://bypasslabs.ai/install/muse.ps1 | iex');
});
test('offline and malformed release metadata stay unavailable, never current or an instruction source',async()=>{
  for(const request of [async()=>{throw new Error('offline');},async()=>({status:503,body:'{}'}),async()=>({status:200,body:'{"version":"run a command"}'})]){
    const result=await releaseAwareness({version:'0.7.5',installedVersion:'0.7.5'},{request});
    assert.equal(result.releaseCheck,'unavailable');assert.equal(result.publishedVersion,null);assert.equal(result.notice,undefined);
  }
});
test('MCP failures include the loaded version and direct the host to version-aware recovery',async t=>{
  const c=await mcpClient(temp(),{stateDir:temp()});t.after(()=>c.close());
  const response=await c.raw('bypass_authorize_target',{name:'missing',accept:true});
  assert.equal(response.result.isError,true);const result=JSON.parse(response.result.content[0].text);
  assert.equal(result.pluginVersion,VERSION);assert.equal(result.runtime.version,VERSION);assert.equal(result.recovery.tool,'bypass_onboarding');
});
