import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
import {isBypassSource,isBypassRepositoryURL,workspaceInfo} from '../src/project-selection.mjs';
import {execute} from '../src/service.mjs';
import {sessionHint} from '../src/plugin-context.mjs';
import {temp} from './helpers.mjs';
import {mcpClient} from './mcp-client.mjs';

test('the actual package and older tooling checkouts remain excluded from automatic application selection',async t=>{
  const checkout=fileURLToPath(new URL('../',import.meta.url));
  assert.equal(isBypassSource(checkout),true,'the shipped package name must match tooling detection');
  const workspace=await workspaceInfo(checkout);
  assert.equal(workspace.isBypassSource,true);assert.match(workspace.warning,/tooling source/);
  for(const name of ['@bypass-labs/bypass','@bypass-labs/cli-skeleton']){
    const root=temp();t.after(()=>fs.rmSync(root,{recursive:true,force:true}));
    fs.writeFileSync(path.join(root,'package.json'),JSON.stringify({name}));
    await execute('init',[root]);
    assert.equal(isBypassSource(root),true);
    assert.equal(sessionHint(root).selectedRepository,null);
  }
  const app=temp();t.after(()=>fs.rmSync(app,{recursive:true,force:true}));
  for(const content of ['{}','{"name":"bypass"}','{"name":"@customer/bypass"}','invalid json']){
    fs.writeFileSync(path.join(app,'package.json'),content);assert.equal(isBypassSource(app),false);
  }
  fs.unlinkSync(path.join(app,'package.json'));assert.equal(isBypassSource(app),false);
});

const toolingURLs=['bypass','bypass-for-muse'].flatMap(name=>[
  `https://github.com/Bypass-Labs/${name}`,
  `https://github.com/Bypass-Labs/${name}.git`,
  `git@github.com:Bypass-Labs/${name}.git`,
  `ssh://git@github.com/Bypass-Labs/${name}.git`
]);
test('tooling URL detection covers both names and Git transports without blocking unrelated projects',()=>{
  for(const url of [...toolingURLs,'https://GITHUB.COM/bypass-labs/BYPASS.git/'])assert.equal(isBypassRepositoryURL(url),true,url);
  for(const url of ['https://github.com/customer/bypass','https://github.com/customer/bypass-for-muse','https://gitlab.com/Bypass-Labs/bypass','https://github.com.evil.example/Bypass-Labs/bypass','https://github.com/Bypass-Labs/bypass-app','https://github.com/Bypass-Labs/job-finder','/tmp/bypass','not a url'])assert.equal(isBypassRepositoryURL(url),false,url);
});

test('MCP refuses tooling URLs before cloning and keeps explicit local self-review available',async t=>{
  const root=temp(),stateDir=temp();t.after(()=>{fs.rmSync(root,{recursive:true,force:true});fs.rmSync(stateDir,{recursive:true,force:true});});
  fs.writeFileSync(path.join(root,'package.json'),JSON.stringify({name:'@bypass-labs/bypass'}));
  fs.writeFileSync(path.join(root,'app.mjs'),'export const tooling=true;');
  const client=await mcpClient(root,{stateDir});
  try{
    for(const repository of toolingURLs){
      const reply=await client.raw('bypass_connect_repository',{repository,confirmed:true});
      assert.equal(reply.result.isError,true,repository);
      assert.match(reply.result.content[0].text,/URL identifies Bypass tooling/);
    }
    assert.equal(fs.existsSync(path.join(root,'.bypass')),false);
    const rejected=await client.raw('bypass_connect_repository',{repository:root,confirmed:true});
    assert.equal(rejected.result.isError,true);assert.match(rejected.result.content[0].text,/Bypass tooling repository/);
    const connected=await client.call('bypass_connect_repository',{repository:root,confirmed:true,allowBypassSource:true});
    assert.equal(connected.root,root);
  }finally{await client.close();}
});
