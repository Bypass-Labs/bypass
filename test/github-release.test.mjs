import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import {releaseInventory,releasePlatforms,installerFields,sha256,readReleaseFile} from '../scripts/release-files.mjs';
import {loadRelease,mirrorRelease,githubAPI,downloadBase} from '../scripts/github-release.mjs';

const repository='Bypass-Labs/bypass-for-muse',commit='a'.repeat(40),releaseId=`main-${commit}-1234-1`;
function fixture(){
  const bytes=new Map(),manifest={schemaVersion:1,releaseId,commit,version:'0.7.7',assets:[]};
  const add=file=>{const body=Buffer.from(`fixture: ${file}`);bytes.set(file,body);return {file,size:body.length,sha256:sha256(body)};};
  for(const platform of releasePlatforms)manifest.assets.push({...add(`bypass-${platform}${platform.startsWith('win-')?'.zip':'.tar.gz'}`),platform});
  for(const [key,file] of Object.entries(installerFields))manifest[key]=add(file);
  const checksums=Buffer.from(manifest.assets.map(a=>`${a.sha256}  ${a.file}`).join('\n')+'\n');
  bytes.set('SHASUMS256.txt',checksums);manifest.checksums={file:'SHASUMS256.txt',size:checksums.length,sha256:sha256(checksums)};
  bytes.set('release.json',Buffer.from(JSON.stringify(manifest)+'\n'));
  return {bytes,source:{...releaseInventory(bytes.get('release.json')),read:async file=>bytes.get(file.file)}};
}
function github(){
  const state={release:null,tag:null,assets:[],calls:[],uploads:0,failAt:0};
  const api=async(method,route,options={})=>{
    state.calls.push({method,route,options});
    const url=new URL(route,'https://api.github.com'),p=url.pathname;
    if(p.includes('/git/ref/tags/'))return state.tag;
    if(p.includes('/commits/'))return {sha:commit};
    if(p.includes('/releases/tags/'))return state.release?.draft?null:state.release;
    if(p.endsWith('/releases')&&method==='GET')return state.release?[state.release]:[];
    if(p.endsWith('/releases')&&method==='POST')return state.release={...options.body,id:12,html_url:'https://github.com/'+repository+'/releases/tag/'+releaseId};
    if(method==='PATCH'){
      Object.assign(state.release,options.body);state.tag={object:{type:'commit',sha:commit}};return state.release;
    }
    if(method==='DELETE'){state.assets=state.assets.filter(a=>a.id!==Number(p.split('/').at(-1)));return null;}
    if(p.endsWith('/assets')&&method==='GET')return state.assets.map(a=>({...a}));
    if(p.endsWith('/assets')&&method==='POST'){
      state.uploads++;assert.equal(options.upload,true);
      if(state.failAt===state.uploads)throw new Error('Synthetic interrupted upload');
      const asset={id:100+state.uploads,name:url.searchParams.get('name'),size:options.bytes.length,digest:'sha256:'+sha256(options.bytes),state:'uploaded'};
      state.assets.push(asset);return asset;
    }
    throw new Error('Unexpected API request: '+method+' '+route);
  };
  return {state,api};
}
const run=(source,api,options={})=>mirrorRelease({source,repository,api,log:()=>{},wait:async()=>{},...options});
const channel=async()=>Response.json({releaseId,commit});

test('GitHub archives the exact complete R2 inventory; drafts are reusable without duplicate uploads',async()=>{
  const {source,bytes}=fixture(),{state,api}=github();
  const result=await run(source,api);
  assert.equal(result.draft,true);assert.equal(result.verifiedAssets,13);
  assert.equal(state.uploads,13);assert.equal(state.release.target_commitish,commit);
  for(const request of state.calls.filter(c=>c.options.upload)){
    const name=new URL(request.route,'https://api.github.com').searchParams.get('name');
    assert.deepEqual(request.options.bytes,bytes.get(name));
  }
  await run(source,api);assert.equal(state.uploads,13);
  assert.equal(state.calls.filter(c=>c.method==='POST'&&c.route.endsWith('/releases')).length,1);
  await run(source,api,{mode:'verify'});assert.equal(state.release.draft,true);
});

test('interrupted uploads resume the draft and never replace completed files',async()=>{
  const {source}=fixture(),{state,api}=github();state.failAt=4;
  await assert.rejects(run(source,api),/interrupted upload/);
  const first=state.assets.map(a=>a.id);assert.equal(first.length,3);
  state.failAt=0;await run(source,api);
  assert.deepEqual(state.assets.slice(0,3).map(a=>a.id),first);
  assert.equal(state.assets.length,13);assert.equal(state.release.draft,true);
});

test('failed zero-byte starter assets can retry only on a matching draft',async()=>{
  const {source}=fixture(),{state,api}=github();await run(source,api);
  const failed=state.assets[0];failed.state='starter';failed.size=0;
  await run(source,api);assert.equal(state.uploads,14);
  assert.equal(state.calls.filter(c=>c.method==='DELETE').length,1);
});

test('mismatched uploaded files and unexpected assets fail without replacement',async()=>{
  for(const corruption of ['digest','extra','duplicate']){
    const {source}=fixture(),{state,api}=github();await run(source,api);
    if(corruption==='digest')state.assets[0].digest='sha256:'+'f'.repeat(64);
    if(corruption==='extra')state.assets.push({...state.assets[0],name:'unrelated.txt'});
    if(corruption==='duplicate')state.assets.push({...state.assets[0]});
    await assert.rejects(run(source,api),/differs|unexpected|duplicate/);
    assert.equal(state.uploads,13);assert.equal(state.calls.filter(c=>c.method==='DELETE').length,0);
  }
});

test('publish requires all GitHub digests and matching R2 promotion before creating the source tag',async()=>{
  const {source}=fixture(),{state,api}=github();await run(source,api);
  await assert.rejects(run(source,api,{mode:'publish',fetchImpl:async()=>Response.json({releaseId:'other',commit})}),/promoted on R2/);
  assert.equal(state.release.draft,true);assert.equal(state.tag,null);
  const old=state.assets[0].digest;state.assets[0].digest=null;
  await assert.rejects(run(source,api,{mode:'publish',fetchImpl:channel}),/incomplete|checksum/);
  assert.equal(state.release.draft,true);state.assets[0].digest=old;
  const result=await run(source,api,{mode:'publish',fetchImpl:channel});
  assert.equal(result.draft,false);assert.equal(state.tag.object.sha,commit);
  assert.equal(state.release.prerelease,true);
  const patches=state.calls.filter(c=>c.method==='PATCH').length;
  await run(source,api,{mode:'publish',fetchImpl:channel});
  assert.equal(state.calls.filter(c=>c.method==='PATCH').length,patches);
});

test('wrong tags, unrelated drafts, and published incomplete releases are never rewritten',async()=>{
  const {source}=fixture();
  for(const scenario of ['tag','identity','published']){
    const {state,api}=github();await run(source,api);const calls=state.calls.length;
    if(scenario==='tag')state.tag={object:{type:'commit',sha:'b'.repeat(40)}};
    if(scenario==='identity')state.release.target_commitish='b'.repeat(40);
    if(scenario==='published'){state.release.draft=false;state.assets.pop();}
    await assert.rejects(run(source,api),/tag|identity|published/);
    assert.ok(state.calls.slice(calls).every(c=>c.method==='GET'));
  }
});

test('manifest validation binds source identity and requires exact unique platform filenames',()=>{
  const {source}=fixture();
  for(const mutate of [m=>m.commit='b'.repeat(40),m=>m.assets.pop(),m=>m.assets[0]=m.assets[1],m=>m.assets[0].file='../secret',m=>m.installer.file='token',m=>m.assets[0].sha256='bad',m=>m.assets[0].size=100000001]){
    const value=structuredClone(source.manifest);mutate(value);
    assert.throws(()=>releaseInventory(Buffer.from(JSON.stringify(value))));
  }
  assert.throws(()=>releaseInventory(Buffer.from(JSON.stringify(source.manifest)),'b'.repeat(40)),/CI commit/);
});

test('corrupt file or checksum-list bytes are rejected before any GitHub write',async()=>{
  const {source,bytes}=fixture(),{state,api}=github();bytes.set(source.files[0].file,Buffer.from('corrupt'));
  await assert.rejects(run(source,api),/checksum mismatch/);assert.equal(state.calls.length,0);
  const second=fixture();const bad=Buffer.from('wrong checksum list\n');second.bytes.set('SHASUMS256.txt',bad);
  const metadata={file:'SHASUMS256.txt',size:bad.length,sha256:sha256(bad)};
  second.source.files[second.source.files.findIndex(f=>f.file==='SHASUMS256.txt')]=metadata;
  await assert.rejects(run(second.source,api),/Checksum list/);assert.equal(state.calls.length,0);
});

test('release files reject symlinks and load from the same local manifest',async t=>{
  const {source,bytes}=fixture(),directory=fs.mkdtempSync(path.join(os.tmpdir(),'bypass-github-release-'));
  t.after(()=>fs.rmSync(directory,{recursive:true,force:true}));
  for(const [file,body] of bytes)fs.writeFileSync(path.join(directory,file),body);
  const loaded=await loadRelease({dist:directory,expectedCommit:commit});assert.equal(loaded.files.length,13);
  const asset=source.files[0],location=path.join(directory,asset.file);
  fs.renameSync(location,location+'.original');
  if(process.platform!=='win32'){
    fs.symlinkSync(location+'.original',location);
    assert.throws(()=>readReleaseFile(directory,asset),/regular file/);
  }
});

test('R2 backfill downloads original bytes without GitHub credentials or redirect following',async()=>{
  const {bytes}=fixture(),requests=[];
  const fetchImpl=async(url,options)=>{requests.push({url,options});return new Response(bytes.get(new URL(url).pathname.split('/').at(-1)));};
  const loaded=await loadRelease({releaseId,expectedCommit:commit,fetchImpl});
  for(const file of loaded.files)assert.deepEqual(await loaded.read(file),bytes.get(file.file));
  assert.ok(requests.every(r=>r.url.startsWith(downloadBase+'/releases/'+releaseId+'/')&&r.options.redirect==='error'&&!r.options.headers));
  const corrupt=await loadRelease({releaseId,fetchImpl:async url=>new Response(url.endsWith('release.json')?bytes.get('release.json'):Buffer.from('bad'))});
  await assert.rejects(corrupt.read(corrupt.files[0]),/checksum/);
  await assert.rejects(loadRelease({releaseId:'../other',fetchImpl}),/Invalid R2/);
});

test('GitHub credentials are confined to API/upload origins and redirects fail closed',async()=>{
  const calls=[],api=githubAPI('synthetic-token',async(url,options)=>{calls.push({url,options});return Response.json({id:1});});
  await api('GET','/repos/owner/repo/releases');
  await api('POST','/repos/owner/repo/releases/1/assets?name=a.zip',{bytes:Buffer.from('zip'),upload:true});
  assert.deepEqual(calls.map(c=>new URL(c.url).hostname),['api.github.com','uploads.github.com']);
  assert.ok(calls.every(c=>c.options.headers.Authorization==='Bearer synthetic-token'&&c.options.redirect==='error'));
  await assert.rejects(api('GET','https://unrelated.example/secret'),/Invalid GitHub route/);
});

test('release workflow archives before R2 upload and verifies the mirror before promotion',()=>{
  const workflow=fs.readFileSync(new URL('../.github/workflows/release.yml',import.meta.url),'utf8');
  const release=workflow.split('\n  release:\n')[1].split('\n  windows:\n')[0];
  const promote=workflow.split('\n  promote:\n')[1];
  assert.match(release,/if: github.ref == 'refs\/heads\/main'/);
  assert.match(release,/contents: write/);assert.match(promote,/contents: write/);
  assert.match(promote,/needs: \[release, windows, macos-terminal\]/);
  assert.ok(release.indexOf('npm run release:github')<release.indexOf('npm run release:upload'));
  assert.ok(promote.indexOf('--verify')<promote.indexOf('npm run release:promote'));
  assert.ok(promote.indexOf('--publish')>promote.indexOf('Verify both public installer entry points'));
  assert.match(workflow.split('jobs:')[0],/permissions:\n  contents: read/);
  assert.equal((workflow.match(/persist-credentials: false/g)||[]).length,5);
});
