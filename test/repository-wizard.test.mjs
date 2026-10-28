import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { onboard } from '../src/onboarding.mjs';
import { execute } from '../src/service.mjs';
import { read } from '../src/store.mjs';
import { execFile } from '../src/util.mjs';
import { temp } from './helpers.mjs';

const remote='https://example.test/team/job-finder';
const remainingSetup=['1','','','','n','n']; // Model setup, no connection test or dashboard; source-only flow.

async function fixture(t) {
  const home=temp(), source=path.join(home,'source'), config=path.join(home,'gitconfig');
  const previousCwd=process.cwd();process.chdir(home);
  t.mock.method(os,'homedir',()=>home);
  const environment={GIT_CONFIG_GLOBAL:config,GIT_CONFIG_NOSYSTEM:'1',GIT_TERMINAL_PROMPT:'0'};
  const previous=Object.fromEntries(Object.keys(environment).map(key=>[key,process.env[key]]));
  Object.assign(process.env,environment);
  t.after(()=>{process.chdir(previousCwd);for(const [key,value] of Object.entries(previous))if(value===undefined)delete process.env[key];else process.env[key]=value;fs.rmSync(home,{recursive:true,force:true});});
  async function git(...args) { const result=await execFile('git',args);assert.equal(result.code,0,result.stderr);return result; }
  await git('init',source);
  fs.writeFileSync(path.join(source,'README.md'),'Fixture source; never executed.');
  fs.writeFileSync(path.join(source,'app.mjs'),'export const sourceOnlyFixture = true;');
  await git('-C',source,'add','README.md','app.mjs');
  await git('-C',source,'-c','user.name=Fixture','-c','user.email=fixture@example.test','commit','-m','Fixture');
  // Real git clone, with these test URLs mapped to a local fixture. No external request.
  await git('config','--file',config,`url.${source}.insteadOf`,remote);
  await git('config','--file',config,'--add',`url.${source}.insteadOf`,'git@example.test:team/job-finder.git');
  return {home,source,git};
}

async function wizard(answers,options={}) {
  const prompts=[],output=[];
  const result=await onboard({flow:'quickstart',mode:'code',...options},[],{
    write:value=>output.push(value),
    ask:async(label,fallback)=>{
      prompts.push({label,fallback});
      assert.ok(answers.length,`Unexpected prompt: ${label}\n${output.join('\n')}`);
      return answers.shift()||fallback||'';
    }
  });
  assert.equal(answers.length,0,'Unused wizard answers');
  return {result,prompts,output:output.join('\n')};
}

test('Git URL plus Enter clones into the suggested project folder and continues setup',async t=>{
  const {home}=await fixture(t);
  const actual=await wizard([`[${remote}](${remote})`,'',...remainingSetup]);
  assert.equal(actual.result.root,path.join(home,'Projects/job-finder'));
  assert.equal(actual.prompts.find(p=>p.label==='Clone into folder').fallback,'~/Projects/job-finder');
  assert.equal(fs.readFileSync(path.join(actual.result.root,'README.md'),'utf8'),'Fixture source; never executed.');
  assert.equal(read(actual.result.root).project.repository.kind,'git');
  assert.equal(read(actual.result.root).models[0].provider,'meta');
});

test('an occupied parent suggests a child and retries only the folder, preserving existing files',async t=>{
  const {home}=await fixture(t);
  fs.mkdirSync(path.join(home,'Projects'));
  const existing=path.join(home,'Projects/keep.txt');fs.writeFileSync(existing,'Do not change.');
  const actual=await wizard([remote,'~/Projects/','',...remainingSetup]);
  assert.equal(actual.result.root,path.join(home,'Projects/job-finder'));
  assert.equal(actual.prompts.filter(p=>p.label==='Repository directory or Git URL').length,1);
  assert.deepEqual(actual.prompts.filter(p=>p.label==='Clone into folder').map(p=>p.fallback),['~/Projects/job-finder','~/Projects/job-finder']);
  assert.match(actual.output,/already contains files/);
  assert.equal(fs.readFileSync(existing,'utf8'),'Do not change.');
});

test('an occupied suggested folder or file gets a usable new suggestion without overwriting',async t=>{
  const {home}=await fixture(t);
  const occupied=path.join(home,'Projects/job-finder');fs.mkdirSync(occupied,{recursive:true});
  fs.writeFileSync(path.join(occupied,'keep.txt'),'Keep');
  fs.writeFileSync(`${occupied}-2`,'Also keep');
  const actual=await wizard([remote,'','',...remainingSetup]);
  assert.equal(actual.result.root,`${occupied}-3`);
  assert.equal(actual.prompts.filter(p=>p.label==='Clone into folder')[1].fallback,'~/Projects/job-finder-3');
  assert.equal(fs.readFileSync(path.join(occupied,'keep.txt'),'utf8'),'Keep');
  assert.equal(fs.readFileSync(`${occupied}-2`,'utf8'),'Also keep');
  const second=await wizard([remote,'~/Projects/job-finder-2','',...remainingSetup]);
  assert.equal(second.result.root,`${occupied}-4`);
  assert.match(second.output,/is a file/);
});

test('an existing matching checkout resumes its saved setup and preserves uncommitted source',async t=>{
  await fixture(t);
  const first=await wizard([remote,'',...remainingSetup]);
  const id=read(first.result.root).project.id;
  fs.writeFileSync(path.join(first.result.root,'README.md'),'Uncommitted work');
  const resumed=await wizard([remote,'','yes','n','n']);
  assert.equal(resumed.result.root,first.result.root);
  assert.equal(read(resumed.result.root).project.id,id);
  assert.equal(read(resumed.result.root).models.length,1);
  assert.equal(fs.readFileSync(path.join(resumed.result.root,'README.md'),'utf8'),'Uncommitted work');
  assert.match(resumed.output,/already checked out/);
  assert.match(resumed.output,/resuming saved setup/);
});

test('a different origin is explained and the user can explicitly choose that local checkout',async t=>{
  const {git}=await fixture(t);
  const first=await wizard([remote,'',...remainingSetup]);
  await git('-C',first.result.root,'remote','set-url','origin','https://example.test/my-fork/job-finder.git');
  fs.writeFileSync(path.join(first.result.root,'README.md'),'My local edits');
  const resumed=await wizard([remote,'','2','n','n']);
  assert.equal(resumed.result.root,first.result.root);
  assert.match(resumed.output,/contains a checkout of example.test\/my-fork\/job-finder/);
  assert.match(resumed.output,/You requested example.test\/team\/job-finder/);
  assert.equal(fs.readFileSync(path.join(first.result.root,'README.md'),'utf8'),'My local edits');
});

test('SSH URLs and an explicit tilde destination work, and back can switch to a local checkout',async t=>{
  const {home,source}=await fixture(t);
  const cloned=await wizard([...remainingSetup],{repo:'git@example.test:team/job-finder.git',dir:'~/Work/job-finder'});
  assert.equal(cloned.result.root,path.join(home,'Work/job-finder'));
  const local=await wizard(['back',source,...remainingSetup],{repo:remote});
  assert.equal(local.result.root,source);
  assert.equal(fs.existsSync(path.join(home,'Projects/job-finder')),false);
});

test('a failed clone offers retry with the same URL, then a way to change repository',async t=>{
  const {home,source,git}=await fixture(t);
  // A missing local fixture fails deterministically without a network or credential request.
  const missing='https://example.test/team/missing';
  await git('config','--file',path.join(home,'gitconfig'),`url.${home}/missing-source.insteadOf`,missing);
  const actual=await wizard([missing,'','1','','2',source,...remainingSetup]);
  assert.equal(actual.result.root,source);
  assert.equal(actual.prompts.filter(p=>p.label==='Repository directory or Git URL').length,2);
  assert.deepEqual(actual.prompts.filter(p=>p.label==='Clone into folder').map(p=>p.fallback),['~/Projects/missing','~/Projects/missing']);
  assert.match(actual.output,/Git clone failed/);
  assert.equal(fs.existsSync(path.join(home,'Projects/missing/.bypass/state.json')),false);
});

test('stopping a failed clone exits cleanly; noninteractive init still rejects occupied destinations',async t=>{
  const {home,git}=await fixture(t);
  const missing='https://example.test/team/missing';
  await git('config','--file',path.join(home,'gitconfig'),`url.${home}/missing-source.insteadOf`,missing);
  await assert.rejects(wizard([missing,'','3']),error=>error.code===130);
  const file=path.join(home,'keep.txt');fs.writeFileSync(file,'Keep');
  await assert.rejects(execute('init',[remote],{dir:file,'non-interactive':true}),/new or empty folder/);
  assert.equal(fs.readFileSync(file,'utf8'),'Keep');
});
