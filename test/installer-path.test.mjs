import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import {execFileSync} from 'node:child_process';
import {configurePath} from '../scripts/configure-path.mjs';
const quote=value=>"'"+value.replaceAll("'","'\\''")+"'";
function fixture(t){
  const directory=fs.mkdtempSync(path.join(os.tmpdir(),'bypass-path-test-'));
  t.after(()=>fs.rmSync(directory,{recursive:true,force:true}));
  const binDir=path.join(directory,"bin ' dollar$ `literal` [x]");fs.mkdirSync(binDir);
  fs.writeFileSync(path.join(binDir,'bypass'),'#!/bin/sh\nprintf "bypass-ready\\n"\n',{mode:0o755});
  return {directory,binDir,homeDirectory:directory,shell:'/bin/bash',skip:false,zdotdir:undefined};
}
const shellEnv=()=>({...process.env,PATH:'/usr/bin:/bin'});
const check='bypass --version; printf "%s\\n" "$PATH"';
function assertPath(output,bin){const lines=output.trim().split('\n');assert.equal(lines[0],'bypass-ready');assert.equal(lines.at(-1).split(':').filter(p=>p===bin).length,1);}

test('Bash PATH works in interactive and login startup files, preserves content and is idempotent',t=>{
  const options=fixture(t),rc=path.join(options.directory,'.bashrc'),login=path.join(options.directory,'.bash_profile');
  fs.writeFileSync(rc,'# User configuration without final newline',{mode:0o600});
  fs.writeFileSync(login,`. ${quote(rc)}\n# Keep existing login configuration\n`);
  const result=configurePath(options);assert.deepEqual(result.errors,[]);assert.deepEqual(result.changed,[rc,login]);
  assert.ok(fs.readFileSync(rc,'utf8').startsWith('# User configuration without final newline\n'));assert.equal(fs.statSync(rc).mode&0o777,0o600);
  assertPath(execFileSync('/bin/bash',['--noprofile','--rcfile',rc,'-ic',check],{env:shellEnv(),encoding:'utf8',stdio:['pipe','pipe','pipe']}),options.binDir);
  assertPath(execFileSync('/bin/bash',['--noprofile','-c',`. ${quote(login)}; . ${quote(rc)}; ${check}`],{env:shellEnv(),encoding:'utf8'}),options.binDir);
  const before=[rc,login].map(f=>fs.readFileSync(f,'utf8'));
  assert.deepEqual(configurePath(options).changed,[]);assert.deepEqual([rc,login].map(f=>fs.readFileSync(f,'utf8')),before);
  assertPath(execFileSync('/bin/bash',['--noprofile','-c',`${result.activation}; ${check}`],{env:shellEnv(),encoding:'utf8'}),options.binDir);
});

test('Bash respects the existing login profile instead of creating one that would hide it',t=>{
  for(const name of ['.profile','.bash_login']){
    const options=fixture(t),file=path.join(options.directory,name);fs.writeFileSync(file,'# existing login\n');
    const result=configurePath(options);assert.deepEqual(result.errors,[]);assert.ok(result.files.includes(file));assert.ok(!fs.existsSync(path.join(options.directory,'.bash_profile')));
  }
});

test('Zsh PATH is available in interactive and login shells and respects ZDOTDIR', {skip:!fs.existsSync('/bin/zsh')},t=>{
  const options=fixture(t);options.shell='/bin/zsh';options.zdotdir=path.join(options.directory,'custom zsh');
  const result=configurePath(options);assert.deepEqual(result.errors,[]);assert.deepEqual(result.files,['.zshrc','.zprofile'].map(f=>path.join(options.zdotdir,f)));
  for(const mode of ['-ic','-lc','-lic'])assertPath(execFileSync('/bin/zsh',['-d',mode,check],{env:{...shellEnv(),ZDOTDIR:options.zdotdir},encoding:'utf8'}),options.binDir);
  assert.ok(!fs.existsSync(path.join(options.directory,'.zshrc')));assert.deepEqual(configurePath(options).changed,[]);
});

test('managed PATH entries update when the executable directory changes and preserve symlinked profiles',t=>{
  const options=fixture(t),real=path.join(options.directory,'real-rc'),rc=path.join(options.directory,'.bashrc');fs.writeFileSync(real,'# Dotfiles repository\n',{mode:0o600});fs.symlinkSync(real,rc);
  configurePath(options);const original=options.binDir;options.binDir=path.join(options.directory,'new-bin');
  const result=configurePath(options);assert.deepEqual(result.errors,[]);assert.ok(fs.lstatSync(rc).isSymbolicLink());assert.equal(fs.statSync(real).mode&0o777,0o600);
  const text=fs.readFileSync(real,'utf8');assert.ok(text.startsWith('# Dotfiles repository\n'));assert.equal(text.split('# >>> Bypass PATH >>>').length,2);assert.ok(!text.includes(quote(original)));assert.ok(text.includes(quote(options.binDir)));
});

test('PATH setup reports uneditable or malformed profiles, honors opt-out, and leaves unsupported shells alone',t=>{
  const options=fixture(t),rc=path.join(options.directory,'.bashrc');
  assert.equal(configurePath({...options,skip:true}).skipped,true);assert.ok(!fs.existsSync(rc));
  assert.equal(configurePath({...options,shell:'/usr/bin/fish'}).unsupported,true);assert.ok(!fs.existsSync(rc));
  fs.mkdirSync(rc);assert.ok(configurePath(options).errors.find(e=>e.file===rc));fs.rmdirSync(rc);
  fs.writeFileSync(rc,'# >>> Bypass PATH >>>\nunrelated configuration\n');
  const before=fs.readFileSync(rc,'utf8');assert.ok(configurePath(options).errors.find(e=>e.file===rc));assert.equal(fs.readFileSync(rc,'utf8'),before);
  assert.throws(()=>configurePath({...options,binDir:'/tmp/bin:other'}),/colon/);
});
