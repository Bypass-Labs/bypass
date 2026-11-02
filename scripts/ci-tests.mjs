import fs from 'node:fs';
import path from 'node:path';
import {fileURLToPath,pathToFileURL} from 'node:url';
import {execFileSync,spawn} from 'node:child_process';

const checkout=fileURLToPath(new URL('../',import.meta.url));
export const shardCount=4;
const need=(ok,message)=>{if(!ok)throw new Error(message);};
const compare=(a,b)=>a<b?-1:a>b?1:0;

export function discoverTests(root=checkout){
  return fs.readdirSync(path.join(root,'test'),{withFileTypes:true}).filter(entry=>entry.name.endsWith('.test.mjs')).map(entry=>{
    need(entry.isFile(),`Test entry must be a regular file: ${entry.name}`);
    return `test/${entry.name}`;
  }).sort(compare);
}

// Durations influence scheduling only. New files missing from the sample run too.
export function planTests(files,weights={},count=shardCount){
  need(Number.isInteger(count)&&count>=1&&count<=16&&files.length>=count,'Invalid shard count or empty test inventory');
  need(new Set(files).size===files.length&&files.every(file=>/^test\/[^/\\]+\.test\.mjs$/.test(file)),'Invalid or duplicate test path');
  need(weights&&typeof weights==='object'&&!Array.isArray(weights),'Invalid timing estimates');
  for(const value of Object.values(weights))need(Number.isFinite(value)&&value>=0,'Invalid test duration');
  const duration=file=>Math.max(1,weights[file]??15000);
  const groups=Array.from({length:count},(_,i)=>({shard:i+1,estimatedMs:0,files:[]}));
  for(const file of [...files].sort((a,b)=>duration(b)-duration(a)||compare(a,b))){
    const group=[...groups].sort((a,b)=>a.estimatedMs-b.estimatedMs||a.shard-b.shard)[0];
    group.files.push(file);group.estimatedMs+=duration(file);
  }
  return groups;
}

export function documentationOnly(files){
  // This Markdown file is runtime input, not ordinary documentation.
  const runtimeCatalog='docs/muse_spark_bug_bounty_tier_1_tier_2.md';
  return files.length>0&&files.every(file=>file!==runtimeCatalog&&!file.split('/').some(part=>part==='..'||part==='.')&&
    (file==='README.md'||/^docs\/[^\0\r\n]+\.md$/.test(file)));
}

export function changedFiles(base,head,root=checkout){
  need([base,head].every(value=>/^[a-f0-9]{40}$/.test(value||'')),'Expected exact base and head commit SHAs');
  // No API pagination/truncation; retain both sides of a move.
  return execFileSync('git',['diff','--no-renames','--name-only','-z',base,head,'--'],{cwd:root,encoding:'utf8',timeout:30000,maxBuffer:10*1024*1024}).split('\0').filter(Boolean);
}

export function checkGate(needs){
  need(needs?.fast?.result==='success','Fast checks did not succeed');
  const full=needs.fast.outputs?.full;
  need(full==='true'||full==='false','Missing or invalid change classification');
  for(const name of ['regression','policy','codeql']){
    const expected=full==='true'?'success':'skipped';
    need(needs[name]?.result===expected,`${name} must be ${expected}; got ${needs[name]?.result||'missing'}`);
  }
}

export async function runTests(group,{root=checkout,node=process.execPath,env=process.env}={}){
  need(group?.files?.length>0,'Refusing to run an empty test shard');
  const started=Date.now();
  console.log(`Shard ${group.shard}: ${group.files.length} test files; estimated test time ${(group.estimatedMs/60000).toFixed(1)} minutes (not an ETA).`);
  console.log(group.files.join('\n'));
  const childEnv={...env};delete childEnv.NODE_TEST_CONTEXT;
  const child=spawn(node,['--import','./test/legacy-muse-env.mjs','--test','--test-concurrency=1','--test-reporter=tap',...group.files],{cwd:root,env:childEnv,stdio:'inherit'});
  const terminate=()=>child.kill('SIGTERM');
  process.once('SIGTERM',terminate);
  try{
    return await new Promise((resolve,reject)=>{child.once('error',reject);child.once('close',code=>resolve(code??1));});
  }finally{
    process.removeListener('SIGTERM',terminate);
    console.log(`Shard ${group.shard} finished in ${((Date.now()-started)/1000).toFixed(1)} seconds.`);
  }
}

async function main(){
  const [command,value]=process.argv.slice(2);
  if(command==='gate'){checkGate(JSON.parse(process.env.CI_NEEDS_JSON||'null'));console.log('All required PR checks passed.');return;}
  const weights=JSON.parse(fs.readFileSync(path.join(checkout,'scripts/ci-test-timings.json'))).milliseconds;
  const groups=planTests(discoverTests(),weights);
  if(command==='plan'){
    let full=true,reason='Full validation is the default.';
    try{
      const files=changedFiles(process.env.CI_BASE_SHA,process.env.CI_HEAD_SHA);
      full=!documentationOnly(files);reason=full?'Code, runtime input, or other non-documentation changes.':'Only presentation Markdown changed; fast checks still run.';
    }catch(error){reason=`Unable to prove documentation-only changes; running all checks: ${error.message}`;}
    const matrix={shard:groups.map(group=>group.shard)};
    console.log(JSON.stringify({full,reason,groups},null,2));
    if(process.env.GITHUB_OUTPUT)fs.appendFileSync(process.env.GITHUB_OUTPUT,`full=${full}\nmatrix=${JSON.stringify(matrix)}\n`);
    if(process.env.GITHUB_STEP_SUMMARY)fs.appendFileSync(process.env.GITHUB_STEP_SUMMARY,`## PR validation plan\n\n${reason}\n\n| Shard | Files | Estimated test minutes |\n|---|---:|---:|\n${groups.map(group=>`| ${group.shard} | ${group.files.length} | ${(group.estimatedMs/60000).toFixed(1)} |`).join('\n')}\n\nEstimates come from a previous CI run; setup, cache misses, and runner contention add time.\n`);
  }else if(command==='run'){
    need(/^[1-9][0-9]*$/.test(value||'')&&Number(value)<=shardCount,'Choose a valid shard number');
    process.exitCode=await runTests(groups[Number(value)-1]);
  }else throw new Error('Usage: node scripts/ci-tests.mjs plan | run <shard> | gate');
}
if(process.argv[1]&&import.meta.url===pathToFileURL(path.resolve(process.argv[1])).href)main().catch(error=>{console.error(error.message);process.exitCode=1;});
