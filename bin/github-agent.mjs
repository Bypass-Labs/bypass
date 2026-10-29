#!/usr/bin/env node
import fs from 'node:fs';
import path from 'node:path';
import { GitHubAPI } from '../src/github-api.mjs';
import { runGitHubAgent } from '../src/github-agent.mjs';
import { need, redact, registerSecret } from '../src/util.mjs';

// Only the pinned composite action invokes this entry point; no application checkout is needed.
const env=process.env;
for(const [key,value] of Object.entries(env))if(/TOKEN|SECRET|PASSWORD|API_KEY|COOKIE/.test(key))registerSecret(value);
const progress=message=>process.stdout.write(redact(String(message)).replace(/\r/g,'').replace(/^::/gm,' :')+'\n');
try{
  need(env.GITHUB_ACTIONS==='true'&&env.RUNNER_OS==='Linux','The GitHub agent requires a Linux Actions runner.');
  need(env.GITHUB_SERVER_URL==='https://github.com','This runner supports GitHub.com; enterprise API routing is not configured.');
  need(/^\d+$/.test(env.GITHUB_RUN_ID||'')&&/^\d+$/.test(env.GITHUB_RUN_ATTEMPT||''),'Missing Actions run identity.');
  const api=new GitHubAPI({token:env.GITHUB_TOKEN,repository:env.GITHUB_REPOSITORY});
  const controller=new AbortController();for(const event of ['SIGINT','SIGTERM'])process.once(event,()=>controller.abort());
  const deadline=setTimeout(()=>controller.abort(),20*60*1000);deadline.unref();
  const result=await runGitHubAgent(api,{eventName:env.GITHUB_EVENT_NAME,event:JSON.parse(fs.readFileSync(env.GITHUB_EVENT_PATH,'utf8')),operation:env.BYPASS_GITHUB_OPERATION||'auto',prNumber:env.BYPASS_GITHUB_PR||undefined,runId:env.GITHUB_RUN_ID,signal:controller.signal,progress});
  const directory=path.join(env.RUNNER_TEMP,`bypass-${env.GITHUB_RUN_ID}-${env.GITHUB_RUN_ATTEMPT}`);fs.mkdirSync(directory,{recursive:true,mode:0o700});
  fs.writeFileSync(path.join(directory,'report.json'),JSON.stringify(result.report,null,2)+'\n',{mode:0o600});
  fs.writeFileSync(path.join(directory,'summary.md'),result.summary+'\n',{mode:0o600});
  if(result.state)fs.writeFileSync(path.join(directory,'state.json'),JSON.stringify(result.state)+'\n',{mode:0o600});
  if(env.GITHUB_STEP_SUMMARY)fs.appendFileSync(env.GITHUB_STEP_SUMMARY,result.summary+'\n');
  if(env.GITHUB_OUTPUT)fs.appendFileSync(env.GITHUB_OUTPUT,`report-directory=${directory}\nstate-written=${!!result.state}\nexecution=${result.report.execution}\nconclusion=${result.report.conclusion}\n`);
  progress(`Bypass: ${result.report.execution} · ${result.report.modelCalls} Meta calls · ${result.report.findings.length} source concerns · ${result.report.checks.length} HTTP checks`);
  process.exitCode=result.exitCode;
}catch(error){progress(`Bypass could not start: ${error.message}`);process.exitCode=3;}
