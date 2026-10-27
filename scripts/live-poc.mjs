// Opt-in real Muse host integration. No API key extraction and no mocked model.
// This TEST launches Muse as the outer host; production plugin code never does.
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { execFile, VERSION } from '../src/util.mjs';
import { read } from '../src/store.mjs';
import { stopPOC } from '../src/poc.mjs';
const checkout=fileURLToPath(new URL('../',import.meta.url)),directory=fs.mkdtempSync(path.join(os.tmpdir(),'bypass-host-validation-'));
const plugin=path.join(directory,'plugin'),workspace=path.join(directory,'workspace'),fixture=path.join(workspace,'fixture');
fs.mkdirSync(workspace);fs.cpSync(path.join(checkout,'plugin'),plugin,{recursive:true});
const manifestFile=path.join(plugin,'.muse-plugin/plugin.json'),manifest=JSON.parse(fs.readFileSync(manifestFile));
manifest.name='bypass-host-audit-'+Date.now();manifest.displayName='Bypass host integration audit';fs.writeFileSync(manifestFile,JSON.stringify(manifest,null,2));
const report={version:VERSION,kind:'real Muse host integration',billingVerified:false,subscription:'Not attested by MCP; no subscription credential inspection',apiProviderSmoke:'Not performed by this harness',directory,fixture};
let installed=false;
try {
  for(const args of [['plugins','validate',plugin,'--json'],['plugins','install',plugin,'--scope','user','--json'],['plugins','approve',manifest.name,'--json']]){
    const r=await execFile('muse',args,{timeout:120000,env:{MUSE_NO_AUTO_UPDATE:'1'}});if(r.code!==0)throw new Error(`Native plugin ${args[1]} failed: ${r.stderr}`);if(args[1]==='install')installed=true;
    const data=JSON.parse(r.stdout);if(args[1]==='validate'&&(!data.valid||data.diagnostics?.length))throw new Error('Native manifest validation failed');
  }
  const prefix='mcp__plugin_'+manifest.name.replaceAll('-','_')+'_security__';
  const prompt=path.join(directory,'prompt.txt');
  fs.writeFileSync(prompt,`Validate the installed Bypass candidate ${manifest.name} using ONLY its ${prefix} tools (ignore any older bypass plugin). This is a public synthetic fixture and I authorize its full local demo and fixture-only edits. Contributor mode is off for this test run. We acknowledge subscription billing cannot be attested through MCP; do not inspect credentials or claim verified billing. Do not configure a provider, invoke a nested agent or use the shell.\nStart bypass_demo_start kind real dir ${fixture}. Call bypass_onboarding. Then bypass_scan combined. You are the reasoning agent: read policy.mjs and server.mjs through bypass_review_step, analyze the actual source, submit the exact cited authentication/ownership hypothesis and one useful cited source knowledge record, choose the approved resource index and execute the probe, then finish. Inspect the finding. Fix the isolated fixture with bypass_demo_control fix and retest that finding. Export all saved tests and run them via bypass_run_tests; watch this deterministic job to completion. Regress the fixture and rerun saved tests to demonstrate failure with zero plugin model calls, then restore the fixture fix and retest. Finish by stopping the demo. Show observed source citation, owner/other-account/anonymous controls, saved check and regression result. Do not stop after setup or ask routine fixture permission questions. This entire workflow is already authorized.\n`);
  let output='';
  const result=await execFile('muse',['exec','--json','--provider','meta','--preset','native-basic','--workspace',workspace,'--contributor-mode','off','--no-session-log','--disable-web-tools','--disable-reminders','--disable-request-user-input','--disable-shell','--disable-write','--reasoning-effort','minimal','--max-model-steps','35','--prompt-file',prompt],{
    cwd:workspace,timeout:600000,killGroup:true,env:{MUSE_NO_AUTO_UPDATE:'1'},onStdout:chunk=>{output+=chunk;fs.appendFileSync(path.join(directory,'host.jsonl'),chunk,{mode:0o600});}
  });
  fs.writeFileSync(path.join(directory,'host.jsonl'),output,{mode:0o600});
  report.hostExit=result.code;
  const state=read(fixture),review=state.runs.find(r=>r.executionMode==='muse-host');
  report.review={id:review?.id,status:review?.status,modelCalls:review?.modelCalls,steps:review?.steps};
  report.findings=state.findings.map(f=>({id:f.id,status:f.status,sourceEvidence:f.sourceEvidence,history:f.history}));
  report.checks=state.checks.map(c=>({id:c.id,lastResult:c.lastResult}));
  report.replays=state.runs.filter(r=>r.kind==='tests').map(r=>({id:r.id,exitCode:r.exitCode,modelCalls:r.modelCalls}));
  report.exported=fs.existsSync(path.join(fixture,'tests/security/bypass'));
  report.passed=result.code===0&&review?.status==='completed'&&review?.modelCalls===0&&state.findings.some(f=>f.sourceEvidence.kind==='source'&&f.status==='fixed_verified')&&state.checks.length>0&&report.exported&&report.replays.some(r=>r.exitCode===0)&&report.replays.some(r=>r.exitCode===1)&&report.replays.every(r=>r.modelCalls===0);
  if(!report.passed)process.exitCode=1;
} catch(error){report.passed=false;report.error=error.message;process.exitCode=1;}
finally {
  try{await stopPOC(fixture);}catch{}
  if(installed)await execFile('muse',['plugins','remove',manifest.name,'--json'],{timeout:120000}).catch(()=>{});
  report.finishedAt=new Date().toISOString();fs.writeFileSync(path.join(directory,'validation.json'),JSON.stringify(report,null,2));
  console.log(JSON.stringify({passed:report.passed,evidence:path.join(directory,'validation.json'),error:report.error}));
}
