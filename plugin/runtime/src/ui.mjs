import { promptValue, confirmChoice, credentialTypes, verificationChoices, scopeSuggestions } from './interaction.mjs';
import { appEnvironmentQuestion, appEnvironmentChoices } from './app-connection.mjs';
import { promptAPIProfile } from './provider-setup.mjs';
import readline from 'node:readline/promises';
import fs from 'node:fs';
import path from 'node:path';
import { read, rootFrom } from './store.mjs';
import { execute, readiness } from './service.mjs';
import { parse, help } from './catalog.mjs';
import { cleanText, redact, Fault, abortFault } from './util.mjs';
import { onboard } from './onboarding.mjs';
import { checkModelConnection } from './model-check.mjs';
import { guidedDemo } from './guided-demo.mjs';
import { homeActions, previewRun, quickCommands, reviewSummary } from './experience.mjs';
import { appOriginInput, loopback } from './network.mjs';
import { isBypassSource } from './project-selection.mjs';
import { createTerminalSession } from './terminal-session.mjs';
import { summaryText as blackboxSummary } from './blackbox/report.mjs';
import { progressLine as blackboxProgressLine } from './blackbox/progress.mjs';
import { createTheme, brandHeading } from './terminal-theme.mjs';
import { promptMethods, mayChangeData } from './http-methods.mjs';

const theme=createTheme();
const color=!!process.stdout.isTTY&&!process.env.NO_COLOR;
const tones={'31':'error','33':'warning','90':'muted','1':'title'};
const paint=(n,s)=>theme.paint(tones[n]||'accent',s);
const accent=s=>theme.paint('accent',s),muted=s=>theme.paint('muted',s),bold=s=>theme.paint('title',s);
const label=s=>String(s).replace(/_/g,' ');
export function printResult(data){
  if(!data)return;
  const value=redact(data);
  if(value.error){console.error(paint('31',value.error));if(value.details&&Object.keys(value.details).length)console.error(JSON.stringify(value.details,null,2));return;}
  if(value.kind==='blackbox-audit'){console.log(blackboxSummary(value,{color}));return;}
  if(value.kind==='blackbox-scope'){console.log(`\nScope: ${value.file}\nTarget: ${value.origin}\nIncluded paths: ${value.include.join(', ')}\nCredential origins: ${value.credentialOrigins.join(', ')}\nAccounts: ${value.identities.owner}, ${value.identities.outsider}\nNext: ${value.next}`);return;}
  if(value.kind==='blackbox-setup'){
    const scopeAction = value.created ? 'created' : value.updated ? 'rate updated' : 'reused';
    console.log(`\n${bold('BYPASS / blackbox setup')}\nTarget  ${value.origin}\nScope   ${value.scopeFile} · ${scopeAction}\n`);
    for(const step of value.steps){
      if(step.kind==='ownership')console.log(`Publish DNS TXT ${step.record} = ${step.value}\nThen: ${step.command}\n`);
      else if(step.kind==='authorization')console.log(`Review ${step.file}${step.production?' (set productionAcknowledged: true after review)':''}\nThen: ${step.command}\n`);
      else console.log(`Audit: ${step.command}`);
    }
    console.log(`\nOptional Muse check: ${value.modelCheck}`);
    return;
  }
  if(value.kind==='blackbox-verify'){console.log(`\n${value.integrity.ok?'Ledger intact':'Ledger broken'} · ${value.reportedFindings??value.proofs.length} findings · ${value.proofs.length} proofs\n${value.proofs.map(item=>`  ${item.id}: ${item.verdict}${item.corroborates?` · corroborates ${item.corroborates}`:''}`).join('\n')}\nExit ${value.exitCode}`);return;}
  if(value.kind==='blackbox-export'){
    console.log(`\nExported ${value.files.length} regression tests for ${value.reportedFindings??value.files.length} findings to ${value.output}`);
    if(value.skippedProofs?.length)console.log(`Skipped ${value.skippedProofs.length} unsupported private-read proof${value.skippedProofs.length===1?'':'s'}`);
    if(value.files.length)console.log(`Run: node --test ${value.output}/*.test.mjs`);
    return;
  }
  if(value.kind==='feature-security-context'){
    console.log(`\n${bold('Build with security context')}\n${value.task}\nRepository: ${value.repository}\n${value.next}`);
    for(const requirement of value.securityRequirements)console.log(`  Preserve owner access; deny other-account and anonymous access · ${requirement.resourcePath}\n    ${requirement.id} · ${requirement.enabled?'enabled':'disabled'} · last ${requirement.lastResult} · replay required`);
    printResult(value.memory);console.log('\nNext: re-read relevant citations, implement the feature, then test new behavior and replay the relevant saved checks.');return;
  }
  if(value.kind==='project-memory'){
    console.log(`\n${bold('Security memory')} · ${value.enabled?'on':'off'} · ${value.records} stored · ${value.entries.length} shown`);
    for(const e of value.entries){console.log(`  ${e.title}\n    ${e.id} · ${e.validity.status} · ${e.confidence}\n    ${e.summary}`);for(const f of e.evidence.files||[])console.log(`    ${f.path}:${f.line} · ${f.quote}`);console.log(`    ${e.retrievalReason} ${e.validity.reason}`);}
    if(!value.records)console.log('  No security memory yet. A real source review saves cited knowledge; verified fixes add reusable behavior checks.');
    console.log('\nLocal storage · historical evidence, not a current security verdict\nInspect: memory show <id> · Search: memory --query "auth"\nBuild context: context --task "Add a feature" --files "src/api.js"\nForget: memory forget <id> · Disable: memory use off');return;
  }
  if(value.kind==='environment-diagnostics'){console.log(`\nBypass ${value.runtime.version} · ${value.runtime.sourcePath}\nEnvironment checks`);for(const c of value.checks)console.log(`  ${c.ok?'✓':'!'} ${c.name} · ${c.ok?c.version?.trim()||'available':c.message||'unavailable'}${c.optional?' (optional)':''}`);console.log(value.message);return;}
  if(value.models){console.log('\nModel connections');for(const m of value.models)console.log(`  ${m.name===value.active?'●':'○'} ${m.name} · ${m.provider} · ${m.lastAttempt?.status||m.lastTest?.status||'not tested'}\n    ${m.dataDestination}`);return;}
  if(value.targets){console.log('\nConnected apps');for(const t of value.targets)console.log(`  ${t.name===value.active?'●':'○'} ${t.name} · ${t.url}\n    ${t.environment} · ownership ${t.ownership?.status||'pending'}`);if(!value.targets.length)console.log('  No app yet. Use /app to connect one.');return;}
  if(value.project&&value.review){console.log(`\nBypass ${value.runtime.version} · ${value.runtime.sourcePath}\n`+reviewSummary(value.review));console.log(`Model: ${value.model?.name||'not configured'} · ${value.model?.connection||'optional for the preview'}\nSaved tests: ${value.checks.enabled} · passed ${value.checks.passed} · failed ${value.checks.failed}\nSecurity memory: ${value.memory?.records||0} records · ${value.memory?.enabled===false?'off':'on'} · /memory\nNext: ${value.next}`);return;}
  if(value.plan){
    const p=value.plan;
    console.log(`\n${bold('Review plan')} · ${p.mode==='code'?'code only':p.mode}\n`);
    console.log(reviewSummary(p));
    console.log(`  App           ${p.mode==='code'?'no live requests':p.target||'not connected'}\n  Saved checks  ${p.savedChecks}${p.mode==='code'?' · replay requires an authorized app':' · replay first'}\n  Source        ${p.simulation?'local inventory only':'selected excerpts sent to '+p.model?.destination}\n  Analysis      ${p.simulation?'simulated · no model calls':'real Docker agents · shared model'}\n  Evidence      saved locally`);
    if(p.blockers.length)console.log(`\n${paint('33','Setup needed:')}\n${p.blockers.map(x=>'  '+x).join('\n')}`);
    else console.log(p.simulation?'\nReady for a walkthrough review. Simulated results are not a security verdict.':'\nReady for a bounded real review. Model usage applies; HTTP evidence decides confirmation.');
    return;
  }
  if(value.run){
    const r=value.run;
    if(previewRun(r)){
      if(r.result.plan)console.log('\n'+reviewSummary(r.result.plan));
      console.log(`\n${bold('Review preview complete')}\n  ${r.result.inventory.sourceFileCount} source files inventoried locally\n  ${r.result.findings.length} example scenario${r.result.findings.length===1?'':'s'} ready to open\n  Model calls: 0 · no live discovery requests`);
      for(const check of r.result.regression||[])console.log(`  Saved check: ${check.status} — ${check.reason}`);
      console.log('\nThis is a successful prototype preview. The example is simulated; it is not a verified vulnerability in your app.');return;
    }
    const incomplete=['failed','incomplete','interrupted'].includes(r.status);
    console.log(`\n${bold(incomplete?'Review incomplete':r.id)}  ${label(r.kind)} · ${incomplete?'stopped':r.status}`);
    if(r.result?.message)console.log(`\n${r.result.message}`);
    for(const result of r.result?.results||r.result?.regression||[])console.log(`  ${result.status==='passed'?accent('✓'):paint('33','!')} ${result.id}  ${result.status} — ${result.reason}`);
    if(r.result?.findings?.length)console.log(`\nFindings: ${r.result.findings.join(', ')}\nNext: bypass finding show ${r.result.findings[0]}`);
    if(incomplete)console.log(`\nStopped at: ${r.result?.details?.stage||r.stage||'review'}\nSetup and partial evidence are saved. No complete security result is available.\nNext inside Bypass: ${r.result?.details?.next||'status'}\nEvidence: .bypass/runs/${r.id}.json`);
    console.log(muted(`Exit ${value.exitCode} · model calls ${r.result?.modelCalls??0} · evidence stored locally`));return;
  }
  if(value.target?.challenge){const t=value.target;console.log(`\n${bold(t.name)} · ${t.url}\nOwnership: ${t.ownership?.status||'pending'}\n`);if(t.environment==='local')console.log(`Next: bypass target verify ${t.name} --method local`);else console.log(`Publish TXT record:\n  Name:  ${t.challenge.record}\n  Value: ${t.challenge.token}\n\nOr serve exactly that value at:\n  ${t.url}${t.challenge.httpPath}\n\nThen: bypass target verify ${t.name} --method dns`);if(t.authorization)console.log(`Scope: ${t.authorization.paths.join(', ')} · expires ${t.authorization.expiresAt}`);return;}
  if(value.findings){console.log(`\n${value.findings.length} findings`);for(const f of value.findings)console.log(`  ${bold(f.id)}  ${f.title}\n    ${label(f.status)} · ${f.fixture?'local fixture':f.simulation?'SIMULATED · unproven':'evidence available'}`);return;}
  if(value.checks&&Array.isArray(value.checks)){console.log(`\n${value.checks.length} saved checks`);for(const c of value.checks)console.log(`  ${bold(c.id)}  ${c.title||c.behavior}\n    ${c.status||c.lastResult?.status||'not run'} · ${c.enabled===false?'disabled':c.target}`);if(value.message)console.log(value.message);return;}
  if(value.finding){const f=value.finding;const next=f.fixture||f.engine==='docker'?`bypass ${['confirmed_fixture','confirmed','regression_failed'].includes(f.status)?'retest':'verify'} ${f.id}`:'bypass demo — complete the proof loop in a separate local app';console.log(`\n${bold(f.title)}\n${f.id} · ${label(f.status)}\n\n${f.hypothesis}\n\n${f.sourceEvidence?.file?`${f.sourceEvidence.file}:${f.sourceEvidence.line}\n${f.sourceEvidence.quote}`:f.sourceEvidence?.message||''}\n\nFix: ${f.recommendation}\n\nNext: ${next}`);if(f.verification)console.log(JSON.stringify(f.verification,null,2));return;}
  if((value.installed||value.integration)&&value.state&&value.next){
    console.log(`\n${bold('Bypass in Muse')} · ${label(value.state)}\n${value.message||'Native plugin status'}\n`);
    for(const capability of value.capabilities||[])console.log(`  ${capability.id?.includes(':hook:')?'Session context':'Security tools'} · ${label(capability.status)}`);
    console.log(`\nNext: ${value.next}`);return;
  }
  if(value.message)console.log(`\n${value.message}`);
  const rest={...value};delete rest.schemaVersion;delete rest.exitCode;delete rest.message;
  if(Object.keys(rest).length)console.log(JSON.stringify(rest,null,2));
}
export function tokenize(line){
  const tokens=[];let word='',quote=null,escaped=false,started=false;
  for(const ch of line){if(escaped){word+=ch;escaped=false;started=true;}else if(ch==='\\'&&quote!=="'"){escaped=true;}else if(quote){if(ch===quote)quote=null;else word+=ch;started=true;}else if(ch==='"'||ch==="'"){quote=ch;started=true;}else if(/\s/.test(ch)){if(started){tokens.push(word);word='';started=false;}}else{word+=ch;started=true;}}
  if(quote||escaped)throw new Fault('Unclosed quote or escape in command.');if(started)tokens.push(word);return tokens;
}
function createPrompt(){
  if(process.stdin.isTTY&&process.stdout.isTTY&&process.env.TERM!=='dumb'&&process.env.BYPASS_PLAIN!=='1')return createTerminalSession();
  const rl=readline.createInterface({input:process.stdin,output:process.stdout});
  const controller=new AbortController();
  rl.once('SIGINT',()=>{controller.abort();rl.close();});
  rl.once('close',()=>controller.abort());
  const ask=async(text,defaultValue='')=>{try{const result=await rl.question(`${text}${defaultValue?muted(` [${defaultValue}]`):''}: `,{signal:controller.signal});return result.trim()||defaultValue;}catch(e){if(e.name==='AbortError')throw new Fault('Setup stopped. Saved choices are retained.',130);throw e;}};
  const run=async work=>{
    if(controller.signal.aborted)throw abortFault(controller.signal);
    const operation=new AbortController();
    const skip=()=>operation.abort(new Fault('Connection check skipped.',130,{skipped:true}));
    const stop=()=>operation.abort(abortFault(controller.signal));
    rl.on('line',skip);controller.signal.addEventListener('abort',stop,{once:true});
    try{return await work(operation.signal);}
    finally{rl.removeListener('line',skip);controller.signal.removeEventListener('abort',stop);}
  };
  return {ask,run,signal:controller.signal,close:()=>rl.close()};
}
async function choose(ask,items,title){
  if(ask.select&&items.length)return ask.select(title,items,{back:true});
  console.log(`\n${bold(title)}`);if(!items.length){console.log('Nothing here yet. Return to the home screen for the next step.');return null;}
  items.forEach((x,i)=>console.log(`  ${i+1}  ${x.label||x.name||x.id}`));console.log('  0  Back');
  while(true){const choice=await ask('Choose','1');if(['0','back','q'].includes(choice))return null;const item=items[Number(choice)-1];if(item)return item;console.log('Choose one of the numbers shown, or 0 to go back.');}
}

export async function initWizard(options={},args=[]){
  const prompt=createPrompt();
  try{
    let result;
    try{result=await onboard(options,args,prompt);}
    catch(error){
      if(!prompt.rich||!error.details?.cancelled)throw error;
      prompt.write(error.message);prompt.stopTasks();
      result={root:prompt.state.context.repo,interactive:true,openDashboard:!!prompt.state.context.repo,exitCode:0};
    }
    if(prompt.rich&&result.openDashboard){await terminal({project:result.root},prompt);return {...result,openDashboard:false};}
    if(prompt.rich){prompt.setNext('Evidence saved. Press Enter to close this session.');await prompt.ask(result.completed?'Walkthrough complete — Enter to finish':'Enter to finish');}
    return result;
  }finally{prompt.close();}
}
export async function modelTestWizard(root,name,{interactive=process.stdin.isTTY&&process.stdout.isTTY}={}){
  const prompt=interactive?createPrompt():null;
  try{if(prompt?.rich&&fs.existsSync(path.join(root,'.bypass/state.json')))updateWorkspace(prompt,root);const result=await checkModelConnection(root,name,prompt||{write:message=>console.error(message)});if(prompt?.rich)await prompt.ask('Enter to finish');return result;}finally{prompt?.close();}
}
function updateWorkspace(prompt,root){
  if(!prompt.setContext)return;
  const info=readiness(root);
  prompt.setContext({demo:false,engine:info.engine.mode,title:info.project.name,repo:root,branch:info.project.repository.branch,app:info.target?`${info.target.url} · ${info.target.authorized?'authorized':info.target.ownership==='verified'?'scope required':'DNS pending'}`:'not connected · code preview available',model:info.model?`${info.model.name} · ${info.model.provider} · ${info.model.connection}`:'not configured · /models for API setup',checks:info.checks.enabled,memory:info.memory?.records||0});
}
async function modelWizard(ask,root,io){
  const setup=await promptAPIProfile(ask,(title,options)=>choose(ask,options,title));if(!setup)return;
  const name=await promptValue(ask,'Profile name',[setup.selection.name]);
  const options={project:root,...setup.config};
  const added=await execute('model add',[name],options);
  await execute('model use',[name],{project:root});
  console.log(`\nModel selected: ${added.model.name} · ${added.model.model} · ${added.model.baseUrl}\nKey variable: ${added.model.secretEnv} (value stays in your shell)`);
  if(await confirmChoice(ask,'Check the model connection now?',{yes:'Send a synthetic test prompt',no:'Skip for now (recommended)'}))await checkModelConnection(root,name,io);
}
async function targetWizard(ask,root){
  const url=appOriginInput(await ask('App domain or URL'));const environment=(await choose(ask,appEnvironmentChoices,appEnvironmentQuestion(url)))?.id;if(!environment)return;
  const name=await promptValue(ask,'Target name',[environment]);
  const added=await execute('target add',[name],{project:root,url,environment});printResult(added);
  if(added.target.ownership.status==='verified'){console.log(`\nOwnership already verified for ${new URL(url).hostname}.`);await authorizeWizard(ask,root,name);}
  else if(environment==='local'){await execute('target verify',[name],{project:root,method:'local'});await authorizeWizard(ask,root,name);}
  else console.log('\nPublish the ownership challenge, then choose Targets → Verify. App testing becomes available after verification and scope approval.');
}
async function authorizeWizard(ask,root,name){
  const target=read(root).targets.find(t=>t.name===name);console.log(`\nAuthorize testing on ${target?.url} only. This expires in seven days.`);
  const paths=await promptValue(ask,'Allowed path prefixes, comma-separated',scopeSuggestions(target));
  const methods=await promptMethods(ask,console.log,target?.authorization?.methods);
  console.log(`Methods: ${methods.join(', ')} · Paths: ${paths} · Limit: 2 requests/second`);
  console.log('Also read public app pages/scripts for sign-in setup (anonymous GET only).');
  if(mayChangeData(methods))console.log('These methods can change test data or start jobs. Only explicitly configured requests will run.');
  if(!await confirmChoice(ask,'Do you authorize these methods and paths?',{yes:'Authorize the displayed scope',no:'Keep testing disabled'}))return;
  let production=false;if(target?.environment==='production')production=await confirmChoice(ask,'Confirm testing on this production app',{yes:'Authorize the displayed production scope',no:'Keep production testing disabled'});
  if(target?.environment==='production'&&!production)return;
  printResult(await execute('target authorize',[name],{project:root,paths,methods,accept:true,production,'public-config':true}));
}
function dashboard(root){
  console.log('\n'+brandHeading('Security that stays with your code.')+'\n');
  let info;try{info=readiness(root);}catch{console.log('No project connected. Choose Setup or Demo to begin.');return;}
  console.log(`${bold(info.project.name)}\n${muted(root)}\n`);
  console.log(`  REPOSITORY   ${info.project.repository.kind==='app'?'App only · no source repository':info.project.repository.kind==='git'?'Git connected':'Directory connected'}`);
  console.log(`  LIVE APP     ${info.target?`${info.target.url} · ${info.target.authorized?'authorized':info.target.ownership}`:'not connected'}`);
  console.log(`  MODEL        ${info.model?`${info.model.name} · ${info.model.provider} · ${info.model.connection}`:'choose a provider'}`);
  console.log(`  EVIDENCE     local · ${info.findings.total} findings · ${info.checks.enabled} saved tests`);
  console.log(`  MONITOR      ${info.worker.status} · ${info.monitors} schedules`);
  console.log(`\n${theme.paint(info.engine.mode==='docker'?'accent':'warning',info.engine.mode==='docker'?'  REAL AI · Docker agents':'  PREVIEW · simulated discovery')}  ${muted('Evidence and saved checks stay in this project.')}`);
  const next=homeActions(read(root))[0].label;
  console.log(`  Next: ${accent(next)}\n`);
}
export async function terminal(options={},io){
  let root=options.project?path.resolve(options.project):process.cwd();
  try{root=rootFrom(root);}catch{const result=await initWizard(options);if(!result.openDashboard)return;root=result.root;}
  const prompt=io||createPrompt(),{ask,close}=prompt;
  let advanced=false;
  const run=async(key,args=[],flags={})=>{
    if(key==='demo')return tour(flags);
    if(key==='model test')return checkModelConnection(flags.project||root,args[0],prompt);
    if(prompt.rich&&['auth login','mcp serve','_run','_demo-serve'].includes(key))throw new Fault('Run this process in a separate shell. Type /help for commands available in this workspace.');
    if(prompt.rich&&key==='monitor worker'&&!flags.once&&!flags.stop&&!flags.detach)flags={...flags,detach:true};
    let lastStage=-1, blackboxRequests=0, blackboxModelCalls=0, blackboxChecks=0,
      blackboxTotal=0, blackboxEstimate=0, blackboxResearch=0, blackboxUntested=0;
    const blackboxStages=['Scope and hosts','Assets and source','Routes and responses',
      'Plan and test leads','Replay and assess','Report and coverage'];
    const real=read(root).settings.analysisEngine==='docker';
    const stages=real?['replay','containers','orchestrator',...(flags.mode==='live'?[]:['white-box']),...(flags.mode==='code'?[]:['black-box'])]:['replay','inventory','mock-analysis'];
    const stageLabels={'replay':'Saved checks / scope','containers':'Docker services','orchestrator':'Shared-model plan','white-box':'White-box source review','black-box':'Black-box HTTP proof','inventory':'Local source inventory','mock-analysis':'Simulated discovery'};
    if(key==='scan')prompt.setTasks?.(real?'Real AI review':'Review preview',stages.map(stage=>stageLabels[stage]));
    if(key==='blackbox'){
      prompt.setTasks?.('Black-box audit',blackboxStages);
      prompt.setNext?.('Recon in progress · 0 HTTP · 0 Muse');
    }
    const work=async signal=>{
      const result=await execute(key,args,{project:root,...flags},{signal,onProgress:step=>{
        if(key==='blackbox'){
          if(step.stage==='progress'&&step.type==='phase'){
            const index=step.step-1;
            if(step.state==='doing'){
              prompt.task?.(index,'running');
              prompt.setNext?.(`${blackboxStages[index]||'Audit in progress'} · ${blackboxRequests} HTTP · ${blackboxModelCalls} Muse`);
            }
            if(step.state==='done')prompt.task?.(index,'done');
          }
          if(step.stage==='progress'){
            if(step.type==='request')blackboxRequests=Math.max(blackboxRequests,step.requests??0);
            if(step.type==='model')blackboxModelCalls=Math.max(blackboxModelCalls,step.modelCalls??0);
            if(step.type==='task-done')blackboxChecks++;
            if(step.type==='research-attempt')blackboxResearch++;
            if(step.type==='task-estimate'){
              blackboxTotal+=Math.max(0,step.total??0)-blackboxEstimate;
              blackboxEstimate=Math.max(0,step.total??0);
            }
            if(step.type==='task-total'){
              blackboxTotal+=Math.max(0,step.total??0)-blackboxEstimate;
              blackboxEstimate=0;
            }
            if(step.type==='task-untested')blackboxUntested++;
            if(step.type==='task-reconcile'){
              blackboxTotal=Math.max(0,step.total??0);
              blackboxChecks=Math.max(0,step.done??0);
              blackboxUntested=Math.max(0,step.untested??0);
            }
            if(['request','model','task-done','task-estimate','task-total','task-untested','task-reconcile','research-attempt'].includes(step.type))
              prompt.setNext?.(`${blackboxRequests} HTTP · ${blackboxModelCalls} Muse · ${blackboxChecks}${blackboxTotal?`/${blackboxTotal}`:''} checks${blackboxResearch?` · ${blackboxResearch} research tries`:''}${blackboxUntested?` · ${blackboxUntested} untested`:''}`);
          }
          const line=blackboxProgressLine(step);
          if(line)prompt.write?.(`${line.label}  ${line.text}`);
        } else prompt.write?.(step.message);
        if(key==='scan'){const nextStage=stages.indexOf(step.stage);if(nextStage>=0&&nextStage!==lastStage){if(lastStage>=0)prompt.task?.(lastStage,'done');lastStage=nextStage;prompt.task?.(lastStage,'running');}}
      }});
      if(result.exitCode===130)throw new Fault('Run stopped. Partial evidence is saved.',130,{cancelled:true});
      if(key==='scan'&&lastStage>=0)prompt.task?.(lastStage,previewRun(result.run)||result.run?.status==='completed'?'done':'attention');
      return result;
    };
    const result=prompt.activity?await prompt.activity(key==='scan'?(real?'Review repository · real Docker agents':'Review repository · simulated discovery'):key==='test run'?'Replay saved checks · no model':key==='blackbox'?'Black-box audit':key,work,{verdict:r=>key.startsWith('blackbox')&&r.exitCode===1?'done':r.exitCode&&!(previewRun(r.run)&&r.exitCode===3)?'attention':'done'}):await work(prompt.signal);
    if(!(prompt.rich&&key==='blackbox setup'&&result.ready))printResult(result);
    return result;
  };
  const tour=async(flags={})=>{try{return await guidedDemo(flags,prompt);}finally{if(prompt.rich)updateWorkspace(prompt,root);}};
  const showResults=async()=>{
    const findings=read(root).findings;
    if(!findings.length){console.log('\nNo review results yet. Press Enter on the home screen to run the first preview.');return;}
    const finding=findings.length===1?findings[0]:await choose(ask,findings.map(f=>({...f,label:`${f.title} · ${label(f.status)}`})),'Review results');
    if(!finding)return;
    if(!finding.fixture&&finding.engine!=='docker'){
      prompt.setNext?.('Try the local walkthrough to prove the example and save a regression test');
      console.log(`\n${bold('Example scenario / account access')}\nCould another account read a resource owned by someone else?\n\nThis sample demonstrates how a finding will look. It was not discovered in your code.\nThe deployed-app investigation engine is not built yet; DNS verification will not turn this sample into a verified vulnerability.`);
      const action=await choose(ask,[{label:'See the full prove → fix → retest walkthrough in a local app',id:'demo'},{label:'Show saved scenario details',id:'details'}],'Next step');
      if(action?.id==='demo')await tour();else if(action?.id==='details')printResult({finding});
    }else{
      printResult({finding});
      const action=await choose(ask,[{label:finding.engine==='docker'?'Reproduce with HTTP controls':'Verify this local fixture',id:'verify'},{label:'Retest a fix',id:'retest'},{label:'Follow a fresh guided walkthrough',id:'demo'}],'Next step');
      if(action?.id==='demo')await tour();else if(action)await run(action.id,[finding.id]);
    }
  };
  try{
    updateWorkspace(prompt,root);
    if(prompt.rich){const info=readiness(root);console.log(`\nProject ready · ${info.findings.total} saved result(s) · ${info.checks.enabled} regression test(s)\n${info.latestRun?`Last run: ${info.latestRun.kind} · ${info.latestRun.status}. `:''}Use /history for saved activity, /status for review scope.`);}
    if(isBypassSource(root)){
      console.log(`\nYou opened the Bypass tooling repository:\n${root}\nChoose your application source for white-box review.`);
      const action=await choose(ask,[{id:'repo',label:'Choose my application repository (recommended)'},{id:'demo',label:'Run the separate local walkthrough'},{id:'tool',label:'Intentionally review Bypass tooling itself'}],'What do you want to review?');
      if(!action)return;
      if(action.id==='demo'){await tour();if(prompt.rich)await ask('Walkthrough finished — Enter to close');return;}
      if(action.id==='repo'){const result=await onboard({flow:'quickstart'},[],{...prompt,inDashboard:true});root=result.root;}
    }
    while(true){
      let choice;
      if(advanced&&prompt.rich){
        const action=await choose(ask,[{id:'1',label:'Resume setup'},{id:'2',label:'App ownership & test accounts'},{id:'3',label:'Models & privacy'},{id:'6',label:'Saved tests'},{id:'7',label:'Monitoring'},{id:'8',label:'Session context'},{id:'9',label:'Manual fixture controls'},{id:'10',label:'Muse plugin'}],'Settings');
        advanced=false;if(!action)continue;choice=action.id;
      }else if(advanced){
        dashboard(root);
        console.log('SETTINGS & ADVANCED\n  1  Resume setup                  6  Saved tests\n  2  App & test accounts           7  Monitoring\n  3  Models                        8  Session context\n  4  Review preview                9  Manual demo controls\n  5  Review results               10  Muse plugin\n  0  Back to project home\n');
        choice=await ask('Choose, or type a command','0');
        if(['0','back'].includes(choice)){advanced=false;continue;}
      }else{
        const state=read(root),info=readiness(root),actions=homeActions(state);
        if(prompt.rich){
          updateWorkspace(prompt,root);
          prompt.setNext(`${actions[0].label} · /${actions[0].id}   |   /demo for the complete proof loop`);
          choice=(await prompt.command(actions[0].id)).replace(/^\//,'');
        }else{
        console.log(`\n${accent('━'.repeat(Math.min(66,process.stdout.columns||66)))}\n${bold(state.project.name)} / Bypass prototype\n${muted(root)}`);
        console.log(reviewSummary(info.review));
        console.log(`Model: ${info.model?`${info.model.name} · ${info.model.modelId||info.model.provider} · ${info.model.connection}`:'not configured; mock preview needs no model'} · ${info.findings.total} review result(s)`);
        console.log('\n'+actions.map((action,i)=>`  ${i+1}  ${action.label}${i===0?'  ← Enter':''}`).join('\n'));
        console.log('  0  Exit\n\n? commands · repo change repository · app verification · q quit');
        const selected=await ask('Choose or type a command','1');
        if(selected==='0')break;
        choice=/^[1-3]$/.test(selected)?actions[Number(selected)-1].id:selected;
        }
      }
      choice=choice.replace(/^\//,'');
      if(['q','quit','exit'].includes(choice))break;
      if(['?','help','commands'].includes(choice)){console.log('\n'+quickCommands);continue;}
      if(choice==='help all'){console.log(help());continue;}
      if(choice==='back'){advanced=false;continue;}
      if(choice==='settings'){advanced=true;continue;}
      if(choice==='status'){console.log('\n'+reviewSummary(readiness(root).review));continue;}
      if(choice==='history'){const s=read(root);console.log('\nSaved project activity\n'+(s.events.slice(-15).map(e=>`${e.at} · ${e.message}`).join('\n')||'No saved activity yet. Start with /review or /demo.'));continue;}
      const aliases={review:'4',results:'5',tests:'6',app:prompt.rich?'app':'1',models:'3',plugin:'10'};
      choice=aliases[choice]||choice;
      try{
        if(choice==='blackbox'){
          const state=read(root);
          const selected=state.targets.find(target=>target.name===state.activeTarget);
          const input=await promptValue(ask,'App URL',selected?[{value:selected.url,label:selected.url}]:[]);
          const url=appOriginInput(input),local=loopback(new URL(url).hostname);
          const savedPaths=selected?.url===url?selected.authorization?.paths?.join(','):null;
          const include=await promptValue(ask,'Allowed path prefixes',[
            {value:savedPaths||'/',label:savedPaths?`Saved scope (${savedPaths})`:'Entire app (/)'},
            ...(savedPaths&&savedPaths!=='/'?[{value:'/',label:'Entire app (/)' }]:[])],
          {write:message=>prompt.write?.(message)});
          const defaultRps=local?'5':'2';
          const rps=await promptValue(ask,'Maximum requests per second',[
            {value:defaultRps,label:`${defaultRps} requests per second`},
            {value:'1',label:'1 request per second'},
            {value:'10',label:'10 requests per second'}],
          {write:message=>prompt.write?.(message)});
          const limits={agents:options.agents,'http-workers':options['http-workers'],
            'model-calls':options['model-calls'],'max-urls':options['max-urls'],
            'max-tasks':options['max-tasks'],minutes:options.minutes,
            'dom-script-bytes':options['dom-script-bytes']};
          const setup=await run('blackbox setup',[url],{include,rps,...limits});
          if(!setup.ready){prompt.setNext?.('Complete the displayed ownership and scope steps, then use /blackbox again');continue;}
          if(prompt.rich)console.log(`Scope: ${path.relative(root,setup.scopeFile)} · ${setup.created?'created':'reused'} · includes ${include}`);
          const profile=state.models.find(model=>model.name===state.activeModel);
          console.log(options['no-model']?'Model: code-only audit':profile?
            `Model: ${profile.provider} · ${profile.model} · ${profile.baseUrl} · key variable ${profile.secretEnv} · ${profile.lastAttempt?.status||profile.lastTest?.status||'not tested'}`:
            'Model: Meta default · muse-spark-1.3 · https://api.meta.ai/v1 · key variable LLM_KEY, META_API_KEY or MODEL_API_KEY');
          if(!await confirmChoice(ask,`Start black-box audit of ${url} within ${include} at ${rps} rps?`,
            {yes:'Start audit',no:'Return to project',write:message=>prompt.write?.(message)}))continue;
          const result=await run('blackbox',[url],{scope:setup.scopeFile,rps,...limits,
            'accept-local':local,'no-model':!!options['no-model'],
            'no-discovery':!!options['no-discovery'],offline:!!options.offline,
            source:options.source});
          if(result.run){
            let auditResult=result;
            for(;;){
              const actions=[
                ...(auditResult.findings?.length?[
                  {id:'verify',label:'Replay confirmed finding proofs'},
                  {id:'export',label:'Export regression tests'}]:[]),
                ...(auditResult.coverage?.pendingResearchCheckpoints?[{id:'resume',label:'Resume pending research'}]:[]),
                {id:'home',label:'Return to project'}];
              if(actions.length<=1)break;
              const next=await choose(ask,actions,'Audit result');
              if(!next||next.id==='home')break;
              const followup=await run(`blackbox ${next.id}`,[auditResult.run]);
              if(next.id==='resume'&&followup.run)auditResult=followup;
            }
          }
          continue;
        }
        if(choice==='engine'){await engineWizard(ask,root,run);continue;}
        if(choice==='poc'){const result=await run('poc start',[],{project:root});root=result.root;updateWorkspace(prompt,root);continue;}
        if(choice==='demo'||choice==='walkthrough'){await tour();continue;}
        if(choice==='repo'){const result=await onboard({flow:'quickstart'},[],{...prompt,inDashboard:true});root=result.root;continue;}
        if(choice==='app'){
          const info=readiness(root),state=read(root);let target=state.targets.find(t=>t.name===state.activeTarget);
          if(!target){await targetWizard(ask,root);continue;}
          const ownershipValid=target.ownership?.status==='verified'&&Date.parse(target.ownership.expiresAt)>Date.now();
          if(!ownershipValid&&Date.parse(target.challenge?.expiresAt||0)<=Date.now())target=(await run('target verify',[target.name],{renew:true})).target;
          if(ownershipValid)console.log(`\n${target.url}\nOwnership verified · ${info.target.authorized?'testing scope authorized':'choose the paths you authorize for testing'}`);
          else if(target.environment==='local')console.log(`\nConfirm you control the local app at ${target.url}.`);
          else console.log(`\nPublish this DNS record:\n  Type   TXT · TTL Auto\n  Name   ${target.challenge.record}\n  Value  ${target.challenge.token}\n\nChoose the DNS check below when ready. Testing scope is authorized separately.`);
          prompt.setNext?.(info.target.authorized?'Edit allowed methods and paths, or return with Esc to review.':ownershipValid?'Choose allowed HTTP methods and paths':'Publish the TXT record, then choose Check the DNS TXT record');
          const action=await choose(ask,[{id:ownershipValid?'authorize':'verify',label:ownershipValid?(info.target.authorized?'Edit allowed methods & paths':'Choose allowed methods & paths'):`Check ${target.environment==='local'?'local ownership':'the DNS TXT record'}`},{id:'add',label:'Connect another app'},{id:'advanced',label:'All app settings & test accounts'}],'App connection');
          if(action?.id==='verify')await run('target verify',[target.name],{method:target.environment==='local'?'local':'dns'});
          else if(action?.id==='authorize')await authorizeWizard(ask,root,target.name);
          else if(action?.id==='add')await targetWizard(ask,root);
          else if(action?.id==='advanced'){advanced=true;}
          continue;
        }
        if(choice==='1'){const result=await onboard({project:root,flow:'quickstart'},[],{...prompt,inDashboard:true});root=result.root;}
        else if(choice==='2'){
          const state=read(root);const action=await choose(ask,[{label:'Add a target',id:'add'},{label:'Show targets / ownership challenges',id:'show'},{label:'Verify ownership',id:'verify'},{label:'Authorize testing scope',id:'authorize'},{label:'Select active target',id:'use'},{label:'Add test identity',id:'identity'},{label:'Test identity connection',id:'identity-test'},{label:'Revoke testing',id:'revoke'}],'Targets & identities');
          if(action?.id==='add')await targetWizard(ask,root);
          else if(action?.id==='identity'){const name=await promptValue(ask,'Identity name',['owner','outsider']);const type=await promptValue(ask,'Credential type',credentialTypes);const secret=await promptValue(ask,'Credential environment variable NAME',[`BYPASS_${name.toUpperCase().replace(/[^A-Z0-9_]/g,'_')}_TOKEN`]);const check=await promptValue(ask,'Identity-check endpoint path',['/api/me','/api/profile','/me']);const header=type==='header'?await promptValue(ask,'Header name',['X-API-Key','X-Auth-Token'],{recommended:false}):undefined;await run('identity add',[name],{target:state.activeTarget,type,'secret-env':secret,'check-path':check,header});}
          else if(action?.id==='identity-test'){const identity=await choose(ask,state.identities,'Identity');if(identity)await run('identity test',[identity.name]);}
          else if(action){const t=await choose(ask,state.targets,'Target');if(t){if(action.id==='authorize')await authorizeWizard(ask,root,t.name);else await run(`target ${action.id}`,[t.name],action.id==='verify'?{method:await promptValue(ask,'Verification method',verificationChoices(t))}:{});}}
        }
        else if(choice==='3'){
          const action=await choose(ask,[{label:'Add model profile',id:'add'},{label:'Choose active model',id:'use'},{label:'Test connection with synthetic prompt',id:'test'},{label:'Show profiles and privacy',id:'list'}],'Models');
          if(action?.id==='add')await modelWizard(ask,root,prompt);else if(action?.id==='list')await run('model list');else if(action){const model=await choose(ask,read(root).models,'Profile');if(model)await run(`model ${action.id}`,[model.name]);}
        }
        else if(choice==='4'){
          const ready=readiness(root).ready.liveReview;
          const mode=read(root).settings.reviewMode||(ready?'combined':'code');
          console.log('\n'+reviewSummary(readiness(root).review));
          console.log(`\nRunning your ${read(root).settings.analysisEngine==='docker'?'real AI review':'review preview'}${mode==='code'?' (code only)':mode==='live'?' (app only)':''}…`);
          const result=await run('scan',[],{mode});
          if(result.run?.result?.findings?.length)await showResults();
        }
        else if(choice==='5')await showResults();
        else if(choice==='6'){
          if(!read(root).checks.length){console.log('\nNo saved tests yet. The guided walkthrough creates your first example regression.');if(await choose(ask,[{label:'Start the guided walkthrough',id:'demo'}],'Next step'))await tour();continue;}
          await run('test list');const action=await choose(ask,[{label:'Replay all saved tests',id:'run'},{label:'Export standalone Node tests',id:'export'},{label:'Show coverage and gaps',id:'coverage'}],'Saved tests');if(action)await run(action.id==='coverage'?'coverage':`test ${action.id}`,[],action.id==='coverage'?{}:{all:true});
        }
        else if(choice==='7'){
          await run('monitor list');const action=await choose(ask,[{label:'Add a local monitor',id:'add'},{label:'Start background worker',id:'worker'},{label:'Run monitor now',id:'run'},{label:'Pause monitor',id:'pause'},{label:'Stop worker',id:'stop'}],'Monitoring');
          if(action?.id==='add')await run('monitor add',[await promptValue(ask,'Monitor name',['security'])],{every:await promptValue(ask,'Interval',[{value:'1h',label:'Every hour'},{value:'15m',label:'Every 15 minutes'},{value:'24h',label:'Daily'}]),runner:'local'});
          else if(action?.id==='worker'||action?.id==='stop')await run('monitor worker',[],action.id==='stop'?{stop:true}:{detach:true});
          else if(action){const m=await choose(ask,read(root).monitors,'Monitor');if(m)await run(`monitor ${action.id}`,[m.name]);}
        }
        else if(choice==='8')await run('context');
        else if(choice==='9'){
          const action=await choose(ask,[{label:'Start / open demo project',id:'start'},{label:'Apply ownership fix',id:'fix'},{label:'Reintroduce regression',id:'regress'},{label:'Add uncovered export route',id:'add-route'},{label:'Reset fixture behavior',id:'reset'},{label:'Stop fixture server',id:'stop'}],'Local demo');
          if(action){const result=await run(`demo ${action.id}`);if(action.id==='start')root=result.root;}
        }
        else if(choice==='10'){await run('integrate muse',[],{scope:'project'});}
        else if(choice){const tokens=tokenize(choice);if(['bypass','./bypass'].includes(tokens[0]))tokens.shift();const parsed=parse(tokens);if(parsed.options.help)console.log(help(parsed.key));else await run(parsed.key,parsed.args,parsed.options);}
      }catch(e){if(e.code===130&&!e.details?.cancelled)throw e;prompt.stopTasks?.(e.code===130?'cancelled':'failed');console.log(`\n${paint('31','!')} ${cleanText(e.message)}`);if(e.details?.challenge)console.log(JSON.stringify(e.details.challenge,null,2));}
    }
  }finally{close?.();}
  console.log(muted(`\nProject state saved. Reopen from the Bypass checkout with:\n  ./bypass --project ${JSON.stringify(root)}\n`));
}

async function engineWizard(ask,root,run){
  const mode=await choose(ask,[{id:'docker',label:'Real AI agents · two Docker services · model usage applies'},{id:'mock',label:'Offline preview · simulated discovery · no model usage'}],'Analysis engine');
  if(!mode)return;
  await run('engine use',[mode.id]);if(mode.id==='mock')return;
  await run('engine doctor');
  let state=read(root);
  if(!state.activeModel){console.log('Choose the shared model in /models before reviewing.');return;}
  const profile=state.models.find(m=>m.name===state.activeModel);
  console.log(`Orchestrator + white-box + black-box all use ${profile.name} / ${profile.model}. Selected source excerpts go to ${profile.dataDestination}.`);
  const target=state.targets.find(t=>t.name===state.activeTarget);
  if(!target||!readiness(root).ready.authorized){console.log('Source review is ready. Use /app to finish ownership and scope before HTTP proof.');return;}
  if(target.probes?.length){for(const p of target.probes)await run('probe test',[p.name]);return;}
  if(target.accountChoice?.mode==='skip'){console.log('Keeping your choice to continue without accounts. Source and anonymous checks remain available.');return;}
  if(target.accountChoice?.mode==='create'&&!target.registration){console.log('Account creation permission is saved. Finish registration configure with the source-derived signup route, then registration test. In Muse, the host discovers and configures these values.');return;}
  const accountChoice=target.accountChoice?{id:'connect'}:await choose(ask,[{id:'skip',label:'Continue without imported accounts (recommended)',description:'Source and configured anonymous checks remain available.'},{id:'connect',label:'Connect existing test accounts',description:'Choose saved accounts or add private references.'}],'Account-boundary checks are optional');
  if(!accountChoice)return;
  if(!target.accountChoice)await run('registration choose',[],{target:target.name,mode:accountChoice.id==='connect'?'existing':'skip'});
  if(accountChoice.id!=='connect')return;
  console.log('For real account-boundary proof, use two different test accounts and one resource belonging to the owner. Supply environment variable NAMES, never token values.');
  const identities=[];
  for(const role of ['owner','outsider']){
    state=read(root);
    const available=state.identities.filter(i=>i.target===target.name&&!identities.includes(i.name));
    const selected=await choose(ask,[...available.map(i=>({id:i.name,label:`Use ${i.name} (${i.secretEnv})`})),{id:'__new',label:`Add ${role} account`}],`${role} identity`);
    if(!selected)return;
    if(selected.id!=='__new'){identities.push(selected.id);continue;}
    const name=await promptValue(ask,'Account reference name',[role]);
    const type=await promptValue(ask,'Credential type',credentialTypes);
    const secret=await promptValue(ask,'Credential environment variable',[`BYPASS_${role.toUpperCase()}_TOKEN`]);
    const check=await promptValue(ask,'Signed-in identity endpoint',['/api/me','/api/profile','/me']);
    const header=type==='header'?await promptValue(ask,'Header name',['X-API-Key','X-Auth-Token'],{recommended:false}):undefined;
    await run('identity add',[name],{target:target.name,type,'secret-env':secret,'check-path':check,header});identities.push(name);
  }
  const resourcePath=await ask('Exact path to an owner-owned JSON resource (GET)');
  const resourceId=await ask('Expected resource identifier');
  const idField=await promptValue(ask,'JSON field identifying the resource',['id','resource.id','data.id']);
  const identityField=await promptValue(ask,'JSON field identifying the account at the identity endpoint',['id','uid','owner_uid']);
  await run('probe add',['primary'],{target:target.name,path:resourcePath,'resource-id':resourceId,owner:identities[0],outsider:identities[1],'id-field':idField,'identity-field':identityField});
  await run('probe test',['primary']);
  console.log('Ready. Use /review for source analysis and real HTTP proof. Fix confirmed issues in your editor, then use /results → Retest a fix.');
}
