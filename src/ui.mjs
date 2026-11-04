import { promptValue, confirmChoice, credentialTypes, verificationChoices, scopeSuggestions } from './interaction.mjs';
import { ownershipReady, verificationDisabled } from './ownership-store.mjs';
import { appEnvironmentQuestion, appEnvironmentChoices } from './app-connection.mjs';
import { promptAPIProfile } from './provider-setup.mjs';
import readline from 'node:readline/promises';
import { emitKeypressEvents } from 'node:readline';
import fs from 'node:fs';
import path from 'node:path';
import { read, rootFrom } from './store.mjs';
import { execute, readiness } from './service.mjs';
import { parse, help } from './catalog.mjs';
import { cleanText, redact, Fault, abortFault } from './util.mjs';
import { onboard } from './onboarding.mjs';
import { checkModelConnection } from './model-check.mjs';
import { guidedDemo } from './guided-demo.mjs';
import { homeActions, previewRun, reviewSummary } from './experience.mjs';
import { appOriginInput, loopback, DEFAULT_REQUESTS_PER_SECOND } from './network.mjs';
import { isBypassSource } from './project-selection.mjs';
import { createTerminalSession, interactiveHelp } from './terminal-session.mjs';
import { summaryText as blackboxSummary } from './blackbox/report.mjs';
import { progressLine as blackboxProgressLine } from './blackbox/progress.mjs';
import { createTheme, brandHeading } from './terminal-theme.mjs';
import { promptMethods, mayChangeData, recommendedMethods } from './http-methods.mjs';
import { modelDisplay } from './model-display.mjs';

const theme=createTheme();
const color=!!process.stdout.isTTY&&!process.env.NO_COLOR;
const tones={'31':'error','33':'warning','90':'muted','1':'title'};
const paint=(n,s)=>theme.paint(tones[n]||'accent',s);
const accent=s=>theme.paint('accent',s),muted=s=>theme.paint('muted',s),bold=s=>theme.paint('title',s);
const label=s=>String(s).replace(/_/g,' ');
const shellArg=value=>`'${String(value).replaceAll("'","'\"'\"'")}'`;
const RESEARCH_BEHAVIOR=new Set(['model-differential','model-json-differential','model-http-sequence']);
const BLACKBOX_PHASES=[
  {label:'Scope and hosts',working:'Confirming the approved origin, host boundaries and request limits',why:'Every request is checked against the scope before it can leave the CLI.',next:'Inspect public app assets and source facts.'},
  {label:'Assets and source',working:'Extracting routes, methods, inputs and trust boundaries from source and public assets',why:'Each retained fact becomes a concrete test candidate; source concerns remain unproven until HTTP replay.',next:'Show the route inventory, then test the highest-value candidates.'},
  {label:'Routes and responses',working:'Requesting reachable routes and recording status, content type and response shape',why:'Real response controls distinguish reachable behavior from source-only hypotheses.',next:'Queue baseline disclosure, authentication and injection checks.'},
  {label:'Plan and test leads',working:'Running deterministic checks first, then bounded Muse follow-up experiments',why:'The CLI—not the model—validates scope and executes each HTTP request.',next:'Show executed, queued and confirmed counts; replay every suspicious result.'},
  {label:'Replay and assess',working:'Replaying suspicious behavior with fresh controls',why:'A result becomes a finding only after independent HTTP evidence reproduces it.',next:'Write the finding, impact, remediation and coverage report.'},
  {label:'Report and coverage',working:'Building the evidence report and remaining-coverage summary',why:'The result separates confirmed findings from observations and untested work.',next:'Review findings, save regression tests or resume pending research.'}
];
export function blackboxOutcomeText(result){
  const findings=(result?.findings??[]).filter(finding=>finding.verdict==='confirmed'&&
    !RESEARCH_BEHAVIOR.has(finding.kind));
  if(!findings.length){
    const replayed=result?.replayInconclusive??[];
    const source=result?.sourceFindings??[];
    const sourceSummary=source.length?`\nSource review: ${source.length} unproven lead${source.length===1?'':'s'} · ${source.filter(item=>item.status==='not reproduced').length} not reproduced · ${source.filter(item=>['inconclusive','blocked'].includes(item.status)).length} inconclusive · ${source.filter(item=>item.status==='not tested').length} not tested.`:'';
    if(replayed.length)return `\nNo confirmed security finding survived final proof replay. ${replayed.length} positive signal${replayed.length===1?' was':'s were'} found, but the final replay was inconclusive; this is not a clean result.${sourceSummary}\nOpen report.md for the signal, replay reason and remaining coverage.`;
    return `\nNo confirmed security finding was produced; this is not a security clearance.${sourceSummary}\nOpen report.md for coverage gaps and untested work.`;
  }
  const cards=findings.map(finding=>{
    const impact=finding.assessment?.impact||finding.rationale||'A replayed HTTP proof confirmed this security boundary failure.';
    const preconditions=finding.assessment?.preconditions;
    const remediation=finding.assessment?.remediation||finding.remediation||'Review the affected server-side security control and add a regression test.';
    return `\n${String(finding.severity||'unrated').toUpperCase()} · ${finding.cwe||'Unclassified'} · ${finding.id}\n${finding.title}\nAffected: ${finding.pattern||finding.url||result.origin}\n\nBusiness impact\n${impact}${preconditions?`\n\nRequired conditions\n${preconditions}`:''}\n\nRecommended fix\n${remediation}\n\nCOPY FOR YOUR CODING AGENT\nFix ${finding.title} at ${finding.pattern||finding.url||result.origin}. The confirmed evidence rule is ${finding.rule||'a replayed HTTP proof'}. ${remediation} Add an automated regression test that proves the vulnerable behavior is no longer reproducible without weakening legitimate access.`;
  }).join('\n\n');
  return `\n${bold(findings.length===1?'CONFIRMED SECURITY FINDING':`${findings.length} CONFIRMED SECURITY FINDINGS`)}${cards}\n\nVerify the fix\n  bypass blackbox verify ${shellArg(result.run)} --project ${shellArg(result.projectRoot)}\nSave standalone tests\n  bypass blackbox export ${shellArg(result.run)} --project ${shellArg(result.projectRoot)}\n\nSecurity memory\n${result.memory?.saved?.length?`✓ Saved ${result.memory.saved.length} confirmed finding${result.memory.saved.length===1?'':'s'} for future coding context.`:'No new confirmed finding was saved.'}`;
}

export function regressionExportText(value){
  if(!value.files?.length)return `\nNo standalone regression test was saved. ${value.skippedProofs?.length?`${value.skippedProofs.length} proof${value.skippedProofs.length===1?' was':'s were'} not exportable.`:''}`;
  return `\n✓ Saved ${value.files.length} standalone regression test${value.files.length===1?'':'s'}\nLocation: ${value.output}\nRun now:\n  node --test ${value.files.map(shellArg).join(' ')}`;
}
export function printResult(data,{interactive=false}={}){
  if(!data)return;
  const value=redact(data);
  if(value.error){console.error(paint('31',value.error));if(value.details&&Object.keys(value.details).length)console.error(JSON.stringify(value.details,null,2));return;}
  if(value.kind==='blackbox-audit'){console.log(blackboxSummary(value,{color})+blackboxOutcomeText(value));return;}
  if(value.run?.kind==='scan'&&value.run.result?.blackbox){
    const audit={kind:'blackbox-audit',...value.run.result.blackbox};
    console.log(blackboxSummary(audit,{color})+blackboxOutcomeText(audit));
    return;
  }
  if(value.kind==='blackbox-scope'){console.log(`\nScope: ${value.file}\nTarget: ${value.origin}\nIncluded paths: ${value.include.join(', ')}\nCredential origins: ${value.credentialOrigins.join(', ')}\nAccounts: ${value.identities.owner}, ${value.identities.outsider}\nNext: ${value.next}`);return;}
  if(value.kind==='blackbox-setup'){
    const scopeAction = value.created ? 'created' : value.updated ? 'rate updated' : 'reused';
    const localPath=file=>{
      const relative=path.relative(value.root,file);
      return relative&&!relative.startsWith('..')&&!path.isAbsolute(relative)?`./${relative}`:file;
    };
    const localCommand=command=>interactive?command
      .replace(` --project ${shellArg(value.root)}`,'')
      .replaceAll(value.root+path.sep,'./'):command;
    const setup=value.steps.filter(step=>step.kind!=='run');
    console.log(`\n${bold('BLACK-BOX SETUP')}\n`+
      `TARGET       ${value.origin}\n`+
      `SCOPE        ${localPath(value.scopeFile)} · ${scopeAction}\n`+
      `ALLOWED      ${(value.methods??[]).join(', ')||'saved methods'} · ${value.rate??'saved'} requests/second\n`+
      `STATUS       ${setup.length?`${setup.length} setup action${setup.length===1?'':'s'} before testing`:'Ready to start the audit'}`);
    let number=0;
    for(const step of value.steps){
      number++;
      if(step.kind==='ownership')console.log(`\n${String(number).padStart(2,'0')} / VERIFY APP OWNERSHIP\n`+
        `DNS NAME     ${step.record}\nDNS VALUE    ${step.value}\n`+
        `${accent('RUN')}          ${localCommand(step.command)}`);
      else if(step.kind==='authorization')console.log(`\n${String(number).padStart(2,'0')} / AUTHORIZE TESTING\n`+
        `SCOPE FILE   ${localPath(step.file)}\n`+
        `ACTION       Review the saved paths, methods and rate${step.production?'; acknowledge production testing':''}.\n`+
        `${accent('RUN')}          ${localCommand(step.command)}`);
      else console.log(`\n${String(number).padStart(2,'0')} / START SECURITY AUDIT\n`+
        `${accent('RUN')}          ${localCommand(step.command)}`);
    }
    console.log(`\n${muted('The configured Muse connection is checked automatically when the audit starts.')}`);
    return;
  }
  if(value.kind==='blackbox-verify'){console.log(`\n${value.integrity.ok?'Ledger intact':'Ledger broken'} · ${value.reportedFindings??value.proofs.length} findings · ${value.proofs.length} proofs\n${value.proofs.map(item=>`  ${item.id}: ${item.verdict}${item.corroborates?` · corroborates ${item.corroborates}`:''}`).join('\n')}\nExit ${value.exitCode}`);return;}
  if(value.kind==='blackbox-export'){
    console.log(regressionExportText(value));
    if(value.skippedProofs?.length)console.log(`Skipped ${value.skippedProofs.length} unsupported private-read proof${value.skippedProofs.length===1?'':'s'}`);
    return;
  }
  if(value.export?.kind==='blackbox-export'){
    console.log(regressionExportText(value.export));
    if(value.export.skippedProofs?.length)console.log(`Skipped ${value.export.skippedProofs.length} unsupported private-read proof${value.export.skippedProofs.length===1?'':'s'}`);
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
    if(!value.records)console.log('  No security memory yet. A source security audit saves cited knowledge; verified fixes add reusable behavior checks.');
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
    console.log(`  App           ${p.mode==='code'?'no live requests':p.target||'not connected'}\n  Saved checks  ${p.savedChecks}${p.mode==='code'?' · replay requires an authorized app':' · replay first'}\n  Source        ${p.simulation?'local inventory only':'selected excerpts sent to '+p.model?.destination}\n  Analysis      ${p.simulation?'simulated · no model calls':'containerized source review · shared model'}\n  Evidence      saved locally`);
    if(p.blockers.length)console.log(`\n${paint('33','Setup needed:')}\n${p.blockers.map(x=>'  '+x).join('\n')}`);
    else console.log(p.simulation?'\nReady for a walkthrough review. Simulated results are not a security verdict.':'\nReady for a bounded security audit. Model usage applies; HTTP evidence decides confirmation.');
    return;
  }
  if(value.run&&/^scan_[a-f0-9]{24}$/.test(value.run.id)){
    const r=value.run,status=value.status||r.status;
    const incomplete=['failed','incomplete','interrupted','error'].includes(status);
    console.log(`\n${bold(incomplete?'Discovery incomplete':'Discovery')} · ${label(status)}\nRun: ${r.id}`);
    if(value.message||r.message)console.log(`\n${value.message||r.message}`);
    console.log(`\nStage: ${r.phase||r.stage||'discovery'}\nDetector signals: ${r.signalCount}\nEvaluation: ${r.evaluation}`);
    console.log(r.executionMode==='muse-host'?'Reasoning: active Muse session · usage unavailable':`Model requests: ${r.reasoning?.independentModelRequests??((r.policy?.modelRequests||0)+(r.evaluationSummary?.modelRequests||0))}`);
    console.log(`Evidence: .bypass/scanner/${r.id}/manifest.json`);
    console.log(`Next: bypass discover ${status==='interrupted'?`resume ${r.id}`:`report ${r.id} --format md`}`);
    console.log(muted(`Exit ${value.exitCode} · source-only analysis; no runtime reproduction`));return;
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
  if(value.target?.challenge&&verificationDisabled(value.target)){console.log(`\n${value.target.url}\nDomain verification: off (project setting). No DNS/HTTPS proof was checked.\nNext: approve the exact testing scope.`);return;}
  if(value.target?.challenge){const t=value.target;console.log(`\n${bold(t.name)} · ${t.url}\nOwnership: ${t.ownership?.status||'pending'}\n`);if(t.environment==='local')console.log(`Next: bypass target verify ${t.name} --method local`);else console.log(`Publish TXT record:\n  Name:  ${t.challenge.record}\n  Value: ${t.challenge.token}\n\nOr serve exactly that value at:\n  ${t.url}${t.challenge.httpPath}\n\nThen: bypass target verify ${t.name} --method dns`);if(t.authorization)console.log(`Scope: ${t.authorization.paths.join(', ')} · expires ${t.authorization.expiresAt}`);return;}
  if(value.findings){console.log(`\n${value.findings.length} findings`);for(const f of value.findings)console.log(`  ${bold(f.id)}  ${f.title}\n    ${label(f.status)} · ${f.fixture?'local fixture':f.simulation?'SIMULATED · unproven':'evidence available'}`);return;}
  if(value.checks&&Array.isArray(value.checks)){console.log(`\n${value.checks.length} saved checks`);for(const c of value.checks)console.log(`  ${bold(c.id)}  ${c.title||c.behavior}\n    ${c.status||c.lastResult?.status||'not run'} · ${c.enabled===false?'disabled':c.target}`);if(value.message)console.log(value.message);return;}
  if(value.finding){const f=value.finding;const next=f.fixture||f.engine==='docker'?`bypass ${['confirmed_fixture','confirmed','regression_failed'].includes(f.status)?'retest':'verify'} ${f.id}`:'bypass demo — complete the proof loop in a separate local app';console.log(`\n${bold(f.title)}\n${f.id} · ${label(f.status)}\n\n${f.hypothesis}\n\n${f.sourceEvidence?.file?`${f.sourceEvidence.file}:${f.sourceEvidence.line}\n${f.sourceEvidence.quote}`:f.sourceEvidence?.message||''}\n\nFix: ${f.recommendation}\n\nNext: ${next}`);if(f.verification)console.log(JSON.stringify(f.verification,null,2));return;}
  if((value.installed||value.integration)&&value.state&&value.next){
    console.log(`\n${bold('Bypass in Muse Code')} · ${label(value.state)}\n${value.message||'Native plugin status'}\n`);
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
  const secret=async text=>{
    if(!process.stdin.isTTY||!process.stdout.isTTY)throw new Fault('Set MODEL_API_KEY before launching Bypass in a non-interactive environment.',3,{reason:'credential_missing'});
    rl.pause();const input=process.stdin,output=process.stdout,wasRaw=input.isRaw;let value='';
    emitKeypressEvents(input);input.setRawMode(true);input.resume();output.write(`${text}: `);
    return new Promise((resolve,reject)=>{
      const finish=(error)=>{input.off('keypress',key);input.setRawMode(Boolean(wasRaw));rl.resume();output.write('\n');if(error)reject(error);else resolve(value);};
      const key=(str,event={})=>{
        if(event.ctrl&&event.name==='c'){finish(new Fault('Setup stopped. Saved choices are retained.',130));return;}
        if(['return','enter'].includes(event.name)){finish();return;}
        if(event.name==='backspace'){if(value){value=value.slice(0,-1);output.write('\b \b');}return;}
        if(str&&!event.ctrl&&!event.meta&&!str.includes('\x1b')&&value.length<8192){const clean=str.replace(/[\r\n]/g,'');value+=clean;output.write('•'.repeat([...clean].length));}
      };
      input.on('keypress',key);
    });
  };
  ask.secret=secret;
  const run=async work=>{
    if(controller.signal.aborted)throw abortFault(controller.signal);
    const operation=new AbortController();
    const skip=()=>operation.abort(new Fault('Connection check skipped.',130,{skipped:true}));
    const stop=()=>operation.abort(abortFault(controller.signal));
    rl.on('line',skip);controller.signal.addEventListener('abort',stop,{once:true});
    try{return await work(operation.signal);}
    finally{rl.removeListener('line',skip);controller.signal.removeEventListener('abort',stop);}
  };
  return {ask,secret,run,signal:controller.signal,close:()=>rl.close()};
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
    if(prompt.rich&&result.openDashboard){await terminal({project:result.root,startReview:result.startReview},prompt);return {...result,openDashboard:false};}
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
  prompt.setContext({demo:false,engine:info.engine.mode,title:info.project.name,repo:root,
    bypassProject:path.join(root,'.bypass'),branch:info.project.repository.branch,
    app:info.target?`${info.target.url} · ${info.target.authorized?'authorized':info.target.ownership==='verified'||info.target.ownershipVerification==='off'?'scope required':'verification pending'}`:'not connected · code preview available',
    model:info.model?modelDisplay(info.model):'not configured · /models for API setup',
    checks:info.checks.enabled,memory:info.memory?.records||0});
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
  if(verificationDisabled(added.target)||ownershipReady(added.target)){console.log(verificationDisabled(added.target)?'Domain verification is off. Scope approval confirms you control this app.':`\nOwnership already verified for ${new URL(url).hostname}.`);await authorizeWizard(ask,root,name);}
  else if(environment==='local'){await execute('target verify',[name],{project:root,method:'local'});await authorizeWizard(ask,root,name);}
  else console.log('\nPublish the ownership challenge, then choose Targets → Verify. App testing becomes available after verification and scope approval.');
}
async function authorizeWizard(ask,root,name){
  const target=read(root).targets.find(t=>t.name===name);console.log(`\nAuthorize testing on ${target?.url} only. This expires in seven days.`);
  const paths=await promptValue(ask,'Allowed path prefixes, comma-separated',scopeSuggestions(target));
  const methods=await promptMethods(ask,console.log,target?.authorization?.methods);
  console.log(`Methods: ${methods.join(', ')} · Paths: ${paths} · Limit: ${DEFAULT_REQUESTS_PER_SECOND} requests/second`);
  console.log('Also read public app pages/scripts for sign-in setup (anonymous GET only).');
  if(mayChangeData(methods))console.log('These methods can change test data or start jobs. Only explicitly configured requests will run.');
  const production=target?.environment==='production';
  if(!await confirmChoice(ask,production?
    `Authorize these checks on the production app ${target.url}?`:
    verificationDisabled(target)?`Confirm you control ${target.url} and authorize these checks?`:`Authorize these checks on ${target.url}?`,
    {yes:production?'Yes, authorize this production scope':'Yes, authorize these checks',
      no:'Not now — keep testing disabled',fallback:true,recommended:'yes'}))return;
  printResult(await execute('target authorize',[name],{project:root,paths,methods,rps:DEFAULT_REQUESTS_PER_SECOND,accept:true,production,'public-config':true}));
}
function dashboard(root){
  console.log('\n'+brandHeading('Security that stays with your code.')+'\n');
  let info;try{info=readiness(root);}catch{console.log('No project connected. Choose Setup or Demo to begin.');return;}
  console.log(`${bold(info.project.name)}\n${muted(root)}\n`);
  console.log(`  REPOSITORY   ${info.project.repository.kind==='app'?'App only · no source repository':info.project.repository.kind==='git'?'Git connected':'Directory connected'}`);
  console.log(`  LIVE APP     ${info.target?`${info.target.url} · ${info.target.authorized?'authorized':info.target.ownership}`:'not connected'}`);
  console.log(`  MODEL        ${info.model?modelDisplay(info.model):'choose a provider'}`);
  console.log(`  EVIDENCE     local · ${info.findings.total} findings · ${info.checks.enabled} saved tests`);
  console.log(`  MONITOR      ${info.worker.status} · ${info.monitors} schedules`);
  console.log(`\n${theme.paint(info.engine.mode==='docker'?'accent':'warning',info.engine.mode==='docker'?'  SECURITY AUDIT · source review + HTTP proof':'  PREVIEW · simulated discovery')}  ${muted('Evidence and saved checks stay in this project.')}`);
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
      blackboxTotal=0, blackboxEstimate=0, blackboxResearch=0, blackboxUntested=0,
      blackboxConfirmed=0, blackboxStage='Recon in progress', lastBlackboxLine='';
    const blackboxStages=BLACKBOX_PHASES.map(phase=>phase.label);
    let blackboxLive={done:'Approved target and limits loaded; no audit request has been sent yet.',
      ...BLACKBOX_PHASES[0],recovered:''};
    const syncBlackboxLive=overrides=>{
      blackboxLive={...blackboxLive,...overrides};
      prompt.setLiveStatus?.({done:blackboxLive.done,working:blackboxLive.working,why:blackboxLive.why,
        recovered:blackboxLive.recovered,next:blackboxLive.next,
        metrics:`${blackboxChecks}${blackboxTotal?`/${blackboxTotal}`:''} checks · ${blackboxRequests} HTTP · ${blackboxModelCalls} Muse${blackboxConfirmed?` · ${blackboxConfirmed} confirmed`:''}${blackboxUntested?` · ${blackboxUntested} untested`:''}`});
    };
    const real=read(root).settings.analysisEngine==='docker';
    const scanMode=flags.mode||read(root).settings.reviewMode||'combined';
    const hasLiveAudit=key==='blackbox'||key==='scan'&&real&&scanMode!=='code';
    const sourceTaskOffset=key==='scan'&&scanMode==='combined'?1:0;
    const stages=real?['replay','containers','orchestrator',...(flags.mode==='live'?[]:['white-box'])]:['replay','inventory','mock-analysis'];
    const stageLabels={'replay':'Saved checks / scope','containers':'Source-review worker','orchestrator':'Source-review plan','white-box':'Code security review','inventory':'Local source inventory','mock-analysis':'Simulated discovery'};
    if(key==='scan')prompt.setTasks?.(real?'Security audit':'Review preview',hasLiveAudit?
      [...(sourceTaskOffset?['Code security review']:[]),...blackboxStages]:
      stages.map(stage=>stageLabels[stage]));
    if(key==='blackbox'){
      prompt.setTasks?.(flags.combined?'Combined security audit':'Black-box audit',blackboxStages);
      prompt.setNext?.('Recon in progress · 0 HTTP · 0 Muse');
      syncBlackboxLive();
    }
    const work=async signal=>{
      const result=await execute(key,args,{project:root,...flags},{signal,onProgress:step=>{
        const blackboxStep=key==='blackbox'?step:step.blackbox;
        if(hasLiveAudit&&blackboxStep){
          if(blackboxStep.stage==='progress'&&blackboxStep.type==='phase'){
            const index=blackboxStep.step-1;
            if(blackboxStep.state==='doing'){
              blackboxStage=blackboxStages[index]||'Audit in progress';
              const phase=BLACKBOX_PHASES[index];
              if(phase)syncBlackboxLive({...phase,done:index?
                `${index} of ${BLACKBOX_PHASES.length} phases complete · ${BLACKBOX_PHASES[index-1].label}`:
                'Approved target and limits loaded; beginning the first guarded requests.'});
              prompt.task?.(index+sourceTaskOffset,'running');
              prompt.setNext?.(`${blackboxStage} · ${blackboxRequests} HTTP · ${blackboxModelCalls} Muse`);
            }
            if(blackboxStep.state==='done'){
              prompt.task?.(index+sourceTaskOffset,'done');
              syncBlackboxLive({done:`${blackboxStep.step} of ${BLACKBOX_PHASES.length} phases complete · ${blackboxStage}`});
            }
          }
          if(blackboxStep.stage==='progress'){
            if(blackboxStep.type==='request')blackboxRequests=Math.max(blackboxRequests,blackboxStep.requests??0);
            if(blackboxStep.type==='model')blackboxModelCalls=Math.max(blackboxModelCalls,blackboxStep.modelCalls??0);
            if(blackboxStep.type==='task-done'){blackboxChecks++;if(blackboxStep.confirmed)blackboxConfirmed++;}
            if(blackboxStep.type==='research-attempt')blackboxResearch++;
            if(blackboxStep.type==='task-estimate'){
              blackboxTotal+=Math.max(0,blackboxStep.total??0)-blackboxEstimate;
              blackboxEstimate=Math.max(0,blackboxStep.total??0);
            }
            if(blackboxStep.type==='task-total'){
              blackboxTotal+=Math.max(0,blackboxStep.total??0)-blackboxEstimate;
              blackboxEstimate=0;
            }
            if(blackboxStep.type==='task-untested')blackboxUntested++;
            if(blackboxStep.type==='task-reconcile'){
              blackboxTotal=Math.max(0,blackboxStep.total??0);
              blackboxChecks=Math.max(0,blackboxStep.done??0);
              blackboxUntested=Math.max(0,blackboxStep.untested??0);
            }
            if(['request','model','task-done','task-estimate','task-total','task-untested','task-reconcile','research-attempt'].includes(blackboxStep.type))
              prompt.setNext?.(`${blackboxStage} · ${blackboxChecks}${blackboxTotal?`/${blackboxTotal}`:''} checks${blackboxConfirmed?` · ${blackboxConfirmed} finding${blackboxConfirmed===1?'':'s'}`:''} · ${blackboxRequests} HTTP · ${blackboxModelCalls} Muse${blackboxResearch?` · ${blackboxResearch} research tries`:''}${blackboxUntested?` · ${blackboxUntested} untested`:''}`);
          }
          const line=blackboxProgressLine(blackboxStep);
          if(line){
            if(line.label==='Muse recovered')syncBlackboxLive({recovered:line.text,
              working:'Continuing from saved evidence with a smaller or later bounded batch'});
            else if(line.label==='Muse source')syncBlackboxLive({working:line.text,
              why:'Each source batch extracts route facts and security hypotheses; live HTTP proof still decides every finding.',
              next:'Finish bounded source batches, then execute the highest-value live checks.'});
            else if(line.label==='Muse web')syncBlackboxLive({working:`Muse is reviewing observed test candidates · ${line.text}`});
            else if(line.label==='Muse research')syncBlackboxLive({working:`Running a bounded experiment · ${line.text}`});
            else if(line.label==='Proof')syncBlackboxLive({working:`Independently replaying a suspicious result · ${line.text}`});
            else if(line.label==='Source')syncBlackboxLive({done:`Source inventory: ${line.text}`,
              next:'Map those routes against reachable app responses, then run live checks.'});
            else if(line.label==='Web tests')syncBlackboxLive({done:`Live checks: ${line.text}`,
              working:'Reconciling executed checks, queued work and independently replayed evidence'});
            else if(['Assets','Muse assets','Recon','Routes'].includes(line.label))syncBlackboxLive({done:`${line.label}: ${line.text}`});
          }
          if(blackboxStep.stage==='progress')syncBlackboxLive();
          const rendered=line?`${line.label}  ${line.text}`:'';
          if(rendered&&rendered!==lastBlackboxLine){lastBlackboxLine=rendered;prompt.write?.(rendered);}
        } else prompt.write?.(step.message);
        if(key==='scan'&&sourceTaskOffset&&step.stage==='white-box'){
          prompt.task?.(0,/source hypothes/i.test(step.message)?'done':'running');
        }else if(key==='scan'&&!hasLiveAudit){const nextStage=stages.indexOf(step.stage);if(nextStage>=0&&nextStage!==lastStage){if(lastStage>=0)prompt.task?.(lastStage,'done');lastStage=nextStage;prompt.task?.(lastStage,'running');}}
      }});
      if(result.exitCode===130)throw new Fault('Run stopped. Partial evidence is saved.',130,{cancelled:true});
      if(key==='scan'&&!hasLiveAudit&&lastStage>=0)prompt.task?.(lastStage,previewRun(result.run)||result.run?.status==='completed'?'done':'attention');
      return result;
    };
    const result=prompt.activity?await prompt.activity(key==='scan'?(real?'Security audit':'Review preview'):key==='test run'?'Replay saved checks · no model':key==='blackbox'?'Black-box audit':key,work,{verdict:r=>(key.startsWith('blackbox')||key==='scan')&&r.exitCode===1?'done':r.exitCode&&!(previewRun(r.run)&&r.exitCode===3)?'attention':'done'}):await work(prompt.signal);
    if(!(prompt.rich&&key==='blackbox setup'&&result.ready))printResult(result,{interactive:!!prompt.rich});
    if(key==='blackbox'){
      const confirmed=(result.findings??[]).filter(finding=>finding.verdict==='confirmed'&&
        !RESEARCH_BEHAVIOR.has(finding.kind)).length;
      if(confirmed)prompt.setNext?.(`${confirmed} confirmed finding${confirmed===1?'':'s'} · review impact and remediation below`);
    }
    if(key==='blackbox export'&&result.files?.length)prompt.setNext?.(`Regression test saved · node --test ${result.files.map(shellArg).join(' ')}`);
    return result;
  };
  const tour=async(flags={})=>{try{return await guidedDemo(flags,prompt);}finally{if(prompt.rich)updateWorkspace(prompt,root);}};
  const showResults=async()=>{
    const findings=read(root).findings;
    if(!findings.length){console.log('\nNo review results yet. Press Enter on the home screen to run the first preview.');return;}
    const finding=findings.length===1?findings[0]:await choose(ask,findings.map(f=>({...f,label:`${f.title} · ${label(f.status)}`})),'Review results');
    if(!finding)return;
    if(!finding.fixture&&!['docker','host','blackbox'].includes(finding.engine)){
      prompt.setNext?.('Try the local walkthrough to prove the example and save a regression test');
      console.log(`\n${bold('Example scenario / account access')}\nCould another account read a resource owned by someone else?\n\nThis sample demonstrates how a finding will look. It was not discovered in your code.\nThe deployed-app investigation engine is not built yet; DNS verification will not turn this sample into a verified vulnerability.`);
      const action=await choose(ask,[{label:'See the full prove → fix → retest walkthrough in a local app',id:'demo'},{label:'Show saved scenario details',id:'details'}],'Next step');
      if(action?.id==='demo')await tour();else if(action?.id==='details')printResult({finding});
    }else{
      printResult({finding});
      const action=await choose(ask,[{label:['docker','blackbox'].includes(finding.engine)?'Reproduce with saved HTTP proof':'Verify this local fixture',id:'verify'},{label:'Retest a fix',id:'retest'},{label:'Follow a fresh guided walkthrough',id:'demo'}],'Next step');
      if(action?.id==='demo')await tour();else if(action)await run(action.id,[finding.id]);
    }
  };
  try{
    let queuedStart=options.startReview;
    updateWorkspace(prompt,root);
    if(prompt.rich){const info=readiness(root);console.log(`\nProject ready · ${info.findings.total} saved result(s) · ${info.checks.enabled} regression test(s)\n${info.latestRun?`Last run: ${info.latestRun.kind} · ${info.latestRun.status}. `:''}Use /history for saved activity, /status for review scope.`);}
    if(isBypassSource(root)){
      console.log(`\nYou opened the Bypass tooling repository:\n${root}\nChoose your application source for white-box review.`);
      const action=await choose(ask,[{id:'repo',label:'Choose my application repository (recommended)'},{id:'demo',label:'Run the separate local walkthrough'},{id:'tool',label:'Intentionally review Bypass tooling itself'}],'What do you want to review?');
      if(!action)return;
      if(action.id==='demo'){await tour();if(prompt.rich)await ask('Walkthrough finished — Enter to close');return;}
      if(action.id==='repo'){const result=await onboard({flow:'quickstart'},[],{...prompt,inDashboard:true});root=result.root;queuedStart=result.startReview;}
    }
    while(true){
      const starting=queuedStart;queuedStart=null;
      let choice;
      if(starting)choice=starting.id;
      else if(advanced&&prompt.rich){
        const action=await choose(ask,[{id:'1',label:'Resume setup'},{id:'2',label:'App ownership & test accounts'},{id:'3',label:'Models & privacy'},{id:'6',label:'Saved tests'},{id:'7',label:'Monitoring'},{id:'8',label:'Session context'},{id:'9',label:'Manual fixture controls'},{id:'10',label:'Muse plugin'},{id:'11',label:'Domain ownership verification'}],'Settings');
        advanced=false;if(!action)continue;choice=action.id;
      }else if(advanced){
        dashboard(root);
        console.log('SETTINGS & ADVANCED\n  1  Resume setup                  6  Saved tests\n  2  App & test accounts           7  Monitoring\n  3  Models                        8  Session context\n  4  Review preview                9  Manual demo controls\n  5  Review results               10  Muse plugin\n 11  Domain ownership verification\n  0  Back to project home\n');
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
        console.log(`Model: ${info.model?modelDisplay(info.model):'not configured; mock preview needs no model'} · ${info.findings.total} review result(s)`);
        console.log('\n'+actions.map((action,i)=>`  ${i+1}  ${action.label}${i===0?'  ← Enter':''}`).join('\n'));
        console.log('  0  Exit\n\n? commands · repo change repository · app verification · q quit');
        const selected=await ask('Choose or type a command','1');
        if(selected==='0')break;
        choice=/^[1-3]$/.test(selected)?actions[Number(selected)-1].id:selected;
        }
      }
      choice=choice.replace(/^\//,'');
      if(['q','quit','exit'].includes(choice))break;
      if(['?','help','commands'].includes(choice)){console.log('\n'+interactiveHelp());continue;}
      if(choice==='help all'){console.log(help());continue;}
      if(choice==='back'){advanced=false;continue;}
      if(choice==='settings'){advanced=true;continue;}
      if(choice==='status'){await run('status');continue;}
      if(choice==='history'){const s=read(root);console.log('\nSaved project activity\n'+(s.events.slice(-15).map(e=>`${e.at} · ${e.message}`).join('\n')||'No saved activity yet. Start with /review or /demo.'));continue;}
      const aliases={review:'4',results:'5',tests:'6',app:prompt.rich?'app':'1',models:'3',plugin:'10'};
      choice=aliases[choice]||choice;
      try{
        if(choice==='blackbox'){
          const state=read(root);
          const selected=state.targets.find(target=>target.name===state.activeTarget);
          const automatic=starting?.id==='blackbox';
          let url,include,methods,rps,environment,out,force=false;
          if(automatic){
            if(!selected?.authorization)throw new Fault('The approved app boundaries are unavailable. Resume app setup before testing.',3);
            url=selected.url;include=selected.authorization.paths.join(',');methods=selected.authorization.methods.join(',');
            rps=String(selected.authorization.maxRequestsPerSecond);environment=selected.environment;
            out='blackbox.onboarding.scope.json';force=true;
            prompt.write?.(`Starting app audit · ${url} · ${include} · ${methods} · ${rps} requests/second`);
          }else{
            const input=await promptValue(ask,'App URL',selected?[{value:selected.url,label:selected.url}]:[]);
            url=appOriginInput(input);const saved=selected?.url===url?selected.authorization:null;
            include=await promptValue(ask,'Allowed path prefixes',[
              {value:saved?.paths?.join(',')||'/',label:saved?`Saved scope (${saved.paths.join(', ')})`:'Entire app (/)'},
              ...(saved&&saved.paths.join(',')!=='/'?[{value:'/',label:'Entire app (/)' }]:[])],
            {write:message=>prompt.write?.(message)});
            methods=(await promptMethods(ask,message=>prompt.write?.(message),saved?.methods)).join(',');
            const rates=[...new Set([saved?.maxRequestsPerSecond,DEFAULT_REQUESTS_PER_SECOND,10,5,1,32].filter(value=>value!=null).map(String))];
            rps=await promptValue(ask,'Maximum requests per second',rates.map(value=>({value,label:`${value} request${value==='1'?'':'s'} per second`})),
            {write:message=>prompt.write?.(message)});
            environment=selected?.url===url?selected.environment:undefined;
          }
          const local=loopback(new URL(url).hostname);
          const limits={agents:options.agents,'http-workers':options['http-workers'],
            'model-calls':options['model-calls'],
            'max-urls':options['max-urls'],
            'max-tasks':options['max-tasks'],
            minutes:options.minutes,
            'dom-script-bytes':options['dom-script-bytes']};
          const setup=await run('blackbox setup',[url],{include,methods,rps,environment,out,force,...limits});
          if(!setup.ready){prompt.setNext?.('Complete the displayed ownership and scope steps, then start the audit again');continue;}
          if(prompt.rich)console.log(`Scope: ${path.relative(root,setup.scopeFile)} · ${setup.created?'created':'reused'} · includes ${include}`);
          const profile=state.models.find(model=>model.name===state.activeModel);
          console.log(options['no-model']?'Model: code-only audit':profile?
            `Model: ${profile.provider} · ${profile.model} · ${profile.baseUrl} · key variable ${profile.secretEnv} · ${profile.lastAttempt?.status||profile.lastTest?.status||'not tested'}`:
            'Model: Meta default · muse-spark-1.3 · https://api.meta.ai/v1 · key variable LLM_KEY, META_API_KEY or MODEL_API_KEY');
          if(!automatic&&!await confirmChoice(ask,`Start black-box audit of ${url} within ${include} at ${rps} rps?`,
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
                  {id:'export',label:'Save standalone regression tests'}]:[]),
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
        if(choice==='repo'){const result=await onboard({flow:'quickstart'},[],{...prompt,inDashboard:true});root=result.root;queuedStart=result.startReview;continue;}
        if(choice==='app'){
          const info=readiness(root),state=read(root);let target=state.targets.find(t=>t.name===state.activeTarget);
          if(!target){await targetWizard(ask,root);continue;}
          const ownershipValid=verificationDisabled(target)||ownershipReady(target);
          const proofMethod=target.environment==='local'?'local':target.ownershipVerification==='http'?'http':'dns';
          if(!ownershipValid&&Date.parse(target.challenge?.expiresAt||0)<=Date.now())target=(await run('target verify',[target.name],{renew:true})).target;
          if(verificationDisabled(target))console.log(`\n${target.url}\nDomain verification is off. Approve the exact testing scope to continue.`);
          else if(ownershipValid)console.log(`\n${target.url}\nOwnership verified · ${info.target.authorized?'testing scope authorized':'choose the paths you authorize for testing'}`);
          else if(target.environment==='local')console.log(`\nConfirm you control the local app at ${target.url}.`);
          else if(proofMethod==='http')console.log(`\nServe exactly ${target.challenge.token} at:\n${target.url}${target.challenge.httpPath}\nChoose Check the HTTPS file when ready.`);
          else console.log(`\nPublish this DNS record:\n  Type   TXT · TTL Auto\n  Name   ${target.challenge.record}\n  Value  ${target.challenge.token}\n\nChoose the DNS check below when ready. Testing scope is authorized separately.`);
          prompt.setNext?.(info.target.authorized?'Edit allowed methods and paths, or return with Esc to review.':ownershipValid?'Choose allowed HTTP methods and paths':proofMethod==='http'?'Publish the file, then choose Check the HTTPS file':'Publish the TXT record, then choose Check the DNS TXT record');
          const action=await choose(ask,[{id:ownershipValid?'authorize':'verify',label:ownershipValid?(info.target.authorized?'Edit allowed methods & paths':'Choose allowed methods & paths'):`Check ${proofMethod==='local'?'local ownership':proofMethod==='http'?'the HTTPS file':'the DNS TXT record'}`},{id:'add',label:'Connect another app'},{id:'advanced',label:'All app settings & test accounts'}],'App connection');
          if(action?.id==='verify')await run('target verify',[target.name],{method:proofMethod});
          else if(action?.id==='authorize')await authorizeWizard(ask,root,target.name);
          else if(action?.id==='add')await targetWizard(ask,root);
          else if(action?.id==='advanced'){advanced=true;}
          continue;
        }
        if(choice==='11'){
          const current=read(root).settings.ownershipVerification??'off';
          const selected=await choose(ask,[{id:'off',label:'Off: acknowledge control when approving scope'},{id:'dns',label:'Require DNS TXT verification'},{id:'http',label:'Require an HTTPS verification file'}],`Domain verification: ${current}. Changing it clears testing permission.`);
          if(selected)await run('config set',['ownershipVerification',selected.id]);
        }
        else if(choice==='1'){const result=await onboard({project:root,flow:'quickstart'},[],{...prompt,inDashboard:true});root=result.root;queuedStart=result.startReview;}
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
          const mode=starting?.mode||read(root).settings.reviewMode||(ready?'combined':'code');
          console.log('\n'+reviewSummary(readiness(root).review));
          console.log(`\nRunning your ${read(root).settings.analysisEngine==='docker'?'security audit':'security review preview'}${mode==='code'?' (code only)':mode==='live'?' (app only)':''}…`);
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
  const mode=await choose(ask,[{id:'docker',label:'Security audit · isolated source review + scoped live runner'},{id:'mock',label:'Offline preview · simulated discovery · no model usage'}],'Analysis engine');
  if(!mode)return;
  await run('engine use',[mode.id]);if(mode.id==='mock')return;
  await run('engine doctor');
  let state=read(root);
  if(!state.activeModel){console.log('Choose the shared model in /models before reviewing.');return;}
  const profile=state.models.find(m=>m.name===state.activeModel);
  console.log(`Source review and live planning use ${profile.name} / ${profile.model}. Selected source excerpts go to ${profile.dataDestination}; the live runner independently controls every request and proof.`);
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
