import readline from 'node:readline/promises';
import path from 'node:path';
import { read, rootFrom } from './store.mjs';
import { execute, readiness } from './service.mjs';
import { parse, help } from './catalog.mjs';
import { cleanText, redact, Fault, abortFault } from './util.mjs';
import { onboard } from './onboarding.mjs';
import { checkModelConnection } from './model-check.mjs';
import { guidedDemo } from './guided-demo.mjs';
import { homeActions, previewRun, quickCommands, reviewSummary } from './experience.mjs';
import { appOriginInput } from './network.mjs';
import { isBypassSource } from './project-selection.mjs';
import { createTerminalSession } from './terminal-session.mjs';

const color=!!process.stdout.isTTY&&!process.env.NO_COLOR;
const paint=(n,s)=>color?`\x1b[${n}m${s}\x1b[0m`:s;
const accent=s=>paint('38;5;150',s),muted=s=>paint('90',s),bold=s=>paint('1',s);
const label=s=>String(s).replace(/_/g,' ');
export function printResult(data){
  if(!data)return;
  const value=redact(data);
  if(value.error){console.error(paint('31',value.error));if(value.details&&Object.keys(value.details).length)console.error(JSON.stringify(value.details,null,2));return;}
  if(value.models){console.log('\nModel connections');for(const m of value.models)console.log(`  ${m.name===value.active?'●':'○'} ${m.name} · ${m.provider} · ${m.lastAttempt?.status||m.lastTest?.status||'not tested'}\n    ${m.dataDestination}`);return;}
  if(value.targets){console.log('\nConnected apps');for(const t of value.targets)console.log(`  ${t.name===value.active?'●':'○'} ${t.name} · ${t.url}\n    ${t.environment} · ownership ${t.ownership?.status||'pending'}`);if(!value.targets.length)console.log('  No app yet. Use /app to connect one.');return;}
  if(value.project&&value.review){console.log('\n'+reviewSummary(value.review));console.log(`Model: ${value.model?.name||'not configured'} · ${value.model?.connection||'optional for the preview'}\nSaved tests: ${value.checks.enabled} · passed ${value.checks.passed} · failed ${value.checks.failed}\nNext: ${value.next}`);return;}
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
    const incomplete=r.result?.details?.stage||r.result?.details?.reason==='model_timeout';
    console.log(`\n${bold(incomplete?'Review incomplete':r.id)}  ${label(r.kind)} · ${incomplete?'stopped':r.status}`);
    if(r.result?.message)console.log(`\n${r.result.message}`);
    for(const result of r.result?.results||r.result?.regression||[])console.log(`  ${result.status==='passed'?accent('✓'):paint('33','!')} ${result.id}  ${result.status} — ${result.reason}`);
    if(r.result?.findings?.length)console.log(`\nFindings: ${r.result.findings.join(', ')}\nNext: bypass finding show ${r.result.findings[0]}`);
    if(incomplete)console.log(`\nStopped at: ${r.result.details.stage||'model response'}\nSetup and partial evidence are saved. No complete security result is available.\nNext inside Bypass: model test\nIf that fails, use /models to choose another connection. After it passes, /review retries.\nEvidence: .bypass/runs/${r.id}.json`);
    console.log(muted(`Exit ${value.exitCode} · model calls ${r.result?.modelCalls??0} · evidence stored locally`));return;
  }
  if(value.target?.challenge){const t=value.target;console.log(`\n${bold(t.name)} · ${t.url}\nOwnership: ${t.ownership?.status||'pending'}\n`);if(t.environment==='local')console.log(`Next: bypass target verify ${t.name} --method local`);else console.log(`Publish TXT record:\n  Name:  ${t.challenge.record}\n  Value: ${t.challenge.token}\n\nOr serve exactly that value at:\n  ${t.url}${t.challenge.httpPath}\n\nThen: bypass target verify ${t.name} --method dns`);if(t.authorization)console.log(`Scope: ${t.authorization.paths.join(', ')} · expires ${t.authorization.expiresAt}`);return;}
  if(value.findings){console.log(`\n${value.findings.length} findings`);for(const f of value.findings)console.log(`  ${bold(f.id)}  ${f.title}\n    ${label(f.status)} · ${f.fixture?'local fixture':f.simulation?'SIMULATED · unproven':'evidence available'}`);return;}
  if(value.checks&&Array.isArray(value.checks)){console.log(`\n${value.checks.length} saved checks`);for(const c of value.checks)console.log(`  ${bold(c.id)}  ${c.title||c.behavior}\n    ${c.status||c.lastResult?.status||'not run'} · ${c.enabled===false?'disabled':c.target}`);if(value.message)console.log(value.message);return;}
  if(value.finding){const f=value.finding;const next=f.fixture||f.engine==='docker'?`bypass ${['confirmed_fixture','confirmed','regression_failed'].includes(f.status)?'retest':'verify'} ${f.id}`:'bypass demo — complete the proof loop in a separate local app';console.log(`\n${bold(f.title)}\n${f.id} · ${label(f.status)}\n\n${f.hypothesis}\n\n${f.sourceEvidence?.file?`${f.sourceEvidence.file}:${f.sourceEvidence.line}\n${f.sourceEvidence.quote}`:f.sourceEvidence?.message||''}\n\nFix: ${f.recommendation}\n\nNext: ${next}`);if(f.verification)console.log(JSON.stringify(f.verification,null,2));return;}
  if(value.installed&&value.next){console.log(`\n${value.message}\n${value.next}`);return;}
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
  try{if(prompt?.rich)updateWorkspace(prompt,root);const result=await checkModelConnection(root,name,prompt||{write:message=>console.error(message)});if(prompt?.rich)await prompt.ask('Enter to finish');return result;}finally{prompt?.close();}
}
function updateWorkspace(prompt,root){
  if(!prompt.setContext)return;
  const info=readiness(root);
  prompt.setContext({engine:info.engine.mode,title:info.project.name,repo:root,branch:info.project.repository.branch,app:info.target?`${info.target.url} · ${info.target.authorized?'authorized':info.target.ownership==='verified'?'scope required':'DNS pending'}`:'not connected · code preview available',model:info.model?`${info.model.name} · ${info.model.provider} · ${info.model.connection}`:'not configured · optional for this preview'});
}
async function modelWizard(ask,root,io){
  const choice=await choose(ask,[{label:'Muse Code subscription',provider:'muse-code'},{label:'Local model · inference on this machine',provider:'local'},{label:'Your self-hosted compatible endpoint',provider:'endpoint'}],'Where should model inference run?');if(!choice)return;
  const name=await ask('Profile name',choice.provider==='muse-code'?'muse':choice.provider==='local'?'local':'selfhosted');
  const options={project:root,provider:choice.provider};
  if(choice.provider!=='muse-code'){options['base-url']=await ask('Base URL',choice.provider==='local'?'http://127.0.0.1:1234/v1':'');options.model=await ask('Model ID');const env=await ask('Credential environment variable (leave blank if none)');if(env)options['secret-env']=env;}
  printResult(await execute('model add',[name],options));
  if((await ask('Check the model connection now? (y/n)','n')).toLowerCase()==='y')await checkModelConnection(root,name,io);
}
async function targetWizard(ask,root){
  const name=await ask('Target name','staging');const url=appOriginInput(await ask('App domain or URL'));const environment=await ask('Environment: local / preview / staging / production',url.includes('localhost')||url.includes('127.0.0.1')||url.includes('[::1]')?'local':'staging');
  printResult(await execute('target add',[name],{project:root,url,environment}));
  if(environment==='local'){await execute('target verify',[name],{project:root,method:'local'});await authorizeWizard(ask,root,name);}
  else console.log('\nPublish the ownership challenge, then choose Targets → Verify. Code-only review can continue while DNS propagates.');
}
async function authorizeWizard(ask,root,name){
  const target=read(root).targets.find(t=>t.name===name);console.log(`\nAuthorize testing on ${target?.url} only. This expires in seven days.`);
  const paths=await ask('Allowed path prefixes, comma-separated','/api');
  const accepted=await ask('Do you authorize read-only testing of these paths? (yes/no)','no');if(accepted!=='yes')return;
  let production=false;if(target?.environment==='production')production=(await ask('Type production to authorize the production environment'))==='production';
  printResult(await execute('target authorize',[name],{project:root,paths,accept:true,production}));
}
function dashboard(root){
  console.log(`\n${accent('━'.repeat(Math.min(76,process.stdout.columns||76)))}\n${bold('BYPASS')}  /  security checks that stay with your code\n`);
  let info;try{info=readiness(root);}catch{console.log('No project connected. Choose Setup or Demo to begin.');return;}
  console.log(`${bold(info.project.name)}\n${muted(root)}\n`);
  console.log(`  REPOSITORY   ${info.project.repository.kind==='git'?'Git connected':'Directory connected'}`);
  console.log(`  LIVE APP     ${info.target?`${info.target.url} · ${info.target.authorized?'authorized':info.target.ownership}`:'not connected'}`);
  console.log(`  MODEL        ${info.model?`${info.model.name} · ${info.model.provider} · ${info.model.connection}`:'choose a provider'}`);
  console.log(`  EVIDENCE     local · ${info.findings.total} findings · ${info.checks.enabled} saved tests`);
  console.log(`  MONITOR      ${info.worker.status} · ${info.monitors} schedules`);
  console.log(`\n${paint('33','  MOCK ANALYSIS')}  ${muted('Real onboarding, HTTP fixture proof, tests, and scheduler.')}`);
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
    let lastStage=-1;
    const real=read(root).settings.analysisEngine==='docker';
    const stages=real?['replay','containers','orchestrator','white-box','black-box']:['replay','inventory','mock-analysis'];
    if(key==='scan')prompt.setTasks?.(real?'Real AI review':'Review preview',real?['Saved checks','Docker services','Shared-model plan','White-box source review','Black-box HTTP proof']:['Saved checks / scope','Local source inventory','Simulated discovery']);
    const work=async signal=>{
      const result=await execute(key,args,{project:root,...flags},{signal,onProgress:step=>{
        prompt.write?.(step.message);
        if(key==='scan'){if(lastStage>=0)prompt.task?.(lastStage,'done');lastStage=stages.indexOf(step.stage);prompt.task?.(lastStage,'running');}
      }});
      if(result.exitCode===130)throw new Fault('Run stopped. Partial evidence is saved.',130,{cancelled:true});
      if(key==='scan'&&lastStage>=0)prompt.task?.(lastStage,previewRun(result.run)?'done':'attention');
      return result;
    };
    const result=prompt.activity?await prompt.activity(key==='scan'?(real?'Review repository · real Docker agents':'Review repository · simulated discovery'):key==='test run'?'Replay saved checks · no model':key,work,{verdict:r=>r.exitCode&&!(previewRun(r.run)&&r.exitCode===3)?'attention':'done'}):await work(prompt.signal);
    printResult(result);return result;
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
        console.log(`Model: ${info.model?.connection||'not configured; mock preview needs no model'} · ${info.findings.total} review result(s)`);
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
          prompt.setNext?.(info.target.authorized?'This app is authorized. Return with Esc to continue your review.':ownershipValid?'Authorize the allowed testing paths':'Publish the TXT record, then choose Check the DNS TXT record');
          const action=await choose(ask,[...(!info.target.authorized?[{id:ownershipValid?'authorize':'verify',label:ownershipValid?'Set the allowed testing scope':`Check ${target.environment==='local'?'local ownership':'the DNS TXT record'}`}]:[]),{id:'add',label:'Connect another app'},{id:'advanced',label:'All app settings & test accounts'}],'App connection');
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
          else if(action?.id==='identity'){const name=await ask('Identity name');const type=await ask('Type: bearer / cookie / header','bearer');const secret=await ask('Environment variable containing the secret');const check=await ask('Identity-check endpoint path','/api/me');const header=type==='header'?await ask('Header name'):undefined;await run('identity add',[name],{target:state.activeTarget,type,'secret-env':secret,'check-path':check,header});}
          else if(action?.id==='identity-test'){const identity=await choose(ask,state.identities,'Identity');if(identity)await run('identity test',[identity.name]);}
          else if(action){const t=await choose(ask,state.targets,'Target');if(t){if(action.id==='authorize')await authorizeWizard(ask,root,t.name);else await run(`target ${action.id}`,[t.name],action.id==='verify'?{method:await ask('Verification method',t.environment==='local'?'local':'dns')}:{});}}
        }
        else if(choice==='3'){
          const action=await choose(ask,[{label:'Add model profile',id:'add'},{label:'Choose active model',id:'use'},{label:'Test connection with synthetic prompt',id:'test'},{label:'Show profiles and privacy',id:'list'}],'Models');
          if(action?.id==='add')await modelWizard(ask,root,prompt);else if(action?.id==='list')await run('model list');else if(action){const model=await choose(ask,read(root).models,'Profile');if(model)await run(`model ${action.id}`,[model.name]);}
        }
        else if(choice==='4'){
          const ready=readiness(root).ready.liveReview;
          const mode=ready?'combined':'code';
          console.log('\n'+reviewSummary(readiness(root).review));
          console.log(`\nRunning your ${read(root).settings.analysisEngine==='docker'?'real AI review':'review preview'}${ready?'':' (code only; app verification can wait)'}…`);
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
          if(action?.id==='add')await run('monitor add',[await ask('Monitor name','security')],{every:await ask('Interval','1h'),runner:'local'});
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
  if(!target||!readiness(root).ready.liveTesting){console.log('Source review is ready. Use /app to finish ownership and scope before HTTP proof.');return;}
  if(target.probes?.length){console.log(`${target.probes.length} authorized resource(s) configured. Use /review to begin.`);return;}
  console.log('For real account-boundary proof, use two different test accounts and one resource belonging to the owner. Supply environment variable NAMES, never token values.');
  const identities=[];
  for(const role of ['owner','outsider']){
    state=read(root);
    const available=state.identities.filter(i=>i.target===target.name&&!identities.includes(i.name));
    const selected=await choose(ask,[...available.map(i=>({id:i.name,label:`Use ${i.name} (${i.secretEnv})`})),{id:'__new',label:`Add ${role} account`}],`${role} identity`);
    if(!selected)return;
    if(selected.id!=='__new'){identities.push(selected.id);continue;}
    const name=await ask('Account reference name',role);
    const type=await ask('Credential type: bearer / cookie / header','bearer');
    const secret=await ask('Credential environment variable',`BYPASS_${role.toUpperCase()}_TOKEN`);
    const check=await ask('Signed-in identity endpoint','/api/me');
    const header=type==='header'?await ask('Header name'):undefined;
    await run('identity add',[name],{target:target.name,type,'secret-env':secret,'check-path':check,header});identities.push(name);
  }
  const resourcePath=await ask('Exact path to an owner-owned JSON resource (GET)');
  const resourceId=await ask('Expected resource identifier');
  const idField=await ask('JSON field identifying the resource','id');
  const identityField=await ask('JSON field identifying the account at the identity endpoint','id');
  await run('probe add',['primary'],{target:target.name,path:resourcePath,'resource-id':resourceId,owner:identities[0],outsider:identities[1],'id-field':idField,'identity-field':identityField});
  console.log('Ready. Use /review for source analysis and real HTTP proof. Fix confirmed issues in your editor, then use /results → Retest a fix.');
}
