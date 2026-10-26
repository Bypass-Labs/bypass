import readline from 'node:readline/promises';
import path from 'node:path';
import { read, rootFrom } from './store.mjs';
import { execute, readiness } from './service.mjs';
import { parse, help } from './catalog.mjs';
import { cleanText, redact, Fault } from './util.mjs';
import { onboard } from './onboarding.mjs';

const color=!!process.stdout.isTTY&&!process.env.NO_COLOR;
const paint=(n,s)=>color?`\x1b[${n}m${s}\x1b[0m`:s;
const accent=s=>paint('38;5;150',s),muted=s=>paint('90',s),bold=s=>paint('1',s);
const label=s=>String(s).replace(/_/g,' ');
export function printResult(data){
  if(!data)return;
  const value=redact(data);
  if(value.error){console.error(paint('31',value.error));if(value.details&&Object.keys(value.details).length)console.error(JSON.stringify(value.details,null,2));return;}
  if(value.plan){
    const p=value.plan;
    console.log(`\n${bold('Review plan')} · ${p.mode==='code'?'code only':p.mode}\n`);
    console.log(`  App           ${p.mode==='code'?'no live requests':p.target||'not connected'}\n  Saved checks  ${p.savedChecks}${p.mode==='code'?' · replay requires an authorized app':' · replay first'}\n  Source        stays on this machine\n  Analysis      simulated · no model calls\n  Evidence      saved locally`);
    if(p.blockers.length)console.log(`\n${paint('33','Setup needed:')}\n${p.blockers.map(x=>'  '+x).join('\n')}`);
    else console.log('\nReady for a walkthrough review. Simulated results are not a security verdict.');
    return;
  }
  if(value.run){
    const r=value.run;console.log(`\n${bold(r.id)}  ${label(r.kind)} · ${r.status}`);
    for(const step of r.steps||[])console.log(`  ${muted('›')} ${step.message}`);
    if(r.result?.message)console.log(`\n${r.result.message}`);
    for(const result of r.result?.results||r.result?.regression||[])console.log(`  ${result.status==='passed'?accent('✓'):paint('33','!')} ${result.id}  ${result.status} — ${result.reason}`);
    if(r.result?.findings?.length)console.log(`\nFindings: ${r.result.findings.join(', ')}\nNext: bypass finding show ${r.result.findings[0]}`);
    console.log(muted(`Exit ${value.exitCode} · model calls ${r.result?.modelCalls??0} · evidence stored locally`));return;
  }
  if(value.target?.challenge){const t=value.target;console.log(`\n${bold(t.name)} · ${t.url}\nOwnership: ${t.ownership?.status||'pending'}\n`);if(t.environment==='local')console.log(`Next: bypass target verify ${t.name} --method local`);else console.log(`Publish TXT record:\n  Name:  ${t.challenge.record}\n  Value: ${t.challenge.token}\n\nOr serve exactly that value at:\n  ${t.url}${t.challenge.httpPath}\n\nThen: bypass target verify ${t.name} --method dns`);if(t.authorization)console.log(`Scope: ${t.authorization.paths.join(', ')} · expires ${t.authorization.expiresAt}`);return;}
  if(value.findings){console.log(`\n${value.findings.length} findings`);for(const f of value.findings)console.log(`  ${bold(f.id)}  ${f.title}\n    ${label(f.status)} · ${f.fixture?'local fixture':f.simulation?'SIMULATED · unproven':'evidence available'}`);return;}
  if(value.checks&&Array.isArray(value.checks)){console.log(`\n${value.checks.length} saved checks`);for(const c of value.checks)console.log(`  ${bold(c.id)}  ${c.title||c.behavior}\n    ${c.status||c.lastResult?.status||'not run'} · ${c.enabled===false?'disabled':c.target}`);if(value.message)console.log(value.message);return;}
  if(value.finding){const f=value.finding;console.log(`\n${bold(f.title)}\n${f.id} · ${label(f.status)}\n\n${f.hypothesis}\n\n${f.sourceEvidence?.message||''}\n\nFix: ${f.recommendation}\n\nNext: bypass ${f.status==='confirmed_fixture'?'retest':'verify'} ${f.id}`);if(f.verification)console.log(JSON.stringify(f.verification,null,2));return;}
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
  const rl=readline.createInterface({input:process.stdin,output:process.stdout});
  const controller=new AbortController();
  rl.once('SIGINT',()=>{controller.abort();rl.close();});
  rl.once('close',()=>controller.abort());
  const ask=async(text,defaultValue='')=>{try{const result=await rl.question(`${text}${defaultValue?muted(` [${defaultValue}]`):''}: `,{signal:controller.signal});return result.trim()||defaultValue;}catch(e){if(e.name==='AbortError')throw new Fault('Setup stopped. Saved choices are retained.',130);throw e;}};
  return {ask,close:()=>rl.close()};
}
async function choose(ask,items,title){console.log(`\n${bold(title)}`);items.forEach((x,i)=>console.log(`  ${i+1}  ${x.label||x.name||x.id}`));const choice=await ask('Choose','1');return items[Number(choice)-1]||null;}

export async function initWizard(options={},args=[]){
  const prompt=createPrompt();
  try{return await onboard(options,args,{ask:prompt.ask});}finally{prompt.close();}
}
async function modelWizard(ask,root){
  const choice=await choose(ask,[{label:'Muse Code subscription',provider:'muse-code'},{label:'Local model · inference on this machine',provider:'local'},{label:'Your self-hosted compatible endpoint',provider:'endpoint'}],'Where should model inference run?');if(!choice)return;
  const name=await ask('Profile name',choice.provider==='muse-code'?'muse':choice.provider==='local'?'local':'selfhosted');
  const options={project:root,provider:choice.provider};
  if(choice.provider!=='muse-code'){options['base-url']=await ask('Base URL',choice.provider==='local'?'http://127.0.0.1:1234/v1':'');options.model=await ask('Model ID');const env=await ask('Credential environment variable (leave blank if none)');if(env)options['secret-env']=env;}
  printResult(await execute('model add',[name],options));
  if((await ask('Run a synthetic connection test now? (y/n)','n')).toLowerCase()==='y')printResult(await execute('model test',[name],{project:root}));
}
async function targetWizard(ask,root){
  const name=await ask('Target name','staging');const url=await ask('App origin URL');const environment=await ask('Environment: local / preview / staging / production',url.includes('localhost')||url.includes('127.0.0.1')?'local':'staging');
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
  const next=!info.model?'Setup → choose a model':!info.ready.liveTesting?(info.target?'Setup → finish app verification, or Run a review in code-only mode':'Run a review (code only), or Setup → connect an app'):!info.findings.total?'Run a review':!info.checks.enabled?'Findings → verify, fix, and retest':'Saved tests → replay your regressions';
  console.log(`  Next: ${accent(next)}\n`);
}
export async function terminal(options={}){
  let root=options.project?path.resolve(options.project):process.cwd();
  try{root=rootFrom(root);}catch{const result=await initWizard(options);if(!result.openDashboard)return;root=result.root;}
  const {ask,close}=createPrompt();
  const run=async(key,args=[],flags={})=>{const result=await execute(key,args,{project:root,...flags});printResult(result);return result;};
  try{
    while(true){
      dashboard(root);
      console.log('  1  Setup / resume onboarding      6  Saved tests\n  2  Targets & identities            7 Monitoring\n  3  Models & privacy                8  Session context\n  4  Run a review                    9  Demo controls\n  5  Findings                        0  Exit\n');
      console.log(muted('You can also type any Bypass command here. Type help for the command reference.'));
      const choice=await ask('bypass');if(['0','q','quit','exit'].includes(choice))break;
      try{
        if(choice==='1'){const result=await onboard({project:root},[],{ask,inDashboard:true});root=result.root;}
        else if(choice==='2'){
          const state=read(root);const action=await choose(ask,[{label:'Add a target',id:'add'},{label:'Show targets / ownership challenges',id:'show'},{label:'Verify ownership',id:'verify'},{label:'Authorize testing scope',id:'authorize'},{label:'Select active target',id:'use'},{label:'Add test identity',id:'identity'},{label:'Test identity connection',id:'identity-test'},{label:'Revoke testing',id:'revoke'}],'Targets & identities');
          if(action?.id==='add')await targetWizard(ask,root);
          else if(action?.id==='identity'){const name=await ask('Identity name');const type=await ask('Type: bearer / cookie / header','bearer');const secret=await ask('Environment variable containing the secret');const check=await ask('Identity-check endpoint path','/api/me');const header=type==='header'?await ask('Header name'):undefined;await run('identity add',[name],{target:state.activeTarget,type,'secret-env':secret,'check-path':check,header});}
          else if(action?.id==='identity-test'){const identity=await choose(ask,state.identities,'Identity');if(identity)await run('identity test',[identity.name]);}
          else if(action){const t=await choose(ask,state.targets,'Target');if(t){if(action.id==='authorize')await authorizeWizard(ask,root,t.name);else await run(`target ${action.id}`,[t.name],action.id==='verify'?{method:await ask('Verification method',t.environment==='local'?'local':'dns')}:{});}}
        }
        else if(choice==='3'){
          const action=await choose(ask,[{label:'Add model profile',id:'add'},{label:'Choose active model',id:'use'},{label:'Test connection with synthetic prompt',id:'test'},{label:'Show profiles and privacy',id:'list'}],'Models');
          if(action?.id==='add')await modelWizard(ask,root);else if(action?.id==='list')await run('model list');else if(action){const model=await choose(ask,read(root).models,'Profile');if(model)await run(`model ${action.id}`,[model.name]);}
        }
        else if(choice==='4'){
          const ready=readiness(root).ready.liveTesting;
          const mode=await ask('Review mode: combined / code / live',ready?'combined':'code');const planned=await run('scan',[],{mode,plan:true});if(planned.exitCode===0&&(await ask('Run this plan? (y/n)','y')).toLowerCase()==='y')await run('scan',[],{mode});
        }
        else if(choice==='5'){
          const finding=await choose(ask,read(root).findings.map(f=>({...f,label:`${f.title} · ${label(f.status)} · ${f.id}`})),'Findings');
          if(finding){await run('finding show',[finding.id]);const action=await ask('Action: verify / retest / back','back');if(['verify','retest'].includes(action))await run(action,[finding.id]);}
        }
        else if(choice==='6'){
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
        else if(choice==='help')console.log(help());
        else if(choice){const tokens=tokenize(choice);if(tokens[0]==='bypass')tokens.shift();const parsed=parse(tokens);if(parsed.options.help)console.log(help(parsed.key));else await run(parsed.key,parsed.args,parsed.options);}
      }catch(e){console.log(`\n${paint('31','!')} ${cleanText(e.message)}`);if(e.details?.challenge)console.log(JSON.stringify(e.details.challenge,null,2));}
      await ask('\nPress Enter to return');
    }
  }finally{close();}
  console.log(muted('\nProject state saved. Continue from this directory with bypass.\n'));
}
