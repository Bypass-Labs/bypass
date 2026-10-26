import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawn } from 'node:child_process';
import { rootFrom, read, change, initStore, snapshot, atomic, event } from './store.mjs';
import { need, named, safeName, envName, now, duration, outcome, execFile, Fault, redact } from './util.mjs';
import { connectRepository, repositoryInfo, inventory } from './repository.mjs';
import { targetURL, makeChallenge, verifyOwnership, authorization, scopeReady, safeRequest } from './network.mjs';
import { modelProfile, testModel } from './models.mjs';
import { scanPlan, executeRun, verifyFinding } from './engine.mjs';
import { saveCheck, bindCheck, exportChecks } from './checks.mjs';
import { dispatchRun, watchRun, startWorker, workerStatus, runMonitor } from './jobs.mjs';
import { startDemo, updateDemo, serveDemo, demoConfig, CLI } from './demo.mjs';

export const PACKAGE_ROOT=path.resolve(path.dirname(fileURLToPath(import.meta.url)),'..');
function loadJSON(file){try{return JSON.parse(fs.readFileSync(path.resolve(file),'utf8'));}catch{throw new Fault(`Cannot parse JSON file: ${file}`);}}
function filter(list,options,keys){return list.filter(item=>keys.every(k=>!options[k]||item[k]===options[k]));}
const wrap=value=>value?.schemaVersion==='bypass.v1'?value:outcome(value);
export function readiness(root){
  const s=read(root),target=s.targets.find(t=>t.name===s.activeTarget),model=s.models.find(m=>m.name===s.activeModel);
  let liveReady=false;try{scopeReady(target||{});liveReady=true;}catch{}
  return {project:s.project,root,engine:{mode:'mock',analysisImplemented:false,label:'MOCK analysis · real setup and saved-test replay'},
    model:model?{name:model.name,provider:model.provider,destination:model.dataDestination,connection:model.lastAttempt?.status||model.lastTest?.status||'not tested'}:null,
    target:target?{name:target.name,url:target.url,environment:target.environment,ownership:target.ownership?.status||'pending',authorized:liveReady}:null,
    ready:{repository:true,model:!!model,target:!!target,liveTesting:liveReady},
    findings:{total:s.findings.length,fixtureConfirmed:s.findings.filter(f=>f.status==='confirmed_fixture').length,simulated:s.findings.filter(f=>f.status==='simulated_unproven').length,fixed:s.findings.filter(f=>f.status==='fixed_verified').length},
    checks:{total:s.checks.length,enabled:s.checks.filter(c=>c.enabled).length,passed:s.checks.filter(c=>c.lastResult?.status==='passed').length,failed:s.checks.filter(c=>c.lastResult?.status==='failed').length},
    worker:workerStatus(root),monitors:s.monitors.length,latestRun:s.runs.at(-1)||null,
    privacy:{evidence:'local',sourceUpload:false,analysisInference:'not invoked (mock engine)',secretStorage:'environment variable references; public fixture credentials only in demo'},
    next:!model?'model add':!target?'target add':!liveReady?'target verify / target authorize':!s.findings.length?'scan':!s.checks.length?'finding show → verify → fix → retest':'test run --all',
    limitations:['White-box and black-box engines are simulated.','Hosted Bypass account, cloud scheduler, and deployment attestation are not connected.','No passing result implies complete security coverage.']};
}

export async function execute(key,args=[],o={},context={}){
  const working=path.resolve(o.project||context.cwd||process.cwd());
  if(key==='init'||key==='repo connect'){
    const config=o.config?loadJSON(o.config):null;
    const {root,repository}=await connectRepository(o.repo||args[0]||config?.repo||working,o.dir||config?.dir);
    const {resumed}=initStore(root,repository,o.name||config?.name);
    if(config){
      if(config.model&&!read(root).models.some(m=>m.name===config.model.name))await execute('model add',[config.model.name],{...config.model,project:root},context);
      if(config.target&&!read(root).targets.some(t=>t.name===config.target.name))await execute('target add',[config.target.name],{...config.target,project:root},context);
    }
    return outcome({root,resumed,message:resumed?'Existing project resumed; settings and evidence retained.':'Repository connected. No source code was executed.',readiness:readiness(root)});
  }
  if(key==='demo start')return outcome(await startDemo(o.dir||path.join(PACKAGE_ROOT,'.demo/ledger'),{port:o.port||4317}));
  if(key==='auth login'){
    if(o.device)throw new Fault('A hosted Bypass identity service is not configured. Local mode needs no Bypass account. Use --provider muse-code for the official Muse login.',3,{implemented:false});
    if(o.provider==='muse-code'){
      need(!o.json&&!o['non-interactive'],'Muse login is interactive. Run muse login in your terminal.',3);
      const code=await new Promise((resolve,reject)=>{const p=spawn('muse',['login'],{stdio:'inherit',env:{...process.env,MUSE_NO_AUTO_UPDATE:'1'},cwd:working});p.on('error',reject);p.on('close',resolve);});
      return outcome({provider:'muse-code',message:'Official Muse login completed. Bypass does not read or store Muse credentials.'},code===0?0:3);
    }
    need(!o.provider||o.provider==='local','Supported account modes: local or muse-code.');
    return outcome({mode:'local',accountRequired:false,message:'Local mode is ready. No Bypass account or cloud upload is required.'});
  }
  if(key==='mcp serve'){const {serveMCP}=await import('./mcp.mjs');await serveMCP(working);return null;}
  if(key==='integrate muse'||key==='integrate status'||key==='integrate remove')return integrate(key,args,o,working);
  const root=rootFrom(working);const s=read(root);const targetName=o.target||s.activeTarget;
  let result;
  switch(key){
    case 'status':result=readiness(root);break;
    case 'repo show':result={repository:await repositoryInfo(root)};break;
    case 'doctor':{
      const checks=[{name:'Node >=22',ok:Number(process.versions.node.split('.')[0])>=22,version:process.version}];
      for(const binary of ['git','muse']){try{const r=await execFile(binary,['--version']);checks.push({name:binary,ok:r.code===0,version:r.stdout});}catch(e){checks.push({name:binary,ok:false,message:e.message,optional:binary==='muse'});}}
      result={checks,readiness:readiness(root),message:'Doctor checks configuration and executables. It does not prove model access or app security.'};break;
    }
    case 'config show':result=snapshot(s);break;
    case 'config set':result=await change(root,state=>{
      const [key,value]=args;
      if(key==='autoSave'){need(['true','false'].includes(value),'autoSave must be true or false.');state.settings.autoSave=value==='true';}
      else if(key==='requestTimeoutMs'){need(Number(value)>=1000&&Number(value)<=60000,'requestTimeoutMs must be between 1000 and 60000.');state.settings.requestTimeoutMs=Number(value);}
      else if(key==='project.name'){need(value.length<=100,'Project name is too long.');state.project.name=value;}
      else throw new Fault('Supported settings: autoSave, requestTimeoutMs, project.name. Use target/model commands for their settings.');
      return {key,value};});break;
    case 'auth status':result={mode:'local',accountRequired:false,muse:'Uses official Muse account when the muse-code provider is selected. Credentials are never extracted.',cloud:'not configured'};break;
    case 'auth logout':result=await change(root,state=>{state.auth=null;return {message:'Bypass-local account metadata cleared. Use muse logout to sign out of Muse itself.'};});break;
    case 'target add':{
      safeName(args[0]);need(o.url,'--url is required.');const environment=o.environment||'staging',url=targetURL(o.url,environment);
      result=await change(root,state=>{need(!state.targets.some(t=>t.name===args[0]),'A target with this name already exists.');const t={name:args[0],url,environment,createdAt:now(),ownership:{status:'pending'},authorization:null};t.challenge=makeChallenge(state.project,t);state.targets.push(t);state.activeTarget??=t.name;return {target:t,next:`bypass target verify ${t.name} --method ${environment==='local'?'local':'dns'}`};});break;
    }
    case 'target list':result={targets:s.targets,active:s.activeTarget};break;
    case 'target show':result={target:named(s.targets,args[0]||s.activeTarget,'Target')};break;
    case 'target use':result=await change(root,state=>{state.activeTarget=named(state.targets,args[0],'Target').name;return {activeTarget:state.activeTarget};});break;
    case 'target verify':{
      const name=args[0]||s.activeTarget;let t=named(s.targets,name,'Target');
      if(o.renew){result=await change(root,state=>{const target=named(state.targets,name,'Target');target.challenge=makeChallenge(state.project,target);target.ownership={status:'pending'};target.authorization=null;return {target,message:'New ownership challenge issued; previous authorization invalidated.'};});break;}
      const ownership=await verifyOwnership(t,o.method||(t.environment==='local'?'local':'dns'),{wait:o.wait,signal:context.signal});
      result=await change(root,state=>{const target=named(state.targets,name,'Target');need(target.challenge.id===t.challenge.id,'Challenge changed during verification; retry.',3);target.ownership=ownership;event(state,'ownership',`${name}: ownership verified`);return {target,next:`bypass target authorize ${name}`};});break;
    }
    case 'target authorize':{
      const name=args[0]||s.activeTarget;
      need(o['scope-file']||o.accept,'Review scope, then provide --scope-file or --accept --paths /api. Ownership alone is not authorization.');
      const scope=context.scope||(o['scope-file']?loadJSON(o['scope-file']):{paths:(o.paths||'/api').split(','),productionAcknowledged:!!o.production});
      result=await change(root,state=>{const t=named(state.targets,name,'Target');t.authorization=authorization(t,scope);event(state,'authorized',`${name}: testing authorized`,{scope:t.authorization});return {target:t.name,authorization:t.authorization};});break;
    }
    case 'target revoke':case 'target remove':result=await change(root,state=>{
      const t=named(state.targets,args[0],'Target');t.authorization=null;t.ownership={status:'revoked'};
      state.monitors.filter(m=>m.target===t.name).forEach(m=>m.enabled=false);
      state.runs.filter(r=>r.options.target===t.name&&['queued','running'].includes(r.status)).forEach(r=>r.cancelRequested=true);
      if(key==='target remove'){state.targets=state.targets.filter(x=>x.name!==t.name);if(state.activeTarget===t.name)state.activeTarget=state.targets[0]?.name||null;}
      event(state,'revoked',`${t.name}: authorization revoked`);return {target:t.name,message:'Testing revoked; monitors paused; historical evidence retained.'};});break;
    case 'identity add':{
      safeName(args[0]);need(o['secret-env'],'--secret-env is required. Bypass stores a reference, never the credential.');envName(o['secret-env']);need(['bearer','cookie','header'].includes(o.type),'--type must be bearer, cookie, or header.');
      if(o.type==='header')need(/^[A-Za-z][A-Za-z0-9-]*$/.test(o.header||'')&&!['host','connection','content-length','transfer-encoding'].includes(o.header.toLowerCase()),'Supply a safe custom --header name.');
      const checkPath=o['check-path']||null;if(checkPath)need(checkPath.startsWith('/')&&!/[?#\\]/.test(checkPath),'Identity check path must be a path without query strings.');
      result=await change(root,state=>{named(state.targets,targetName,'Target');need(!state.identities.some(i=>i.name===args[0]),'Identity name already exists.');const identity={name:args[0],target:targetName,type:o.type,secretEnv:o['secret-env'],header:o.header||null,checkPath,createdAt:now()};state.identities.push(identity);return {identity};});break;
    }
    case 'identity list':result={identities:filter(s.identities,o,['target']).map(({fixtureValue,...x})=>x)};break;
    case 'identity test':{
      const identity=named(s.identities,args[0],'Identity'),target=named(s.targets,identity.target,'Target');need(identity.checkPath,'Configure --check-path before testing this identity.');scopeReady(target,identity.checkPath);
      const secret=process.env[identity.secretEnv]||(s.demo?.target===identity.target?identity.fixtureValue:null);need(secret,`Set ${identity.secretEnv} before testing.`,3);
      const headers=identity.type==='bearer'?{Authorization:`Bearer ${secret}`}:identity.type==='cookie'?{Cookie:secret}:{[identity.header]:secret};
      const response=await safeRequest(target.url+identity.checkPath,{headers,allowLocal:target.environment==='local',timeout:s.settings.requestTimeoutMs});
      const check={httpStatus:response.status,status:response.status>=200&&response.status<300?'accepted':'blocked',checkedAt:now(),bodyStored:false,message:'Endpoint accepted the request; account role is not automatically attested.'};
      await change(root,state=>{named(state.identities,args[0],'Identity').lastTest=check;});return outcome({identity:args[0],check},check.status==='accepted'?0:3);
    }
    case 'identity update':result=await change(root,state=>{const identity=named(state.identities,args[0],'Identity');need(o['secret-env']||o['check-path'],'Supply --secret-env or --check-path.');if(o['secret-env']){identity.secretEnv=envName(o['secret-env']);delete identity.fixtureValue;}if(o['check-path']){need(o['check-path'].startsWith('/')&&!/[?#\\]/.test(o['check-path']),'Invalid check path.');identity.checkPath=o['check-path'];}delete identity.lastTest;return {identity};});break;
    case 'identity remove':result=await change(root,state=>{named(state.identities,args[0],'Identity');state.identities=state.identities.filter(i=>i.name!==args[0]);return {removed:args[0]};});break;
    case 'model add':{
      safeName(args[0]);const profile=modelProfile(args[0],o);result=await change(root,state=>{need(!state.models.some(m=>m.name===args[0]),'Model profile already exists.');state.models.push(profile);state.activeModel??=profile.name;return {model:profile};});break;
    }
    case 'model list':result={models:s.models,active:s.activeModel,privacy:'Local inference is available with a compatible local server. A Muse-hosted session can still use its own remote provider.'};break;
    case 'model use':result=await change(root,state=>{state.activeModel=named(state.models,args[0],'Model').name;return {activeModel:state.activeModel};});break;
    case 'model test':{
      const m=named(s.models,args[0]||s.activeModel,'Model');
      try {
        const check=await testModel(m,root,context);
        await change(root,state=>{const model=named(state.models,m.name,'Model');model.lastTest=check;model.lastAttempt=check;});
        result={model:m.name,check};
      } catch(error) {
        await change(root,state=>{named(state.models,m.name,'Model').lastAttempt={status:error.code===130?'skipped':'failed',checkedAt:now(),reason:error.details?.reason||'connection_check',message:redact(error.message),repositorySent:false};});
        throw error;
      }
      break;
    }
    case 'model remove':result=await change(root,state=>{named(state.models,args[0],'Model');state.models=state.models.filter(m=>m.name!==args[0]);if(state.activeModel===args[0])state.activeModel=state.models[0]?.name||null;return {removed:args[0]};});break;
    case 'scan':{
      const plan=scanPlan(s,o);if(o.plan)return outcome({plan},plan.blockers.length?3:0);
      return dispatchRun(root,'scan',{mode:o.mode||'combined',target:targetName,base:o.base,full:!!o.full},!!o.detach,context.signal);
    }
    case 'finding list':result={findings:filter(s.findings,{...o,lastRunId:o.run},['target','status','severity','lastRunId'])};break;
    case 'finding show':result={finding:named(s.findings,args[0],'Finding')};break;
    case 'verify':case 'retest':return verifyFinding(root,args[0],{target:o.target,build:o.build,retest:key==='retest',signal:context.signal});
    case 'test list':result={checks:filter(s.checks,o,['target'])};break;
    case 'test show':result={check:named(s.checks,args[0],'Check')};break;
    case 'test save':result={check:await saveCheck(root,args[0])};break;
    case 'test run':need(o.all||args[0],'Specify a check ID or --all.');need(!(o.all&&args[0]),'Choose a check ID or --all.');return dispatchRun(root,'tests',{checkId:args[0],target:targetName},!!o.detach,context.signal);
    case 'test bind':need(o.all||args[0],'Specify a check ID or --all.');need(o.file&&o.target,'Supply --file <binding.json> and --target.');result=await bindCheck(root,o.all?'all':args[0],o.target,loadJSON(o.file));break;
    case 'test export':need(o.all||args[0],'Specify a check ID or --all.');result=exportChecks(root,{checkId:args[0],all:o.all,target:o.target,out:o.out,force:o.force});break;
    case 'test disable':case 'test enable':result=await change(root,state=>{const c=named(state.checks,args[0],'Check');if(key==='test disable')need(o.reason,'--reason is required.');c.enabled=key==='test enable';c.disabledReason=c.enabled?null:o.reason;event(state,'check-setting',`${c.id}: ${c.enabled?'enabled':'disabled'}`,{reason:c.disabledReason});return {check:c};});break;
    case 'coverage':{
      const inv=await inventory(root);result={scope:'Specific saved HTTP behaviors only',complete:false,sourceFingerprint:inv.fingerprint,checks:s.checks.map(c=>({id:c.id,behavior:c.title,target:c.target,status:!c.enabled?'disabled':['failed','blocked'].includes(c.lastResult?.status)?c.lastResult.status:c.sourceFingerprint!==inv.fingerprint?'stale':c.lastResult?.status||'not-run',sourceChanged:c.sourceFingerprint!==inv.fingerprint,lastResult:c.lastResult})),unproven:s.findings.filter(f=>f.status==='simulated_unproven').map(f=>({id:f.id,title:f.title,simulation:true})),message:'A route is not fully covered just because one behavior on that route has a test.'};break;
    }
    case 'context':result={project:s.project.name,engine:'mock',summary:readiness(root),finding:o.finding?named(s.findings,o.finding,'Finding'):null,recentEvents:s.events.slice(-15),attention:s.checks.filter(c=>c.enabled&&['failed','blocked','stale'].includes(c.lastResult?.status)),next:'Replay saved checks first. Investigate failed, blocked, stale, and uncovered behaviors. Never treat simulated candidates as verified issues.'};break;
    case 'report':{
      const r=named(s.runs,o.run||s.runs.at(-1)?.id,'Run'),format=o.format||'json';need(['json','md'].includes(format),'Report format must be json or md.');
      const content=format==='json'?JSON.stringify(redact(r),null,2):`# Bypass run ${r.id}\n\nStatus: ${r.status}. Exit: ${r.exitCode}.\n\nAnalysis simulated: ${r.simulation}. Model calls: ${r.result?.modelCalls??0}.\n\n${r.result?.message||''}\n\n## Evidence\n\n\`\`\`json\n${JSON.stringify(redact(r.result),null,2)}\n\`\`\`\n`;
      if(o.out){const file=path.resolve(root,o.out);need(!fs.existsSync(file),'Report destination exists. Choose another filename.');atomic(file,content);result={path:file,format,runId:r.id};}else result={format,content};break;
    }
    case 'run list':result={runs:s.runs.map(({result,steps,...r})=>r)};break;
    case 'run show':result={run:named(s.runs,args[0],'Run')};break;
    case 'run watch':return watchRun(root,args[0],o.timeout?duration(o.timeout):300000);
    case 'run stop':result=await change(root,state=>{const r=named(state.runs,args[0],'Run');if(['queued','running'].includes(r.status))r.cancelRequested=true;return {runId:r.id,status:r.status,cancelRequested:r.cancelRequested};});break;
    case 'monitor add':{
      safeName(args[0]);need((o.runner||'local')==='local','Hosted cloud workers are not configured. Use --runner local.',3,{implemented:false});const everyMs=duration(o.every||'1h',10000);
      result=await change(root,state=>{const t=named(state.targets,targetName,'Target');scopeReady(t);need(!state.monitors.some(m=>m.name===args[0]),'Monitor name already exists.');const m={name:args[0],target:targetName,everyMs,runner:'local',enabled:true,createdAt:now(),nextRunAt:now()};state.monitors.push(m);return {monitor:m,worker:workerStatus(root),next:'bypass monitor worker --detach'};});break;
    }
    case 'monitor list':result={monitors:s.monitors,worker:workerStatus(root)};break;
    case 'monitor run':return runMonitor(root,args[0]);
    case 'monitor pause':case 'monitor resume':result=await change(root,state=>{const m=named(state.monitors,args[0],'Monitor');m.enabled=key==='monitor resume';if(m.enabled)scopeReady(named(state.targets,m.target,'Target'));return {monitor:m};});break;
    case 'monitor remove':result=await change(root,state=>{named(state.monitors,args[0],'Monitor');state.monitors=state.monitors.filter(m=>m.name!==args[0]);return {removed:args[0]};});break;
    case 'monitor worker':return startWorker(root,{detach:o.detach,once:o.once,stop:o.stop});
    case 'ci init':{
      need(!o.provider||o.provider==='github','Only GitHub Actions is supported.');named(s.targets,targetName,'Target');const file=path.join(root,'.github/workflows/bypass-security.yml');need(!fs.existsSync(file)||o.force,'Workflow exists; review before replacing with --force.');
      const exported=exportChecks(root,{all:true,target:targetName,force:o.force});
      const identities=s.identities.filter(i=>i.target===targetName);const envLines=[...new Set(identities.map(i=>i.secretEnv))].map(name=>`      ${name}: \${{ secrets.${name} }}`).join('\n');
      const workflow=`name: Bypass saved security checks\non:\n  workflow_dispatch:\n  pull_request:\npermissions:\n  contents: read\njobs:\n  regression:\n    runs-on: ubuntu-latest\n    timeout-minutes: 10\n    env:\n${envLines||'      BYPASS_CI: "true"'}\n    steps:\n      - uses: actions/checkout@v4\n      - uses: actions/setup-node@v4\n        with:\n          node-version: '22'\n      - name: Run exported checks (no model or Bypass account)\n        run: node --test tests/security/bypass/*.test.mjs\n`;
      atomic(file,workflow);result={workflow:file,tests:exported.files,notPublished:true,notes:['Review and commit generated files. Configure the named repository secrets.','Fork pull requests do not receive secrets; run authorized checks in a trusted workflow.','The local demo URL is not reachable on hosted GitHub runners. Bind a verified deployed target before enabling CI.']};break;
    }
    case 'demo status':result={demo:s.demo?demoConfig(root):null};break;
    case 'demo fix':case 'demo regress':case 'demo add-route':case 'demo reset':case 'demo stop':result=await updateDemo(root,key.split(' ')[1]);break;
    case '_run':return executeRun(root,args[0]);
    case '_demo-serve':await serveDemo(root);return null;
    default:throw new Fault(`Unknown operation: ${key}`);
  }
  return wrap(result);
}

async function integrate(key,args,o,working){
  if(key==='integrate status'){
    const r=await execFile('muse',['plugins','inspect','bypass','--json'],{cwd:working});let data;try{data=JSON.parse(r.stdout);}catch{data={message:r.stderr||r.stdout};}return outcome({integration:data},r.code===0?0:3);
  }
  if(key==='integrate remove'){
    need(args[0]==='muse','Only muse is supported.');const r=await execFile('muse',['plugins','remove','bypass','--json'],{cwd:working});return outcome({message:r.stdout||r.stderr},r.code===0?0:3);
  }
  const plugin=path.join(PACKAGE_ROOT,'plugin');
  const build=await execFile(process.execPath,[path.join(PACKAGE_ROOT,'scripts/build-plugin.mjs')],{cwd:PACKAGE_ROOT});need(build.code===0,'Plugin build failed.',3);
  const validation=await execFile('muse',['plugins','validate',plugin,'--json'],{cwd:working});need(validation.code===0,'Muse rejected plugin validation.',3,{validation:validation.stdout});
  const scope=o.scope||'project';need(['user','project'].includes(scope),'Scope must be user or project.');
  const installed=await execFile('muse',['plugins','install',plugin,'--scope',scope,'--json'],{cwd:working});
  need(installed.code===0,'Muse plugin installation failed. Check the native CLI output.',3,{output:installed.stderr||installed.stdout});
  return outcome({plugin,scope,installed:JSON.parse(installed.stdout),next:'Review with muse plugins inspect bypass, then muse plugins approve bypass. Start a new Muse session and use /bypass:review.',message:'Installation does not grant runtime trust. Muse’s native capability review remains visible.'});
}
