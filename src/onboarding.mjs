import { promptValue, confirmChoice, scopeSuggestions, credentialTypes } from './interaction.mjs';
import { reviewChoices, reviewQuestion } from './application-setup.mjs';
import { rememberSelection } from './plugin-context.mjs';
import { ownershipRevoked } from './ownership-store.mjs';
import { promptAPIProfile } from './provider-setup.mjs';
import { execute, readiness } from './service.mjs';
import { connectProject } from './onboarding-repository.mjs';
import { checkModelConnection } from './model-check.mjs';
import { guidedDemo } from './guided-demo.mjs';
import { reviewSummary } from './experience.mjs';
import { read, change } from './store.mjs';
import { scopeReady, loopback, appOriginInput } from './network.mjs';
import { appAddressQuestion, appAddressHelp, appEnvironmentQuestion, appEnvironmentChoices } from './app-connection.mjs';
import { promptMethods, mayChangeData } from './http-methods.mjs';
import { cleanText, redact, Fault, need, outcome } from './util.mjs';

const unique = (base, entries) => { let name=base, n=2; while(entries.some(x=>x.name===name)) name=base+n++; return name; };
const verified = target => target?.ownership?.status==='verified' && Date.parse(target.ownership.expiresAt)>Date.now() && !ownershipRevoked(target);
const authorized = target => { try { scopeReady(target); return true; } catch { return false; } };

// The same wizard is used by onboard, interactive init, and the terminal menu.
// Injecting prompt/output lets tests exercise real persisted setup and DNS gates.
export async function onboard(options={}, args=[], io={}) {
  need(io.ask, 'Onboarding needs an interactive terminal. Use init --non-interactive for scripts.');
  if(options.flow) need(['quickstart','advanced','demo'].includes(options.flow), '--flow must be quickstart, advanced, or demo.');
  const say = value => (io.write||console.log)(cleanText(redact(String(value))));
  const ask = async (label, fallback='') => (await io.ask(label,fallback)).trim() || fallback;
  ask.multiselect=io.multiselect||io.ask.multiselect;
  ask.select=io.select||io.ask.select;
  const yes = (label, fallback='n') => confirmChoice(ask,label,{fallback:fallback==='y',write:say});
  const suggested=(label,values,extra={})=>promptValue(ask,label,values,{write:say,...extra});
  const pick = async (title, items, fallback=0) => {
    if(io.select)return io.select(title,items,{fallback});
    say('\n'+title);items.forEach((item,i)=>say(`  ${i+1}  ${item.label}`));
    while(true){const number=Number(await ask('Choose',String(fallback+1)));if(Number.isInteger(number)&&items[number-1])return items[number-1];say('Choose one of the numbers above.');}
  };
  const recover = async (work, {required=false}={}) => {
    while(true) { try{return await work();}catch(e){if(e.code===130||e.name==='AbortError')throw e;say(`\n${e.message}`);if(!await yes(required?'Try again?':'Try again now?')){if(required)throw new Fault('Setup stopped. Saved choices are retained.',130);return null;}} }
  };
  const call = (root,key,argv=[],flags={}) => {
    const work=signal=>execute(key,argv,{...flags,project:root},{signal});
    return io.activity?io.activity(key,work):work(io.signal);
  };
  say('\nBYPASS / Get started\nChoose code, a running app, or both.');
  say('Press Enter for the recommended next action. Your progress is saved.');
  const flow=options.flow||((options.repo||options.project||args[0])?'quickstart':(await pick('How would you like to start?',[
    {label:'Connect my application (recommended)',id:'quickstart'},
    {label:'See the full local walkthrough — no login or DNS needed',id:'demo'},
    {label:'Advanced setup — more configuration choices',id:'advanced'}
  ])).id);
  const advanced=flow==='advanced';
  let root, museInstalled=false;
  if(flow==='demo') {
    return {...await guidedDemo(options,io),interactive:true,openDashboard:false};
  }
  let savedMode;try{savedMode=read(options.project||process.cwd()).settings.reviewMode;}catch{}
  const mode=options.mode||savedMode||(await pick(reviewQuestion,reviewChoices,1)).id;
  need(['code','combined','live'].includes(mode),'Choose code, combined, or live review.');
  say(mode==='live'
    ? 'A black-box audit uses your provider API key and does not need Docker. Setup and saved tests need no model.'
    : 'Source AI review uses Docker and your provider API key. Setup and saved tests need no model.');
  io.setTasks?.('Setup',[mode==='live'?'Connect running app':'Connect application source','Choose inference connection',mode==='code'?'App testing skipped':'Verify app / choose permissions','Save setup and open project']);
  io.task?.(0,'running');
  say(`\nStep 1 of 4 / ${mode==='live'?'Connect your running app':'Connect your repository'}`);
  async function appAddress(){
    say(appAddressQuestion+'\n'+appAddressHelp);
    while(true){
      const input=await ask('App URL');
      let url;try{url=appOriginInput(input);}catch(error){say(error.message);continue;}
      if(url!==input)say(`Using ${url}`);
      while(true){
        const environment=loopback(new URL(url).hostname)?'local':(await pick(appEnvironmentQuestion(url),appEnvironmentChoices)).id;
        try{const {targetURL}=await import('./network.mjs');targetURL(url,environment);return {url,environment};}catch(error){say(error.message);}
      }
    }
  }
  if(mode==='live'){
    const app=await appAddress();
    const initial=await call(null,'app connect',[app.url],{environment:app.environment});root=initial.root;
    say(`✓ App connected: ${app.url}. No repository required.`);
  }else{
    say('Choose the application source folder or Git URL.');
    const initial=await connectProject(options,args,{ask,say,yes,pick,activity:io.activity,signal:io.signal});root=initial.root;
    if(!initial.resumed)await call(root,'engine use',['docker']);
    say(`✓ Application source connected: ${root}${initial.resumed?' · resuming saved setup':''}`);
  }
  await change(root,s=>{s.settings.reviewMode=mode;});
  io.setContext?.({title:read(root).project.name,repo:root,branch:read(root).project.repository.branch});
  io.task?.(0,'done');io.task?.(1,'running');

  say('\nStep 2 of 4 / Choose your model connection');
  let model=read(root).models.find(m=>m.name===read(root).activeModel);
  if(model&&model.executionMode!=='standalone-api'){say('Your old model profile is retained but cannot run standalone AI. Choose an API-key profile below, or use /bypass:review inside Muse.');model=null;}
  if(model) say(`Keeping ${model.name} · ${model.provider} · ${model.lastAttempt?.status||model.lastTest?.status||'connection not tested'}. Change it later in Models & privacy.`);
  else await addModel();
  async function addModel(){await recover(async()=>{
    const {selection,config}=await promptAPIProfile(ask,pick);
    const name=advanced?await suggested('Profile name',[selection.name]):unique(selection.name,read(root).models);
    const result=await call(root,'model add',[name],config);await call(root,'model use',[name]);model=result.model;
    io.setContext?.({model:`${model.name} · ${model.provider} · not tested`});
    say(`✓ Model choice saved: ${model.name}\nModel runs through: ${model.dataDestination}\nConnection has not been checked yet.`);
    say(`Only the environment-variable name is saved. Set ${model.secretEnv} privately before starting an AI audit.`);
  });}
  if(model&&(model.lastAttempt||model.lastTest)?.status!=='connected'){
    say('Optional: send one small test prompt. Provider usage may apply. You can finish setup without this check.');
    if(await yes('Check the connection now?'))while(true){
      try{await checkModelConnection(root,model.name,{...io,write:say});break;}
      catch(error){
        if(error.code===130||error.name==='AbortError')throw error;
        say(`\nConnection not verified. ${error.message}`);
        const action=await pick('What would you like to do?',[
          {label:'Continue setup — check the connection later',id:'continue'},
          {label:'Retry the connection check',id:'retry'},
          {label:'Choose another model connection',id:'change'}
        ]);
        if(action.id==='continue')break;
        if(action.id==='change'){await addModel();break;}
      }
    }
  }

  io.task?.(1,'done');io.task?.(2,'running');io.setNext?.('Save setup → open your project → run a review');
  say(`\nStep 3 of 4 / ${mode==='code'?'Code-only review — app setup skipped':'App ownership and testing permissions'}`);
  let state=read(root), target=mode==='code'?null:state.targets.find(t=>t.name===state.activeTarget);
  if(mode!=='code'){
    if(!target&&state.targets.length){target=state.targets[0];await call(root,'target use',[target.name]);}
    if(target)say(`Continuing ${target.name}: ${target.url}`);
    else {
      const {url,environment}=await appAddress();
      const name=advanced?await suggested('Target name',[environment]):unique(environment,read(root).targets);
      target=(await call(root,'target add',[name],{url,environment})).target;
      await call(root,'target use',[target.name]);
    }
  }
  if(target)io.setContext?.({app:`${target.url} · ${authorized(target)?'authorized':verified(target)?'scope required':'DNS pending'}`});
  if(target){await connectApp();target=read(root).targets.find(t=>t.name===target.name);}

  io.task?.(2,'done');io.task?.(3,'running');
  say('\nStep 4 of 4 / Finish setup');
  if(advanced&&target&&authorized(target)){
    const identities=read(root).identities.filter(i=>i.target===target.name);
    if(identities.length>=2)say(`Keeping ${identities.length} test-account references.`);
    else if(await yes('Add two test-account references now?'))await recover(async()=>{
      say('Use two different accounts. Enter environment-variable names, never token values.');
      for(const role of ['owner','outsider']){
        const name=`${target.name.slice(0,45)}-${role}`;
        if(read(root).identities.some(i=>i.name===name))continue;
        const type=advanced?(await pick('Authentication type', ['bearer','cookie','header'].map(id=>({id,label:id})))).id:'bearer';
        const secret=await suggested(`${role==='owner'?'Owner':'Other account'} token variable`,[role==='owner'?'BYPASS_OWNER_TOKEN':'BYPASS_OUTSIDER_TOKEN']);
        const checkPath=await suggested('Authenticated account endpoint',['/api/me','/api/profile','/me']);
        const header=type==='header'?await suggested('Header name',['X-API-Key','X-Auth-Token'],{recommended:false}):undefined;
        await call(root,'identity add',[name],{target:target.name,type,'secret-env':secret,'check-path':checkPath,header});
        say(`✓ ${name}: reference saved. Credential not tested.`);
      }
      say('These are environment references for CLI/CI. To connect accounts without shell exports, use identity import; Muse imports known private account files itself. Test connections in Targets & identities.');
    });
  }else say((mode==='live'
    ? 'App-only review selected. Use /blackbox to choose its scope and run the audit.'
    : 'You can review source now. Use /engine for account-boundary probes.')+
    ' Accounts are optional; add two test accounts for cross-account checks.');
  if(advanced&&await yes('Connect the Muse Code plugin now?'))try{
    say('Checking the existing Muse plugin installation…');
    const integration=await call(root,'integrate muse',[],{scope:'project'});museInstalled=true;
    say(integration.message);
    if(integration.next)say(integration.next);
    say('Review permissions in Muse /plugins → Installed → Bypass → Runtime. Then start a new Muse session in your app and use /bypass:start.');
  }catch(error){if(error.code===130)throw error;say(`Plugin setup can wait. ${error.message}\nContinue in the CLI; choose Settings → Muse plugin to return later.`);}
  return finish();

  async function connectApp(){
    if(!verified(target)&&target.environment!=='local'){
      const {sharedOwnership}=await import('./ownership-store.mjs');
      if(sharedOwnership(target.url))target=(await call(root,'target verify',[target.name])).target;
    }
    if(!verified(target)){
      if(target.environment==='local'){
        if(!await yes(`Confirm you control ${target.url}?`))return;
        target=(await call(root,'target verify',[target.name],{method:'local'})).target;
      }else{
        if(Date.parse(target.challenge?.expiresAt||0)<=Date.now())target=(await call(root,'target verify',[target.name],{renew:true})).target;
        say('If your DNS provider appends the zone name, omit that suffix from the record name.\nExample: for staging.example.com in the example.com zone, enter _bypass-verification.staging.');
        const pendingMessage=mode==='live'?'App testing can begin after ownership and scope are ready.':'Source review can continue while DNS is pending.';
        say(pendingMessage);
        say(`\nAdd this DNS record (keep unrelated records):\n  Type    TXT · TTL Auto\n  Name    ${target.challenge.record}\n  Value   ${target.challenge.token}`);
        while(!verified(target)){
          const choices=[{label:"I've added the record — check DNS",method:'dns'},{label:mode==='live'?'Save setup — verify DNS later':'Continue to my review — verify DNS later (recommended)',method:null}];
          if(advanced)choices.push({label:'Use the HTTPS challenge instead',method:'http'});
          const selection=await pick('Optional: verify ownership now',choices,1);
          if(!selection.method){say('DNS pending — saved for later. '+pendingMessage);return;}
          if(selection.method==='http'){
            say(`Serve ${target.challenge.token} at:\n${target.url}${target.challenge.httpPath}`);
            if(!await yes('Is that HTTPS challenge published?'))continue;
          }
          try{const verifiedResult=await call(root,'target verify',[target.name],{method:selection.method});if(verifiedResult.kind==='setup-pending'){say('DNS pending — keep the published record and retry later. '+pendingMessage);return;}target=verifiedResult.target;}
          catch(e){if(e.code===130)throw e;say(`Not verified yet: ${selection.method==='dns'?'the matching TXT value is not visible. Check the DNS host/name and allow propagation.':e.message}\nPress Enter to continue your review now; your record is saved.`);}
        }
      }
    }
    say(target.ownership.reused?`✓ Ownership already verified for ${new URL(target.url).hostname}.`:'✓ App ownership verified.');
    if(authorized(target)){say(`Keeping authorized scope: ${target.authorization.paths.join(', ')}`);return;}
    await recover(async()=>{
      const paths=await suggested('Paths to test (comma-separated)',scopeSuggestions(target));
      const methods=await promptMethods(ask,say);
      say(`${methods.join(', ')} checks on ${target.url}\nPaths: ${paths}\nMaximum 2 requests/second · permission expires in 7 days.`);
      say('Also read public pages and scripts on this app to discover sign-in configuration (anonymous GET only).');
      if(mayChangeData(methods))say('Selected methods can create/change/delete test data or start jobs. Bypass sends only explicitly configured requests.');
      if(!await yes('Do you authorize these checks?')){say('Scope not authorized. Live testing stays blocked.');return;}
      let production=false;
      if(target.environment==='production')production=await confirmChoice(ask,'Confirm testing on this production app',{yes:'Authorize the displayed production scope',no:'Keep production testing disabled',write:say});
      if(target.environment==='production'&&!production){say('Production scope not authorized.');return;}
      await call(root,'target authorize',[target.name],{accept:true,paths,methods,production,'public-config':true});
      say('✓ Testing scope authorized.');
    });
  }
  async function finish(){
    rememberSelection(options.project||process.cwd(),root);
    const info=readiness(root);
    io.setContext?.({model:info.model?`${info.model.name} · ${info.model.provider} · ${info.model.connection}`:'not configured',app:info.target?`${info.target.url} · ${info.target.authorized?'authorized':info.target.ownership==='verified'?'scope required':'DNS pending'}`:'not connected · source review available'});
    io.task?.(3,'done');io.setNext?.(mode==='live'?'Run /blackbox; type / to see commands':'Run /review; type / to see commands');
    say('\nSetup saved\n');
    say(`  ${mode==='live'?'App profile   ':'Repository    '}${root}\n  Model         ${info.model?`${info.model.name} · ${info.model.connection}`:'add later'}\n  App           ${info.target?`${info.target.url} · ${info.target.authorized?'verified and authorized':info.target.ownership==='verified'?'scope required':'verification pending'}`:'add later; code-only review available'}\n  Test accounts ${read(root).identities.length} references\n  Muse plugin   ${museInstalled?'installed; approve in Muse':'optional'}`);
    if(mode==='live')say('\nUse /blackbox to audit the running app. The selected API model runs without Docker; check its connection in /models.');
    else say(info.engine.mode==='docker'?'\nReal AI selected. The first review checks your model connection before sending source.':'\nYour saved offline-preview choice is retained. Use /engine to switch to real AI.');
    say('\nYour review\n'+reviewSummary(info.review));
    say(mode==='live'
      ? 'Press Enter to open the project, then use /blackbox. It asks for target, scope and request rate. /models checks the API connection.'
      : 'Press Enter on the next screen to review source. Live checks need verified app scope. Accounts are optional; add them for cross-account checks or authorize registration testing.\nType / for commands; /app resumes DNS and /models changes the model.');
    const openDashboard=io.inDashboard||io.rich||await yes('Open my project?','y');
    return outcome({root,interactive:true,openDashboard,readiness:info});
  }
}
