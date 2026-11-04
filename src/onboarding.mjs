import { promptValue, confirmChoice, scopeSuggestions, credentialTypes } from './interaction.mjs';
import { reviewChoices, reviewQuestion } from './application-setup.mjs';
import { rememberSelection } from './plugin-context.mjs';
import { ownershipReady, verificationDisabled } from './ownership-store.mjs';
import { promptMuseProfile } from './provider-setup.mjs';
import { execute, readiness } from './service.mjs';
import { connectProject } from './onboarding-repository.mjs';
import { guidedDemo } from './guided-demo.mjs';
import { reviewSummary } from './experience.mjs';
import { read, change } from './store.mjs';
import { scopeReady, loopback, appOriginInput, DEFAULT_REQUESTS_PER_SECOND } from './network.mjs';
import { appAddressQuestion, appAddressHelp, appEnvironmentQuestion, appEnvironmentChoices } from './app-connection.mjs';
import { promptMethods, mayChangeData } from './http-methods.mjs';
import { modelDisplay } from './model-display.mjs';
import { cleanText, redact, Fault, need, outcome } from './util.mjs';

const unique = (base, entries) => { let name=base, n=2; while(entries.some(x=>x.name===name)) name=base+n++; return name; };
const verified = ownershipReady;
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
    ? 'A black-box audit uses your Muse connection and does not need Docker. Setup and saved tests need no model.'
    : 'Source AI review uses Docker and your Muse connection. Setup and saved tests need no model.');
  io.setTasks?.('Setup',['Choose and connect Muse inference',mode==='live'?'Connect running app':'Connect application source',mode==='code'?'App testing skipped':'Choose app testing permissions','Save setup and open project']);
  io.task?.(0,'running');

  say('\nStep 1 of 4 / Choose and connect Muse inference');
  let prepared=null,model=null,replaceMuseKey=false;
  const candidateRoot=options.project||(!/^https:\/\/|^ssh:\/\/|^git@/.test(args[0]||'')?args[0]:null);
  try{
    const existing=read(candidateRoot||'');model=existing.models.find(item=>item.name===existing.activeModel);
    if((model?.lastAttempt||model?.lastTest)?.status==='connected'){
      prepared={saved:true,check:model.lastAttempt||model.lastTest};
      say(`✓ Keeping ${model.model} · ${model.provider==='meta'?'Meta Model API':'local Muse model'} · connection verified.`);
    }else model=null;
  }catch{/* New application: configure Muse before creating project state. */}
  while(!prepared){
    try{
      prepared=await promptMuseProfile(ask,pick,{secret:io.secret||io.ask.secret,write:say,activity:io.activity,signal:io.signal,metaBaseUrl:io.metaBaseUrl,forceSecret:replaceMuseKey});
      replaceMuseKey=false;
    }catch(error){
      if(error.code===130||error.name==='AbortError')throw error;
      say(`\nMuse connection not ready. ${error.message}`);
      const actions=[
        {id:'retry',label:'Retry this Muse setup (recommended)'},
        ...(['authentication','authorization','billing','quota'].includes(error.details?.reason)?[{id:'replace',label:'Enter a different API key'}]:[]),
        {id:'stop',label:'Stop and keep existing setup'}
      ];
      const action=await pick('What would you like to do?',actions);
      if(action.id==='replace'){replaceMuseKey=true;continue;}
      if(action.id==='stop')throw new Fault('Setup stopped. Saved choices are retained.',130);
    }
  }
  io.task?.(0,'done');io.task?.(1,'running');
  say(`\nStep 2 of 4 / ${mode==='live'?'Connect your running app':'Connect your repository'}`);
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
    say('Choose the application source folder or Git URL. Bypass will preview every repository file before setup writes it.');
    const initial=await connectProject(options,args,{ask,say,yes,pick,activity:io.activity,signal:io.signal,filePlanChoice:io.filePlanChoice});root=initial.root;
    if(!initial.resumed)await call(root,'engine use',['docker']);
    say(`✓ Application source connected: ${root}${initial.resumed?' · resuming saved setup':''}`);
    if(initial.fileChanges?.length){
      say('Repository setup changes:');
      for(const file of initial.fileChanges)say(`  ${file.action.padEnd(7)} ${file.path} · ${file.purpose}${file.commit?' · review and commit':' · local only'}`);
    }
  }
  await change(root,s=>{s.settings.reviewMode=mode;});
  io.setContext?.({title:read(root).project.name,repo:root,branch:read(root).project.repository.branch});
  if(!prepared.saved){
    const state=read(root),active=state.models.find(item=>item.name===state.activeModel);
    if((active?.lastAttempt||active?.lastTest)?.status==='connected'&&active.provider===prepared.config.provider&&active.model===prepared.config.model){
      prepared.saved=true;model=active;say(`✓ Reusing the verified ${active.model} connection already saved with this application.`);
    }
  }
  if(!prepared.saved){
    const name=advanced?await suggested('Muse connection name',[prepared.selection.name]):unique(prepared.selection.name,read(root).models);
    const result=await call(root,'model add',[name],prepared.config);await call(root,'model use',[name]);model=result.model;
    await change(root,state=>{const saved=state.models.find(item=>item.name===name);saved.lastTest=prepared.check;saved.lastAttempt=prepared.check;});
    model=read(root).models.find(item=>item.name===name);
  }else model=read(root).models.find(item=>item.name===read(root).activeModel);
  io.setContext?.({model:`${model.model} · ${model.provider==='meta'?'Meta Model API':'local Muse'} · connected`});
  say(`✓ Muse connection saved: ${model.model}\n  Destination: ${model.dataDestination}\n  Authentication: verified`);

  io.task?.(1,'done');io.task?.(2,'running');io.setNext?.('Save setup → open your project → run a review');
  say(`\nStep 3 of 4 / ${mode==='code'?'Code-only review — app setup skipped':'App testing permissions'}`);
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
  if(target)io.setContext?.({app:`${target.url} · ${authorized(target)?'authorized':verified(target)||verificationDisabled(target)?'scope required':'verification pending'}`});
  if(target&&verificationDisabled(target))say('No DNS record required. Confirm control when you approve the exact testing permissions below. You can require DNS or HTTPS later in Settings → Domain ownership verification.');
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
  }else if(mode==='live'&&target&&authorized(target))say('App and testing boundaries are ready. Starting the first audit now. Accounts are optional and can be added later for signed-in checks.');
  else say((mode==='live'
    ? 'App-only setup is saved. Testing starts as soon as the app boundaries are authorized.'
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
    if(!verificationDisabled(target)&&!verified(target)&&target.environment!=='local'){
      const {sharedOwnership}=await import('./ownership-store.mjs');
      if(sharedOwnership(target.url))target=(await call(root,'target verify',[target.name])).target;
    }
    if(!verificationDisabled(target)&&!verified(target)){
      if(target.environment==='local'){
        if(!await yes(`Confirm you control ${target.url}?`))return;
        target=(await call(root,'target verify',[target.name],{method:'local'})).target;
      }else{
        if(Date.parse(target.challenge?.expiresAt||0)<=Date.now())target=(await call(root,'target verify',[target.name],{renew:true})).target;
        const useFile=target.ownershipVerification==='http';
        if(!useFile)say('If your DNS provider appends the zone name, omit that suffix from the record name.\nExample: for staging.example.com in the example.com zone, enter _bypass-verification.staging.');
        const pendingMessage=mode==='live'?'App testing can begin after ownership and scope are ready.':'Source review can continue while verification is pending.';
        say(pendingMessage);
        if(useFile)say(`Serve ${target.challenge.token} at:\n${target.url}${target.challenge.httpPath}`);
        else say(`\nAdd this DNS record (keep unrelated records):\n  Type    TXT · TTL Auto\n  Name    ${target.challenge.record}\n  Value   ${target.challenge.token}`);
        while(!verified(target)){
          const choices=[{label:useFile?"I've added the file — check HTTPS":"I've added the record — check DNS",method:useFile?'http':'dns'},{label:mode==='live'?'Save setup — verify later':'Continue to my review — verify later (recommended)',method:null}];
          if(advanced)choices.push({label:useFile?'Use DNS TXT instead':'Use HTTPS file instead',method:useFile?'dns':'http'});
          const selection=await pick('Verify app ownership',choices,1);
          if(!selection.method){say('Verification pending — saved for later. '+pendingMessage);return;}
          if(selection.method==='http'&&!useFile){
            say(`Serve ${target.challenge.token} at:\n${target.url}${target.challenge.httpPath}`);
            if(!await yes('Is that HTTPS challenge published?'))continue;
          }
          try{const verifiedResult=await call(root,'target verify',[target.name],{method:selection.method});if(verifiedResult.kind==='setup-pending'){say('DNS pending — keep the published record and retry later. '+pendingMessage);return;}target=verifiedResult.target;}
          catch(e){if(e.code===130)throw e;say(`Not verified yet: ${selection.method==='dns'?'the matching TXT value is not visible. Check the DNS host/name and allow propagation.':e.message}\nPress Enter to continue your review now; your record is saved.`);}
        }
      }
    }
    if(!verificationDisabled(target))say(target.ownership.reused?`✓ Ownership already verified for ${new URL(target.url).hostname}.`:'✓ App ownership verified.');
    if(authorized(target)){say(`Keeping authorized scope: ${target.authorization.paths.join(', ')}`);return;}
    await recover(async()=>{
      const paths=await suggested('Paths to test (comma-separated)',scopeSuggestions(target));
      const methods=await promptMethods(ask,say);
      say(`${methods.join(', ')} checks on ${target.url}\nPaths: ${paths}\nMaximum ${DEFAULT_REQUESTS_PER_SECOND} requests/second · permission expires in 7 days.`);
      say('Also read public pages and scripts on this app to discover sign-in configuration (anonymous GET only).');
      if(mayChangeData(methods))say('Selected methods can create/change/delete test data or start jobs. Bypass sends only explicitly configured requests.');
      const production=target.environment==='production';
      const approved=await confirmChoice(ask,production?
        `Authorize these checks on the production app ${target.url}?`:
        `Authorize these checks on ${target.url}?`,{
        yes:production?'Yes, authorize this production scope':'Yes, authorize these checks',
        no:'Not now — keep testing disabled',fallback:true,recommended:'yes',write:say});
      if(!approved){say(production?'Production scope not authorized.':'Scope not authorized. Live testing stays blocked.');return;}
      await call(root,'target authorize',[target.name],{accept:true,paths,methods,rps:DEFAULT_REQUESTS_PER_SECOND,production,'public-config':true});
      say('✓ Testing scope authorized.');
    });
  }
  async function finish(){
    rememberSelection(options.project||process.cwd(),root);
    const info=readiness(root);
    const startReview=mode==='live'&&info.ready.liveTesting?{id:'blackbox'}:null;
    io.setContext?.({model:modelDisplay(info.model),app:info.target?`${info.target.url} · ${info.target.authorized?'authorized':info.target.ownership==='verified'||info.target.ownershipVerification==='off'?'scope required':'verification pending'}`:'not connected · source review available'});
    io.task?.(3,'done');io.setNext?.(startReview?'Starting your first app audit':mode==='live'?'Authorize app boundaries to start testing':'Run /review; type / to see commands');
    say('\nSetup saved\n');
    say(`  ${mode==='live'?'App profile   ':'Repository    '}${root}\n  Model         ${info.model?modelDisplay(info.model):'add later'}\n  App           ${info.target?`${info.target.url} · ${info.target.authorized?'authorized':info.target.ownership==='verified'||info.target.ownershipVerification==='off'?'scope required':'verification pending'}`:'add later; code-only review available'}\n  Test accounts ${read(root).identities.length} references\n  Muse plugin   ${museInstalled?'installed; approve in Muse':'optional'}`);
    if(startReview)say(`\nStarting the audit now with the approved boundaries: ${target.authorization.paths.join(', ')} · ${target.authorization.methods.join(', ')} · ${target.authorization.maxRequestsPerSecond} requests/second.`);
    else if(mode==='live')say('\nThe selected API model runs without Docker. Authorize app testing boundaries to start the audit.');
    else say(info.engine.mode==='docker'?'\nReal AI selected. The first review checks your model connection before sending source.':'\nYour saved offline-preview choice is retained. Use /engine to switch to real AI.');
    say('\nYour review\n'+reviewSummary(info.review));
    say(mode==='live'
      ? startReview?'No additional audit setup is required. Progress and coverage will appear next.':'Open the project to finish testing permission; the audit starts immediately after approval.'
      : 'Press Enter on the next screen to review source. Live checks need verified app scope. Accounts are optional; add them for cross-account checks or authorize registration testing.\nType / for commands; /app resumes DNS and /models changes the model.');
    const openDashboard=!!startReview||io.inDashboard||io.rich||await yes('Open my project?','y');
    return outcome({root,interactive:true,openDashboard,readiness:info,...(startReview?{startReview}:{})});
  }
}
