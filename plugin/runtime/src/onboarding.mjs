import { execute, readiness } from './service.mjs';
import { connectProject } from './onboarding-repository.mjs';
import { checkModelConnection } from './model-check.mjs';
import { guidedDemo } from './guided-demo.mjs';
import { reviewSummary } from './experience.mjs';
import { read } from './store.mjs';
import { scopeReady, loopback, appOriginInput } from './network.mjs';
import { cleanText, redact, Fault, need, outcome } from './util.mjs';

const unique = (base, entries) => { let name=base, n=2; while(entries.some(x=>x.name===name)) name=base+n++; return name; };
const verified = target => target?.ownership?.status==='verified' && Date.parse(target.ownership.expiresAt)>Date.now();
const authorized = target => { try { scopeReady(target); return true; } catch { return false; } };

// The same wizard is used by onboard, interactive init, and the terminal menu.
// Injecting prompt/output lets tests exercise real persisted setup and DNS gates.
export async function onboard(options={}, args=[], io={}) {
  need(io.ask, 'Onboarding needs an interactive terminal. Use init --non-interactive for scripts.');
  if(options.flow) need(['quickstart','advanced','demo'].includes(options.flow), '--flow must be quickstart, advanced, or demo.');
  const say = value => (io.write||console.log)(cleanText(redact(String(value))));
  const ask = async (label, fallback='') => (await io.ask(label,fallback)).trim() || fallback;
  const yes = async (label, fallback='n') => {
    while(true) { const value=(await ask(label+' (y/n)',fallback)).toLowerCase(); if(['y','yes'].includes(value))return true;if(['n','no'].includes(value))return false;say('Choose y or n.'); }
  };
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
  say('\nBYPASS / Get started\nConnect your application, then choose /engine for real Docker agents. Offline preview is also available.');
  say('Press Enter for the recommended next action. Your progress is saved.');
  const flow=options.flow||((options.repo||options.project||args[0])?'quickstart':(await pick('How would you like to start?',[
    {label:'Connect my application (recommended) — repository + live app',id:'quickstart'},
    {label:'See the full local walkthrough — no login or DNS needed',id:'demo'},
    {label:'Advanced setup — more configuration choices',id:'advanced'}
  ])).id);
  const advanced=flow==='advanced';
  let root, museInstalled=false;
  if(flow==='demo') {
    return {...await guidedDemo(options,io),interactive:true,openDashboard:false};
  }
  say('Repository → model → optional app connection → first review.\nDNS, test accounts, and the Muse plugin can all be finished later.');
  io.setTasks?.('Setup',['Connect application source','Choose inference connection','Connect app / optional DNS','Save setup and open project']);
  io.task?.(0,'running');io.setNext?.('Choose model → connect app → first review');

  say('\nStep 1 of 4 / Connect your repository');
  say('White-box uses this application source. Black-box uses its deployed app URL.\nChoose the application you want to review, not the Bypass CLI checkout.');
  const initial=await connectProject(options,args,{ask,say,yes,pick,activity:io.activity,signal:io.signal});
  root=initial.root;
  io.setContext?.({title:read(root).project.name,repo:root,branch:read(root).project.repository.branch});
  io.task?.(0,'done');io.task?.(1,'running');io.setNext?.('Connect your deployed app, or continue with a code preview');
  say(`✓ Repository connected: ${root}${initial.resumed?' · resuming saved setup':''}`);

  say('\nStep 2 of 4 / Choose your model connection');
  let model=read(root).models.find(m=>m.name===read(root).activeModel);
  if(model) say(`Keeping ${model.name} · ${model.provider} · ${model.lastAttempt?.status||model.lastTest?.status||'connection not tested'}. Change it later in Models & privacy.`);
  else await addModel();
  async function addModel(){await recover(async()=>{
    const selection=await pick('How would you like to connect to a model?',[
      {label:'Muse Code subscription — use your existing account',provider:'muse-code',name:'muse'},
      {label:'Local Muse / local model — compatible server on this machine',provider:'local',name:'local'},
      {label:'Self-hosted model — your compatible HTTPS endpoint',provider:'endpoint',name:'selfhosted'}
    ]);
    const config={provider:selection.provider};
    if(selection.provider!=='muse-code'){
      config['base-url']=await ask('Model server URL',selection.provider==='local'?'http://127.0.0.1:1234/v1':'');
      config.model=await ask('Model ID on that server');
      const secret=await ask('API-token environment variable (Enter if not needed)');if(secret)config['secret-env']=secret;
      if(advanced&&selection.provider==='endpoint')config['allow-private']=await yes('Allow this model endpoint on a private network?');
    }
    const name=advanced?await ask('Profile name',selection.name):unique(selection.name,read(root).models);
    const result=await call(root,'model add',[name],config);await call(root,'model use',[name]);model=result.model;
    io.setContext?.({model:`${model.name} · ${model.provider} · not tested`});
    say(`✓ Model choice saved: ${model.name}\nModel runs through: ${model.dataDestination}\nConnection has not been checked yet.`);
    if(selection.provider==='muse-code')say('Uses the official Muse login. If needed, run muse login in your terminal.');
    else if(selection.provider==='local')say('Requires your running compatible local server. No weights are downloaded and there is no cloud fallback.');
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

  io.task?.(1,'done');io.task?.(2,'running');io.setNext?.('Save setup → open your project → run a review preview');
  say('\nStep 3 of 4 / Connect your running app');
  say('Have a deployed app? Enter its URL to verify ownership. Press Enter to add it later.');
  let state=read(root), target=state.targets.find(t=>t.name===state.activeTarget);
  if(!target&&state.targets.length){target=state.targets[0];await call(root,'target use',[target.name]);}
  if(target)say(`Continuing ${target.name}: ${target.url}`);
  else while(!target){
    const input=await ask('App domain or URL (Enter to add later)');if(!input)break;
    let url;try{url=appOriginInput(input);}catch(error){say(`${error.message}\nTry the address again, or press Enter to continue without an app.`);continue;}
    if(url!==input)say(`Using ${url}`);
    const parsed=new URL(url);
    const environment=loopback(parsed.hostname)?'local':(await pick('Which environment is this?',[
      {label:'Staging / preview',id:'staging'},{label:'Production',id:'production'}
    ])).id;
    const name=advanced?await ask('Target name',environment):unique(environment,read(root).targets);
    target=(await call(root,'target add',[name],{url,environment})).target;
    await call(root,'target use',[target.name]);
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
        const secret=await ask(`${role==='owner'?'Owner':'Other account'} token variable`,role==='owner'?'BYPASS_OWNER_TOKEN':'BYPASS_OUTSIDER_TOKEN');
        const checkPath=await ask('Authenticated account endpoint','/api/me');
        const header=type==='header'?await ask('Header name'):undefined;
        await call(root,'identity add',[name],{target:target.name,type,'secret-env':secret,'check-path':checkPath,header});
        say(`✓ ${name}: reference saved. Credential not tested.`);
      }
      say('Load those variables in your terminal before testing accounts or starting Muse. Test the connections in Targets & identities.');
    });
  }else say('No test accounts are needed for the offline preview. Use /engine to enable real Docker agents and guided account/resource setup.');
  say('The CLI works on its own. The Muse plugin is optional.');
  if(await yes('Connect the Muse Code plugin now?'))try{
    say('Checking the existing Muse plugin installation…');
    const integration=await call(root,'integrate muse',[],{scope:'project'});museInstalled=true;
    say(integration.message);
    if(integration.next)say(integration.next);
    say('Native capability review stays in Muse.');
    say(`In ${root}, run:\n  muse plugins inspect bypass\n  muse plugins approve bypass\nThen start a new Muse session and run /bypass:review.`);
  }catch(error){if(error.code===130)throw error;say(`Plugin setup can wait. ${error.message}\nContinue in the CLI; choose Settings → Muse plugin to return later.`);}
  return finish();

  async function connectApp(){
    if(!verified(target)){
      if(target.environment==='local'){
        if(!await yes(`Confirm you control ${target.url}?`))return;
        target=(await call(root,'target verify',[target.name],{method:'local'})).target;
      }else{
        if(Date.parse(target.challenge?.expiresAt||0)<=Date.now())target=(await call(root,'target verify',[target.name],{renew:true})).target;
        say('If your DNS provider appends the zone name, omit that suffix from the record name.\nExample: for staging.example.com in the example.com zone, enter _bypass-verification.staging.\nYou can preview this project and run the complete local walkthrough while DNS is pending.');
        say(`\nAdd this DNS record (keep unrelated records):\n  Type    TXT · TTL Auto\n  Name    ${target.challenge.record}\n  Value   ${target.challenge.token}`);
        while(!verified(target)){
          const choices=[{label:"I've added the record — check DNS",method:'dns'},{label:'Continue to my review — verify DNS later (recommended)',method:null}];
          if(advanced)choices.push({label:'Use the HTTPS challenge instead',method:'http'});
          const selection=await pick('Optional: verify ownership now',choices,1);
          if(!selection.method){say('DNS pending — saved for later. Your review preview and the local walkthrough are ready. Live requests to this app remain disabled.');return;}
          if(selection.method==='http'){
            say(`Serve ${target.challenge.token} at:\n${target.url}${target.challenge.httpPath}`);
            if(!await yes('Is that HTTPS challenge published?'))continue;
          }
          try{target=(await call(root,'target verify',[target.name],{method:selection.method})).target;}
          catch(e){if(e.code===130)throw e;say(`Not verified yet: ${selection.method==='dns'?'the matching TXT value is not visible. Check the DNS host/name and allow propagation.':e.message}\nPress Enter to continue your review now; your record is saved.`);}
        }
      }
    }
    say('✓ App ownership verified.');
    if(authorized(target)){say(`Keeping authorized scope: ${target.authorization.paths.join(', ')}`);return;}
    await recover(async()=>{
      const paths=await ask('Paths to test (comma-separated)','/api');
      say(`Read-only GET/HEAD checks on ${target.url}\nPaths: ${paths}\nMaximum 2 requests/second · permission expires in 7 days.`);
      if(!await yes('Do you authorize these checks?')){say('Scope not authorized. Live testing stays blocked.');return;}
      let production=false;
      if(target.environment==='production')production=(await ask('Type production to confirm this production scope'))==='production';
      if(target.environment==='production'&&!production){say('Production scope not authorized.');return;}
      await call(root,'target authorize',[target.name],{accept:true,paths,production});
      say('✓ Testing scope authorized.');
    });
  }
  async function finish(){
    const info=readiness(root);
    io.setContext?.({model:info.model?`${info.model.name} · ${info.model.provider} · ${info.model.connection}`:'optional for this preview',app:info.target?`${info.target.url} · ${info.target.authorized?'authorized':info.target.ownership==='verified'?'scope required':'DNS pending'}`:'not connected · code preview available'});
    io.task?.(3,'done');io.setNext?.('Run a review preview, or /demo for the complete proof loop');
    say('\nSetup saved\n');
    say(`  Repository    ${root}\n  Model         ${info.model?`${info.model.name} · ${info.model.connection}`:'add later'}\n  App           ${info.target?`${info.target.url} · ${info.target.authorized?'verified and authorized':info.target.ownership==='verified'?'scope required':'verification pending'}`:'add later; code-only review available'}\n  Test accounts ${read(root).identities.length} references\n  Muse plugin   ${museInstalled?'installed; approve in Muse':'optional'}`);
    say('\nOffline preview is selected. Use /engine for real source review and scoped HTTP proof, or /poc for a separate real-AI test app.');
    say('\nYour review\n'+reviewSummary(info.review));
    say('Ready: your review preview. Press Enter on the next screen to continue.\nApp verification and plugin setup are available later in Settings.');
    const openDashboard=io.inDashboard||io.rich||await yes('Open my project?','y');
    return outcome({root,interactive:true,openDashboard,readiness:info});
  }
}
