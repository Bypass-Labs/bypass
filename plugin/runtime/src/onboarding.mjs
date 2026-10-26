import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import net from 'node:net';
import { execute, readiness, PACKAGE_ROOT } from './service.mjs';
import { read } from './store.mjs';
import { scopeReady, loopback } from './network.mjs';
import { cleanText, redact, execFile, Fault, need, outcome } from './util.mjs';

const expand = value => value === '~' ? os.homedir() : value.startsWith('~/') ? path.join(os.homedir(), value.slice(2)) : value;
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
    say('\n'+title);items.forEach((item,i)=>say(`  ${i+1}  ${item.label}`));
    while(true){const number=Number(await ask('Choose',String(fallback+1)));if(Number.isInteger(number)&&items[number-1])return items[number-1];say('Choose one of the numbers above.');}
  };
  const recover = async (work, {required=false}={}) => {
    while(true) { try{return await work();}catch(e){if(e.code===130||e.name==='AbortError')throw e;say(`\n${e.message}`);if(!await yes(required?'Try again?':'Try again now?')){if(required)throw new Fault('Setup stopped. Saved choices are retained.',130);return null;}} }
  };
  const call = (root,key,argv=[],flags={}) => execute(key,argv,{...flags,project:root});
  say('\nBYPASS / Get started\nReal setup and saved checks. Analysis engines are mocked.');
  const flow=options.flow||(await pick('How would you like to start?',[
    {label:'QuickStart (recommended) — connect your project',id:'quickstart'},
    {label:'Try the demo — a local app with two test accounts',id:'demo'},
    {label:'Advanced setup — more configuration choices',id:'advanced'}
  ])).id;
  const advanced=flow==='advanced';
  let root, museInstalled=false;
  if(flow==='demo') {
    let dir=path.resolve(expand(options.dir||path.join(PACKAGE_ROOT,'.demo/ledger')));
    if(fs.existsSync(path.join(dir,'.bypass/state.json'))){
      need(read(dir).demo,'This directory is a connected project, not a demo. Choose an empty demo directory; the project is unchanged.');
      const action=await pick('A saved demo already exists.',[{label:'Continue the existing demo',id:'resume'},{label:'Start a fresh demo; keep the old one',id:'fresh'}]);
      if(action.id==='fresh')dir=path.join(path.dirname(dir),`ledger-${Date.now()}`);
    }else need(!fs.existsSync(dir)||(fs.statSync(dir).isDirectory()&&fs.readdirSync(dir).length===0),'Choose an empty demo directory. Existing files are left unchanged.');
    const result=await recover(async()=>{
      // A free local port avoids colliding with a previous rehearsal.
      const server=net.createServer();
      await new Promise((resolve,reject)=>{server.once('error',reject);server.listen(0,'127.0.0.1',resolve);});
      const port=server.address().port;await new Promise(resolve=>server.close(resolve));
      return execute('demo start',[],{dir,port});
    },{required:true});
    root=result.root;
    say(`\nDemo running: ${result.url}\nOpen that address in your browser.\nPublic fixture accounts and local testing scope are ready.\nMuse profile is configured; no model was called.`);
    say('Next: choose Run a review in the terminal, then Findings to verify the invoice.');
    return finish();
  }

  say('\n1 / Repository');
  let location=options.repo||args[0]||options.project;
  const initial=await recover(async()=>{
    const current=process.cwd();
    location=location||await ask('Repository directory or Git URL',current===PACKAGE_ROOT?'':current);
    need(location,'Enter the path to your app repository, or its Git URL.');
    const selected=expand(location);location=null;
    const remote=/^(https:|ssh:|git@)/.test(selected);
    const dir=options.dir||(remote?expand(await ask('Clone into directory')):undefined);
    if(remote)need(dir,'Choose an empty directory for the clone.');
    return execute('init',[selected],{...options,repo:undefined,dir,'non-interactive':true});
  },{required:true});
  root=initial.root;
  say(`✓ Repository connected: ${root}${initial.resumed?' · resuming saved setup':''}`);

  say('\n2 / Model');
  let model=read(root).models.find(m=>m.name===read(root).activeModel);
  if(model) say(`Keeping ${model.name} · ${model.provider} · ${model.lastTest?.status||'connection not tested'}. Change it later in Models & privacy.`);
  else await recover(async()=>{
    const selection=await pick('Where should inference run?',[
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
    say(`✓ Model configured: ${model.name}\nInference destination: ${model.dataDestination}`);
    if(selection.provider==='muse-code')say('Uses the official Muse login. If needed, run muse login in your terminal.');
    else if(selection.provider==='local')say('Requires your running compatible local server. No weights are downloaded and there is no cloud fallback.');
  });
  if(model&&!model.lastTest&&await yes('Test the model connection? Sends a synthetic prompt; provider usage may apply.')){
    await recover(async()=>{const result=await call(root,'model test',[model.name]);say(`✓ Model connection: ${result.check.status}. No repository content sent.`);});
  }

  say('\n3 / Running app');
  let state=read(root), target=state.targets.find(t=>t.name===state.activeTarget);
  if(!target&&state.targets.length){target=state.targets[0];await call(root,'target use',[target.name]);}
  if(target)say(`Continuing ${target.name}: ${target.url}`);
  else await recover(async()=>{
    const url=await ask('App URL (Enter to add later)');if(!url)return;
    let parsed;try{parsed=new URL(url);}catch{throw new Fault('Enter an origin such as https://staging.example.com.');}
    const environment=loopback(parsed.hostname)?'local':(await pick('Which environment is this?',[
      {label:'Staging / preview',id:'staging'},{label:'Production',id:'production'}
    ])).id;
    const name=advanced?await ask('Target name',environment):unique(environment,read(root).targets);
    target=(await call(root,'target add',[name],{url,environment})).target;
    await call(root,'target use',[target.name]);
  });
  if(target){await connectApp();target=read(root).targets.find(t=>t.name===target.name);}

  say('\n4 / Optional connections');
  if(target&&authorized(target)){
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
  }else say('Test accounts can be added after app verification in Targets & identities.');
  if(await yes('Install the Muse Code plugin for this repository?'))await recover(async()=>{
    await execFile('muse',['--version']);
    await call(root,'integrate muse',[],{scope:'project'});museInstalled=true;
    say('✓ Muse plugin installed. Native capability approval is still required.');
    say(`In ${root}, run:\n  muse plugins inspect bypass\n  muse plugins approve bypass\nThen start a new Muse session and run /bypass:review.`);
  });
  return finish();

  async function connectApp(){
    if(!verified(target)){
      if(target.environment==='local'){
        if(!await yes(`Confirm you control ${target.url}?`))return;
        target=(await call(root,'target verify',[target.name],{method:'local'})).target;
      }else{
        if(Date.parse(target.challenge?.expiresAt||0)<=Date.now())target=(await call(root,'target verify',[target.name],{renew:true})).target;
        say(`\nVerify this app in your DNS provider:\n  Type    TXT\n  Name    ${target.challenge.record}\n  Value   ${target.challenge.token}\n  TTL     Auto / provider default\n\nCopy the complete generated value. Keep unrelated DNS records.`);
        while(!verified(target)){
          const choices=[{label:"I've added the record — check DNS",method:'dns'},{label:'Do this later — save and continue',method:null}];
          if(advanced)choices.push({label:'Use the HTTPS challenge instead',method:'http'});
          const selection=await pick('Verify ownership',choices);
          if(!selection.method){say('DNS pending. Setup is saved; live testing stays blocked.');return;}
          if(selection.method==='http'){
            say(`Serve ${target.challenge.token} at:\n${target.url}${target.challenge.httpPath}`);
            if(!await yes('Is that HTTPS challenge published?'))continue;
          }
          try{target=(await call(root,'target verify',[target.name],{method:selection.method})).target;}
          catch(e){if(e.code===130)throw e;say(`Not verified yet: ${e.message}\nYou can retry or come back later.`);}
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
    say('\nSetup saved\n');
    say(`  Repository    ${root}\n  Model         ${info.model?`${info.model.name} · ${info.model.connection}`:'add later'}\n  App           ${info.target?`${info.target.url} · ${info.target.authorized?'verified and authorized':info.target.ownership==='verified'?'scope required':'verification pending'}`:'add later; code-only review available'}\n  Test accounts ${read(root).identities.length} references\n  Muse plugin   ${museInstalled?'installed; approve in Muse':'optional'}`);
    say('\nAnalysis is simulated. Fixture proof and saved-test replay are real.');
    if(info.target&&!info.target.authorized)say(`Resume verification with: ./bypass onboard ${JSON.stringify(root)}`);
    else if(!info.target)say('You can add an app later by running onboarding again.');
    const openDashboard=io.inDashboard||await yes('Open Bypass now?','y');
    return outcome({root,interactive:true,openDashboard,readiness:info});
  }
}
