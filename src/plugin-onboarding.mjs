import { choiceInput, scopeSuggestions, testingApproval } from './interaction.mjs';
import { hostAI } from './execution-mode.mjs';
import { read } from './store.mjs';
import { VERSION, need } from './util.mjs';
import { scopeOutputForOrigin } from './blackbox/setup.mjs';
import { workspaceInfo } from './project-selection.mjs';
import { scopeReady, appOriginInput, DEFAULT_REQUESTS_PER_SECOND } from './network.mjs';
import { reviewReadiness } from './review-readiness.mjs';
import { pluginIdentity } from './runtime-identity.mjs';
import { credentialStatus } from './credentials.mjs';
import { registrationStatus } from './registration.mjs';
import { appConnection } from './app-connection.mjs';
import { httpMethods, methodChoices, methodInput, recommendedMethods } from './http-methods.mjs';
import { reviewQuestion, reviewInput, sourceStatus, repositoryAction } from './application-setup.mjs';
import { ownershipReady, verificationDisabled, sharedOwnership } from './ownership-store.mjs';
import { latestRemediation } from './remediation-checkpoint.mjs';

// Setup plans are read-only. The MCP adapter remembers explicitly selected modes.
export async function pluginOnboarding(cwd,root,{intent='real',mode,url,environment,repository,dir,reviewScope=false,
  interactiveCombined=false,methods,rps,modelCalls,minutes,scopeApproved=false}={}){
  const [workspace,identity]=await Promise.all([workspaceInfo(cwd,root),pluginIdentity()]);
  const state=root?read(root):null;
  mode??=state?.settings.reviewMode||(state?.targets.length?'combined':null);
  const early=(stage,nextAction,extra={})=>({version:VERSION,runtime:identity,intent,mode,workspace,selectedRepository:root,stage,steps:[],ready:{source:false,live:false},nextAction,...extra});
  if(!mode)return early('review-type',{id:'review-type',tool:'bypass_onboarding',question:reviewQuestion,input:reviewInput()},
    {guidance:'Open the host question/selection tool with these three choices. Do not initialize the current folder yet. Retain any repository URL and app URL the user supplied for the selected flow.'});
  need(['code','combined','live'].includes(mode),'Choose code, combined, or live review.');
  const pending = root && latestRemediation(root);
  if (pending && !repository && !url && methods == null && rps == null &&
    modelCalls == null && minutes == null) return early('release',
    {id:'release',tool:'bypass_remediation',arguments:{action:'status',review:pending.review},
      message:'Resume this PR deployment and proof replay. The old audit does not need to restart.'},
    {release:{review:pending.review,pr:pending.pr,status:pending.status,target:pending.target},
      alternatives:[{label:'Start a separate new review',tool:'bypass_scan',arguments:{mode}}]});
  if(intent==='preview'&&state?.demo)return {...early('ready',{tool:'bypass_scan',arguments:{mode:'combined'}}),engine:'mock',simulation:true,ai:hostAI(),ready:{source:true,live:true}};
  if(mode!=='live'){
    if(repository){const action=await repositoryAction(cwd,root,repository,dir);if(action)return early('repository',action);}
    const source=root?await sourceStatus(root):null;
    if(!root||!source.ready){
      const candidate=await sourceStatus(cwd).catch(()=>({ready:false}));
      const choices=[...(candidate.ready&&!workspace.isBypassSource?[{id:'current',label:'Use detected application folder',description:cwd,value:cwd}]:[]),{id:'git',label:'Connect a Git repository',description:'Paste the Git URL in the custom-answer/note field.',requiresInput:'repository'},{id:'folder',label:'Use another local folder',description:'Enter the folder path in the custom-answer/note field.',requiresInput:'repository'}];
      return early('repository',{id:'repository',tool:'bypass_connect_repository',question:'Which application should Bypass review?',
        input:choiceInput('repository',choices,{recommended:choices[0].id==='current'?'current':undefined,custom:'value'})},{sourceInventory:source,guidance:'Open the repository picker. Prefer explicit inputs already supplied; connect them without asking again. Suggest the current folder only when it contains source. Collect an unknown Git URL/path through the custom field; never substitute a choice ID for a path. Validate actual source before DNS or scope.'});
    }
  }else if(!root){
    const action=appConnection({url,environment});action.tool='bypass_connect_app';
    if(action.automatic)delete action.arguments.name;
    return early(action.id,action,{guidance:'App-only review needs no repository. Ask only for the missing app URL or environment using the supplied input, then connect its app profile.'});
  }
  const target=state.targets.find(t=>t.name===state.activeTarget),ready=reviewReadiness(state,{executionMode:'muse-host'});
  const source=mode!=='live';
  const skipVerification=verificationDisabled(target);
  let owned=ownershipReady(target),authorized=false;
  if(owned)try{scopeReady(target);authorized=true;}catch{}
  const reusable=target&&!skipVerification&&!owned&&target.environment!=='local'?sharedOwnership(target.url):null;
  const challenge=target&&!skipVerification&&!owned?target.challenge:null;
  const steps=[{id:'repository',label:source?'Application source':'Source review not selected',status:source?'complete':'skipped',path:source?root:null},
    {id:'host',label:'AI reasoning in this Muse session',status:'complete',message:'No provider profile or API key required.',billing:hostAI().billing},
    {id:'app',label:'App address',status:target?'complete':'needed',url:target?.url||null,environment:target?.environment||null,tool:'bypass_add_target'},
    {id:'ownership',label:target?.environment==='local'?'Local ownership acknowledgment':'App ownership',status:owned?'complete':skipVerification?'skipped':target?'needed':'waiting',tool:'bypass_verify_target',
      ...(owned&&target.ownership.status==='verified'?{message:`Ownership already verified for ${new URL(target.url).hostname}.`,expiresAt:target.ownership.expiresAt,reused:!!target.ownership.reused}:skipVerification?{message:owned?'App control acknowledged with testing permission.':'Confirm control when approving tests.'}:{}),
      ...(challenge?{challenge:{record:challenge.record,...(target.ownershipVerification==='http'?{url:target.url+challenge.httpPath}:{}),value:challenge.token,method:target.environment==='local'?'local':target.ownershipVerification==='http'?'http':'dns',expiresAt:challenge.expiresAt,renewRequired:Date.parse(challenge.expiresAt)<=Date.now()}}:{})},
    {id:'scope',label:'Testing permission',status:authorized?'complete':owned||skipVerification?'needed':'waiting',tool:'bypass_authorize_target',paths:target?.authorization?.paths||[],methods:target?.authorization?.methods||[],message:skipVerification?'Confirm you control this app and approve its exact testing scope.':'Ownership and testing permission are separate; production requires explicit acknowledgment.'}];
  const {identities,usable,probes}=ready;
  steps.push({id:'accounts',label:'Test accounts (optional)',status:usable.length>=2?'complete':'optional',tool:'bypass_import_identity',configured:identities.map(i=>({name:i.name,type:i.type,credential:credentialStatus(state,target,i)})),message:'Existing or authorized dedicated accounts are optional; missing credentials do not block anonymous checks.'},
    {id:'registration',label:'Account registration check',status:target?.registration?'configured':'optional',tool:'bypass_configure_registration',...registrationStatus(target)},
    {id:'resource',label:'Resource checks',status:probes.length?'configured':'optional',tool:'bypass_add_probe',probes,message:source?'Derive routes and response selectors from source.':'Use authorized app observations and supplied API information; source is not available. Exact resources and intended access policy must be established.'});
  const requestedOrigin=mode!=='code'&&url?appOriginInput(url):null;
  const live=mode!=='code'&&authorized&&ready.live&&(!requestedOrigin||target?.url===requestedOrigin);
  const next=steps.find(s=>s.status==='needed');
  let nextAction=next?{id:next.id,tool:next.tool,...(next.id==='ownership'?{question:target.ownershipVerification==='http'?'Publish the HTTPS verification file, then check it.':'Publish the TXT record, then check DNS.',challenge:next.challenge}:{})}:mode==='live'?{
    id:'review',tool:'bypass_blackbox_setup',arguments:{url:target.url,include:target.authorization.paths.join(','),methods:target.authorization.methods.join(','),rps:target.authorization.maxRequestsPerSecond,environment:target.environment,...scopeOutputForOrigin(root,target.url)},
    message:'Reuse this app and authorized scope, apply the default bounded budgets, and start the blackbox audit immediately. Do not ask another setup question before showing progress.'
  }:{id:'review',tool:'bypass_scan',arguments:{mode},message:'Show the selected source/app and scope, then start the requested review.'};
  if(mode==='code'){
    nextAction={id:'review',tool:'bypass_scan',arguments:{mode:'code'},message:'Review the code now. Do not ask for app URL, DNS, scope or accounts.'};
    for(const step of steps)if(['app','ownership','scope'].includes(step.id)&&step.status!=='complete')step.status='deferred';
  }else if(url||!target){
    const saved=requestedOrigin?state.targets.find(t=>t.url===requestedOrigin):null;
    if(saved){
      need(!environment||environment===saved.environment,`This app is saved as ${saved.environment}. Review its saved configuration before changing its environment.`);
      if(saved.name!==target?.name)nextAction={id:'app',tool:'bypass_use_target',arguments:{name:saved.name},automatic:true,message:'Reuse the saved app and ownership record.'};
    }else{
      nextAction=appConnection({url,environment});
      if(nextAction.automatic){const base=nextAction.arguments.name;let n=2;while(state.targets.some(t=>t.name===nextAction.arguments.name))nextAction.arguments.name=base+n++;}
    }
  }
  if(reviewScope&&!interactiveCombined&&mode!=='code'&&(owned||skipVerification)&&(!requestedOrigin||requestedOrigin===target.url))nextAction={id:'scope',tool:'bypass_authorize_target'};
  if(nextAction.id==='ownership'){
    if(reusable)nextAction={id:'ownership',tool:'bypass_verify_target',automatic:true,arguments:{name:target.name,method:reusable.method},message:'Reuse existing valid ownership for this app URL. No DNS publication is needed.'};
    else if(target?.environment!=='local'&&!challenge)nextAction={id:'ownership',tool:'bypass_verify_target',automatic:true,arguments:{name:target.name,renew:true,method:target.ownershipVerification==='http'?'http':'dns'},message:'The prior ownership proof has expired. Issue a new challenge.'};
    else if(target?.environment==='local')Object.assign(nextAction,{question:`Do you control the app at ${target.url} on this computer?`,input:choiceInput('ownership',[{id:'confirm',label:'Confirm local ownership',description:'I control this local application.',arguments:{name:target.name,method:'local'}},{id:'later',label:'Set up later',description:'Keep live testing disabled.'}])});
    else nextAction.input=choiceInput('ownership',[{id:'check',label:target.ownershipVerification==='http'?'I added the file: check HTTPS':'I added the TXT record: check DNS',description:'Check the displayed proof without starting tests.',arguments:{name:target.name,method:target.ownershipVerification==='http'?'http':'dns'}},{id:'later',label:source?'Review code while DNS updates':'Save and verify later',description:'Keep app testing disabled.'},{id:target.ownershipVerification==='http'?'dns':'http',label:target.ownershipVerification==='http'?'Use a DNS TXT record':'Use an HTTPS verification file',description:'Show the alternative ownership proof.'}],{recommended:'check'});
  }
  if(interactiveCombined&&mode==='combined'&&target&&(owned||skipVerification)&&
    (!requestedOrigin||requestedOrigin===target.url)&&['scope','review'].includes(nextAction.id)){
    const savedMethods=target.authorization?.methods||recommendedMethods;
    const savedRate=target.authorization?.maxRequestsPerSecond||DEFAULT_REQUESTS_PER_SECOND;
    if(methods==null)nextAction={id:'methods',tool:'bypass_onboarding',question:'Which HTTP methods may this combined audit use?',
      input:choiceInput('methods',[
        {id:'current',label:target.authorization?'Keep saved methods':'Default methods',description:savedMethods.join(', '),arguments:{methods:savedMethods.join(',')}},
        {id:'all',label:'All methods',description:'GET, HEAD, POST, PUT, PATCH, DELETE, OPTIONS.',arguments:{methods:methodChoices.map(choice=>choice.id).join(',')}},
        {id:'custom',label:'Custom methods',description:'Enter comma-separated method names.',requiresInput:'methods'}
      ],{custom:'value'}),guidance:'Ask this question once. Send the selected comma-separated methods to bypass_onboarding; a custom answer can name any supported HTTP methods.'};
    else if(rps==null)nextAction={id:'rps',tool:'bypass_onboarding',question:'What request rate should the combined audit use?',
      input:choiceInput('rps',[
        {id:'current',label:`${savedRate} RPS`,description:'Use the saved request rate.',arguments:{rps:savedRate}},
        {id:'ten',label:`${savedRate===10?5:10} RPS`,description:'Use this request rate.',arguments:{rps:savedRate===10?5:10}},
        {id:'custom',label:'Custom rate',description:'Enter a positive requests-per-second number.',requiresInput:'rps'}
      ],{custom:'value'}),guidance:'Ask this question once. Send the selected positive number to bypass_onboarding; do not silently reuse a saved rate.'};
    else if(modelCalls==null)nextAction={id:'model-calls',tool:'bypass_onboarding',question:'How many Muse decision calls may the live audit use?',
      input:choiceInput('modelCalls',[
        {id:'default',label:'120 calls',description:'Use the standard live audit limit.',arguments:{modelCalls:120}},
        {id:'more',label:'240 calls',description:'Allow more live audit decisions.',arguments:{modelCalls:240}},
        {id:'custom',label:'Custom number',description:'Enter a positive whole number.',requiresInput:'modelCalls'}
      ],{custom:'value'}),guidance:'Ask this question once. This cap covers the connected full live audit; Muse Code source-review reasoning is outside this counter.'};
    else if(minutes==null)nextAction={id:'minutes',tool:'bypass_onboarding',question:'What time budget should the combined review use?',
      input:choiceInput('minutes',[
        {id:'quick',label:'5-minute test',description:'Fast first pass with partial coverage; remaining work is reported.',arguments:{minutes:5}},
        {id:'default',label:'30 minutes',description:'Use the default total duration.',arguments:{minutes:30}},
        {id:'custom',label:'Custom duration',description:'Enter a positive number of minutes.',requiresInput:'minutes'}
      ],{recommended:'default',custom:'value'}),guidance:'Ask this question once. Elapsed time starts at the source review; Bypass applies the remaining time to the connected live audit. Five minutes is a quick pass, not full coverage. The plugin cannot interrupt Muse Code while it is thinking.'};
    else if(!scopeApproved)nextAction={id:'scope',tool:'bypass_authorize_target'};
    else nextAction={id:'review',tool:'bypass_scan',arguments:{mode:'combined',modelCalls,minutes},
      message:'Start the combined source and live review with the selected total Muse-call and time limits.'};
  }
  if(nextAction.id==='scope'){
    const scope={url:target.url,environment:target.environment,paths:target.authorization?.paths||['/'],
      methods:methods==null?target.authorization?.methods||recommendedMethods:httpMethods(methods),
      maxRequestsPerSecond:rps??target.authorization?.maxRequestsPerSecond??DEFAULT_REQUESTS_PER_SECOND,
      expiresAt:target.authorization?.expiresAt||new Date(Date.now()+7*86400000).toISOString(),
      publicConfigDiscovery:target.authorization?.publicConfigDiscovery??true};
    const input=testingApproval(target,scope);
    input.choices.find(choice=>choice.id==='custom').description='Choose all methods, paths or limits before approving.';
    const methodPicker=methodInput(scope.methods);
    methodPicker.singleSelectFallback.choices=[
      {label:'Keep selected methods',description:scope.methods.join(', '),methods:scope.methods},
      {label:'All methods',description:'Allow GET, HEAD, POST, PUT, PATCH, DELETE and OPTIONS.',
        methods:methodChoices.map(choice=>choice.id)},
      {label:'Custom methods',description:'Enter exactly the methods to allow, separated by commas.',custom:true}
    ];
    Object.assign(nextAction,{question:input.question,input,scope,
      arguments:{name:target.name,paths:scope.paths.join(','),methods:scope.methods,'public-config':scope.publicConfigDiscovery,rps:scope.maxRequestsPerSecond},
      custom:{methods:methodPicker,paths:choiceInput('paths',scopeSuggestions(target).map((item,n)=>({...item,id:String(n)})),{recommended:'0',custom:'value'})},
      guidance:'Show the compact proposed scope and Approve / Decline / Custom instructions picker. Explain that Custom offers All methods (GET, HEAD, POST, PUT, PATCH, DELETE, OPTIONS) as one choice. Approve confirms app control and the displayed testing scope, including production when shown. Continue automatically after approval. Custom opens method/path choices or accepts instructions; do not require a questionnaire. Keep optional account creation separate unless its exact effects were explicitly approved. Domain verification is a project setting; show DNS/HTTPS steps only when required. Never describe acknowledgment as verified domain ownership.'});
  }
  return {version:VERSION,runtime:identity,intent,mode,workspace,selectedRepository:source?root:null,profileRoot:root,engine:'host',ai:hostAI(),stage:nextAction.id==='review'?'ready':nextAction.id,steps,ready:{source,live},coverageGaps:mode==='code'?[]:ready.coverageGaps,nextAction,
    alternatives:mode==='combined'&&source&&!live?[{label:'Review code now; connect the app later',tool:'bypass_scan',arguments:{mode:'code'}}]:[],
    guidance:'Show a short stage label and the next input. Do not repeat Done / Now / Next after simple choices, summarize the checklist, or ask to continue between automatic steps. Use nextAction already returned by a tool rather than calling onboarding again. Use native pickers with recommended options and custom notes whenever meaningful alternatives exist. Reuse known answers; discover technical values before asking. Text-only input is reserved for an unknown exact URL/path or a user-selected custom value. Use supplied repository and app URL as actual tool inputs before progressing. Show billing/privacy only if not already disclosed by the installer or this session. Accounts are optional. Never ask users to export tokens or restart Muse for credentials. Source hypotheses are not live proof. App-only review skips source and reports its coverage limits.'};
}
