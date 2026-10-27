import path from 'node:path';
import { execute } from './service.mjs';
import { SCHEMA, VERSION, redact, need, outcome } from './util.mjs';
import { workspaceInfo, isBypassSource, projectPath } from './project-selection.mjs';
import { pluginOnboarding } from './plugin-onboarding.mjs';
import { savedSelection, rememberSelection } from './plugin-context.mjs';

const str=(description,extra={})=>({type:'string',description,...extra});
const bool=description=>({type:'boolean',description});
const target=str('Configured target name');
function tool(name,description,properties,required,command,makeArgs=()=>[],makeOptions=a=>a,readOnly=false){return {name,description,inputSchema:{type:'object',properties,required,additionalProperties:false},annotations:{readOnlyHint:readOnly,destructiveHint:!readOnly,idempotentHint:readOnly,openWorldHint:!readOnly},command,makeArgs,makeOptions};}
const identityKey=str('Finding, check, or run ID');
const repositorySelection={repository:str('Application repository: explicit local folder or Git URL selected by the user'),dir:str('Empty clone destination for a Git URL'),confirmed:bool('True only when the user has identified or confirmed this repository'),allowBypassSource:bool('Only true when the user specifically wants to review Bypass tooling itself'),name:str('Optional project display name')};
export const toolDefinitions=[
  tool('bypass_onboarding','Start or resume the guided plugin setup. Returns version, selected application, a checklist and one next action. No scan, inference or app request.',{intent:str('Requested experience; real is recommended',{enum:['real','preview']})},[],'onboarding',undefined,undefined,true),
  tool('bypass_workspace','Inspect the Muse workspace and repository selection without initializing or scanning anything.',{},[],'workspace',undefined,undefined,true),
  tool('bypass_connect_repository','Select the application repository for ALL subsequent Bypass calls in this Muse session. Reuse its existing setup or clone a Git URL into an explicit empty directory. Never executes repository code.',repositorySelection,['repository','confirmed'],'connect-session'),
  tool('bypass_status','Read readiness, selected analysis engine, and evidence boundaries.',{},[],'status',undefined,undefined,true),
  tool('bypass_init','Select and initialize an explicitly user-selected application repository. Never defaults to the Muse working directory.',repositorySelection,['repository','confirmed'],'connect-session'),
  tool('bypass_targets','List configured targets and their ownership/scope state.',{},[],'target list',undefined,undefined,true),
  tool('bypass_add_target','Connect a local or deployed app. Returns the DNS/HTTP ownership challenge.',{name:str('Target name'),url:str('Exact origin URL'),environment:str('Environment',{enum:['local','preview','staging','production']})},['name','url','environment'],'target add',a=>[a.name]),
  tool('bypass_verify_target','Check the published ownership challenge. This does not authorize security testing.',{name:str('Target name'),method:str('Challenge method',{enum:['dns','http','local']}),renew:bool('Issue a new expired ownership challenge; invalidates prior scope')},['name','method'],'target verify',a=>[a.name]),
  tool('bypass_authorize_target','Record scope only after the user explicitly authorizes testing of these paths.',{name:str('Target name'),paths:str('Comma-separated path prefixes'),accept:bool('True only after explicit user authorization'),production:bool('True only after explicit production authorization')},['name','paths','accept'],'target authorize',a=>[a.name]),
  tool('bypass_use_target','Select an existing configured application target.',{name:str('Target name')},['name'],'target use',a=>[a.name]),
  tool('bypass_revoke_target','Revoke testing authorization and pause monitors.',{name:str('Target name')},['name'],'target revoke',a=>[a.name]),
  tool('bypass_add_identity','Store a credential environment-variable reference, never a raw secret.',{name:str('Identity name'),target,type:str('Identity kind',{enum:['bearer','cookie','header']}),'secret-env':str('Environment variable name'),header:str('Custom header name'),'check-path':str('Configured identity check path')},['name','target','type','secret-env'],'identity add',a=>[a.name]),
  tool('bypass_update_identity','Repair an existing credential reference or signed-in identity endpoint without adding a duplicate.',{name:str('Existing identity name'),'secret-env':str('Credential environment variable name'),'check-path':str('Signed-in JSON identity endpoint')},['name'],'identity update',a=>[a.name]),
  tool('bypass_identities','List identity references without credentials.',{target},[],'identity list',undefined,undefined,true),
  tool('bypass_test_identity','Test a configured identity against an authorized identity-check path.',{name:str('Identity name')},['name'],'identity test',a=>[a.name]),
  tool('bypass_models','List inference profiles and data destinations.',{},[],'model list',undefined,undefined,true),
  tool('bypass_add_model','Configure a provider. Host Muse sessions continue to use their current model; Bypass never extracts subscription credentials.',{name:str('Profile name'),provider:str('Provider',{enum:['local','endpoint','muse-code']}),'base-url':str('Compatible endpoint base URL'),model:str('Model ID'),effort:str('Muse request reasoning effort; default minimal',{enum:['minimal','low','medium','high']}),'secret-env':str('Credential environment variable')},['name','provider'],'model add',a=>[a.name]),
  tool('bypass_test_model','Test or diagnose the selected model connection with one synthetic prompt. No repository content is sent.',{name:str('Model profile name')},[],'model test',a=>a.name?[a.name]:[]),
  tool('bypass_use_model','Select the standalone Bypass provider profile.',{name:str('Profile name')},['name'],'model use',a=>[a.name]),
  tool('bypass_engine','Select the real Docker POC or offline mocked preview. Real runs send source excerpts to the selected shared model.',{mode:str('Analysis engine',{enum:['docker','mock']})},['mode'],'engine use',a=>[a.mode]),
  tool('bypass_engine_doctor','Check Docker and the shared agent model profile.',{},[],'engine doctor',undefined,undefined,true),
  tool('bypass_add_probe','Add a user-approved JSON resource for real GET proof. Two different valid accounts and positive-control endpoints are required.',{name:str('Probe name'),target,path:str('Exact resource path'),'resource-id':str('Expected JSON resource identifier'),owner:str('Owner identity name'),outsider:str('Other account identity name'),'id-field':str('Resource identifier field or nested selector, e.g. run.id or /run/id; default id'),'identity-field':str('Account identifier field or nested selector at identity endpoint, e.g. owner_uid; default id')},['name','path','resource-id','owner','outsider'],'probe add',a=>[a.name]),
  tool('bypass_probes','List approved resource probes.',{target},[],'probe list',undefined,undefined,true),
  tool('bypass_prepare_scan','Read the proposed run scope, data flow, and blockers without starting a run.',{mode:str('Review mode',{enum:['code','live','combined']}),target},[],'scan',undefined,a=>({...a,plan:true}),true),
  tool('bypass_scan','Start a durable scan with the selected engine. Docker mode uses the shared model and actual scoped HTTP controls; mock mode remains simulated. Saved checks run first. Poll bypass_run.',{mode:str('Review mode',{enum:['code','live','combined']}),target,base:str('Optional Git base reference')},[],'scan',undefined,a=>({...a,detach:true})),
  tool('bypass_findings','Read findings and their simulation/evidence labels.',{target,status:str('Finding status')},[],'finding list',undefined,undefined,true),
  tool('bypass_finding','Read one finding, evidence, and remediation context.',{id:identityKey},['id'],'finding show',a=>[a.id],undefined,true),
  tool('bypass_verify','Reproduce a real finding using its bound owner, outsider, and anonymous HTTP controls. Mock examples cannot become deployed proof.',{id:identityKey,target},['id'],'verify',a=>[a.id]),
  tool('bypass_retest','Retest a previously confirmed finding; save a reusable test only after the identity, owner, non-owner and anonymous controls pass.',{id:identityKey,target,build:str('Operator-supplied build ID; not attested')},['id'],'retest',a=>[a.id]),
  tool('bypass_tests','List saved regression checks and last results.',{target},[],'test list',undefined,undefined,true),
  tool('bypass_run_tests','Start deterministic regression replay, with no model calls.',{id:identityKey,all:bool('Run every enabled check'),target},[],'test run',a=>a.id?[a.id]:[],a=>({...a,all:a.all??!a.id,detach:true})),
  tool('bypass_export_tests','Export standalone Node tests inside the repository. No model or Bypass dependency.',{id:identityKey,all:bool('Export all saved checks'),target,out:str('Relative output directory')},[],'test export',a=>a.id?[a.id]:[],a=>({...a,all:a.all??!a.id})),
  tool('bypass_coverage','Read behavior-level coverage, stale checks, and unproven candidates.',{},[],'coverage',undefined,undefined,true),
  tool('bypass_context','Read prior evidence and monitor results at the start of a coding session.',{finding:identityKey},[],'context',undefined,undefined,true),
  tool('bypass_run','Read the current status and output of a durable run.',{id:identityKey},['id'],'run show',a=>[a.id],undefined,true),
  tool('bypass_stop_run','Request cancellation of a durable run.',{id:identityKey},['id'],'run stop',a=>[a.id]),
  tool('bypass_monitors','Read schedules and worker health.',{},[],'monitor list',undefined,undefined,true),
  tool('bypass_add_monitor','Schedule saved tests on the separately running local worker.',{name:str('Monitor name'),target,every:str('Interval, e.g. 1h')},['name','target','every'],'monitor add',a=>[a.name]),
  tool('bypass_pause_monitor','Pause a local monitor.',{name:str('Monitor name')},['name'],'monitor pause',a=>[a.name])
];
function validate(schema,input){
  need(input&&typeof input==='object'&&!Array.isArray(input),'Arguments must be an object.');
  for(const name of schema.required)need(Object.hasOwn(input,name),`Missing required argument: ${name}`);
  for(const [key,value] of Object.entries(input)){
    const p=schema.properties[key];need(p,`Unknown argument: ${key}`);need(typeof value===p.type,`${key} must be ${p.type}.`);
    if(p.enum)need(p.enum.includes(value),`Unsupported ${key}.`);
    if(typeof value==='string')need(value.length<=4096,`${key} exceeds the length limit.`);
  }
}
const protocolVersions=['2026-07-28','2025-11-25','2025-06-18','2025-03-26','2024-11-05'];
export async function serveMCP(cwd=process.cwd(),io={input:process.stdin,output:process.stdout}){
  let initialized=false,buffer='',selectedRoot=savedSelection(cwd),selecting=false;const pending=new Map(),tasks=new Set();
  const context=async()=>selectedRoot?{...await execute('context',[],{project:selectedRoot,json:true,'non-interactive':true}),pluginVersion:VERSION}:outcome(await pluginOnboarding(cwd,null));
  const send=value=>io.output.write(JSON.stringify(redact(value))+'\n');
  const respond=(id,result)=>send({jsonrpc:'2.0',id,result});
  const error=(id,code,message)=>send({jsonrpc:'2.0',id,error:{code,message}});
  async function handle(message){
    if(!message||typeof message!=='object'||Array.isArray(message)){error(null,-32600,'Invalid Request');return;}
    const {id,method,params={}}=message;
    if(message.jsonrpc!=='2.0'||typeof method!=='string'){error(id??null,-32600,'Invalid Request');return;}
    if(method==='notifications/cancelled'){pending.get(params.requestId)?.abort();return;}
    if(method==='notifications/initialized')return;
    if(id===undefined)return;
    if(method==='initialize'){
      initialized=true;respond(id,{protocolVersion:protocolVersions.includes(params.protocolVersion)?params.protocolVersion:'2025-11-25',capabilities:{tools:{listChanged:false},resources:{subscribe:false,listChanged:false},prompts:{listChanged:false}},serverInfo:{name:'bypass',version:VERSION},instructions:'Start Bypass requests with bypass_onboarding. It returns version, the exact selected application, an ordered checklist, and one next action. Use a previously explicit saved selection when returned. Otherwise ask one repository question; never silently initialize this folder. Perform MCP calls yourself after the user answers. Do not display MCP syntax as a user command, call setup a top finding, or search .demo history. Real review uses Docker and one shared model profile; never silently fall back to mock. Source review can proceed while DNS/account setup is pending. Confirmed findings require actual HTTP controls.'});return;
    }
    if(method==='ping'){respond(id,{});return;}
    if(!initialized){error(id,-32002,'Initialize the server first.');return;}
    if(method==='tools/list'){respond(id,{tools:toolDefinitions.map(({command,makeArgs,makeOptions,...t})=>t)});return;}
    if(method==='resources/list'){respond(id,{resources:[{uri:'bypass://context',name:'Bypass session context',mimeType:'application/json',description:'Local evidence and monitor updates'}]});return;}
    if(method==='prompts/list'){respond(id,{prompts:[{name:'bypass_review',description:'Review the current repository with the Bypass proof-to-regression workflow.'}]});return;}
    if(method==='prompts/get'){if(params.name!=='bypass_review'){error(id,-32602,'Unknown prompt');return;}respond(id,{messages:[{role:'user',content:{type:'text',text:'Start with bypass_onboarding (intent real). Follow its checklist and next action. Reuse the explicitly saved application selection or ask one plain-language repository question. Continue configuration yourself after each answer, showing repository, shared model, Docker, app, ownership, scope, accounts and resource. Offer source-only review while live setup is pending. No searches of .demo history and no MCP syntax for the user to execute.'}}]});return;}
    if(method==='resources/read'){
      if(params.uri!=='bypass://context'){error(id,-32602,'Unknown resource');return;}
      try{const data=await context();respond(id,{contents:[{uri:params.uri,mimeType:'application/json',text:JSON.stringify(redact(data))}]});}catch(e){error(id,-32001,e.message);}return;
    }
    if(method!=='tools/call'){error(id,-32601,'Method not found');return;}
    const t=toolDefinitions.find(t=>t.name===params.name);
    if(!t){error(id,-32602,'Unknown tool');return;}
    const args=params.arguments||{};
    try{validate(t.inputSchema,args);if(args.out)need(!path.isAbsolute(args.out)&&!args.out.split(/[\\/]/).includes('..'),'Export path must stay inside the current repository.');}
    catch(e){error(id,-32602,e.message);return;}
    const controller=new AbortController();pending.set(id,controller);const token=params._meta?.progressToken;
    if(token!==undefined)send({jsonrpc:'2.0',method:'notifications/progress',params:{progressToken:token,progress:0,total:1,message:'Starting Bypass operation'}});
    try{
      let result;
      if(t.command==='onboarding')result=outcome(await pluginOnboarding(cwd,selectedRoot,{intent:args.intent||'real',signal:controller.signal}));
      else if(t.command==='workspace')result=outcome(await workspaceInfo(cwd,selectedRoot));
      else if(t.command==='connect-session'){
        need(!selecting,'Repository selection is already in progress.');
        need(args.confirmed,'Ask which application repository to review before connecting it.');
        need(args.repository.trim(),'Supply the application repository path or Git URL.');
        const remote=/^(https:\/\/|ssh:\/\/|git@)/.test(args.repository);
        const location=remote?args.repository:projectPath(args.repository,cwd);
        need(!remote||!/[/ :]bypass-for-muse(?:\.git)?\/?$/i.test(location)||args.allowBypassSource,'This URL identifies Bypass tooling. Choose the application repository, or explicitly request reviewing Bypass itself.');
        need(remote||!isBypassSource(location)||args.allowBypassSource,'This is the Bypass tooling repository. Ask for the application repository; allowBypassSource requires an explicit request to review Bypass itself.');
        selecting=true;
        try{
          result=await execute('init',[location],{dir:args.dir?projectPath(args.dir,cwd):undefined,name:args.name,json:true,'non-interactive':true},{signal:controller.signal});
          selectedRoot=result.root;
          let persistence;try{persistence=rememberSelection(cwd,selectedRoot);}catch{persistence={remembered:false,reason:'Could not save the workspace selection; this session remains connected.'};}
          result.session={selectedRepository:selectedRoot,hostWorkspace:cwd,allSubsequentToolsUse:selectedRoot,selectionPersists:persistence.remembered?'future sessions opened from this host folder':'this MCP session only',editorWorkspaceMatches:path.resolve(cwd)===selectedRoot,...persistence};
          result.onboarding=await pluginOnboarding(cwd,selectedRoot,{signal:controller.signal});
        }finally{selecting=false;}
      }else if(!selectedRoot&&['status','context'].includes(t.command))result=outcome(await pluginOnboarding(cwd,null));
      else{
        need(selectedRoot&&!selecting,'Choose the application repository first with bypass_connect_repository. The current Muse folder is not selected automatically.');
        result=await execute(t.command,t.makeArgs(args),{...t.makeOptions(args),project:selectedRoot,json:true,'non-interactive':true},{cwd:selectedRoot,signal:controller.signal});
      }
      result={...result,pluginVersion:VERSION};
      if(token!==undefined)send({jsonrpc:'2.0',method:'notifications/progress',params:{progressToken:token,progress:1,total:1,message:'Operation complete'}});
      respond(id,{content:[{type:'text',text:JSON.stringify(redact(result))}],isError:!result?.plan&&(result?.exitCode??0)!==0});
    }catch(e){respond(id,{content:[{type:'text',text:JSON.stringify(redact({schemaVersion:SCHEMA,error:e.message,exitCode:e.code||2,details:e.details||{}}))}],isError:true});}
    finally{pending.delete(id);}
  }
  await new Promise(resolve=>{
    io.input.setEncoding('utf8');
    io.input.on('data',chunk=>{
      buffer+=chunk;if(Buffer.byteLength(buffer)>1_048_576){error(null,-32700,'Message exceeds 1 MiB');buffer='';return;}
      let index;while((index=buffer.indexOf('\n'))!==-1){const line=buffer.slice(0,index).trim();buffer=buffer.slice(index+1);if(!line)continue;let message;try{message=JSON.parse(line);}catch{error(null,-32700,'Invalid JSON');continue;}const task=handle(message).catch(e=>error(message?.id??null,-32603,e.message));tasks.add(task);task.finally(()=>tasks.delete(task));}
    });
    io.input.on('end',()=>{for(const c of pending.values())c.abort();Promise.allSettled([...tasks]).then(resolve);});
    io.input.on('error',()=>{for(const c of pending.values())c.abort();resolve();});
  });
}
