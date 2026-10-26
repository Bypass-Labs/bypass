import path from 'node:path';
import { execute } from './service.mjs';
import { SCHEMA, VERSION, redact, need } from './util.mjs';

const str=(description,extra={})=>({type:'string',description,...extra});
const bool=description=>({type:'boolean',description});
const target=str('Configured target name');
function tool(name,description,properties,required,command,makeArgs=()=>[],makeOptions=a=>a,readOnly=false){return {name,description,inputSchema:{type:'object',properties,required,additionalProperties:false},annotations:{readOnlyHint:readOnly,destructiveHint:!readOnly,idempotentHint:readOnly,openWorldHint:!readOnly},command,makeArgs,makeOptions};}
const identityKey=str('Finding, check, or run ID');
export const toolDefinitions=[
  tool('bypass_status','Read readiness and the explicit mock-engine boundary.',{},[],'status',undefined,undefined,true),
  tool('bypass_init','Initialize Bypass in this session’s repository. Does not execute repository code.',{name:str('Project display name')},[],'init'),
  tool('bypass_targets','List configured targets and their ownership/scope state.',{},[],'target list',undefined,undefined,true),
  tool('bypass_add_target','Connect a local or deployed app. Returns the DNS/HTTP ownership challenge.',{name:str('Target name'),url:str('Exact origin URL'),environment:str('Environment',{enum:['local','preview','staging','production']})},['name','url','environment'],'target add',a=>[a.name]),
  tool('bypass_verify_target','Check the published ownership challenge. This does not authorize security testing.',{name:str('Target name'),method:str('Challenge method',{enum:['dns','http','local']})},['name','method'],'target verify',a=>[a.name]),
  tool('bypass_authorize_target','Record scope only after the user explicitly authorizes testing of these paths.',{name:str('Target name'),paths:str('Comma-separated path prefixes'),accept:bool('True only after explicit user authorization'),production:bool('True only after explicit production authorization')},['name','paths','accept'],'target authorize',a=>[a.name]),
  tool('bypass_revoke_target','Revoke testing authorization and pause monitors.',{name:str('Target name')},['name'],'target revoke',a=>[a.name]),
  tool('bypass_add_identity','Store a credential environment-variable reference, never a raw secret.',{name:str('Identity name'),target,type:str('Identity kind',{enum:['bearer','cookie','header']}),'secret-env':str('Environment variable name'),header:str('Custom header name'),'check-path':str('Configured identity check path')},['name','target','type','secret-env'],'identity add',a=>[a.name]),
  tool('bypass_identities','List identity references without credentials.',{target},[],'identity list',undefined,undefined,true),
  tool('bypass_test_identity','Test a configured identity against an authorized identity-check path.',{name:str('Identity name')},['name'],'identity test',a=>[a.name]),
  tool('bypass_models','List inference profiles and data destinations.',{},[],'model list',undefined,undefined,true),
  tool('bypass_add_model','Configure a provider. Host Muse sessions continue to use their current model; Bypass never extracts subscription credentials.',{name:str('Profile name'),provider:str('Provider',{enum:['local','endpoint','muse-code']}),'base-url':str('Compatible endpoint base URL'),model:str('Model ID'),'secret-env':str('Credential environment variable')},['name','provider'],'model add',a=>[a.name]),
  tool('bypass_use_model','Select the standalone Bypass provider profile.',{name:str('Profile name')},['name'],'model use',a=>[a.name]),
  tool('bypass_prepare_scan','Read the proposed run scope, data flow, and blockers without starting a run.',{mode:str('Review mode',{enum:['code','live','combined']}),target},[],'scan',undefined,a=>({...a,plan:true}),true),
  tool('bypass_scan','Start a durable mock-engine scan. Saved checks run first. Returns a run ID; poll bypass_run. Never claims a real deployed vulnerability.',{mode:str('Review mode',{enum:['code','live','combined']}),target,base:str('Optional Git base reference')},[],'scan',undefined,a=>({...a,detach:true})),
  tool('bypass_findings','Read findings and their simulation/evidence labels.',{target,status:str('Finding status')},[],'finding list',undefined,undefined,true),
  tool('bypass_finding','Read one finding, evidence, and remediation context.',{id:identityKey},['id'],'finding show',a=>[a.id],undefined,true),
  tool('bypass_verify','Verify a local fixture candidate. Deployed-app verification remains explicitly mocked.',{id:identityKey,target},['id'],'verify',a=>[a.id]),
  tool('bypass_retest','Retest the local fixture fix with owner, non-owner, and anonymous controls; save a reusable test on success.',{id:identityKey,target,build:str('Operator-supplied build ID; not attested')},['id'],'retest',a=>[a.id]),
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
  let initialized=false,buffer='';const pending=new Map(),tasks=new Set();
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
      initialized=true;respond(id,{protocolVersion:protocolVersions.includes(params.protocolVersion)?params.protocolVersion:'2025-11-25',capabilities:{tools:{listChanged:false},resources:{subscribe:false,listChanged:false},prompts:{listChanged:false}},serverInfo:{name:'bypass',version:VERSION},instructions:'Bypass skeleton: analysis engines are mocked. Read bypass_context first. Never describe simulated findings as verified. Saved tests and the local fixture proof loop are real.'});return;
    }
    if(method==='ping'){respond(id,{});return;}
    if(!initialized){error(id,-32002,'Initialize the server first.');return;}
    if(method==='tools/list'){respond(id,{tools:toolDefinitions.map(({command,makeArgs,makeOptions,...t})=>t)});return;}
    if(method==='resources/list'){respond(id,{resources:[{uri:'bypass://context',name:'Bypass session context',mimeType:'application/json',description:'Local evidence and monitor updates'}]});return;}
    if(method==='prompts/list'){respond(id,{prompts:[{name:'bypass_review',description:'Review the current repository with the Bypass proof-to-regression workflow.'}]});return;}
    if(method==='prompts/get'){if(params.name!=='bypass_review'){error(id,-32602,'Unknown prompt');return;}respond(id,{messages:[{role:'user',content:{type:'text',text:'Read bypass_context, then bypass_prepare_scan. Explain any missing ownership/scope. Run saved checks before simulated investigation. Keep mock and fixture evidence labels visible. Guide me through findings, fixing in my editor, retest, standalone test export, and local monitoring.'}}]});return;}
    if(method==='resources/read'){
      if(params.uri!=='bypass://context'){error(id,-32602,'Unknown resource');return;}
      try{const data=await execute('context',[],{project:cwd,json:true,'non-interactive':true});respond(id,{contents:[{uri:params.uri,mimeType:'application/json',text:JSON.stringify(redact(data))}]});}catch(e){error(id,-32001,e.message);}return;
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
      const result=await execute(t.command,t.makeArgs(args),{...t.makeOptions(args),project:cwd,json:true,'non-interactive':true},{cwd,signal:controller.signal});
      if(token!==undefined)send({jsonrpc:'2.0',method:'notifications/progress',params:{progressToken:token,progress:1,total:1,message:'Operation complete'}});
      respond(id,{content:[{type:'text',text:JSON.stringify(redact(result))}],isError:(result?.exitCode??0)!==0});
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
