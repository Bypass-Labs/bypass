#!/usr/bin/env node
import { parse, help } from '../src/catalog.mjs';
import { execute } from '../src/service.mjs';
import { terminal, initWizard, modelTestWizard, printResult } from '../src/ui.mjs';
import { VERSION, SCHEMA, redact, need } from '../src/util.mjs';

const argv=process.argv.slice(2);
const json=argv.includes('--json');
try{
  const {key,args,options}=parse(argv);
  if(options.version){console.log(json?JSON.stringify({schemaVersion:SCHEMA,version:VERSION}):VERSION);}
  else if(options.help){console.log(help(key));}
  else if(!key){if(process.stdin.isTTY&&process.stdout.isTTY&&!options['non-interactive']&&!json)await terminal(options);else {const result=await execute('status',[],options).catch(()=>null);if(result)json?console.log(JSON.stringify(redact(result))):printResult(result);else console.log(json?JSON.stringify({schemaVersion:SCHEMA,status:'not-initialized',next:'bypass init',exitCode:0}):help());}}
  else {
    const interactive=process.stdin.isTTY&&process.stdout.isTTY&&!options['non-interactive']&&!json;
    if(key==='onboard'||key==='demo'||key==='poc')need(interactive,`${key} needs an interactive terminal. For scripts, use init --non-interactive or demo start.`);
    const modelFeedback=key==='model test'&&!json;
    const result=key==='poc'&&interactive?{...(await execute('poc start',[],options)),interactive:true,openDashboard:true}:['init','onboard','demo'].includes(key)&&interactive?await initWizard({...options,...(key==='init'?{flow:'quickstart'}:key==='demo'?{flow:'demo'}:{})},args):modelFeedback?await modelTestWizard(options.project||process.cwd(),args[0],{interactive}):await execute(key,args,options,{onProgress:json?undefined:step=>console.error(redact(step.message))});
    if(result?.interactive){if(result.openDashboard)await terminal({project:result.root});process.exitCode=result.exitCode||0;}
    else if(result){if(json)console.log(JSON.stringify(redact(result)));else if(!modelFeedback)printResult(result);process.exitCode=result.skipped?130:result.exitCode||0;}
  }
}catch(e){
  const code=Number.isInteger(e.code)?e.code:2;
  const error=redact({schemaVersion:SCHEMA,error:e.message,details:e.details||{},exitCode:code});
  if(json)console.log(JSON.stringify(error));else printResult(error);process.exitCode=code;
}
