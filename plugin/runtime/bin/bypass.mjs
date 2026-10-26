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
    if(key==='onboard')need(interactive,'onboard needs an interactive terminal. For scripts, use init --non-interactive and explicit model/target commands.');
    const modelFeedback=key==='model test'&&!json;
    const result=['init','onboard'].includes(key)&&interactive?await initWizard({...options,...(key==='init'?{flow:'quickstart'}:{})},args):modelFeedback?await modelTestWizard(options.project||process.cwd(),args[0],{interactive}):await execute(key,args,options);
    if(result?.interactive){if(result.openDashboard)await terminal({project:result.root});process.exitCode=result.exitCode||0;}
    else if(result){if(json)console.log(JSON.stringify(redact(result)));else if(!modelFeedback)printResult(result);process.exitCode=result.skipped?130:result.exitCode||0;}
  }
}catch(e){
  const code=Number.isInteger(e.code)?e.code:2;
  const error=redact({schemaVersion:SCHEMA,error:e.message,details:e.details||{},exitCode:code});
  if(json)console.log(JSON.stringify(error));else printResult(error);process.exitCode=code;
}
