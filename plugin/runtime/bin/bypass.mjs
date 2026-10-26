#!/usr/bin/env node
import { parse, help } from '../src/catalog.mjs';
import { execute } from '../src/service.mjs';
import { terminal, initWizard, printResult } from '../src/ui.mjs';
import { VERSION, SCHEMA, redact } from '../src/util.mjs';

const argv=process.argv.slice(2);
const json=argv.includes('--json');
try{
  const {key,args,options}=parse(argv);
  if(options.version){console.log(json?JSON.stringify({schemaVersion:SCHEMA,version:VERSION}):VERSION);}
  else if(options.help){console.log(help(key));}
  else if(!key){if(process.stdin.isTTY&&process.stdout.isTTY&&!options['non-interactive']&&!json)await terminal(options);else {const result=await execute('status',[],options).catch(()=>null);if(result)json?console.log(JSON.stringify(redact(result))):printResult(result);else console.log(json?JSON.stringify({schemaVersion:SCHEMA,status:'not-initialized',next:'bypass init',exitCode:0}):help());}}
  else {
    const result=key==='init'&&process.stdin.isTTY&&!options['non-interactive']&&!json?await initWizard(options,args):await execute(key,args,options);
    if(result){if(json)console.log(JSON.stringify(redact(result)));else printResult(result);process.exitCode=result.exitCode||0;}
  }
}catch(e){
  const code=Number.isInteger(e.code)?e.code:2;
  const error=redact({schemaVersion:SCHEMA,error:e.message,details:e.details||{},exitCode:code});
  if(json)console.log(JSON.stringify(error));else printResult(error);process.exitCode=code;
}
