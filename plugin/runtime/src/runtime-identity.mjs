import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { VERSION, execFile } from './util.mjs';

const sourcePath=path.resolve(path.dirname(fileURLToPath(import.meta.url)),'..');
export const runtimeIdentity=()=>({version:VERSION,sourcePath,launchCommand:`node ${path.join(sourcePath,'bin/bypass.mjs')}`,product:'Bypass for Muse'});

export function comparePlugin(record,running=runtimeIdentity()){
  const cached=running.sourcePath.includes('/plugins/cache/');
  const restartRequired=cached&&!!record?.cache_path&&path.dirname(running.sourcePath)!==path.resolve(record.cache_path);
  return {...running,installedVersion:record?.version||null,installedSource:record?.source?.path||null,restartRequired,
    ...(restartRequired?{message:'This Muse session is running an older cached plugin. Exit Muse and open a new session to load the installed package.'}:record?.version&&record.version!==running.version?{message:'The running package and installed Muse plugin have different versions. Update the plugin from your chosen checkout and start a new Muse session.'}:{})};
}
let cached,pending;
export async function pluginIdentity({inspect}={}){
  if(!inspect&&cached&&Date.now()-cached.at<60000)return cached.value;
  if(!inspect&&pending)return pending;
  const readIdentity=async()=>{
    try{const result=await (inspect||(()=>execFile('muse',['plugins','inspect','bypass','--json'],{timeout:8000})))();
      if(result.code!==undefined&&result.code!==0)throw new Error('Native inspection failed');
      const record=JSON.parse(result.stdout).record;
      return {...comparePlugin(record),installationCheck:record?'verified':'not_installed'};
    }catch(error){return {...runtimeIdentity(),installedVersion:null,restartRequired:null,installationCheck:error.details?.reason==='timeout'?'timed_out':'unavailable',message:'Running package version is known; native installation could not be checked. Retry integration status; this does not block review.'};}
  };
  if(inspect)return readIdentity();
  pending=readIdentity();try{const value=await pending;cached={at:Date.now(),value};return value;}finally{pending=null;}
}
