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
export async function pluginIdentity({inspect=()=>execFile('muse',['plugins','inspect','bypass','--json'],{timeout:2000})}={}){
  try{const result=await inspect();return comparePlugin(JSON.parse(result.stdout).record);}
  catch{return {...runtimeIdentity(),installedVersion:null,restartRequired:null,installationCheck:'unavailable; use muse plugins inspect bypass in the launching terminal'};}
}
