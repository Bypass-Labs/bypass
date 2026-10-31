import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { VERSION, execFile } from './util.mjs';
import { safeRequest } from './network.mjs';

const sourcePath=path.resolve(path.dirname(fileURLToPath(import.meta.url)),'..');
export const runtimeIdentity=()=>({version:VERSION,sourcePath,launchCommand:`node ${path.join(sourcePath,'bin/bypass.mjs')}`,product:'Bypass for Muse Code'});

export function comparePlugin(record,running=runtimeIdentity()){
  const cached=running.sourcePath.includes('/plugins/cache/');
  const restartRequired=cached&&!!record?.cache_path&&path.dirname(running.sourcePath)!==path.resolve(record.cache_path);
  return {...running,installedVersion:record?.version||null,installedSource:record?.source?.path||null,restartRequired,
    ...(restartRequired?{message:'This Muse session is running an older cached plugin. Exit Muse and open a new session to load the installed package.'}:record?.version&&record.version!==running.version?{message:'The running package and installed Muse plugin have different versions. Update the plugin from your chosen checkout and start a new Muse session.'}:{})};
}
export const updateCommand=platform=>platform==='win32'?'irm https://bypasslabs.ai/install/muse.ps1 | iex':'curl -fsSL https://bypasslabs.ai/install/muse | bash';
const newer=(left,right)=>{
  if(!/^\d+\.\d+\.\d+$/.test(left||'')||!/^\d+\.\d+\.\d+$/.test(right||''))return false;
  const a=left.split('.').map(Number),b=right.split('.').map(Number);
  for(let i=0;i<3;i++){if(a[i]!==b[i])return a[i]>b[i];}return false;
};
export async function releaseAwareness(identity,{request=safeRequest,platform=process.platform}={}){
  // Public version metadata only: no project, app URL, credentials or source.
  // Offline/failed checks never block a review or install software automatically.
  let publishedVersion=null,releaseCheck='unavailable';
  try{
    const response=await request('https://bypasslabs.ai/downloads/bypass/channels/main.json',{timeout:2000,maxBytes:65536,signal:AbortSignal.timeout(2500)});
    if(response.status!==200)throw new Error('Version check failed');
    const manifest=JSON.parse(response.body);
    if(!/^\d+\.\d+\.\d+$/.test(manifest.version||''))throw new Error('Invalid version');
    publishedVersion=manifest.version;releaseCheck='verified';
  }catch{}
  const updateAvailable=newer(publishedVersion,identity.version);
  const restartRequired=identity.restartRequired===true||newer(identity.installedVersion,identity.version)?true:identity.restartRequired??null;
  const installationUpdateAvailable=updateAvailable&&newer(publishedVersion,identity.installedVersion||identity.version);
  const command=updateCommand(platform);
  const notice=installationUpdateAvailable?{kind:'update_available',command,message:`This session runs Bypass ${identity.version}; ${publishedVersion} is published. Update with the public installer, then start a new Muse session. Native Muse update only refreshes its recorded local source, which can be pinned to an older release.`}
    :restartRequired?{kind:'restart_required',message:`This session runs Bypass ${identity.version}; Muse has ${identity.installedVersion||'a different package'} installed. Exit this Muse session and open a new one to load it. Project setup is retained.`}:null;
  return {...identity,publishedVersion,releaseCheck,updateAvailable,restartRequired,updateCommand:command,...(notice?{notice}:{})};
}
let cached,pending;
export async function pluginIdentity({inspect,request}={}){
  if(!inspect&&cached&&Date.now()-cached.at<60000)return cached.value;
  if(!inspect&&pending)return pending;
  const readIdentity=async()=>{
    try{const result=await (inspect||(()=>execFile('muse',['plugins','inspect','bypass','--json'],{timeout:8000})))();
      if(result.code!==undefined&&result.code!==0)throw new Error('Native inspection failed');
      const record=JSON.parse(result.stdout).record;
      return {...comparePlugin(record),installationCheck:record?'verified':'not_installed'};
    }catch(error){return {...runtimeIdentity(),installedVersion:null,restartRequired:null,installationCheck:error.details?.reason==='timeout'?'timed_out':'unavailable',message:'Running package version is known; native installation could not be checked. Retry integration status; this does not block review.'};}
  };
  if(inspect){const identity=await readIdentity();return request?releaseAwareness(identity,{request}):identity;}
  pending=readIdentity().then(identity=>releaseAwareness(identity,{request}));try{const value=await pending;cached={at:Date.now(),value};return value;}finally{pending=null;}
}
