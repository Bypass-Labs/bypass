import fs from 'node:fs';
import path from 'node:path';

// Meta's Windows installer provides muse.cmd plus .muse-launcher.ps1. Launch
// the script directly so repository paths and model arguments never enter cmd.exe.
export function commandInvocation(command,args,env=process.env){
  if(process.platform!=='win32'||command!=='muse')return {command,args};
  const search=Object.entries(env).find(([key])=>key.toLowerCase()==='path')?.[1]||'';
  for(const directory of search.split(path.delimiter).filter(Boolean)){
    const base=directory.replace(/^"|"$/g,''),exe=path.join(base,'muse.exe');
    if(fs.existsSync(exe))return {command:exe,args};
    const launcher=path.join(base,'.muse-launcher.ps1');
    if(fs.existsSync(path.join(base,'muse.cmd'))&&fs.existsSync(launcher))return {
      command:path.join(env.SystemRoot||env.SYSTEMROOT||'C:\\Windows','System32','WindowsPowerShell','v1.0','powershell.exe'),
      args:['-NoLogo','-NoProfile','-ExecutionPolicy','Bypass','-File',launcher,...args]
    };
  }
  return {command,args};
}
