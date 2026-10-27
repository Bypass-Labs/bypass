import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const root=fileURLToPath(new URL('../',import.meta.url));
export const installAssetFiles=['install.sh','install.ps1','install-muse.sh','install-muse.ps1','install-muse.md'];
export function buildInstallAssets(dist){
  fs.mkdirSync(dist,{recursive:true});
  const shell=fs.readFileSync(path.join(root,'scripts/install.sh'),'utf8');
  const powershell=fs.readFileSync(path.join(root,'scripts/install.ps1'),'utf8');
  if(!shell.endsWith('bypass_install "$@"\n')||!powershell.endsWith('}\n'))throw new Error('Installer entrypoint changed; update Muse variant generation');
  const assets={
    'install.sh':shell,'install.ps1':powershell,
    'install-muse.sh':shell.replace(/bypass_install "\$@"\n$/,'bypass_install --muse "$@"\n'),
    'install-muse.ps1':powershell.replace(/}\n$/,'} -Muse\n'),
    'install-muse.md':fs.readFileSync(path.join(root,'skills/bypass-install/SKILL.md'),'utf8')
  };
  for(const [name,content] of Object.entries(assets))fs.writeFileSync(path.join(dist,name),content);
}
