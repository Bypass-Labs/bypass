import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import { fileURLToPath } from 'node:url';
import { execFileSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { buildInstallAssets } from './build-install-assets.mjs';
const root=fileURLToPath(new URL('../',import.meta.url));
const runtime=JSON.parse(fs.readFileSync(new URL('./node-runtime.json',import.meta.url)));
const version=JSON.parse(fs.readFileSync(path.join(root,'package.json'))).version;
const commit=process.env.GITHUB_SHA||execFileSync('git',['rev-parse','HEAD'],{cwd:root,encoding:'utf8'}).trim();
const run=process.env.GITHUB_RUN_ID||'1',attempt=process.env.GITHUB_RUN_ATTEMPT||'1';
if(!/^[a-f0-9]{40}$/.test(commit)||![run,attempt].every(v=>/^[1-9][0-9]{0,15}$/.test(v)))throw new Error('Invalid release identity');
const releaseId=`main-${commit}-${run}-${attempt}`;
const selected=process.env.BYPASS_BUILD_PLATFORMS?.split(',')||Object.keys(runtime.sha256);
if(!selected.length||selected.some(p=>!runtime.sha256[p]))throw new Error('Unsupported platform');
const dist=path.resolve(process.env.BYPASS_RELEASE_DIST||path.join(root,'dist/releases'));
fs.mkdirSync(dist,{recursive:true});
execFileSync(process.execPath,[path.join(root,'scripts/build-plugin.mjs')],{stdio:'inherit'});
const sha=bytes=>createHash('sha256').update(bytes).digest('hex');
const metadata=file=>{const bytes=fs.readFileSync(path.join(dist,file));return {file,sha256:sha(bytes),size:bytes.length};};
const assets=[];
for(const platform of selected){
  const work=fs.mkdtempSync(path.join(os.tmpdir(),'bypass-release-'));
  try{
    const windows=platform.startsWith('win-'),name=`node-v${runtime.version}-${platform}`,filename=name+(windows?'.zip':'.tar.gz');
    console.log(`Building ${platform} with Node ${runtime.version}`);
    const response=await fetch(`https://nodejs.org/dist/v${runtime.version}/${filename}`,{signal:AbortSignal.timeout(180000)});
    if(!response.ok)throw new Error(`Node download failed: HTTP ${response.status}`);
    const bytes=Buffer.from(await response.arrayBuffer());
    if(sha(bytes)!==runtime.sha256[platform])throw new Error('Official Node runtime checksum mismatch');
    fs.writeFileSync(path.join(work,filename),bytes);
    if(windows)execFileSync('unzip',['-q',path.join(work,filename),`${name}/node.exe`,`${name}/LICENSE`,'-d',work]);
    else execFileSync('tar',['-xzf',path.join(work,filename),'-C',work,`${name}/bin/node`,`${name}/LICENSE`]);
    const bundle=path.join(work,'bypass'),plugin=path.join(bundle,'plugin');
    fs.mkdirSync(bundle);fs.cpSync(path.join(root,'plugin'),plugin,{recursive:true});
    const nodeFile=windows?'node.exe':'node';
    fs.copyFileSync(path.join(work,name,windows?'node.exe':'bin/node'),path.join(plugin,'runtime',nodeFile));fs.chmodSync(path.join(plugin,'runtime',nodeFile),0o755);
    fs.copyFileSync(path.join(work,name,'LICENSE'),path.join(plugin,'runtime/NODE_LICENSE'));
    const manifestPath=path.join(plugin,'.muse-plugin/plugin.json'),manifest=JSON.parse(fs.readFileSync(manifestPath));
    for(const capability of [...manifest.capabilities.mcpServers,...manifest.capabilities.hooks]){
      // Muse resolves the first declared source path (our executable), but keeps
      // the customer's cwd. Resolve the entrypoint from that executable as well.
      const entry=capability.command[1];
      capability.command=['./runtime/'+nodeFile,'--input-type=module','-e',`import { pathToFileURL } from 'node:url'; await import(new URL('../${entry}', pathToFileURL(process.execPath)));`];
    }
    fs.writeFileSync(manifestPath,JSON.stringify(manifest,null,2)+'\n');
    fs.copyFileSync(path.join(root,'scripts/launch-bypass.sh'),path.join(bundle,'launch-bypass'));fs.chmodSync(path.join(bundle,'launch-bypass'),0o755);
    fs.copyFileSync(path.join(root,'scripts/configure-path.mjs'),path.join(bundle,'configure-path.mjs'));
    if(windows)fs.copyFileSync(path.join(root,'scripts/windows-launcher.ps1'),path.join(bundle,'windows-launcher.ps1'));
    fs.copyFileSync(path.join(root,'README.md'),path.join(bundle,'README.md'));
    fs.writeFileSync(path.join(bundle,'release.json'),JSON.stringify({releaseId,commit,version,platform,node:runtime.version},null,2)+'\n');
    const file=`bypass-${platform}`+(windows?'.zip':'.tar.gz');
    if(windows){fs.rmSync(path.join(dist,file),{force:true});execFileSync('zip',['-qr',path.join(dist,file),'bypass'],{cwd:work});}
    else execFileSync('tar',['-czf',path.join(dist,file),'-C',work,'bypass'],{env:{...process.env,COPYFILE_DISABLE:'1'}});
    assets.push({...metadata(file),platform});
  }finally{fs.rmSync(work,{recursive:true,force:true});}
}
buildInstallAssets(dist);
fs.writeFileSync(path.join(dist,'SHASUMS256.txt'),assets.map(a=>`${a.sha256}  ${a.file}`).join('\n')+'\n');
const release={schemaVersion:1,releaseId,commit,version,node:runtime.version,assets,installer:metadata('install.sh'),windowsInstaller:metadata('install.ps1'),museInstaller:metadata('install-muse.sh'),museWindowsInstaller:metadata('install-muse.ps1'),installSkill:metadata('install-muse.md'),checksums:metadata('SHASUMS256.txt')};
fs.writeFileSync(path.join(dist,'release.json'),JSON.stringify(release,null,2)+'\n');
console.log(JSON.stringify({releaseId,dist,platforms:selected}));
