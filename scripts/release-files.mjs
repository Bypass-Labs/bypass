import fs from 'node:fs';
import path from 'node:path';
import {createHash} from 'node:crypto';

export const releasePattern=/^main-([a-f0-9]{40})-[1-9][0-9]{0,15}-[1-9][0-9]{0,15}$/;
export const releasePlatforms=['darwin-arm64','darwin-x64','linux-arm64','linux-x64','win-arm64','win-x64'];
export const installerFields={installer:'install.sh',windowsInstaller:'install.ps1',museInstaller:'install-muse.sh',museWindowsInstaller:'install-muse.ps1',installSkill:'install-muse.md',checksums:'SHASUMS256.txt'};
export const sha256=bytes=>createHash('sha256').update(bytes).digest('hex');
const need=(ok,message)=>{if(!ok)throw new Error(message);};

/** One inventory for R2 and GitHub: never glob a build directory or rebuild assets. */
export function releaseInventory(bytes,expectedCommit){
  need(bytes.length<=16384,'Release manifest exceeds 16 KiB');
  const manifest=JSON.parse(bytes.toString('utf8'));
  const identity=releasePattern.exec(manifest.releaseId);
  need(manifest.schemaVersion===1&&identity&&identity[1]===manifest.commit,'Invalid release identity');
  need(!expectedCommit||manifest.commit===expectedCommit,'Release does not match this CI commit');
  need(/^\d+\.\d+\.\d+(?:[-+][a-zA-Z0-9.-]+)?$/.test(manifest.version),'Invalid release version');
  need(Array.isArray(manifest.assets)&&manifest.assets.length===releasePlatforms.length,'Release must contain all six platforms');
  const expected=releasePlatforms.map(p=>`bypass-${p}${p.startsWith('win-')?'.zip':'.tar.gz'}`);
  need(expected.every(name=>manifest.assets.filter(a=>a.file===name).length===1),'Incomplete or duplicate platform assets');
  const files=[...manifest.assets];
  for(const [key,file] of Object.entries(installerFields)){
    need(manifest[key]?.file===file,`Missing release metadata: ${file}`);files.push(manifest[key]);
  }
  for(const file of files){
    const maximum=expected.includes(file.file)?100000000:65536;
    need(/^[a-f0-9]{64}$/.test(file.sha256)&&Number.isSafeInteger(file.size)&&file.size>0&&file.size<=maximum,`Invalid asset metadata: ${file.file}`);
  }
  files.push({file:'release.json',size:bytes.length,sha256:sha256(bytes)});
  return {manifest,files};
}

export function verifyBytes(bytes,file){
  need(bytes.length===file.size&&sha256(bytes)===file.sha256,`Asset size/checksum mismatch: ${file.file}`);
  return bytes;
}

export function readReleaseFile(dist,file){
  const location=path.join(dist,file.file),stat=fs.lstatSync(location);
  need(stat.isFile()&&!stat.isSymbolicLink()&&stat.size===file.size,`Release asset must be a regular file of the recorded size: ${file.file}`);
  return verifyBytes(fs.readFileSync(location),file);
}

export function verifyChecksums(bytes,manifest){
  const expected=manifest.assets.map(a=>`${a.sha256}  ${a.file}`).sort();
  const actual=bytes.toString('utf8').trimEnd().split('\n').sort();
  need(JSON.stringify(actual)===JSON.stringify(expected),'Checksum list does not match the manifest');
}
