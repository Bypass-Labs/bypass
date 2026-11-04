import fs from 'node:fs';
import { execFile } from './util.mjs';

// Read-only diagnosis for an unreachable Docker daemon.
//
// `docker` on macOS/Windows is only a client: the daemon lives in a VM
// (Docker Desktop or Colima/Lima). A generic "start Docker" message strands
// users whose real problem is a stopped Colima profile or a Docker context
// pointed at a socket that does not exist. These probes never start, stop, or
// reconfigure anything; they only name the exact fix.

function parseObjects(text) {
  const objects = [];
  for (const line of String(text || '').split('\n')) {
    const trimmed = line.trim();
    if (!trimmed) continue;
    try { objects.push(JSON.parse(trimmed)); } catch { /* ignore non-JSON noise */ }
  }
  return objects;
}

async function probe(runner, command, args, signal) {
  try {
    const result = await runner(command, args, {signal, timeout:5000});
    return result && result.code === 0 ? result : null;
  } catch { return null; }
}

export function colimaContextName(profile) {
  return profile === 'default' ? 'colima' : `colima-${profile}`;
}

function installSteps(platform) {
  if (platform === 'darwin') return [
    {command:'brew install colima docker', description:'Install Colima and the Docker CLI with Homebrew. Alternative: `brew install --cask docker` for Docker Desktop.'},
    {command:'colima start', description:'Start the Docker daemon VM (skip if you installed Docker Desktop; open it instead).'},
  ];
  if (platform === 'linux') return [
    {command:'sudo systemctl start docker', description:'Start Docker Engine. If it is not installed, install Docker Engine for your distribution first.'},
  ];
  if (platform === 'win32') return [
    {command:null, description:'Install Docker Desktop, start it, and wait until it reports that Docker is running.'},
  ];
  return [
    {command:null, description:'Install Docker (Docker Desktop, Colima, or Docker Engine) and start its daemon.'},
  ];
}

function startSteps(platform) {
  if (platform === 'darwin') return [
    {command:'colima start', description:'If you use Colima, start its Docker daemon VM.'},
    {command:'open -a Docker', description:'If you use Docker Desktop instead, start it and wait until it reports running.'},
  ];
  if (platform === 'linux') return [
    {command:'sudo systemctl start docker', description:'Start the Docker Engine daemon.'},
  ];
  if (platform === 'win32') return [
    {command:null, description:'Start Docker Desktop and wait until it reports that Docker is running.'},
  ];
  return [
    {command:null, description:'Start the Docker daemon (Docker Desktop, Colima, or Docker Engine).'},
  ];
}

export async function dockerRemediation({runner = execFile, signal, platform = process.platform, fileExists = fs.existsSync, cliMissing = false} = {}) {
  let contexts = [], colimaProfiles = [];
  if (!cliMissing) {
    const listed = await probe(runner, 'docker', ['context','ls','--format','json'], signal);
    contexts = parseObjects(listed?.stdout)
      .filter(item => typeof item?.Name === 'string')
      .map(item => ({name:item.Name, current:!!item.Current, endpoint:String(item.DockerEndpoint || '')}));
    for (const context of contexts.filter(item => !item.current).slice(0, 4)) {
      if (await probe(runner, 'docker', ['--context', context.name, 'version', '--format', '{{.Server.Version}}'], signal)) {
        return {reason:'wrong-context', contexts, colimaProfiles, remediation:[
          {command:`docker context use ${context.name}`, description:`Docker context "${context.name}" is already reachable; the active context is not. Switch to it.`},
        ]};
      }
    }
    const colima = await probe(runner, 'colima', ['list','--json'], signal);
    colimaProfiles = parseObjects(colima?.stdout)
      .filter(item => typeof item?.name === 'string')
      .map(item => ({name:item.name, status:String(item.status || ''), runtime:String(item.runtime || 'docker')}))
      .filter(item => item.runtime === 'docker');
    const stopped = colimaProfiles.filter(item => !/^running$/i.test(item.status));
    if (stopped.length) return {reason:'daemon-stopped', contexts, colimaProfiles, remediation:stopped.slice(0, 3).flatMap(item => [
      {command:`colima start ${item.name}`, description:`Start the stopped Colima profile "${item.name}" (Docker daemon VM).`},
      {command:`docker context use ${colimaContextName(item.name)}`, description:`Then point the Docker CLI at that profile if it is not already active.`},
    ])};
    const running = colimaProfiles.filter(item => /^running$/i.test(item.status));
    if (running.length) return {reason:'wrong-context', contexts, colimaProfiles, remediation:running.slice(0, 3).map(item => (
      {command:`docker context use ${colimaContextName(item.name)}`, description:`Colima profile "${item.name}" is running; select its Docker context.`}
    ))};
  }
  if (platform === 'darwin' && fileExists('/Applications/Docker.app')) {
    return {reason:cliMissing ? 'cli-missing' : 'daemon-stopped', contexts, colimaProfiles, remediation:[
      {command:'open -a Docker', description:'Start Docker Desktop and wait until it reports that Docker is running.'},
    ]};
  }
  if (cliMissing) return {reason:'cli-missing', contexts, colimaProfiles, remediation:installSteps(platform)};
  return {reason:'daemon-unreachable', contexts, colimaProfiles, remediation:startSteps(platform)};
}

export function dockerBlockerMessage(prefix, diagnostics, suffix = 'Then re-run the check.') {
  const steps = (diagnostics?.remediation || []).map(step => step.command ? `${step.description} Run: ${step.command}` : step.description);
  return [prefix, ...steps, suffix].filter(Boolean).join(' ');
}
