import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { randomUUID } from 'node:crypto';
import { execFile, hash, need, abortFault } from '../util.mjs';
import { ScannerClient } from './client.mjs';

export const scannerDirectory = fileURLToPath(new URL('../../scanner/', import.meta.url));

// Shared by image hashing and plugin packaging; caches/tests never enter a release.
export function scannerPackageFiles(root = scannerDirectory) {
  const files = ['Dockerfile', '.dockerignore', 'pyproject.toml', 'README.md', 'protocol/v1.json'];
  function visit(relative) {
    for (const entry of fs.readdirSync(path.join(root, relative), { withFileTypes: true }).sort((a, b) => a.name.localeCompare(b.name))) {
      const name = `${relative}/${entry.name}`;
      if (entry.isDirectory() && entry.name !== '__pycache__') visit(name);
      else if (entry.isFile() && entry.name.endsWith('.py')) files.push(name);
    }
  }
  visit('src');
  return files;
}

export function scannerTag() {
  return `bypass-scanner:${hash(scannerPackageFiles().map(name => [name, fs.readFileSync(path.join(scannerDirectory, name), 'utf8')])).slice(0, 16)}`;
}

export async function scannerDoctor({ signal, runner = execFile } = {}) {
  const tag = scannerTag();
  let docker;
  try { docker = await runner('docker', ['version', '--format', '{{.Server.Version}}'], { signal, timeout: 10000 }); }
  catch (error) { if (signal?.aborted) throw error; return { docker: { available: false }, image: { tag, available: false }, analysisImplemented: false, status: 'blocked', message: 'Docker is unavailable. Scanner analysis remains unimplemented.' }; }
  if (docker.code !== 0) return { docker: { available: false }, image: { tag, available: false }, analysisImplemented: false, status: 'blocked', message: 'Docker cannot be reached. Check the Docker daemon, context, and socket permissions.' };
  const inspected = await runner('docker', ['image', 'inspect', tag, '--format', '{{.Id}}'], { signal, timeout: 10000 });
  const image = inspected.code === 0 && /^sha256:[a-f0-9]{64}$/.test(inspected.stdout) ? inspected.stdout : null;
  return { docker: { available: true, version: docker.stdout }, image: { tag, available: !!image, id: image }, status: image ? 'scaffold' : 'blocked', analysisImplemented: false,
    message: image ? 'Scanner scaffold image is available. Analysis is not implemented.' : 'Run bypass scanner prepare to build the scaffold image. Analysis is not implemented.' };
}

export async function prepareScanner({ signal, onProgress, runner = execFile } = {}) {
  let diagnostics = await scannerDoctor({ signal, runner });
  need(diagnostics.docker.available, diagnostics.message, 3);
  if (!diagnostics.image.available) {
    onProgress?.({ stage: 'scanner', message: 'Building the scanner scaffold image; analysis is not implemented.' });
    const built = await runner('docker', ['build', '--tag', diagnostics.image.tag, scannerDirectory], { signal, timeout: 300000, killGroup: true });
    need(built.code === 0, 'Scanner scaffold image build failed.', 3);
    diagnostics = await scannerDoctor({ signal, runner });
  }
  need(diagnostics.image.available, 'Cannot resolve the scanner scaffold image.', 3);
  return diagnostics;
}

export function scannerContainerArgs(name, image) {
  return ['create', '--rm', '-i', '--name', name, '--label', 'com.bypass.scanner=true', '--network', 'none', '--read-only', '--cap-drop', 'ALL', '--security-opt', 'no-new-privileges', '--pids-limit', '64', '--memory', '256m', '--cpus', '1', image];
}

/** Connect only to an explicitly prepared image; no build or inference fallback. */
export async function connectScanner({ signal, runner = execFile, timeoutMs } = {}) {
  const diagnostics = await scannerDoctor({ signal, runner });
  need(diagnostics.image.available, diagnostics.message, 3);
  const name = `bypass-scanner-${randomUUID()}`;
  const remove = async () => { try { await runner('docker', ['rm', '--force', name], { timeout: 10000 }); } catch {} };
  // Await creation before checking cancellation so cleanup cannot race creation.
  let created;
  try { created = await runner('docker', scannerContainerArgs(name, diagnostics.image.id), { timeout: 20000, killGroup: true }); }
  catch (error) { await remove(); throw error; }
  if (created.code !== 0) { await remove(); need(false, 'Cannot create scanner container.', 3); }
  if (signal?.aborted) { await remove(); throw abortFault(signal); }
  const client = new ScannerClient('docker', ['start', '--attach', '--interactive', name], { timeoutMs, onClose: remove });
  try { await client.initialize({ signal }); return client; }
  catch (error) { await client.close(); throw error; }
}
